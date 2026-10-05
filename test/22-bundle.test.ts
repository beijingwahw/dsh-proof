/**
 * APP/1.0 BUNDLE — the portable proof-bundle exchange format.
 *
 * The adversary here is the *producer*: a bundle arrives from elsewhere
 * (another machine, another session, possibly the agent itself) and the
 * verifier must re-derive every conclusion from the bundle's own bytes. These
 * tests mint honest bundles with a real `EvidenceStore` (in memory, via the
 * same fakes `09-trust` uses) and then attack them the way a forger would:
 * edit a byte of the log, swap the baseline, inflate the anchor, re-dialect
 * the manifest. Nothing touches real disk — the whole suite runs on MemoryFs.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'

import { buildBundle, verifyBundle, type ProofBundle } from '../src/app/bundle.ts'
import { appFingerprint } from '../src/app/protocol.ts'
import { EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { sha256 } from '../src/core/hash.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { FakeClock, MemoryFs, spec } from './helpers.ts'

const LOG = '/ws/.proof/evidence.jsonl'
const BASE = '/ws/.proof/baseline.json'
const ANCHOR = '/trust/anchors/ws/anchor.json'
const AT = '2026-10-06T00:00:00.000Z'
const WS = snapshotWorkspace('head1', ['src/a.ts'])

/** Deterministic stand-in for the host key: the attacker knows its keyId, never its secret. */
class FakeSigner implements SignerPort {
  readonly keyId = 'fake-key'
  async sign(data: string): Promise<string> { return `sig:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> { return signature === `sig:${sha256(data)}` }
}

/** The bundle-verifier's view of the same key: it can only verify, never sign. */
function anchorVerifier(signer: FakeSigner): { keyId: string; verify: (data: string, sig: string) => Promise<boolean> } {
  return { keyId: signer.keyId, verify: (data, sig) => signer.verify(data, sig) }
}

function evidence(id: string, status: 'pass' | 'fail' = 'pass') {
  return makeEvidence(spec({ id }), { status, exitCode: status === 'pass' ? 0 : 1, durationMs: 5, output: `${status}\n` }, WS, new FakeClock())
}

function trustedStore(fs: MemoryFs) {
  const signer = new FakeSigner()
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => signer,
    anchorPath: ANCHOR,
    workspaceKey: 'ws',
    checkpointEvery: 1000,
  })
  return { store, signer }
}

/**
 * An honest, fully-armed bundle: signed chain (one checkpoint mid-log, one
 * record after it), a self-addressed baseline, and the anchor the checkpoint
 * wrote. The anchor's head therefore matches the *last* checkpoint, and the
 * tail holds exactly one uncovered record.
 */
async function honestFullChain() {
  const fs = MemoryFs.of({})
  const { store, signer } = trustedStore(fs)
  const ev1 = evidence('c1')
  await store.append(ev1)
  await store.checkpoint()
  await store.append(evidence('c2'))
  const baseline = buildBaseline([ev1], WS, new FakeClock())
  const log = await fs.readFile(LOG)
  const anchorJson = await fs.readFile(ANCHOR)
  assert.ok(typeof log === 'string' && typeof anchorJson === 'string')
  const bundle = buildBundle(
    { evidenceLog: log, baselineJson: JSON.stringify(baseline, null, 2), anchorJson },
    'ws',
    AT,
  )
  return { bundle, signer, baseline }
}

/** Replace a file's contents AND re-manifest it — a forger holding the pen. */
function withFile(bundle: ProofBundle, path: string, contents: string): ProofBundle {
  return {
    manifest: {
      ...bundle.manifest,
      files: bundle.manifest.files.map(f => f.path === path
        ? { path, sha256: sha256(contents), bytes: Buffer.byteLength(contents, 'utf8') }
        : f),
    },
    files: { ...bundle.files, [path]: contents },
  }
}

/** Replace a file's contents WITHOUT touching the manifest — naive tampering. */
function withRawFile(bundle: ProofBundle, path: string, contents: string): ProofBundle {
  return { manifest: bundle.manifest, files: { ...bundle.files, [path]: contents } }
}

test('buildBundle is deterministic: same input, same bytes, manifest digests match an independent sha256', () => {
  const input = {
    evidenceLog: '{"v":2,"kind":"evidence","at":"2026-10-06T00:00:00.000Z","prev":"aa","payload":{}}\n',
    baselineJson: '{\n  "baselineId": "deadbeef"\n}\n',
    anchorJson: '{"v":1,"keyId":"k","count":1,"head":"bb","sig":"sig:x","at":"2026-10-06T00:00:00.000Z","workspaceKey":"ws"}',
  }
  const first = buildBundle(input, 'ws', AT)
  const second = buildBundle(input, 'ws', AT)
  assert.deepEqual(first, second)
  assert.equal(JSON.stringify(first), JSON.stringify(second), 'serialization must be byte-deterministic')
  assert.deepEqual(Object.keys(first), ['manifest', 'files'], 'manifest leads, files follow')
  assert.deepEqual(Object.keys(first.files), ['evidence.jsonl', 'baseline.json', 'anchor.json'], 'fixed file order')
  assert.equal(first.manifest.protocol, 'APP/1.0')
  assert.equal(first.manifest.appFingerprint, appFingerprint())
  assert.equal(first.manifest.workspaceKey, 'ws')
  assert.equal(first.manifest.createdAt, AT)
  const [evEntry, baseEntry, anchorEntry] = first.manifest.files
  assert.ok(evEntry && baseEntry && anchorEntry)
  assert.deepEqual(evEntry, { path: 'evidence.jsonl', sha256: sha256(input.evidenceLog), bytes: Buffer.byteLength(input.evidenceLog, 'utf8') })
  assert.deepEqual(baseEntry, { path: 'baseline.json', sha256: sha256(input.baselineJson), bytes: Buffer.byteLength(input.baselineJson, 'utf8') })
  assert.deepEqual(anchorEntry, { path: 'anchor.json', sha256: sha256(input.anchorJson), bytes: Buffer.byteLength(input.anchorJson, 'utf8') })
  assert.deepEqual(Object.keys(buildBundle({ evidenceLog: 'x' }, 'ws', AT).files), ['evidence.jsonl'], 'optional files are simply absent')
})

test('minimal evidence-only bundles verify clean: empty log, and a real unsigned chain', async () => {
  const empty = buildBundle({ evidenceLog: '' }, 'ws', AT)
  const emptyVerdict = await verifyBundle(empty)
  assert.equal(emptyVerdict.protocolOk, true)
  assert.equal(emptyVerdict.manifestOk, true)
  assert.deepEqual(emptyVerdict.problems, [])
  assert.equal(emptyVerdict.chainMode, 'unsigned')
  assert.equal(emptyVerdict.tailRecords, 0)

  const fs = MemoryFs.of({})
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  const log = await fs.readFile(LOG)
  assert.ok(typeof log === 'string')
  const unsigned = await verifyBundle(buildBundle({ evidenceLog: log }, 'ws', AT))
  assert.equal(unsigned.protocolOk, true)
  assert.equal(unsigned.manifestOk, true)
  assert.deepEqual(unsigned.problems, [])
  assert.equal(unsigned.chainMode, 'unsigned')
  assert.equal(unsigned.tailRecords, 2, 'no checkpoint: every record is tail')
})

test('full chain from a trusted store: signed mode, honest tail count, anchor head matches', async () => {
  const { bundle, signer, baseline } = await honestFullChain()
  const verdict = await verifyBundle(bundle, anchorVerifier(signer))
  assert.equal(verdict.protocolOk, true)
  assert.equal(verdict.manifestOk, true)
  assert.deepEqual(verdict.problems, [])
  assert.equal(verdict.chainMode, 'signed')
  assert.equal(verdict.tailRecords, 1, 'c2 was appended after the checkpoint')
  assert.deepEqual(verdict.chainBreaks, [])
  assert.deepEqual(verdict.corruptLines, [])
  assert.equal(verdict.anchor?.headMatchesChain, true)
  assert.equal(verdict.anchor?.count, 1)
  assert.equal(verdict.baselineId, baseline.baselineId)
  assert.equal(verdict.baselineSelfAddressed, true)
})

test('tamper matrix: one edited byte in evidence.jsonl is a manifest digest mismatch (and a chain break)', async () => {
  const { bundle } = await honestFullChain()
  const original = bundle.files['evidence.jsonl']
  const doctoredLog = original?.replace('"pass"', '"qass"')
  assert.ok(typeof original === 'string' && typeof doctoredLog === 'string' && doctoredLog !== original, 'the edit must actually change a byte')
  const verdict = await verifyBundle(withRawFile(bundle, 'evidence.jsonl', doctoredLog))
  assert.equal(verdict.manifestOk, false)
  assert.deepEqual(verdict.digestMismatches, ['evidence.jsonl'])
  assert.ok(verdict.problems.some(p => p.startsWith('digest mismatch for evidence.jsonl')))
  assert.deepEqual(verdict.chainBreaks, [1], 'the line after the edit no longer chains')
})

test('tamper matrix: a swapped baseline fails self-addressing even when the manifest is recomputed', async () => {
  const { bundle, baseline } = await honestFullChain()
  const doctored = JSON.stringify({ ...baseline, root: '0'.repeat(64) }, null, 2)
  const verdict = await verifyBundle(withFile(bundle, 'baseline.json', doctored))
  assert.equal(verdict.manifestOk, true, 'the forger re-manifested the file: digests agree')
  assert.equal(verdict.baselineId, baseline.baselineId, 'the id field itself was left in place')
  assert.equal(verdict.baselineSelfAddressed, false)
  assert.ok(verdict.problems.some(p => p.includes('not self-addressed')))
})

test('tamper matrix: inflating the anchor count is refuted by its signature', async () => {
  const { bundle, signer } = await honestFullChain()
  const anchor = JSON.parse(bundle.files['anchor.json'] as string) as Record<string, unknown>
  const doctored = JSON.stringify({ ...anchor, count: 99 }, null, 2)
  const verdict = await verifyBundle(withFile(bundle, 'anchor.json', doctored), anchorVerifier(signer))
  assert.equal(verdict.manifestOk, true, 'digests were recomputed — only the signature knows')
  assert.equal(verdict.anchor?.count, 99)
  assert.equal(verdict.anchor?.headMatchesChain, true, 'the head was not touched; the count is what the signature guards')
  assert.deepEqual(verdict.problems, ['anchor signature invalid'])
})

test('tamper matrix: an unknown protocol version in the manifest is rejected', async () => {
  const { bundle, signer } = await honestFullChain()
  const alien: ProofBundle = { ...bundle, manifest: { ...bundle.manifest, protocol: 'APP/9.9' as unknown as 'APP/1.0' } }
  const verdict = await verifyBundle(alien, anchorVerifier(signer))
  assert.equal(verdict.protocolOk, false)
  assert.equal(verdict.manifestOk, true, 'the files themselves are still exactly what the manifest describes')
  assert.deepEqual(verdict.digestMismatches, [])
  assert.ok(verdict.problems.some(p => p.includes('unsupported bundle protocol')))
})

test('without an anchorSigner the signature is skipped, never charged: only headMatchesChain is judged', async () => {
  const { bundle } = await honestFullChain()
  const honest = await verifyBundle(bundle)
  assert.deepEqual(honest.problems, [])
  assert.equal(honest.anchor?.headMatchesChain, true)

  const anchor = JSON.parse(bundle.files['anchor.json'] as string) as Record<string, unknown>
  const doctored = JSON.stringify({ ...anchor, count: 99 }, null, 2)
  const unverifiable = await verifyBundle(withFile(bundle, 'anchor.json', doctored))
  assert.equal(unverifiable.problems.some(p => p.includes('signature')), false, 'no key in hand, no adjudication — a missing capability is not an accusation')
  assert.deepEqual(unverifiable.problems, [])
  assert.equal(unverifiable.anchor?.headMatchesChain, true)
})

test('exchange round-trip: JSON.stringify -> JSON.parse preserves the verification exactly', async () => {
  const { bundle, signer } = await honestFullChain()
  const overTheWire = JSON.parse(JSON.stringify(bundle)) as ProofBundle
  const local = await verifyBundle(bundle, anchorVerifier(signer))
  const remote = await verifyBundle(overTheWire, anchorVerifier(signer))
  assert.deepEqual(remote, local)
  assert.deepEqual(local.problems, [])
  assert.equal(remote.anchor?.headMatchesChain, true)
  assert.equal(remote.baselineSelfAddressed, true)
  assert.equal(remote.chainMode, 'signed')
})

test('structural anomalies: unmanifested files, a missing evidence.jsonl, and an anchor without checkpoints are problems', async () => {
  const plain = buildBundle({ evidenceLog: '' }, 'ws', AT)

  const rogue = { ...plain, files: { ...plain.files, 'evil.txt': 'payload' } }
  const rogueVerdict = await verifyBundle(rogue)
  assert.equal(rogueVerdict.manifestOk, false)
  assert.ok(rogueVerdict.problems.some(p => p.includes('evil.txt')), `expected an unmanifested-file problem, got ${JSON.stringify(rogueVerdict.problems)}`)

  const gutted: ProofBundle = { manifest: { ...plain.manifest, files: [] }, files: {} }
  const guttedVerdict = await verifyBundle(gutted)
  assert.equal(guttedVerdict.manifestOk, false)
  assert.ok(guttedVerdict.problems.some(p => p.includes('missing evidence.jsonl')))

  const anchorOnly = buildBundle({
    evidenceLog: '',
    anchorJson: JSON.stringify({ v: 1, keyId: 'k', count: 1, head: 'bb', sig: 'sig:whatever', at: AT, workspaceKey: 'ws' }),
  }, 'ws', AT)
  const anchorVerdict = await verifyBundle(anchorOnly)
  assert.equal(anchorVerdict.anchor?.headMatchesChain, false)
  assert.ok(anchorVerdict.problems.some(p => p.includes('no checkpoint')))
})
