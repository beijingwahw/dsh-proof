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

import { buildBundle, verifyBundle, type ManifestTransparency, type ProofBundle } from '../src/app/bundle.ts'
import {
  CHAIN_MODES, CHECK_STATUSES, CLAIM_KINDS, GRADE_VALUES, PROTOCOL_VERSION, VERDICT_VALUES,
  appFingerprint, knownDialects,
} from '../src/app/protocol.ts'
import { EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { canonicalJson, sha256 } from '../src/core/hash.ts'
import { GENESIS_PREV, checkpointSignedData, walkChain } from '../src/core/trust.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { FakeClock, MemoryFs, spec } from './helpers.ts'

const LOG = '/ws/.proof/evidence.jsonl'
const BASE = '/ws/.proof/baseline.json'
const ANCHOR = '/trust/anchors/ws/anchor.json'
const AT = '2026-10-06T00:00:00.000Z'
const WS = snapshotWorkspace('head1', ['src/a.ts'])

/**
 * Deterministic stand-in for the host key: the attacker knows its keyId,
 * never its secret.
 *
 * Y-M-36 (v0.24): the fixture now HAS a secret. `sig = sha256(data)` with no
 * key material meant every "signature cannot be forged" assertion in this
 * file only ever pinned "a garbage string is refused" — an attacker who can
 * re-hash the public payload could have computed every signature in this
 * suite. Keying the digest off module-private material makes the forged
 * signatures the negative tests plant (sig 'FORGED', 'sig:forged', …)
 * stand for what they claim: bytes the key holder never produced.
 */
const FAKE_SIGNER_SECRET = 'fixture-host-key-material-never-published'
class FakeSigner implements SignerPort {
  readonly keyId = 'fake-key'
  async sign(data: string): Promise<string> { return `sig:${sha256(`${FAKE_SIGNER_SECRET}:${data}`)}` }
  async verify(data: string, signature: string): Promise<boolean> {
    return signature === `sig:${sha256(`${FAKE_SIGNER_SECRET}:${data}`)}`
  }
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
 * An honest, fully-armed and FULLY-COVERED bundle: signed chain (checkpoint
 * after each record, so `tailRecords` is 0), a self-addressed baseline, and
 * the anchor the last checkpoint wrote. Since v0.23 (X-H-04) an uncovered
 * tail is a problem, so "honest" for these fixtures means the exporter
 * checkpointed after its last record — exactly what the engine's verify()
 * boundary does before a child bundles its chain. The uncovered-tail shape
 * has its own adversarial test below.
 */
async function honestFullChain() {
  const fs = MemoryFs.of({})
  const { store, signer } = trustedStore(fs)
  const ev1 = evidence('c1')
  await store.append(ev1)
  await store.checkpoint()
  await store.append(evidence('c2'))
  await store.checkpoint()
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
  assert.equal(first.manifest.protocol, PROTOCOL_VERSION)
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

test('an empty evidence log is a problem, not a clean verdict; a real unsigned chain stays clean (v0.22 flip)', async () => {
  // The empty-log bless is FLIPPED (H-05 app-layer pillar): a bundle whose
  // log carries zero lines has nothing to verify, and "problems: []" let a
  // zero-evidence artifact ride `verifyBundle`'s clean verdict into
  // delegation submissions. The structural fields stay true — the bundle IS
  // well-formed — but the aggregate verdict must refuse to read as proof.
  const empty = buildBundle({ evidenceLog: '' }, 'ws', AT)
  const emptyVerdict = await verifyBundle(empty)
  assert.equal(emptyVerdict.protocolOk, true)
  assert.equal(emptyVerdict.manifestOk, true)
  assert.equal(emptyVerdict.chainMode, 'unsigned')
  assert.equal(emptyVerdict.tailRecords, 0)
  assert.deepEqual(emptyVerdict.malformedCheckpoints, [])
  assert.ok(
    emptyVerdict.problems.some(p => p.startsWith('evidence log is empty')),
    `the empty log must be named, got ${JSON.stringify(emptyVerdict.problems)}`,
  )

  // A real unsigned chain (records, no checkpoints) verifies exactly as
  // before: emptiness was the problem, not unsignedness.
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
  assert.equal(unsigned.checkpointSignature, undefined, 'no signatures on the chain: no adjudication to report')
})

test('full chain from a trusted store: signed mode, fully covered tail, anchor head matches', async () => {
  const { bundle, signer, baseline } = await honestFullChain()
  const verdict = await verifyBundle(bundle, anchorVerifier(signer))
  assert.equal(verdict.protocolOk, true)
  assert.equal(verdict.manifestOk, true)
  assert.deepEqual(verdict.problems, [])
  assert.equal(verdict.chainMode, 'signed')
  assert.equal(verdict.tailRecords, 0, 'the exporter checkpointed after its last record: nothing rides the tail')
  assert.equal('headLiars' in verdict, false, 'an honest chain never lies about a head — the field is absent, not zero')
  assert.deepEqual(verdict.chainBreaks, [])
  assert.deepEqual(verdict.corruptLines, [])
  assert.equal(verdict.anchor?.headMatchesChain, true)
  assert.equal(verdict.anchor?.count, 2, 'the anchor the second checkpoint wrote covers both records')
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
  const alien: ProofBundle = { ...bundle, manifest: { ...bundle.manifest, protocol: 'APP/9.9' as unknown as typeof PROTOCOL_VERSION } }
  const verdict = await verifyBundle(alien, anchorVerifier(signer))
  assert.equal(verdict.protocolOk, false)
  assert.equal(verdict.manifestOk, true, 'the files themselves are still exactly what the manifest describes')
  assert.deepEqual(verdict.digestMismatches, [])
  assert.ok(verdict.problems.some(p => p.includes('unsupported bundle protocol')))
})

test('without an anchorSigner the signature is skipped, never charged — but the keyless cross-checks fire (v0.22 flip)', async () => {
  const { bundle } = await honestFullChain()
  const honest = await verifyBundle(bundle)
  assert.deepEqual(honest.problems, [], 'an honest anchor still verifies clean without any key')
  assert.equal(honest.anchor?.headMatchesChain, true)
  assert.equal(honest.chainMode, 'signed-unverified', 'no key at hand: signatures exist but were not verified')
  assert.equal(honest.checkpointSignature, 'unverified')

  // The no-signer bless is FLIPPED (M-57): inflating the anchor count used
  // to be invisible without a key — a "missing capability is not an
  // accusation" that somehow also suppressed every contradiction the bundle
  // CAN prove on its own. The count the anchor claims and the count the
  // chain's own last checkpoint says are both in the bundle: they disagree,
  // and that disagreement is a problem now.
  const anchor = JSON.parse(bundle.files['anchor.json'] as string) as Record<string, unknown>
  const doctored = JSON.stringify({ ...anchor, count: 99 }, null, 2)
  const unverifiable = await verifyBundle(withFile(bundle, 'anchor.json', doctored))
  assert.equal(unverifiable.problems.some(p => p.includes('signature')), false, 'no key in hand, no signature adjudication — a missing capability is not an accusation')
  assert.ok(
    unverifiable.problems.some(p => p.includes('anchor count (99) does not match the last checkpoint')),
    `the keyless count cross-check must fire, got ${JSON.stringify(unverifiable.problems)}`,
  )
  assert.equal(unverifiable.anchor?.headMatchesChain, true, 'the head was not touched')

  // The same keyless floor catches a workspaceKey swap and a foreign keyId
  // on the anchor — contradictions no signature was ever needed to see.
  const swappedKey = JSON.stringify({ ...anchor, workspaceKey: 'DIFFERENT-WORKSPACE' }, null, 2)
  const swapped = await verifyBundle(withFile(bundle, 'anchor.json', swappedKey))
  assert.ok(swapped.problems.some(p => p.includes('anchor workspaceKey') && p.includes('DIFFERENT-WORKSPACE')))

  const foreignAnchor = JSON.stringify({ ...anchor, keyId: 'foreign-key' }, null, 2)
  const foreign = await verifyBundle(withFile(bundle, 'anchor.json', foreignAnchor))
  assert.ok(foreign.problems.some(p => p.includes('anchor keyId') && p.includes('foreign-key')))
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

// ---------------------------------------------------------------------------
// transparency manifest records (v0.18.0) — structural adjudication only.
//
// The bundle verifier never sees the log the record points at, so these
// tests hold it to exactly what it CAN judge from the manifest alone:
// shapes, ranges, and the proof-length bound. Leaf-hash truth, inclusion
// and consistency are the PTL CLI's job (28-ptl-cli) — the line between
// the two is deliberate and load-bearing.
// ---------------------------------------------------------------------------

/** A structurally sound publication record over a one-entry log. */
function soundTransparency(): ManifestTransparency {
  return {
    logId: 'operator-key-id',
    sequence: 0,
    leafHash: sha256('leaf'),
    publishedHead: { logId: 'operator-key-id', treeSize: 1, root: sha256('root'), at: AT, sig: 'sig:head' },
    inclusionProof: [],
  }
}

/** A bundle whose manifest carries an arbitrary (possibly forged) transparency value. */
function withTransparency(value: unknown): ProofBundle {
  const sound = buildBundle({ evidenceLog: '' }, 'ws', AT, { transparency: soundTransparency() })
  return { manifest: { ...sound.manifest, transparency: value as ManifestTransparency }, files: sound.files }
}

test('transparency: a sound record stamps through deterministically; a record over a chain with no signed checkpoint is refused (v0.22 flip)', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  const log = await fs.readFile(LOG)
  assert.ok(typeof log === 'string')
  const record = soundTransparency()
  const first = buildBundle({ evidenceLog: log }, 'ws', AT, { transparency: record })
  const second = buildBundle({ evidenceLog: log }, 'ws', AT, { transparency: record })
  assert.equal(JSON.stringify(first), JSON.stringify(second), 'extras make the build no less deterministic')
  assert.deepEqual(
    Object.keys(first.manifest),
    ['protocol', 'appFingerprint', 'workspaceKey', 'createdAt', 'files', 'transparency'],
    'transparency appends at a fixed position, after the header and files',
  )
  assert.deepEqual(first.manifest.transparency, record)
  // The fabricated-record bless is FLIPPED (M-59/H-05 territory): this
  // chain carries NO signed checkpoint — the store had no signer, nothing
  // was ever publishable — so a transparency record claiming a publication
  // is a contradiction the bundle itself proves. Structure alone still
  // stamps 'recorded'; the aggregate verdict refuses.
  const verdict = await verifyBundle(first)
  assert.equal(verdict.transparency, 'recorded', 'the record is structurally sound — that judgment stays structural')
  assert.ok(
    verdict.problems.some(p => p.includes('transparency record but the bundled chain has no signed checkpoint')),
    `a record without a publishable chain must be named, got ${JSON.stringify(verdict.problems)}`,
  )
})

test('transparency: every malformed shape is refused with a named reason', async () => {
  const cases: [string, unknown][] = [
    ['leafHash is not a digest', { ...soundTransparency(), leafHash: 'not-hex' }],
    ['sequence is negative', { ...soundTransparency(), sequence: -1 }],
    ['sequence is fractional', { ...soundTransparency(), sequence: 1.5 }],
    ['sequence is a string', { ...soundTransparency(), sequence: '0' }],
    ['proof is longer than a one-leaf tree can explain', {
      ...soundTransparency(),
      inclusionProof: [sha256('a'), sha256('b')],
    }],
    ['proof is not an array', { ...soundTransparency(), inclusionProof: 'nope' }],
    ['publishedHead is missing its root', {
      ...soundTransparency(),
      publishedHead: { logId: 'k', treeSize: 1, at: AT, sig: 's' },
    }],
    ['publishedHead treeSize is zero', {
      ...soundTransparency(),
      publishedHead: { logId: 'k', treeSize: 0, root: sha256('r'), at: AT, sig: 's' },
    }],
    ['publishedHead root is not a digest', {
      ...soundTransparency(),
      publishedHead: { logId: 'k', treeSize: 1, root: 'zz', at: AT, sig: 's' },
    }],
    ['publishedHead sig is empty', {
      ...soundTransparency(),
      publishedHead: { logId: 'k', treeSize: 1, root: sha256('r'), at: AT, sig: '' },
    }],
    ['logId is empty', { ...soundTransparency(), logId: '' }],
    ['record is not an object', 'totally-transparent'],
  ]
  for (const [name, forged] of cases) {
    const verdict = await verifyBundle(withTransparency(forged))
    assert.equal(verdict.transparency, 'malformed', name)
    assert.ok(
      verdict.problems.some(p => p.startsWith('malformed transparency record: ')),
      `${name} must name its reason, got ${JSON.stringify(verdict.problems)}`,
    )
  }
})

test('transparency: no record means no field and byte-identical behaviour', async () => {
  const fs = MemoryFs.of({})
  const { store, signer } = trustedStore(fs)
  await store.append(evidence('c1'))
  const log = await fs.readFile(LOG)
  assert.ok(typeof log === 'string')
  const plain = buildBundle({ evidenceLog: log }, 'ws', AT)
  const verdict = await verifyBundle(plain, anchorVerifier(signer))
  assert.equal(verdict.transparency, undefined)
  assert.equal('transparency' in verdict, false, 'the field is absent, not merely falsy')
  assert.deepEqual(verdict.problems, [])
  // The extras parameter is optional: omitting it (or passing {}) keeps the
  // exact bytes every pre-0.18.0 producer emitted.
  const withEmptyExtras = buildBundle({ evidenceLog: log }, 'ws', AT, {})
  assert.equal(JSON.stringify(withEmptyExtras), JSON.stringify(plain))
})

// ---------------------------------------------------------------------------
// v0.22 adversarial additions — forged checkpoints, closed manifest layout,
// transparency bounds, dialect negotiation.
// ---------------------------------------------------------------------------

/** Re-chain a log's lines so every `prev` links again (the forger holds the pen). */
function rechain(lines: string[]): string[] {
  let prev = GENESIS_PREV
  return lines.map(line => {
    const envelope = JSON.parse(line) as Record<string, unknown>
    envelope.prev = prev
    const rewritten = JSON.stringify(envelope)
    prev = sha256(rewritten)
    return rewritten
  })
}

test('v0.22: a fully re-chained log with a lying-count checkpoint is refused, not laundered', async () => {
  const { bundle } = await honestFullChain()
  const original = (bundle.files['evidence.jsonl'] as string).split('\n').filter(l => l.length > 0)
  // Rewrite the whole log with this package's own hashing, then stamp a
  // checkpoint whose count (`1e999` parses to Infinity) the walk refutes —
  // the exact laundering shape core/trust built malformedCheckpoints for.
  const walk0 = walkChain(original)
  const forgedCheckpoint = {
    v: 2, kind: 'checkpoint', at: AT,
    payload: { count: 999, head: sha256('forged-head'), workspaceKey: 'ws', at: AT },
    sig: 'FORGED', keyId: 'fake-key',
  }
  const lines = [...original.slice(0, walk0.checkpoints[0]?.index ?? original.length), JSON.stringify(forgedCheckpoint)]
  const doctored = `${rechain(lines).join('\n')}\n`
  const verdict = await verifyBundle(withFile(bundle, 'evidence.jsonl', doctored), anchorVerifier(new FakeSigner()))
  assert.deepEqual(verdict.malformedCheckpoints.length, 1, 'the lying count is surfaced, not swallowed')
  assert.ok(
    verdict.problems.some(p => p.startsWith('malformed checkpoint at line')),
    `the malformed checkpoint must be a problem, got ${JSON.stringify(verdict.problems)}`,
  )
  assert.ok(verdict.problems.some(p => p.includes('checkpoint signature invalid') || p.includes('malformed checkpoint')))
})

test('v0.22: a garbage checkpoint signature under the held key is refuted; without the key it is honestly unverified', async () => {
  const { bundle, signer } = await honestFullChain()
  const original = (bundle.files['evidence.jsonl'] as string).split('\n').filter(l => l.length > 0)
  // Keep the honest keyId, replace only the sig bytes, then re-chain the
  // remainder (the forger holds the pen): signature present, signature
  // false, chain intact. The re-chain re-digests the first checkpoint's
  // line, so the SECOND checkpoint's payload.head — still naming the
  // pre-forgery position — becomes a keyless head-liar on top.
  const lines = original.map(line => line.replace(/"sig":"sig:[0-9a-f]+"/, '"sig":"sig:forged"'))
  assert.notEqual(lines[1], original[1], 'the edit must change the checkpoint sig')
  const doctored = `${rechain(lines).join('\n')}\n`
  const refuted = await verifyBundle(withFile(bundle, 'evidence.jsonl', doctored), anchorVerifier(signer))
  assert.equal(refuted.checkpointSignature, 'invalid')
  assert.ok(refuted.problems.some(p => p.includes('checkpoint signature invalid at line')), JSON.stringify(refuted.problems))
  assert.deepEqual(refuted.chainBreaks, [], 'the forgery is re-chained: the signature and head-liar checks catch it')

  // Same forged bytes, no key at hand: a missing capability is not an
  // accusation — but the re-chained log's last checkpoint head-lies about
  // its position, and THAT contradiction needs no key to name (v0.23).
  const unverified = await verifyBundle(withFile(bundle, 'evidence.jsonl', doctored))
  assert.equal(unverified.checkpointSignature, 'unverified')
  assert.equal(unverified.chainMode, 'signed-unverified', 'presence of sig fields is not proof of them')
  assert.equal(unverified.headLiars, 1, 'the second checkpoint declares a head from the pre-forgery chain')
  assert.ok(
    unverified.problems.some(p => p.includes('checkpoint head does not match the walked chain position at line 3')),
    `the keyless head-liar must be named, got ${JSON.stringify(unverified.problems)}`,
  )
  assert.equal(
    unverified.problems.some(p => p.includes('signature')),
    false,
    'no key in hand: no signature adjudication of any kind',
  )
})

test('v0.22: an honest signed chain with the key at hand reports verified signatures and mode signed', async () => {
  const { bundle, signer } = await honestFullChain()
  const verdict = await verifyBundle(bundle, anchorVerifier(signer))
  assert.equal(verdict.checkpointSignature, 'verified')
  assert.equal(verdict.chainMode, 'signed')
  assert.deepEqual(verdict.problems, [])
  assert.deepEqual(verdict.malformedCheckpoints, [])
})

test('v0.22: the manifest layout is closed — traversal, absolute, UNC and duplicate paths are refused', async () => {
  const { bundle } = await honestFullChain()
  const base = buildBundle({ evidenceLog: bundle.files['evidence.jsonl'] ?? '' }, 'ws', AT)
  const rogueEntry = (path: string): ProofBundle => ({
    manifest: {
      ...base.manifest,
      files: [...base.manifest.files, { path, sha256: sha256('x'), bytes: 1 }],
    },
    files: { ...base.files, [path]: 'x' },
  })
  for (const path of ['../../etc/cron.d/evil', '/etc/passwd', 'C:/Windows/evil', '\\\\server\\share\\evil', 'sub/dir/evil.txt', 'evil.txt']) {
    const verdict = await verifyBundle(rogueEntry(path))
    assert.equal(verdict.manifestOk, false, path)
    assert.ok(
      verdict.problems.some(p => p.includes('outside the bundle layout') && p.includes(path)),
      `${path} must be named as out-of-layout, got ${JSON.stringify(verdict.problems)}`,
    )
  }
  // A duplicate of a legal name is just as refused: two entries for one file
  // is a layout violation no unpacker should have to arbitrate.
  const duplicated = await verifyBundle({
    manifest: {
      ...base.manifest,
      files: [...base.manifest.files, { ...base.manifest.files[0]! }],
    },
    files: base.files,
  })
  assert.equal(duplicated.manifestOk, false)
  assert.ok(duplicated.problems.some(p => p.includes('more than once')))
})

test('v0.22: transparency records with an out-of-tree sequence or disagreeing logIds are malformed', async () => {
  const beyond = withTransparency({ ...soundTransparency(), sequence: 999999 })
  const beyondVerdict = await verifyBundle(beyond)
  assert.equal(beyondVerdict.transparency, 'malformed')
  assert.ok(beyondVerdict.problems.some(p => p.includes('sequence 999999 is not below the published tree size 1')))

  const split = withTransparency({ ...soundTransparency(), logId: 'log-B' })
  const splitVerdict = await verifyBundle(split)
  assert.equal(splitVerdict.transparency, 'malformed')
  assert.ok(splitVerdict.problems.some(p => p.includes('record logId') && p.includes('publishedHead.logId')))

  const nonHex = withTransparency({ ...soundTransparency(), inclusionProof: ['zz'.repeat(32)] })
  const nonHexVerdict = await verifyBundle(nonHex)
  assert.equal(nonHexVerdict.transparency, 'malformed')
  assert.ok(nonHexVerdict.problems.some(p => p.includes('inclusionProof must be an array of 64-hex digest strings')))
})

test('v0.22: a real APP/1.3 bundle verifies under fingerprint-match acceptance, flagged as legacy', async () => {
  const { bundle, signer } = await honestFullChain()
  // The exact v0.20-era dialect pair: APP/1.3 with the fingerprint that
  // era's constants digested to (recomputed from the pinned material — the
  // same derivation protocol.ts's knownDialects uses).
  const app13Fingerprint = sha256(canonicalJson({
    name: 'agent-proof-protocol',
    version: 'APP/1.3',
    verdict: VERDICT_VALUES,
    grade: GRADE_VALUES,
    chainModes: CHAIN_MODES,
    claimKinds: CLAIM_KINDS,
    checkStatuses: CHECK_STATUSES,
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }))
  const legacy: ProofBundle = {
    manifest: { ...bundle.manifest, protocol: 'APP/1.3' as typeof bundle.manifest.protocol, appFingerprint: app13Fingerprint },
    files: bundle.files,
  }
  const verdict = await verifyBundle(legacy, anchorVerifier(signer))
  assert.equal(verdict.protocolOk, true, 'a known ancestor dialect is accepted by fingerprint')
  assert.equal(verdict.legacyProtocol, true, 'and flagged, so readers see which dialect they verified under')
  assert.deepEqual(verdict.problems, [], 'the bundle format never changed across the genealogy: full verification applies')
  assert.equal(verdict.chainMode, 'signed')
  assert.equal(verdict.checkpointSignature, 'verified')
  const known = knownDialects().find(d => d.version === 'APP/1.3')
  assert.equal(known?.fingerprint, app13Fingerprint, 'protocol.ts recomputes the same table this test derives')

  // A CURRENT version string wearing a fingerprint that version never had
  // is incoherent, not legacy: refused with the bundle's fingerprint and
  // the current one both on the record (C3-H2's named-refusal demand).
  const incoherent: ProofBundle = {
    manifest: { ...bundle.manifest, appFingerprint: app13Fingerprint },
    files: bundle.files,
  }
  const refused = await verifyBundle(incoherent)
  assert.equal(refused.protocolOk, false)
  assert.equal(refused.legacyProtocol, undefined)
  const refusal = refused.problems.find(p => p.includes('unsupported bundle protocol'))
  assert.ok(refusal !== undefined, JSON.stringify(refused.problems))
  assert.ok(refusal.includes(app13Fingerprint), 'the refusal names the bundle fingerprint')
  assert.ok(refusal.includes('APP/1.4'), 'the refusal names the current dialect')
  assert.ok(refusal.includes('re-publish'), 'the refusal gives the migration path')
})

// ---------------------------------------------------------------------------
// v0.23 adversarial additions — signature replay (X-H-03), the uncovered
// tail (X-H-04), the options-object signer surface (X-H-02), throwing key
// implementations (W10-L8), record-empty logs (W10-M5) and the stripped
// final keyId (W10-L9).
//
// The common thread of the v0.22 round's findings: the signature-verification
// code existed and nobody fed it, and the walk-level facts it would have
// needed (expectedHead, the tail, the record count) were reported as silent
// fields while `problems` — the only channel consumers gate on — stayed
// empty. These tests pin the opposite spelling of every one of those.
// ---------------------------------------------------------------------------

test('v0.23 (X-H-03): a replayed signed checkpoint verifies cryptographically and is still refused', async () => {
  const { bundle, signer } = await honestFullChain()
  const original = (bundle.files['evidence.jsonl'] as string).split('\n').filter(l => l.length > 0)
  // [ev1, cp1, ev2, cp2]. cp1's signature is GENUINE over cp1.payload — the
  // forger never holds the key. Replant cp1 after a different record: the
  // payload (and its signature) are untouched, the chain re-links, the
  // self-reported count even still matches (one record before it) — only
  // the walk's expectedHead knows the head it declares belongs to another
  // position of another chain.
  const cp1 = original[1] as string
  const displacedRecord = original[2] as string
  const doctored = `${rechain([displacedRecord, cp1]).join('\n')}\n`
  const replayed = buildBundle({ evidenceLog: doctored }, 'ws', AT)

  // With the key: the signature itself verifies — and that is exactly the
  // replay case. A verified signature over a planted position is charged
  // invalid, never mistaken for proof of this chain.
  const withKey = await verifyBundle(replayed, anchorVerifier(signer))
  assert.equal(withKey.headLiars, 1)
  assert.ok(
    withKey.problems.some(p => p.includes('checkpoint signature replays at line 1')),
    `the replay must be charged against the adjudication, got ${JSON.stringify(withKey.problems)}`,
  )
  assert.equal(withKey.checkpointSignature, 'invalid', 'verified-but-lied is invalid, not verified')

  // Without the key: the capability gap keeps the adjudication honest
  // (`unverified`, never an accusation) — but the head-liar contradiction
  // is keyless, and it is named regardless.
  const keyless = await verifyBundle(replayed)
  assert.equal(keyless.checkpointSignature, 'unverified')
  assert.equal(keyless.chainMode, 'signed-unverified')
  assert.equal(keyless.headLiars, 1)
  assert.ok(keyless.problems.some(p => p.includes('checkpoint head does not match the walked chain position at line 1')))
  assert.ok(
    keyless.problems.some(p => p.includes('checkpoint signature replays')) === false,
    'no key, no crypto charge — the keyless charge stands on the walk alone',
  )
})

test('v0.23 (X-H-04): records appended behind the last checkpoint are a problem, not a footnote', async () => {
  const { bundle, signer } = await honestFullChain()
  // The honest exporter checkpoints after its last record: covered, clean.
  const clean = await verifyBundle(bundle, anchorVerifier(signer))
  assert.equal(clean.tailRecords, 0)
  assert.deepEqual(clean.problems, [])

  // The piggyback: append one protocol-shaped, correctly chained record
  // AFTER the final signed checkpoint. Every digest walks, every signature
  // verifies — the tail was simply never covered, and a `problems`-gating
  // consumer (the delegation path) used to read exactly this as clean.
  const lines = (bundle.files['evidence.jsonl'] as string).split('\n').filter(l => l.length > 0)
  const piggyback = JSON.stringify({
    v: 2,
    kind: 'evidence',
    at: AT,
    prev: sha256(lines[lines.length - 1] as string),
    payload: { forged: 'rides behind the signed checkpoint' },
  })
  const doctored = `${[...lines, piggyback].join('\n')}\n`
  const verdict = await verifyBundle(withFile(bundle, 'evidence.jsonl', doctored), anchorVerifier(signer))
  assert.equal(verdict.tailRecords, 1, 'the field keeps counting the tail (retained, not replaced)')
  assert.ok(
    verdict.problems.some(p => p.includes('1 record(s) ride behind the last checkpoint, unverifiable by it')),
    `the uncovered tail must be a problem, got ${JSON.stringify(verdict.problems)}`,
  )
  assert.equal(verdict.checkpointSignature, 'verified', 'the attack never touches the signatures — and still is not clean')

  // A checkpoint-less chain keeps its v0.22 semantics: `tailRecords` counts
  // every record, but `unsigned` mode already says no checkpoint vouches
  // for any of them — there is no covered prefix to launder through, so the
  // tail charge stays scoped to chains that have a checkpoint.
  const fs = MemoryFs.of({})
  const plainStore = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  await plainStore.append(evidence('u1'))
  const plainLog = await fs.readFile(LOG)
  assert.ok(typeof plainLog === 'string')
  const unsignedTail = await verifyBundle(buildBundle({ evidenceLog: plainLog }, 'ws', AT))
  assert.equal(unsignedTail.chainMode, 'unsigned')
  assert.equal(unsignedTail.tailRecords, 1)
  assert.deepEqual(unsignedTail.problems, [], 'unsignedness was never the problem (v0.22 pin), and still is not')
})

test('v0.23 (X-H-02): the signer may arrive as an options object — the three-state is reachable, and never crashable', async () => {
  const { bundle, signer } = await honestFullChain()
  const viaOptions = await verifyBundle(bundle, { anchorSigner: anchorVerifier(signer) })
  const positional = await verifyBundle(bundle, anchorVerifier(signer))
  assert.deepEqual(viaOptions, positional, 'both spellings of the argument adjudicate identically')
  assert.equal(viaOptions.checkpointSignature, 'verified')

  // Half-supplied and malformed options degrade to "no signer" — a missing
  // capability, never a crash and never a false charge.
  const noSignerInside = await verifyBundle(bundle, { anchorSigner: undefined })
  assert.equal(noSignerInside.checkpointSignature, 'unverified')
  assert.equal(noSignerInside.chainMode, 'signed-unverified')
  assert.deepEqual(noSignerInside.problems, [])
  const malformed = await verifyBundle(bundle, { keyId: 42, verify: 'not-a-function' } as unknown as { anchorSigner: never })
  assert.equal(malformed.checkpointSignature, 'unverified', 'a malformed capability object is treated as absent')
  assert.deepEqual(malformed.problems, [])

  // A key that names a keyId the chain never used verifies nothing: the
  // honest answer is unverified (capability gap), and the honest chain
  // still reads clean — a foreign signer must never fabricate a charge.
  const foreign = await verifyBundle(bundle, { anchorSigner: { keyId: 'some-other-key', verify: async () => false } })
  assert.equal(foreign.checkpointSignature, 'unverified')
  assert.deepEqual(foreign.problems, [])
})

test('v0.23 (W10-L8): a throwing key implementation is a failed verification, never a crashed auditor', async () => {
  const { bundle } = await honestFullChain()
  const explosive = {
    keyId: 'fake-key',
    verify: async (): Promise<boolean> => { throw new Error('key daemon exploded') },
  }
  // Checkpoint side: both adjudicable checkpoints "fail" via the throw —
  // charged invalid, promise intact.
  const checkpointSide = await verifyBundle(bundle, explosive)
  assert.equal(checkpointSide.checkpointSignature, 'invalid')
  assert.ok(
    checkpointSide.problems.some(p => p.includes('checkpoint signature invalid at line')),
    JSON.stringify(checkpointSide.problems),
  )
  // Anchor side: the honest anchor is also under the explosive key, so the
  // anchor charge fires the same way — same discipline as EvidenceStore's
  // audit, which never lets a hostile signer reject the audit itself.
  assert.ok(checkpointSide.problems.includes('anchor signature invalid'))
})

test('v0.23 (W10-M5): a structurally intact, record-empty log is not verifiable evidence — even signed', async () => {
  // The canonical empty shape: one well-formed `count: 0` checkpoint over
  // the genesis prev. It chains, walks, counts honestly — and carries zero
  // evidence or marker records. Structure without content must not read as
  // a clean verdict.
  const payload = { count: 0, head: GENESIS_PREV, workspaceKey: 'ws', at: AT }
  const unsignedLine = JSON.stringify({ v: 2, kind: 'checkpoint', at: AT, prev: GENESIS_PREV, payload })
  const unsigned = await verifyBundle(buildBundle({ evidenceLog: `${unsignedLine}\n` }, 'ws', AT))
  assert.equal(unsigned.chainMode, 'unsigned')
  assert.deepEqual(unsigned.malformedCheckpoints, [], 'count 0 over 0 records is structurally honest')
  assert.equal(unsigned.tailRecords, 0)
  assert.equal(unsigned.headLiars, undefined, 'the head names genesis truthfully — emptiness is the charge, not a lie')
  assert.ok(
    unsigned.problems.some(p => p.startsWith('evidence log carries no records')),
    `the record-empty log must be named, got ${JSON.stringify(unsigned.problems)}`,
  )
  assert.ok(unsigned.problems.some(p => p.startsWith('evidence log is empty')) === false,
    'lines exist: the empty-log problem does not double-fire')

  // Sharper still: the SAME empty chain, genuinely signed by the held key.
  // The signature verifies — and a signature over nothing is not evidence.
  const signer = new FakeSigner()
  const sig = await signer.sign(checkpointSignedData(payload))
  const signedLine = JSON.stringify({
    v: 2, kind: 'checkpoint', at: AT, prev: GENESIS_PREV, payload, sig, keyId: signer.keyId,
  })
  const signed = await verifyBundle(buildBundle({ evidenceLog: `${signedLine}\n` }, 'ws', AT), anchorVerifier(signer))
  assert.equal(signed.checkpointSignature, 'verified', 'the cryptographer did their part')
  assert.equal(signed.chainMode, 'signed')
  assert.ok(
    signed.problems.some(p => p.startsWith('evidence log carries no records')),
    `and the verdict still refuses to read it as proof, got ${JSON.stringify(signed.problems)}`,
  )
})

test('v0.23 (W10-L9): a stripped final keyId cannot hide a foreign anchor key from the chain\'s own signature', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()
  const lines = ((await fs.readFile(LOG)) as string).split('\n').filter(l => l.length > 0)
  // [ev1, cp1(signed, keyId fake-key)]. Append an honestly-shaped UNSIGNED
  // final checkpoint with NO keyId field: the last checkpoint the anchor
  // cross-check used to consult carries no identity at all.
  const lastDigest = sha256(lines[lines.length - 1] as string)
  const unsignedFinal = JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: AT,
    prev: lastDigest,
    payload: { count: 1, head: lastDigest, workspaceKey: 'ws', at: AT },
  })
  const doctoredLog = `${[...lines, unsignedFinal].join('\n')}\n`
  const anchorOver = (keyId: string): string => JSON.stringify({
    v: 1, keyId, count: 1, head: lastDigest, sig: 'sig:whatever', at: AT, workspaceKey: 'ws',
  })

  // The anchor names a FOREIGN key; the chain's only signed checkpoint
  // names the real one. Pre-v0.23 the null final keyId blanked the
  // cross-check; now the signature-bearing checkpoint speaks for the chain.
  const foreign = await verifyBundle(buildBundle(
    { evidenceLog: doctoredLog, anchorJson: anchorOver('foreign-key') },
    'ws',
    AT,
  ))
  assert.equal(foreign.anchor?.headMatchesChain, true, 'the head and count agree — keyId is the whole attack')
  assert.equal(foreign.tailRecords, 0)
  assert.ok(
    foreign.problems.some(p => p.includes('anchor keyId') && p.includes('foreign-key') && p.includes('fake-key')),
    `the earlier signed checkpoint's keyId must arbitrate, got ${JSON.stringify(foreign.problems)}`,
  )

  // Negative control: an anchor naming the key the chain actually signed
  // under stays clean — the fallback must not fabricate charges either.
  const honestKey = await verifyBundle(buildBundle(
    { evidenceLog: doctoredLog, anchorJson: anchorOver('fake-key') },
    'ws',
    AT,
  ))
  assert.deepEqual(honestKey.problems, [], 'agreement with the chain\'s signed identity is not a contradiction')
})
