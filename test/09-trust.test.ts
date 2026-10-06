/**
 * TRUST — tamper-evidence against the log's own writer.
 *
 * The adversary in these tests is the agent itself: it can read and write
 * every file in the workspace, and it can use the package's own hashing
 * functions. What it cannot do is produce a signature for a key it never
 * sees, or move an anchor that lives outside its sandbox.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace, createVerifiedView } from '../src/core/evidence.ts'
import { GENESIS_PREV, checkpointSignedData, lineDigest, walkChain } from '../src/core/trust.ts'
import { addressOf, sha256 } from '../src/core/hash.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { ProofEngine } from '../src/engine.ts'
import { NodeEd25519Signer, NodeFsPort } from '../src/node-ports.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs, spec } from './helpers.ts'

const LOG = '/ws/.proof/evidence.jsonl'
const BASE = '/ws/.proof/baseline.json'
const ANCHOR = '/trust/anchors/ws/anchor.json'
const WS = snapshotWorkspace('head1', ['src/a.ts'])

/** Deterministic stand-in for the host key: the attacker knows its keyId, never its secret. */
class FakeSigner implements SignerPort {
  readonly keyId = 'fake-key'
  async sign(data: string): Promise<string> { return `sig:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> { return signature === `sig:${sha256(data)}` }
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

function evidence(id: string, status: 'pass' | 'fail' = 'pass') {
  return makeEvidence(spec({ id }), { status, exitCode: status === 'pass' ? 0 : 1, durationMs: 5, output: `${status}\n` }, WS, new FakeClock())
}

test('signed flow: append, checkpoint, audit clean with an anchor on disk', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  const audit = await store.audit()
  assert.equal(audit.ok, true)
  assert.equal(audit.chain.mode, 'signed')
  assert.equal(audit.chain.checkpoints, 1)
  assert.equal(audit.chain.rewind, false)
  assert.equal(audit.chain.tailRecords, 0)
  assert.notEqual(await fs.readFile(ANCHOR), undefined, 'the high-water anchor must exist outside the workspace')
})

test('editing a record mid-log breaks the hash chain', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2'))
  assert.equal((await store.audit()).ok, true)

  // Rewrite line 1's payload, keeping valid JSON: the next line's `prev` no longer matches.
  const lines = await fs.readLines(LOG)
  const first = JSON.parse(lines[0] as string) as { payload: { status: string } }
  first.payload.status = 'pass'
  lines[0] = JSON.stringify(first)
  fs.mutate(LOG, `${lines.join('\n')}\n`)

  const audit = await new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner(), anchorPath: ANCHOR }).audit()
  assert.equal(audit.ok, false)
  assert.ok(audit.chain.breaks.length > 0, `expected chain breaks, got ${JSON.stringify(audit.chain)}`)
})

test('THE ADVERSARY: full rewrite with recomputed addresses cannot defeat the anchor', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2', 'fail'))
  await store.checkpoint()
  assert.equal((await store.audit()).ok, true)

  // The agent rewrites history: it knows addressOf, lineDigest and GENESIS_PREV —
  // everything this package exports. It flips both failures to passes and
  // rebuilds a perfectly chained, perfectly self-addressed log from genesis.
  // The one thing it cannot manufacture is a signed checkpoint.
  const lines = await fs.readLines(LOG)
  const payloads = lines
    .map(line => JSON.parse(line) as { kind: string; payload: Record<string, unknown> })
    .filter(envelope => envelope.kind === 'evidence')
    .map(envelope => envelope.payload)
  const forged = payloads.map((payload) => {
    const { evidenceId, ...rest } = payload
    const altered = { ...rest, status: 'pass' } as Record<string, unknown>
    return { ...altered, evidenceId: addressOf(altered) }
  })
  let prev = GENESIS_PREV
  const rebuilt = forged.map((payload) => {
    const line = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
  fs.mutate(LOG, `${rebuilt.join('\n')}\n`)

  const verifier = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner(), anchorPath: ANCHOR })
  const audit = await verifier.audit()
  assert.equal(audit.chain.rewind, true, 'the anchor remembers a checkpoint the rewritten log no longer contains')
  assert.equal(audit.ok, false)
  assert.equal(audit.total, 2)
})

test('rewind: truncating the log below the anchored checkpoint is detected', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  const lines = await fs.readLines(LOG)
  fs.mutate(LOG, `${lines[0] as string}\n`)

  const audit = await new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner(), anchorPath: ANCHOR }).audit()
  assert.equal(audit.chain.rewind, true)
  assert.equal(audit.ok, false)
})

test('baseline substitution is caught by the digest recorded in the chain', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  const baseline = buildBaseline([evidence('c1')], WS, new FakeClock())
  await store.saveBaseline(baseline)
  assert.equal((await store.audit()).ok, true)

  // The agent swaps in a doctored baseline (a different merkle root).
  fs.mutate(BASE, JSON.stringify({ ...baseline, root: '0'.repeat(64) }, null, 2))

  const audit = await new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner(), anchorPath: ANCHOR }).audit()
  assert.equal(audit.chain.baselineTampered, true)
  assert.equal(audit.ok, false)
})

test('legacy v1 logs remain readable; an anchorless audit of one no longer passes ok', async () => {
  const fs = MemoryFs.of({})
  const ev = evidence('c1')
  fs.mutate(LOG, `${JSON.stringify({ v: 1, kind: 'evidence', at: '2026-09-01T00:00:00.000Z', payload: ev })}\n`)
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  const audit = await store.audit()
  assert.equal(audit.chain.mode, 'legacy')
  assert.equal(audit.total, 1)
  // L-A1-11 (v0.22): a v1-only chain carries no prev linkage at all — nothing
  // integrity-shaped for an anchorless audit to pass. It stays fully readable
  // (that is what `legacy` mode promises); what it no longer gets is `ok`
  // vouching for bytes the chain never linked. The old blessing let a fully
  // downgraded (v1-exempt) rewrite audit green whenever no anchor existed.
  assert.equal(audit.ok, false, 'readable is not the same as verified — legacy mode names the gap, ok must not paper over it')
  // A v2 append after legacy lines chains from the physically previous line —
  // and once a v2 line exists the chain HAS linkage an audit can pass again.
  await store.append(evidence('c2'))
  const after = await store.audit()
  assert.equal(after.ok, true)
  assert.equal(after.total, 2)
})

test('checkpoint cadence fires without an explicit call', async () => {
  const fs = MemoryFs.of({})
  const signer = new FakeSigner()
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => signer,
    anchorPath: ANCHOR,
    checkpointEvery: 2,
  })
  await store.append(evidence('c1'))
  assert.equal((await store.audit()).chain.checkpoints, 0)
  await store.append(evidence('c2'))
  const audit = await store.audit()
  assert.equal(audit.chain.checkpoints, 1, 'cadence must checkpoint after every N records')
  assert.equal(audit.ok, true)
})

test('concurrent appends never break the hash chain (single-flight writes)', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  // All three racers read the same tail before any of them writes; without
  // serialized write sections, two of the three `prev` values would point at
  // a tail the log has already moved past.
  await Promise.all([
    store.append(evidence('c1')),
    store.append(evidence('c2')),
    store.mark('session/start', { who: 'test' }),
  ])
  const audit = await store.audit()
  assert.deepEqual(audit.chain.breaks, [], `chain breaks at: ${JSON.stringify(audit.chain.breaks)}`)
  assert.equal(audit.total, 2, 'both evidence records landed (the marker chains through but is not evidence)')
  assert.equal(audit.ok, true)
})

test('a failed write does not deadlock the queue behind it', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  const boom = new Error('disk full')
  const original = fs.appendLine.bind(fs)
  let armed = true
  fs.appendLine = async (path: string, line: string) => {
    if (armed) { armed = false; throw boom }
    return original(path, line)
  }
  await assert.rejects(() => store.append(evidence('c1')), /disk full/)
  await store.append(evidence('c2')) // must not hang behind the rejected op
  const audit = await store.audit()
  assert.equal(audit.total, 1)
  assert.deepEqual(audit.chain.breaks, [])
})

test('append idempotency survives a restart: existing addresses are re-indexed from the log', async () => {
  const fs = MemoryFs.of({})
  const first = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  const ev = evidence('c1')
  await first.append(ev)

  // A second instance over the same log stands for a restarted process: the
  // in-memory cache is gone, but the one full scan the first mutation already
  // does re-indexes every address on disk — replaying the same evidence is
  // still a no-op, never a duplicate line.
  const second = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  await second.append(ev)
  assert.equal((await second.all()).length, 1)
  const audit = await second.audit()
  assert.equal(audit.total, 1)
  assert.equal(audit.ok, true)
})

test('a torn tail line (crash mid-append) is recovered, and the repair is a fact on the chain', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()
  assert.equal((await store.audit()).ok, true)

  // Kill the writer mid-line: the physical end of the log is a JSON prefix.
  const torn = '{"v":2,"kind":"evidence","at":"2026-10-05T00:00:00.000Z","prev":"deadbeef","payl'
  const lines = await fs.readLines(LOG)
  fs.mutate(LOG, `${lines.join('\n')}\n${torn}`)
  assert.equal(
    (await new EvidenceStore(fs, LOG, BASE, new FakeClock()).audit()).ok, false,
    'before repair the torn tail fails audit (audit is read-only and must not self-heal)',
  )

  // A fresh store's first mutation triggers the recovery inside the queue.
  const revived = trustedStore(fs).store
  await revived.append(evidence('c2'))

  const audit = await revived.audit()
  assert.equal(audit.ok, true, 'recovery must leave a clean, unbroken chain')
  assert.equal(audit.total, 2, 'the torn line was never a complete evidence record')
  assert.deepEqual(audit.corrupt, [])
  assert.deepEqual(audit.chain.breaks, [])

  const markers = (await fs.readLines(LOG))
    .map(line => JSON.parse(line) as { kind?: string; payload?: { label?: string; droppedChars?: number } })
    .filter(e => e.kind === 'marker' && e.payload?.label === 'log/recovered-partial-tail')
  assert.equal(markers.length, 1, 'the repair itself is recorded on the chain')
  assert.equal(markers[0]?.payload?.droppedChars, torn.length)
})

test('a corrupt line mid-log is never "recovered" — tampering stays visible', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))

  // Damage that is NOT the crash signature: garbage between two intact lines.
  const lines = await fs.readLines(LOG)
  lines.splice(1, 0, 'this is not json')
  fs.mutate(LOG, `${lines.join('\n')}\n`)

  const revived = trustedStore(fs).store
  await revived.append(evidence('c3'))

  const logNow = await fs.readLines(LOG)
  assert.ok(logNow.includes('this is not json'), 'recovery is reserved for torn TAILS; mid-log lines are left in place')
  assert.equal(logNow.filter(l => l.includes('log/recovered-partial-tail')).length, 0)
  const audit = await revived.audit()
  assert.equal(audit.ok, false, 'mid-log corruption must keep failing audit')
  assert.ok(audit.chain.breaks.length > 0, 'the line after the garbage no longer chains')
  assert.deepEqual(audit.chain.corruptLines, [1], 'the garbage line itself is named by index — the channel says WHICH line is not an envelope')
})

test('signed chain audited without the key is UNVERIFIABLE, not forged', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()

  // Same log + anchor, but this host holds no signer at all (key lost, or
  // the log moved machines). A missing capability is not an accusation.
  const keyless = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { anchorPath: ANCHOR })
  const audit = await keyless.audit()
  assert.equal(audit.chain.unverifiableCheckpoints.length, 1, 'one signed checkpoint, no key to adjudicate it')
  assert.deepEqual(audit.chain.badCheckpoints, [], 'no forgery charge without a refuting key')
  assert.equal(audit.ok, true, 'unverifiable must not flip ok — the anchor data checks still cover rewind')

  // A host holding a *different* key is equally unable to adjudicate.
  const foreignKey: SignerPort = {
    keyId: 'another-key',
    sign: async () => 'x',
    verify: async () => false, // would "refute" everything if consulted — it must not be
  }
  const foreign = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => foreignKey, anchorPath: ANCHOR })
  const foreignAudit = await foreign.audit()
  assert.equal(foreignAudit.chain.unverifiableCheckpoints.length, 1)
  assert.deepEqual(foreignAudit.chain.badCheckpoints, [])
  assert.equal(foreignAudit.ok, true)
})

test('tampering with the anchor file is caught by its own signature', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()

  const raw = await fs.readFile(ANCHOR)
  assert.ok(raw !== undefined, 'anchor must exist after a signed checkpoint')
  const anchor = JSON.parse(raw) as { workspaceKey?: string }
  assert.equal(anchor.workspaceKey, 'ws', 'the anchor carries the workspace key its signature commits to')

  // Inflate the high-water count without re-signing: monotonicity alone would
  // also flag a rewind here, but the signature check is what turns "data
  // disagrees" into "the anchor was forged".
  const doctored = { ...JSON.parse(raw) as Record<string, unknown>, count: 99 }
  fs.mutate(ANCHOR, JSON.stringify(doctored, null, 2))

  const audit = await store.audit()
  assert.equal(audit.chain.anchorForged, true, 'the anchor sig must refute the tampered fields')
  assert.equal(audit.ok, false)
})

test('engine end to end with signing: baseline -> verify -> signed audit + anchor', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'vitest run', build: 'tsc -b' } }),
    '/ws/src/a.ts': 'export const a = 1\n',
    '/ws/src/b.ts': "import { a } from './a'\nexport const b = a + 1\n",
    '/ws/test/a.test.ts': "import { a } from '../src/a'\nvoid a\n",
  })
  const workspace = new FakeWorkspace('/ws')
  const engine = new ProofEngine({
    root: '/ws',
    fs,
    commands: new FakeCommands(),
    workspace,
    clock: new FakeClock(),
    signer: async () => new FakeSigner(),
    trustDir: '/trust',
    workspaceKey: 'wskey',
    impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'proven')

  const audit = await engine.audit()
  assert.equal(audit.ok, true)
  assert.equal(audit.chain.mode, 'signed')
  assert.ok(audit.chain.checkpoints >= 2, 'baseline and verify boundaries must both checkpoint')
  assert.notEqual(await fs.readFile('/trust/anchors/wskey/anchor.json'), undefined)
})

// -- the real host key (Ed25519 on disk, outside the workspace) ----------------

const KEYROOT = join(fileURLToPath(new URL('../../', import.meta.url)), '.openclaw', 'tmp', `proof-trust-keys-${process.pid}`)

before(async () => {
  await fsp.rm(KEYROOT, { recursive: true, force: true })
})

after(async () => {
  await fsp.rm(KEYROOT, { recursive: true, force: true })
})

test('NodeEd25519Signer: key persists across loads, signatures verify, forgeries do not', async () => {
  const first = await NodeEd25519Signer.load(join(KEYROOT, 'keys'))
  const second = await NodeEd25519Signer.load(join(KEYROOT, 'keys'))
  assert.equal(first.keyId, second.keyId, 'the host key must be stable across sessions')

  const signature = await first.sign('checkpoint payload')
  assert.ok(await first.verify('checkpoint payload', signature))
  assert.ok(await second.verify('checkpoint payload', signature))
  assert.equal(await first.verify('other payload', signature), false)
  assert.equal(await first.verify('checkpoint payload', `${signature.slice(0, -4)}AAAA`), false)

  const pem = await fsp.readFile(join(KEYROOT, 'keys', 'proof-signing-key.pem'), 'utf8')
  assert.match(pem, /BEGIN PRIVATE KEY/)
  // And the key signs checkpoints the store accepts end to end on real disk.
  const store = new EvidenceStore(new NodeFsPort(), join(KEYROOT, 'log', 'evidence.jsonl'), join(KEYROOT, 'log', 'baseline.json'), { now: () => Date.now() }, {
    signer: async () => first,
    anchorPath: join(KEYROOT, 'log', 'anchor.json'),
    workspaceKey: 'real',
  })
  await store.append(evidence('c1'))
  await store.checkpoint()
  const audit = await store.audit()
  assert.equal(audit.ok, true)
  assert.equal(audit.chain.mode, 'signed')
})

// -- the forged-checkpoint laundering family (v0.14.0) --------------------------
//
// The first ADVERSARY test closed "rewrite everything" with the anchor; the
// second move is to *answer* the anchor from inside the rewritten log. The
// attacker cannot sign, but it can append a checkpoint envelope under any
// keyId it invents, and for a while the audit took the last checkpoint's
// SELF-REPORTED count at face value when comparing against the anchor. These
// tests pin the fix: the count is judged against the records the walk itself
// counted, and the anchor is answered only by its own key.

/** THE ADVERSARY's move verbatim: flip every failure to a pass, rebuild a perfectly chained, self-addressed log from genesis. */
async function rewriteHidingFailures(fs: MemoryFs): Promise<string[]> {
  const lines = await fs.readLines(LOG)
  const payloads = lines
    .map(line => JSON.parse(line) as { kind: string; payload: Record<string, unknown> })
    .filter(envelope => envelope.kind === 'evidence')
    .map(envelope => envelope.payload)
  const forged = payloads.map((payload) => {
    const { evidenceId, ...rest } = payload
    const altered = { ...rest, status: 'pass' } as Record<string, unknown>
    return { ...altered, evidenceId: addressOf(altered) }
  })
  let prev = GENESIS_PREV
  return forged.map((payload) => {
    const line = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
}

/**
 * A checkpoint line the attacker writes itself: valid JSON, correctly chained,
 * honestly recomputed head — every field except a signature it cannot produce
 * and a count only it chose. `countText` is spliced in as raw text so `1e999`
 * (JSON's spelling of Infinity) survives where `JSON.stringify(Infinity)`
 * would quietly emit `null`.
 */
function forgedCheckpointLine(prev: string, countText: string, keyId = 'attacker'): string {
  const payload = `{"count":${countText},"head":${JSON.stringify(prev)},"workspaceKey":"ws","at":"2026-10-05T00:00:00.000Z"}`
  return `{"v":2,"kind":"checkpoint","at":"2026-10-05T00:00:00.000Z","prev":${JSON.stringify(prev)},"payload":${payload},"sig":"x","keyId":${JSON.stringify(keyId)}}`
}

/** An honest audit's eye: same log and anchor, the host key in hand. */
function auditor(fs: MemoryFs): EvidenceStore {
  return new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner(), anchorPath: ANCHOR })
}

test('THE ADVERSARY II: a forged checkpoint with an inflated count cannot launder a rewrite', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2', 'fail'))
  await store.checkpoint()
  assert.equal((await store.audit()).ok, true)

  // The full rewrite from THE ADVERSARY, plus the counter-move: append a
  // checkpoint of the attacker's own with count 1e999 — JSON for Infinity —
  // a correctly recomputed head and a junk signature. The old audit compared
  // the anchor against this self-report: ∞ silenced the rewind check,
  // `records - ∞` clamped to 0 erased the tail, and the rewrite audited
  // clean. The walk now derives the count itself: Infinity is not a safe
  // integer, and no forged number survives comparison with the records
  // actually walked to that line.
  const rebuilt = await rewriteHidingFailures(fs)
  const prev = lineDigest(rebuilt[rebuilt.length - 1] as string)
  fs.mutate(LOG, `${[...rebuilt, forgedCheckpointLine(prev, '1e999')].join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.equal(audit.chain.malformedCheckpoints!.length, 1, 'the forged count is refuted by the walked record count, signatures aside')
  assert.equal(audit.chain.rewind, true, 'no well-formed checkpoint the anchored key signed remains — the rewrite is a rewind')
  assert.equal(audit.chain.tailRecords, 2, 'the true tail survives: both rewritten records are chain-covered only, not ∞-washed to 0')
  assert.equal(audit.ok, false)
})

test('a forged checkpoint with a plausible count (anchor.count + 1) is equally malformed', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2', 'fail'))
  await store.checkpoint()

  // Same rewrite, but the forged count is a boring safe integer one past the
  // anchor: high enough to silence the old rewind comparison, plausible
  // enough to pass any range check. Only the walked record count (two
  // records walked, not three) can refute it.
  const rebuilt = await rewriteHidingFailures(fs)
  const prev = lineDigest(rebuilt[rebuilt.length - 1] as string)
  const anchor = JSON.parse(await fs.readFile(ANCHOR) as string) as { count: number }
  fs.mutate(LOG, `${[...rebuilt, forgedCheckpointLine(prev, String(anchor.count + 1))].join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.equal(audit.chain.malformedCheckpoints!.length, 1, 'count 3 where the walk counted 2')
  assert.equal(audit.chain.rewind, true, 'the foreign checkpoint cannot answer an anchor it never signed — best is undefined, not the forger')
  assert.equal(audit.chain.tailRecords, 2)
  assert.equal(audit.ok, false)
})

test('count is verified against the walked record count', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()
  assert.equal((await store.audit()).ok, true)

  // Nudge the checkpoint's count by one. It is the log's LAST line, so no
  // later `prev` links into it and the chain stays intact — only the walk
  // (and the signature, now covering bytes that no longer exist) can refute
  // it. Two records were walked to this position; the checkpoint claims three.
  const lines = await fs.readLines(LOG)
  lines[lines.length - 1] = (lines[lines.length - 1] as string).replace('"count":2', '"count":3')
  fs.mutate(LOG, `${lines.join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.deepEqual(audit.chain.malformedCheckpoints, [2], 'the last line claims 3 records where the walk counted 2')
  assert.equal(audit.ok, false)
})

test('Infinity, negative and fractional checkpoint counts are all malformed', async () => {
  const cases: ReadonlyArray<[label: string, countText: string]> = [
    ['count 1e999 (JSON Infinity)', '1e999'],
    ['a negative count', '-5'],
    ['a fractional count', '2.5'],
  ]
  for (const [label, countText] of cases) {
    const fs = MemoryFs.of({})
    const { store } = trustedStore(fs)
    await store.append(evidence('c1'))
    await store.append(evidence('c2'))
    await store.checkpoint()

    const lines = await fs.readLines(LOG)
    lines[lines.length - 1] = (lines[lines.length - 1] as string).replace('"count":2', `"count":${countText}`)
    fs.mutate(LOG, `${lines.join('\n')}\n`)

    const audit = await auditor(fs).audit()
    assert.equal(audit.chain.malformedCheckpoints!.length, 1, `${label}: must be malformed — no safe-integer match against the walked count`)
    assert.equal(audit.ok, false, label)
  }
})

test('the anchor answers to its own key: a later well-formed foreign checkpoint cannot stand in for it', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  for (const id of ['c1', 'c2', 'c3', 'c4', 'c5']) await store.append(evidence(id))
  await store.checkpoint() // the host key's checkpoint: count 5, mirrored to the anchor
  await store.append(evidence('c6'))

  // A well-formed checkpoint under a foreign keyId lands at the tail: count 6
  // matches the six records actually walked, the head is honestly recomputed,
  // the chain is unbroken. The anchor remembers {keyId: 'fake-key', count: 5}.
  // The log's answer to that anchor must be the HOST KEY's last well-formed
  // checkpoint (count 5 ≥ 5, matching head) — not the positionally-last
  // foreign one. Letting any well-shaped appendage answer for the anchor
  // would hand the high-water mark to whoever appends last.
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  fs.mutate(LOG, `${[...lines, forgedCheckpointLine(prev, '6', 'foreign-key')].join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.equal(audit.chain.rewind, false, 'the anchored key\'s own checkpoint (count 5) answers its anchor: no rewind')
  assert.equal(audit.chain.anchorMismatch, false)
  assert.equal(audit.chain.unverifiableCheckpoints.length, 1, 'the foreign checkpoint stays unverifiable — a missing capability, not a charge')
  assert.equal(audit.ok, true, 'a well-formed foreign checkpoint must not fail the audit')
})

// -- M15 + real audit-channel triggers (v0.17) -----------------------------------
//
// The deep-read finding: badCheckpoints / headMismatches / unsignedCheckpoints
// / anchorMismatch / corruptLines had ZERO real-coverage — the only "audit"
// tests for them fed hand-built reports into formatters (test/08's fakeAudit),
// which tests the formatter, not the channel. These trigger each channel for
// real against an honestly-built chain, with the host key in hand.

test('M15: an anchor file that exists but cannot parse is surfaced as anchorUnreadable, not silence', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()
  // Healthy anchor: readable, flag stays down.
  assert.equal((await store.audit()).anchorUnreadable, false)

  // Malformed JSON at the anchor path: the out-of-band high-water mark cannot
  // be consulted, so the rewind/monotonicity line of defence is SKIPPED — the
  // reader must see that, even though it does not fail ok (a capability gap,
  // not a refuted claim).
  fs.mutate(ANCHOR, '{not json at all')
  let audit = await store.audit()
  assert.equal(audit.anchorUnreadable, true)
  assert.equal(audit.ok, true, 'ok semantics unchanged: the LOG is intact — the flag is the visibility signal')

  // Well-formed JSON that is not an anchor (wrong shape/version): same hole.
  fs.mutate(ANCHOR, JSON.stringify({ v: 2, note: 'not an anchor' }))
  audit = await store.audit()
  assert.equal(audit.anchorUnreadable, true)

  // An anchor that simply does not exist stays silent, as before: "never
  // anchored" is a deployment fact, not a defect of this audit.
  const neverAnchored = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => new FakeSigner() })
  assert.equal((await neverAnchored.audit()).anchorUnreadable, false)
})

test('M15/W1-M3: a rejected signer PROVIDER lands on the sigError channel — not a naked unsigned line', async () => {
  const fs = MemoryFs.of({})
  const signer = new FakeSigner()
  let broken = true
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => {
      if (broken) throw new Error('key directory locked by a scanner')
      return signer
    },
    anchorPath: ANCHOR,
    workspaceKey: 'ws',
  })
  await store.append(evidence('c1'))
  await store.checkpoint() // provider rejects: the boundary must RECORD the failure

  // Recovery: the provider heals. The store must RETRY it — the old code
  // cached the first failure forever, so every later checkpoint stayed
  // unsigned and the audit's ok could never recover either.
  broken = false
  await store.append(evidence('c2'))
  await store.checkpoint()

  const audit = await store.audit()
  // W1-M3 (v0.23): the provider-reject form used to write a NAKED unsigned
  // checkpoint — no sigError, no keyId — which unsignedCheckpoints charged
  // forever (no keyId means no recovery witness is even possible: one AV
  // scan holding the key directory red-flagged the log for life). It is the
  // same social reality as sign() throwing (M-33 above), and now lands on
  // the same channel: sigError recorded, excused under the recovery witness
  // the healed second checkpoint provides. Pin changed from
  // unsignedCheckpoints=[1] / ok=false to the sigError-channel semantics.
  assert.deepEqual(audit.chain.sigErrorCheckpoints, [1], 'the failed boundary names its reason on the transient channel')
  assert.deepEqual(audit.chain.unsignedCheckpoints, [], 'a provider-reject blip is not a stripped signature')
  assert.deepEqual(audit.chain.refusedToSign, [], 'and it is certainly not a refusal — the store was willing, the provider was not')
  assert.equal(audit.ok, true, 'recovery is real: the anchor was lifted at count 2 by the healed signer')
  // Proof the SECOND checkpoint was signed (the retry worked): the anchor is
  // only ever written by a successful sign(), and it covers count 2.
  const anchorRaw = await fs.readFile(ANCHOR)
  assert.notEqual(anchorRaw, undefined, 'no anchor could ever be written while the failure was memoized')
  const anchor = JSON.parse(anchorRaw as string) as { count: number; keyId: string }
  assert.equal(anchor.count, 2)
  assert.equal(anchor.keyId, 'fake-key')
  assert.equal(audit.chain.checkpoints, 2)
  assert.equal(audit.chain.mode, 'signed')
  // And the first boundary's line honestly carries the failure it had.
  const cp1 = JSON.parse((await fs.readLines(LOG))[1] as string) as { sigError?: string; keyId?: string; sig?: string }
  assert.equal(cp1.sig, undefined)
  assert.match(String(cp1.sigError), /key directory locked/, 'the reason is on the chain, not swallowed')
  assert.equal(cp1.keyId, undefined, 'a provider that never resolved never named a key — no keyId is invented')
})

test('badCheckpoints: a tampered checkpoint payload is refuted by the host key (the forgery channel)', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  // Honest chain, then the adversary edits the checkpoint's payload.count,
  // KEEPING the signature. The line is last, so no `prev` links into it — the
  // chain stays intact — but the signature now covers bytes that no longer
  // exist: canonicalJson(payload) changed, and the key-holding host refutes.
  const lines = await fs.readLines(LOG)
  lines[lines.length - 1] = (lines[lines.length - 1] as string).replace('"count":2', '"count":3')
  fs.mutate(LOG, `${lines.join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.deepEqual(audit.chain.badCheckpoints, [2], 'the key this checkpoint names actively refutes its signature')
  // v0.14 semantics ride along: count 3 where the walk counted 2 is ALSO
  // malformed — the channel split is real, both fire on this input.
  assert.deepEqual(audit.chain.malformedCheckpoints, [2])
  // And with the only checkpoint of the anchored key malformed, no well-formed
  // checkpoint can answer the anchor any more — the rewrite reads as a rewind.
  assert.equal(audit.chain.rewind, true)
  assert.equal(audit.ok, false)
})

test('headMismatches: a legitimately-signed checkpoint replayed at another position fails its head', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  // Copy the (honestly signed) checkpoint to the tail, re-chaining `prev` so
  // the chain links. The payload still swears head = H(ev2) — the head at its
  // ORIGINAL position — but the walk expects digest(checkpoint-line) there.
  // The signature verifies (the payload bytes are untouched): only the
  // position is a lie, and only headMismatches can say so.
  const lines = await fs.readLines(LOG)
  const cp = JSON.parse(lines[2] as string) as Record<string, unknown>
  const copy = JSON.stringify({ ...cp, prev: lineDigest(lines[2] as string) })
  fs.mutate(LOG, `${[...lines, copy].join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.deepEqual(audit.chain.headMismatches, [3], 'the replayed checkpoint swears a head it did not see at that position')
  assert.deepEqual(audit.chain.badCheckpoints, [], 'the signature itself stays honest — this is not a forgery charge')
  assert.deepEqual(audit.chain.malformedCheckpoints, [], 'count 2 matches the two records walked: structurally sound')
  assert.equal(audit.ok, false)
})

test('anchorMismatch: a hand-minted anchor whose head disagrees with the log is caught', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  // Forge the out-of-band artifact the one way that survives its own
  // signature: mint a NEW anchor honestly signed by the real key, same count
  // as the log's last checkpoint but a different head. Signature checks pass
  // (it is genuinely signed); only the count/head comparison can catch it.
  const otherHead = 'ff'.repeat(32)
  const at = '2026-10-06T00:00:00.000Z'
  const minted = {
    v: 1 as const,
    keyId: 'fake-key',
    count: 2,
    head: otherHead,
    sig: await new FakeSigner().sign(checkpointSignedData({ count: 2, head: otherHead, workspaceKey: 'ws', at })),
    at,
    workspaceKey: 'ws',
  }
  fs.mutate(ANCHOR, JSON.stringify(minted, null, 2))

  const audit = await store.audit()
  assert.equal(audit.chain.anchorMismatch, true, 'same count, different head — the anchor and the log disagree')
  assert.equal(audit.chain.anchorForged, false, 'the anchor is honestly signed; it simply says something else')
  assert.equal(audit.chain.rewind, false, 'count 2 is not below the anchored 2 — this is a mismatch, not a rewind')
  assert.equal(audit.ok, false)
})

// -- H-08: the keyless audit host (v0.22) ---------------------------------------
//
// The CONFIRMED cross-validation finding (D1 #1): every ADVERSARY test above
// ran on a host holding the key. On a keyless host — key lost, different
// machine, the module's documented audit deployment — a rewrite plus a
// checkpoint that IMPERSONATES the anchor's key with an inflated count used
// to skip the head comparison entirely (sizes were compared, heads only on
// strict equality) and the rewrite audited clean. The exact-pair rule fixes
// the semantics: the anchor is answered only by (anchor.count, anchor.head)
// from its own key — answering means reproducing the anchored prefix
// byte-for-byte, and no self-reported count can substitute for that.

test('H-08: keyless host — rewrite + impersonated anchor key + inflated count is a mismatch, not a pass', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2', 'fail'))
  await store.checkpoint() // anchor: {keyId: 'fake-key', count: 2, head: H(ev2)}
  assert.equal((await store.audit()).ok, true)

  // D1's PoC shape: rebuild a longer self-consistent chain of passes from
  // genesis, then answer the anchor with its OWN keyId, an honestly
  // recomputed head, a count that matches the walk (5) — and a signature no
  // key on this host can adjudicate.
  const rebuilt = [evidence('c1'), evidence('c2'), evidence('c3'), evidence('c4'), evidence('c5')]
  let prev = GENESIS_PREV
  const lines = rebuilt.map((payload) => {
    const line = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
  fs.mutate(LOG, `${[...lines, forgedCheckpointLine(prev, '5', 'fake-key')].join('\n')}\n`)

  const keyless = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { anchorPath: ANCHOR })
  const audit = await keyless.audit()
  assert.equal(audit.chain.rewind, false, 'the rewrite is longer than the anchor remembers — truncation is not the charge')
  assert.equal(audit.chain.anchorMismatch, true, 'an inflated impersonation does not contain the anchored (count, head) pair: the anchor is NOT answered')
  assert.deepEqual(audit.chain.badCheckpoints, [], 'still no forgery charge without a refuting key — three-state adjudication survives this fix')
  assert.equal(audit.chain.unverifiableCheckpoints.length, 1)
  assert.equal(audit.ok, false, 'the unverifiable set contributes nothing positive: the data check alone condemns the rewrite')
})

test('H-08 control: keyless host — equal count with a rewritten head answers nothing either', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  await store.append(evidence('c2', 'fail'))
  await store.checkpoint()

  // Same rewrite but exactly two records, forged count set to the anchored 2.
  // The walk corroborates the count (2 records walked); only the head can
  // differ — and the exact-pair rule demands the anchored head, which is a
  // hash over the ORIGINAL prefix this chain no longer contains.
  const rebuilt = await rewriteHidingFailures(fs)
  const prev = lineDigest(rebuilt[rebuilt.length - 1] as string)
  fs.mutate(LOG, `${[...rebuilt, forgedCheckpointLine(prev, '2', 'fake-key')].join('\n')}\n`)

  const keyless = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { anchorPath: ANCHOR })
  const audit = await keyless.audit()
  assert.equal(audit.chain.anchorMismatch, true)
  assert.equal(audit.ok, false)
})

// -- H-09: the four-line anchor disarm (v0.22) ----------------------------------
//
// The anchor file itself was never domain-validated: {keyId:'x', count:-5,
// sig:''} parsed fine, and the empty signature exempted it from the forgery
// check while the negative count exempted it from every data comparison. An
// honest anchor is only ever written after a successful sign() — it always
// carries a non-empty sig and a walked count. Anchor-shaped but
// dishonest-valued is now `anchorInvalid` (fails ok), distinct from
// `anchorUnreadable` (a capability gap that never did).

test('H-09: the four disarm forms of the anchor file all fail loudly', async () => {
  const disarm = async (doctor: (anchor: Record<string, unknown>) => void, rawSplice?: string) => {
    const fs = MemoryFs.of({})
    const { store } = trustedStore(fs)
    await store.append(evidence('c1'))
    await store.append(evidence('c2'))
    await store.checkpoint()
    assert.equal((await store.audit()).ok, true, 'sanity: the honest anchor audits clean')

    const raw = await fs.readFile(ANCHOR) as string
    if (rawSplice === undefined) {
      const anchor = JSON.parse(raw) as Record<string, unknown>
      doctor(anchor)
      fs.mutate(ANCHOR, JSON.stringify(anchor, null, 2))
    } else {
      // The anchor file is pretty-printed (`"count": 2`); splice raw text so
      // JSON's spelling of Infinity survives what stringify would fold to null.
      fs.mutate(ANCHOR, raw.replace('"count": 2', rawSplice))
    }
    return auditor(fs).audit()
  }

  // (a) strip the signature: never honest, now invalid instead of exempt.
  let audit = await disarm(a => { delete a.sig })
  assert.equal(audit.chain.anchorInvalid, true, 'an anchor without its signature is a disarm, not a capability gap')
  assert.equal(audit.anchorUnreadable, false, 'narrative honesty: the file parses; it is the VALUES no honest writer produces')
  assert.equal(audit.ok, false)

  // (b) strip workspaceKey, keep the sig: the keyholding host reconstructs
  // the only honest pre-field form (workspaceKey: null) and the signature —
  // which commits to 'ws' — refutes it. The old code skipped the check.
  audit = await disarm(a => { delete a.workspaceKey })
  assert.equal(audit.chain.anchorForged, true, 'stripping the workspace key changes the signed bytes; the sig says so')
  assert.equal(audit.chain.anchorInvalid, false)
  assert.equal(audit.ok, false)

  // (c) empty keyId: the anchor used to fall back to "any key may answer".
  audit = await disarm(a => { a.keyId = '' })
  assert.equal(audit.chain.anchorInvalid, true)
  assert.equal(audit.ok, false)

  // (d) negative count — and the JSON-Infinity spelling of the same lie.
  audit = await disarm(a => { a.count = -5 })
  assert.equal(audit.chain.anchorInvalid, true)
  assert.equal(audit.ok, false)
  audit = await disarm(() => {}, '"count":1e999')
  assert.equal(audit.chain.anchorInvalid, true, '1e999 is not a count any writer walked')
  assert.equal(audit.ok, false)
})

// -- H-27: the pre-sign audit (v0.22) -------------------------------------------
//
// "Cannot forge a signature" never stopped the system from SIGNING the
// forgery itself: rewrite the log longer and self-consistent, trigger the
// next boundary, and the old store signed the forged head and lifted the
// anchor onto it — every later audit then answered to the attack. The
// boundary now audits the physical bytes before signing and refuses.

test('H-27: a boundary refuses to sign a chain rewritten behind the store\'s back — the anchor stays put', async () => {
  const fs = MemoryFs.of({})
  const signer = new FakeSigner()
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => signer,
    anchorPath: ANCHOR,
    workspaceKey: 'ws',
  })
  await store.append(evidence('c1', 'fail'))
  await store.checkpoint()
  const anchorBefore = await fs.readFile(ANCHOR)

  // The rewrite: longer, self-consistent, no anchored prefix, no host-key
  // checkpoint — everything a signer must not bless.
  const rebuilt = [evidence('c1'), evidence('c2'), evidence('c3')]
  let prev = GENESIS_PREV
  const lines = rebuilt.map((payload) => {
    const line = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
  fs.mutate(LOG, `${lines.join('\n')}\n`)

  await store.checkpoint() // must refuse rather than sign the forged head

  assert.equal(await fs.readFile(ANCHOR), anchorBefore, 'the anchor must not be lifted onto a rewrite')
  const audit = await store.audit()
  assert.equal(audit.chain.refusedToSign!.length, 1, 'the refusal itself is on the chain and the audit names it')
  assert.equal(audit.ok, false, 'the store accusing its own log is the loudest signal an audit has')
  assert.equal(audit.chain.checkpoints, 1, 'only the refused boundary — the rewrite removed the honest one, and no new signed one was added')
  assert.deepEqual(audit.chain.badCheckpoints, [])

  const markers = (await fs.readLines(LOG))
    .map(line => JSON.parse(line) as { kind?: string; payload?: { label?: string; reason?: string } })
    .filter(e => e.kind === 'marker' && e.payload?.label === 'trust/checkpoint-refused')
  assert.equal(markers.length, 1, 'the refusal is a marker readers can see, not just an audit channel')
  assert.match(String(markers[0]?.payload?.reason), /anchor-(rewind|mismatch)/)
  assert.match(String(markers[0]?.payload?.reason), /physical-tail-moved/, 'the walk also caught the tail moving behind the queue')
})

// -- M-33/H-32: sigError channels — honest blip vs stripped signature (v0.22) ---

/** A signer that resolves fine but whose signing ACTION fails while `broken`. */
class FlakySigner implements SignerPort {
  readonly keyId = 'fake-key'
  private readonly inner = new FakeSigner()
  broken = false
  async sign(data: string): Promise<string> {
    if (this.broken) throw new Error('key file locked by an AV scan')
    return this.inner.sign(data)
  }
  async verify(data: string, signature: string): Promise<boolean> { return this.inner.verify(data, signature) }
}

test('M-33: one transient signing failure, then recovery — visible as sigError, ok recovers', async () => {
  const fs = MemoryFs.of({})
  const signer = new FlakySigner()
  signer.broken = true
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => signer,
    anchorPath: ANCHOR,
    workspaceKey: 'ws',
  })
  await store.append(evidence('c1'))
  await store.checkpoint() // sign() throws: an unsigned-but-attested boundary lands
  signer.broken = false
  await store.append(evidence('c2'))
  await store.checkpoint() // healed: a real signature at count 2

  const audit = await store.audit()
  // The recovery witness (cp2, verified, same key) is what separates an
  // honest blip from a stripped signature — without it the audit cannot tell
  // them apart and must stay red (next test). With it, ok recovers: a
  // permanently red audit for a healed blip is how operators learn to ignore
  // reds, which is its own vulnerability.
  assert.deepEqual(audit.chain.sigErrorCheckpoints, [1], 'the failed boundary is named on its own channel')
  assert.deepEqual(audit.chain.unsignedCheckpoints, [], 'a witnessed transient failure is not a stripped signature')
  assert.deepEqual(audit.chain.refusedToSign, [], 'and it is certainly not a refusal — the signer was willing, the disk was not')
  assert.equal(audit.ok, true, 'recovery is real: the anchor was lifted at count 2 by the healed signer')
  const anchor = JSON.parse(await fs.readFile(ANCHOR) as string) as { count: number }
  assert.equal(anchor.count, 2)
})

test('M-33: a stripped signature stays red — with or without a planted cover story', async () => {
  const strip = async (plantCoverStory: boolean) => {
    const fs = MemoryFs.of({})
    const { store } = trustedStore(fs)
    await store.append(evidence('c1'))
    await store.append(evidence('c2'))
    await store.checkpoint()

    // Remove the signature from the LAST checkpoint. The payload stays honest
    // (the anchor pair still answers) — the red must come from the strip
    // itself. The cover-story variant plants a sigError field mimicking an
    // honest transient failure; with no LATER verified signature to witness
    // recovery, the audit must not buy it.
    const lines = await fs.readLines(LOG)
    const cp = JSON.parse(lines[lines.length - 1] as string) as Record<string, unknown>
    delete cp.sig
    if (plantCoverStory) cp.sigError = 'key directory locked by a scanner'
    lines[lines.length - 1] = JSON.stringify(cp)
    fs.mutate(LOG, `${lines.join('\n')}\n`)
    return auditor(fs).audit()
  }

  let audit = await strip(false)
  assert.deepEqual(audit.chain.unsignedCheckpoints, [2], 'naked strip: charged as unsigned while the signer is active')
  assert.deepEqual(audit.chain.sigErrorCheckpoints, [])
  assert.equal(audit.chain.rewind, false)
  assert.equal(audit.ok, false)

  audit = await strip(true)
  assert.deepEqual(audit.chain.unsignedCheckpoints, [2], 'planted cover story without a recovery witness: still charged — the witness is the only pardon')
  assert.deepEqual(audit.chain.sigErrorCheckpoints, [])
  assert.equal(audit.ok, false)
})

// -- H-32/M-A1-5: protected markers, headRef witnesses, suspect channel (v0.22) --

test('H-32: protected markers carry a headRef witness and honest ones read back clean', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.mark('attest/human', { claimId: 'claim-1', decision: 'endorse', approver: 'lead' })

  const seen = await store.markersWith('attest/human')
  assert.equal(seen.length, 1)
  assert.equal(seen[0]?.suspect, false)
  const lines = await fs.readLines(LOG)
  assert.equal(seen[0]?.payload.headRef, lineDigest(lines[0] as string), 'the witness is the chain head at append time — the digest of the physically previous line')
  assert.equal((await store.audit()).chain.suspectMarkers!.length, 0)
})

test('H-32: an appended baseline/saved twin cannot answer for the chain', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  const baseline = buildBaseline([evidence('c1')], WS, new FakeClock())
  await store.saveBaseline(baseline)
  assert.equal((await store.audit()).ok, true)

  // The M-A1-5 injection: doctor the baseline file, then append — no rewrite,
  // just a tail append — a matching 'baseline/saved' marker so last-wins
  // blesses the doctored bytes. The twin chains fine (prev is honest); what
  // it cannot do is vouch for its position: it carries no headRef the walk
  // can corroborate, so it reads back suspect and the HONEST marker answers.
  const doctored = JSON.stringify({ ...baseline, root: '0'.repeat(64) }, null, 2)
  fs.mutate(BASE, doctored)
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const injected = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
    payload: { label: 'baseline/saved', digest: sha256(doctored), bytes: doctored.length },
  })
  fs.mutate(LOG, `${[...lines, injected].join('\n')}\n`)

  const auditorStore = auditor(fs)
  const audit = await auditorStore.audit()
  assert.deepEqual(audit.chain.suspectMarkers, [3], 'the twin is named: it cannot vouch for where it sits')
  assert.equal(audit.chain.baselineTampered, true, 'the honest marker still answers — the doctored bytes match nothing it remembers')
  assert.equal(audit.ok, false)

  // The read-back contract κ-style consumers use: last-wins among the
  // NON-suspect only. The attacker's digest never enters the comparison.
  const trusted = await auditorStore.markersWith('baseline/saved', { excludeSuspect: true })
  assert.equal(trusted.length, 1)
  assert.notEqual(trusted[0]?.payload.digest, sha256(doctored))
  assert.equal((await auditorStore.markersWith('baseline/saved')).length, 2, 'raw view keeps both — suspect is visible, not deleted')
})

// -- L-A1-10 / L-A1-11 (v0.22) ---------------------------------------------------

test('L-A1-10: lastWellFormedCheckpoint answers only to the anchored key', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  for (const id of ['c1', 'c2', 'c3', 'c4', 'c5']) await store.append(evidence(id))
  await store.checkpoint() // fake-key, count 5
  await store.append(evidence('c6'))
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  fs.mutate(LOG, `${[...lines, forgedCheckpointLine(prev, '6', 'foreign-key')].join('\n')}\n`)

  const best = await store.lastWellFormedCheckpoint()
  assert.equal(best?.count, 5, 'the anchored key\'s checkpoint — never the positionally-later foreign one')
  assert.equal(best?.keyId, 'fake-key')

  // Anchor-less chains keep the any-key semantics (an honest unsigned store).
  const anchorless = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  assert.equal((await anchorless.lastWellFormedCheckpoint())?.count, 6)

  // And when the anchored key's checkpoints are rewritten away entirely, the
  // honest answer is "nothing" — not whichever foreign checkpoint sits last.
  const rewritten = [evidence('c1'), evidence('c2')]
  let prev2 = GENESIS_PREV
  const rebuilt = rewritten.map((payload) => {
    const line = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev: prev2, payload })
    prev2 = lineDigest(line)
    return line
  })
  fs.mutate(LOG, `${[...rebuilt, forgedCheckpointLine(prev2, '2', 'foreign-key')].join('\n')}\n`)
  assert.equal(await store.lastWellFormedCheckpoint(), undefined, 'an anchor naming a key the chain no longer answers is not satisfied by a foreign key')
})

test('L-A1-11: a v2 line of an unknown kind is malformed, not silently chained', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[0] as string)
  const smuggled = JSON.stringify({ v: 2, kind: 'sidechannel', at: '2026-10-05T00:00:00.000Z', prev, payload: { note: 'no honest writer emits me' } })
  fs.mutate(LOG, `${[lines[0], smuggled].join('\n')}\n`)

  const audit = await auditor(fs).audit()
  assert.deepEqual(audit.chain.malformedCheckpoints, [1], 'unknown-kind lines are named on the loud channel')
  assert.equal(audit.ok, false)
})

// -- X-H-08: cross-session tail absorption (v0.23) -------------------------------
//
// THE ADVERSARY III: no store process is alive (CLI invocation gap, MCP server
// restart). The agent appends to the log tail: a self-addressed fake evidence
// record (recomputed with this package's own exported functions) and a
// `baseline/saved` marker whose headRef is CORRECTLY computed for its physical
// position — so it chains perfectly, is not suspect, and remembers the digest
// of a doctored baseline document. v0.22 absorbed all of it as honest history
// and the next checkpoint SIGNED the attack bytes and lifted the anchor over
// them (audit stayed green the whole time — the notarisation was silent).
// The pre-sign audit now refuses: the newest baseline-family marker on the
// checkpoint-uncovered tail was authored by no live process.

test('X-H-08: a between-sessions baseline/saved absorption is refused, not notarised', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  const honest = buildBaseline([evidence('c1', 'fail')], WS, new FakeClock())
  await store.saveBaseline(honest) // marker (self-written) + signed checkpoint + anchor
  const anchorBefore = await fs.readFile(ANCHOR)

  // The attack window: session 1 is dead. Everything appended is perfectly
  // shaped — chained, self-addressed, headRef exact — which is exactly why no
  // shape check can see it.
  const lines = await fs.readLines(LOG)
  let prev = lineDigest(lines[lines.length - 1] as string)
  const fakeLine = JSON.stringify({
    v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev, payload: evidence('npm/never-ran-critical'),
  })
  prev = lineDigest(fakeLine)
  const forged = buildBaseline([evidence('c1', 'pass')], WS, new FakeClock())
  const forgedBytes = JSON.stringify(forged, null, 2)
  fs.mutate(BASE, forgedBytes)
  const twinMarker = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:01.000Z', prev,
    payload: { label: 'baseline/saved', digest: sha256(forgedBytes), bytes: forgedBytes.length, headRef: prev },
  })
  fs.mutate(LOG, `${[...lines, fakeLine, twinMarker].join('\n')}\n`)

  // Session 2: a fresh process absorbs the bytes as history — but the first
  // boundary must refuse to lend them the host key.
  const session2 = trustedStore(fs).store
  await session2.checkpoint()
  const audit = await session2.audit()
  assert.equal(audit.chain.refusedToSign!.length, 1, 'the store accuses its own log instead of notarising the tail')
  assert.equal(audit.ok, false, 'v0.22 kept this audit GREEN while the anchor was lifted onto the attack')
  assert.equal(await fs.readFile(ANCHOR), anchorBefore, 'the out-of-band high-water mark is not moved over the absorption')
  const refusal = (await fs.readLines(LOG)).find(l => l.includes('trust/checkpoint-refused'))
  assert.match(String(refusal), /unvouched-baseline-marker/, 'the refusal names the authorless baseline claim')

  // Recovery is the documented re-anchor flow: THIS process saves a baseline,
  // its marker supersedes the orphan as the newest of the label, and signing
  // resumes. The old refusal stays on the record (history, not amnesia).
  await session2.saveBaseline(buildBaseline([evidence('c1', 'fail')], WS, new FakeClock()))
  await session2.append(evidence('c2'))
  await session2.checkpoint() // no second refusal: the tail's newest claim is self-authored now
  const recovered = await session2.audit()
  assert.equal(recovered.chain.refusedToSign!.length, 1, 'exactly one refusal — recovery does not loop')
  assert.deepEqual(recovered.chain.refusedToSignPardoned, recovered.chain.refusedToSign,
    'Y-H-02: the refusal is visible history whose generation recovered — signed again over a re-anchored chain')
  assert.equal(recovered.ok, true,
    'Y-H-02: v0.23 billed this refusal forever, so the documented recovery never actually recovered (the X-H-09 consumers capped every later grade at stale); the generational slice makes re-anchor mean it')
  assert.notEqual(await fs.readFile(ANCHOR), anchorBefore, 'the anchor lifts again over the re-anchored, honest tail')
  assert.equal(recovered.chain.checkpoints, 4, 'signed checkpoints resumed after the refusal and the re-anchor')
})

test('X-H-08 control: an honest restart over a previous session\'s baseline never refuses', async () => {
  const fs = MemoryFs.of({})
  const first = trustedStore(fs).store
  await first.append(evidence('c1'))
  await first.saveBaseline(buildBaseline([evidence('c1')], WS, new FakeClock()))
  // The marker sits at-or-below session 1's signed checkpoint — vouched-for,
  // inherited history. Session 2 appends and checkpoints: no refusal.
  const second = trustedStore(fs).store
  await second.append(evidence('c2'))
  await second.checkpoint()
  const audit = await second.audit()
  assert.deepEqual(audit.chain.refusedToSign, [])
  assert.equal(audit.ok, true, 'an inherited, checkpoint-covered baseline marker is legitimate history')
  assert.equal(audit.chain.checkpoints, 2)
})

test('X-H-08: a foreign baseline/established tail marker is refused too (and superseded by a self-written one)', async () => {
  const fs = MemoryFs.of({})
  const first = trustedStore(fs).store
  await first.append(evidence('c1'))
  await first.checkpoint() // a verified vouching boundary

  // The attack: an authorless `baseline/established` (the engine's re-anchor
  // record) lands on the covered tail's end.
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const twin = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
    payload: { label: 'baseline/established', reason: 'never happened', headRef: prev },
  })
  fs.mutate(LOG, `${[...lines, twin].join('\n')}\n`)

  const session2 = trustedStore(fs).store
  await session2.checkpoint()
  assert.equal((await session2.audit()).chain.refusedToSign!.length, 1, 'both baseline-family labels are protected')

  // Superseding, per label: a NEWER marker of the same label authored by THIS
  // process makes the orphan a dead letter — last-wins reads never consult it.
  await session2.mark('baseline/established', { reason: 'operator re-anchor after refusal' })
  await session2.checkpoint()
  const recovered = await session2.audit()
  assert.equal(recovered.chain.refusedToSign!.length, 1, 'no second refusal: the newest claim of the label is self-authored')
  assert.equal(recovered.chain.checkpoints, 3)
  assert.equal(recovered.ok, true, 'Y-H-02: the re-anchor recovered the refusal\'s generation — visible scar, green audit')
})

// -- X-H-03: headLiared on the walk (v0.23) ---------------------------------------
//
// The walk always recorded expectedHead; nothing outside preSignAudit compared
// it, so a legitimately-SIGNED checkpoint replayed at another position passed
// every signature check while swearing a head it never saw. The verdict is now
// a first-class field the bundle/publish layers consume.

test('X-H-03: walk.checkpoints expose headLiared — honest false, replayed true', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()

  // Honest: the checkpoint's head is the digest of the physically previous line.
  const honest = walkChain(await fs.readLines(LOG))
  assert.equal(honest.checkpoints.length, 1)
  assert.equal(honest.checkpoints[0]?.headLiared, false)
  assert.equal(honest.checkpoints[0]?.payload.head, honest.checkpoints[0]?.expectedHead)

  // The replay (the headMismatches shape): copy the signed checkpoint to the
  // tail re-chained — signature verifies, position is a lie.
  const lines = await fs.readLines(LOG)
  const cp = JSON.parse(lines[2] as string) as Record<string, unknown>
  const copy = JSON.stringify({ ...cp, prev: lineDigest(lines[2] as string) })
  fs.mutate(LOG, `${[...lines, copy].join('\n')}\n`)
  const replayed = walkChain(await fs.readLines(LOG))
  assert.equal(replayed.checkpoints[0]?.headLiared, false, 'the original still tells the truth where it sits')
  assert.equal(replayed.checkpoints[1]?.headLiared, true, 'the replay swears a head from another position')
})

// -- W1-L10: CRLF tolerance in the chain digest (v0.23) ---------------------------

test('W1-L10: an externally CRLF-rewritten log keeps its chain; mid-line tampering still breaks it', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()
  assert.equal((await store.audit()).ok, true)

  // git autocrlf / a CRLF editor re-terminates every line. JSON.parse tolerates
  // the trailing \r; v0.22 digested it — every prev link mass-failed, loud and
  // unrecoverable, indistinguishable from real tampering. Digests now normalize
  // the line terminator: the honest chain walks clean again.
  const lines = await fs.readLines(LOG)
  fs.mutate(LOG, `${lines.join('\r\n')}\r\n`)
  const crlfAudit = await auditor(fs).audit()
  assert.deepEqual(crlfAudit.chain.breaks, [], 'a CRLF rewrite is not a rewrite of content')
  assert.equal(crlfAudit.ok, true)

  // A real edit in the MIDDLE of a line is still a different digest: the next
  // line's prev no longer matches. Tolerance extends only to the terminator
  // byte no honest writer ever produced.
  const back = (await fs.readLines(LOG)).map(l => l.replace(/\r$/, ''))
  back[0] = (back[0] as string).replace('"head1"', '"headX"')
  fs.mutate(LOG, `${back.join('\n')}\n`)
  const tampered = await auditor(fs).audit()
  assert.ok(tampered.chain.breaks.length > 0, 'mid-line tampering is still detected')
  assert.equal(tampered.ok, false)
})

// -- W1-M7: lastWellFormedCheckpoint anchor parity (v0.23) -------------------------

test('W1-M7: lastWellFormedCheckpoint fails loudly on an unusable anchor, like latestSignedCheckpoint', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  for (const id of ['c1', 'c2', 'c3', 'c4', 'c5']) await store.append(evidence(id))
  await store.checkpoint() // fake-key, count 5
  await store.append(evidence('c6'))
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  fs.mutate(LOG, `${[...lines, forgedCheckpointLine(prev, '6', 'foreign-key')].join('\n')}\n`)

  // Sanity: a healthy anchor constrains the answer to the anchored key.
  assert.equal((await store.lastWellFormedCheckpoint())?.keyId, 'fake-key')

  // Unparseable anchor: the old code silently fell back to the any-key pool and
  // the foreign checkpoint won. Parity with latestSignedCheckpoint is loud.
  fs.mutate(ANCHOR, '{not json at all')
  assert.equal(await store.lastWellFormedCheckpoint(), undefined, 'unparseable anchor: no silent any-key fallback')
  assert.equal(await store.latestSignedCheckpoint(), undefined, 'parity: the publish path said undefined all along')

  // Domain-invalid anchor (the H-09 disarm shape): same loud answer.
  fs.mutate(ANCHOR, JSON.stringify({ v: 1, keyId: '', count: 1, head: 'ff'.repeat(32), sig: 'x', at: 't' }))
  assert.equal(await store.lastWellFormedCheckpoint(), undefined, 'invalid anchor: nothing is publishable')

  // No anchor file at all keeps the any-key semantics (never anchored ≠ attacked).
  const anchorless = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  assert.equal((await anchorless.lastWellFormedCheckpoint())?.count, 6)
})

// -- v0.23: the verified read layer's bestCheckpoint adjudication ------------------

test('createVerifiedView.bestCheckpoint: verified / refuted / unverifiable / none, with the X-H-03 mirror', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  const view = createVerifiedView(store)

  // An unsigned chain has nothing publishable.
  const unsignedFs = MemoryFs.of({})
  const unsignedStore = new EvidenceStore(unsignedFs, LOG, BASE, new FakeClock())
  await unsignedStore.append(evidence('c1'))
  assert.equal((await createVerifiedView(unsignedStore).bestCheckpoint()).signature, 'none')

  // Honest signed chain: selected, signature adjudicated under the very key it
  // names, head corroborated.
  await store.append(evidence('c1'))
  await store.checkpoint()
  const good = await view.bestCheckpoint()
  assert.equal(good.signature, 'verified')
  assert.equal(good.headLiared, false)
  assert.equal(good.checkpoint?.keyId, 'fake-key')
  assert.equal(good.checkpoint?.payload.count, 1)

  // Refuted: the payload is edited under a kept signature — structure stays
  // well-formed (count still matches the walk), the signed bytes no longer
  // exist, and adjudication does what selection alone never did (the X-H-11
  // predicate). Editing `count` instead would trip the malformed exclusion
  // first and answer 'none' — a different, already-covered charge.
  const lines = await fs.readLines(LOG)
  lines[lines.length - 1] = (lines[lines.length - 1] as string).replace('"workspaceKey":"ws"', '"workspaceKey":"WS"')
  fs.mutate(LOG, `${lines.join('\n')}\n`)
  assert.equal((await view.bestCheckpoint()).signature, 'refuted', 'a checkpoint the key refutes is not publishable')

  // Unverifiable: this host holds a DIFFERENT key — a missing capability, and
  // (X-H-10's evidence-side half) the payload rides along so a key-holder
  // downstream can verify the old head itself.
  const foreign: SignerPort = { keyId: 'another-key', sign: async () => 'x', verify: async () => false }
  const foreignView = createVerifiedView(store, { signerProvider: async () => foreign })
  const unverifiable = await foreignView.bestCheckpoint()
  assert.equal(unverifiable.signature, 'unverifiable')
  assert.notEqual(unverifiable.checkpoint, undefined)
  assert.equal(typeof unverifiable.checkpoint?.sig, 'string')

  // The X-H-03 mirror ON THE SELECTION (Y-H-01, v0.24): replay the
  // (honestly signed) checkpoint at the tail — signature verifies, position
  // is a lie. The v0.23 view selected it and advised `headLiared: true`,
  // leaving every consumer to remember the second half of the predicate;
  // the liar is now excluded from the candidate pool at selection, so the
  // view answers with the HONEST original (verified, corroborated) and no
  // publish path can notarise a transplant even by forgetting to check.
  const fs2 = MemoryFs.of({})
  const s2 = trustedStore(fs2).store
  await s2.append(evidence('c1'))
  await s2.append(evidence('c2'))
  await s2.checkpoint()
  const l2 = await fs2.readLines(LOG)
  const cp = JSON.parse(l2[2] as string) as Record<string, unknown>
  fs2.mutate(LOG, `${[...l2, JSON.stringify({ ...cp, prev: lineDigest(l2[2] as string) })].join('\n')}\n`)
  const replayed = await createVerifiedView(s2).bestCheckpoint()
  assert.equal(replayed.signature, 'verified', 'the honest original is selected — the signature is honest and so is its position')
  assert.equal(replayed.headLiared, false)
  assert.equal(replayed.checkpoint?.index, 2, 'the tail replay is not a candidate at all: selection enforces the publish predicate')
  // ...and when a rewrite leaves ONLY the transplanted liar on the chain,
  // there is nothing publishable — the transplant does not stand in.
  const rebuilt = await rewriteHidingFailures(fs2)
  let prevR = lineDigest(rebuilt[rebuilt.length - 1] as string)
  const transplanted = JSON.stringify({ ...cp, prev: prevR })
  prevR = lineDigest(transplanted)
  const honestTail = evidence('c3')
  fs2.mutate(LOG, `${[...rebuilt, transplanted, JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-05T00:00:00.000Z', prev: prevR, payload: honestTail })].join('\n')}\n`)
  assert.equal(await s2.latestSignedCheckpoint(), undefined, 'a log whose only signed checkpoint lies about its position has nothing publishable')
  assert.equal((await createVerifiedView(s2).bestCheckpoint()).signature, 'none')
  // The walk's own charge still names the liar (audit red is the tamper
  // verdict; selection merely refuses to publish it).
  assert.ok((await s2.audit()).chain.headMismatches.includes(2), 'the audit charges the transplant even though selection will not publish it')

  // Passthrough: the view's audit is the store's audit, not a second opinion.
  const byView = await createVerifiedView(s2).audit()
  assert.equal(byView.ok, (await s2.audit()).ok)
})

// -- Y-H-09 (v0.24): absorption is refused at READ time ------------------------

test('Y-H-09: a pseudo-absorbed baseline is refused at read time — no signing boundary required', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1', 'fail'))
  const honest = buildBaseline([evidence('c1', 'fail')], WS, new FakeClock())
  await store.saveBaseline(honest)

  // Control: a fresh signer-holding session over the HONEST chain still
  // loads — session 1's marker sits below its own signed checkpoint, which
  // is exactly what "vouched" means.
  const control = trustedStore(fs).store
  assert.notEqual(await control.loadBaseline(), undefined, 'an inherited, checkpoint-covered baseline marker is authorised history')

  // THE ADVERSARY (the X-H-08 shape, canonical document included): a
  // correctly chained, headRef-exact `baseline/saved` twin remembering the
  // digest of a doctored-but-canonical baseline. v0.23's only defence was
  // the NEXT signing boundary's refusal — verdicts minted against the
  // poisoned bytes first, and a keyless deployment never detected anything.
  const forged = buildBaseline([evidence('c1', 'pass')], WS, new FakeClock())
  const forgedBytes = JSON.stringify(forged, null, 2)
  fs.mutate(BASE, forgedBytes)
  const lines = await fs.readLines(LOG)
  let prev = lineDigest(lines[lines.length - 1] as string)
  const twinMarker = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
    payload: { label: 'baseline/saved', digest: sha256(forgedBytes), bytes: forgedBytes.length, headRef: prev },
  })
  fs.mutate(LOG, `${[...lines, twinMarker].join('\n')}\n`)

  // The read path: no checkpoint is called, no boundary is crossed. The
  // absorption is already a verdict for every consumer of loadBaseline/audit.
  const session2 = trustedStore(fs).store
  assert.equal(await session2.loadBaseline(), undefined,
    'the poisoned document is not a baseline to verify against — the verdict path cannot mint grades over it before a refusal lands')
  const audit = await session2.audit()
  assert.equal(audit.chain.baselineTampered, true, 'the un-authored, un-vouched newest baseline claim is a tamper verdict at read time')
  assert.equal(audit.ok, false)
  assert.deepEqual(audit.chain.refusedToSign, [], 'and it did not take a refusal row to say so')

  // Scope control (the three-state rule): a host holding a DIFFERENT key
  // than every signed checkpoint is a borrowed pair of eyes — the vouch
  // demand is scoped to the key that owns the log, so the absorption stays
  // invisible to THIS host's digest/canonical rules (they bind what they
  // can see: the bytes match the newest marker's digest exactly). Charging
  // a capability gap would invert the burden of proof; the keyed host is
  // where the charge lives.
  const foreignKey: SignerPort = { keyId: 'another-key', sign: async () => 'x', verify: async () => false }
  const foreign = new EvidenceStore(fs, LOG, BASE, new FakeClock(), { signer: async () => foreignKey, anchorPath: ANCHOR })
  const foreignAudit = await foreign.audit()
  assert.equal(foreignAudit.chain.baselineTampered, false, 'the authorship demand does not ride a foreign key — a capability gap is not an accusation')
})

// -- Y-H-02 (v0.24): signer adoption end to end --------------------------------

test('Y-H-02: signer adoption — the unsigned era is a generation, not a life sentence (engine E2E)', async () => {
  // ONE physical workspace across both eras: era 2's engine must see era 1's
  // log, baseline and markers — that is what "adoption" means.
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'vitest run', build: 'tsc -b' } }),
    '/ws/src/a.ts': 'export const a = 1\n',
    '/ws/src/b.ts': "import { a } from './a'\nexport const b = a + 1\n",
    '/ws/test/a.test.ts': "import { a } from '../src/a'\nvoid a\n",
  })
  // Era 1: no trustDir, no signer — the deployment runs unsigned.
  const keyless = new ProofEngine({
    root: '/ws',
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(),
    impactGraphLimit: 1_000,
  })
  await keyless.establishBaseline()
  const unsigned = await keyless.audit()
  assert.equal(unsigned.chain.mode, 'unsigned')
  assert.equal(unsigned.ok, true, 'the keyless era is green on its own terms')

  // Era 2: the operator installs a trust directory over the same workspace.
  // Before the re-anchor the adoption gap is red (the keyless era's baseline
  // claims are authored by no key this host holds) — then the documented
  // recovery runs: re-anchor.
  const engine = new ProofEngine({
    root: '/ws',
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(),
    signer: async () => new FakeSigner(),
    trustDir: '/trust',
    workspaceKey: 'wskey',
    impactGraphLimit: 1_000,
  })
  const mid = await engine.audit()
  assert.equal(mid.ok, false, 'before the re-anchor, the un-vouched keyless-era baseline claims keep the audit red')
  await engine.establishBaseline({ reason: 'signer adoption' })

  const audit = await engine.audit()
  assert.deepEqual(audit.chain.refusedToSign, [],
    'v0.24 writes the established marker before saveBaseline\'s checkpoint, so even the design-anticipated first-boundary refusal never happens: every baseline-family newest is self-authored before the first signing boundary')
  assert.ok((audit.chain.unsignedEraCheckpoints?.length ?? 0) >= 2,
    'the keyless era\'s naked boundaries stay visible on their own channel')
  assert.deepEqual(audit.chain.unsignedCheckpoints, [], 'and they are not a charge — the era is a generation, not a life sentence')
  assert.equal(audit.ok, true,
    'v0.23 billed the keyless era\'s naked checkpoints forever: adoption was a one-way door to a permanent red, and every later grade was capped at stale by X-H-09')

  // X-H-09 consumer side: a recovered audit means grades are grades again.
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'proven', 'the adoption recovered — the workspace can still prove work')
  assert.equal(outcome.auditFailed, undefined)
})

// -- V1-M7 (v0.24): the one-line DoS charges the line, not the deployment ------

test('V1-M7: an unknown-kind line is a red, not a permanent signing ban — surgery plus re-anchor recovers', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint()

  // THE ADVERSARY: one appended `ghost` line, chained correctly. v0.23: the
  // line is malformed forever, every later checkpoint REFUSES forever (the
  // refusal rows themselves piling up), and no documented recovery exists.
  const lines = await fs.readLines(LOG)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const ghost = JSON.stringify({ v: 2, kind: 'ghost', at: '2026-10-06T00:00:00.000Z', prev, payload: { note: 'no honest writer emits me' } })
  fs.mutate(LOG, `${[...lines, ghost].join('\n')}\n`)
  await store.checkpoint()

  const attacked = await store.audit()
  assert.deepEqual(attacked.chain.malformedCheckpoints, [2], 'the smuggled line is named on the loud channel')
  assert.equal(attacked.chain.refusedToSign!.length, 1, 'the boundary refused to lend the key over it')
  assert.equal(attacked.ok, false, 'the attack itself is correctly red — that charge stays')

  // Operator surgery: remove ONLY the ghost line and re-chain the honest tail.
  // The refusal rows are honest history and stay on the chain.
  const after = await fs.readLines(LOG)
  const kept = after.filter(l => l !== ghost)
  const ghostAt = after.indexOf(ghost)
  const healed: string[] = [...kept]
  for (let i = ghostAt; i < healed.length; i++) {
    const prevDigest = i === 0 ? GENESIS_PREV : lineDigest(healed[i - 1] as string)
    const envelope = JSON.parse(healed[i] as string) as { prev: string; payload?: { head?: string } }
    envelope.prev = prevDigest
    if (envelope.payload?.head !== undefined) envelope.payload.head = prevDigest
    healed[i] = JSON.stringify(envelope)
  }
  fs.mutate(LOG, `${healed.join('\n')}\n`)

  // The next boundary signs again, and the OLD refusal — whose cause is gone
  // — is pardoned by the generational slice instead of billing forever.
  const session2 = trustedStore(fs).store
  await session2.checkpoint()
  const recovered = await session2.audit()
  assert.deepEqual(recovered.chain.malformedCheckpoints, [])
  assert.equal(recovered.chain.refusedToSign!.length, 1, 'the scar stays visible')
  assert.deepEqual(recovered.chain.refusedToSignPardoned, [recovered.chain.refusedToSign![0]], 'Y-H-02/V1-M7: recovered generation, no longer a charge')
  assert.equal(recovered.ok, true, 'surgery plus re-anchor is a real recovery — the DoS does not outlive its cause')
})

// -- V1-M9 (v0.24): the adopted trust labels carry the witness ------------------

test('V1-M9: agent-team/economics/claim/synthetic labels carry headRef — injected twins are excluded by the reads that claim to filter', async () => {
  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.mark('agent-team/delegated', { hostTaskId: 'h1', engineTaskId: 'e1' })
  await store.mark('economics/quote', { quoteId: 'q1' })
  await store.mark('claim/jury', { claimId: 'c1', verdict: 'uphold' })
  await store.mark('synthetic/requested', { claimId: 's1', entry: 'x' })
  const labels = ['agent-team/delegated', 'economics/quote', 'claim/jury', 'synthetic/requested'] as const
  for (const label of labels) {
    const honest = await store.markersWith(label)
    assert.equal(honest[0]?.suspect, false, `${label}: the honest write reads clean`)
    assert.equal(typeof honest[0]?.payload.headRef, 'string', `${label}: the write stamps the position witness`)
  }

  // THE ADVERSARY: headRef-less twins appended out of band under the same
  // labels — the exact shape that made every `excludeSuspect` read of these
  // labels a dead channel in v0.23 (the labels were not protected, so
  // `suspect` was structurally false and the filter never fired).
  const lines = await fs.readLines(LOG)
  let prev = lineDigest(lines[lines.length - 1] as string)
  const twins = labels.map(label => {
    const line = JSON.stringify({ v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev, payload: { label, forged: true } })
    prev = lineDigest(line)
    return line
  })
  fs.mutate(LOG, `${[...lines, ...twins].join('\n')}\n`)

  for (const label of labels) {
    const trusted = await store.markersWith(label, { excludeSuspect: true })
    assert.equal(trusted.length, 1, `${label}: only the honest line survives the suspect filter`)
    assert.notEqual(trusted[0]?.payload.forged, true)
    const view = await createVerifiedView(store).markers(label)
    assert.equal(view.degraded, false)
    assert.equal(view.records.length, 1, `${label}: the verified view keeps the twin out of the trusted pool`)
  }
})
