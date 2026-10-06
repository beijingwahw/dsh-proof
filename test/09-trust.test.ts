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

import { EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { GENESIS_PREV, checkpointSignedData, lineDigest } from '../src/core/trust.ts'
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

test('M15 + unsignedCheckpoints: a transient signer failure is not memoized — the next checkpoint signs again', async () => {
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
  await store.checkpoint() // provider rejects: an unsigned checkpoint lands

  // Recovery: the provider heals. The store must RETRY it — the old code
  // cached the first failure forever, so every later checkpoint stayed
  // unsigned and the audit's ok could never recover either.
  broken = false
  await store.append(evidence('c2'))
  await store.checkpoint()

  const audit = await store.audit()
  // The real channel trigger: a sig-less checkpoint while a signer is (again)
  // active is exactly what unsignedCheckpoints exists to name.
  assert.deepEqual(audit.chain.unsignedCheckpoints, [1], 'the first checkpoint is unsigned and the host key is back — charged')
  assert.equal(audit.ok, false)
  // Proof the SECOND checkpoint was signed (the retry worked): the anchor is
  // only ever written by a successful sign(), and it covers count 2.
  const anchorRaw = await fs.readFile(ANCHOR)
  assert.notEqual(anchorRaw, undefined, 'no anchor could ever be written while the failure was memoized')
  const anchor = JSON.parse(anchorRaw as string) as { count: number; keyId: string }
  assert.equal(anchor.count, 2)
  assert.equal(anchor.keyId, 'fake-key')
  assert.equal(audit.chain.checkpoints, 2)
  assert.equal(audit.chain.mode, 'signed')
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
