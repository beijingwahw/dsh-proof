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
import { GENESIS_PREV, lineDigest } from '../src/core/trust.ts'
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

test('legacy v1 logs remain readable and audit honestly as legacy', async () => {
  const fs = MemoryFs.of({})
  const ev = evidence('c1')
  fs.mutate(LOG, `${JSON.stringify({ v: 1, kind: 'evidence', at: '2026-09-01T00:00:00.000Z', payload: ev })}\n`)
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock())
  const audit = await store.audit()
  assert.equal(audit.chain.mode, 'legacy')
  assert.equal(audit.total, 1)
  assert.equal(audit.ok, true)
  // A v2 append after legacy lines chains from the physically previous line.
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
