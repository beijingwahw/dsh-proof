import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace, verdictOf,
} from '../src/core/evidence.ts'
import { assembleProof } from '../src/core/report.ts'
import { addressOf } from '../src/core/hash.ts'
import { MemoryFs, FakeClock, FakeWorkspace, spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', ['src/a.ts'])

test('evidence addresses itself: evidenceId === addressOf(the rest)', () => {
  const clock = new FakeClock()
  const ev = makeEvidence(spec({ id: 'c1' }), {
    status: 'pass', exitCode: 0, durationMs: 12, output: 'ok\n',
  }, WS, clock)
  const { evidenceId, ...rest } = ev
  assert.equal(evidenceId, addressOf(rest))
})

test('identical outcomes collapse to the same address', () => {
  const clock = new FakeClock()
  const s = spec({ id: 'c1' })
  const a = makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok\n' }, WS, clock)
  const b = makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 99, output: 'ok \n' }, WS, clock)
  // duration differs -> different address; content digest is what collapses.
  assert.notEqual(a.evidenceId, b.evidenceId)
  assert.equal(a.outputDigest, b.outputDigest, 'cosmetic output churn must not change the digest')
})

test('store appends, dedupes and audits integrity', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const ev = makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)

  await store.append(ev)
  await store.append(ev)
  const all = await store.all()
  assert.equal(all.length, 1, 're-appending the same address is a no-op')

  const audit = await store.audit()
  assert.equal(audit.ok, true)
  assert.equal(audit.total, 1)
  assert.deepEqual(audit.corrupt, [])
  assert.equal(audit.chain.mode, 'unsigned', 'a store without a signer produces an unsigned v2 chain')
  assert.equal(audit.chain.breaks.length, 0)

  // Tamper with the log and confirm the audit catches it.
  fs.mutate('/ws/.proof/evidence.jsonl', JSON.stringify({ v: 1, kind: 'evidence', at: 't', payload: { ...ev, status: 'fail' } }) + '\n')
  const tampered = await store.audit()
  assert.equal(tampered.ok, false)
  assert.deepEqual(tampered.corrupt, ['c1'])
})

test('latest() keeps the newest evidence per check', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const s = spec({ id: 'c1' })
  await store.append(makeEvidence(s, { status: 'fail', exitCode: 1, durationMs: 1, output: 'no' }, WS, clock))
  await store.append(makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 1, output: 'yes' }, WS, clock))
  const latest = await store.latest()
  assert.equal(latest.get('c1')?.status, 'pass')
})

test('baseline round-trips through the store', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const records = [makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)]
  const baseline = buildBaseline(records, WS, clock)
  await store.saveBaseline(baseline)
  const loaded = await store.loadBaseline()
  assert.equal(loaded?.baselineId, baseline.baselineId)
  assert.equal(loaded?.root, baseline.root)
  assert.equal(loaded?.checks.length, 1)
})

test('verdictOf is the baseline differential', () => {
  const clock = new FakeClock()
  const s = spec({ id: 'c1' })
  const pass = makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)
  const fail = makeEvidence(s, { status: 'fail', exitCode: 1, durationMs: 1, output: 'no' }, WS, clock)
  const skipped = makeEvidence(s, { status: 'skipped', exitCode: null, durationMs: 0, output: 'skipped: budget exhausted' }, WS, clock)
  const timeout = makeEvidence(s, { status: 'timeout', exitCode: null, durationMs: 9, output: '' }, WS, clock)

  assert.equal(verdictOf(pass, pass), 'still-passing')
  assert.equal(verdictOf(fail, fail), 'still-failing')
  assert.equal(verdictOf(pass, fail), 'regression')
  assert.equal(verdictOf(fail, pass), 'fixed')
  assert.equal(verdictOf(undefined, fail), 'new-failure')
  assert.equal(verdictOf(undefined, pass), 'new-check')
  assert.equal(verdictOf(pass, undefined), 'not-run')

  // The knowledge lattice: unknown is neither credit nor blame. A baseline
  // that never produced a result cannot seed a regression (or a fix), and a
  // current run without a conclusion cannot bank a pass.
  assert.equal(verdictOf(skipped, fail), 'indeterminate', 'a never-run baseline must not charge a regression')
  assert.equal(verdictOf(skipped, pass), 'indeterminate', 'a never-run baseline must not mint a pass either')
  assert.equal(verdictOf(pass, skipped), 'indeterminate', 'skipped this run is not "still passing"')
  assert.equal(verdictOf(fail, skipped), 'indeterminate', 'skipped this run must not fake a "fixed"')
  assert.equal(verdictOf(undefined, skipped), 'indeterminate', 'a new check that never ran earns nothing')
  assert.equal(verdictOf(timeout, pass), 'indeterminate', 'timeout at baseline is not a decisive fail')
  assert.equal(verdictOf(pass, timeout), 'indeterminate', 'timeout this run is not a decisive regression')
  assert.equal(verdictOf(skipped, skipped), 'indeterminate')
})

test('summary counts indeterminate verdicts and never credits unrun new checks', () => {
  const clock = new FakeClock()
  const s = spec({ id: 'c1' })
  const passedAtBaseline = makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)
  const skippedNow = makeEvidence(s, { status: 'skipped', exitCode: null, durationMs: 0, output: 'skipped: budget exhausted' }, WS, clock)

  const { report } = assembleProof({
    specs: [s],
    baseline: buildBaseline([passedAtBaseline], WS, clock),
    records: [skippedNow],
    changed: ['src/a.ts'],
    workspace: WS,
    clock,
  })
  assert.equal(report.checks[0]?.verdict, 'indeterminate')
  assert.equal(report.summary.indeterminate, 1)
  assert.equal(report.summary.passing, 0, 'a skipped current run must not count as passing')
  assert.equal(report.summary.failing, 0, 'nor as failing — blame needs a decisive red')

  // A newly discovered check that was never run: counted as a new check, but
  // it must not dilute the passing number.
  const fresh = assembleProof({
    specs: [spec({ id: 'c-new' })],
    records: [],
    changed: ['src/a.ts'],
    workspace: WS,
    clock,
  })
  assert.equal(fresh.report.checks[0]?.verdict, 'new-check')
  assert.equal(fresh.report.summary.newChecks, 1)
  assert.equal(fresh.report.summary.passing, 0, 'an unrun check is not a passing check')
})

test('snapshotWorkspace digests the dirty set order-independently', () => {
  const a = snapshotWorkspace(null, ['b', 'a'])
  const b = snapshotWorkspace(null, ['a', 'b'])
  assert.equal(a.dirtDigest, b.dirtDigest)
  assert.deepEqual(a.dirty, ['a', 'b'])
})

test('snapshotWorkspace resolves through a WorkspacePort', async () => {
  const ws = new FakeWorkspace('/ws')
  ws.dirty = ['x.ts']
  const snapshot = await snapshotWorkspace(ws)
  assert.equal(snapshot.head, 'abc123')
  assert.deepEqual(snapshot.dirty, ['x.ts'])
})

test('M-34: a failed git query is a degraded snapshot, never a clean tree', async () => {
  const broken = new FakeWorkspace('/ws')
  broken.gitHead = async () => { throw new Error('index.lock: another git process') }
  const snapshot = await snapshotWorkspace(broken)
  assert.equal(snapshot.gitDegraded, true, 'head:null + dirty:[] now say WHY: the queries failed, the tree was not observed clean')
  assert.equal(snapshot.head, null)
  assert.deepEqual(snapshot.dirty, [])
  // The honest port attaches nothing — every existing address is untouched.
  const clean = await snapshotWorkspace(new FakeWorkspace('/ws'))
  assert.equal('gitDegraded' in clean, false)
})

test('H-23: loadBaseline refuses a baseline that cannot re-derive its own identity', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const records = [makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)]
  const baseline = buildBaseline(records, WS, clock)
  await store.saveBaseline(baseline)
  assert.notEqual(await store.loadBaseline(), undefined, 'sanity: the honest round trip still loads')

  // The lazy edit: flip a payload field under a kept evidenceId. The file
  // parses and shape-checks; only recomputing the identity catches it.
  const doctored = JSON.parse(JSON.stringify(baseline)) as typeof baseline
  ;(doctored.checks[0] as { status: string }).status = 'fail'
  fs.mutate('/ws/.proof/baseline.json', JSON.stringify(doctored, null, 2))
  assert.equal(await store.loadBaseline(), undefined, 'a doctored payload under a kept id is not a baseline')
  const audit = await store.audit()
  assert.equal(audit.chain.baselineTampered, true)
  assert.equal(audit.ok, false)
})

test('H-23: stripping a non-addressing attachment (scriptDigests) is caught by the chain digest', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const records = [makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)]
  const baseline = buildBaseline(records, WS, clock)
  // The engine's shape: scriptDigests rides as a non-addressing attachment —
  // canonical ids alone can never see it, the recorded file digest can.
  const anchored = { ...baseline, scriptDigests: { 'config:c1': 'deadbeef' } }
  await store.saveBaseline(anchored)
  assert.notEqual(await store.loadBaseline(), undefined, 'the attachment loads while intact')

  fs.mutate('/ws/.proof/baseline.json', JSON.stringify(baseline, null, 2))
  assert.equal(await store.loadBaseline(), undefined, 'stripping the field changed the bytes the chain remembers — not the baseline the chain saved')
  const audit = await store.audit()
  assert.equal(audit.chain.baselineTampered, true)
  assert.equal(audit.ok, false)
})

test('a baseline with no chain witness loads on canonical merit alone (legacy tolerance)', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  const records = [makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)]
  // Hand-placed, never marked: no baseline/saved witness exists. Integrity
  // still holds canonically, and the loader degrades to the canonical check
  // rather than manufacturing an accusation it cannot support.
  fs.mutate('/ws/.proof/baseline.json', JSON.stringify(buildBaseline(records, WS, clock), null, 2))
  const loaded = await store.loadBaseline()
  assert.notEqual(loaded, undefined)
  assert.equal(loaded?.checks.length, 1)
})
