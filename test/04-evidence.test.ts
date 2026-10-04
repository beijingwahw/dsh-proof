import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  EvidenceStore, buildBaseline, makeEvidence, snapshotWorkspace, verdictOf,
} from '../src/core/evidence.ts'
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
  assert.deepEqual(audit, { ok: true, total: 1, corrupt: [] })

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

  assert.equal(verdictOf(pass, pass), 'still-passing')
  assert.equal(verdictOf(fail, fail), 'still-failing')
  assert.equal(verdictOf(pass, fail), 'regression')
  assert.equal(verdictOf(fail, pass), 'fixed')
  assert.equal(verdictOf(undefined, fail), 'new-failure')
  assert.equal(verdictOf(undefined, pass), 'new-check')
  assert.equal(verdictOf(pass, undefined), 'not-run')
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
