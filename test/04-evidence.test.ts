import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  EvidenceStore, buildBaseline, createVerifiedView, makeEvidence, snapshotWorkspace, verdictOf,
} from '../src/core/evidence.ts'
import { assembleProof } from '../src/core/report.ts'
import { addressOf, sha256 } from '../src/core/hash.ts'
import { checkpointSignedData, lineDigest } from '../src/core/trust.ts'
import type { SignerPort } from '../src/core/ports.ts'
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

// -- W1-M6 (v0.23): the marker label is store-owned --------------------------------

test('W1-M6: mark() data cannot re-brand the line — label is written by the store', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const store = new EvidenceStore(fs, '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', clock)
  await store.mark('session/start', { who: 'test', label: 'attest/human', decision: 'endorse' })

  const seen = await store.markersWith('session/start')
  assert.equal(seen.length, 1, 'the line keeps the label the caller passed to mark()')
  assert.equal(seen[0]?.payload.label, 'session/start')
  assert.equal((await store.markersWith('attest/human')).length, 0, 'no protected-label twin was minted by the spread')
  // Honest byte order is unchanged: label is still the payload's first key,
  // so pre-v0.23 log shapes (and any reader keyed on them) are untouched.
  const line = JSON.parse((await fs.readLines('/ws/.proof/evidence.jsonl'))[0] as string) as { payload: Record<string, unknown> }
  assert.equal(Object.keys(line.payload)[0], 'label')
  assert.equal(line.payload.who, 'test', 'caller data rides along untouched')
})

// -- W1-M8 (v0.23): dirtDigest is injective over the dirty set ---------------------

test('W1-M8: a newline inside a filename is not two files — dirtDigest is injective', () => {
  const one = snapshotWorkspace(null, ['a\nb'])
  const two = snapshotWorkspace(null, ['a', 'b'])
  assert.notEqual(one.dirtDigest, two.dirtDigest, 'join("\\n") made {a\\nb} ≡ {a,b}; the length-prefixed encoding cannot')
  // The old guarantees survive: order-independence and the clean-tree digest.
  assert.equal(snapshotWorkspace(null, ['b', 'a']).dirtDigest, snapshotWorkspace(null, ['a', 'b']).dirtDigest)
  assert.equal(snapshotWorkspace(null, []).dirtDigest, sha256(''), 'an empty dirty set keeps its v0.22 digest (sha256 of nothing)')
})

// -- v0.23: the verified read layer — markers() -------------------------------------
//
// The one trust surface for marker reads: single physical read, suspect
// position adjudication, the X-H-06 generational fallback, and an epoch window.

test('VerifiedChainView.markers: trusted pool only; the attacker twin is not admitted', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const log = '/ws/.proof/evidence.jsonl'
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', clock)
  await store.append(makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock))
  await store.mark('attest/human', { claimId: 'claim-1', decision: 'endorse' })
  await store.mark('attest/human', { claimId: 'claim-2', decision: 'endorse' })

  // THE ADVERSARY: a twin appended at the tail carrying the digest it wants
  // read back. It chains fine; its headRef is a guess and reads suspect.
  const lines = await fs.readLines(log)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const twin = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
    payload: { label: 'attest/human', claimId: 'claim-2', decision: 'reject', headRef: 'ff'.repeat(32) },
  })
  fs.mutate(log, `${[...lines, twin].join('\n')}\n`)

  const view = createVerifiedView(store)
  const seen = await view.markers('attest/human')
  assert.equal(seen.degraded, false)
  assert.equal(seen.records.length, 2, 'only the two honest markers are trusted')
  assert.deepEqual(seen.records.map(r => r.payload.claimId), ['claim-1', 'claim-2'])
  assert.equal(seen.last?.payload.decision, 'endorse', 'last-wins reads the honest line, never the twin')
  // The raw view keeps everything — suspect is visible, not deleted.
  assert.equal((await store.markersWith('attest/human')).length, 3)
})

test('VerifiedChainView.markers: X-H-06 generational fallback — a legacy all-suspect label degrades, never evaporates', async () => {
  const fs = MemoryFs.of({})
  const log = '/ws/.proof/evidence.jsonl'
  // A v0.21-shaped log: protected markers written before the headRef witness
  // existed. Every one of them reads suspect under the H-32 rule, and v0.22's
  // hard exclusion evaporated the whole DAG (delegation renumbering, lost
  // attestations). The view falls back to the full list, marked degraded.
  const legacy = [
    { label: 'delegation/created', taskId: 'task-1', parent: 'root' },
    { label: 'delegation/created', taskId: 'task-2', parent: 'root' },
    { label: 'delegation/created', taskId: 'task-3', parent: 'task-1' },
  ]
  let prev = '0000000000000000000000000000000000000000000000000000000000000000'
  const lines = legacy.map(payload => {
    const line = JSON.stringify({ v: 2, kind: 'marker', at: '2026-01-01T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
  fs.mutate(log, `${lines.join('\n')}\n`)
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', new FakeClock())

  const view = createVerifiedView(store)
  const seen = await view.markers('delegation/created')
  assert.equal(seen.degraded, true, 'every marker of the label is suspect: the legacy generation, not an attack verdict')
  assert.equal(seen.records.length, 3, 'the whole DAG is read back — an upgraded deployment is never worse than before')
  assert.ok(seen.records.every(r => r.degraded === true), 'each record is marked degraded so consumers can refuse degraded trust')
  assert.equal(seen.last?.payload.taskId, 'task-3', 'last-wins keeps the physically last record, lastBaselineDigest\'s rule')
})

test('VerifiedChainView.markers: the sinceLine epoch window and the mixed-generation rule', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const log = '/ws/.proof/evidence.jsonl'
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', clock)
  await store.mark('proof/verified', { grade: 'proven', gen: 1 })
  const boundary = (await fs.readLines(log)).length // the generation boundary callers anchor on
  await store.mark('proof/verified', { grade: 'stale', gen: 2 })

  const view = createVerifiedView(store)
  const all = await view.markers('proof/verified')
  assert.equal(all.records.length, 2)
  const since = await view.markers('proof/verified', { sinceLine: boundary })
  assert.equal(since.records.length, 1, 'only markers at or after the boundary line are in the window')
  assert.equal(since.records[0]?.payload.gen, 2)
  assert.equal(since.last?.payload.gen, 2, 'last is last-wins within the window')

  // Mixed generations: a suspect marker inside the window is EXCLUDED (not
  // fallen back for) whenever the label has any non-suspect marker at all —
  // the fallback is a property of the log's generation, not of the window.
  const lines = await fs.readLines(log)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const twin = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
    payload: { label: 'proof/verified', grade: 'proven', gen: 2, headRef: '00'.repeat(32) },
  })
  fs.mutate(log, `${[...lines, twin].join('\n')}\n`)
  const afterTwin = await view.markers('proof/verified', { sinceLine: boundary })
  assert.deepEqual(afterTwin.records.map(r => r.payload.gen), [2], 'the twin stays out: a trusted generation excludes, never degrades')
  assert.equal(afterTwin.degraded, false)
})

// -- V1-M5/M6 (v0.24): the degraded pool only reaches DOWN to the anchor -------

test('V1-M6: the generational fallback stops at the last verified checkpoint — a fresh headRef-less injection is not legacy history', async () => {
  const fs = MemoryFs.of({})
  const log = '/ws/.proof/evidence.jsonl'
  // The v0.21 shape: protected markers written before the headRef witness
  // existed (all suspect under the H-32 rule), and — like every real v0.21
  // chain — a checkpoint. The v0.23 fallback pool was "every suspect marker
  // of the label", which could not tell this history from a headRef-less
  // line appended AFTER the anchor today.
  const legacy = [
    { label: 'delegation/created', taskId: 'task-1', parent: 'root' },
    { label: 'delegation/created', taskId: 'task-2', parent: 'root' },
  ]
  let prev = '0000000000000000000000000000000000000000000000000000000000000000'
  const lines = legacy.map(payload => {
    const line = JSON.stringify({ v: 2, kind: 'marker', at: '2026-01-01T00:00:00.000Z', prev, payload })
    prev = lineDigest(line)
    return line
  })
  const checkpointPayload = { count: 2, head: prev, workspaceKey: null, at: '2026-01-02T00:00:00.000Z' }
  const checkpoint = JSON.stringify({
    v: 2, kind: 'checkpoint', at: '2026-01-02T00:00:00.000Z', prev,
    payload: checkpointPayload,
    sig: `sig:${sha256(checkpointSignedData(checkpointPayload))}`, keyId: 'fake-key',
  })
  prev = lineDigest(checkpoint)
  fs.mutate(log, `${[...lines, checkpoint].join('\n')}\n`)

  // THE ADVERSARY: a headRef-less `delegation/created` appended after the
  // checkpoint — chained correctly (so the walk stays clean), shaped exactly
  // like the legacy rows.
  const injection = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
    payload: { label: 'delegation/created', taskId: 'task-999', parent: 'root', obligation: 'forged-proven' },
  })
  fs.mutate(log, `${[...lines, checkpoint, injection].join('\n')}\n`)

  const signer = new (class implements SignerPort {
    readonly keyId = 'fake-key'
    async sign(): Promise<string> { throw new Error('read-only signer') }
    async verify(data: string, sig: string): Promise<boolean> { return sig === `sig:${sha256(data)}` }
  })()
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', new FakeClock(), {
    signer: async () => signer,
  })
  const view = createVerifiedView(store)
  const seen = await view.markers('delegation/created')
  assert.equal(seen.degraded, true, 'the legacy generation still reads — an upgraded deployment is never worse than before')
  assert.deepEqual(
    seen.records.map(r => r.payload.taskId),
    ['task-1', 'task-2'],
    'the fresh injection does not enter the degraded pool: a headRef-less line above the anchor is a forgery, not history',
  )
  assert.equal(seen.last?.payload.taskId, 'task-2', 'last-wins answers the legacy tail, never the injected task-999')

  // Control: the same log WITHOUT a verifiable checkpoint has no epoch bound
  // to defend with — the whole suspect population reads degraded as before
  // (the keyless-view residual, deliberately not guessed around).
  const keylessView = createVerifiedView(new EvidenceStore(fs, log, '/ws/.proof/baseline.json', new FakeClock()))
  const keyless = await keylessView.markers('delegation/created')
  assert.deepEqual(keyless.records.map(r => r.payload.taskId), ['task-1', 'task-2', 'task-999'])
})

// -- V1-M8 (v0.24): one line-array convention, both faces ----------------------

test('V1-M8: a blank line cannot fork the store face — marker reads judge headRef in the readLines domain', async () => {
  const fs = MemoryFs.of({})
  const log = '/ws/.proof/evidence.jsonl'
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', new FakeClock())
  await store.append(makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, new FakeClock()))
  await store.mark('attest/human', { claimId: 'claim-1', decision: 'endorse' })

  // THE ADVERSARY: insert a blank line between the marker and its physical
  // predecessor. The writer stamped headRef against the last NON-BLANK line
  // (the store's tail); a face that judged the witness against the raw
  // previous line saw a blank and read the honest marker as suspect.
  const lines = (await fs.readFile(log) as string).split('\n').filter(l => l.length > 0)
  lines.splice(1, 0, '')
  fs.mutate(log, `${lines.join('\n')}\n`)

  const seen = await store.markersWith('attest/human')
  assert.equal(seen.length, 1)
  assert.equal(seen[0]?.suspect, false, 'the witness names the previous non-blank line — the readLines domain, on every face')
  const view = createVerifiedView(store)
  const trusted = await view.markers('attest/human')
  assert.equal(trusted.degraded, false)
  assert.equal(trusted.records.length, 1, 'the view (same domain) still admits the honest marker')
})

// -- V1-L11 (v0.24): twin evidence rows cannot win last-wins -------------------

test('V1-L11: an out-of-band twin evidence row (same id, doctored payload) is dropped at read time', async () => {
  const fs = MemoryFs.of({})
  const clock = new FakeClock()
  const log = '/ws/.proof/evidence.jsonl'
  const store = new EvidenceStore(fs, log, '/ws/.proof/baseline.json', clock)
  const honest = makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: 'ok' }, WS, clock)
  await store.append(honest)

  // THE ADVERSARY: append a chained line re-using the honest row's id over a
  // doctored payload. It parses, chains, and self-reports the same id — but
  // it no longer addresses itself, which is the only identity an evidence
  // row ever has.
  const lines = await fs.readLines(log)
  const prev = lineDigest(lines[lines.length - 1] as string)
  const { evidenceId, ...rest } = honest
  const doctored = { ...rest, status: 'fail' as const }
  const twin = JSON.stringify({ v: 2, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', prev, payload: { ...doctored, evidenceId } })
  fs.mutate(log, `${[...lines, twin].join('\n')}\n`)

  const all = await store.all()
  assert.equal(all.length, 1, 'the twin does not exist for the read surface')
  assert.equal((await store.latest()).get('c1')?.status, 'pass', 'last-wins cannot be hijacked by a row that cannot derive its own id')
  // The audit still SEES the bad row and charges it — visibility is the
  // charge's job, read trust is all()'s.
  const audit = await store.audit()
  assert.equal(audit.ok, false)
  assert.deepEqual(audit.corrupt, ['c1'])
})
