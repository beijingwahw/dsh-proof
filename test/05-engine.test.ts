import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ProofEngine } from '../src/engine.ts'
import { assembleProof } from '../src/core/report.ts'
import { attributeChecks } from '../src/core/regression.ts'
import { snapshotWorkspace } from '../src/core/evidence.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs, spec } from './helpers.ts'

const ROOT = '/ws'

function project() {
  return {
    [`${ROOT}/package.json`]: JSON.stringify({
      name: 'demo',
      scripts: { test: 'vitest run', build: 'tsc -b' },
    }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/src/b.ts`]: "import { a } from './a'\nexport const b = a + 1\n",
    [`${ROOT}/test/a.test.ts`]: "import { a } from '../src/a'\nvoid a\n",
  }
}

function makeEngine(fs: MemoryFs, commands: FakeCommands, dirty: string[] = []) {
  const ws = new FakeWorkspace(ROOT)
  ws.dirty = dirty
  return new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: ws,
    clock: new FakeClock(),
    impactGraphLimit: 1_000,
    checkTimeoutMs: 5_000,
    verifyBudgetMs: 20_000,
    concurrency: 2,
  })
}

function preciseEngine(fs: MemoryFs, commands: FakeCommands, checks: ConstructorParameters<typeof ProofEngine>[0]['checks']) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    autoDiscover: false,
    checks,
  })
}

test('discovers the workspace objective checks', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  const checks = await engine.loadChecks()
  assert.deepEqual(checks.map(c => c.kind).sort(), ['build', 'test'])
})

test('a clean session: baseline green, verify green -> PROVEN', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())

  const { baseline } = await engine.establishBaseline()
  assert.equal(baseline.checks.length, 2)
  assert.ok(baseline.checks.every(c => c.status === 'pass'))

  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'proven')
  assert.equal(outcome.report.summary.regressions, 0)
  assert.equal(outcome.report.baselineRoot, baseline.root)
  assert.equal(outcome.report.root.length, 64, 'proof root is a sha-256 hex digest')
})

test('THE HEADLINE: regression is charged to the session, pre-existing red is not', async () => {
  const commands = new FakeCommands()
    .on(argv => argv.includes('test'), { exitCode: 1, output: 'FAIL test/a.test.ts\nAssertionError: expected 1 to be 2' })
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, commands)

  const { baseline } = await engine.establishBaseline()
  assert.equal(baseline.checks.find(c => c.kind === 'test')?.status, 'fail')
  assert.equal(baseline.checks.find(c => c.kind === 'build')?.status, 'pass')

  // The session now breaks `build` too. `test` is still red — but it was red
  // before we touched anything, so it must NOT be charged to this work.
  commands.on(argv => argv.includes('build'), { exitCode: 2, output: "src/b.ts(1,1): error TS2304: Cannot find name 'a'" })
  const outcome = await engine.verify({ changed: ['src/b.ts'] })

  const byKind = new Map(outcome.checks.map(c => [c.kind, c]))
  assert.equal(byKind.get('test')?.verdict, 'still-failing', 'already-red stays pre-existing')
  assert.equal(byKind.get('build')?.verdict, 'regression', 'newly-red is a regression')

  assert.equal(outcome.report.grade, 'regressed')
  assert.equal(outcome.report.summary.regressions, 1)
  assert.equal(outcome.report.summary.preExisting, 1)
  assert.equal(outcome.report.regressions.length, 1)
  assert.match(outcome.report.regressions[0] ?? '', /build/)

  const buildCheck = byKind.get('build')
  assert.ok(buildCheck, 'build check present')
  assert.ok(buildCheck.suspects.includes('src/b.ts'), `suspects: ${buildCheck.suspects.join(', ')}`)
})

test('fixing a pre-existing failure is recognised as FIXED', async () => {
  const commands = new FakeCommands().on(argv => argv.includes('test'), { exitCode: 1, output: 'old failure' })
  const engine = makeEngine(MemoryFs.of(project()), commands)
  await engine.establishBaseline()

  commands.on(argv => argv.includes('test'), { exitCode: 0, output: 'ok' })
  const outcome = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(outcome.checks.find(c => c.kind === 'test')?.verdict, 'fixed')
  assert.equal(outcome.report.summary.fixed, 1)
})

test('no baseline -> grade is no-baseline, never proven', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  const outcome = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(outcome.report.grade, 'no-baseline')
  assert.equal(outcome.report.baselineRoot, null)
})

test('a check that could not produce a verdict makes the claim STALE', async () => {
  const commands = new FakeCommands()
    .on(argv => argv.includes('test'), { exitCode: null, spawnError: 'spawn failed: ENOENT' })
  const engine = makeEngine(MemoryFs.of(project()), commands)
  await engine.establishBaseline()
  const outcome = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(outcome.report.grade, 'stale')
  assert.ok(outcome.report.unverified.length > 0, 'the undecidable check must be named')
})

test('an aborted run refuses to claim PROVEN', async () => {
  const commands = new FakeCommands()
    .on(argv => argv.includes('build'), { exitCode: null, aborted: true })
  const engine = makeEngine(MemoryFs.of(project()), commands)
  await engine.establishBaseline()
  const outcome = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(outcome.report.grade, 'stale')
})

test('budget exhaustion marks checks skipped and downgrades to STALE', async () => {
  const engine = new ProofEngine({
    root: ROOT,
    fs: MemoryFs.of(project()),
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    verifyBudgetMs: 1,
  })
  await engine.establishBaseline()
  const outcome = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(outcome.report.grade, 'stale', `got ${outcome.report.grade}`)
  assert.ok(outcome.report.unverified.length > 0)
})

test('a global invalidator forces every check to re-run', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  fs.mutate(`${ROOT}/package.json`, JSON.stringify({
    name: 'demo',
    scripts: { test: 'vitest run', build: 'tsc -b', lint: 'eslint .' },
  }))
  const outcome = await engine.verify({ changed: ['package.json'] })
  assert.equal(outcome.selection.forcedAll, true)
  assert.equal(outcome.report.grade, 'proven')
  assert.equal(outcome.report.unverified.length, 0)
})

test('impact analysis runs only what the change set touched', async () => {
  const fs = MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/docs/guide.md`]: '# guide\n',
    [`${ROOT}/docs/note.md`]: '# note\n',
  })
  const engine = preciseEngine(fs, new FakeCommands(), [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
    { label: 'docs build', command: ['make', 'docs'], kind: 'build', paths: ['docs/**'] },
  ])
  await engine.establishBaseline()

  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.deepEqual(outcome.selection.affected.map(c => c.label), ['src tests'])
  assert.deepEqual(outcome.selection.untouched.map(c => c.label), ['docs build'])
  assert.equal(outcome.checks.find(c => c.label === 'docs build')?.verdict, 'not-run')
  assert.equal(outcome.report.grade, 'proven')
})

test('a change set no check covers is honestly UNPROVEN, not proven', async () => {
  const fs = MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/docs/guide.md`]: '# guide\n',
  })
  const engine = preciseEngine(fs, new FakeCommands(), [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
  ])
  await engine.establishBaseline()

  const outcome = await engine.verify({ changed: ['docs/guide.md'] })
  assert.equal(outcome.selection.affected.length, 0, 'no check covers docs/')
  assert.equal(outcome.report.grade, 'unproven', `got ${outcome.report.grade}`)
})

test('the evidence log survives a full cycle and audits clean', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'], all: true })
  const audit = await engine.audit()
  assert.equal(audit.ok, true, `corrupt: ${audit.corrupt.join(', ')}`)
  assert.ok(audit.total >= 4, `expected >= 4 records, got ${audit.total}`)
})

test('assembleProof is deterministic for identical inputs', () => {
  const clock = new FakeClock()
  const ws = snapshotWorkspace('h', [])
  const s = spec({ id: 'x', paths: ['src/**'] })
  const input = {
    specs: [s],
    records: [],
    changed: ['src/a.ts'],
    workspace: ws,
    clock,
    requireFullCoverage: true,
  }
  const first = assembleProof(input)
  const second = assembleProof(input)
  assert.equal(first.report.root, second.report.root)
  assert.equal(first.report.grade, second.report.grade)
})

test('attributeChecks explains every verdict in one line', () => {
  const s = spec({ id: 'x', label: 'unit tests', paths: ['src/**'] })
  const pass = { evidenceId: 'p', checkId: 'x', status: 'pass' as const, outputHead: '' }
  const fail = { evidenceId: 'f', checkId: 'x', status: 'fail' as const, outputHead: 'boom' }
  const checks = attributeChecks({
    checks: [s],
    baselineById: new Map([['x', pass as never]]),
    currentById: new Map([['x', fail as never]]),
    changed: ['src/a.ts'],
  })
  assert.equal(checks[0]?.verdict, 'regression')
  assert.match(checks[0]?.rationale ?? '', /charged to this session/)
  assert.ok(checks[0]?.attributedTo.includes('src/a.ts'))
})
