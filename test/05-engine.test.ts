import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ProofEngine } from '../src/engine.ts'
import { assembleProof } from '../src/core/report.ts'
import { attributeChecks, proofNarrative } from '../src/core/regression.ts'
import { makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { VerificationRunner } from '../src/core/runner.ts'
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
  const engine = makeEngine(MemoryFs.of(project()), commands)
  // A green baseline first — an abort observed *during* the baseline batch is
  // the E1 case and must anchor nothing. This case is the other half: the
  // verification run itself gets killed mid-flight.
  await engine.establishBaseline()
  commands.on(argv => argv.includes('build'), { exitCode: null, aborted: true })
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

test('concurrent completion order never leaks into the baseline (determinism)', async () => {
  // The slow `test` command is submitted first but settles last; without the
  // reorder the records — and therefore the baselineId, which hashes the
  // checkId sequence — would flip with every race.
  const commands = new FakeCommands()
    .on(argv => argv.includes('test'), { output: 'tests ok' }, { delayMs: 60 })
    .on(argv => argv.includes('build'), { output: 'build ok' }, { delayMs: 1 })
  const engine = makeEngine(MemoryFs.of(project()), commands)
  const { baseline } = await engine.establishBaseline()
  assert.deepEqual(
    baseline.checks.map(c => c.kind),
    ['test', 'build'],
    'records follow discovery order, not wall-clock completion order',
  )

  const reordered = new FakeCommands()
    .on(argv => argv.includes('test'), { output: 'tests ok' }, { delayMs: 1 })
    .on(argv => argv.includes('build'), { output: 'build ok' }, { delayMs: 60 })
  const engine2 = makeEngine(MemoryFs.of(project()), reordered)
  const second = await engine2.establishBaseline()
  assert.deepEqual(
    second.baseline.checks.map(c => c.kind),
    ['test', 'build'],
    'flipping which command is slow must not move records around',
  )
  assert.deepEqual(baseline.checks.map(c => c.checkId), second.baseline.checks.map(c => c.checkId))
})

test('the runner executes subpackage checks inside their own directory', async () => {
  const commands = new FakeCommands()
  const runner = new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
  await runner.run([
    spec({ id: 'root-check', command: ['npm', 'run', '--silent', 'test'] }),
    spec({ id: 'sub-check', command: ['npm', 'run', '--silent', 'test'], cwd: 'packages/a' }),
  ], { concurrency: 2 })
  const cwds = commands.calls.map(c => c.cwd).sort()
  assert.deepEqual(cwds, [ROOT, `${ROOT}/packages/a`], `got ${cwds.join(', ')}`)
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

// -- E1: aborted baselines must not land on disk --------------------------------

test('E1: an aborted baseline run keeps its evidence but never becomes the anchor', async () => {
  const commands = new FakeCommands()
    .on(argv => argv.includes('build'), { exitCode: null, aborted: true })
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, commands)

  const { baseline, records } = await engine.establishBaseline()
  // The half-run comes back — flagged as aborted on the returned object...
  assert.equal(baseline.aborted, true)
  assert.equal(records.length, 2, 'observed facts are still returned')
  // ...but nothing anchor-shaped exists on disk.
  assert.equal(await fs.readFile(`${ROOT}/.proof/baseline.json`), undefined, 'an aborted run must not write baseline.json')
  assert.equal(await engine.baseline(), undefined)
  // The chain keeps the facts and names the abort.
  assert.ok(fs.log.some(l => l.includes('"status":"aborted"')), 'aborted evidence record present')
  assert.ok(fs.log.some(l => l.includes('baseline/aborted')), 'abort marker present')
  assert.ok(!fs.log.some(l => l.includes('baseline/saved')), 'no baseline/saved marker may exist')
  // The next verify anchors on nothing and says so, instead of silently
  // diffing against a half-built truth.
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'no-baseline')
})

// -- E2: signer degradation must be visible -------------------------------------

test('E2: a signer that cannot load degrades loudly — marker in the chain, chain still intact', async () => {
  const fs = MemoryFs.of(project())
  const warnings: string[] = []
  const engine = new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    // Minimal injection: a host signer provider whose key material is gone.
    signer: () => Promise.reject(new Error('trust keys dir is not writable')),
    verbose: true,
    logger: message => warnings.push(message),
  })
  const { baseline } = await engine.establishBaseline()
  // The marker is fired, not awaited (see watchSigner: awaiting it inside the
  // signer resolution would self-deadlock the store's single-flight queue), so
  // it lands one queue-slot behind the in-flight checkpoint — drain
  // deterministically instead of racing the log read.
  for (let i = 0; i < 200 && !fs.log.some(l => l.includes('trust/signer-unavailable')); i++) {
    await new Promise(resolve => setTimeout(resolve, 5))
  }
  // The degradation itself is a chain fact, with the reason attached.
  assert.ok(fs.log.some(l => l.includes('trust/signer-unavailable')), 'degradation marker in the evidence log')
  assert.ok(fs.log.some(l => l.includes('trust keys dir is not writable')), 'marker carries the failure reason')
  assert.ok(warnings.some(l => l.includes('signer unavailable')), 'verbose channel warned')
  // Unsigned — but honestly so, and the chain still audits clean.
  const audit = await engine.audit()
  assert.equal(audit.chain.mode, 'unsigned')
  assert.equal(audit.ok, true, `chain broke: ${JSON.stringify(audit.chain)}`)
  assert.equal((await engine.baseline())?.baselineId, baseline.baselineId)
})

// -- E3: git invisibility forces the full check set ------------------------------

test('E3 (port contract): FakeWorkspace.gitAvailableValue models absent, true and false', async () => {
  const ws = new FakeWorkspace(ROOT)
  assert.equal(typeof ws.gitAvailable, 'function', 'default: capability present, git available')
  assert.equal(await ws.gitAvailable?.(), true)
  ws.gitAvailableValue = false
  assert.equal(await ws.gitAvailable?.(), false)
  ws.gitAvailableValue = null
  assert.equal(ws.gitAvailable, undefined, 'null removes the method entirely, like a port that never had it')
})

test('E3: git unavailable forces the full check set even for a narrow change', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace(ROOT)
  ws.gitAvailableValue = false
  const engine = new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: ws,
    clock: new FakeClock(),
    impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()
  // src/a.ts was clean at baseline; now it moves.
  fs.mutate(`${ROOT}/src/a.ts`, 'export const a = 2\n')
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.selection.forcedAll, true, 'a git-less change set must not narrow the run')
  assert.equal(outcome.selection.precision, 'forced')
  assert.equal(outcome.selection.affected.length, 2, 'every discovered check is selected')
  assert.equal(outcome.selection.untouched.length, 0)
  assert.equal(outcome.degraded, true, 'degradation is surfaced on the outcome')
  assert.equal(outcome.report.grade, 'proven', 'the forced run itself still grades normally')
})

// -- β: bayesian wave scheduling + graded trust ----------------------------------

function waveProject() {
  return {
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/src/b.ts`]: 'export const b = 1\n',
    [`${ROOT}/src/c.ts`]: 'export const c = 1\n',
    [`${ROOT}/src/d.ts`]: 'export const d = 1\n',
  }
}

const WAVE_CHECKS = [
  { label: 'a tests', command: ['npm', 'run', '--silent', 'a'], kind: 'test' as const, paths: ['src/a.ts'] },
  { label: 'b tests', command: ['npm', 'run', '--silent', 'b'], kind: 'test' as const, paths: ['src/b.ts'] },
  { label: 'c tests', command: ['npm', 'run', '--silent', 'c'], kind: 'test' as const, paths: ['src/c.ts'] },
  { label: 'd tests', command: ['npm', 'run', '--silent', 'd'], kind: 'test' as const, paths: ['src/d.ts'] },
]

const WAVE_CHANGED = ['src/a.ts', 'src/b.ts', 'src/c.ts', 'src/d.ts']

function waveEngine(
  fs: MemoryFs,
  commands: FakeCommands,
  overrides: Partial<ConstructorParameters<typeof ProofEngine>[0]> = {},
) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    autoDiscover: false,
    checks: WAVE_CHECKS,
    concurrency: 2,
    impactGraphLimit: 1_000,
    checkTimeoutMs: 5_000,
    verifyBudgetMs: 20_000,
    ...overrides,
  })
}

/** Seed straight green history straight into the evidence log, behind the engine's back. */
async function seedGreenHistory(engine: ProofEngine, passes: number): Promise<void> {
  const specs = await engine.loadChecks()
  const clock = new FakeClock()
  const ws = snapshotWorkspace('abc123', [])
  for (let i = 0; i < passes; i++) {
    for (const s of specs) {
      await engine.storeView.append(makeEvidence(s, { status: 'pass', exitCode: 0, durationMs: 5, output: 'ok' }, ws, clock))
    }
  }
}

test('β: bayesian scheduling certifies early — planned skips carry their priors', async () => {
  const fs = MemoryFs.of(waveProject())
  const commands = new FakeCommands()
  const engine = waveEngine(fs, commands, { certifyTarget: 0.5 })
  await engine.establishBaseline()
  await seedGreenHistory(engine, 6)

  const callsBefore = commands.calls.length
  const outcome = await engine.verify({ changed: WAVE_CHANGED })

  const schedule = outcome.schedule
  assert.ok(schedule, 'bayesian mode carries schedule metadata')
  assert.equal(schedule.mode, 'bayesian')
  assert.equal(schedule.waves, 1, 'one wave dispatched')
  assert.equal(schedule.stoppedEarly, 'certified')
  assert.equal(commands.calls.length - callsBefore, 2, 'only the first wave actually executed')
  assert.equal(schedule.skippedByPlan.length, 2, 'the rest of the plan is a planned skip')
  for (const skip of schedule.skippedByPlan) {
    assert.ok(skip.priorHealthy > 0.5 && skip.priorHealthy < 1, `prior for ${skip.checkId} is a healthy probability`)
  }
  assert.deepEqual(schedule.skippedByPlan.map(s => s.checkId), outcome.report.unverified, 'unverified is exactly the planned skips')
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence >= 0.5, 'claim posterior crosses the target')
  assert.equal(outcome.report.grade, 'proven')
  assert.equal(outcome.report.confidenceBasis, 'certified-subset')
  assert.match(proofNarrative(outcome.report), /PROVEN \(p≈0\.\d+\)/)
})

test('β: a decisive failure in the first wave stops the plan — attribution over coverage', async () => {
  const fs = MemoryFs.of(waveProject())
  const commands = new FakeCommands()
  const engine = waveEngine(fs, commands)
  await engine.establishBaseline()
  commands.on(() => true, { exitCode: 1, output: 'boom' })

  const callsBefore = commands.calls.length
  const outcome = await engine.verify({ changed: WAVE_CHANGED })

  const schedule = outcome.schedule
  assert.ok(schedule)
  assert.equal(schedule.stoppedEarly, 'failed')
  assert.equal(schedule.waves, 1)
  assert.equal(commands.calls.length - callsBefore, 2, 'no second wave is dispatched after a decisive failure')
  assert.equal(schedule.skippedByPlan.length, 2)
  assert.equal(outcome.report.grade, 'regressed')
  assert.equal(outcome.report.summary.regressions, 2)
  assert.equal(outcome.report.confidenceBasis, 'degraded')
  assert.ok((outcome.report.confidence ?? 1) < 0.97, 'a dead assertion drags the claim posterior down')
})

test('β: scheduler set keeps the legacy whole-batch behaviour', async () => {
  const fs = MemoryFs.of(waveProject())
  const commands = new FakeCommands()
  const engine = waveEngine(fs, commands, { scheduler: 'set' })
  await engine.establishBaseline()

  const callsBefore = commands.calls.length
  const outcome = await engine.verify({ changed: WAVE_CHANGED })

  assert.equal(outcome.schedule, undefined, 'no wave metadata on the legacy path')
  assert.equal(commands.calls.length - callsBefore, 4, 'every affected check ran')
  assert.equal(outcome.report.grade, 'proven')
  assert.equal(outcome.report.unverified.length, 0)
  assert.ok(outcome.report.confidence !== undefined, 'the whole-batch path still displays a confidence number')
  assert.equal(outcome.report.confidenceBasis, 'full-coverage')
})

test('β: identical inputs produce byte-identical confidence (determinism)', async () => {
  const runOnce = async () => {
    const fs = MemoryFs.of(waveProject())
    const commands = new FakeCommands()
    const engine = waveEngine(fs, commands, { certifyTarget: 0.9 })
    await engine.establishBaseline()
    await seedGreenHistory(engine, 6)
    return engine.verify({ changed: WAVE_CHANGED })
  }
  const first = await runOnce()
  const second = await runOnce()
  assert.strictEqual(first.report.confidence, second.report.confidence, 'confidence is bit-for-bit stable')
  assert.equal(JSON.stringify(first.schedule), JSON.stringify(second.schedule))
  assert.equal(first.report.root, second.report.root)
})

test('β: budget exhaustion degrades below target and grades stale', async () => {
  const fs = MemoryFs.of(waveProject())
  const commands = new FakeCommands()
  const warm = waveEngine(fs, commands)
  await warm.establishBaseline()

  // A second engine over the same evidence log, holding a budget the
  // FakeClock (1ms per read) exhausts before the first wave can be afforded.
  const starved = waveEngine(fs, commands, { verifyBudgetMs: 1 })
  const outcome = await starved.verify({ changed: WAVE_CHANGED })

  const schedule = outcome.schedule
  assert.ok(schedule)
  assert.equal(schedule.stoppedEarly, 'budget')
  assert.equal(schedule.waves, 0, 'no wave was ever dispatched')
  assert.equal(schedule.skippedByPlan.length, 4, 'the whole plan is skipped')
  assert.equal(outcome.report.grade, 'stale')
  assert.equal(outcome.report.confidenceBasis, 'degraded')
  assert.ok((outcome.report.confidence ?? 1) < 0.97, 'the claim never reached the target')
})

// -- ζ: typed claim contracts wired into the engine -------------------------------

/**
 * A workspace whose package.json declares a source entry point, so the engine
 * derives an API surface: index re-exports a and b, b imports a internally.
 */
function surfaceProject() {
  return {
    [`${ROOT}/package.json`]: JSON.stringify({
      name: 'demo',
      main: './src/index.ts',
      scripts: { test: 'vitest run', build: 'tsc -b' },
    }),
    [`${ROOT}/src/index.ts`]: "export { a } from './a'\nexport { b } from './b'\n",
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/src/b.ts`]: "import { a } from './a'\nexport const b = a + 1\n",
    [`${ROOT}/test/a.test.ts`]: "import { a } from '../src/a'\nvoid a\n",
  }
}

function contractEngine(
  fs: MemoryFs,
  commands: FakeCommands,
  checks?: ConstructorParameters<typeof ProofEngine>[0]['checks'],
) {
  const base: ConstructorParameters<typeof ProofEngine>[0] = {
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    impactGraphLimit: 1_000,
    checkTimeoutMs: 5_000,
    verifyBudgetMs: 20_000,
    concurrency: 2,
  }
  return new ProofEngine(checks === undefined ? base : { ...base, autoDiscover: false, checks })
}

test('ζ: behavior-preserving end to end — surface snapshot, then the downgrade', async () => {
  const fs = MemoryFs.of(surfaceProject())
  const engine = contractEngine(fs, new FakeCommands())

  const { baseline } = await engine.establishBaseline()
  assert.ok(Array.isArray(baseline.apiSurface) && baseline.apiSurface.length >= 3,
    `baseline carries the apiSurface snapshot: ${JSON.stringify(baseline.apiSurface)}`)

  // Internal-only edit: same exports, different body. The claim holds.
  fs.mutate(`${ROOT}/src/b.ts`, "import { a } from './a'\nexport const b = a + 2\n")
  const kept = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'behavior-preserving', claim: 'refactored b internals, no API change' },
  })
  assert.equal(kept.report.grade, 'proven')
  const keptSurface = kept.contract.obligations.find(o => o.id === 'api-surface-unchanged')
  assert.ok(keptSurface, 'api-surface-unchanged obligation present')
  assert.equal(keptSurface.met, true)
  assert.equal(kept.contract.kind, 'behavior-preserving')

  // Public face moves: a new export appears. The run is still green, but the
  // obligation fails and drags the grade down — the engine never co-signs
  // more than the contract allows.
  fs.mutate(`${ROOT}/src/a.ts`, 'export const a = 1\nexport const a2 = 2\n')
  const broken = await engine.verifyContract({
    changed: ['src/a.ts'],
    contract: { kind: 'behavior-preserving', claim: 'still preserving, honest' },
  })
  assert.equal(broken.report.grade, 'stale', 'a proven run with unmet obligations is capped at stale')
  assert.ok(broken.report.confidence !== undefined, 'the confidence number survives the downgrade')
  assert.equal(broken.report.confidenceBasis, 'full-coverage')
  const brokenSurface = broken.contract.obligations.find(o => o.id === 'api-surface-unchanged')
  assert.ok(brokenSurface)
  assert.equal(brokenSurface.met, false)
  assert.match(brokenSurface.detail, /a2/, 'the detail names the new symbol')
  // The contract summary rides the proof/verified boundary marker.
  assert.ok(fs.log.some(l => l.includes('proof/verified') && l.includes('"kind":"behavior-preserving"')),
    'chain marker carries the contract summary')
})

test('ζ: behavior-adding — new paths must be covered by a passing check', async () => {
  const make = () => MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo', main: './src/index.ts' }),
    [`${ROOT}/src/index.ts`]: "export { a } from './a'\n",
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
  })

  // Covered: a check whose paths match the new file exists and passes.
  const coveredFs = make()
  const covered = contractEngine(coveredFs, new FakeCommands(), [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
  ])
  await covered.establishBaseline()
  coveredFs.mutate(`${ROOT}/src/new.ts`, 'export const n = 1\n')
  const good = await covered.verifyContract({
    changed: ['src/new.ts'],
    contract: { kind: 'behavior-adding', claim: 'added a new module' },
  })
  assert.equal(good.report.grade, 'proven')
  const goodPaths = good.contract.obligations.find(o => o.id === 'new-paths-covered')
  assert.ok(goodPaths)
  assert.equal(goodPaths.met, true)

  // Uncovered: the new file matches no check's paths — the obligation names it.
  const bareFs = make()
  const bare = contractEngine(bareFs, new FakeCommands(), [
    { label: 'a tests', command: ['npm', 'test'], kind: 'test', paths: ['src/a.ts'] },
  ])
  await bare.establishBaseline()
  bareFs.mutate(`${ROOT}/src/new.ts`, 'export const n = 1\n')
  const bad = await bare.verifyContract({
    changed: ['src/a.ts', 'src/new.ts'],
    contract: { kind: 'behavior-adding', claim: 'added a new module' },
  })
  assert.equal(bad.report.grade, 'stale')
  const badPaths = bad.contract.obligations.find(o => o.id === 'new-paths-covered')
  assert.ok(badPaths)
  assert.equal(badPaths.met, false)
  assert.match(badPaths.detail, /src\/new\.ts/, 'the detail names the uncovered file')
})

test('ζ: perf-budget — benchmark evidence is force-run and judged against budgetMs', async () => {
  const make = () => MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/bench/run.ts`]: 'export const run = (): number => 1\n',
  })
  const checks: ConstructorParameters<typeof ProofEngine>[0]['checks'] = [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
    { label: 'bench', command: ['node', 'bench/run.ts'], kind: 'benchmark', paths: ['bench/**'] },
  ]

  // Over budget: the benchmark must run anyway (its paths never matched the
  // change set) and its duration fails the stated budget.
  const slowFs = make()
  const slowCommands = new FakeCommands()
    .on(argv => argv.includes('bench/run.ts'), { exitCode: 0, output: 'bench: 500ms', durationMs: 500 })
  const slow = contractEngine(slowFs, slowCommands, checks)
  await slow.establishBaseline()
  const callsAfterBaseline = slowCommands.calls.length
  const over = await slow.verifyContract({
    changed: ['src/a.ts'],
    contract: { kind: 'perf-budget', claim: 'no path got slower', budgetMs: 100 },
  })
  assert.equal(slowCommands.calls.length - callsAfterBaseline, 2,
    'the benchmark ran despite impact analysis not selecting it')
  assert.equal(over.report.grade, 'stale', 'green checks cannot carry an over-budget claim')
  const within = over.contract.obligations.find(o => o.id === 'within-budget')
  assert.ok(within)
  assert.equal(within.met, false)
  assert.match(within.detail, /500ms/)
  const evidence = over.contract.obligations.find(o => o.id === 'benchmark-evidence')
  assert.ok(evidence?.met, 'the forced benchmark run produced decisive evidence')

  // Within budget: fresh workspace, fresh engine, fast benchmark.
  const fastFs = make()
  const fastCommands = new FakeCommands()
    .on(argv => argv.includes('bench/run.ts'), { exitCode: 0, output: 'bench: 50ms', durationMs: 50 })
  const fast = contractEngine(fastFs, fastCommands, checks)
  await fast.establishBaseline()
  const okRun = await fast.verifyContract({
    changed: ['src/a.ts'],
    contract: { kind: 'perf-budget', claim: 'no path got slower', budgetMs: 100 },
  })
  assert.equal(okRun.report.grade, 'proven')
  assert.ok(okRun.contract.obligations.every(o => o.met), 'every perf-budget obligation met')
})

test('ζ: docs-only — the jury path runs no checks and caps its own confidence', async () => {
  const fs = MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/docs/guide.md`]: '# guide\n',
  })
  const commands = new FakeCommands()
  const engine = contractEngine(fs, commands, [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
  ])
  await engine.establishBaseline()

  const callsBefore = commands.calls.length
  const outcome = await engine.verifyContract({
    changed: ['docs/guide.md'],
    contract: {
      kind: 'docs-only',
      claim: 'rewrote the guide',
      review: 'Replaced the outdated CLI flags section with the current ones; no code was touched.',
    },
  })
  assert.equal(commands.calls.length, callsBefore, 'a docs-only claim executes zero commands')
  assert.equal(outcome.report.grade, 'proven')
  assert.equal(outcome.report.confidence, 0.8, 'jury confidence sits exactly at the cap')
  assert.equal(outcome.report.confidenceBasis, 'jury-only')
  assert.equal(outcome.checks.length, 0)
  assert.equal(outcome.selection.affected.length, 0)
  assert.equal(outcome.contract.juryConfidenceCap, 0.8)
  assert.ok(fs.log.some(l => l.includes('claim/jury')), 'the jury verdict is a chain marker')
  assert.match(proofNarrative(outcome.report), /PROVEN \(p≈0\.80, jury evidence — self-attestation is capped\)/)

  // A code file sneaking into a docs-only claim is caught — still without
  // running anything: the obligation, not a check, does the catching.
  const mixed = await engine.verifyContract({
    changed: ['docs/guide.md', 'src/a.ts'],
    contract: { kind: 'docs-only', claim: 'just docs', review: 'honest review text' },
  })
  assert.equal(commands.calls.length, callsBefore, 'even a failing docs-only claim runs no commands')
  assert.equal(mixed.report.grade, 'stale')
  assert.equal(mixed.report.confidenceBasis, 'jury-only')
  const docs = mixed.contract.obligations.find(o => o.id === 'docs-only-changes')
  assert.ok(docs)
  assert.equal(docs.met, false)
  assert.match(docs.detail, /src\/a\.ts/)
})

test('ζ: a pre-ζ baseline without apiSurface fails behavior-preserving honestly', async () => {
  const fs = MemoryFs.of(surfaceProject())
  const engine = contractEngine(fs, new FakeCommands())
  await engine.establishBaseline()

  // Hand-strip the surface attachment, exactly like a baseline written before
  // the field existed: the rest of the file stays intact.
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { apiSurface?: unknown }
  assert.ok(Array.isArray(parsed.apiSurface), 'sanity: the fresh baseline does carry a surface')
  delete parsed.apiSurface
  fs.mutate(`${ROOT}/.proof/baseline.json`, JSON.stringify(parsed, null, 2))

  fs.mutate(`${ROOT}/src/b.ts`, "import { a } from './a'\nexport const b = a + 2\n")
  const outcome = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'behavior-preserving', claim: 'internal refactor only' },
  })
  const surface = outcome.contract.obligations.find(o => o.id === 'api-surface-unchanged')
  assert.ok(surface)
  assert.equal(surface.met, false, 'an un-comparable surface is never a pass')
  assert.match(surface.detail, /baseline/, 'the detail tells the user to rebuild the baseline')
  assert.equal(outcome.report.grade, 'stale')
})
