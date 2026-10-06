import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { ProofEngine } from '../src/engine.ts'
import { assembleProof } from '../src/core/report.ts'
import { attributeChecks, proofNarrative } from '../src/core/regression.ts'
import { makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { VerificationRunner } from '../src/core/runner.ts'
import { claimIdOf } from '../src/core/attest.ts'
import { SYNTHETIC_TEMPLATE } from '../src/core/synthetic.ts'
import { createProofTools, toVerifyValue } from '../src/dsh/tools.ts'
import { deriveProofPaths, touchesEvidencePath } from '../src/adapters/shared/paths.ts'
import { NodeCommandPort, NodeFsPort, SystemClock } from '../src/node-ports.ts'
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
  // H12 tightened the baseline half of this scenario: a budget-starved
  // baseline is an incomplete observation and no longer anchors (see the
  // E1-style case in the H12 block below). The baseline here is therefore
  // established with a healthy budget, and only the VERIFICATION is starved —
  // which is what this case was always about: skipped checks leave the claim
  // stale, never proven.
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const anchoring = makeEngine(fs, commands)
  await anchoring.establishBaseline()
  const starved = new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    verifyBudgetMs: 1,
  })
  const outcome = await starved.verify({ changed: ['src/a.ts'], all: true })
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

test('M7: a script added mid-session joins the next verify — the spec pool cannot silently expire', async () => {
  // The discovery cache used to live for the whole engine instance: a script
  // added after the baseline was invisible to every later verify — never run,
  // never unverified, never blocking a grade. Discovery reads a few manifest
  // files, so the engine's verbs now force re-discovery.
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  assert.equal((await engine.baseline())?.checks.length, 2, 'two checks at baseline time')

  fs.mutate(`${ROOT}/package.json`, JSON.stringify({
    name: 'demo',
    scripts: { test: 'vitest run', build: 'tsc -b', lint: 'eslint .' },
  }))
  const outcome = await engine.verify({ changed: ['package.json'] })
  assert.equal(outcome.report.discovered, 3, 'the lint script joined the discovered pool')
  assert.ok(outcome.checks.some(c => c.label === 'npm script "lint"'),
    'the new check was selected, run and attributed')
  assert.equal(outcome.report.grade, 'proven', 'the widened pool runs green')
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

test('H12: a budget-starved baseline is an incomplete observation — it anchors nothing', async () => {
  // E1's own rule, extended to the SILENT truncation shapes: a baseline whose
  // tail was `skipped` (budget drained) or `timeout` observed fewer checks
  // than the workspace declares, and a half-observed truth must not become
  // THE anchor. The FakeClock advances 1ms per read, so verifyBudgetMs:1 is
  // exhausted before the first spec is ever dispatched — every record lands
  // `skipped`, the batch flag stays down, and only the record-level guard
  // catches it.
  const fs = MemoryFs.of(project())
  const engine = new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    verifyBudgetMs: 1,
  })

  const { baseline, records } = await engine.establishBaseline()
  assert.equal(baseline.aborted, true, 'a starved batch is an abort, not an anchor')
  assert.ok(records.length === 2 && records.every(r => r.status === 'skipped'),
    'the budget died before any spec ran')
  assert.equal(await fs.readFile(`${ROOT}/.proof/baseline.json`), undefined,
    'an incomplete observation must not write baseline.json')
  assert.ok(fs.log.some(l => l.includes('baseline/aborted') && l.includes('incomplete-observation')),
    'the abort marker names the reason')
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'no-baseline', 'the next verify honestly reports there is no anchor')
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

/**
 * H2: the prior-only certification fixture — ONE check carrying a deep green
 * history (baseline + 30 seeded passes → 31 observed runs, all pass), so its
 * prior (≈0.972) clears the default 0.97 certify target on its own. That
 * number is history's, not this run's; the two cases below pin that it can
 * never stand in for an observation this run did not make.
 */
function priorOnlyEngine(fs: MemoryFs, commands: FakeCommands) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    autoDiscover: false,
    checks: [{ label: 'a tests', command: ['npm', 'run', '--silent', 'a'], kind: 'test', paths: ['src/a.ts'] }],
    concurrency: 2,
    impactGraphLimit: 1_000,
    checkTimeoutMs: 5_000,
    verifyBudgetMs: 20_000,
  })
}

test('β (H2): a pre-aborted signal observes nothing — a prior product above the target still grades stale', async () => {
  const fs = MemoryFs.of(waveProject())
  const engine = priorOnlyEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await seedGreenHistory(engine, 30)

  const controller = new AbortController()
  controller.abort()
  const outcome = await engine.verify({ changed: ['src/a.ts'], signal: controller.signal })

  const schedule = outcome.schedule
  assert.ok(schedule, 'the bayesian path ran and planned')
  assert.equal(schedule.waves, 0, 'zero waves dispatched')
  assert.equal(schedule.stoppedEarly, 'budget')
  // The trap this case pins: zero records, zero observations, every factor a
  // prior — and the prior product sits ABOVE the certify target. The old
  // grade rule certified on that number alone; a prior is what the check
  // brought to the table, not what this run measured.
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence >= 0.97,
    `prior product ${outcome.report.confidence} crosses the target — and still proves nothing`)
  assert.equal(outcome.report.grade, 'stale', 'a run that observed nothing is unfinished, never proven')
  assert.notEqual(outcome.report.confidenceBasis, 'certified-subset')
  assert.equal(outcome.report.confidenceBasis, 'degraded')
  assert.deepEqual(outcome.report.unverified, schedule.skippedByPlan.map(s => s.checkId))
})

test('β (H2): a high-prior check that cannot answer certifies nothing — the plan ends starved, not certified', async () => {
  const fs = MemoryFs.of(waveProject())
  const commands = new FakeCommands()
  const engine = priorOnlyEngine(fs, commands)
  await engine.establishBaseline()
  await seedGreenHistory(engine, 30)
  // The one check now dies at spawn: a non-decisive `error` record — the same
  // knowledge-lattice bucket as timeout/skipped (no verdict). Its prior would
  // clear the target on its own; the wave that heard nothing cannot certify.
  commands.on(() => true, { exitCode: null, spawnError: 'spawn failed: ENOENT' })

  const outcome = await engine.verify({ changed: ['src/a.ts'] })

  const schedule = outcome.schedule
  assert.ok(schedule)
  assert.equal(schedule.waves, 1, 'the plan dispatched the check')
  assert.notEqual(schedule.stoppedEarly, 'certified', 'a wave with zero decisive records cannot certify')
  assert.equal(schedule.stoppedEarly, 'budget', 'the unanswered check ends the plan as starved')
  assert.equal(outcome.report.grade, 'stale')
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence >= 0.97,
    `prior product ${outcome.report.confidence} crosses the target — and still proves nothing`)
  assert.equal(outcome.report.confidenceBasis, 'degraded')
  assert.equal(outcome.report.unverified.length, 1, 'the unanswered check is named as unverified')
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

// -- κ: graded evidence fused into confidence and contracts --------------------

/** A B-class jury verdict seeded straight onto the chain, as the attest marker writes it. */
async function seedJuryAttestation(
  engine: ProofEngine,
  claim: string,
  over: { gen: number; verdict: 'uphold' | 'reject' | 'abstain'; probability: number },
): Promise<void> {
  // The marker payload is {label, ...data}; ι's parser keys on `kind`, so the
  // data carries it too. `at` is epoch millis supplied by the caller.
  await engine.storeView.mark('attest/jury', {
    kind: 'attest/jury',
    claimId: claimIdOf(claim),
    gen: over.gen,
    prompt: `Judge the claim: "${claim}"`,
    rubricVersion: 'jury-rubric/v1',
    model: 'jury-test-model',
    independence: 'fresh-context',
    verdict: over.verdict,
    probability: over.probability,
    output: 'verdict rendered by the seeded jury',
    at: 1_767_225_600_000,
  })
}

/** A C-class human decision seeded straight onto the chain. */
async function seedHumanAttestation(
  engine: ProofEngine,
  claim: string,
  over: { gen: number; decision: 'endorse' | 'reject' },
): Promise<void> {
  await engine.storeView.mark('attest/human', {
    kind: 'attest/human',
    claimId: claimIdOf(claim),
    gen: over.gen,
    approver: 'reviewer-1',
    approvedAt: 1_767_225_600_000,
    scope: { claim, evidenceRoot: null },
    decision: over.decision,
  })
}

test('κ: llm-jury — a chain-seeded B-class uphold certifies with zero commands', async () => {
  const fs = MemoryFs.of(surfaceProject())
  const commands = new FakeCommands()
  const engine = contractEngine(fs, commands)
  await engine.establishBaseline()

  const claim = 'refactored b internals; an independent jury reviewed the diff'
  await seedJuryAttestation(engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })

  const callsBefore = commands.calls.length
  const outcome = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'llm-jury', claim },
  })
  assert.equal(commands.calls.length, callsBefore, 'an llm-jury claim executes zero commands')
  assert.equal(outcome.checks.length, 0)
  assert.equal(outcome.selection.affected.length, 0, 'llm-jury never goes through check selection')

  // Confidence is exactly the class-weighted factor: 0.99^0.7 ≈ 0.993.
  assert.ok(outcome.report.confidence !== undefined)
  assert.ok(Math.abs(outcome.report.confidence - 0.99 ** 0.7) < 1e-12,
    `confidence ${outcome.report.confidence} vs 0.99^0.7`)
  assert.equal(outcome.report.grade, 'proven', '0.993 clears the 0.97 certify target')
  assert.equal(outcome.report.confidenceBasis, 'jury-only', 'no machine record, a B witness: jury-only')
  assert.ok(outcome.contract.obligations.every(o => o.met), 'every llm-jury obligation met')

  // The contract summary carries the fused witness.
  assert.ok(outcome.contract.attestations !== undefined && outcome.contract.attestations.length === 1)
  const summary = outcome.contract.attestations?.[0]
  assert.equal(summary?.class, 'B')
  assert.equal(summary?.gen, 0)
  assert.equal(summary?.verdict, 'uphold')
  assert.ok(summary !== undefined && Math.abs(summary.factor - 0.99 ** 0.7) < 1e-12)

  // The boundary marker summarises what the grade rode on (no prompt/output dump).
  assert.ok(fs.log.some(l => l.includes('claim/jury') && l.includes('"verdict":"uphold"') && l.includes('jury-test-model')),
    'claim/jury marker carries the attestation summary')
})

test('κ: appeal override — the highest-gen attestation decides, in both directions', async () => {
  const fs = MemoryFs.of(surfaceProject())
  const commands = new FakeCommands()
  const engine = contractEngine(fs, commands)
  await engine.establishBaseline()
  const claim = 'appealable claim'

  // Rejected first (gen 0): a reject at p=0.2 collapses the fused confidence.
  await seedJuryAttestation(engine, claim, { gen: 0, verdict: 'reject', probability: 0.2 })
  const rejected = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'llm-jury', claim },
  })
  assert.equal(rejected.report.grade, 'stale')
  assert.ok(rejected.report.confidence !== undefined)
  assert.ok(Math.abs(rejected.report.confidence - 0.2 ** 0.7) < 1e-12, 'reject factor is 0.2^0.7')

  // Appealed and upheld (gen 1): the appeal overrides, confidence follows the NEW verdict.
  await seedJuryAttestation(engine, claim, { gen: 1, verdict: 'uphold', probability: 0.99 })
  const upheld = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'llm-jury', claim },
  })
  assert.equal(upheld.report.grade, 'proven')
  assert.ok(Math.abs((upheld.report.confidence ?? 0) - 0.99 ** 0.7) < 1e-12,
    'the active attestation is the gen-1 uphold, not the gen-0 reject')
  assert.equal(upheld.contract.attestations?.[0]?.gen, 1)
  assert.equal(upheld.contract.attestations?.[0]?.verdict, 'uphold')

  // Appealed back to reject (gen 2): the newest verdict wins again.
  await seedJuryAttestation(engine, claim, { gen: 2, verdict: 'reject', probability: 0.2 })
  const overturned = await engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'llm-jury', claim },
  })
  assert.equal(overturned.report.grade, 'stale')
  assert.equal(overturned.contract.attestations?.[0]?.verdict, 'reject')
  const upholds = overturned.contract.obligations.find(o => o.id === 'jury-upholds')
  assert.ok(upholds)
  assert.equal(upholds.met, false, 'a reject cannot satisfy jury-upholds')
})

/**
 * Six checks, each failing at baseline and passing at verify: every posterior
 * lands at 0.99, so the machine confidence is 0.99^6 ≈ 0.9415 — a certification
 * sitting ~0.03 under the 0.97 target. The Class C endorse then fuses in.
 */
function endorsementProject(): Record<string, string> {
  const files: Record<string, string> = {
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo', main: './src/index.ts' }),
    [`${ROOT}/src/index.ts`]: '',
  }
  for (const name of ['a', 'b', 'c', 'd', 'e', 'f']) {
    files[`${ROOT}/src/${name}.ts`] = `export const ${name} = 1\n`
    files[`${ROOT}/src/index.ts`] += `export { ${name} } from './${name}'\n`
  }
  return files
}

const ENDORSEMENT_CHECKS = ['a', 'b', 'c', 'd', 'e', 'f'].map(name => ({
  label: `${name} tests`, command: ['npm', 'run', '--silent', name], kind: 'test' as const, paths: [`src/${name}.ts`],
}))

const ENDORSEMENT_CHANGED = ['a', 'b', 'c', 'd', 'e', 'f'].map(name => `src/${name}.ts`)

test('κ: a Class C endorsement fuses into a machine certification — and a rejection drags it down', async () => {
  const claim = 'refactored six modules, behaviour preserved'

  const setup = async (fs: MemoryFs, commands: FakeCommands): Promise<ProofEngine> => {
    const engine = contractEngine(fs, commands, ENDORSEMENT_CHECKS)
    // Baseline: every check fails (decisively — the baseline still anchors).
    commands.on(() => true, { exitCode: 1, output: 'red' })
    await engine.establishBaseline()
    // Verify: everything heals — six `fixed` verdicts, full coverage.
    commands.on(() => true, { exitCode: 0, output: 'green' })
    return engine
  }

  const verify = async (engine: ProofEngine): Promise<Awaited<ReturnType<ProofEngine['verifyContract']>>> =>
    engine.verifyContract({ changed: ENDORSEMENT_CHANGED, contract: { kind: 'behavior-preserving', claim } })

  // Control: no attestation — pure machine number.
  const control = await setup(MemoryFs.of(endorsementProject()), new FakeCommands())
  const machineRun = await verify(control)
  const machine = machineRun.report.confidence
  assert.ok(machine !== undefined && machine > 0.9 && machine < 0.97,
    `machine confidence sits ~0.03 under the target (got ${machine})`)
  assert.equal(machineRun.report.grade, 'proven', 'full green coverage: the machine run itself proves')
  assert.equal(machineRun.report.confidenceBasis, 'full-coverage')
  assert.equal(machineRun.contract.attestations, undefined, 'no witness on chain: no summary')

  // Endorsement: risk acceptance, not certainty transfer. The number the
  // machines measured is what stands; the basis records who took the residual.
  const endorseFs = MemoryFs.of(endorsementProject())
  const endorse = await setup(endorseFs, new FakeCommands())
  await seedHumanAttestation(endorse, claim, { gen: 0, decision: 'endorse' })
  const endorsed = await verify(endorse)
  assert.equal(endorsed.report.grade, 'proven', 'the machine grade survives; endorsement never demotes')
  assert.equal(endorsed.report.confidenceBasis, 'attested', 'machine + witness: attested')
  assert.ok(endorsed.report.confidence !== undefined && machine !== undefined)
  assert.ok(Math.abs(endorsed.report.confidence - machine) < 1e-12,
    `endorse leaves the machine number untouched (got ${endorsed.report.confidence}, machine ${machine})`)
  assert.deepEqual(endorsed.contract.attestations, [
    { class: 'C', gen: 0, verdict: 'endorse', factor: Math.pow(0.95, 0.9) },
  ])
  assert.ok(endorseFs.log.some(l => l.includes('proof/verified') && l.includes('"verdict":"endorse"')),
    'the boundary marker carries the fused witness')
  assert.match(proofNarrative(endorsed.report), /PROVEN \(p≈0\.\d+, machine \+ B\/C attested\)/)

  // Rejection: the number collapses under the human's error probability, and
  // the symmetric lock demotes the grade — a claim a sworn witness denies
  // cannot keep a grade the number no longer supports.
  const reject = await setup(MemoryFs.of(endorsementProject()), new FakeCommands())
  await seedHumanAttestation(reject, claim, { gen: 0, decision: 'reject' })
  const rejected = await verify(reject)
  assert.equal(rejected.report.confidenceBasis, 'attested')
  assert.ok(rejected.report.confidence !== undefined && machine !== undefined)
  assert.ok(Math.abs(rejected.report.confidence - machine * 0.05 ** 0.9) < 1e-12,
    `reject factor is (1-0.95)^0.9 (got ${rejected.report.confidence})`)
  assert.ok((rejected.report.confidence ?? 1) < 0.1, 'a human rejection collapses the certified number')
  assert.equal(rejected.report.grade, 'stale', 'an explicit rejection locks the grade down')
})

test('κ (H3): endorsement cannot pay for unrun checks — the unlock requires completed work', async () => {
  const claim = 'docs and internals tidied, no behaviour change'
  // The semantics this case pins were REVERSED by the 2026-10-06 deep read:
  // a budget-starved run skips every check, the machine grade is honestly
  // stale — and the old unlock lifted that stale to `proven` on one human
  // endorsement, i.e. the endorsement paid for work that never happened. The
  // honest rule: an endorsement accepts the residual risk of work that DID
  // happen (a completed run sitting just under the certify target); six
  // skipped checks are not residual risk, they are missing work. (H12
  // additionally keeps a starved baseline from anchoring, so the baseline is
  // established with a healthy budget first and only the verification is
  // starved.)
  const fs = MemoryFs.of(endorsementProject())
  const anchoring = contractEngine(fs, new FakeCommands(), ENDORSEMENT_CHECKS)
  await anchoring.establishBaseline()
  const starved = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), autoDiscover: false, checks: ENDORSEMENT_CHECKS,
    verifyBudgetMs: 1,
  })
  const starvedRun = await starved.verifyContract({ changed: ENDORSEMENT_CHANGED, contract: { kind: 'behavior-preserving', claim } })
  assert.equal(starvedRun.report.grade, 'stale', 'budget starvation is stale before any witness speaks')
  assert.equal(starvedRun.report.summary.regressions, 0)
  assert.equal(starvedRun.report.unverified.length, 6, 'every check is unverified — nothing ran')

  // Seed the SAME claim's endorsement on the same chain and re-verify: the
  // witness is recorded and fused into the number, but the grade does not
  // move — no unlock without completed work.
  await seedHumanAttestation(starved, claim, { gen: 0, decision: 'endorse' })
  const endorsed = await starved.verifyContract({ changed: ENDORSEMENT_CHANGED, contract: { kind: 'behavior-preserving', claim } })
  assert.equal(endorsed.report.grade, 'stale', 'an endorsement buys zero unrun checks')
  assert.equal(endorsed.report.confidenceBasis, 'attested', 'the witness is still honestly fused into the number')
  assert.equal(endorsed.report.summary.regressions, 0)

  // But an unmet obligation is missing work, not residual risk: endorsement
  // must not pay for it (grow the API surface, keep the endorsement seeded).
  const tamperedFs = MemoryFs.of(endorsementProject())
  const tampered = contractEngine(tamperedFs, new FakeCommands(), ENDORSEMENT_CHECKS)
  await tampered.establishBaseline()
  tamperedFs.mutate('/ws/src/a.ts', 'export const a = 1\nexport const a2 = 2\n')
  await seedHumanAttestation(tampered, claim, { gen: 0, decision: 'endorse' })
  const paid = await tampered.verifyContract({ changed: ENDORSEMENT_CHANGED, contract: { kind: 'behavior-preserving', claim } })
  assert.notEqual(paid.report.grade, 'proven', 'endorsement cannot buy off an unmet obligation')
})

test('κ: plain verify stays pure machine — chain attestations never touch it', async () => {
  const runOnce = async (withAttestation: boolean) => {
    const fs = MemoryFs.of(waveProject())
    const commands = new FakeCommands()
    const engine = waveEngine(fs, commands)
    await engine.establishBaseline()
    if (withAttestation) {
      // A hostile on-chain witness: a B-class rejection at p=0.2. verify()
      // must not even read it.
      await seedJuryAttestation(engine, 'the wave workspace is healthy', { gen: 0, verdict: 'reject', probability: 0.2 })
    }
    return engine.verify({ changed: WAVE_CHANGED })
  }
  const plain = await runOnce(false)
  const attested = await runOnce(true)
  assert.strictEqual(attested.report.confidence, plain.report.confidence,
    'confidence is byte-identical with a rejection on chain')
  assert.strictEqual(attested.report.confidenceBasis, plain.report.confidenceBasis,
    'the basis never becomes attested on the plain verify path')
  assert.equal(attested.report.grade, plain.report.grade)
  assert.equal(JSON.stringify(attested.schedule), JSON.stringify(plain.schedule))
})

// -- π: PTC synthesis — the conjure request/execution protocol ------------------
//
// Real-process tests mirror 07/14: a scratch workspace under
// <workspace>/.openclaw/tmp, production Node ports, and `node` actually
// executing the conjured scripts — because the whole point of conjureRun is
// that execution happens through the verifier's port, not the agent's word.

const WORKSPACE_DIR = fileURLToPath(new URL('../../', import.meta.url))
const CONJURE_ROOT = join(WORKSPACE_DIR, '.openclaw', 'tmp', `proof-conjure-${process.pid}`)

before(async () => {
  await fsp.rm(CONJURE_ROOT, { recursive: true, force: true })
  await fsp.mkdir(CONJURE_ROOT, { recursive: true })
})

after(async () => {
  await fsp.rm(CONJURE_ROOT, { recursive: true, force: true })
})

/** A real engine over a real scratch directory: conjured scripts really run. */
function conjureEngine(dir: string, overrides: Partial<ConstructorParameters<typeof ProofEngine>[0]> = {}) {
  return new ProofEngine({
    root: dir,
    fs: new NodeFsPort(),
    commands: new NodeCommandPort(),
    workspace: new FakeWorkspace(dir),
    clock: new SystemClock(),
    autoDiscover: false,
    checkTimeoutMs: 10_000,
    verifyBudgetMs: 30_000,
    ...overrides,
  })
}

/** A minimal real workspace: package.json + one source file. */
async function makeConjureWorkspace(dir: string): Promise<void> {
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(join(dir, 'src'), { recursive: true })
  await fsp.writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'conjure-fixture', private: true }))
  await fsp.writeFile(join(dir, 'src', 'feature.ts'), 'export const feature = 2\n')
}

test('π: conjure closed loop — request scaffolds, the agent writes, the run executes and records', async () => {
  const root = join(CONJURE_ROOT, 'closed-loop')
  await makeConjureWorkspace(root)
  const engine = conjureEngine(root)
  const claim = 'feature doubles its input'
  try {
    const { request, template, instruction } = await engine.conjureRequest({ claim, paths: ['src/feature.ts'] })
    assert.equal(template, SYNTHETIC_TEMPLATE, 'the template is the module scaffold itself')
    assert.ok(request.entry.length > 0)
    assert.equal(request.claimId, claimIdOf(claim))
    assert.deepEqual(request.paths, ['src/feature.ts'])
    assert.ok(instruction.includes(request.entry), 'the instruction names the entry to write')
    // The scaffold is on disk for the model to copy — under the
    // .template.mjs suffix, so the scaffold itself can never be executed.
    const scaffold = await engine.fsView.readFile(join(root, '.proof-synthetic', `${request.entry}.template.mjs`))
    assert.equal(scaffold, SYNTHETIC_TEMPLATE)

    // The "agent": write the test (a real assertion, SYNTHETIC: PASS on success).
    const script = [
      '// conjured test — authored by the agent, executed by the verifier',
      "const check = (ok, msg) => { if (!ok) { console.error('SYNTHETIC: FAIL ' + msg); process.exit(1) } }",
      'check(1 + 1 === 2, "1+1===2")',
      "console.log('SYNTHETIC: PASS')",
      '',
    ].join('\n')
    await fsp.writeFile(join(root, '.proof-synthetic', request.entry), script)

    const run = await engine.conjureRun({ claim, entry: request.entry })
    assert.equal(run.status, 'pass')
    assert.equal(run.sandbox, 'screened-subprocess')
    assert.deepEqual(run.screened, [], 'a clean script screens with no findings')
    assert.match(run.outputHead, /SYNTHETIC: PASS/)

    // Chain facts: the request (digest null — the script did not exist yet)
    // and the run (digest of what actually executed).
    const log = await engine.fsView.readLines(join(root, '.proof', 'evidence.jsonl'))
    assert.ok(log.some(l => l.includes('"synthetic/requested"') && l.includes('"scriptDigest":null')),
      'the requested marker carries the full request with a null digest')
    assert.ok(log.some(l => l.includes('"synthetic/run"') && l.includes(run.checkId) && l.includes(run.scriptDigest)),
      'the run marker carries checkId and the executed digest')

    // The evidence record carries its synthetic metadata — and is the latest
    // record under its own checkId.
    const latest = await engine.latestEvidence()
    const evidence = latest.get(run.checkId)
    assert.ok(evidence, 'the synthetic run recorded evidence under its checkId')
    assert.equal(evidence?.synthetic?.scriptDigest, run.scriptDigest)
    assert.equal(evidence?.synthetic?.author, 'agent')
    assert.equal(evidence?.synthetic?.sandbox, 'screened-subprocess')
    assert.deepEqual(evidence?.synthetic?.screened, [])

    // The enriched record still addresses itself.
    const audit = await engine.audit()
    assert.equal(audit.ok, true, `corrupt: ${audit.corrupt.join(', ')}`)

    // Phase B (deterministic ports, same file): one changed character in the
    // script is a different digest, and the digest is addressing material —
    // same fake outcome, different evidence identity.
    const fs = MemoryFs.of(project())
    const engineB = makeEngine(fs, new FakeCommands())
    const claimB = 'the digest participates in addressing'
    const { request: requestB } = await engineB.conjureRequest({ claim: claimB, paths: ['src/a.ts'] })
    fs.mutate(`${ROOT}/.proof-synthetic/${requestB.entry}`, 'const one = 1\n')
    const first = await engineB.conjureRun({ claim: claimB, entry: requestB.entry })
    const firstEvidence = (await engineB.latestEvidence()).get(first.checkId)
    assert.ok(firstEvidence)
    fs.mutate(`${ROOT}/.proof-synthetic/${requestB.entry}`, 'const one = 2\n')
    const second = await engineB.conjureRun({ claim: claimB, entry: requestB.entry })
    const secondEvidence = (await engineB.latestEvidence()).get(second.checkId)
    assert.ok(secondEvidence)
    assert.notEqual(second.scriptDigest, first.scriptDigest, 'one character moves the digest')
    assert.notEqual(secondEvidence.evidenceId, firstEvidence.evidenceId,
      'a different script is different evidence, even with an identical outcome')
    assert.equal(secondEvidence.synthetic?.scriptDigest, second.scriptDigest)
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

test('π: screening refusal — forbidden import rejected before execution, nothing lands on chain', async () => {
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  const claim = 'lists the files'
  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  fs.mutate(`${ROOT}/.proof-synthetic/${request.entry}`, [
    "import { exec } from 'node:child_process'",
    "exec('ls -la')",
    '',
  ].join('\n'))

  const run = await engine.conjureRun({ claim, entry: request.entry })
  assert.equal(run.status, 'skipped', 'a refused script never ran')
  assert.ok(run.screened.length > 0, 'the findings travel back to the model')
  assert.match(run.screened.join('; '), /child/i, 'the finding names the forbidden capability')
  assert.match(run.outputHead, /refus/i)
  // No execution, no chain writes: the refusal is the tool result, not a fact
  // about the workspace.
  assert.equal(commands.calls.length, 0, 'no command port call may happen for a refused script')
  assert.ok(!fs.log.some(l => l.includes('"synthetic/run"')), 'a refusal writes no run marker')
  assert.equal((await engine.latestEvidence()).get(run.checkId), undefined,
    'a refusal writes no evidence')
})

test('π: synthetic β pricing — a conjured pass certifies less than an organic pass', async () => {
  // Organic: one configured check covers the file.
  const organicRoot = join(CONJURE_ROOT, 'beta-organic')
  await makeConjureWorkspace(organicRoot)
  const synthRoot = join(CONJURE_ROOT, 'beta-synthetic')
  await makeConjureWorkspace(synthRoot)
  try {
    const organic = conjureEngine(organicRoot, {
      checks: [{ label: 'feature tests', command: ['node', '-e', 'process.exit(0)'], kind: 'test', paths: ['src/feature.ts'] }],
    })
    await organic.establishBaseline()
    const organicRun = await organic.verify({ changed: ['src/feature.ts'] })
    assert.ok(organicRun.report.confidence !== undefined)
    assert.equal(organicRun.report.confidenceBasis, 'full-coverage', 'organic stays an ordinary machine number')

    // Synthetic: same assertion, different authorship — the only covering
    // check is one the claimant conjured itself.
    const synth = conjureEngine(synthRoot)
    const claim = 'feature is sound'
    const { request } = await synth.conjureRequest({ claim, paths: ['src/feature.ts'] })
    await fsp.writeFile(join(synthRoot, '.proof-synthetic', request.entry),
      'if (1 + 1 !== 2) process.exit(1)\nconsole.log("SYNTHETIC: PASS")\n')
    const conjured = await synth.conjureRun({ claim, entry: request.entry })
    assert.equal(conjured.status, 'pass')
    // The organic anchor: an empty baseline, so verify has something to
    // diff against (the conjured check joins as a new-check, honestly).
    await synth.establishBaseline()
    const synthRun = await synth.verify({ changed: ['src/feature.ts'] })

    assert.ok(synthRun.report.confidence !== undefined)
    assert.ok(synthRun.checks.some(c => c.checkId === conjured.checkId),
      'the conjured check was part of the verification pool')
    assert.ok((synthRun.report.confidence ?? 1) < (organicRun.report.confidence ?? 1),
      `synthetic ${synthRun.report.confidence} must price below organic ${organicRun.report.confidence}`)
    assert.equal(synthRun.report.confidenceBasis, 'synthetic',
      'only synthetic checks spoke: the basis names the regime')
    assert.match(proofNarrative(synthRun.report), /synthetic evidence — conjured tests, discounted/)
  } finally {
    await fsp.rm(organicRoot, { recursive: true, force: true })
    await fsp.rm(synthRoot, { recursive: true, force: true })
  }
})

test('π: behavior-adding falls back to conjured coverage — obligation met, basis names the discount', async () => {
  const root = join(CONJURE_ROOT, 'behavior-adding')
  await makeConjureWorkspace(root)
  try {
    // An organic check covers the OLD path only; src/new.ts has none.
    const engine = conjureEngine(root, {
      checks: [{ label: 'feature tests', command: ['node', '-e', 'process.exit(0)'], kind: 'test', paths: ['src/feature.ts'] }],
    })
    await engine.establishBaseline()
    await fsp.writeFile(join(root, 'src', 'new.ts'), 'export const added = 1\n')

    const claim = 'added a new module, covered by a conjured test'
    const { request } = await engine.conjureRequest({ claim, paths: ['src/new.ts'] })
    // υ: the conjured test EXECUTES the module it claims to cover. Before the
    // coverage dimension this was a green assertion that never touched the
    // change; now such a test is worth nothing to the grade (the blind-spot
    // case at the bottom of this file), so the fixture exercises the honest
    // version: import it, assert on it, then the arithmetic.
    await fsp.writeFile(join(root, '.proof-synthetic', request.entry), [
      'const mod = await import("../src/new.ts")',
      'if (mod.added !== 1) process.exit(1)',
      'if (2 + 2 !== 4) process.exit(1)',
      'console.log("SYNTHETIC: PASS")',
      '',
    ].join('\n'))
    const conjured = await engine.conjureRun({ claim, entry: request.entry })
    assert.equal(conjured.status, 'pass')

    const outcome = await engine.verifyContract({
      changed: ['src/new.ts'],
      contract: { kind: 'behavior-adding', claim },
    })
    const covered = outcome.contract.obligations.find(o => o.id === 'new-paths-covered')
    assert.ok(covered)
    assert.equal(covered.met, true, `detail: ${covered.detail}`)
    // The conjured check joined the pool as an ordinary spec, so verifyContract
    // re-ran it; this run's pass is a *synthetic* pass, and the obligation's
    // tier ladder (run-organic > run-synthetic > latest-organic >
    // latest-synthetic) names the discount in the detail.
    assert.match(covered.detail, /covered by synthetic evidence \(discounted\)/)
    assert.equal(outcome.report.grade, 'proven', `grade: ${outcome.report.grade}`)
    assert.ok(outcome.report.confidence !== undefined)
    assert.equal(outcome.report.confidenceBasis, 'synthetic',
      'every decisive record this run was a conjured test')
    assert.match(proofNarrative(outcome.report), /synthetic evidence — conjured tests, discounted/)
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

// -- υ: coverage-aware proof — injection, collection, gating, cleanup ----------
//
// Real-process tests mirror the π block above: scratch workspaces under
// <workspace>/.openclaw/tmp, production Node ports, and real `node` children
// writing real V8 profiles — because NODE_V8_COVERAGE injection is only ever
// exercised honestly by an actual V8 instance on the other side.

const COVER_ROOT = join(WORKSPACE_DIR, '.openclaw', 'tmp', `proof-coverage-${process.pid}`)

before(async () => {
  await fsp.rm(COVER_ROOT, { recursive: true, force: true })
  await fsp.mkdir(COVER_ROOT, { recursive: true })
})

after(async () => {
  await fsp.rm(COVER_ROOT, { recursive: true, force: true })
})

/** A real engine over a real scratch directory: checks are real node processes. */
function coverageEngine(dir: string, checks: ConstructorParameters<typeof ProofEngine>[0]['checks'], overrides: Partial<ConstructorParameters<typeof ProofEngine>[0]> = {}) {
  return new ProofEngine({
    root: dir,
    fs: new NodeFsPort(),
    commands: new NodeCommandPort(),
    workspace: new FakeWorkspace(dir),
    clock: new SystemClock(),
    autoDiscover: false,
    checkTimeoutMs: 20_000,
    verifyBudgetMs: 60_000,
    checks,
    ...overrides,
  })
}

/** package.json + one source module + a check script that imports it. */
async function makeCoverageWorkspace(dir: string, files: Record<string, string>): Promise<void> {
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(join(dir, 'src'), { recursive: true })
  await fsp.writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'coverage-fixture', private: true }))
  for (const [rel, content] of Object.entries(files)) {
    await fsp.mkdir(join(dir, rel, '..'), { recursive: true })
    await fsp.writeFile(join(dir, rel), content)
  }
}

test('υ: end to end — a green check that executes the change proves with basis v8 and leaves no coverage residue', async () => {
  const root = join(COVER_ROOT, 'covered')
  await makeCoverageWorkspace(root, {
    'src/feature.mjs': 'export const feature = (n) => n * 2\n',
    'check.mjs': [
      "import { feature } from './src/feature.mjs'",
      'if (feature(2) !== 4) process.exit(1)',
      "console.log('executed feature')",
      '',
    ].join('\n'),
  })
  try {
    const engine = coverageEngine(root, [
      { label: 'feature tests', command: ['node', 'check.mjs'], kind: 'test', paths: ['src/**'] },
    ])
    await engine.establishBaseline()
    const outcome = await engine.verify({ changed: ['src/feature.mjs'] })

    assert.equal(outcome.report.grade, 'proven', `grade: ${outcome.report.grade}`)
    assert.equal(outcome.report.coverage?.basis, 'v8', 'the report mounts a v8-basis summary')
    assert.deepEqual(outcome.report.coverage?.uncovered, [])
    assert.ok(outcome.coverage !== undefined)
    assert.equal(outcome.coverage.basis, 'v8')
    assert.deepEqual(outcome.coverage.uncovered, [])
    assert.equal(outcome.coverage.executedCount, 1, 'the one changed file was observed executing')
    assert.match(proofNarrative(outcome.report), /PROVEN \(p≈[01]\.\d+, change-executed\)/)

    // The evidence record itself carries its execution footprint — content
    // addressed, so the chain can audit it.
    const current = outcome.checks.find(c => c.label === 'feature tests')?.current
    assert.ok(current, 'the check produced current evidence')
    assert.deepEqual(current?.coverage?.changedExecuted, ['src/feature.mjs'])
    assert.deepEqual(current?.coverage?.changedUncovered, [])
    const latest = (await engine.latestEvidence()).get(current?.checkId ?? '')
    assert.ok(latest, 'the enriched record is on the chain')
    assert.deepEqual(latest?.coverage?.changedExecuted, ['src/feature.mjs'])
    // Re-addressed records must still address themselves.
    const audit = await engine.audit()
    assert.equal(audit.ok, true, `corrupt: ${audit.corrupt.join(', ')}`)

    // The scratch tree is gone: collected, then removed, nothing left behind.
    const leftovers = await fsp.readdir(join(root, '.proof', 'coverage'), { recursive: true }).catch(() => [])
    assert.ok(!leftovers.some(f => String(f).includes('coverage-')),
      `V8 profiles must not survive the run (found: ${leftovers.join(', ')})`)
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

test('υ: THE BLIND SPOT — a green check whose paths cover the change but never execute it leaves the claim UNPROVEN', async () => {
  // The headline case for the whole dimension: paths coverage says the check
  // owns src/feature.mjs, the check is green — and it never loads the changed
  // file. Selection coverage ≠ execution coverage, and only the latter earns
  // `proven`.
  const root = join(COVER_ROOT, 'blind-spot')
  await makeCoverageWorkspace(root, {
    'src/feature.mjs': 'export const feature = (n) => n * 2\n',
    'src/other.mjs': 'export const other = 7\n',
    'check.mjs': [
      "import { other } from './src/other.mjs'",
      'if (other !== 7) process.exit(1)',
      "console.log('green, without ever touching the change')",
      '',
    ].join('\n'),
  })
  try {
    const engine = coverageEngine(root, [
      // paths: ['src/**'] MATCHES src/feature.mjs — the check is selected,
      // re-run, and green. That is exactly the old, unobservable gap.
      { label: 'feature tests', command: ['node', 'check.mjs'], kind: 'test', paths: ['src/**'] },
    ])
    await engine.establishBaseline()
    const outcome = await engine.verify({ changed: ['src/feature.mjs'] })

    // The check really was green — still-passing, zero failures. The grade
    // died on the coverage dimension, not on a regression.
    assert.equal(outcome.checks[0]?.verdict, 'still-passing')
    assert.equal(outcome.report.summary.failing, 0)
    assert.equal(outcome.report.grade, 'unproven',
      'observe mode + real data + an unexecuted change = unproven, however green')
    assert.equal(outcome.report.coverage?.basis, 'v8')
    assert.ok(outcome.report.coverage?.uncovered.includes('src/feature.mjs'),
      `uncovered names the file (got: ${outcome.report.coverage?.uncovered.join(', ')})`)
    assert.ok(outcome.coverage !== undefined)
    assert.deepEqual(outcome.coverage.uncovered, ['src/feature.mjs'])
    assert.equal(outcome.coverage.executedCount, 0)
    // The narrative names the blind spot and points at the remedy.
    const narrative = proofNarrative(outcome.report)
    assert.match(narrative, /unexecuted change \(src\/feature\.mjs\)/)
    assert.match(narrative, /proof_conjure can synthesize a test that executes them/)
    // The evidence honestly records that this check executed nothing of the change.
    const current = outcome.checks[0]?.current
    assert.deepEqual(current?.coverage?.changedExecuted, [])
    assert.deepEqual(current?.coverage?.changedUncovered, ['src/feature.mjs'])
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

test('υ: require mode blocks on missing data, off mode never gates — the same fake fixture, opposite grades', async () => {
  const make = () => MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
  })
  const checks: ConstructorParameters<typeof ProofEngine>[0]['checks'] = [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
  ]
  const verifyWith = async (coverage?: 'observe' | 'require' | 'off') => {
    const engine = new ProofEngine({
      root: ROOT,
      fs: make(),
      commands: new FakeCommands(),
      workspace: new FakeWorkspace(ROOT),
      clock: new FakeClock(),
      autoDiscover: false,
      checks,
      impactGraphLimit: 1_000,
      ...(coverage !== undefined ? { coverage } : {}),
    })
    await engine.establishBaseline()
    return engine.verify({ changed: ['src/a.ts'] })
  }

  // FakeCommands never reads the injected env, so no coverage exists at all.
  // `require` treats the absence itself as disqualifying: proven → unproven,
  // reason `no-coverage-data` — the gate looked at the basis, not at the
  // (vacuous) uncovered list the summary still slices honestly.
  const required = await verifyWith('require')
  assert.equal(required.report.grade, 'unproven', 'require: no data is not a pass')
  assert.equal(required.report.coverage?.basis, 'none', 'the missing measurement is visible, not silent')
  assert.deepEqual(required.report.coverage?.uncovered, ['src/a.ts'],
    'the summary still names what the (empty) evidence never executed')
  assert.equal(required.coverage?.basis, 'none')

  // `off` injects nothing, gates nothing: the pre-υ grade, byte for byte.
  const off = await verifyWith('off')
  assert.equal(off.report.grade, 'proven', 'off: the gate is not in the room')
  assert.equal(off.report.coverage, undefined, 'off: no summary is mounted at all')
  assert.equal(off.coverage, undefined)
})

test('υ: backward compatibility — default observe over fake ports keeps the pre-gate grade and confidence bit for bit', async () => {
  const runOnce = async (coverage?: 'observe' | 'off') => {
    const engine = new ProofEngine({
      root: ROOT,
      fs: MemoryFs.of(waveProject()),
      commands: new FakeCommands(),
      workspace: new FakeWorkspace(ROOT),
      clock: new FakeClock(),
      autoDiscover: false,
      checks: WAVE_CHECKS,
      scheduler: 'set',
      concurrency: 2,
      impactGraphLimit: 1_000,
      checkTimeoutMs: 5_000,
      verifyBudgetMs: 20_000,
      ...(coverage !== undefined ? { coverage } : {}),
    })
    await engine.establishBaseline()
    return engine.verify({ changed: WAVE_CHANGED })
  }

  const off = await runOnce('off')
  const observe = await runOnce() // default
  // The gate's no-data branch must not move a single bit of the machine
  // verdict: grade, confidence (strict ===, byte equality on the float) and
  // basis are exactly what the pre-υ engine produced. (The report root is
  // deliberately not compared: the observe run consumes one extra clock read
  // for its staging nonce, which legitimately shifts recordedAt — staging
  // noise, not verdict noise. Off-vs-off keeps root stability instead.)
  assert.strictEqual(observe.report.grade, off.report.grade)
  assert.strictEqual(observe.report.confidence, off.report.confidence)
  assert.strictEqual(observe.report.confidenceBasis, off.report.confidenceBasis)
  assert.deepEqual(observe.report.unverified, off.report.unverified)
  // And observe does mount its honest 'nothing was measured' summary.
  assert.equal(observe.report.coverage?.basis, 'none')
  assert.equal(off.report.coverage, undefined)

  const offAgain = await runOnce('off')
  assert.equal(offAgain.report.root, off.report.root, 'determinism itself is untouched')
})

// -- H5: check-definition drift — the script BODY, not the id, must hold ------
//
// The id says `npm run test`; the digest says what `test` said. Discovery
// fills CheckSpec.scriptDigest from the package.json script body; these cases
// pin the engine half: the baseline locks the bodies that answered, and a
// later verify compares, force-re-runs and re-prices whatever drifted —
// regardless of what the change set (or the agent's report of it) says.

/**
 * Monorepo fixture: member scripts carry member-scoped paths
 * (`packages/<m>/**`), so a change in one member's source does NOT select the
 * other member's checks — the shape in which a drifted definition can hide
 * from impact analysis entirely.
 */
function driftProject() {
  return {
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'mono', workspaces: ['packages/*'] }),
    [`${ROOT}/packages/a/package.json`]: JSON.stringify({ name: 'a', scripts: { test: 'vitest run' } }),
    [`${ROOT}/packages/a/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/packages/b/package.json`]: JSON.stringify({ name: 'b', scripts: { test: 'vitest run' } }),
    [`${ROOT}/packages/b/src/b.ts`]: 'export const b = 1\n',
  }
}

function driftEngine(
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
    concurrency: 2,
    impactGraphLimit: 1_000,
    checkTimeoutMs: 5_000,
    verifyBudgetMs: 20_000,
    // 0.99 (not the 0.97 default) so the fixture's arithmetic is unambiguous:
    // an organic pass prices at ≈0.996 and certifies; the drifted check's
    // discounted pass prices at ≈0.986 and — multiplied with the organic
    // factor ≈0.982 — cannot clear the target. The discount prices the risk,
    // it does not veto the pass; at the default 0.97 a single drifted pass
    // would still certify, visibly cheaper but certifying.
    certifyTarget: 0.99,
    ...overrides,
  })
}

test('H5: a tampered script body drifts — detected, force-re-run past selection, synthetic-tier pricing', async () => {
  // Control: the same verify against an untampered workspace certifies.
  const controlFs = MemoryFs.of(driftProject())
  const control = driftEngine(controlFs, new FakeCommands())
  await control.establishBaseline()
  const cleanRun = await control.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(cleanRun.report.grade, 'proven', 'control: a b-only change certifies at the 0.99 target')
  assert.equal(cleanRun.scriptDrift, undefined, 'no drift on an honest workspace')

  // The adversarial half: package a's test script becomes a no-op, and the
  // session's change report names only b's source — impact analysis would
  // leave a's check resting on evidence a DIFFERENT script body earned.
  const fs = MemoryFs.of(driftProject())
  const commands = new FakeCommands()
  const engine = driftEngine(fs, commands)
  const { baseline } = await engine.establishBaseline()
  const locked = (baseline as { scriptDigests?: Record<string, string> }).scriptDigests
  assert.ok(locked !== undefined && Object.keys(locked).length === 2,
    'the baseline locks the script body digest under every discovered id')

  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
  const specs = await engine.loadChecks(true)
  const aCheck = specs.find(c => c.cwd === 'packages/a')
  assert.ok(aCheck !== undefined && aCheck.scriptDigest !== undefined && aCheck.scriptDigest !== locked?.[aCheck.id],
    'sanity: same id, different body')

  const runsInA = (): number => commands.calls.filter(c => c.cwd === `${ROOT}/packages/a`).length
  const callsBeforeVerify = runsInA()
  const outcome = await engine.verify({ changed: ['packages/b/src/b.ts'] })

  // Detected — by digest, not by id.
  assert.ok(outcome.scriptDrift !== undefined && outcome.scriptDrift.length === 1)
  assert.equal(outcome.scriptDrift?.[0], aCheck?.id)
  assert.equal(outcome.scriptDrift?.[0] === specs.find(c => c.cwd === 'packages/b')?.id, false,
    'the untampered sibling did not drift')
  // Force-re-run PAST impact analysis: selection left a untouched, yet it ran.
  assert.ok(outcome.selection.untouched.some(c => c.id === aCheck?.id),
    'sanity: the change set alone does not select the drifted check')
  assert.equal(runsInA(), callsBeforeVerify + 1,
    'the drifted check was re-run regardless of the selection')
  // Priced at the synthetic tier: the vacuous pass ≈0.9864 (β=0.15) times the
  // organic sibling ≈0.9960 lands at ≈0.9825 — under the 0.99 target, above
  // outright failure. The grade follows the number: stale, never proven.
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence < 0.99,
    `discounted posterior ${outcome.report.confidence} must sit under the target`)
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence >= 0.97,
    'the number sank through pricing, not through a failure')
  assert.equal(outcome.report.grade, 'stale', 'a no-op "test" script cannot carry the claim across the target')
  // The chain and the model-facing narrative both carry the warning.
  assert.ok(fs.log.some(l => l.includes('proof/verified') && l.includes('"scriptDrift"')),
    'the boundary marker records which definitions drifted')
  const value = toVerifyValue(
    outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
    outcome.schedule, outcome.coverage, outcome.scriptDrift,
  )
  assert.match(value.summary, /1 check definition\(s\) changed since baseline \(script drift\) — re-run and discounted/)
})

test('H5: a pre-H5 baseline without scriptDigests degrades honestly — no comparison, no drift charge', async () => {
  const fs = MemoryFs.of(driftProject())
  const commands = new FakeCommands()
  const engine = driftEngine(fs, commands)
  await engine.establishBaseline()
  // Hand-strip the attachment, exactly like a baseline written before H5.
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { scriptDigests?: unknown }
  assert.ok(parsed.scriptDigests !== undefined, 'sanity: the fresh baseline does carry the digests')
  delete parsed.scriptDigests
  fs.mutate(`${ROOT}/.proof/baseline.json`, JSON.stringify(parsed, null, 2))

  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
  const runsInA = (): number => commands.calls.filter(c => c.cwd === `${ROOT}/packages/a`).length
  const before = runsInA()
  const outcome = await engine.verify({ changed: ['packages/b/src/b.ts'] })

  assert.equal(outcome.scriptDrift, undefined, 'nothing recorded to compare against — drift is honestly undetectable')
  assert.equal(runsInA(), before, 'the drifted check rests on its stale evidence, exactly as pre-H5')
  assert.ok(!fs.log.some(l => l.includes('"scriptDrift"')), 'no drift marker may exist')
  // The hole a new baseline closes: this grade is the documented reason to
  // re-anchor. (Asserted, not hidden — the upgrade path is a fresh baseline.)
  assert.equal(outcome.report.grade, 'proven', 'the honest statement of the downgrade: pre-H5 baselines cannot see this')
})

test('H5: verifyContract carries the drift verdict on its machine path — obligations eat the re-run evidence', async () => {
  const fs = MemoryFs.of(driftProject())
  const commands = new FakeCommands()
  const engine = driftEngine(fs, commands)
  await engine.establishBaseline()
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
  const aCheck = (await engine.loadChecks(true)).find(c => c.cwd === 'packages/a')

  const outcome = await engine.verifyContract({
    changed: ['packages/b/src/b.ts'],
    contract: { kind: 'behavior-adding', claim: 'extended package b' },
  })
  assert.ok(outcome.scriptDrift !== undefined && outcome.scriptDrift.length === 1)
  assert.equal(outcome.scriptDrift?.[0], aCheck?.id)
  // The drifted check re-ran under the contract too, and its fresh (vacuously
  // green) evidence is exactly what the obligations were judged against.
  assert.ok(outcome.checks.some(c => c.checkId === aCheck?.id && c.current !== undefined),
    'the drifted check produced current evidence for the contract')
  assert.ok(fs.log.some(l => l.includes('proof/verified') && l.includes('"scriptDrift"')),
    'the contract boundary marker records the drift')
})

// -- H6: git-blind snapshots — a failed query is not "clean" -------------------

/** A workspace whose dirty query fails while a flag is set (index.lock, …). */
class FlakyDirtyWorkspace extends FakeWorkspace {
  broken = true
  async gitDirty(): Promise<string[]> {
    if (this.broken) throw new Error('fatal: Unable to create .git/index.lock: File exists')
    return super.gitDirty()
  }
}

test('H6: a baseline built on a failed dirty query is degraded — visibly, and past recovery', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FlakyDirtyWorkspace(ROOT)
  const engine = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: ws, clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  const { baseline } = await engine.establishBaseline()
  assert.equal(baseline.checks.length, 2, 'the anchor itself is fine — the blindness rides beside it')
  assert.equal((baseline as { snapshotDegraded?: true }).snapshotDegraded, true,
    'the failed dirty query is recorded next to the baseline, not silently as "clean"')
  assert.equal(baseline.workspace.dirty.length, 0, 'the snapshot shape is untouched (nothing entered its hash material)')
  assert.ok(fs.log.some(l => l.includes('baseline/established') && l.includes('"snapshotDegraded":true')),
    'the chain marker carries the fact')

  // The query recovers; the blindness does not age out. Every verify against
  // this blind anchor is forced full until a fresh baseline re-anchors — even
  // with git perfectly healthy now (this is the leg B1's resolution-level
  // degradation cannot see: the failure happened at BASELINE time).
  ws.broken = false
  fs.mutate(`${ROOT}/src/a.ts`, 'export const a = 2\n')
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.degraded, true, 'a blind anchor degrades the run even with git healthy now')
  assert.equal(outcome.selection.forcedAll, true)
  assert.equal(outcome.selection.affected.length, 2, 'the full check set ran')
  assert.equal(outcome.report.grade, 'proven', 'the forced run itself still grades normally (E3 semantics)')
})

test('H6: git available but HEAD gone — changedSince is wholly blind, the run is forced', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace(ROOT)
  const engine = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: ws, clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()
  // Unborn/detached repo: no ref to diff against, so every committed change
  // since the baseline commit is invisible to changedSince.
  ws.head = null
  fs.mutate(`${ROOT}/src/a.ts`, 'export const a = 2\n')
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.degraded, true, 'a lost HEAD with git claimed available is blindness')
  assert.equal(outcome.selection.forcedAll, true)
  assert.equal(outcome.selection.precision, 'forced')
})

// -- H9b: shell-blind provenance — absence from touched is not proof of external --

test('H9b: a shell this session demotes untouched changes from external to unknown', async () => {
  const run = async (shellUsedSince: boolean | undefined) => {
    const fs = MemoryFs.of(project())
    const ws = new FakeWorkspace(ROOT)
    const engine = new ProofEngine({
      root: ROOT, fs, commands: new FakeCommands(), workspace: ws, clock: new FakeClock(), impactGraphLimit: 1_000,
    })
    await engine.establishBaseline()
    // A file moves outside the (declared) touched set — the shape a shell's
    // invisible edits produce: nothing in the tool stream names it.
    fs.mutate(`${ROOT}/src/ghost.ts`, 'export const ghost = 1\n')
    ws.dirty = ['src/ghost.ts']
    return engine.verify({ touched: ['src/a.ts'], ...(shellUsedSince !== undefined ? { shellUsedSince } : {}) })
  }

  const blind = await run(true)
  const record = blind.attribution.records.find(r => r.path === 'src/ghost.ts')
  assert.ok(record, 'the ghosted file moved')
  assert.equal(record?.provenance, 'unknown',
    'a shell ran — absence from the touched set is absence of evidence, not proof of external')
  assert.ok(blind.report.checks.every(c => !(c.externalSuspects ?? []).includes('src/ghost.ts')),
    'no check charges the file as an external suspect')

  // The control: the same shape without a shell stays honestly external.
  const control = await run(false)
  assert.equal(control.attribution.records.find(r => r.path === 'src/ghost.ts')?.provenance, 'external')
})

test('H9b: the model-facing tools carry the session shell fact into the engine', async () => {
  // The plugin entry wires `() => watch.sessionShellUsed()` the same route as
  // `touched`; this exercises the tools seam itself — the value the tool
  // reports must move with the session fact, not with the call site.
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace(ROOT)
  const engine = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: ws, clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()
  fs.mutate(`${ROOT}/src/ghost.ts`, 'export const ghost = 1\n')
  ws.dirty = ['src/ghost.ts']
  let shellUsed = true
  const verify = createProofTools(engine, () => ['src/a.ts'], undefined, () => shellUsed)
    .find(t => t.name === 'proof_verify')
  assert.ok(verify !== undefined)
  const execution = {
    callId: 'call-1', rootCallId: 'call-1', name: 'proof_verify', arguments: {},
    token: Symbol('token'), signal: new AbortController().signal,
    deferContext: () => undefined, concludeTurn: () => undefined,
  }
  const run = async (): Promise<string[]> => {
    const value = await verify!.execute({}, execution as Parameters<typeof verify.execute>[1]) as unknown as {
      externalChanged?: string[]
    }
    return value.externalChanged ?? []
  }
  assert.deepEqual(await run(), [], 'with a shell in the session, the ghosted file is not reported external')
  shellUsed = false
  assert.deepEqual(await run(), ['src/ghost.ts'], 'without one, the same file is honestly external')
})

// -- B2 follow-up: the adapter evidence-store guard is separator-blind ----------

test('adapters/shared/paths: the evidence-store guard folds a backslashed evidenceDir segment', () => {
  // deriveProofPaths POSIX-folds the configured segment on its own
  // (`'.\proof'` ≡ `./proof` ≡ the 'proof' directory, never '.proof'); this
  // pins the guard itself, so a hand-assembled ProofPaths still carrying a
  // backslashed segment cannot silently match nothing (an under-deny — the
  // `'.\proof'` shape index.ts closed in H10). test/24 owns the derive-side
  // matrix and is not this batch's to edit; the backslash case lives here.
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace', evidenceDir: '.\\proof' })
  assert.equal(paths.evidenceDir, 'proof', 'deriveProofPaths folds the configured segment')
  assert.equal(touchesEvidencePath('proof/evidence.jsonl', paths), true, 'the derived guard hits the store it derived')
  const handBuilt: typeof paths = { ...paths, evidenceDir: '.\\proof' }
  assert.equal(touchesEvidencePath('proof/evidence.jsonl', handBuilt), true,
    'the guard is separator-blind on the store segment even without deriveProofPaths')
})

test('H5②: a deleted check definition surfaces as vanished — the report cannot shrink back to green', async () => {
  // The other half of definition reconciliation: deleting a check's
  // definition used to make it vanish from specs entirely — never attributed,
  // never unverified, never blocking `proven`. The baseline's anchored ids
  // are now reconciled against discovery; a hole in the pool reads as a hole.
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  assert.equal((await engine.baseline())?.checks.length, 2, 'two checks at baseline time')

  fs.mutate(`${ROOT}/package.json`, JSON.stringify({
    name: 'demo',
    scripts: { build: 'tsc -b' }, // the test script's definition is gone
  }))
  const outcome = await engine.verify({ changed: ['package.json'] })
  assert.equal(outcome.vanished?.length, 1, 'the anchored test check vanished from discovery')
  assert.equal(outcome.report.vanished?.length, 1, 'the report carries the hole')
  assert.equal(outcome.report.grade, 'stale', 'a vanished definition blocks proven')
  assert.ok((outcome.report.vanished?.[0] ?? "").startsWith("package.json:"), "identified by source id")
})

// -- M10: llm-jury never punishes a human endorsement ---------------------------

test('M10: llm-jury — an endorsement leaves the fused product untouched; a rejection still collapses it', async () => {
  const claim = 'b internals refactored; the jury and a human both reviewed it'
  const setup = async (): Promise<{ fs: MemoryFs; engine: ProofEngine }> => {
    const fs = MemoryFs.of(surfaceProject())
    const engine = contractEngine(fs, new FakeCommands())
    await engine.establishBaseline()
    return { fs, engine }
  }
  const verify = (engine: ProofEngine) => engine.verifyContract({
    changed: ['src/b.ts'],
    contract: { kind: 'llm-jury', claim },
  })

  // Control: the B uphold alone — 0.99^0.7 ≈ 0.993 clears the 0.97 target.
  const control = await setup()
  await seedJuryAttestation(control.engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
  const alone = await verify(control.engine)
  assert.equal(alone.report.grade, 'proven')
  assert.ok(alone.report.confidence !== undefined)
  assert.ok(Math.abs(alone.report.confidence - 0.99 ** 0.7) < 1e-12)

  // B uphold + human endorse. The product used to multiply in the human's
  // 0.95^0.9 ≈ 0.955 factor and DEMOTE this exact claim to stale — backing
  // it made it worse, the inversion of what a Class C witness is for. The
  // endorsement is risk acceptance (the machine path's fuseConfidence keeps
  // the number untouched for the same reason), so the product must not move.
  const endorsed = await setup()
  await seedJuryAttestation(endorsed.engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
  await seedHumanAttestation(endorsed.engine, claim, { gen: 0, decision: 'endorse' })
  const withEndorse = await verify(endorsed.engine)
  assert.equal(withEndorse.report.grade, 'proven', 'an endorsement must never demote an llm-jury claim')
  assert.ok(withEndorse.report.confidence !== undefined)
  assert.ok(Math.abs(withEndorse.report.confidence - (alone.report.confidence ?? 0)) < 1e-12,
    `endorse leaves the product untouched (got ${withEndorse.report.confidence}, B alone ${alone.report.confidence})`)
  // Both witnesses stay visible in the summary — the grade rode on both.
  assert.deepEqual(withEndorse.contract.attestations?.map(a => a.class).sort(), ['B', 'C'])

  // B uphold + human reject: the veto keeps its full weight — the product
  // collapses to 0.99^0.7 · 0.05^0.9 and the claim is stale.
  const rejected = await setup()
  await seedJuryAttestation(rejected.engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
  await seedHumanAttestation(rejected.engine, claim, { gen: 0, decision: 'reject' })
  const withReject = await verify(rejected.engine)
  assert.equal(withReject.report.grade, 'stale', 'a human rejection still vetoes an llm-jury claim')
  assert.ok(Math.abs((withReject.report.confidence ?? 0) - (0.99 ** 0.7) * (0.05 ** 0.9)) < 1e-12,
    `reject keeps its product weight (got ${withReject.report.confidence})`)
})

// -- M12: the scaffold's protocol line is judged, not just the exit code --------

test('M12: conjureRun — exit 0 without a SYNTHETIC: PASS line is an error, not a pass', async () => {
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  const claim = 'the silent script'
  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  // Screens clean, exits 0, prints everything EXCEPT the protocol line — the
  // empty-script hole: the exit code alone proved nothing, and the protocol
  // used to be judged by nobody.
  fs.mutate(`${ROOT}/.proof-synthetic/${request.entry}`, 'const one = 1\n')
  commands.on(() => true, { exitCode: 0, output: 'all good, trust me' })

  const run = await engine.conjureRun({ claim, entry: request.entry })
  assert.equal(run.status, 'error', 'no protocol line: the exit code does not get to say PASS')
  assert.match(run.outputHead, /^protocol line missing: scaffolded scripts must end with SYNTHETIC: PASS\/FAIL/)
  assert.match(run.outputHead, /all good, trust me/, 'the original output rides below the note')

  // The evidence and the run marker record the honest verdict, and the
  // re-addressed record still addresses itself.
  const evidence = (await engine.latestEvidence()).get(run.checkId)
  assert.ok(evidence, 'the breached run is still evidence — recorded, not discarded')
  assert.equal(evidence.status, 'error')
  assert.match(evidence.outputHead ?? '', /^protocol line missing/)
  assert.ok(evidence.synthetic !== undefined, 'the synthetic metadata still self-certifies the script')
  assert.ok(fs.log.some(l => l.includes('"synthetic/run"') && l.includes('"status":"error"')),
    'the run marker carries the breach')
  assert.equal((await engine.audit()).ok, true)

  // Control: the same exit 0 WITH the line is a pass — the screen and the
  // scaffold's own contract are untouched.
  const speaking = 'the speaking script'
  const { request: speakingRequest } = await engine.conjureRequest({ claim: speaking, paths: ['src/a.ts'] })
  fs.mutate(`${ROOT}/.proof-synthetic/${speakingRequest.entry}`, "console.log('SYNTHETIC: PASS')\n")
  commands.on(argv => argv.includes(speakingRequest.entry), { exitCode: 0, output: 'SYNTHETIC: PASS' })
  const spoken = await engine.conjureRun({ claim: speaking, entry: speakingRequest.entry })
  assert.equal(spoken.status, 'pass')
})

// -- M18: explicit change sets are canonicalised before they are used -----------

test('M18: backslash and ./ change spellings select and grade like canonical ones', async () => {
  const fs = MemoryFs.of({
    [`${ROOT}/package.json`]: JSON.stringify({ name: 'demo' }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/docs/guide.md`]: '# guide\n',
  })
  const engine = preciseEngine(fs, new FakeCommands(), [
    { label: 'src tests', command: ['npm', 'test'], kind: 'test', paths: ['src/**'] },
  ])
  await engine.establishBaseline()

  // Pre-M18 both spellings silently matched nothing: the selection came back
  // empty and the change read "covered by no check" — unproven by spelling.
  const outcome = await engine.verify({ changed: ['src\\a.ts', './src/a.ts'] })
  assert.deepEqual(outcome.changed, ['src/a.ts'], 'the spellings collapse onto one canonical path')
  assert.deepEqual(outcome.selection.affected.map(c => c.label), ['src tests'],
    'the normalised path selects the check the change actually touches')
  assert.equal(outcome.report.grade, 'proven', 'not unproven by spelling alone')

  // Root-anchored spellings fold against the engine's own root (the
  // toWorkspaceRelative discipline).
  const anchored = await engine.verify({ changed: [`${ROOT}/src/a.ts`] })
  assert.deepEqual(anchored.changed, ['src/a.ts'])
  assert.equal(anchored.report.grade, 'proven')
})

test('M18: coverage matching survives host path spellings — a backslash change no longer reads uncovered', async () => {
  const root = join(COVER_ROOT, 'm18-canonical')
  await makeCoverageWorkspace(root, {
    'src/feature.mjs': 'export const feature = (n) => n * 2\n',
    'check.mjs': [
      "import { feature } from './src/feature.mjs'",
      'if (feature(2) !== 4) process.exit(1)',
      "console.log('executed feature')",
      '',
    ].join('\n'),
  })
  try {
    const engine = coverageEngine(root, [
      { label: 'feature tests', command: ['node', 'check.mjs'], kind: 'test', paths: ['src/**'] },
    ])
    await engine.establishBaseline()
    // The executed set is canonical ('/'-separated, from the V8 profile);
    // the change set arrives in host spellings. Matching the two is exactly
    // what canonicalisation is for — pre-M18 this run read uncovered.
    const outcome = await engine.verify({ changed: ['src\\feature.mjs', './src/feature.mjs'] })
    assert.equal(outcome.report.coverage?.basis, 'v8')
    assert.deepEqual(outcome.coverage?.uncovered, [],
      'the canonical executed set matched the normalised change')
    assert.equal(outcome.coverage?.executedCount, 1)
    assert.equal(outcome.report.grade, 'proven', 'observe mode + executed change: no unproven demotion')
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

// -- M19b: the claim / reason parameters land on the boundary markers -----------

test('M19b: verify claim and baseline reason ride their markers, bounded to 200 characters', async () => {
  const long = 'x'.repeat(350)
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline({ reason: `anchoring: ${long}` })
  const anchored = fs.log.find(l => l.includes('"baseline/established"'))
  assert.ok(anchored, 'the established marker is on the chain')
  assert.ok(anchored.includes(`"reason":"anchoring: ${'x'.repeat(189)}"`),
    'the reason is recorded, truncated at 200 characters total')
  assert.ok(!anchored.includes('x'.repeat(190)), 'and not a character longer')

  const outcome = await engine.verify({ changed: ['src/a.ts'], claim: `claim: ${long}` })
  assert.equal(outcome.report.grade, 'proven')
  const verified = [...fs.log].reverse().find(l => l.includes('"proof/verified"'))
  assert.ok(verified, 'the verified marker is on the chain')
  assert.ok(verified.includes(`"claim":"claim: ${'x'.repeat(193)}"`),
    'the claim rides the marker, truncated at 200 characters total')

  // Absent stays absent: no empty fields are minted for unsaid parameters.
  const quietFs = MemoryFs.of(project())
  const quiet = makeEngine(quietFs, new FakeCommands())
  await quiet.establishBaseline()
  await quiet.verify({ changed: ['src/a.ts'] })
  assert.ok(quietFs.log.filter(l => l.includes('"baseline/established"')).every(l => !l.includes('"reason"')),
    'no reason field when none was given')
  assert.ok(quietFs.log.filter(l => l.includes('"proof/verified"')).every(l => !l.includes('"claim"')),
    'no claim field when none was given')
})

// -- M8: the walk's own truncation reaches the graph -----------------------------

test('M8: loadGraph folds the walk\'s truncation into graph.truncated', async () => {
  // limit 2 over project()'s four files: the WALK stops at two (truncated),
  // while the builder's own eligible count (one .ts among the two walked)
  // never exceeds its limit — so graph.truncated is true exactly through the
  // walkTruncated wiring, not through the builder's own cap.
  const engine = new ProofEngine({
    root: ROOT,
    fs: MemoryFs.of(project()),
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    impactGraphLimit: 2,
  })
  const graph = await engine.loadGraph()
  assert.ok(graph !== undefined)
  assert.equal(graph.truncated, true, 'the walk stopped at its limit; the graph must say so')
})

// -- v0.18: transparency-log publishing (publishCheckpoint) ----------------------

import { sha256 } from '../src/core/hash.ts'
import type { SignerPort } from '../src/core/ports.ts'
import {
  loadPtl, ptlLeafHash, verifyConsistency, verifyInclusion, verifyTreeHead,
} from '../src/core/transparency.ts'

/**
 * Deterministic stand-in keys, one per role: the workspace chain key and the
 * transparency-log operator key are DIFFERENT keys on purpose — the STH must
 * speak for the log operator, never borrow the workspace's authority.
 */
class FakeKey implements SignerPort {
  readonly keyId: string
  constructor(keyId: string) { this.keyId = keyId }
  async sign(data: string): Promise<string> { return `sig:${this.keyId}:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> {
    return signature === `sig:${this.keyId}:${sha256(data)}`
  }
}

const PTL_DIR = `${ROOT}/ptl`

/** The bare signature-check closure T1's verifyTreeHead consumes. */
const operatorCheck = (key: FakeKey) => (data: string, sig: string): Promise<boolean> => key.verify(data, sig)

/** Engine with a signed chain AND a publishable transparency log. */
function publishingEngine(fs: MemoryFs, extra: Record<string, unknown> = {}) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    workspaceKey: 'ws',
    signer: () => Promise.resolve(new FakeKey('ws-key')),
    ptlDir: PTL_DIR,
    ptlSigner: () => Promise.resolve(new FakeKey('operator-key')),
    impactGraphLimit: 1_000,
    ...extra,
  })
}

test('v0.18: publishCheckpoint mirrors the signed checkpoint, signs the tree, and proves inclusion', async () => {
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()

  const first = await engine.publishCheckpoint()
  assert.equal(first.duplicate, false, 'the first publish mints a new leaf')
  assert.equal(first.sequence, 0)
  assert.equal(first.treeSize, 1)
  assert.equal(first.logId, 'operator-key', 'the STH names the operator key that signed it')

  // The outcome describes the tree AS PERSISTED: a fresh load through the
  // same loader a third-party verifier would use recomputes the same root.
  const { log } = await loadPtl(fs, PTL_DIR)
  assert.equal(log.size, 1)
  assert.equal(log.merkleRoot(), first.root, 'sth root is the recomputed Merkle root')
  assert.equal(first.sth.root, first.root)
  assert.equal(first.sth.treeSize, 1)
  assert.equal(first.sth.logId, first.logId)
  assert.equal(first.at, first.sth.at, 'the outcome timestamp is the STH timestamp')

  // The operator signature genuinely covers the tree head (verifyTreeHead
  // takes the bare check function — any key-holding party can adjudicate).
  assert.equal(await verifyTreeHead(first.sth, operatorCheck(new FakeKey('operator-key'))), true)
  assert.equal(await verifyTreeHead(first.sth, operatorCheck(new FakeKey('ws-key'))), false,
    'the workspace key does NOT verify the STH — the operator is a separate authority')

  // The published entry is a faithful mirror of the latest signed checkpoint:
  // same count/head/at/sig/keyId, keyed by the ENGINE's workspace identity.
  const checkpoint = await engine.storeView.latestSignedCheckpoint()
  assert.ok(checkpoint !== undefined)
  const entry = log.entries[0]!
  assert.equal(entry.v, 1)
  assert.equal(entry.workspaceKey, 'ws')
  assert.equal(entry.keyId, checkpoint.keyId)
  assert.equal(entry.count, checkpoint.payload.count)
  assert.equal(entry.head, checkpoint.payload.head)
  assert.equal(entry.at, checkpoint.payload.at)
  assert.equal(entry.sig, checkpoint.sig)
  assert.equal(first.leafHash, ptlLeafHash(entry))

  // Inclusion: the leaf is committed by the root, provably. The verifier
  // takes the ENTRY (it re-derives the leaf hash itself), the proof, and the
  // recomputed root — exactly the third-party position.
  assert.equal(
    verifyInclusion(entry, first.sequence, first.treeSize, first.inclusionProof, first.root),
    true,
  )
})

test('v0.18: republishing the same checkpoint is a duplicate — the tree does not grow', async () => {
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()

  const first = await engine.publishCheckpoint()
  const second = await engine.publishCheckpoint()
  assert.equal(second.duplicate, true, 'nothing new was signed since the first publish')
  assert.equal(second.treeSize, first.treeSize, 'the tree is unchanged')
  assert.equal(second.sequence, first.sequence)
  assert.equal(second.leafHash, first.leafHash)
  assert.equal(second.root, first.root)
  assert.equal((await loadPtl(fs, PTL_DIR)).log.size, 1, 'no second leaf landed on the log')
  assert.equal(await verifyTreeHead(second.sth, operatorCheck(new FakeKey('operator-key'))), true,
    'a duplicate still returns a genuinely signed (re-asserted) tree head')
})

test('v0.18: an unsigned chain has nothing publishable — publishCheckpoint throws clean', async () => {
  const fs = MemoryFs.of(project())
  // No workspace signer: checkpoints land unsigned, and publishing has
  // nothing to mirror. The failure must be a clean precondition error, not a
  // crash or a silently unsigned artifact.
  const engine = new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    ptlDir: PTL_DIR,
    ptlSigner: () => Promise.resolve(new FakeKey('operator-key')),
  })
  await engine.establishBaseline()
  assert.equal((await engine.audit()).chain.mode, 'unsigned')
  await assert.rejects(
    () => engine.publishCheckpoint(),
    /no signed checkpoint on the evidence chain.*baseline.*verification/,
    'the error names the precondition: produce a signed checkpoint first',
  )
})

test('v0.18: publishCheckpoint without ptlDir is a configuration error, checked before anything else', async () => {
  const fs = MemoryFs.of(project())
  // Fully signed chain, fully provisioned operator — but no ptlDir: the
  // feature is OFF, and the refusal must say so before touching any state.
  const engine = publishingEngine(fs, { ptlDir: undefined })
  await engine.establishBaseline()
  await assert.rejects(
    () => engine.publishCheckpoint(),
    /transparency log not configured \(ptlDir\)/,
  )
})

test('v0.18: two checkpoints publish two leaves, and the tree provably extends itself', async () => {
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()
  const publish1 = await engine.publishCheckpoint()

  // New work on the chain: verification appends evidence, a marker, and a
  // NEW signed checkpoint whose count moved past the first one.
  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.report.grade, 'proven')
  const publish2 = await engine.publishCheckpoint()

  assert.equal(publish2.duplicate, false)
  assert.equal(publish2.sequence, 1, 'the second checkpoint lands as the second leaf')
  assert.equal(publish2.treeSize, 2)
  assert.notEqual(publish2.leafHash, publish1.leafHash)

  const { log } = await loadPtl(fs, PTL_DIR)
  assert.equal(log.size, 2)
  assert.ok(log.entries[1]!.count > log.entries[0]!.count,
    'the second mirror carries the later checkpoint count')

  // Consistency: the size-2 tree provably EXTENDS the size-1 tree publish1
  // committed to — the log's history cannot have been rewritten between them.
  assert.equal(
    verifyConsistency(
      publish1.treeSize, publish1.sth.root,
      publish2.treeSize, publish2.sth.root,
      log.consistencyProof(publish1.treeSize, publish2.treeSize),
    ),
    true,
  )
  // And the first leaf is still included in the grown tree.
  assert.equal(
    verifyInclusion(log.entries[0]!, 0, log.size, log.inclusionProof(0), publish2.root),
    true,
  )
})
