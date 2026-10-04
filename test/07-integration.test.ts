/**
 * INTEGRATION — the real thing, not fakes.
 *
 * Uses the production Node ports (`NodeFsPort`, `NodeCommandPort`) against a
 * real temporary project and a real shell: `npm run --silent test` actually
 * spawns a process and its exit code is the evidence. This is the test that
 * proves the thesis end to end, with nothing stubbed.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { ProofEngine } from '../src/engine.ts'
import { NodeCommandPort, NodeFsPort, SystemClock } from '../src/node-ports.ts'
import { FakeWorkspace } from './helpers.ts'

// <workspace>/.openclaw/tmp/proof-it — the designated scratch area.
const WORKSPACE = fileURLToPath(new URL('../../', import.meta.url))
const ROOT = join(WORKSPACE, '.openclaw', 'tmp', `proof-it-${process.pid}`)

const CHECK_SCRIPT = [
  "import { existsSync } from 'node:fs'",
  "import { fileURLToPath } from 'node:url'",
  "const marker = fileURLToPath(new URL('./ok.marker', import.meta.url))",
  "if (!existsSync(marker)) {",
  "  console.error('FAIL src/checkout.js — expected ok.marker to exist')",
  "  process.exit(1)",
  "}",
  "console.log('PASS 1 test')",
  "process.exit(0)",
  '',
].join('\n')

before(async () => {
  await fsp.rm(ROOT, { recursive: true, force: true })
  await fsp.mkdir(ROOT, { recursive: true })
  await fsp.writeFile(join(ROOT, 'package.json'), JSON.stringify({
    name: 'proof-integration-fixture',
    version: '1.0.0',
    private: true,
    scripts: { test: 'node check.mjs' },
  }, null, 2))
  await fsp.writeFile(join(ROOT, 'check.mjs'), CHECK_SCRIPT)
  await fsp.writeFile(join(ROOT, 'ok.marker'), 'present\n')
})

after(async () => {
  await fsp.rm(ROOT, { recursive: true, force: true })
})

function engine() {
  const ws = new FakeWorkspace(ROOT)
  return new ProofEngine({
    root: ROOT,
    fs: new NodeFsPort(),
    commands: new NodeCommandPort(),
    workspace: ws,
    clock: new SystemClock(),
    checkTimeoutMs: 30_000,
  })
}

test('INTEGRATION: a real green baseline, then a real regression, then real attribution', async () => {
  const eng = engine()

  // 1. Discovery finds the workspace's own objective check.
  const checks = await eng.loadChecks()
  assert.equal(checks.length, 1, `expected 1 discovered check, got ${checks.map(c => c.label).join(', ')}`)
  assert.deepEqual(checks[0]?.command, ['npm', 'run', '--silent', 'test'])

  // 2. The baseline really runs `npm run --silent test` and it really passes.
  const { baseline } = await eng.establishBaseline()
  assert.equal(baseline.checks[0]?.status, 'pass', `baseline output: ${baseline.checks[0]?.outputHead}`)
  assert.equal(baseline.checks[0]?.exitCode, 0)

  // 3. The evidence log is on disk and self-consistent.
  const audit = await eng.audit()
  assert.equal(audit.ok, true)
  assert.equal(audit.total, 1)

  // 4. Something breaks — outside the agent's tool stream this time.
  await fsp.rm(join(ROOT, 'ok.marker'))

  // 5. Verification re-runs the real command and grades against the baseline.
  const outcome = await eng.verify({ changed: ['check.mjs'] })
  assert.equal(outcome.report.grade, 'regressed', `summary: ${outcome.report.summary.passing}/${outcome.report.summary.failing}`)
  assert.equal(outcome.report.summary.regressions, 1)
  assert.equal(outcome.report.summary.preExisting, 0)
  assert.equal(outcome.report.checks[0]?.verdict, 'regression')
  assert.ok(outcome.report.checks[0]?.attributedTo.includes('check.mjs'))
  assert.match(outcome.report.checks[0]?.current?.outputHead ?? '', /FAIL/)

  // 6. Restore the marker: against the ORIGINAL green baseline this is
  //    `still-passing`, and the claim is PROVEN again — no false "fixed" credit.
  await fsp.writeFile(join(ROOT, 'ok.marker'), 'present\n')
  const healed = await eng.verify({ changed: ['check.mjs'], all: true })
  assert.equal(healed.report.checks[0]?.verdict, 'still-passing')
  assert.equal(healed.report.grade, 'proven')

  // 7. An agent that accepts red as the new normal, then repairs it, must get
  //    credit for the repair: re-baseline at the broken state, then fix.
  await fsp.rm(join(ROOT, 'ok.marker'))
  await eng.establishBaseline()
  await fsp.writeFile(join(ROOT, 'ok.marker'), 'present\n')
  const repaired = await eng.verify({ changed: ['check.mjs'], all: true })
  assert.equal(repaired.report.checks[0]?.verdict, 'fixed', `got ${repaired.report.checks[0]?.verdict}`)
  assert.equal(repaired.report.grade, 'proven')

  // 8. The evidence chain is content-addressed and still audits clean.
  const finalAudit = await eng.audit()
  assert.equal(finalAudit.ok, true, `corrupt: ${finalAudit.corrupt.join(', ')}`)
  assert.ok(finalAudit.total >= 3, `expected >= 3 distinct evidence records, got ${finalAudit.total}`)
})

test('INTEGRATION: the plugin never claims PROVEN on a workspace with no objective checks', async () => {
  const bare = join(ROOT, 'bare')
  await fsp.mkdir(bare, { recursive: true })
  await fsp.writeFile(join(bare, 'README.md'), '# nothing to verify here\n')

  const eng = new ProofEngine({
    root: bare,
    fs: new NodeFsPort(),
    commands: new NodeCommandPort(),
    workspace: new FakeWorkspace(bare),
    clock: new SystemClock(),
  })
  await eng.establishBaseline()
  const outcome = await eng.verify({ changed: ['README.md'] })
  assert.notEqual(outcome.report.grade, 'proven', 'with nothing objective to run, the honest grade is not "proven"')
})
