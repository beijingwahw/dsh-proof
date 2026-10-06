/**
 * BAYES — the pure-math core of verification scheduling.
 *
 * `core/bayes.ts` decides "which checks to run" by information gain instead
 * of set membership. These tests pin every formula it rests on: the history
 * aggregation (runs/passes/flips/lower-median), the full prior ladder
 * (Laplace-smoothed failure tendency × impact strength with its 1.0 / 1/(1+d)
 * / 0.7 / 0.5 rungs and both π clamps), the Bayesian update (monotonicity,
 * total probability, the flake-tolerance floor), the claim product, the VOI
 * ranking (cheap-and-uncertain beats expensive-and-settled, lexicographic
 * ties, near-zero VOI for near-certain checks), and — because these numbers
 * are destined for evidence and reports — bit-level determinism under input
 * reordering.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  BAYES_CONSTANTS, claimProbability, computePriors, posteriorHealthy,
  rankByInformationGain, summarizeHistory,
  assertFalsePassDomain, validateBayesKnobs,
  DRIFTED_FALSE_PASS_DEFAULT,
  type BayesKnobs, type CheckPrior, type CheckStats, type ClaimModel, type PriorInput,
} from '../src/core/bayes.ts'
import type { CheckStatus, Evidence } from '../src/core/evidence.ts'
import type { DependencyGraph } from '../src/core/impact.ts'
import type { CheckSpec } from '../src/core/ports.ts'
import { spec } from './helpers.ts'

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Minimal evidence record — summarizeHistory reads only checkId/status/durationMs. */
function evidence(checkId: string, status: CheckStatus, durationMs: number): Evidence {
  return {
    evidenceId: `${checkId}:${status}:${durationMs}`,
    checkId,
    label: checkId,
    kind: 'test',
    command: ['npm', 'run', '--silent', 'test'],
    status,
    exitCode: status === 'pass' ? 0 : 1,
    durationMs,
    outputDigest: '0'.repeat(64),
    outputHead: '',
    recordedAt: '2026-01-01T00:00:00.000Z',
    workspace: { head: null, dirty: [], dirtDigest: '' },
  }
}

/**
 * A dependency graph from explicit `[dependent, dependency]` edges (dependent
 * imports dependency), with an optional subset of those edges marked
 * LSP-confirmed. Keyed and shaped exactly like `buildDependencyGraph` output.
 */
function makeGraph(
  edges: readonly (readonly [dependent: string, dependency: string])[],
  lsp: readonly (readonly [dependent: string, dependency: string])[] = [],
): DependencyGraph {
  const dependents = new Map<string, Set<string>>()
  const nodes = new Set<string>()
  const ensure = (node: string) => {
    let set = dependents.get(node)
    if (set === undefined) { set = new Set(); dependents.set(node, set) }
    return set
  }
  for (const [dependent, dependency] of edges) {
    nodes.add(dependent)
    nodes.add(dependency)
    ensure(dependency).add(dependent)
  }
  for (const node of nodes) ensure(node)
  return {
    nodes,
    dependents,
    scanned: nodes.size,
    truncated: false,
    lspConfirmed: new Set(lsp.map(([dependent, dependency]) => `${dependent}\u0000${dependency}`)),
    precision: 'approximate',
  }
}

function prior(overrides: Partial<CheckPrior> & { checkId: string }): CheckPrior {
  return {
    priorHealthy: 0.8,
    falseFail: 0.05,
    falsePass: BAYES_CONSTANTS.falsePass,
    impact: 1,
    expectedCostMs: 1000,
    ...overrides,
  }
}

function priorsOf(...items: readonly CheckPrior[]): Map<string, CheckPrior> {
  return new Map<string, CheckPrior>(items.map(p => [p.checkId, p] as [string, CheckPrior]))
}

function model(factors: Record<string, number>): ClaimModel {
  return { factors: new Map(Object.entries(factors)) }
}

function priorsFor(options: {
  specs: readonly CheckSpec[]
  changed?: readonly string[]
  graph?: DependencyGraph | undefined
  history?: Map<string, CheckStats>
  fallbackCostMs?: number
}): Map<string, CheckPrior> {
  const input: PriorInput = {
    specs: options.specs,
    changed: options.changed ?? [],
    graph: options.graph ?? undefined,
    history: options.history ?? new Map<string, CheckStats>(),
    fallbackCostMs: options.fallbackCostMs ?? 1234,
  }
  return computePriors(input)
}

/** Binary entropy in nats, transcribed straight from the spec for independent comparison. */
function entropy(p: number): number {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log(p) - (1 - p) * Math.log(1 - p)
}

// ---------------------------------------------------------------------------
// 1. summarizeHistory
// ---------------------------------------------------------------------------

test('BAYES: summarizeHistory aggregates runs, passes, flips and the lower median per check', () => {
  const stats = summarizeHistory([
    evidence('a', 'pass', 100),
    evidence('b', 'pass', 10),
    evidence('a', 'pass', 120),
    evidence('a', 'fail', 200),
    evidence('a', 'pass', 90),
    evidence('b', 'fail', 30),
  ])

  const a = stats.get('a')
  assert.equal(a?.runs, 4)
  assert.equal(a?.passes, 3)
  assert.equal(a?.flips, 2, 'pass,pass,fail,pass flips twice')
  assert.equal(a?.medianDurationMs, 100, 'sorted [90,100,120,200] → lower median at index 1')

  const b = stats.get('b')
  assert.equal(b?.runs, 2)
  assert.equal(b?.passes, 1)
  assert.equal(b?.flips, 1)
  assert.equal(b?.medianDurationMs, 10, 'even count takes the lower median, never an average')
})

test('BAYES: flips pair decisive observations only — error/timeout are "no answer", not a different answer', () => {
  const stats = summarizeHistory([
    evidence('c', 'pass', 1),
    evidence('c', 'error', 2),
    evidence('c', 'timeout', 3),
    evidence('c', 'fail', 4),
    evidence('c', 'pass', 5),
  ])
  assert.equal(stats.get('c')?.flips, 2, 'decisive subsequence is pass,fail,pass; error/timeout are skipped when pairing')
})

test('BAYES: summarizeHistory of nothing is an empty map; one record is its own median', () => {
  assert.deepEqual(summarizeHistory([]), new Map())
  const solo = summarizeHistory([evidence('solo', 'skipped', 70)])
  assert.equal(solo.get('solo')?.runs, 1)
  assert.equal(solo.get('solo')?.passes, 0)
  assert.equal(solo.get('solo')?.flips, 0)
  assert.equal(solo.get('solo')?.medianDurationMs, 70)
})

// ---------------------------------------------------------------------------
// 2. computePriors — the full formula ladder
// ---------------------------------------------------------------------------

test('BAYES: the fixed constants are what the docs say they are', () => {
  assert.equal(BAYES_CONSTANTS.falsePass, 0.02)
  assert.equal(BAYES_CONSTANTS.alphaDefault, 0.05)
  assert.equal(BAYES_CONSTANTS.alphaMin, 0.01)
  assert.equal(BAYES_CONSTANTS.alphaMax, 0.3)
  assert.equal(BAYES_CONSTANTS.priorFloor, 0.05)
  assert.equal(BAYES_CONSTANTS.priorCeiling, 0.999)
})

test('BAYES: a new check with a direct hit — ρ = 0.2, s = 1, π = 0.8, default α, fallback cost', () => {
  const out = priorsFor({ specs: [spec({ id: 'c:new', paths: ['src/**'] })], changed: ['src/a.ts'] })
  const p = out.get('c:new')
  assert.equal(p?.checkId, 'c:new')
  assert.equal(p?.impact, 1, 'changed file under an explicit glob is a direct hit')
  assert.ok(Math.abs((p?.priorHealthy ?? Number.NaN) - 0.8) < 1e-12, `π = 1 − 0.2·1, got ${p?.priorHealthy}`)
  assert.equal(p?.falseFail, BAYES_CONSTANTS.alphaDefault, 'no history → default α')
  assert.equal(p?.falsePass, BAYES_CONSTANTS.falsePass, 'β is the fixed constant')
  assert.equal(p?.expectedCostMs, 1234, 'no history → fallback cost')
})

test('BAYES: a 200-run all-green veteran — ρ ≈ 0.005, α at its floor, historical median cost', () => {
  const history = new Map<string, CheckStats>([['c:vet', { runs: 200, passes: 200, flips: 0, medianDurationMs: 4200 }]])
  const out = priorsFor({ specs: [spec({ id: 'c:vet', paths: ['src/**'] })], changed: ['src/a.ts'], history })
  const p = out.get('c:vet')
  const rho = 1 / 205
  assert.ok(Math.abs((p?.priorHealthy ?? Number.NaN) - (1 - rho)) < 1e-12, `π = 1 − 1/205 ≈ 0.995, got ${p?.priorHealthy}`)
  assert.ok((p?.priorHealthy ?? 0) > 0.994)
  assert.equal(p?.falseFail, BAYES_CONSTANTS.alphaMin, '0 flips → raw 0, clamped up to 0.01')
  assert.equal(p?.expectedCostMs, 4200, 'history beats fallback')
})

test('BAYES: graph closure distance decays impact — d = 1 → s = 0.5, d = 2 → s = 1/3', () => {
  const graph = makeGraph([
    ['app/main.ts', 'lib/a.ts'], // app/main.ts imports lib/a.ts
    ['app/deep.ts', 'app/main.ts'], // app/deep.ts imports app/main.ts
  ])
  const near = priorsFor({ specs: [spec({ id: 'c:near', paths: ['app/**'] })], changed: ['lib/a.ts'], graph })
  assert.equal(near.get('c:near')?.impact, 0.5, 'one dependent hop → 1/(1+1)')
  assert.ok(Math.abs((near.get('c:near')?.priorHealthy ?? Number.NaN) - 0.9) < 1e-12, 'new check at s = 0.5 → π = 0.9')

  const far = priorsFor({ specs: [spec({ id: 'c:far', paths: ['app/deep.ts'] })], changed: ['lib/a.ts'], graph })
  assert.ok(Math.abs((far.get('c:far')?.impact ?? Number.NaN) - 1 / 3) < 1e-12, 'two hops → 1/(1+2)')
})

test('BAYES: wildcard-only coverage earns s = 0.5, with or without a graph', () => {
  const bare = priorsFor({ specs: [spec({ id: 'c:wild' })], changed: ['src/a.ts'] })
  assert.equal(bare.get('c:wild')?.impact, 0.5)
  const graph = makeGraph([['app/main.ts', 'lib/a.ts']])
  const withGraph = priorsFor({ specs: [spec({ id: 'c:wild' })], changed: ['lib/a.ts'], graph })
  assert.equal(withGraph.get('c:wild')?.impact, 0.5, 'a dependent one hop out still only ties the wildcard floor')
})

test('BAYES: without a graph, impact degrades to pure path matching — exact/glob 1.0, bare prefix 0.7, wildcard 0.5', () => {
  const exact = priorsFor({ specs: [spec({ id: 'c:x', paths: ['src/a.ts'] })], changed: ['src/a.ts'] })
  const glob = priorsFor({ specs: [spec({ id: 'c:x', paths: ['src/**'] })], changed: ['src/a.ts'] })
  const prefix = priorsFor({ specs: [spec({ id: 'c:x', paths: ['src'] })], changed: ['src/a.ts'] })
  const wild = priorsFor({ specs: [spec({ id: 'c:x', paths: ['*'] })], changed: ['src/a.ts'] })
  assert.equal(exact.get('c:x')?.impact, 1)
  assert.equal(glob.get('c:x')?.impact, 1)
  assert.equal(prefix.get('c:x')?.impact, 0.7, "paths: ['src'] declares a region, not a file — weaker evidence")
  assert.equal(wild.get('c:x')?.impact, 0.5)
  assert.ok(Math.abs((prefix.get('c:x')?.priorHealthy ?? Number.NaN) - 0.86) < 1e-12, 'π = 1 − 0.2·0.7')
  assert.ok(Math.abs((wild.get('c:x')?.priorHealthy ?? Number.NaN) - 0.9) < 1e-12, 'π = 1 − 0.2·0.5')
})

test('BAYES: an LSP-confirmed edge upgrades propagation to a direct hit; approximate edges do not', () => {
  const lsp = makeGraph([['app/main.ts', 'lib/a.ts']], [['app/main.ts', 'lib/a.ts']])
  const confirmed = priorsFor({ specs: [spec({ id: 'c:precise', paths: ['app'] })], changed: ['lib/a.ts'], graph: lsp })
  assert.equal(confirmed.get('c:precise')?.impact, 1, 'verified edge from the changed file into covered code → 1.0')

  const approximate = makeGraph([['app/main.ts', 'lib/a.ts']])
  const unconfirmed = priorsFor({ specs: [spec({ id: 'c:precise', paths: ['app'] })], changed: ['lib/a.ts'], graph: approximate })
  assert.equal(unconfirmed.get('c:precise')?.impact, 0.5, 'same shape, no confirmation → distance pricing 1/(1+1)')
})

test('BAYES: learned α clamps to [0.01, 0.3] — chronic flippers capped, steady checks floored', () => {
  const history = new Map<string, CheckStats>([
    ['c:flip', { runs: 3, passes: 1, flips: 2, medianDurationMs: 100 }], // raw 2/(2·2) = 0.5 → cap
    ['c:calm', { runs: 5, passes: 5, flips: 0, medianDurationMs: 100 }], // raw 0/8 = 0 → floor
  ])
  const out = priorsFor({
    specs: [spec({ id: 'c:flip', paths: ['src/**'] }), spec({ id: 'c:calm', paths: ['src/**'] })],
    changed: ['src/a.ts'],
    history,
  })
  assert.equal(out.get('c:flip')?.falseFail, BAYES_CONSTANTS.alphaMax)
  assert.equal(out.get('c:calm')?.falseFail, BAYES_CONSTANTS.alphaMin)
})

test('BAYES: π respects both clamps — a 95-run all-fail check bottoms out at 0.05, a saint never exceeds 0.999', () => {
  const doomed = priorsFor({
    specs: [spec({ id: 'c:doomed', paths: ['src/**'] })],
    changed: ['src/a.ts'],
    history: new Map<string, CheckStats>([['c:doomed', { runs: 95, passes: 0, flips: 0, medianDurationMs: 100 }]]),
  })
  // raw: ρ = 96/100 → 1 − 0.96 = 0.04 < floor
  assert.equal(doomed.get('c:doomed')?.priorHealthy, BAYES_CONSTANTS.priorFloor)

  const saint = priorsFor({
    specs: [spec({ id: 'c:saint' })],
    changed: ['src/a.ts'],
    history: new Map<string, CheckStats>([['c:saint', { runs: 995, passes: 995, flips: 0, medianDurationMs: 10 }]]),
  })
  // raw: ρ = 1/1000, wildcard s = 0.5 → 1 − 0.0005 = 0.9995 > ceiling
  assert.equal(saint.get('c:saint')?.priorHealthy, BAYES_CONSTANTS.priorCeiling)
})

test('BAYES: a check carrying both "*" and specific patterns takes the max, not the wildcard floor', () => {
  const out = priorsFor({ specs: [spec({ id: 'c:mx', paths: ['*', 'src/**'] })], changed: ['src/a.ts', 'docs/x.md'] })
  assert.equal(out.get('c:mx')?.impact, 1)
})

test('BAYES: computePriors consumes summarizeHistory output end to end', () => {
  const history = summarizeHistory([
    evidence('c:h', 'pass', 100),
    evidence('c:h', 'fail', 300),
    evidence('c:h', 'pass', 200),
  ])
  const out = priorsFor({ specs: [spec({ id: 'c:h' })], changed: ['src/a.ts'], history })
  const p = out.get('c:h')
  // ρ = (1+1)/(3+5) = 0.25, wildcard s = 0.5 → π = 0.875; α = clamp(2/4) = 0.3
  assert.ok(Math.abs((p?.priorHealthy ?? Number.NaN) - 0.875) < 1e-12, `got ${p?.priorHealthy}`)
  assert.equal(p?.falseFail, BAYES_CONSTANTS.alphaMax)
  assert.equal(p?.expectedCostMs, 200)
})

// ---------------------------------------------------------------------------
// 3. posteriorHealthy
// ---------------------------------------------------------------------------

test('BAYES: a pass raises and a fail lowers the posterior across the parameter grid', () => {
  for (const pi of [0.05, 0.2, 0.5, 0.8, 0.95, 0.999]) {
    for (const alpha of [0.01, 0.05, 0.15, 0.3]) {
      const pr = prior({ checkId: 'grid', priorHealthy: pi, falseFail: alpha })
      const afterPass = posteriorHealthy(pr, 'pass')
      const afterFail = posteriorHealthy(pr, 'fail')
      assert.ok(afterPass >= pi - 1e-12, `pass must not lower π=${pi}, α=${alpha} (got ${afterPass})`)
      assert.ok(afterFail <= pi + 1e-12, `fail must not raise π=${pi}, α=${alpha} (got ${afterFail})`)
      assert.ok(afterPass > 0 && afterPass < 1, 'posteriors stay interior')
      assert.ok(afterFail > 0 && afterFail < 1, 'posteriors stay interior')
    }
  }
})

test('BAYES: total probability — P(h|pass)·P(pass) + P(h|fail)·P(fail) = π exactly (the martingale)', () => {
  for (const pi of [0.2, 0.5, 0.8]) {
    for (const alpha of [0.05, 0.3]) {
      const pr = prior({ checkId: 'total', priorHealthy: pi, falseFail: alpha })
      const pPass = pi * (1 - alpha) + (1 - pi) * pr.falsePass
      const mixed = posteriorHealthy(pr, 'pass') * pPass + posteriorHealthy(pr, 'fail') * (1 - pPass)
      assert.ok(Math.abs(mixed - pi) < 1e-12, `normalization broke at π=${pi}, α=${alpha}`)
    }
  }
})

test('BAYES: one fail from an extreme flake (α = 0.3) does not convict a healthy prior', () => {
  const pr = prior({ checkId: 'flake', priorHealthy: 0.8, falseFail: 0.3 })
  const afterFail = posteriorHealthy(pr, 'fail')
  // 0.8·0.3 / (0.8·0.3 + 0.2·0.98) = 0.24/0.436 ≈ 0.5505 — still majority healthy
  assert.ok(afterFail > 0.5, `a single flaky fail must not convict, got ${afterFail}`)
  assert.ok(Math.abs(afterFail - 0.24 / 0.436) < 1e-12)
})

test('BAYES: a decisive observation from a reliable check actually moves the posterior', () => {
  const pr = prior({ checkId: 'sharp', priorHealthy: 0.5, falseFail: 0.05 })
  assert.ok(posteriorHealthy(pr, 'pass') > 0.95, '0.475/0.485 ≈ 0.979')
  assert.ok(posteriorHealthy(pr, 'fail') < 0.15, '0.025/0.515 ≈ 0.049')
})

test('V7-L3: caller-constructed α and π outside [0,1] are refused — no sign-flipped posteriors', () => {
  // β has been domain-gated since W6-F1; α and π arrive at the same boundary
  // argument (callers construct CheckPrior by hand, the engine rewrites β in
  // place). α outside [0,1] makes a likelihood term negative — α=1.2 on the
  // pass branch is P(pass|healthy) = −0.2, and two negatives multiply back to
  // a plausible-looking positive; π outside [0,1] breaks the mixture the same
  // way. The refusal is loud, naming the knob.
  for (const badAlpha of [-0.1, 1.2, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => posteriorHealthy(prior({ checkId: 'x', falseFail: badAlpha }), 'pass'), RangeError, `α=${badAlpha} must be refused`)
    assert.throws(() => posteriorHealthy(prior({ checkId: 'x', falseFail: badAlpha }), 'fail'), RangeError, `α=${badAlpha} refused on the fail branch too`)
  }
  for (const badPi of [-0.5, 1.5, Number.NaN]) {
    assert.throws(() => posteriorHealthy(prior({ checkId: 'x', priorHealthy: badPi }), 'pass'), RangeError, `π=${badPi} must be refused`)
  }
  // Endpoints are degenerate but well-defined channels — legal, not refused.
  assert.doesNotThrow(() => posteriorHealthy(prior({ checkId: 'x', falseFail: 0, priorHealthy: 0 }), 'pass'), 'α=0 / π=0 are defined')
  assert.equal(posteriorHealthy(prior({ checkId: 'x', falseFail: 1, priorHealthy: 1 }), 'fail'), 1, 'π=1 with α=1: the certain-flake fail proves health exactly')
})

// ---------------------------------------------------------------------------
// 4. claimProbability
// ---------------------------------------------------------------------------

test('BAYES: claimProbability multiplies factors; the empty claim holds vacuously', () => {
  assert.equal(claimProbability({ factors: new Map() }), 1)
  assert.ok(Math.abs(claimProbability(model({ a: 0.8, b: 0.5, c: 1 })) - 0.4) < 1e-12)
})

// ---------------------------------------------------------------------------
// 5. rankByInformationGain
// ---------------------------------------------------------------------------

test('BAYES: a new cheap check outranks a stable expensive veteran', () => {
  const fresh = prior({ checkId: 'c:new', priorHealthy: 0.8, falseFail: 0.05, expectedCostMs: 100 })
  const veteran = prior({ checkId: 'c:vet', priorHealthy: 0.995, falseFail: 0.01, expectedCostMs: 5000 })
  const schedule = rankByInformationGain(priorsOf(fresh, veteran), model({ 'c:new': 0.8, 'c:vet': 0.995 }))

  assert.deepEqual(schedule.map(s => s.checkId), ['c:new', 'c:vet'], 'uncertainty per millisecond wins')
  const [head, tail] = schedule
  assert.ok(head !== undefined && tail !== undefined)
  assert.ok(head.voi > 0.3, `the uncertain check carries real entropy, got ${head.voi}`)
  assert.ok(tail.voi < head.voi, 'the settled veteran moves the claim less')
  assert.ok(head.voiPerCost > tail.voiPerCost * 100, 'and costs 50× less per unit of certainty')
})

test('BAYES: exact ties break lexicographically by checkId', () => {
  const z = prior({ checkId: 'zzz', priorHealthy: 0.5, falseFail: 0.1, expectedCostMs: 100 })
  const a = prior({ checkId: 'aaa', priorHealthy: 0.5, falseFail: 0.1, expectedCostMs: 100 })
  const schedule = rankByInformationGain(priorsOf(z, a), model({ zzz: 0.5, aaa: 0.5 }))
  assert.deepEqual(schedule.map(s => s.checkId), ['aaa', 'zzz'])
  assert.equal(schedule[0]?.voi, schedule[1]?.voi, 'identical priors price identically, so only the id tiebreak decides')
})

test('BAYES: a nearly-certain, low-flake check has almost no information left to give', () => {
  const certain = prior({ checkId: 'c:certain', priorHealthy: 0.999, falseFail: 0.01, expectedCostMs: 1000 })
  const schedule = rankByInformationGain(priorsOf(certain), model({ 'c:certain': 0.999 }))
  const voi = schedule[0]?.voi ?? 1
  assert.ok(voi < 0.01, `expected ≈0 VOI (H barely drops, outcome nearly predetermined), got ${voi}`)
})

test('BAYES: an uncertain check carries real entropy — VOI matches the spec formula transcribed independently', () => {
  const uncertain = prior({ checkId: 'c:unc', priorHealthy: 0.5, falseFail: 0.1, expectedCostMs: 1000 })
  const schedule = rankByInformationGain(priorsOf(uncertain), model({ 'c:unc': 0.5 }))
  const voi = schedule[0]?.voi ?? 0
  assert.ok(voi > 0.4, `expected ≈0.478 nats, got ${voi}`)

  const pi = 0.5
  const alpha = 0.1
  const beta = BAYES_CONSTANTS.falsePass
  const pPass = pi * (1 - alpha) + (1 - pi) * beta
  const fPass = (pi * (1 - alpha)) / pPass
  const fFail = (pi * alpha) / (pi * alpha + (1 - pi) * (1 - beta))
  const expected = entropy(pi) - (pPass * entropy(fPass) + (1 - pPass) * entropy(fFail))
  assert.ok(Math.abs(voi - expected) < 1e-9, `implementation matches the formula: ${voi} vs ${expected}`)
})

test('BAYES: VOI is finite and never negative across a wide prior grid (information never adds entropy)', () => {
  const items: CheckPrior[] = []
  const factors: Record<string, number> = {}
  let i = 0
  for (const pi of [0.05, 0.15, 0.3, 0.5, 0.7, 0.85, 0.95, 0.999]) {
    for (const alpha of [0.01, 0.05, 0.1, 0.2, 0.3]) {
      const id = `c:${String(i).padStart(3, '0')}`
      i += 1
      items.push(prior({ checkId: id, priorHealthy: pi, falseFail: alpha, expectedCostMs: 50 * ((i % 7) + 1) }))
      factors[id] = pi
    }
  }
  const schedule = rankByInformationGain(priorsOf(...items), model(factors))
  assert.equal(schedule.length, items.length)
  for (const step of schedule) {
    assert.ok(Number.isFinite(step.voi) && step.voi >= 0, `${step.checkId}: VOI must be finite and ≥ 0, got ${step.voi}`)
    assert.ok(Number.isFinite(step.voiPerCost) && step.voiPerCost >= 0)
  }
})

// ---------------------------------------------------------------------------
// 5b. rankByInformationGain over folded factors — the re-run domain
// ---------------------------------------------------------------------------

test('BAYES: the martingale is exact over the folded-factor domain — E[p1] = claim0 measured from the current factor', () => {
  // π = 0.8, α = 0.3; one pass folds the factor to that observation's
  // posterior ≈ 0.9929. Marginalising the next observation over the FOLDED
  // factor and updating from the same folded factor must return the claim
  // probability unchanged — the total-probability identity that makes
  // VOI ≥ 0 a theorem over the folded domain too. (Marginalising over the
  // fold but updating from the session-start prior — the pre-fix math —
  // measured the two branches of the expectation against different
  // baselines: E[p1] landed 13.5pp below claim0.)
  const pr = prior({ checkId: 'c:fold', priorHealthy: 0.8, falseFail: 0.3 })
  const factor = posteriorHealthy(pr, 'pass')
  assert.ok(Math.abs(factor - 0.56 / 0.564) < 1e-15, `one pass folds π=0.8,α=0.3 to ≈0.9929, got ${factor}`)

  const standing: CheckPrior = { ...pr, priorHealthy: factor }
  const pPass = factor * (1 - pr.falseFail) + (1 - factor) * pr.falsePass
  const afterPass = claimProbability(model({ 'c:fold': posteriorHealthy(standing, 'pass') }))
  const afterFail = claimProbability(model({ 'c:fold': posteriorHealthy(standing, 'fail') }))
  const claim0 = claimProbability(model({ 'c:fold': factor }))
  const expectation = pPass * afterPass + (1 - pPass) * afterFail
  assert.ok(
    Math.abs(expectation - claim0) < 1e-12,
    `E[p1] must equal claim0 exactly when both terms start from the fold, got ${expectation} vs ${claim0}`,
  )

  // The scheduler prices the re-run from the same fold: a folded pass leaves
  // only the fail branch's residual entropy (≈0.0077 nats — small but real),
  // where the stale-baseline math produced a raw −0.197 that the clamp
  // silently ate as exactly 0.
  const schedule = rankByInformationGain(priorsOf(pr), model({ 'c:fold': factor }))
  const voi = schedule[0]?.voi ?? Number.NaN
  assert.ok(voi > 0.005 && voi < 0.01, `a folded pass posterior still prices its fail branch, got ${voi}`)
  const closedForm = entropy(claim0) - (pPass * entropy(afterPass) + (1 - pPass) * entropy(afterFail))
  assert.ok(Math.abs(voi - closedForm) < 1e-12, `implementation matches the formula: ${voi} vs ${closedForm}`)
})

test('BAYES: a failed check keeps real re-run value — VOI measured from the folded factor', () => {
  // π = 0.6, α = 0.3; one fail folds the factor to 0.18/0.572 ≈ 0.3147. The
  // re-run's information is priced from THAT factor: the fold still sits far
  // from both 0 and 1, so its next observation can move the claim a lot, and
  // the scheduler must report that (measured ≈ 0.2846 nats). The pre-fix
  // code priced this state against the raw prior instead — understating the
  // re-run at ≈ 0.124, and clamping the mirrored pass-fold case's raw −0.197
  // to a silent 0: re-run value was systematically mispriced in BOTH
  // directions.
  const pr = prior({ checkId: 'c:retry', priorHealthy: 0.6, falseFail: 0.3 })
  const factor = posteriorHealthy(pr, 'fail')
  assert.ok(Math.abs(factor - 0.18 / 0.572) < 1e-15, `one fail folds π=0.6,α=0.3 to ≈0.3147, got ${factor}`)

  const schedule = rankByInformationGain(priorsOf(pr), model({ 'c:retry': factor }))
  const voi = schedule[0]?.voi ?? 0
  assert.ok(voi > 0.1, `a folded fail posterior still buys >0.1 nats of certainty, got ${voi}`)
  assert.ok(voi > 0.25 && voi < 0.32, `and the measured value is ≈0.2846 nats, got ${voi}`)

  // The value is the new math's closed form, transcribed independently:
  // marginalise over the fold, update from the fold.
  const standing: CheckPrior = { ...pr, priorHealthy: factor }
  const pPass = factor * (1 - pr.falseFail) + (1 - factor) * pr.falsePass
  const fPass = posteriorHealthy(standing, 'pass')
  const fFail = posteriorHealthy(standing, 'fail')
  const expected = entropy(factor) - (pPass * entropy(fPass) + (1 - pPass) * entropy(fFail))
  assert.ok(Math.abs(voi - expected) < 1e-9, `implementation matches the formula: ${voi} vs ${expected}`)
})

test('BAYES: VOI stays ≥ 0 across the folded-factor grid — the clamp only absorbs float dust', () => {
  // Every factor is a posterior of its prior (the folded state of a check
  // that already answered) — the domain over which the martingale, and hence
  // VOI ≥ 0, must hold once re-runs are priced from the current factor. Each
  // grid point is a single-check claim so the entropy is macroscopic and the
  // sign is not a matter of underflow.
  let points = 0
  for (const pi of [0.05, 0.15, 0.3, 0.5, 0.7, 0.85, 0.95, 0.999]) {
    for (const alpha of [0.01, 0.05, 0.1, 0.2, 0.3]) {
      const pr = prior({ checkId: 'c:grid', priorHealthy: pi, falseFail: alpha })
      for (const obs of ['pass', 'fail'] as const) {
        const factor = posteriorHealthy(pr, obs)
        points += 1
        const schedule = rankByInformationGain(priorsOf(pr), model({ 'c:grid': factor }))
        const voi = schedule[0]?.voi ?? Number.NaN
        assert.ok(Number.isFinite(voi) && voi >= 0, `π=${pi} α=${alpha} folded ${obs}: VOI must be ≥ 0, got ${voi}`)
        // And it is the true Jensen gap, not the clamp masking a negative:
        // the closed form (marginalise over the fold, update from the fold)
        // is itself non-negative and matches to float dust.
        const standing: CheckPrior = { ...pr, priorHealthy: factor }
        const pPass = factor * (1 - pr.falseFail) + (1 - factor) * pr.falsePass
        const fPass = posteriorHealthy(standing, 'pass')
        const fFail = posteriorHealthy(standing, 'fail')
        const raw = entropy(factor) - (pPass * entropy(fPass) + (1 - pPass) * entropy(fFail))
        assert.ok(raw > -1e-12, `π=${pi} α=${alpha} folded ${obs}: the unclamped value is mathematically ≥ 0, got ${raw}`)
        assert.ok(Math.abs(voi - Math.max(0, raw)) < 1e-9, `π=${pi} α=${alpha} folded ${obs}: ${voi} vs ${raw}`)
      }
    }
  }
  assert.ok(points >= 80, `the sweep actually swept (${points} folded points)`)

  // The same theorem over a shared multi-check model, folded factors and all:
  // the whole-schedule product claim stays clamp-clean too.
  const items: CheckPrior[] = []
  const factors: Record<string, number> = {}
  let i = 0
  for (const pi of [0.05, 0.15, 0.3, 0.5, 0.7, 0.85, 0.95, 0.999]) {
    for (const alpha of [0.01, 0.05, 0.1, 0.2, 0.3]) {
      const pr = prior({ checkId: `c:${String(i).padStart(3, '0')}`, priorHealthy: pi, falseFail: alpha, expectedCostMs: 50 * ((i % 7) + 1) })
      i += 1
      items.push(pr)
      factors[pr.checkId] = posteriorHealthy(pr, i % 2 === 0 ? 'pass' : 'fail')
    }
  }
  const schedule = rankByInformationGain(priorsOf(...items), model(factors))
  assert.equal(schedule.length, items.length)
  for (const step of schedule) {
    assert.ok(Number.isFinite(step.voi) && step.voi >= 0, `${step.checkId}: folded-domain VOI must be finite and ≥ 0, got ${step.voi}`)
    assert.ok(Number.isFinite(step.voiPerCost) && step.voiPerCost >= 0)
  }
})

// ---------------------------------------------------------------------------
// 6. Determinism
// ---------------------------------------------------------------------------

test('BAYES: identical inputs produce deeply identical outputs, whatever order the specs arrived in', () => {
  const records = [
    evidence('c:a', 'pass', 100),
    evidence('c:a', 'fail', 300),
    evidence('c:b', 'pass', 50),
    evidence('c:b', 'pass', 80),
    evidence('c:b', 'fail', 60),
    evidence('c:a', 'pass', 70),
  ]
  assert.deepEqual(summarizeHistory(records), summarizeHistory(records), 'history aggregation is a pure function')

  const graph = makeGraph([['app/main.ts', 'lib/a.ts']], [['app/main.ts', 'lib/a.ts']])
  const history = summarizeHistory(records)
  const specs = [
    spec({ id: 'c:a', paths: ['src/**'] }),
    spec({ id: 'c:b', paths: ['app'] }),
    spec({ id: 'c:c', paths: ['*'] }),
  ]
  const input = (order: readonly CheckSpec[]): PriorInput => ({
    specs: order,
    changed: ['lib/a.ts', 'src/x.ts'],
    graph,
    history,
    fallbackCostMs: 999,
  })
  const first = computePriors(input(specs))
  assert.deepEqual(computePriors(input(specs)), first, 'same input twice → same output')
  const shuffled = computePriors(input([specs[2] as CheckSpec, specs[0] as CheckSpec, specs[1] as CheckSpec]))
  assert.deepEqual(shuffled, first, 'spec order must not change any prior')
  assert.deepEqual([...shuffled.keys()].sort(), [...first.keys()].sort())

  const factors: Record<string, number> = {}
  for (const p of first.values()) factors[p.checkId] = p.priorHealthy
  const scheduleA = rankByInformationGain(first, model(factors))
  assert.deepEqual(rankByInformationGain(first, model(factors)), scheduleA)
  assert.deepEqual(rankByInformationGain(shuffled, model(factors)), scheduleA, 'ranking is independent of map construction order')
})

// ---------------------------------------------------------------------------
// 7. W6-F1/F2 — β domain validation (the total gate for every falsePass knob)
// ---------------------------------------------------------------------------

test('BAYES: assertFalsePassDomain accepts the open interval (0,1) on a fine grid and rejects everything outside', () => {
  // Interior grid: from float dust above 0 to float dust below 1.
  for (let beta = 0.001; beta < 1; beta += 0.0199) {
    assert.doesNotThrow(() => assertFalsePassDomain(Number(beta.toFixed(4))), `β=${beta} is in the legal open interval`)
  }
  for (const legal of [0.02, 0.15, 0.5, 0.9, 0.999999]) {
    assert.doesNotThrow(() => assertFalsePassDomain(legal), `β=${legal} is legal`)
  }
  // The endpoints are excluded because each collapses the channel: β=0 makes
  // one forged pass certify (posterior exactly 1), β=1 makes a fail prove
  // health (fail posterior exactly 1) — the measured H-03 reversals.
  for (const illegal of [0, 1, -0.5, -1, 1.0000001, 0.9999999999 + 1e-9, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(() => assertFalsePassDomain(illegal), RangeError, `β=${illegal} must be refused`)
    assert.throws(() => assertFalsePassDomain(illegal), /\(0,1\)/, `the error names the domain for β=${illegal}`)
  }
})

test('BAYES: the channel really does reverse at the endpoints — why the domain is open (KAT of the measured reversals)', () => {
  // The reversals, transcribed in closed form (the gated posteriorHealthy
  // refuses to compute them — that refusal IS the fix; this transcription is
  // what it refuses to produce).
  const channel = (pi: number, beta: number, obs: 'pass' | 'fail'): number => {
    const givenHealthy = obs === 'pass' ? 0.95 : 0.05
    const givenBroken = obs === 'pass' ? beta : 1 - beta
    return (pi * givenHealthy) / (pi * givenHealthy + (1 - pi) * givenBroken)
  }
  // β=0: a pass posterior is EXACTLY 1 (one forged green certifies anything).
  assert.equal(channel(0.9, 0, 'pass'), 1, 'β=0 ⇒ P(h|pass) = 1 — the H-03 inversion')
  // β=1: a FAIL posterior is exactly 1 (a fail proves health).
  assert.equal(channel(0.9, 1, 'fail'), 1, 'β=1 ⇒ P(h|fail) = 1 — nonsense, refused by the gate')
  // β<0: the pass posterior EXCEEDS 1 (super-probability on reports).
  assert.ok(channel(0.9, -0.5, 'pass') > 1, 'negative β ⇒ posterior above 1')
  // And the module refuses to be the one computing any of the three:
  for (const beta of [0, 1, -0.5, Number.NaN]) {
    assert.throws(
      () => posteriorHealthy(prior({ checkId: 'bad', priorHealthy: 0.9, falsePass: beta }), 'pass'),
      RangeError,
      `posteriorHealthy is the last line of defence for caller-constructed priors (β=${beta})`,
    )
  }
})

test('BAYES: validateBayesKnobs gates every knob; legal sets pass untouched', () => {
  const legal: BayesKnobs[] = [
    {},
    { certifyTarget: 0.97 },
    { syntheticFalsePass: 0.15, driftedFalsePass: 0.5 },
    { certifyTarget: 0.5, syntheticFalsePass: 0.99, driftedFalsePass: 0.01 },
  ]
  for (const knobs of legal) assert.doesNotThrow(() => validateBayesKnobs(knobs), JSON.stringify(knobs))

  // Each knob is refused alone, and the error names the offender.
  assert.throws(() => validateBayesKnobs({ syntheticFalsePass: 0 }), /syntheticFalsePass/)
  assert.throws(() => validateBayesKnobs({ syntheticFalsePass: 1 }), /syntheticFalsePass/)
  assert.throws(() => validateBayesKnobs({ driftedFalsePass: Number.NaN }), /driftedFalsePass/)
  assert.throws(() => validateBayesKnobs({ driftedFalsePass: -0.5 }), /driftedFalsePass/)
  assert.throws(() => validateBayesKnobs({ driftedFalsePass: Number.POSITIVE_INFINITY }), /driftedFalsePass/)
  // certifyTarget shares the OPEN interval: 0 certifies anything (every H2/
  // H-03 threshold collapses to a tautology), 1 certifies nothing.
  assert.throws(() => validateBayesKnobs({ certifyTarget: 0 }), /certifyTarget/)
  assert.throws(() => validateBayesKnobs({ certifyTarget: 1 }), /certifyTarget/)
  assert.throws(() => validateBayesKnobs({ certifyTarget: Number.NaN }), /certifyTarget/)
})

test('BAYES: computePriors gates its own syntheticFalsePass; posteriorHealthy gates caller-built priors', () => {
  // The pure core does not wait for the engine/config boundary.
  assert.throws(
    () => computePriors({ specs: [spec({ id: 's', source: 'synthetic' })], changed: [], history: new Map(), fallbackCostMs: 1, syntheticFalsePass: 0 }),
    /PriorInput\.syntheticFalsePass/,
  )
  assert.throws(
    () => computePriors({ specs: [spec({ id: 's', source: 'synthetic' })], changed: [], history: new Map(), fallbackCostMs: 1, syntheticFalsePass: Number.NaN }),
    /PriorInput\.syntheticFalsePass/,
  )
  assert.doesNotThrow(() =>
    computePriors({ specs: [spec({ id: 's', source: 'synthetic' })], changed: [], history: new Map(), fallbackCostMs: 1, syntheticFalsePass: 0.3 }))
  // And the module's own defaults satisfy the domain they export (a bad
  // future edit to a constant fails at import time).
  assert.doesNotThrow(() => assertFalsePassDomain(BAYES_CONSTANTS.falsePass))
  assert.doesNotThrow(() => assertFalsePassDomain(DRIFTED_FALSE_PASS_DEFAULT))
})

test('BAYES (W6-F3 KAT): the per-tier one-pass posteriors the grinding-curve table claims', () => {
  // The table in the DRIFTED_FALSE_PASS_DEFAULT doc comment, pinned as
  // numbers so the comment cannot drift from the math it describes
  // (β=0.5, α=0.05, cold priors 1−0.2s):
  const one = (pi: number): number =>
    posteriorHealthy(prior({ checkId: 'tier', priorHealthy: pi, falsePass: 0.5 }), 'pass')
  // The table quotes four decimals; the tolerance pins those, not the ulp.
  const close = (a: number, b: number): boolean => Math.abs(a - b) < 1e-4
  assert.ok(close(one(0.8), 0.8837), `s=1.0 tier: ${one(0.8)}`)
  assert.ok(close(one(0.86), 0.9211), `s=0.7 tier: ${one(0.86)}`)
  assert.ok(close(one(0.9), 0.9448), `s=0.5 tier: ${one(0.9)}`)
  // Every tier stays below the default 0.97 target on ONE pass — single-
  // session certification remains impossible — and the s=0.5 tier is the
  // closest, which is why the table names it the attacker's floor.
  for (const pi of [0.8, 0.86, 0.9]) assert.ok(one(pi) < 0.97)
  assert.ok(one(0.9) > one(0.86) && one(0.86) > one(0.8), 'higher tiers start closer to the target')
})

// ---------------------------------------------------------------------------
// 8. Property sweep — the full (π, α) plane
// ---------------------------------------------------------------------------

test('BAYES: property sweep — posteriors stay interior and observation-respecting over the whole (π, α) grid', () => {
  const pis: number[] = []
  for (let pi = 0.05; pi <= 0.999; pi += 0.037) pis.push(Math.min(pi, 0.999))
  if (pis[pis.length - 1] !== 0.999) pis.push(0.999)
  const alphas = [0.01, 0.04, 0.08, 0.12, 0.16, 0.2, 0.24, 0.27, 0.3]

  let checked = 0
  for (const pi of pis) {
    for (const alpha of alphas) {
      checked += 1
      const pr = prior({ checkId: 'sweep', priorHealthy: pi, falseFail: alpha })
      const pp = posteriorHealthy(pr, 'pass')
      const pf = posteriorHealthy(pr, 'fail')
      assert.ok(pp > 0 && pp < 1 && pf > 0 && pf < 1, `π=${pi} α=${alpha}: posteriors must stay in (0,1)`)
      assert.ok(pp >= pi - 1e-9, `pass must not lower π=${pi}, α=${alpha} → ${pp}`)
      assert.ok(pf <= pi + 1e-9, `fail must not raise π=${pi}, α=${alpha} → ${pf}`)
    }
  }
  assert.ok(checked > 150, `the sweep actually swept (${checked} points)`)
})
