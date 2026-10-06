/**
 * Bayesian verification scheduling — the pure-math core of "which checks to
 * run, in what order, under a budget".
 *
 * Everything upstream of this module is set algebra: a change set, a
 * dependency closure, a pool of affected checks. This module turns that pool
 * into an *information-gain decision*: the evidence log is, among other
 * things, a labelled historical dataset (checkId × status × duration), and
 * from it we can learn two things per check — how flaky it is and how slowly
 * it answers — then pick the sequence of runs that buys the most certainty
 * about "all assertions hold" per millisecond spent. That is predictive test
 * selection (Google's 2015–2021 line of work, Facebook's 2019 paper) applied
 * to agent assertions instead of unit tests.
 *
 * ## The model, and every assumption it rests on
 *
 * Each check is a noisy sensor for one binary proposition: "the workspace is
 * healthy (with respect to what this check asserts)". The sensor model is the
 * classic asymmetric binary channel:
 *
 * - π = P(healthy) — the prior, before this session's changes are observed.
 * - α = falseFail = P(observed `fail` | healthy) — flake-induced failure.
 * - β = falsePass = P(observed `pass` | broken) — a broken workspace passing
 *   anyway (stale caches, fixture drift, a check that never really asserted).
 *
 * Assumptions, stated honestly rather than hidden:
 *
 * 1. **β is fixed at 0.02 and never learned** (one exception: synthetic
 *    checks — see assumption 5). Estimating β needs ground truth about
 *    *breakage*, and the evidence log only records observations — there is
 *    no labelled "actually broken" column. A constant is an admitted
 *    guess; a learned number here would be false precision.
 * 2. **Conditionally independent checks.** `claimProbability` multiplies
 *    per-check health probabilities. Two checks that share the changed files
 *    (or share fixtures, or run the same test suite twice) fail *correlated*,
 *    and independence overcounts the evidence. This is the largest known
 *    distortion in the model; the alternative — modelling the joint
 *    distribution over all checks — needs exactly the ground truth we do not
 *    have. The product is treated as a *ranking* signal, not a calibrated
 *    probability, and downstream consumers must not phrase claims as odds.
 * 3. **Flips estimate α.** A symmetric-flake check whose every observation is
 *    independently wrong with probability α shows adjacent-run disagreement
 *    with probability 2α(1−α) ≈ 2α — hence α ≈ flips / (2·(runs−1)); each flip
 *    is one direction of a two-sided coin, so the count is halved. The
 *    denominator stays `runs−1` (all records, decisive or not), which biases
 *    α *down* when error/timeout records interleave — noted as rough, not
 *    corrected: there is no principled correction without more truth data.
 * 4. **Laplace smoothing on the failure tendency.** ρ = (failures+1)/(runs+5)
 *    is the posterior mean of a Beta(1,4) prior: a never-run check starts at
 *    ρ = 0.2 (skeptical), a 200-run all-green veteran decays toward ≈ 0.005.
 *    Non-decisive records (error/timeout/aborted/skipped) count as failures
 *    for ρ: a check that cannot produce an answer is not a check whose pass
 *    we should trust, so the skepticism is directionally right.
 * 5. **Synthetic checks carry a higher β (ο).** A check the agent wrote for
 *    its own claim is graded homework: β 0.15, not 0.02. The long version of
 *    the argument sits at the use site in `computePriors`; the short version
 *    is that the dominant false-pass mode is different in kind (the author
 *    can simply not assert the broken thing), not merely in degree.
 *
 * ## Determinism
 *
 * This module is pure: no clocks, no randomness, no environment, no `node:*`
 * imports. Every Map whose iteration order could leak into a result is
 * iterated over sorted keys, so identical inputs produce deeply identical
 * outputs — the content-addressing discipline (these numbers end up in
 * evidence and reports) demands nothing less.
 *
 * @module dsh-proof/core/bayes
 */

import type { Evidence } from './evidence.ts'
import type { CheckSpec } from './ports.ts'
import type { DependencyGraph, RelPath } from './impact.ts'
import { matchesAny } from './impact.ts'

// ---------------------------------------------------------------------------
// Fixed constants — one source of truth for every magic number in the model.
// Reports and docs reference these by name so prose and code cannot drift.
// The parameters are deliberately NOT configurable knobs: tuned constants
// that no one re-tunes are worse than honest fixed ones.
// ---------------------------------------------------------------------------

export const BAYES_CONSTANTS: {
  /** β = P(pass | broken). Unlearnable without breakage ground truth (assumption 1). */
  readonly falsePass: number
  /** α for a check with no history at all. */
  readonly alphaDefault: number
  /** Lower clamp for a learned α. */
  readonly alphaMin: number
  /** Upper clamp for a learned α: even a pathological flipper is capped. */
  readonly alphaMax: number
  /** Lower clamp for π. */
  readonly priorFloor: number
  /** Upper clamp for π: never claim certainty above 0.999. */
  readonly priorCeiling: number
  /** Laplace pseudo-failures in ρ = (failures + k) / (runs + k + 4). */
  readonly laplaceFailures: number
  /** Laplace pseudo-runs denominator offset (with laplaceFailures = Beta(1, 4)). */
  readonly laplaceRuns: number
  /** Impact strength s for a direct hit: changed file matches a specific (non-'*') path pattern via exact or explicit-glob match, or an LSP-confirmed edge leads from a changed file into the check's covered files. */
  readonly impactDirect: number
  /** s for a bare-directory prefix match ('src' covering 'src/a.ts') with no graph edge behind it. */
  readonly impactPrefix: number
  /** s for a wildcard-only check, and the floor when no positive evidence exists (the candidate pool was already vetted as affected upstream — absence of path evidence rates as wildcard-level, never zero). */
  readonly impactWildcard: number
} = {
  falsePass: 0.02,
  alphaDefault: 0.05,
  alphaMin: 0.01,
  alphaMax: 0.3,
  priorFloor: 0.05,
  priorCeiling: 0.999,
  laplaceFailures: 1,
  laplaceRuns: 5,
  impactDirect: 1.0,
  impactPrefix: 0.7,
  impactWildcard: 0.5,
}

/**
 * ο: β for a check with `source === 'synthetic'` — a test the agent wrote for
 * its own claim. Kept OUT of BAYES_CONSTANTS on purpose: that object is the
 * fixed, never-re-tuned law of the model, while this number is a per-call
 * overridable modelling guess (PriorInput.syntheticFalsePass) — conflating
 * the two would let a knob masquerade as a law.
 */
const SYNTHETIC_FALSE_PASS_DEFAULT = 0.15

/**
 * H-03: β for a check whose script body DRIFTED from the body the baseline
 * digested — an *unreviewed* body. Higher than the synthetic tier (0.15)
 * because a drifted body is not merely self-authored, it is a body that
 * replaced one the baseline had already vouched for, chosen by the same hand
 * that owns the claim and never screened by anyone: at 0.5 a single pass
 * under it moves a cold prior (≤0.9) to ≈0.94 — visibly short of the default
 * 0.97 target, so a rewritten `"test": "node -e \"\""` cannot certify on one
 * forged green. Exported (unlike its synthetic sibling) because the ENGINE
 * applies it as a map rewrite over drifted ids — `computePriors` cannot know
 * which bodies drifted — and the engine's option default must be this one
 * number, not a second copy of it. Same discipline otherwise: NOT in
 * BAYES_CONSTANTS, overridable per deployment (`EngineOptions.driftedFalsePass`),
 * an admitted modelling guess rather than a law.
 */
export const DRIFTED_FALSE_PASS_DEFAULT = 0.5

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value))
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

// ---------------------------------------------------------------------------
// History statistics: evidence log → per-check empirical parameters
// ---------------------------------------------------------------------------

/** Empirical parameters of one check, learned from the evidence log. */
export interface CheckStats {
  /** Evidence records for this check. */
  readonly runs: number
  /** Records whose status was `pass`. */
  readonly passes: number
  /**
   * Adjacent *decisive* observations that disagreed (pass↔fail). A flip is a
   * flakiness signal: `error`/`timeout`/`skipped` are "no answer", not a
   * different answer, so they are skipped when pairing — `pass → error` must
   * not make a healthy check look flaky.
   */
  readonly flips: number
  /** Lower median of the observed durations; defined whenever `runs > 0`. */
  readonly medianDurationMs: number | undefined
}

/**
 * Aggregate the full evidence log into per-check statistics.
 *
 * Records are consumed in the order given (log order — the caller passes
 * `store.all()`); within a check, adjacency for flip counting follows that
 * order, so "same batch, several records" behaves as the log sequenced them.
 */
export function summarizeHistory(records: readonly Evidence[]): Map<string, CheckStats> {
  const groups = new Map<string, Evidence[]>()
  for (const record of records) {
    const list = groups.get(record.checkId)
    if (list === undefined) groups.set(record.checkId, [record])
    else list.push(record)
  }
  const out = new Map<string, CheckStats>()
  for (const checkId of [...groups.keys()].sort()) {
    const list = groups.get(checkId) as Evidence[]
    let passes = 0
    let flips = 0
    let previous: 'pass' | 'fail' | undefined
    const durations: number[] = []
    for (const record of list) {
      if (record.status === 'pass') passes += 1
      if (record.status === 'pass' || record.status === 'fail') {
        if (previous !== undefined && record.status !== previous) flips += 1
        previous = record.status
      }
      durations.push(record.durationMs)
    }
    durations.sort((a, b) => a - b)
    const mid = Math.floor((durations.length - 1) / 2)
    out.set(checkId, {
      runs: list.length,
      passes,
      flips,
      // Lower median for both parities: [50,100] → 50, [50,100,200] → 100.
      // Deterministic by construction and never invents a duration nobody paid.
      medianDurationMs: durations.length === 0 ? undefined : durations[mid],
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// Priors: failure tendency × change impact
// ---------------------------------------------------------------------------

/** The Bayesian model of one candidate check, before this session's runs. */
export interface CheckPrior {
  readonly checkId: string
  /** π ∈ (0,1): P(the check's assertion holds after this change set). */
  readonly priorHealthy: number
  /** α: P(observed fail | healthy) — the false-fail (flake) rate. */
  readonly falseFail: number
  /**
   * β: P(observed pass | broken) — fixed 0.02, unlearnable (assumption 1);
   * 0.15 for synthetic checks (assumption 5), whose author is a party to the
   * claim under test.
   */
  readonly falsePass: number
  /** s ∈ [0,1]: how strongly this change set acts on this check. */
  readonly impact: number
  /** Expected wall-clock cost; historical lower-median duration, else fallback. */
  readonly expectedCostMs: number
}

/** Everything `computePriors` needs; the candidate pool's soundness is the caller's (closed) problem. */
export interface PriorInput {
  /** Affected candidate pool (upstream closure already vetted these). */
  readonly specs: readonly CheckSpec[]
  /** Files changed this session, workspace-relative. */
  readonly changed: readonly RelPath[]
  /**
   * Reverse-dependency graph; `undefined` (or absent) degrades impact to path
   * matching alone. Optional-tolerant because the engine legitimately reaches
   * this type through partial assembly, where the key may not be set yet.
   */
  readonly graph?: DependencyGraph | undefined
  /** Learned statistics keyed by checkId (typically `summarizeHistory(store.all())`). */
  readonly history: Map<string, CheckStats>
  /** Cost assumed for checks with no history. */
  readonly fallbackCostMs: number
  /**
   * ο: β (falsePass) for checks with `source === 'synthetic'` — tests the
   * agent wrote for its own claim. Default 0.15; see the use site in
   * `computePriors` for why this β is (and must be) a different number from
   * `BAYES_CONSTANTS.falsePass`. Overridable per call so a host with actual
   * ground truth about synthetic-check quality can price its own experience —
   * the fixed constants stay unlearned by policy, this one is a knob because
   * its value is an admitted guess, not a law.
   */
  readonly syntheticFalsePass?: number
}

/**
 * Learn each candidate's prior from history and change impact.
 *
 * - Failure tendency: ρ = (failures + 1) / (runs + 5) — Laplace smoothing,
 *   the posterior mean of Beta(1,4). New check: ρ = 0.2. A 200-run all-green
 *   veteran: ρ ≈ 0.005. Failures include non-decisive records (assumption 4).
 * - Impact strength s (see `impactStrength`): the maximum over all evidence
 *   kinds — direct path/LSP hit 1.0, graph-closure distance 1/(1+d), bare
 *   prefix match 0.7, wildcard or no evidence 0.5.
 * - π = clamp(1 − ρ·s, 0.05, 0.999): impact *scales* the failure tendency —
 *   a change that cannot reach a check (s → 0) leaves its veteran record
 *   untouched, a direct hit (s = 1) charges the full learned tendency.
 * - α: no history → 0.05; else clamp(flips / (2·max(1, runs−1)), 0.01, 0.3)
 *   (assumption 3).
 */
export function computePriors(input: PriorInput): Map<string, CheckPrior> {
  const changed = [...new Set(input.changed)].sort()
  const distance = input.graph === undefined ? undefined : closureDistances(input.graph, changed)
  const out = new Map<string, CheckPrior>()
  for (const spec of input.specs) {
    const stats = input.history.get(spec.id)
    const runs = stats?.runs ?? 0
    const passes = stats?.passes ?? 0
    // Non-decisive records land on the failure side of ρ (assumption 4): a
    // check that keeps erroring produces passes we cannot trust.
    const failures = runs - passes
    const rho = (failures + BAYES_CONSTANTS.laplaceFailures) / (runs + BAYES_CONSTANTS.laplaceRuns)
    const impact = impactStrength(spec, changed, input.graph, distance)
    // ο — the synthetic β, and why it is 7.5× the organic one. For an
    // independent maintainer's suite, a false pass needs a mechanical
    // accident: a stale cache, fixture drift, a check that stopped asserting
    // without anyone noticing — rare, and priced at 0.02. For a synthetic
    // check, the author of the test is a *party to the claim it tests*: the
    // cheap false pass is not an accident but an omission — write the empty
    // assertion loop, forget the input that breaks the code, or assert the
    // accidental behaviour the change just introduced and call it intended.
    // None of those look like failures; they look like a green test. 0.15 is
    // an admitted modelling guess (assumption 1 applies doubly: β is
    // unlearnable, and most so exactly here, since a self-serving test by
    // construction produces no breakage signal to learn from), chosen so a
    // pass moves the posterior honestly but visibly less than an organic
    // pass. α and π are untouched by this: a synthetic check still learns
    // flakiness and failure tendency from history like any other — the
    // discount prices *whose hand wrote the assertions*, not how the sensor
    // otherwise behaves.
    const falsePass = spec.source === 'synthetic'
      ? (input.syntheticFalsePass ?? SYNTHETIC_FALSE_PASS_DEFAULT)
      : BAYES_CONSTANTS.falsePass
    out.set(spec.id, {
      checkId: spec.id,
      priorHealthy: clamp(1 - rho * impact, BAYES_CONSTANTS.priorFloor, BAYES_CONSTANTS.priorCeiling),
      falseFail: stats === undefined
        ? BAYES_CONSTANTS.alphaDefault
        : clamp(stats.flips / (2 * Math.max(1, runs - 1)), BAYES_CONSTANTS.alphaMin, BAYES_CONSTANTS.alphaMax),
      falsePass,
      impact,
      expectedCostMs: stats?.medianDurationMs ?? input.fallbackCostMs,
    })
  }
  return out
}

/**
 * Multi-source BFS over reverse-dependency edges: the length of the shortest
 * chain of importers leading out of the changed set, per reachable file.
 * Integer distances are order-insensitive, so the (insertion-ordered) queue
 * discipline cannot leak into the result.
 */
function closureDistances(
  graph: DependencyGraph,
  changed: readonly RelPath[],
): Map<RelPath, number> {
  const distance = new Map<RelPath, number>()
  const queue: RelPath[] = []
  for (const file of changed) {
    if (file.length > 0 && !distance.has(file)) { distance.set(file, 0); queue.push(file) }
  }
  for (let i = 0; i < queue.length; i++) {
    const current = queue[i] as RelPath
    const hop = (distance.get(current) ?? 0) + 1
    for (const dependent of graph.dependents.get(current) ?? []) {
      if (distance.has(dependent)) continue
      distance.set(dependent, hop)
      queue.push(dependent)
    }
  }
  return distance
}

/**
 * Impact strength s — how hard this change set bears on this check.
 * The check keeps the *maximum* over every kind of positive evidence:
 *
 * - 1.0 — a changed file matches one of the check's specific (non-'*')
 *   patterns with an exact file or explicit glob (`dir/**`, `dir/*`) match;
 *   or the graph carries an LSP-confirmed edge from a changed file to a file
 *   the check covers (verified code-level propagation, even when the path
 *   declaration alone would only earn 0.7 or 0.5).
 * - 1/(1+d) — the changed set reaches a covered file through d ≥ 1
 *   approximate reverse-dependency hops. d = 1 (a direct importer) → 0.5,
 *   d = 2 → 1/3: for a specifically-declared check the distance rung stands
 *   on its own and may fall *below* 0.5 — vague coupling is weaker evidence
 *   than a wildcard's blanket claim.
 * - 0.7 — a changed file matches only through a bare directory prefix
 *   (`paths: ['src']` covering `src/a.ts`): the author declared a region,
 *   not a file or glob, and nothing confirms the coupling.
 *
 * The 0.5 wildcard rung is a *case value*, not a floor: it binds when the
 * check itself declares blanket coverage ('*' in `paths`) or when no positive
 * evidence exists at all — the pool was vetted as affected upstream, so
 * "we cannot say why" rates at wildcard level, never at zero, but neither
 * does it inflate a specifically-declared check whose only evidence is a
 * long, approximate propagation chain.
 *
 * Without a graph the ladder degenerates to pure path matching
 * (1.0 / 0.7 / 0.5) — nothing is invented about propagation that was not
 * declared.
 */
function impactStrength(
  spec: CheckSpec,
  changed: readonly RelPath[],
  graph: DependencyGraph | undefined,
  distance: ReadonlyMap<RelPath, number> | undefined,
): number {
  const specific = spec.paths.filter(pattern => pattern !== '*')
  const hasWildcard = spec.paths.includes('*')
  let best: number | undefined

  for (const file of changed) {
    for (const pattern of specific) {
      if (matchesExactly(file, pattern)) best = Math.max(best ?? 0, BAYES_CONSTANTS.impactDirect)
      else if (matchesByBarePrefix(file, pattern)) best = Math.max(best ?? 0, BAYES_CONSTANTS.impactPrefix)
    }
  }

  if (graph !== undefined) {
    // LSP-confirmed propagation: changed file ← imported by ← covered file.
    // Edge keys follow the graph's convention `${dependent}\u0000${dependency}`.
    for (const file of changed) {
      for (const dependent of [...(graph.dependents.get(file) ?? [])].sort()) {
        if (!graph.lspConfirmed.has(`${dependent}\u0000${file}`)) continue
        if (matchesAny(dependent, spec.paths)) {
          best = Math.max(best ?? 0, BAYES_CONSTANTS.impactDirect)
          break
        }
      }
      if (best !== undefined && best >= BAYES_CONSTANTS.impactDirect) break
    }
    // Approximate propagation by closure distance. Coverage here honours '*'
    // as well: a wildcard check counts any dependent, and the wildcard rung
    // below re-floors it at 0.5 anyway, so nothing is undercut.
    if (distance !== undefined && (best ?? 0) < BAYES_CONSTANTS.impactDirect) {
      let nearest: number | undefined
      for (const file of [...distance.keys()].sort()) {
        const d = distance.get(file) ?? 0
        if (d < 1 || !matchesAny(file, spec.paths)) continue
        if (nearest === undefined || d < nearest) nearest = d
      }
      if (nearest !== undefined) best = Math.max(best ?? 0, 1 / (1 + nearest))
    }
  }

  if (best === undefined) return BAYES_CONSTANTS.impactWildcard // no positive evidence at all
  return hasWildcard ? Math.max(best, BAYES_CONSTANTS.impactWildcard) : best
}

/** Exact-file or explicit-glob match (`dir/**`, `dir/*`) — the strong form of path evidence. */
function matchesExactly(file: RelPath, pattern: string): boolean {
  if (pattern === '*') return false
  const normalized = pattern.replace(/\/+$/, '')
  if (normalized.endsWith('/**')) {
    const prefix = normalized.slice(0, -3)
    return file === prefix || file.startsWith(`${prefix}/`)
  }
  if (normalized.endsWith('/*')) {
    const prefix = normalized.slice(0, -2)
    return file.startsWith(`${prefix}/`) && !file.slice(prefix.length + 1).includes('/')
  }
  return file === normalized
}

/** Bare directory prefix (`src` covering `src/a.ts`) — the weak form: a declared region, no explicit glob. */
function matchesByBarePrefix(file: RelPath, pattern: string): boolean {
  if (pattern === '*') return false
  const normalized = pattern.replace(/\/+$/, '')
  if (normalized.endsWith('/**') || normalized.endsWith('/*')) return false
  return file.startsWith(`${normalized}/`)
}

// ---------------------------------------------------------------------------
// Posterior and claim probability
// ---------------------------------------------------------------------------

/**
 * P(healthy | observed) by Bayes on the binary channel:
 *
 *     P(h|obs) = π·P(obs|h) / [π·P(obs|h) + (1−π)·P(obs|broken)]
 *
 * with P(pass|h) = 1−α, P(pass|broken) = β, P(fail|h) = α, P(fail|broken) = 1−β.
 * All four terms are strictly positive over the parameter ranges the rest of
 * this module produces, so the result is always in (0,1) — no degenerate
 * zeros to guard. Plain floating point; π ∈ [0.05, 0.999] keeps every
 * numerator and denominator comfortably away from underflow.
 */
export function posteriorHealthy(prior: CheckPrior, observed: 'pass' | 'fail'): number {
  const pi = prior.priorHealthy
  const givenHealthy = observed === 'pass' ? 1 - prior.falseFail : prior.falseFail
  const givenBroken = observed === 'pass' ? prior.falsePass : 1 - prior.falsePass
  return (pi * givenHealthy) / (pi * givenHealthy + (1 - pi) * givenBroken)
}

/** The claim "every check's assertion holds", as a product of per-check health factors. */
export interface ClaimModel {
  /**
   * Per-check health probability — posterior for checks already run this
   * session, prior for the rest. Assumption 2 (independence) lives here.
   */
  readonly factors: ReadonlyMap<string, number>
}

/**
 * Π factors, in sorted-key order so the float product is reproducible.
 * The empty model is the vacuous claim, which holds with probability 1.
 */
export function claimProbability(model: ClaimModel): number {
  let p = 1
  for (const key of [...model.factors.keys()].sort()) {
    p *= model.factors.get(key) as number
  }
  return p
}

// ---------------------------------------------------------------------------
// Information-gain ranking
// ---------------------------------------------------------------------------

/** One candidate next run, priced in the certainty it is expected to buy. */
export interface ScheduleStep {
  readonly checkId: string
  /** Expected reduction of the claim's binary entropy (nats) from running this check once. */
  readonly voi: number
  /** voi divided by max(1, expectedCostMs): certainty bought per millisecond. */
  readonly voiPerCost: number
}

/** Binary entropy in nats; 0·ln 0 ≡ 0 at both degenerate endpoints. */
function binaryEntropy(p: number): number {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log(p) - (1 - p) * Math.log(1 - p)
}

function withFactor(model: ClaimModel, checkId: string, value: number): ClaimModel {
  const factors = new Map(model.factors)
  factors.set(checkId, value)
  return { factors }
}

/**
 * Rank every check in `priors` by expected information gain about the claim.
 *
 * For one check: with p₀ = current claim probability and f the check's
 * current factor (its prior, or the posterior folded in by an earlier run —
 * `model.factors`, else the prior),
 *
 *     VOI = H(p₀) − [P(pass)·H(p₁|pass) + P(fail)·H(p₁|fail)]
 *
 * where P(obs) marginalises the observation over f, and p₁|obs replaces the
 * factor with `posteriorHealthy` computed FROM f — the factor is treated as
 * this check's standing prior, so both terms of the expectation are measured
 * against the same baseline. That is what makes the martingale exact over the
 * whole factor domain, folded factors included, not just fresh priors:
 * writing the single-check claim as p₀ = f·Πothers,
 *
 *     E[p₁] = P(pass)·(p₀/f)·P(h|pass) + P(fail)·(p₀/f)·P(h|fail)
 *           = (p₀/f)·[P(h|pass)·P(pass) + P(h|fail)·P(fail)]
 *           = (p₀/f)·f = p₀
 *
 * by total probability over f — whatever f's history. Jensen's inequality on
 * the concave H then gives VOI ≥ 0 over the entire legal factor domain:
 * running a check never *increases* expected uncertainty, and a re-run of an
 * already-folded check is priced by the uncertainty its factor still carries
 * (a fail posterior at 0.31 has most of its entropy left to resolve; the
 * observation that produced it is already spent, but the factor is not
 * settled). The returned value is clamped at 0 to absorb floating-point dust
 * (the mathematical value is provably non-negative; the clamp makes the float
 * answer agree with the theorem).
 *
 * This function does not judge "already run": it scores everything it is
 * given, so callers may simply pass the live model — a folded factor is a
 * legal starting point, and re-running it buys exactly the Jensen gap its
 * residual uncertainty admits. Factors absent from the model default to the
 * prior.
 *
 * Order: voiPerCost descending, ties broken by checkId ascending (byte
 * order) — fully deterministic whatever order the maps were built in.
 */
export function rankByInformationGain(
  priors: ReadonlyMap<string, CheckPrior>,
  model: ClaimModel,
): ScheduleStep[] {
  const h0 = binaryEntropy(claimProbability(model))
  const steps: ScheduleStep[] = []
  for (const checkId of [...priors.keys()].sort()) {
    const prior = priors.get(checkId) as CheckPrior
    const factor = model.factors.get(checkId) ?? prior.priorHealthy
    // The Bayesian step must start from the same value P(obs) marginalises
    // over: the check's standing prior is its CURRENT factor (a posterior,
    // for a check this session already heard from), not the session-start
    // prior. Updating from the raw prior while marginalising over the folded
    // factor would price the re-run against a stale baseline — E[p₁] ≠ p₀,
    // and a genuinely informative re-run could score below zero and be
    // clamped away.
    const standing: CheckPrior = { ...prior, priorHealthy: factor }
    const pPass = factor * (1 - prior.falseFail) + (1 - factor) * prior.falsePass
    const pFail = 1 - pPass
    const afterPass = claimProbability(withFactor(model, checkId, posteriorHealthy(standing, 'pass')))
    const afterFail = claimProbability(withFactor(model, checkId, posteriorHealthy(standing, 'fail')))
    const voi = Math.max(0, h0 - (pPass * binaryEntropy(afterPass) + pFail * binaryEntropy(afterFail)))
    steps.push({ checkId, voi, voiPerCost: voi / Math.max(1, prior.expectedCostMs) })
  }
  steps.sort((a, b) => b.voiPerCost - a.voiPerCost || compareStrings(a.checkId, b.checkId))
  return steps
}
