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
import type { Evidence } from './evidence.ts';
import type { CheckSpec } from './ports.ts';
import type { DependencyGraph, RelPath } from './impact.ts';
export declare const BAYES_CONSTANTS: {
    /** β = P(pass | broken). Unlearnable without breakage ground truth (assumption 1). */
    readonly falsePass: number;
    /** α for a check with no history at all. */
    readonly alphaDefault: number;
    /** Lower clamp for a learned α. */
    readonly alphaMin: number;
    /** Upper clamp for a learned α: even a pathological flipper is capped. */
    readonly alphaMax: number;
    /** Lower clamp for π. */
    readonly priorFloor: number;
    /** Upper clamp for π: never claim certainty above 0.999. */
    readonly priorCeiling: number;
    /** Laplace pseudo-failures in ρ = (failures + k) / (runs + k + 4). */
    readonly laplaceFailures: number;
    /** Laplace pseudo-runs denominator offset (with laplaceFailures = Beta(1, 4)). */
    readonly laplaceRuns: number;
    /** Impact strength s for a direct hit: changed file matches a specific (non-'*') path pattern via exact or explicit-glob match, or an LSP-confirmed edge leads from a changed file into the check's covered files. */
    readonly impactDirect: number;
    /** s for a bare-directory prefix match ('src' covering 'src/a.ts') with no graph edge behind it. */
    readonly impactPrefix: number;
    /** s for a wildcard-only check, and the floor when no positive evidence exists (the candidate pool was already vetted as affected upstream — absence of path evidence rates as wildcard-level, never zero). */
    readonly impactWildcard: number;
};
/**
 * H-03: β for a check whose script body DRIFTED from the body the baseline
 * digested — an *unreviewed* body. Higher than the synthetic tier (0.15)
 * because a drifted body is not merely self-authored, it is a body that
 * replaced one the baseline had already vouched for, chosen by the same hand
 * that owns the claim and never screened by anyone.
 *
 * W6-F3 — the honest grinding curve, per impact tier (measured, lib/core/
 * bayes.js, β=0.5, α=0.05, default target 0.97; "n greens" counts post-drift
 * pass observations folded from the cold prior, one decisive record per
 * check per session, with the firstSeen boundary costing ≈2 sessions of
 * lag — engine.ts drops this-run records recorded at or before the drift
 * marker's timestamp):
 *
 * | s (impact tier)                 | cold π | 1 pass → | greens to re-cross 0.97 | ≈ sessions |
 * |---------------------------------|--------|----------|--------------------------|------------|
 * | 1.0 direct                      | 0.800  | 0.8837   | 13                       | ≈15        |
 * | 0.7 bare-prefix                 | 0.860  | 0.9211   | 8                        | ≈10        |
 * | 0.5 wildcard / distance-1       | 0.900  | 0.9448   | 4                        | ≈6         |
 *
 * The k=13 claim in the original H-03 note holds ONLY at s=1.0 (direct-hit
 * rewrites). s=0.5 is the FLOOR of what an attacker self-selects into: any
 * check declared with `paths: ['*']` (or reached only through one
 * approximate hop) sits there, and 4 forged greens — roughly six sessions —
 * re-cross the target. One forged green remains short of the line at every
 * tier (single-session certification is still impossible), but "multiple
 * honest observations" is tier-dependent, not the flat k=13 the old comment
 * implied. The chain keeps a visible scriptDrift marker per session; what it
 * does NOT have is any counter that escalates after N consecutive un-
 * re-anchored drifts — that mechanism, or a per-tier β, is the recorded
 * follow-up. Exported (unlike its synthetic sibling) because the ENGINE
 * applies it as a map rewrite over drifted ids — `computePriors` cannot know
 * which bodies drifted — and the engine's option default must be this one
 * number, not a second copy of it. Same discipline otherwise: NOT in
 * BAYES_CONSTANTS, overridable per deployment (`EngineOptions.driftedFalsePass`,
 * domain-gated by `assertFalsePassDomain` below), an admitted modelling guess
 * rather than a law.
 */
export declare const DRIFTED_FALSE_PASS_DEFAULT = 0.5;
/**
 * W15-L12: the one true default for `certifyTarget` — the number behind
 * "proven (p≈0.97)". It lives HERE (the graded-trust module, which core owns
 * free of host-side imports) so every mirror of it references ONE binding:
 * the config schema's default (config.ts imports this constant), the
 * engine's EngineOptions fallback, and the narrative's display fallback in
 * core/regression.ts. Re-typing 0.97 in each place is how the display and
 * the gate silently disagree the day one of them moves.
 */
export declare const DEFAULT_CERTIFY_TARGET = 0.97;
/**
 * Assert that β (a falsePass rate) lies in the OPEN interval (0, 1), rejecting
 * non-finite values (NaN, ±Infinity). Both endpoints are excluded because
 * each collapses the binary channel the whole model rests on: at β=0 every
 * pass certifies, at β=1 every fail certifies health. Throws `RangeError`.
 */
export declare function assertFalsePassDomain(beta: number, knob?: string): void;
/**
 * The Bayesian knobs a host may set, validated as one batch at the
 * construction boundary (engine options / plugin config). Every β runs
 * through `assertFalsePassDomain`; `certifyTarget` gets the same OPEN (0,1)
 * domain for the symmetric reason — target 0 certifies anything (every H2/
 * H-03 threshold collapses to a tautology), target 1 certifies nothing, and
 * both are configuration errors, not policy choices, because neither can
 * ever produce a meaningful verdict. Callers that construct the engine or
 * parse its config should call this once with whatever knobs they received;
 * `computePriors` independently gates its own `syntheticFalsePass` argument,
 * so the pure core stays defended even when called directly.
 *
 * Note for hosts tightening β: the certify threshold interacts with it. At
 * the default β=0.5/α=0.05/cold-π=0.9 (the s=0.5 tier above), a target at or
 * below ≈0.9448 lets a SINGLE forged green cross the line — tightening the
 * target without considering the tier is how a host re-opens what H-03
 * closed. (See the W6-F3 table at `DRIFTED_FALSE_PASS_DEFAULT`.)
 */
export interface BayesKnobs {
    readonly certifyTarget?: number;
    readonly syntheticFalsePass?: number;
    readonly driftedFalsePass?: number;
}
/** Validate a partial knob set; throws `RangeError` naming the offender. */
export declare function validateBayesKnobs(knobs: BayesKnobs): void;
/** Empirical parameters of one check, learned from the evidence log. */
export interface CheckStats {
    /** Evidence records for this check. */
    readonly runs: number;
    /** Records whose status was `pass`. */
    readonly passes: number;
    /**
     * Adjacent *decisive* observations that disagreed (pass↔fail). A flip is a
     * flakiness signal: `error`/`timeout`/`skipped` are "no answer", not a
     * different answer, so they are skipped when pairing — `pass → error` must
     * not make a healthy check look flaky.
     */
    readonly flips: number;
    /** Lower median of the observed durations; defined whenever `runs > 0`. */
    readonly medianDurationMs: number | undefined;
}
/**
 * Aggregate the full evidence log into per-check statistics.
 *
 * Records are consumed in the order given (log order — the caller passes
 * `store.all()`); within a check, adjacency for flip counting follows that
 * order, so "same batch, several records" behaves as the log sequenced them.
 */
export declare function summarizeHistory(records: readonly Evidence[]): Map<string, CheckStats>;
/** The Bayesian model of one candidate check, before this session's runs. */
export interface CheckPrior {
    readonly checkId: string;
    /** π ∈ (0,1): P(the check's assertion holds after this change set). */
    readonly priorHealthy: number;
    /** α: P(observed fail | healthy) — the false-fail (flake) rate. */
    readonly falseFail: number;
    /**
     * β: P(observed pass | broken) — fixed 0.02, unlearnable (assumption 1);
     * 0.15 for synthetic checks (assumption 5), whose author is a party to the
     * claim under test.
     */
    readonly falsePass: number;
    /** s ∈ [0,1]: how strongly this change set acts on this check. */
    readonly impact: number;
    /** Expected wall-clock cost; historical lower-median duration, else fallback. */
    readonly expectedCostMs: number;
}
/** Everything `computePriors` needs; the candidate pool's soundness is the caller's (closed) problem. */
export interface PriorInput {
    /** Affected candidate pool (upstream closure already vetted these). */
    readonly specs: readonly CheckSpec[];
    /** Files changed this session, workspace-relative. */
    readonly changed: readonly RelPath[];
    /**
     * Reverse-dependency graph; `undefined` (or absent) degrades impact to path
     * matching alone. Optional-tolerant because the engine legitimately reaches
     * this type through partial assembly, where the key may not be set yet.
     */
    readonly graph?: DependencyGraph | undefined;
    /** Learned statistics keyed by checkId (typically `summarizeHistory(store.all())`). */
    readonly history: Map<string, CheckStats>;
    /** Cost assumed for checks with no history. */
    readonly fallbackCostMs: number;
    /**
     * ο: β (falsePass) for checks with `source === 'synthetic'` — tests the
     * agent wrote for its own claim. Default 0.15; see the use site in
     * `computePriors` for why this β is (and must be) a different number from
     * `BAYES_CONSTANTS.falsePass`. Overridable per call so a host with actual
     * ground truth about synthetic-check quality can price its own experience —
     * the fixed constants stay unlearned by policy, this one is a knob because
     * its value is an admitted guess, not a law.
     */
    readonly syntheticFalsePass?: number;
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
export declare function computePriors(input: PriorInput): Map<string, CheckPrior>;
/**
 * P(healthy | observed) by Bayes on the binary channel:
 *
 *     P(h|obs) = π·P(obs|h) / [π·P(obs|h) + (1−π)·P(obs|broken)]
 *
 * with P(pass|h) = 1−α, P(pass|broken) = β, P(fail|h) = α, P(fail|broken) = 1−β.
 * All four terms are non-negative over the parameter domain — every knob is
 * domain-gated at this entry for caller-constructed priors (β via
 * `assertFalsePassDomain`: open interval (0,1), non-finite refused; α and π
 * via the closed [0,1] checks of V7-L3), so the result is always in [0,1],
 * no degenerate zeros or sign reversals to guard. Plain floating point;
 * π ∈ [0.05, 0.999] (the computePriors clamp) keeps every numerator and
 * denominator comfortably away from underflow.
 */
export declare function posteriorHealthy(prior: CheckPrior, observed: 'pass' | 'fail'): number;
/** The claim "every check's assertion holds", as a product of per-check health factors. */
export interface ClaimModel {
    /**
     * Per-check health probability — posterior for checks already run this
     * session, prior for the rest. Assumption 2 (independence) lives here.
     */
    readonly factors: ReadonlyMap<string, number>;
}
/**
 * Π factors, in sorted-key order so the float product is reproducible.
 * The empty model is the vacuous claim, which holds with probability 1.
 */
export declare function claimProbability(model: ClaimModel): number;
/** One candidate next run, priced in the certainty it is expected to buy. */
export interface ScheduleStep {
    readonly checkId: string;
    /** Expected reduction of the claim's binary entropy (nats) from running this check once. */
    readonly voi: number;
    /** voi divided by max(1, expectedCostMs): certainty bought per millisecond. */
    readonly voiPerCost: number;
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
export declare function rankByInformationGain(priors: ReadonlyMap<string, CheckPrior>, model: ClaimModel): ScheduleStep[];
//# sourceMappingURL=bayes.d.ts.map