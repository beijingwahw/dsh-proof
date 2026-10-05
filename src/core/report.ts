/**
 * Proof assembly: the verdict the model is allowed to state, and the root that
 * makes it recomputable by anyone holding the evidence log.
 *
 * Grades are deliberately pessimistic. "Proven" means: a baseline exists, every
 * check the change set touches was re-run, and none of them regressed. Anything
 * less is `unproven` — the model may still say the task is done, but the plugin
 * will not co-sign it.
 *
 * @module dsh-proof/core/report
 */

import type {
  Baseline, CheckReport, Evidence, ProofGrade, ProofReport, WorkspaceSnapshot,
} from './evidence.ts'
import { buildBaseline, isDecisiveStatus } from './evidence.ts'
import { merkleRoot } from './hash.ts'
import type { CheckSpec, Clock } from './ports.ts'
import type { RelPath, DependencyGraph } from './impact.ts'
import { forcedSelection, selectAffectedChecks } from './impact.ts'
import { attributeChecks, type AttributedCheck } from './regression.ts'
import type { ChangeProvenance } from './changeset.ts'
// ζ: the jury path consumes the typed claim contract straight from its module —
// the core barrel is not this batch's to edit, and a direct import keeps the
// dependency on `core/contract.ts` (ε) explicit.
import type { ClaimContract, ObligationResult } from './contract.ts'

/**
 * How the confidence number on a report was earned (β).
 *
 * - `full-coverage`: every affected check was executed to a decisive outcome.
 *   The posterior is still below 1 — the flake residual in every factor is
 *   honest, not a bug.
 * - `certified-subset`: the bayesian scheduler stopped early because the claim
 *   posterior crossed the target; the checks not run are listed as planned
 *   skips carrying their priors.
 * - `degraded`: the run ended below target without certifying — budget
 *   exhausted, aborted, or a decisive failure stopped the plan.
 * - `jury-only`: no objective check speaks for the claim — a docs-only change
 *   graded by jury review (the author's self-attestation, capped by
 *   `juryConfidenceCap`). The number is a ceiling, not a measurement (ζ).
 * - `attested`: machine evidence fused with on-chain Class B/C witnesses (κ)
 *   — a machine posterior (or, with no machine record, the neutral 1)
 *   discounted by every active attestation factor. Still a measurement at
 *   heart, but no longer a purely machine-made number.
 */
export type ConfidenceBasis = 'full-coverage' | 'certified-subset' | 'degraded' | 'jury-only' | 'attested'

/**
 * `ProofReport` grown by the graded-trust fields (β). Declared here as an
 * extension because `ProofReport` itself lives in `evidence.ts`, which is not
 * this batch's file to edit; every plain `ProofReport` stays assignable, so
 * legacy consumers see nothing change.
 */
export type GradedProofReport = ProofReport & {
  /**
   * Posterior probability that every affected check is healthy — the "p" in
   * `proven (p≈0.97)`. The full value is stored; rendering rounds to two
   * decimals for display only.
   */
  readonly confidence?: number
  /** How `confidence` was earned; present exactly when `confidence` is. */
  readonly confidenceBasis?: ConfidenceBasis
}

/** Graded-trust inputs handed to `assembleProof` by a bayesian-aware engine. */
export interface ConfidenceInput {
  /** The certification threshold — `certifyTarget` in the engine/config. */
  readonly target: number
  /**
   * Per-check health probabilities over the affected set: a posterior for
   * every check observed to a decisive outcome this run, the prior for
   * everything still undecided (never run, timed out, skipped...).
   */
  readonly factors: ReadonlyMap<string, number>
  /** Checks this verification actually dispatched (records exist for them). */
  readonly runCheckIds: ReadonlySet<string>
  /** Checks the wave plan deliberately never dispatched, with their priors. */
  readonly skippedByPlan: ReadonlyArray<{ checkId: string; priorHealthy: number }>
}

export interface AssembleInput {
  readonly specs: readonly CheckSpec[]
  readonly baseline?: Baseline | undefined
  readonly records: readonly Evidence[]
  readonly changed: readonly RelPath[]
  readonly graph?: DependencyGraph
  readonly workspace: WorkspaceSnapshot
  readonly clock: Clock
  /** Provenance per changed file: agent tool stream vs external edit (v0.3). */
  readonly provenance?: ReadonlyMap<RelPath, ChangeProvenance>
  /** When true, an incremental run must cover every affected check to be `proven`. */
  readonly requireFullCoverage?: boolean
  /** When true, impact analysis is bypassed and every check counts as affected. */
  readonly forceAll?: boolean
  /**
   * Graded trust (β): when present (and `requireFullCoverage` is false), the
   * binary coverage gate is replaced by the certify target — confidence ≥
   * target is `proven`, below it `stale`.
   */
  readonly confidence?: ConfidenceInput
}

export interface AssembleResult {
  /** Carries the graded-trust fields whenever `AssembleInput.confidence` was wired. */
  readonly report: GradedProofReport
  readonly checks: readonly AttributedCheck[]
}

export function assembleProof(input: AssembleInput): AssembleResult {
  const baselineById = new Map((input.baseline?.checks ?? []).map(e => [e.checkId, e]))
  const currentById = new Map(input.records.map(e => [e.checkId, e]))

  const attributed = attributeChecks({
    checks: input.specs,
    baselineById,
    currentById,
    changed: input.changed,
    ...(input.graph !== undefined ? { graph: input.graph } : {}),
    ...(input.provenance !== undefined ? { provenance: input.provenance } : {}),
  })

  const selection = input.forceAll === true
    ? forcedSelection(input.specs, input.changed)
    : selectAffectedChecks(input.specs, input.changed, input.graph)
  const affectedIds = new Set(selection.affected.map(c => c.id))

  // Coverage: an affected check counts as verified only when this run produced
  // a decisive outcome for it. `skipped`, `aborted`, `timeout` and silence all
  // mean the same thing to a reader: no verdict, so no proof.
  const unverified = [...affectedIds].filter((id) => {
    const record = currentById.get(id)
    return !isDecisiveStatus(record?.status)
  }).sort()

  const grade = decideGrade({
    hasBaseline: input.baseline !== undefined,
    changed: input.changed,
    affectedCount: affectedIds.size,
    unverifiedCount: unverified.length,
    discoveredCount: input.specs.length,
    records: input.records,
    attributed,
    requireFullCoverage: input.requireFullCoverage ?? true,
    ...(input.confidence !== undefined
      ? { confidence: { value: productOf(input.confidence.factors), target: input.confidence.target } }
      : {}),
  })

  const summary = {
    passing: attributed.filter(c => isPassing(c)).length,
    failing: attributed.filter(c => isFailing(c.verdict)).length,
    regressions: attributed.filter(c => c.verdict === 'regression').length,
    fixed: attributed.filter(c => c.verdict === 'fixed').length,
    preExisting: attributed.filter(c => c.verdict === 'still-failing').length,
    newChecks: attributed.filter(c => c.verdict === 'new-check').length,
    indeterminate: attributed.filter(c => c.verdict === 'indeterminate').length,
  }

  // β graded trust: the claim posterior and how it was earned. Both fields
  // ride together or not at all, so a reader can never see a probability it
  // cannot place in a regime.
  const confidence = input.confidence !== undefined ? productOf(input.confidence.factors) : undefined
  const confidenceBasis = input.confidence !== undefined && confidence !== undefined
    ? basisFor(confidence, input.confidence.target, unverified, new Set(input.confidence.skippedByPlan.map(s => s.checkId)))
    : undefined

  const report: GradedProofReport = {
    grade,
    root: merkleRoot(input.records.map(r => r.evidenceId)),
    baselineRoot: input.baseline?.root ?? null,
    baselineCreatedAt: input.baseline?.createdAt ?? null,
    generatedAt: new Date(input.clock.now()).toISOString(),
    workspace: input.workspace,
    checks: attributed.map(toCheckReport),
    discovered: input.specs.length,
    unverified,
    summary,
    regressions: attributed
      .filter(c => c.verdict === 'regression' || c.verdict === 'new-failure')
      .map(c => `${c.label}: ${c.rationale}`),
    ...(confidence !== undefined ? { confidence } : {}),
    ...(confidenceBasis !== undefined ? { confidenceBasis } : {}),
  }

  return { report, checks: attributed }
}

/** Build the baseline view over a full run. */
export function assembleBaseline(
  specs: readonly CheckSpec[],
  records: readonly Evidence[],
  workspace: WorkspaceSnapshot,
  clock: Clock,
): Baseline {
  // `specs` is accepted purely for API symmetry with `assembleProof`; the
  // baselineId deliberately hashes only what the log can recompute later
  // (records + workspace), never the discovery-time spec list.
  void specs
  return buildBaseline(records, workspace, clock)
}

/** Inputs for the docs-only jury report (ζ). */
export interface JuryReportInput {
  /** The claim being judged — the report carries its identity implicitly. */
  readonly contract: ClaimContract
  /** What the jury path demands; the report's grade is exactly "all met". */
  readonly obligations: readonly ObligationResult[]
  /** The capped self-attestation number (`juryCappedConfidence`). */
  readonly confidence: number
  readonly workspace: WorkspaceSnapshot
  readonly clock: Clock
}

/**
 * The report a docs-only claim earns (ζ): no objective check was run, so there
 * is nothing to attribute, nothing discovered, nothing unverified — the grade
 * is exactly "did every jury obligation hold", and the confidence is the
 * capped self-attestation, never a measurement. `root` commits to the empty
 * evidence set (`merkleRoot([])`), which is itself the honest statement: this
 * verdict rests on the chain's `claim/jury` marker, not on check records.
 */
export function assembleJuryReport(input: JuryReportInput): GradedProofReport {
  const allMet = input.obligations.every(o => o.met)
  return {
    grade: allMet ? 'proven' : 'stale',
    root: merkleRoot([]),
    baselineRoot: null,
    baselineCreatedAt: null,
    generatedAt: new Date(input.clock.now()).toISOString(),
    workspace: input.workspace,
    checks: [],
    discovered: 0,
    unverified: [],
    summary: { passing: 0, failing: 0, regressions: 0, fixed: 0, preExisting: 0, newChecks: 0, indeterminate: 0 },
    regressions: [],
    confidence: input.confidence,
    confidenceBasis: 'jury-only',
  }
}

interface GradeInput {
  hasBaseline: boolean
  changed: readonly RelPath[]
  affectedCount: number
  unverifiedCount: number
  discoveredCount: number
  records: readonly Evidence[]
  attributed: readonly AttributedCheck[]
  requireFullCoverage: boolean
  /**
   * Graded trust (β): the claim posterior and its target. Present exactly when
   * the caller wired a `ConfidenceInput`; it only takes over the grade gate
   * when `requireFullCoverage` is false (the bayesian regime).
   */
  confidence?: { value: number; target: number }
}

/** Statuses that actually answer the question — single source: `evidence.ts`. */

function decideGrade(input: GradeInput): ProofGrade {
  const regressions = input.attributed.filter(c => c.verdict === 'regression').length
  const newFailures = input.attributed.filter(c => c.verdict === 'new-failure').length

  if (!input.hasBaseline) return 'no-baseline'
  if (regressions > 0 || newFailures > 0) return 'regressed'
  // β graded trust: under the bayesian scheduler coverage stops being binary.
  // The stale gate ("something ran without a verdict") is replaced by the
  // certify target — a claim is proven when its posterior crosses the target,
  // stale when it does not. Priority over the legacy gate is inherited: it
  // sits exactly where the coverage rule used to, after regressions (a dead
  // assertion is never "certified") and before the nothing-to-verify honesty
  // below. The legacy 'set'/forced path never passes `confidence` with
  // `requireFullCoverage: false`, so its grades are bit-for-bit unchanged.
  if (input.confidence !== undefined && !input.requireFullCoverage) {
    // Nothing objective speaks for the claim: the workspace declares no
    // checks, or the change set touches none of them. Honest answer stays
    // "unproven" — an empty product is vacuous certainty, not proof.
    if (input.discoveredCount === 0 || input.affectedCount === 0) return 'unproven'
    return input.confidence.value >= input.confidence.target ? 'proven' : 'stale'
  }
  if (input.unverifiedCount > 0 && input.requireFullCoverage) return 'stale'
  // Nothing objective speaks for the claim: the workspace declares no checks,
  // or the change set touches none of them. Honest answer is "unproven".
  if (input.discoveredCount === 0 || input.affectedCount === 0) return 'unproven'
  return 'proven'
}

/**
 * The claim posterior: the product of the per-check health factors, iterated
 * in sorted-key order so the float product is bit-identical to
 * `claimProbability` (core/bayes.ts) over the same factors — the number the
 * engine gates on and the number the report displays must never disagree in
 * the last ulp. The empty product is 1 by convention — guarded upstream by
 * the `affectedCount` honesty branch, which never lets a vacuous 1 stand as
 * proof.
 */
function productOf(factors: ReadonlyMap<string, number>): number {
  let product = 1
  for (const key of [...factors.keys()].sort()) {
    product *= factors.get(key) as number
  }
  return product
}

/**
 * Which regime earned the number: a planned skip-set whose claim crossed the
 * target is a certified subset; a fully decisive run is full coverage (still
 * below 1 — flake residual); anything else — unplanned gaps, or stops below
 * target — is degraded.
 */
function basisFor(
  confidence: number,
  target: number,
  unverified: readonly string[],
  plannedSkips: ReadonlySet<string>,
): ConfidenceBasis {
  if (plannedSkips.size > 0 && confidence >= target && unverified.every(id => plannedSkips.has(id))) {
    return 'certified-subset'
  }
  if (unverified.length === 0) return 'full-coverage'
  return 'degraded'
}

/**
 * Credit only goes to checks with a decisive pass on record. A `new-check`
 * that was never actually run must not dilute the passing number — it is
 * already accounted for separately by `summary.newChecks`.
 */
function isPassing(check: CheckReport): boolean {
  if (check.verdict === 'new-check') return check.current?.status === 'pass'
  return check.verdict === 'still-passing' || check.verdict === 'fixed'
}

/** Blame only attaches to decisive failures; `indeterminate` and `not-run` carry neither. */
function isFailing(verdict: CheckReport['verdict']): boolean {
  return verdict === 'regression' || verdict === 'still-failing' || verdict === 'new-failure'
}

function toCheckReport(check: AttributedCheck): CheckReport {
  return {
    checkId: check.checkId,
    label: check.label,
    kind: check.kind,
    verdict: check.verdict,
    ...(check.baseline !== undefined ? { baseline: check.baseline } : {}),
    ...(check.current !== undefined ? { current: check.current } : {}),
    attributedTo: check.attributedTo,
    ...(check.externalSuspects !== undefined ? { externalSuspects: check.externalSuspects } : {}),
  }
}
