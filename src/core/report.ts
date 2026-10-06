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
// τ: types only — core/coverage.ts is a leaf of the import graph (it depends
// on nothing in core), so report can consume it without any cycle.
import type { CoverageGateResult, CoverageSummary } from './coverage.ts'

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
 * - `synthetic`: every decisive record this run came from conjured tests (π)
 *   — checks the claim's own author wrote, on request, after the fact. The
 *   number is a real measurement, but each factor was priced with the raised
 *   synthetic β (`syntheticFalsePass`), because the test's author is the
 *   claim's interested party.
 *
 * Priority order, pinned (π): a basis is chosen by the *strongest* regime
 * present, and the chain is
 *
 *     jury-only > attested > synthetic > certified-subset > full-coverage > degraded
 *
 * `jury-only` and `attested` outrank `synthetic` because a B/C witness
 * changes what the number *is* (testimony fused into it), not merely how
 * much a factor was discounted; `synthetic` outranks the plain machine bases
 * because a reader must know the only checks that spoke were authored by the
 * claimant — "full coverage" would be technically true and materially
 * misleading. The grade itself never branches on `synthetic` (decideGrade is
 * untouched): the β lift already did the pricing inside the factors.
 */
export type ConfidenceBasis = 'full-coverage' | 'certified-subset' | 'degraded' | 'jury-only' | 'attested' | 'synthetic'

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
  /**
   * τ: the coverage summary this report was judged against (attached by
   * `applyCoverageGate`). `basis: 'none'` says no check produced coverage
   * data; `uncovered` lists the changed source files no evidence run ever
   * executed — the τ analog of `unverified`, which lists the checks that
   * never produced a verdict. One is about the checks, the other about the
   * change itself.
   */
  readonly coverage?: {
    readonly basis: 'v8' | 'none'
    readonly uncovered: readonly string[]
  }
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
  /**
   * Checks this verification actually dispatched (records exist for them).
   *
   * H2: this field is the prior-only-certification guard's material — only a
   * decisive record for a check *this run dispatched* counts as an
   * observation, so a factors map that is all priors (zero dispatches, or
   * every dispatch landing timeout/error/skipped) can never certify, no
   * matter how green the history behind those priors is.
   */
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
   * H5②: checkIds the baseline anchored but discovery can no longer find.
   * A vanished definition is a hole in the pool, not a smaller, greener
   * report — it must surface and block `proven` until the baseline is
   * rebuilt against the edited pool.
   */
  readonly vanished?: readonly string[]
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

  // H5②: reconciliation against the baseline's anchored check set. The ids
  // below have no spec, so they can never be attributed, run, or counted as
  // unverified — without this line, deleting a check's definition would
  // simply shrink the report and keep it green.
  const vanished = [...(input.vanished ?? [])].sort()

  // H2: how many decisive observations THIS run actually produced — counted
  // over the intersection of `runCheckIds` (the checks this verification
  // dispatched) and the AFFECTED set (W6-F5: the checks the claim is about),
  // so a decisive record from anywhere else — another run's log, a caller's
  // stray input, or a green check the change set never touched — cannot
  // stand in for this run's own work on the claim. Zero means every affected
  // factor is a prior: nothing the claim rests on was measured, so nothing
  // was certified.
  const runIds = input.confidence?.runCheckIds
  const observedDecisive = input.records
    .filter(r => isDecisiveStatus(r.status)
      && affectedIds.has(r.checkId)
      && (runIds === undefined || runIds.has(r.checkId)))
    .length

  const grade = decideGrade({
    hasBaseline: input.baseline !== undefined,
    changed: input.changed,
    affectedCount: affectedIds.size,
    unverifiedCount: unverified.length,
    discoveredCount: input.specs.length,
    records: input.records,
    attributed,
    requireFullCoverage: input.requireFullCoverage ?? true,
    observedDecisive,
    vanishedCount: vanished.length,
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
  let confidenceBasis = input.confidence !== undefined && confidence !== undefined
    ? basisFor(confidence, input.confidence.target, unverified, new Set(input.confidence.skippedByPlan.map(s => s.checkId)), observedDecisive)
    : undefined
  // π: conjured-test-only coverage renames the regime. When every decisive
  // record this run addressed a synthetic-source spec (and at least one
  // exists), "full-coverage"/"certified-subset" would be technically true and
  // materially misleading — the only checks that spoke were authored by the
  // claim's interested party, and the reader must see that in the basis. The
  // factors themselves already paid the synthetic β, so the grade never
  // branches here; and because `jury-only`/`attested` are never produced by
  // this function (they come from the jury assembler and the engine's κ
  // fusion, which run after and overwrite), the pinned priority order
  // jury-only > attested > synthetic > machine bases holds by construction.
  if (confidenceBasis !== undefined && onlySyntheticDecisive(input.records, input.specs, runIds)) {
    confidenceBasis = 'synthetic'
  }

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
    vanished,
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

// ---------------------------------------------------------------------------
// τ: coverage-aware proof
// ---------------------------------------------------------------------------

/**
 * Apply the τ gate to a graded report: demote `proven` to `unproven` when the
 * gate blocked, and attach the coverage summary either way.
 *
 * The semantic line this function draws — **unproven vs stale**:
 *
 * - `stale` is a *process* verdict: the verification did not finish. Checks
 *   were selected but produced no decisive outcome (skipped, timed out,
 *   never dispatched), so the reader's move is "re-run and complete the
 *   verification". Nothing is known yet.
 * - `unproven` (the τ demotion) is an *evidence* verdict: the process
 *   completed, everything that ran was green — and the green evidence never
 *   executed the changed code. There is nothing to wait for and nothing to
 *   re-run to fix it with the current check set; the claim simply has no
 *   supporting evidence for the thing that changed. The reader's move is
 *   "add/extend a check that exercises the change", not "wait".
 *
 * `regressed` and `stale` are never overwritten by this gate: `regressed` is
 * a strictly worse verdict (a decisive failure must not be laundered into a
 * coverage complaint), and `stale` already blocks `proven` on its own. Only a
 * report that was about to claim `proven` gets demoted — τ's whole point is
 * that "ran + green" must additionally mean "and executed the change".
 *
 * The coverage summary (`basis` + `uncovered`) is attached unconditionally so
 * a reader of a passing report can also *see* the change was covered — the
 * same transparency `confidence`/`confidenceBasis` buy for the β layer.
 */
export function applyCoverageGate(
  report: GradedProofReport,
  gate: CoverageGateResult,
  coverage: CoverageSummary,
): GradedProofReport {
  const attached: GradedProofReport['coverage'] = {
    basis: coverage.basis,
    uncovered: [...coverage.changedUncovered],
  }
  if (gate.blocked && report.grade === 'proven') {
    return { ...report, grade: 'unproven', coverage: attached }
  }
  return { ...report, coverage: attached }
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
  /**
   * H2: decisive observations this run produced (decisive records over the
   * dispatched ∩ affected set — see `assembleProof`). The bayesian grade gate
   * refuses to certify without at least one: priors are what checks brought
   * to the table, not what this run measured.
   */
  observedDecisive: number
  /** H5②: baseline checks whose definitions vanished from discovery. */
  vanishedCount: number
}

/**
 * W6-F9 (H-04 family): one completeness door between a green run and
 * `proven`. `decideGrade` closes these doors in a pinned priority to pick
 * the grade; the engine's endorsement unlock (`endorsementUnlock`) must ask
 * the SAME questions or the two lists drift — H-04 fixed the last drift by
 * hand, this type is the structural fix: one enumeration, two consumers.
 */
export type EndorsementDoor =
  /** No baseline to compare against — nothing can be proven, only re-anchored. */
  | 'no-baseline'
  /** A check that passed at baseline now fails — broken work, never residual risk. */
  | 'regressed'
  /** A check with no baseline failed — indistinguishable from new breakage. */
  | 'new-failure'
  /** The workspace declares no checks, or the change set touches none of them. */
  | 'nothing-to-verify'
  /** H2: zero decisive observations this run — every factor is a prior. */
  | 'unobserved'
  /** Checks were selected but produced no decisive outcome (full-coverage regime). */
  | 'unfinished'
  /** H5②: a baseline check's definition vanished from discovery — a hole in the pool. */
  | 'vanished'
  /** β: the claim posterior sits below the certify target. */
  | 'below-target'

/** The facts every door is read from — primitive counts, so both consumers (report and engine) can state them. */
export interface EndorsementDoorInput {
  readonly hasBaseline: boolean
  readonly discoveredCount: number
  readonly affectedCount: number
  readonly regressions: number
  readonly newFailures: number
  readonly unverifiedCount: number
  readonly vanishedCount: number
  readonly observedDecisive: number
  /**
   * Present exactly when the caller wired a `ConfidenceInput`; the
   * `below-target` door only exists in the bayesian regime
   * (`requireFullCoverage: false`), and `unfinished` only in the
   * full-coverage regime — the two gates replace each other, they never
   * stack.
   */
  readonly confidence?: { value: number; target: number }
  readonly requireFullCoverage: boolean
}

/**
 * W6-F9: every OPEN door, in the canonical order above — the single
 * enumeration `decideGrade` reads and the engine's endorsement unlock
 * should read instead of re-deriving the list by hand. Empty means nothing
 * stands between this run and `proven` (the machine side; the engine adds
 * its own doors — unmet obligations, script drift, coverage blocks, a
 * tampered baseline — around this call).
 *
 * For the endorsement contract specifically: `'below-target'` is the ONE
 * door a human endorsement is allowed to accept (residual risk is what an
 * endorser signs for), so an unlock is "every door closed except
 * below-target" — plus the engine's own extras. Every other open door is
 * missing or broken work, which endorsement never pays for (H3).
 */
export function endorsementBlockers(input: EndorsementDoorInput): EndorsementDoor[] {
  const doors: EndorsementDoor[] = []
  if (!input.hasBaseline) doors.push('no-baseline')
  if (input.regressions > 0) doors.push('regressed')
  if (input.newFailures > 0) doors.push('new-failure')
  if (input.discoveredCount === 0 || input.affectedCount === 0) doors.push('nothing-to-verify')
  if (input.observedDecisive === 0) doors.push('unobserved')
  if (input.vanishedCount > 0) doors.push('vanished')
  if (input.unverifiedCount > 0 && input.requireFullCoverage) doors.push('unfinished')
  if (input.confidence !== undefined && input.confidence.value < input.confidence.target) {
    doors.push('below-target')
  }
  return doors
}

/** Statuses that actually answer the question — single source: `evidence.ts`. */

function decideGrade(input: GradeInput): ProofGrade {
  // W6-F9: the doors are enumerated ONCE (endorsementBlockers) and consumed
  // here with the pinned per-regime priority; the engine's endorsement
  // unlock reads the same enumeration, so a new door can never again exist
  // in one list and not the other.
  const doors = endorsementBlockers({
    hasBaseline: input.hasBaseline,
    discoveredCount: input.discoveredCount,
    affectedCount: input.affectedCount,
    regressions: input.attributed.filter(c => c.verdict === 'regression').length,
    newFailures: input.attributed.filter(c => c.verdict === 'new-failure').length,
    unverifiedCount: input.unverifiedCount,
    vanishedCount: input.vanishedCount,
    observedDecisive: input.observedDecisive,
    ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
    requireFullCoverage: input.requireFullCoverage,
  })

  if (doors.includes('no-baseline')) return 'no-baseline'
  if (doors.includes('regressed') || doors.includes('new-failure')) return 'regressed'
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
    // "unproven" — an empty product is vacuous certainty, not proof. This
    // outranks the unfinished doors on this branch: an empty claim is not an
    // unfinished verification.
    if (doors.includes('nothing-to-verify')) return 'unproven'
    // H2: prior-only certification guard. Zero decisive observations means
    // the verification never finished — every factor is a prior, and however
    // high the prior product sits, it is history's number, not this run's
    // measurement. An unobserved run lands in the same bucket as any other
    // unfinished verification: stale. H5② joins it: a vanished definition is
    // a hole in the pool, and a sub-target posterior is simply not
    // certified.
    if (doors.includes('unobserved') || doors.includes('vanished') || doors.includes('below-target')) {
      return 'stale'
    }
    return 'proven'
  }
  // Legacy full-coverage path: unfinished work and vanished definitions are
  // 'stale' (missing work), and only THEN does the nothing-to-verify honesty
  // apply — the reverse of the bayesian branch's priority, pinned by the
  // pre-β grades.
  if (doors.includes('unfinished') || doors.includes('vanished')) return 'stale'
  if (doors.includes('nothing-to-verify')) return 'unproven'
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
 * π: whether every decisive record this run addressed a synthetic-source
 * spec (with at least one decisive record at all). Scoped exactly like
 * `observedDecisive` (W6-F7): when the caller wired `runCheckIds`, only the
 * checks THIS run dispatched decide the basis — a log carrying an old
 * synthetic-green history next to this run's organic observations must not
 * have its basis renamed by records the run never produced. Records whose
 * checkId no spec claims count as non-synthetic — an unknown speaker is
 * never evidence FOR the interested-party discount.
 */
function onlySyntheticDecisive(
  records: readonly Evidence[],
  specs: readonly CheckSpec[],
  runIds: ReadonlySet<string> | undefined,
): boolean {
  const decisive = records.filter(r =>
    isDecisiveStatus(r.status) && (runIds === undefined || runIds.has(r.checkId)))
  if (decisive.length === 0) return false
  const synthetic = new Set(specs.filter(s => s.source === 'synthetic').map(s => s.id))
  return decisive.every(r => synthetic.has(r.checkId))
}

/**
 * Which regime earned the number: a planned skip-set whose claim crossed the
 * target is a certified subset; a fully decisive run is full coverage (still
 * below 1 — flake residual); anything else — unplanned gaps, or stops below
 * target — is degraded.
 *
 * H2: a certified subset is a subset that was *certified* — at least one
 * decisive observation landed this run. Priors alone crossing the target (a
 * mature history behind a run that never observed anything) is the degraded
 * regime wearing a certified label; the number may still display, the basis
 * may not claim certification it did not earn. (The grade agrees by
 * construction: `decideGrade` returns `stale` on the same zero-observation
 * fact, so the two statements can never contradict each other again.)
 */
function basisFor(
  confidence: number,
  target: number,
  unverified: readonly string[],
  plannedSkips: ReadonlySet<string>,
  observedDecisive: number,
): ConfidenceBasis {
  if (observedDecisive > 0
    && plannedSkips.size > 0
    && confidence >= target
    && unverified.every(id => plannedSkips.has(id))) {
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
