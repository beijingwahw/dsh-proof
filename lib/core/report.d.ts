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
import type { Baseline, Evidence, ProofReport, WorkspaceSnapshot } from './evidence.ts';
import type { CheckSpec, Clock } from './ports.ts';
import type { RelPath, DependencyGraph } from './impact.ts';
import { type AttributedCheck } from './regression.ts';
import type { ChangeProvenance } from './changeset.ts';
import type { ClaimContract, ObligationResult } from './contract.ts';
import type { CoverageGateResult, CoverageSummary } from './coverage.ts';
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
export type ConfidenceBasis = 'full-coverage' | 'certified-subset' | 'degraded' | 'jury-only' | 'attested' | 'synthetic';
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
    readonly confidence?: number;
    /** How `confidence` was earned; present exactly when `confidence` is. */
    readonly confidenceBasis?: ConfidenceBasis;
    /**
     * τ: the coverage summary this report was judged against (attached by
     * `applyCoverageGate`). `basis: 'none'` says no check produced coverage
     * data; `uncovered` lists the changed source files no evidence run ever
     * executed — the τ analog of `unverified`, which lists the checks that
     * never produced a verdict. One is about the checks, the other about the
     * change itself.
     */
    readonly coverage?: {
        readonly basis: 'v8' | 'none';
        readonly uncovered: readonly string[];
    };
};
/** Graded-trust inputs handed to `assembleProof` by a bayesian-aware engine. */
export interface ConfidenceInput {
    /** The certification threshold — `certifyTarget` in the engine/config. */
    readonly target: number;
    /**
     * Per-check health probabilities over the affected set: a posterior for
     * every check observed to a decisive outcome this run, the prior for
     * everything still undecided (never run, timed out, skipped...).
     */
    readonly factors: ReadonlyMap<string, number>;
    /**
     * Checks this verification actually dispatched (records exist for them).
     *
     * H2: this field is the prior-only-certification guard's material — only a
     * decisive record for a check *this run dispatched* counts as an
     * observation, so a factors map that is all priors (zero dispatches, or
     * every dispatch landing timeout/error/skipped) can never certify, no
     * matter how green the history behind those priors is.
     */
    readonly runCheckIds: ReadonlySet<string>;
    /** Checks the wave plan deliberately never dispatched, with their priors. */
    readonly skippedByPlan: ReadonlyArray<{
        checkId: string;
        priorHealthy: number;
    }>;
}
export interface AssembleInput {
    readonly specs: readonly CheckSpec[];
    readonly baseline?: Baseline | undefined;
    readonly records: readonly Evidence[];
    readonly changed: readonly RelPath[];
    readonly graph?: DependencyGraph;
    readonly workspace: WorkspaceSnapshot;
    readonly clock: Clock;
    /** Provenance per changed file: agent tool stream vs external edit (v0.3). */
    readonly provenance?: ReadonlyMap<RelPath, ChangeProvenance>;
    /** When true, an incremental run must cover every affected check to be `proven`. */
    readonly requireFullCoverage?: boolean;
    /** When true, impact analysis is bypassed and every check counts as affected. */
    readonly forceAll?: boolean;
    /**
     * H5②: checkIds the baseline anchored but discovery can no longer find.
     * A vanished definition is a hole in the pool, not a smaller, greener
     * report — it must surface and block `proven` until the baseline is
     * rebuilt against the edited pool.
     */
    readonly vanished?: readonly string[];
    /**
     * Graded trust (β): when present (and `requireFullCoverage` is false), the
     * binary coverage gate is replaced by the certify target — confidence ≥
     * target is `proven`, below it `stale`.
     */
    readonly confidence?: ConfidenceInput;
}
export interface AssembleResult {
    /** Carries the graded-trust fields whenever `AssembleInput.confidence` was wired. */
    readonly report: GradedProofReport;
    readonly checks: readonly AttributedCheck[];
}
export declare function assembleProof(input: AssembleInput): AssembleResult;
/** Build the baseline view over a full run. */
export declare function assembleBaseline(specs: readonly CheckSpec[], records: readonly Evidence[], workspace: WorkspaceSnapshot, clock: Clock): Baseline;
/** Inputs for the docs-only jury report (ζ). */
export interface JuryReportInput {
    /** The claim being judged — the report carries its identity implicitly. */
    readonly contract: ClaimContract;
    /** What the jury path demands; the report's grade is exactly "all met". */
    readonly obligations: readonly ObligationResult[];
    /** The capped self-attestation number (`juryCappedConfidence`). */
    readonly confidence: number;
    readonly workspace: WorkspaceSnapshot;
    readonly clock: Clock;
}
/**
 * The report a docs-only claim earns (ζ): no objective check was run, so there
 * is nothing to attribute, nothing discovered, nothing unverified — the grade
 * is exactly "did every jury obligation hold", and the confidence is the
 * capped self-attestation, never a measurement. `root` commits to the empty
 * evidence set (`merkleRoot([])`), which is itself the honest statement: this
 * verdict rests on the chain's `claim/jury` marker, not on check records.
 */
export declare function assembleJuryReport(input: JuryReportInput): GradedProofReport;
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
export declare function applyCoverageGate(report: GradedProofReport, gate: CoverageGateResult, coverage: CoverageSummary): GradedProofReport;
/**
 * W6-F9 (H-04 family): one completeness door between a green run and
 * `proven`. `decideGrade` closes these doors in a pinned priority to pick
 * the grade; the engine's endorsement unlock (`endorsementUnlock`) must ask
 * the SAME questions or the two lists drift — H-04 fixed the last drift by
 * hand, this type is the structural fix: one enumeration, two consumers.
 */
export type EndorsementDoor = 
/** No baseline to compare against — nothing can be proven, only re-anchored. */
'no-baseline'
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
 | 'below-target';
/** The facts every door is read from — primitive counts, so both consumers (report and engine) can state them. */
export interface EndorsementDoorInput {
    readonly hasBaseline: boolean;
    readonly discoveredCount: number;
    readonly affectedCount: number;
    readonly regressions: number;
    readonly newFailures: number;
    readonly unverifiedCount: number;
    readonly vanishedCount: number;
    readonly observedDecisive: number;
    /**
     * Present exactly when the caller wired a `ConfidenceInput`; the
     * `below-target` door only exists in the bayesian regime
     * (`requireFullCoverage: false`), and `unfinished` only in the
     * full-coverage regime — the two gates replace each other, they never
     * stack.
     */
    readonly confidence?: {
        value: number;
        target: number;
    };
    readonly requireFullCoverage: boolean;
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
 *
 * V7-M5 (consumption contract, spelled for the engine): this module exports
 * the door enumeration, the door-input shape and this function precisely so
 * the engine can consume them as-is —
 *
 *     const doors = endorsementBlockers({
 *       hasBaseline, discoveredCount, affectedCount,
 *       regressions, newFailures, unverifiedCount, vanishedCount,
 *       observedDecisive,
 *       ...(confidence !== undefined ? { confidence } : {}),
 *       requireFullCoverage,
 *     })
 *     const unlock = endorsed
 *       && doors.every(d => d === 'below-target')
 *       && <engine-only doors: unmet obligations, coverageBlocked,
 *                       scriptDrifted, auditFailed>
 *
 * Every field is a primitive count the engine already states when it calls
 * `assembleProof` (the same numbers `decideGrade` reads). TWO deliberate
 * engine-side strictness notes, so the wiring does not silently lose them:
 * (1) the engine's historic `unverified.length === 0` check is UNconditional
 * — stricter than the `unfinished` door, which only opens under
 * `requireFullCoverage` — and it subsumes `unobserved` (zero decisive
 * observations with zero unverified affected checks is impossible), so the
 * engine keeps it as its own door rather than passing `requireFullCoverage:
 * false` here; (2) `graded.grade === 'stale'` (unlock only lifts residual
 * risk, never a worse verdict) is likewise engine-side. A new door added to
 * THIS enumeration is closed for both consumers by the `every` predicate;
 * a new engine door is added next to it, visible in the same expression.
 */
export declare function endorsementBlockers(input: EndorsementDoorInput): EndorsementDoor[];
//# sourceMappingURL=report.d.ts.map