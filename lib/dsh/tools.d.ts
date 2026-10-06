/**
 * The nine model-facing tools.
 *
 * Contract discipline (DSH's hard rules, applied):
 *  - `execute` returns exactly one canonical JSON value; all human prose lives
 *    in `output.render`.
 *  - `presentCall` / `presentResult` / `presentationMeta` are pure projections
 *    of `args` and the canonical value, so a session-log replay reproduces the
 *    identical card. No I/O, no clock, no session reads.
 *
 * @module dsh-proof/dsh/tools
 */
import type { ToolDefinition, ToolResult, ToolCallView, ToolResultView } from '../vendor/dsh-tools.ts';
import type { ProofEngine } from '../engine.ts';
import type { AuditReport, CheckStatus, ProofGrade } from '../core/evidence.ts';
import type { ConfidenceBasis, GradedProofReport } from '../core/report.ts';
import type { ClaimKind, ObligationResult } from '../core/contract.ts';
export interface StatusValue {
    hasBaseline: boolean;
    baselineCreatedAt: string | null;
    baselineRoot: string | null;
    discovered: number;
    checks: {
        id: string;
        label: string;
        kind: string;
        lastStatus: string | null;
        recordedAt: string | null;
    }[];
    evidenceRecords: number;
    evidenceLogIntact: boolean;
    /** Trust telemetry from the hash chain + signed checkpoints (v0.2). */
    chainMode: 'signed' | 'unsigned' | 'legacy';
    checkpoints: number;
    chainIntact: boolean;
    tailRecords: number;
    rewindDetected: boolean;
    baselineTampered: boolean;
    /**
     * Present only when > 0 (v0.7): checkpoints carrying a signature this host
     * cannot adjudicate — key lost or foreign machine. A missing capability is
     * not an accusation, so it never flips `chainIntact`; it only rides along
     * when non-zero to keep the normal-path canonical value byte-stable.
     */
    unverifiableCheckpoints?: number;
    /** Present only when true (v0.7): the anchor failed its own signature check. */
    anchorForged?: boolean;
    /**
     * Present only when true (v0.17, M19d): the log's content at the anchor's
     * remembered checkpoint disagrees with what was anchored — records behind
     * the anchor were rewritten. The audit already fails on it (unlike a mere
     * unverifiable checkpoint); this field carries that verdict into the
     * structured output so `chainIntact` and the render agree.
     */
    anchorMismatch?: true;
    dirtyFiles: number;
    summary: string;
}
export interface BaselineValue {
    ok: boolean;
    baselineId: string | null;
    root: string | null;
    ran: number;
    passing: number;
    failing: number;
    skipped: number;
    durationMs: number;
    failingLabels: string[];
    summary: string;
    /**
     * Present only when the run aborted (v0.7, engine E1): the engine refused to
     * anchor a batch that did not observe every check, so no baseline file was
     * written — the next verify will honestly report `no-baseline`.
     */
    aborted?: true;
}
export interface VerifyValue {
    grade: ProofGrade;
    root: string;
    changed: string[];
    attributionMethod: string;
    externalChanged: string[];
    impactPrecision: string;
    affectedChecks: number;
    untouchedChecks: number;
    /**
     * Present only when the engine flagged degradation (v0.7, engine E3): git
     * facts were unavailable, so impact analysis was skipped and the full check
     * set was forced. Surfaced so "we ran everything because we couldn't tell
     * what moved" stays loud instead of reading like a deliberate `all: true`.
     */
    degraded?: true;
    /**
     * Posterior probability that every affected check is healthy (γ): the "p" in
     * `proven (p≈0.97)`, pre-rounded to two decimals for display. Present exactly
     * when the report carried graded trust; the legacy binary path omits every
     * field below so its canonical value stays byte-stable.
     */
    confidence?: number;
    /** How `confidence` was earned; rides with it, never alone. */
    confidenceBasis?: ConfidenceBasis;
    /** Checks the wave plan never dispatched, resting on their priors (>0 only). */
    certifiedSkips?: number;
    /** Why the wave plan ended before every affected check ran; only when it did. */
    stoppedEarly?: 'certified' | 'failed' | 'budget';
    /** Waves the bayesian plan actually dispatched; present only with a schedule. */
    waves?: number;
    /**
     * υ: what the execution-coverage dimension said about the change set — not
     * what the checks' paths matched, what they actually EXECUTED. Present
     * exactly when coverage collection ran (modes observe/require, via the
     * outcome); absent in mode `off` and on pre-υ session logs, so the
     * no-coverage canonical value stays byte-identical.
     */
    coverage?: {
        /** `'v8'` — real profiles were read; `'none'` — no execution data this run. */
        basis: 'v8' | 'none';
        /** Changed files a decisively-passing check actually executed. */
        executedCount: number;
        /** Changed files no green check ever executed. */
        uncovered: readonly string[];
    };
    regressions: {
        label: string;
        suspects: string[];
        detail: string;
    }[];
    fixed: string[];
    preExisting: string[];
    unverified: string[];
    passing: number;
    failing: number;
    summary: string;
}
export interface ClaimValue {
    claim: string;
    grade: ProofGrade;
    proven: boolean;
    root: string;
    /**
     * The verification posterior (γ), transferred when the run carried one so a
     * claim card can speak in probabilities. Absent on the legacy binary path.
     */
    confidence?: number;
    /**
     * M4: how the claim's `confidence` was earned — the full six-value union,
     * because a plain verify over a conjured-test-only run reaches this card
     * with basis 'synthetic', and a probability without its regime would dress
     * testimony up as a machine measurement. Rides with `confidence`, never
     * alone.
     */
    confidenceBasis?: ConfidenceBasis;
    /**
     * ζ: the contract kind this claim was typed against. Present exactly when the
     * call carried a `kind` (the typed path); the legacy path omits every field
     * below so its canonical value stays byte-identical to pre-ζ session logs.
     */
    kind?: ClaimKind;
    /** ζ: per-obligation verdicts under the claim's contract, in engine order. */
    obligations?: ReadonlyArray<{
        id: string;
        met: boolean;
        detail: string;
    }>;
    /**
     * ζ: docs-only whose every obligation held — the verdict is jury evidence
     * (the author's self-attestation, structurally capped), never a measurement.
     */
    jury?: true;
    /** Checks that regressed against the baseline — blame, not credit. */
    regressions: VerifyValue['regressions'];
    blockers: string[];
    summary: string;
}
/**
 * λ: the Class B protocol, step 1 — the frozen deliberation prompt handed to
 * the juror. The canonical value carries the prompt verbatim because the
 * prompt is the evidence bundle's replay key: a third party re-runs exactly
 * these bytes against the declared model and compares outputs.
 */
export interface JuryRequestValue {
    claimId: string;
    rubricVersion: string;
    prompt: string;
    /** The one-line charge to the juror: deliberate, then submit via the tool. */
    instruction: string;
}
/** λ: the Class B protocol, step 2 — the verdict exactly as it landed on-chain. */
export interface JurySubmitValue {
    recorded: true;
    claimId: string;
    /** Deliberation generation: max existing gen for the claim + 1 (appeals supersede). */
    gen: number;
    verdict: 'uphold' | 'reject' | 'abstain';
    probability: number;
    /**
     * The pure Class B factor under the default trust policy — p^classB, full
     * precision (abstain carries 1). Recomputable by anyone from the record;
     * the engine's own fusion may weigh it differently, this number never lies
     * about which policy produced it.
     */
    factor: number;
    note: string;
}
/** λ: Class C — a named human's endorsement/rejection exactly as recorded. */
export interface EndorseValue {
    recorded: true;
    claimId: string;
    decision: 'endorse' | 'reject';
    approver: string;
    /** Exactly what the approver took responsibility for. */
    scope: {
        claim: string;
        evidenceRoot: string | null;
    };
    note: string;
}
/**
 * ρ: PTC synthesis, step 1 — the synthetic-verification request exactly as it
 * was committed to the chain. The canonical value carries the scaffold
 * template VERBATIM because the model writes from it: a digest alone cannot be
 * filled in, and the template's header is where the content-addressing warning
 * lives (an assertion deleted is a different scriptDigest, forever).
 */
export interface ConjureValue {
    claimId: string;
    /** Sandbox-relative script name the model must copy the template to. */
    entry: string;
    /** Paths the conjured test must exercise, as the request locked them. */
    paths: string[];
    /** Workspace-relative sandbox directory the entry lives in. */
    sandboxDir: string;
    /** The scaffold, byte for byte — the model's writing surface. */
    template: string;
    /** The standing charge: copy, fill, run via proof_conjure_run. */
    instruction: string;
}
/** ρ: PTC synthesis, step 2 — a script that ran and landed as evidence. */
export interface ConjureRunValue {
    recorded: true;
    checkId: string;
    status: CheckStatus;
    /** sha256 of the script as it existed at execution time — proves what ran. */
    scriptDigest: string;
    /** Screening findings for exactly that digest; empty = cleared to run. */
    screened: string[];
    sandbox: 'screened-subprocess' | 'ptc-runtime';
    /** Excerpt of the run's output (or the refusal reason when skipped). */
    outputHead: string;
    note: string;
}
/**
 * ρ: a script the capability screen refused — `recorded: false` is a
 * protocol-internal outcome, NOT a tool error: the model's next move is to
 * edit the script and call proof_conjure_run again, which an isError result
 * would only obscure.
 */
export interface ConjureRefusedValue {
    recorded: false;
    entry: string;
    screened: string[];
    reason: string;
}
/**
 * λ: `evidenceLogPath` is the physical evidence-log location, derived by the
 * plugin entry with the same rule ProofEngine applies to its own private copy
 * (the store exposes no marker read-back, and the engine exports neither the
 * path nor its derivation). The Class B/C tools read attestation markers off
 * the chain through the engine's own fs port with it. When absent (direct
 * construction), every read-backed guard degrades to refusal rather than
 * trusting an unverifiable submitter.
 */
export declare function createProofTools(engine: ProofEngine, touched?: () => readonly string[], evidenceLogPath?: string, 
/**
 * H9b: whether a shell-class tool ran this session
 * (`WorkspaceWatch.sessionShellUsed`), wired the same route as `touched` —
 * the plugin entry closes over its watch instance and hands both accessors
 * down. Present only when the host provides one; a bare construction keeps
 * the pre-H9 classification byte-for-byte.
 */
shellUsed?: () => boolean): ToolDefinition[];
/** Structural view of the engine facts `toStatusValue` reads; the real engine
 * types satisfy it, and tests can hand-pick the interesting corner. */
export interface StatusProjectInput {
    readonly specs: readonly {
        id: string;
        label: string;
        kind: string;
    }[];
    readonly baseline?: {
        readonly createdAt: string;
        readonly root: string;
        readonly checks: readonly unknown[];
    };
    readonly latest: {
        get(id: string): {
            status: string;
            recordedAt: string;
        } | undefined;
    };
    readonly audit: AuditReport;
    readonly snapshot: {
        readonly dirty: readonly string[];
    };
}
export declare function toStatusValue(input: StatusProjectInput): StatusValue;
export declare function toBaselineValue(baseline: {
    readonly baselineId: string;
    readonly root: string;
    readonly aborted?: true;
}, records: readonly {
    status: string;
    label: string;
    durationMs: number;
}[]): BaselineValue;
export declare function toVerifyValue(report: GradedProofReport, changed: readonly string[], checks: readonly {
    label: string;
    verdict: string;
    suspects: readonly string[];
    current?: {
        outputHead?: string;
    };
}[], selection?: {
    readonly untouched?: readonly unknown[];
    readonly precision?: string;
}, attribution?: {
    method: string;
    records: readonly {
        path: string;
        provenance: string;
    }[];
}, degraded?: true, schedule?: {
    readonly mode: 'bayesian';
    readonly waves: number;
    readonly stoppedEarly: 'certified' | 'failed' | 'budget' | null;
    readonly skippedByPlan: ReadonlyArray<{
        checkId: string;
        priorHealthy: number;
    }>;
}, 
/**
 * υ: the execution-coverage verdict on the change set, as the outcome
 * reported it (report.coverage carries the same basis/uncovered — the
 * outcome is the one that also holds executedCount). Absent in mode `off`.
 */
coverage?: {
    readonly basis: 'v8' | 'none';
    readonly uncovered: readonly string[];
    readonly executedCount: number;
}, 
/**
 * H5: check definitions whose script body changed since the baseline, as
 * the outcome reported them. Each was force-re-run and priced at the
 * synthetic false-pass tier; the summary appends one warning line so the
 * model cannot read a "proven" posterior as if the baseline's original
 * definitions had answered. Absent (and the summary line with it) when
 * nothing drifted, keeping the canonical value byte-stable.
 */
scriptDrift?: readonly string[], 
/**
 * H5②: baseline checks whose definitions vanished from discovery. The
 * summary appends one warning line so a shrunken pool cannot read as a
 * green report; absent when nothing vanished (canonical value stable).
 */
vanished?: readonly string[]): VerifyValue;
export declare function toClaimValue(claim: string, 
/** Graded since γ; υ reads the coverage summary the gate attached to it. */
report: GradedProofReport, verified: VerifyValue, 
/** ζ: the engine's contract verdict; present only on the typed (kind) path. */
contract?: {
    readonly kind: ClaimKind;
    readonly obligations: readonly ObligationResult[];
}): ClaimValue;
export type { ToolResult, ToolResultView, ToolCallView };
//# sourceMappingURL=tools.d.ts.map