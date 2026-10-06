/**
 * Regression attribution: turning "something is broken" into "this change
 * broke this check, and here is the file that owns it".
 *
 * A regression is charged to the current session only when the check passed at
 * baseline and fails now. Anything already red at baseline is pre-existing and
 * is reported as such — otherwise an agent "fixing" one thing inherits every
 * historical failure and learns to lie about the rest.
 *
 * @module dsh-proof/core/regression
 */
import type { CheckReport, Evidence, ProofReport } from './evidence.ts';
import type { CheckSpec } from './ports.ts';
import type { RelPath } from './impact.ts';
import type { DependencyGraph } from './impact.ts';
import type { ChangeProvenance } from './changeset.ts';
/** The minimum a report needs to decide who owns a red check. */
export interface AttributionInput {
    readonly checks: readonly CheckSpec[];
    readonly baselineById: ReadonlyMap<string, Evidence>;
    readonly currentById: ReadonlyMap<string, Evidence>;
    readonly changed: readonly RelPath[];
    readonly graph?: DependencyGraph;
    /**
     * Provenance of each changed file (agent tool stream vs external edit).
     * Absent for legacy callers — everything then counts as attributable.
     */
    readonly provenance?: ReadonlyMap<RelPath, ChangeProvenance>;
}
export interface AttributedCheck extends CheckReport {
    /** Candidate owner files, most specific first. Empty when unattributable. */
    readonly suspects: readonly RelPath[];
    /** Why this verdict was reached, in one line. */
    readonly rationale: string;
}
/**
 * Attribute every check in the batch. `attributedTo` is the changed-file subset
 * that lands inside the check's impact set; `suspects` additionally ranks those
 * files by how narrowly they map to this check.
 */
export declare function attributeChecks(input: AttributionInput): AttributedCheck[];
/**
 * Human-readable regression lines ready for `agent.inject()`. Short on purpose:
 * this is corrective context, not a report.
 */
export declare function regressionNarrative(checks: readonly AttributedCheck[]): string[];
/**
 * Plain-language summary of what is and is not proven. The certify-target
 * fallback for the display is the config module's own default (see the
 * import above). Callers that know the run's actual target pass it; the
 * plain `ProofReport` carries only the posterior, not the threshold it was
 * certified against.
 */
export declare function proofNarrative(report: ProofReport, certifyTarget?: number): string;
//# sourceMappingURL=regression.d.ts.map