/**
 * The verification runner: budget-aware, incremental, cancellable.
 *
 * Runs only the checks a change set made stale, in a deterministic order, with
 * bounded concurrency and a per-check cooperative timeout. Every outcome —
 * including a timeout or an abort — becomes evidence, because "we didn't run
 * it" is itself a fact the model must not paper over.
 *
 * @module dsh-proof/core/runner
 */
import type { CheckSpec, Clock, CommandPort, WorkspacePort } from './ports.ts';
import type { Evidence, WorkspaceSnapshot } from './evidence.ts';
import type { ExcerptOptions } from './excerpt.ts';
import type { NormalizeOptions } from './hash.ts';
/** How raw outcomes become evidence records: excerpt budget + canonical roots. */
export interface EvidenceShape {
    readonly excerpt?: ExcerptOptions;
    readonly canonical?: NormalizeOptions;
}
export interface RunnerOptions {
    readonly concurrency?: number;
    readonly signal?: AbortSignal;
    /** Wall-clock budget for the whole batch; unused checks are marked `skipped`. */
    readonly totalBudgetMs?: number;
    /** Snapshot the workspace once and reuse it for every record in the batch. */
    readonly workspace?: WorkspaceSnapshot;
    /** Called as each check settles, for streaming UIs. */
    readonly onEvidence?: (evidence: Evidence, index: number, total: number) => void;
    /**
     * υ: base directory for V8 execution-coverage collection, OWNED by the
     * engine: it prepares one fresh staging directory per run, passes it here,
     * and re-derives the same per-spec subdirectories when harvesting — the
     * runner never invents or persists a directory of its own (H-17: keep the
     * anti-forgery fencing with the collector). When set, every spec executes
     * with `NODE_V8_COVERAGE=<coverageDir>/<sanitised specId>` in its
     * environment — see `coverageSubdir` for why the id is hashed. Absent (the
     * default) injects nothing and the batch is byte-for-byte pre-υ.
     */
    readonly coverageDir?: string;
}
export interface BatchResult {
    readonly records: readonly Evidence[];
    readonly workspace: WorkspaceSnapshot;
    readonly ranIds: readonly string[];
    readonly skippedIds: readonly string[];
    readonly aborted: boolean;
    /**
     * M-08: set when a check that had already STARTED finished AFTER the
     * wall-clock budget elapsed. The budget is cooperative by contract — an
     * in-flight check is never hard-killed mid-run (its evidence is real, its
     * own timeoutMs is its only ceiling) — so an overrun is a fact the batch
     * must be able to name rather than silently absorb. Absent when the batch
     * fit its budget (or no budget was set); budget-exhaustion skipping is
     * reported separately through `skippedIds`.
     */
    readonly budgetExceeded?: true;
    readonly totalDurationMs: number;
}
export declare class VerificationRunner {
    private readonly commands;
    private readonly workspace;
    private readonly clock;
    private readonly excerpt;
    private readonly canonical;
    constructor(commands: CommandPort, workspace: WorkspacePort, clock: Clock, shape?: EvidenceShape);
    /** Run a batch of checks and turn every outcome into evidence. */
    run(specs: readonly CheckSpec[], options?: RunnerOptions): Promise<BatchResult>;
    /**
     * υ: filesystem-safe subdirectory for one spec's V8 coverage output.
     *
     * specIds embed their command (and may carry colons, hashes, spaces, even
     * whole argv strings), none of which are safe as a path segment on every
     * platform this runner executes on. `sha256(id).slice(0,16)` is: 16 hex
     * characters, collision-safe for any realistic check pool, and deterministic
     * — the engine collecting the output re-derives the exact same name from the
     * exact same spec.
     */
    private coverageSubdir;
    private runOne;
}
//# sourceMappingURL=runner.d.ts.map