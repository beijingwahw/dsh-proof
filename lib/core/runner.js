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
import { makeEvidence, snapshotWorkspace } from "./evidence.js";
import { sha256 } from "./hash.js";
export class VerificationRunner {
    commands;
    workspace;
    clock;
    excerpt;
    canonical;
    constructor(commands, workspace, clock, shape = {}) {
        this.commands = commands;
        this.workspace = workspace;
        this.clock = clock;
        this.excerpt = shape.excerpt ?? { budget: 2_000, strategy: 'head' };
        this.canonical = shape.canonical ?? {};
    }
    /** Run a batch of checks and turn every outcome into evidence. */
    async run(specs, options = {}) {
        const concurrency = Math.max(1, Math.min(options.concurrency ?? 2, 8));
        const started = this.clock.now();
        const snapshot = options.workspace ?? await snapshotWorkspace(this.workspace);
        const records = [];
        const skippedIds = [];
        const ranIds = [];
        let aborted = false;
        const queue = [...specs];
        const total = queue.length;
        let index = 0;
        let budgetExceeded = false;
        const worker = async () => {
            for (;;) {
                if (aborted || options.signal?.aborted) {
                    aborted = true;
                    return;
                }
                const spec = queue.shift();
                if (spec === undefined)
                    return;
                const budgetExhausted = options.totalBudgetMs !== undefined
                    && this.clock.now() - started >= options.totalBudgetMs;
                if (budgetExhausted) {
                    const skipped = makeEvidence(spec, {
                        status: 'skipped', exitCode: null, durationMs: 0,
                        output: `skipped: total verification budget of ${options.totalBudgetMs}ms exhausted`,
                    }, snapshot, this.clock, this.excerpt, this.canonical);
                    records.push(skipped);
                    skippedIds.push(spec.id);
                    options.onEvidence?.(skipped, index++, total);
                    continue;
                }
                const outcome = await this.runOne(spec, options.signal, snapshot, options.coverageDir);
                const evidence = makeEvidence(spec, outcome, snapshot, this.clock, this.excerpt, this.canonical);
                records.push(evidence);
                ranIds.push(spec.id);
                options.onEvidence?.(evidence, index++, total);
                // M-08: the budget only gates which checks START. A check admitted
                // just before exhaustion may still land past the line (its own
                // timeoutMs is its only ceiling) — record the overrun instead of
                // pretending the batch fit. No hard kill: the evidence it produced
                // is real, and the flag lets the narrative say so.
                if (options.totalBudgetMs !== undefined
                    && this.clock.now() - started > options.totalBudgetMs) {
                    budgetExceeded = true;
                }
            }
        };
        await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, total)) }, worker));
        // Workers settle in wall-clock order, but evidence identity is
        // order-sensitive downstream: `buildBaseline` hashes the checkId sequence,
        // so a concurrent batch must not leak completion order into baselineIds.
        // Re-project records (and ran ids) onto the spec order; the stable sort
        // keeps completion order for any id the spec list does not know.
        const specRank = new Map(specs.map((s, i) => [s.id, i]));
        const rankOf = (id) => {
            const rank = specRank.get(id);
            return rank === undefined ? total : rank;
        };
        const orderedRecords = [...records].sort((a, b) => rankOf(a.checkId) - rankOf(b.checkId));
        const orderedRanIds = [...ranIds].sort((a, b) => rankOf(a) - rankOf(b));
        const orderedSkippedIds = [...skippedIds].sort((a, b) => rankOf(a) - rankOf(b));
        return {
            records: orderedRecords,
            workspace: snapshot,
            ranIds: orderedRanIds,
            skippedIds: orderedSkippedIds,
            aborted: aborted || options.signal?.aborted === true,
            ...(budgetExceeded ? { budgetExceeded: true } : {}),
            totalDurationMs: this.clock.now() - started,
        };
    }
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
    coverageSubdir(coverageDir, specId) {
        return `${coverageDir.replace(/[\/]+$/, '')}/${sha256(specId).slice(0, 16)}`;
    }
    async runOne(spec, signal, _snapshot, coverageDir) {
        const started = this.clock.now();
        const controller = new AbortController();
        const onAbort = () => controller.abort();
        signal?.addEventListener('abort', onAbort, { once: true });
        // W15-L8(a): registration and check are one atomic step. An outer signal
        // that aborted BETWEEN the worker-loop's top-of-iteration check and this
        // registration never fires the listener (an aborted signal is silent to
        // new subscribers), the inner controller the port sees never aborts, and
        // the check ran to its own full timeout as ordinary evidence instead of
        // `aborted`. Re-checking synchronously here closes the window: the signal
        // either fires the listener or is already set — never neither.
        if (signal?.aborted)
            controller.abort();
        try {
            const result = await this.commands.run(spec.command, {
                // Monorepo checks execute inside the subpackage that declares them;
                // everything else runs at the workspace root, exactly as before.
                cwd: spec.cwd === undefined
                    ? this.workspace.root
                    : `${this.workspace.root.replace(/[\/]+$/, '')}/${spec.cwd.replace(/^\/+/, '')}`,
                timeoutMs: spec.timeoutMs,
                signal: controller.signal,
                maxOutputChars: 64_000,
                // υ: zero-instrumentation execution coverage. `NODE_V8_COVERAGE` is a
                // Node runtime flag delivered through the environment: any node process
                // that inherits it — the check itself, and any nested node the check
                // spawns through npm/.cmd shims or scripts, because the overlay merges
                // into the child's full inherited environment at the port — writes its
                // raw V8 coverage profile to <dir>/coverage-<pid>-<seq>.json on exit.
                // No mocks, no babel hooks, no import rewriting: the profile is
                // produced by the same V8 instance that executed the check. H-17
                // honesty note: that is provenance, NOT unforgeability — the checked
                // code can read this variable out of its own environment and write a
                // forged profile into the directory, so the actual anti-forgery
                // defences (filename shape, pid attribution, run fencing) must live
                // with the collector in the engine, not here. This runner's duty is
                // exactly two things: inject the engine-chosen per-run directory
                // verbatim (never invent one of its own), and let the port strip any
                // inherited NODE_V8_COVERAGE so the injection is the only source
                // (node-ports B8-L2). Command ports that ignore `env` (the test
                // fakes) simply produce no coverage directory — the engine's observe
                // mode treats that as "no data" and declines to gate on it, so this
                // injection is invisible to every pre-υ consumer.
                ...(coverageDir !== undefined
                    ? { env: { NODE_V8_COVERAGE: this.coverageSubdir(coverageDir, spec.id) } }
                    : {}),
            });
            // Death-cause honesty: `exitCode === null` alone cannot tell "our
            // timeout killed it" from "something outside killed it". A port that
            // observed an external signal (OOM-killer, user `kill -9`) reports it
            // via `killedBySignal`; that is a different fact from a timeout — the
            // model reading the evidence must be able to distinguish "ran too slow,
            // we killed it" from "killed by the outside world" — so it maps to
            // `error`, with the signal named on the first output line. A port that
            // killed the process for exceeding its budget says so with
            // `timedOut: true`; that outranks the `spawnError` the same result
            // carries for legacy consumers (real ports describe timeouts through
            // that channel), so 'timeout' is reachable from the real port, not
            // only from fakes. Both `aborted` (we chose to stop) and a
            // non-timeout `spawnError` (it never ran) outrank the signal reading,
            // matching the port contract that leaves `killedBySignal` unset in
            // exactly those cases.
            const externalSignal = result.aborted || result.spawnError !== undefined
                ? undefined
                : result.killedBySignal;
            const status = result.aborted
                ? 'aborted'
                : result.timedOut === true
                    ? 'timeout'
                    : result.spawnError !== undefined || externalSignal !== undefined
                        ? 'error'
                        : result.exitCode === 0
                            ? 'pass'
                            : result.exitCode === null
                                ? 'timeout'
                                : 'fail';
            return {
                status,
                exitCode: result.exitCode,
                durationMs: result.durationMs || this.clock.now() - started,
                output: result.spawnError !== undefined
                    ? `${result.spawnError}\n${result.output}`
                    : externalSignal !== undefined
                        ? `killed by signal ${externalSignal}\n${result.output}`
                        : result.output,
            };
        }
        catch (error) {
            return {
                status: 'error',
                exitCode: null,
                durationMs: this.clock.now() - started,
                output: `runner error: ${errorMessage(error)}`,
            };
        }
        finally {
            signal?.removeEventListener('abort', onAbort);
        }
    }
}
function errorMessage(error) {
    if (error instanceof Error)
        return error.message;
    try {
        return String(error);
    }
    catch {
        return '<unprintable>';
    }
}
//# sourceMappingURL=runner.js.map