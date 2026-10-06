/**
 * τ: coverage-aware proof — the pure domain of "the checks were green, and
 * they actually executed the change".
 *
 * Until τ, `proven` meant "every affected check was re-run and none
 * regressed". That has a blind spot a reader cannot see from the report: the
 * green checks may never have *executed the changed code at all* — a test
 * suite that passes because the change sits in a file no test imports, a lint
 * that skips the new extension, a typecheck that was already green before the
 * edit. "All green" is a statement about the checks; it is not, by itself, a
 * statement about the change. τ closes that gap by feeding V8 function-level
 * coverage (the `NODE_V8_COVERAGE` JSON a check subprocess leaves behind)
 * into the same content-addressed pipeline as every other observation.
 *
 * Everything here is a pure function of its inputs — no clock, no randomness,
 * no filesystem — because the outputs are destined for the evidence chain,
 * where the same input must always yield the byte-identical result.
 *
 * @module dsh-proof/core/coverage
 */
/**
 * One V8 coverage file's parse product: the workspace-relative files that were
 * *executed* (at least one function with `count > 0`) and those that were
 * merely *loaded* (present in the report with every range at `count 0` —
 * block coverage's signature for "imported but never ran a line"). Files the
 * process never loaded do not appear in a V8 report at all, and therefore in
 * neither bucket.
 */
export interface ParsedCoverage {
    /** Sorted, deduplicated, workspace-relative, `/`-separated. */
    readonly executed: readonly string[];
    /** Sorted, deduplicated, workspace-relative, `/`-separated. */
    readonly loadedNotExecuted: readonly string[];
}
/**
 * Parse one `coverage-<pid>-<seq>-<ns>.json` as written by a Node process run
 * under `NODE_V8_COVERAGE=<dir>`.
 *
 * Defensive by contract: unparseable JSON or a wrong shape (`result` missing
 * or not an array) yields `undefined` — the caller treats "no report" exactly
 * like "no file", never like "empty coverage". A well-formed report with an
 * empty `result` is *not* undefined: both buckets come back empty, because
 * "the process loaded nothing from this workspace" is real information.
 *
 * URL handling accepts both `file:///C:/…` (three-slash, Windows drive) and
 * `file://C:/…` spellings, percent-decodes, and drops everything outside
 * `root` (other checkouts, `node:` internals never start with `file:` at all)
 * and everything under a `node_modules` segment (dependencies executed are
 * not *this workspace's* change being executed).
 */
export declare function parseV8CoverageReport(content: string, root: string): ParsedCoverage | undefined;
/**
 * The change set sliced by execution: which changed source files the decisive
 * evidence actually executed, which it never touched, and which changed files
 * are not source at all (documents and other non-code assets do not
 * participate in gating — there is nothing to "execute" in a README).
 */
export interface CoverageSummary {
    /** `none` = no check this run produced coverage data at all. */
    readonly basis: 'v8' | 'none';
    /** Changed source files executed by at least one decisive-pass evidence run. Ascending. */
    readonly changedExecuted: readonly string[];
    /** Changed source files no evidence run ever executed. Ascending. */
    readonly changedUncovered: readonly string[];
    /** Changed non-source files (docs etc.) — informational, never gated on. Ascending. */
    readonly changedNotApplicable: readonly string[];
}
/**
 * Union the executed-sets of every decisive pass (the engine collects one set
 * per check run out of `Evidence.coverage`) and slice the change set by it.
 *
 * Pinned rule: **zero executedSets means `basis: 'none'`** — the difference
 * between "we measured and the change never ran" (`v8` + non-empty
 * `changedUncovered`) and "nothing produced a measurement" (`none`) is
 * exactly the difference the gate's `observe`/`require` modes arbitrate.
 */
export declare function summarizeCoverage(input: {
    changed: readonly string[];
    /** Each decisive pass evidence's executed set (from `Evidence.coverage`). */
    executedSets: readonly (readonly string[])[];
}): CoverageSummary;
/** `coverageGate`'s verdict; `reason` names the blocking cause, or is `null`. */
export interface CoverageGateResult {
    readonly blocked: boolean;
    /** `'uncovered-change'` = a changed source file never executed; `'no-coverage-data'` = `require` mode met a `none` basis. */
    readonly reason: 'uncovered-change' | 'no-coverage-data' | null;
}
/**
 * Pure gate verdict: an uncovered change means `proven` is unavailable.
 *
 * - `'observe'` — gate only when there is data; a `none` basis (no check
 *   produced coverage) does not block. The honest default for workspaces
 *   whose checks simply are not instrumented: τ must degrade to a no-op, not
 *   to a new way of failing every claim.
 * - `'require'` — a `none` basis blocks too (`no-coverage-data`): the caller
 *   has promised coverage instrumentation exists, so its absence is itself a
 *   finding.
 * - `'off'` — never blocks; τ is disabled.
 *
 * `reason: null` with `blocked: false` covers every passing case (including
 * "not applicable"); the caller that wants to leave the report untouched
 * simply never calls `applyCoverageGate` with a gate it did not compute.
 */
export declare function coverageGate(coverage: CoverageSummary, mode: 'observe' | 'require' | 'off'): CoverageGateResult;
//# sourceMappingURL=coverage.d.ts.map