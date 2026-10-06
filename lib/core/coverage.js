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
export function parseV8CoverageReport(content, root) {
    let parsed;
    try {
        parsed = JSON.parse(content);
    }
    catch {
        return undefined;
    }
    if (parsed === null || typeof parsed !== 'object')
        return undefined;
    const result = parsed.result;
    if (!Array.isArray(result))
        return undefined;
    const executed = new Set();
    const loaded = new Set();
    for (const entry of result) {
        if (entry === null || typeof entry !== 'object')
            continue;
        const url = entry.url;
        if (typeof url !== 'string')
            continue;
        const rel = fileUrlToRelative(url, root);
        if (rel === null)
            continue;
        if (hasNodeModulesSegment(rel))
            continue;
        // count > 0 on any range of any function = this file's code actually ran.
        const functions = entry.functions;
        if (Array.isArray(functions) && functions.some(fn => anyRangeExecuted(fn))) {
            executed.add(rel);
        }
        else {
            loaded.add(rel);
        }
    }
    // The same script can appear more than once in a merged report; a single
    // executed occurrence means executed, so execution wins over mere loading.
    for (const file of executed)
        loaded.delete(file);
    return { executed: [...executed].sort(), loadedNotExecuted: [...loaded].sort() };
}
/**
 * Whether one `functions[]` entry has a range with `count > 0`. Tolerates
 * missing/foreign-shaped ranges (they count as 0): a report this defensive
 * about shape never crashes a proof over a field V8 did not feel like writing.
 */
function anyRangeExecuted(fn) {
    if (fn === null || typeof fn !== 'object')
        return false;
    const ranges = fn.ranges;
    if (!Array.isArray(ranges))
        return false;
    return ranges.some(range => {
        if (range === null || typeof range !== 'object')
            return false;
        const count = range.count;
        return typeof count === 'number' && count > 0;
    });
}
/**
 * `file://` URL → workspace-relative path, or `null` when the URL is not a
 * file URL / sits outside `root`.
 *
 * Same semantics as `uriToRelative` in `dsh/lsp-impact.ts` (kept in sync by
 * this note): three-slash and two-slash forms, percent-decoding, Windows
 * drive letters arriving as `/C:/…` normalized back to `C:/…`, backslashes
 * folded, trailing-slash-stripped root, and a prefix comparison that is
 * case-insensitive exactly when the root is drive-form — Windows servers
 * routinely disagree with the host on drive-letter case while POSIX roots
 * stay case-sensitive. One deliberate divergence (W15-L8): this copy strips
 * a `?query`/`#fragment` suffix before comparing, because V8 coverage URLs
 * may carry a cache-bust query while LSP document URIs never do. A second
 * divergence (V7-L4): this copy models the two-slash UNC form
 * (`file://server/share/…` → `//server/share/…`) — v0.23's host-path fold
 * (adapters/shared/paths.ts) added UNC, and this mirror follows so a UNC
 * workspace's coverage URLs resolve instead of silently missing the root.
 * Reimplemented here rather than imported because the core must not depend
 * on the DSH adapter layer (`core` never imports `dsh`).
 */
function fileUrlToRelative(url, root) {
    if (!url.startsWith('file:'))
        return null;
    // W15-L8: a coverage URL may carry a cache-bust query or fragment
    // (`file:///src/x.mjs?bust=1`) — the executed FILE is the path part, and a
    // literal `?…` must be percent-encoded (%3F) to be part of a real file URL,
    // so cutting at the first raw `?`/`#` never truncates a genuine path.
    // Matching the query verbatim used to leave executed code permanently
    // "uncovered" (the changed file never equalled the queried spelling), the
    // gate blocking on workspaces that cache-bust — conservative, but factually
    // wrong about what ran.
    const queryCut = url.search(/[?#]/);
    const bareUrl = queryCut >= 0 ? url.slice(0, queryCut) : url;
    let path;
    if (bareUrl.startsWith('file:///')) {
        path = `/${decodeURIComponentSafe(bareUrl.slice('file:///'.length))}`;
    }
    else if (bareUrl.startsWith('file://')) {
        // Two-slash `file://host/…`: either a UNC share or the legacy Windows
        // spelling with a drive letter riding in the host position.
        // V7-L4: a UNC host (`file://server/share/ws/src/a.ts`) denotes
        // `//server/share/ws/src/a.ts` — emitting it WITHOUT the leading `//`
        // (the pre-fix behaviour) dropped the UNC prefix, so a UNC workspace's
        // coverage URLs never matched its UNC root (`\\server\share\ws`, folded
        // to `//server/share/ws` below) and every changed file read "uncovered"
        // — the τ gate observe-no-op'd or required-everything for the whole
        // workspace, silently. The drive-in-host spelling (`file://C:/ws/…`) is
        // NOT UNC: `C:` is the drive, and the pre-existing reading (bare
        // `C:/ws/…`, normalized by the drive folds below) is pinned by tests
        // and unchanged.
        const rest = decodeURIComponentSafe(bareUrl.slice('file://'.length));
        path = /^[A-Za-z]:[\\/]/.test(rest) ? rest : `//${rest}`;
    }
    else {
        return null;
    }
    if (/^\/[A-Za-z]:\//.test(path))
        path = path.slice(1);
    path = path.replace(/\\/g, '/');
    const normalizedRoot = root.replace(/\\/g, '/').replace(/\/+$/, '');
    const prefix = `${normalizedRoot}/`;
    const inside = /^[A-Za-z]:\//.test(normalizedRoot)
        ? path.toLowerCase().startsWith(prefix.toLowerCase())
        : path.startsWith(prefix);
    if (!inside)
        return null;
    return path.slice(prefix.length);
}
function decodeURIComponentSafe(value) {
    try {
        return decodeURIComponent(value);
    }
    catch {
        return value;
    }
}
/**
 * Whether any path segment is `node_modules` — the segment-based form of the
 * "/node_modules/ 段也排除" drop rule, so a top-level `node_modules/…` is
 * caught along with the interior `pkg/node_modules/dep/…` nesting pnpm-style
 * layouts produce. Executed dependency code is real coverage for the
 * *dependency*, not for the workspace change being proven.
 */
function hasNodeModulesSegment(rel) {
    return rel.split('/').includes('node_modules');
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
export function summarizeCoverage(input) {
    const executed = new Set();
    for (const set of input.executedSets) {
        for (const file of set)
            executed.add(file);
    }
    const basis = input.executedSets.length === 0 ? 'none' : 'v8';
    const changedExecuted = [];
    const changedUncovered = [];
    const changedNotApplicable = [];
    for (const file of [...new Set(input.changed)].sort()) {
        if (!isSourcePath(file)) {
            changedNotApplicable.push(file);
            continue;
        }
        if (executed.has(file))
            changedExecuted.push(file);
        else
            changedUncovered.push(file);
    }
    return { basis, changedExecuted, changedUncovered, changedNotApplicable };
}
/**
 * Same semantics as `SOURCE_EXT` in `core/impact.ts` (mirrored again, also
 * module-private, in `core/contract.ts`): a RelPath is source when its
 * extension says code. Neither module exports the predicate, so it is
 * reimplemented here under this provenance note; keep the three in sync.
 */
const SOURCE_EXT = /\.(m|c)?(j|t)sx?$|\.py$|\.go$|\.rs$|\.java$|\.kt$|\.rb$|\.php$|\.cs$/;
function isSourcePath(rel) {
    return SOURCE_EXT.test(rel);
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
export function coverageGate(coverage, mode) {
    if (mode === 'off')
        return { blocked: false, reason: null };
    if (coverage.basis === 'none') {
        return mode === 'require'
            ? { blocked: true, reason: 'no-coverage-data' }
            : { blocked: false, reason: null };
    }
    if (coverage.changedUncovered.length > 0) {
        return { blocked: true, reason: 'uncovered-change' };
    }
    return { blocked: false, reason: null };
}
//# sourceMappingURL=coverage.js.map