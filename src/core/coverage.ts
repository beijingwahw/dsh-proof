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

// ---------------------------------------------------------------------------
// Parsing one V8 coverage file
// ---------------------------------------------------------------------------

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
  readonly executed: readonly string[]
  /** Sorted, deduplicated, workspace-relative, `/`-separated. */
  readonly loadedNotExecuted: readonly string[]
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
export function parseV8CoverageReport(content: string, root: string): ParsedCoverage | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    return undefined
  }
  if (parsed === null || typeof parsed !== 'object') return undefined
  const result = (parsed as { result?: unknown }).result
  if (!Array.isArray(result)) return undefined

  const executed = new Set<string>()
  const loaded = new Set<string>()
  for (const entry of result) {
    if (entry === null || typeof entry !== 'object') continue
    const url = (entry as { url?: unknown }).url
    if (typeof url !== 'string') continue
    const rel = fileUrlToRelative(url, root)
    if (rel === null) continue
    if (hasNodeModulesSegment(rel)) continue
    // count > 0 on any range of any function = this file's code actually ran.
    const functions = (entry as { functions?: unknown }).functions
    if (Array.isArray(functions) && functions.some(fn => anyRangeExecuted(fn))) {
      executed.add(rel)
    } else {
      loaded.add(rel)
    }
  }
  // The same script can appear more than once in a merged report; a single
  // executed occurrence means executed, so execution wins over mere loading.
  for (const file of executed) loaded.delete(file)
  return { executed: [...executed].sort(), loadedNotExecuted: [...loaded].sort() }
}

/**
 * Whether one `functions[]` entry has a range with `count > 0`. Tolerates
 * missing/foreign-shaped ranges (they count as 0): a report this defensive
 * about shape never crashes a proof over a field V8 did not feel like writing.
 */
function anyRangeExecuted(fn: unknown): boolean {
  if (fn === null || typeof fn !== 'object') return false
  const ranges = (fn as { ranges?: unknown }).ranges
  if (!Array.isArray(ranges)) return false
  return ranges.some(range => {
    if (range === null || typeof range !== 'object') return false
    const count = (range as { count?: unknown }).count
    return typeof count === 'number' && count > 0
  })
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
 * may carry a cache-bust query while LSP document URIs never do.
 * Reimplemented here rather than imported because the core must not depend
 * on the DSH adapter layer (`core` never imports `dsh`).
 */
function fileUrlToRelative(url: string, root: string): string | null {
  if (!url.startsWith('file:')) return null
  // W15-L8: a coverage URL may carry a cache-bust query or fragment
  // (`file:///src/x.mjs?bust=1`) — the executed FILE is the path part, and a
  // literal `?…` must be percent-encoded (%3F) to be part of a real file URL,
  // so cutting at the first raw `?`/`#` never truncates a genuine path.
  // Matching the query verbatim used to leave executed code permanently
  // "uncovered" (the changed file never equalled the queried spelling), the
  // gate blocking on workspaces that cache-bust — conservative, but factually
  // wrong about what ran.
  const queryCut = url.search(/[?#]/)
  const bareUrl = queryCut >= 0 ? url.slice(0, queryCut) : url
  let path: string
  if (bareUrl.startsWith('file:///')) {
    path = `/${decodeURIComponentSafe(bareUrl.slice('file:///'.length))}`
  } else if (bareUrl.startsWith('file://')) {
    path = decodeURIComponentSafe(bareUrl.slice('file://'.length))
  } else {
    return null
  }
  if (/^\/[A-Za-z]:\//.test(path)) path = path.slice(1)
  path = path.replace(/\\/g, '/')
  const normalizedRoot = root.replace(/\\/g, '/').replace(/\/+$/, '')
  const prefix = `${normalizedRoot}/`
  const inside = /^[A-Za-z]:\//.test(normalizedRoot)
    ? path.toLowerCase().startsWith(prefix.toLowerCase())
    : path.startsWith(prefix)
  if (!inside) return null
  return path.slice(prefix.length)
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

/**
 * Whether any path segment is `node_modules` — the segment-based form of the
 * "/node_modules/ 段也排除" drop rule, so a top-level `node_modules/…` is
 * caught along with the interior `pkg/node_modules/dep/…` nesting pnpm-style
 * layouts produce. Executed dependency code is real coverage for the
 * *dependency*, not for the workspace change being proven.
 */
function hasNodeModulesSegment(rel: string): boolean {
  return rel.split('/').includes('node_modules')
}

// ---------------------------------------------------------------------------
// Summarizing coverage over the change set
// ---------------------------------------------------------------------------

/**
 * The change set sliced by execution: which changed source files the decisive
 * evidence actually executed, which it never touched, and which changed files
 * are not source at all (documents and other non-code assets do not
 * participate in gating — there is nothing to "execute" in a README).
 */
export interface CoverageSummary {
  /** `none` = no check this run produced coverage data at all. */
  readonly basis: 'v8' | 'none'
  /** Changed source files executed by at least one decisive-pass evidence run. Ascending. */
  readonly changedExecuted: readonly string[]
  /** Changed source files no evidence run ever executed. Ascending. */
  readonly changedUncovered: readonly string[]
  /** Changed non-source files (docs etc.) — informational, never gated on. Ascending. */
  readonly changedNotApplicable: readonly string[]
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
export function summarizeCoverage(input: {
  changed: readonly string[]
  /** Each decisive pass evidence's executed set (from `Evidence.coverage`). */
  executedSets: readonly (readonly string[])[]
}): CoverageSummary {
  const executed = new Set<string>()
  for (const set of input.executedSets) {
    for (const file of set) executed.add(file)
  }
  const basis: CoverageSummary['basis'] = input.executedSets.length === 0 ? 'none' : 'v8'
  const changedExecuted: string[] = []
  const changedUncovered: string[] = []
  const changedNotApplicable: string[] = []
  for (const file of [...new Set(input.changed)].sort()) {
    if (!isSourcePath(file)) {
      changedNotApplicable.push(file)
      continue
    }
    if (executed.has(file)) changedExecuted.push(file)
    else changedUncovered.push(file)
  }
  return { basis, changedExecuted, changedUncovered, changedNotApplicable }
}

/**
 * Same semantics as `SOURCE_EXT` in `core/impact.ts` (mirrored again, also
 * module-private, in `core/contract.ts`): a RelPath is source when its
 * extension says code. Neither module exports the predicate, so it is
 * reimplemented here under this provenance note; keep the three in sync.
 */
const SOURCE_EXT = /\.(m|c)?(j|t)sx?$|\.py$|\.go$|\.rs$|\.java$|\.kt$|\.rb$|\.php$|\.cs$/

function isSourcePath(rel: string): boolean {
  return SOURCE_EXT.test(rel)
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/** `coverageGate`'s verdict; `reason` names the blocking cause, or is `null`. */
export interface CoverageGateResult {
  readonly blocked: boolean
  /** `'uncovered-change'` = a changed source file never executed; `'no-coverage-data'` = `require` mode met a `none` basis. */
  readonly reason: 'uncovered-change' | 'no-coverage-data' | null
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
export function coverageGate(
  coverage: CoverageSummary,
  mode: 'observe' | 'require' | 'off',
): CoverageGateResult {
  if (mode === 'off') return { blocked: false, reason: null }
  if (coverage.basis === 'none') {
    return mode === 'require'
      ? { blocked: true, reason: 'no-coverage-data' }
      : { blocked: false, reason: null }
  }
  if (coverage.changedUncovered.length > 0) {
    return { blocked: true, reason: 'uncovered-change' }
  }
  return { blocked: false, reason: null }
}
