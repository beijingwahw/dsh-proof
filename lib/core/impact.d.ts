/**
 * Change-impact analysis: from "these files changed" to "these checks are now
 * stale" — through a reverse-dependency closure, not a guess.
 *
 * Why this matters: running every check after every edit is how agent sessions
 * burn minutes and money; running no check is how "I fixed it" turns into a
 * broken main branch. The closure gives a *sound* middle ground: a check is
 * re-run whenever something it transitively depends on moved.
 *
 * @module dsh-proof/core/impact
 */
import type { CheckSpec, DefinitionResolverPort, FsPort } from './ports.ts';
/** A file path relative to the workspace root, using `/` separators. */
export type RelPath = string;
/** How exact the impact analysis behind a selection is. */
export type SelectionPrecision = 'lsp-verified' | 'approximate' | 'forced';
/** Adjacency: file -> files it directly depends on. */
export interface DependencyGraph {
    readonly nodes: ReadonlySet<RelPath>;
    /** module -> importing modules (reverse edges), for cheap closure walks. */
    readonly dependents: ReadonlyMap<RelPath, ReadonlySet<RelPath>>;
    /** How many files were scanned; surfaced in reports so limits are visible. */
    readonly scanned: number;
    readonly truncated: boolean;
    /** Edges confirmed by the resolver, keyed `${dependent}\u0000${dependency}`. */
    readonly lspConfirmed: ReadonlySet<string>;
    readonly precision: SelectionPrecision;
}
export interface BuildGraphOptions {
    readonly limit?: number;
    readonly ignoreDirs?: readonly string[];
    /** Optional LSP-backed resolver for precise, alias-aware edges. */
    readonly resolver?: DefinitionResolverPort;
    /** Maximum resolver round-trips for one graph build (degrades beyond). */
    readonly lspQueryBudget?: number;
    /**
     * M8: the caller's workspace walk (`FsPort.walk`) reported truncation — the
     * `files` list handed to this builder is a prefix of the workspace, so the
     * graph is incomplete for reasons THIS function cannot detect (its own
     * `limit` may never have fired). Propagated into `DependencyGraph.truncated`
     * so `selectAffectedChecks` degrades the selection to uncertain (all checks
     * run) instead of silently reasoning over a partial node set — a workspace
     * bigger than the walk limit used to produce a complete-looking graph that
     * never said it was partial.
     */
    readonly walkTruncated?: boolean;
}
/** Files whose change invalidates every check, regardless of path filters. */
export declare const GLOBAL_INVALIDATORS: readonly RegExp[];
export declare function isGlobalInvalidator(path: RelPath): boolean;
/**
 * Build a reverse-dependency graph from the workspace's source files.
 *
 * Two edge sources, fused conservatively:
 *
 * 1. *Approximate* — regex-extracted relative specifiers resolved against the
 *    filesystem. Always available; errs toward over-inclusion.
 * 2. *LSP-verified* — when a `resolver` is provided, every import site
 *    (relative AND bare/alias) is resolved through the language server's
 *    goToDefinition. This both confirms approximate edges and discovers
 *    workspace-internal edges regex cannot see (tsconfig `paths` aliases,
 *    package-internal imports) — real breakage blind spots in monorepos.
 *
 * Selection semantics never narrow: confirmed and approximate edges are
 * unioned; a failed or budget-exhausted resolver simply leaves the edge
 * approximate. `precision` reports which regime produced the graph.
 */
export declare function buildDependencyGraph(fs: FsPort, root: string, files: readonly RelPath[], options?: BuildGraphOptions): Promise<DependencyGraph>;
/**
 * Every file transitively affected by `changed`: the changed set itself, plus
 * all files that (transitively) import something in it.
 */
export declare function impactClosure(graph: DependencyGraph, changed: readonly RelPath[]): Set<RelPath>;
export interface SelectionResult {
    /** Checks whose impact set intersects the change closure. */
    readonly affected: CheckSpec[];
    /** Checks proven untouched by this change set. */
    readonly untouched: CheckSpec[];
    /** True when a global invalidator was present, forcing every check to run. */
    readonly forcedAll: boolean;
    /** The closure actually used for the decision (for reporting). */
    readonly closure: readonly RelPath[];
    /** True when the dependency graph could not cover every changed file. */
    readonly uncertain: boolean;
    /** Which edge regime produced the graph behind this selection. */
    readonly precision: SelectionPrecision;
}
/**
 * The forced selection: every check affected, nothing untouched, precision
 * `forced`. Single source of truth for this shape — it is what
 * `selectAffectedChecks` returns on a global invalidator, and what the engine
 * (`verify` with `all`/degraded git facts) and the report (`forceAll`) reach
 * for when impact analysis is deliberately bypassed. Before this constructor
 * existed the same literal lived in three modules and had already begun to
 * drift; one factory keeps them byte-identical.
 *
 * `closure` is NOT an impact closure here — no graph was consulted (or none
 * was allowed to narrow the run). It carries the change set the forced
 * decision was made on, so reports and attribution still name the files that
 * triggered the full sweep. `uncertain` is `false` for the same reason: the
 * selection does not depend on graph coverage, so graph coverage cannot make
 * it uncertain; `precision: 'forced'` states exactly which regime produced it.
 */
export declare function forcedSelection(specs: readonly CheckSpec[], changed: readonly RelPath[]): SelectionResult;
/**
 * Select the checks a change set makes stale. Conservative by construction:
 * uncertainty (unknown file types, truncated graphs, missing path filters)
 * widens the selection rather than narrowing it.
 */
export declare function selectAffectedChecks(checks: readonly CheckSpec[], changed: readonly RelPath[], graph?: DependencyGraph): SelectionResult;
/**
 * Map each changed file to the checks it invalidates — the attribution table
 * used when a regression needs an owner.
 */
export declare function attributeChange(checks: readonly CheckSpec[], changed: readonly RelPath[], graph?: DependencyGraph): Map<string, string[]>;
/** `src/foo/**` and `src/foo` both match `src/foo/bar.ts`. `*` matches everything. */
export declare function matchesAny(file: RelPath, patterns: readonly string[]): boolean;
export declare function matches(file: RelPath, pattern: string): boolean;
/**
 * One import site: a module specifier plus the 0-based UTF-16 position of its
 * first character — exactly where a language server's goToDefinition resolves
 * the module the statement binds to.
 */
export interface ImportSite {
    readonly specifier: string;
    readonly line: number;
    readonly character: number;
    readonly kind: 'relative' | 'bare';
}
/** Pull every import site (specifier + cursor position) out of source text. */
export declare function extractImportSites(content: string): ImportSite[];
/**
 * Pull workspace-reachable module specifiers out of source text.
 *
 * Line-based rather than one heroic regex: ESM/CJS `import`/`export ... from`,
 * bare side-effect `import '...'`, `require('...')`, Python `from x.y import`
 * (module and imported names) and bare `import x.y`. Bare package names and
 * `node:` builtins are dropped — those are external dependencies, already
 * covered by the lockfile rules.
 */
export declare function extractImports(content: string): string[];
//# sourceMappingURL=impact.d.ts.map