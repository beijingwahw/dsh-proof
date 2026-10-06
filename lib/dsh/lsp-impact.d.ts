/**
 * LSP-backed impact resolution: turns the host's language servers into a
 * precise, alias-aware DefinitionResolverPort for the dependency graph.
 *
 * The trick that makes the closed four-operation LSP surface sufficient:
 * goToDefinition placed *on the module specifier of an import statement*
 * resolves to the file that specifier binds to — including tsconfig `paths`
 * aliases and package-internal imports that regex extraction cannot see.
 *
 * Cost control: every result is cached per (file, content version, position),
 * a hard query budget degrades the remainder to the approximate graph, and —
 * H-34 — every round-trip is raced against a wall-clock deadline: a language
 * server that never answers degrades its position to a null answer (uncached,
 * retried later), never hangs the whole verify.
 *
 * M-30 (v0.24): the budget is TWO-LAYERED. The invocation count
 * (`budget`, fed from `lspQueryBudget`) caps round-trips; the cumulative
 * wall-clock (`totalBudgetMs`) caps the TIME those round-trips spend — a
 * merely SLOW server (every answer arrives inside the 5s per-query deadline,
 * but takes seconds each) used to be bounded only by count: 400 × 5s ≈ 33
 * minutes of graph building with no budget ever firing. Cumulative time is
 * accounted across the resolver's whole lifetime (it is a plugin-lifetime
 * singleton), cache hits cost nothing, and once the clock runs dry new
 * queries degrade to null exactly like count exhaustion — approximate graph,
 * soundness never narrows.
 *
 * @module dsh-proof/dsh/lsp-impact
 */
import type { DefinitionResolverPort, FsPort } from '../core/ports.ts';
import type { LspLike } from '../vendor/dsh-tools.ts';
export interface LspResolverOptions {
    /** Maximum language-server round-trips (per resolver instance). */
    readonly budget?: number;
    /**
     * H-34: wall-clock ceiling for ONE language-server round-trip, in ms. A
     * server that never answers (init deadlock, a zombie language-server
     * process) must degrade that position to a null answer — costing one
     * query's worth of latency — instead of hanging the whole verify: no
     * engine budget covers this await (graph building sits outside the check
     * dispatch loop). Default 5s; injectable so tests can pin the behaviour in
     * real time.
     */
    readonly queryTimeoutMs?: number;
    /**
     * M-30: cumulative wall-clock ceiling for ALL round-trips this resolver
     * ever makes, in ms (default 60s). Unlike the count budget, this one binds
     * slow-but-answerable servers: each round-trip's full duration — including
     * a timed-out or rejected one, whose wall time was spent just the same —
     * accrues to the total; once it runs dry, new positions degrade to null
     * (uncached, like every degradation here) while cached answers stay free.
     */
    readonly totalBudgetMs?: number;
}
/** Build a caching, budgeted resolver over the host's LSP seam, if present. */
export declare function createLspResolver(lsp: LspLike | undefined, root: string, fs: FsPort, options?: LspResolverOptions): DefinitionResolverPort | undefined;
/** Convert a `file://` URI to a workspace-relative path, or null when outside. */
export declare function uriToRelative(uri: string, root: string): string | null;
//# sourceMappingURL=lsp-impact.d.ts.map