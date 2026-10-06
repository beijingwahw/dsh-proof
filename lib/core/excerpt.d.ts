/**
 * Evidence excerpting: how much of a check's output survives into the
 * evidence record, and *which* part.
 *
 * The failure this exists for: naive head truncation keeps the banner
 * ("✓ 50 passed") and cuts off exactly what the model needs to fix the bug —
 * the assertion, the diff, the stack trace, which in most test runners live
 * in the middle or at the end. v0.5 replaced it with a three-segment
 * excerpt: head + salient failure lines + tail, under one budget.
 *
 * THE CONTRACT (v0.8 — these invariants are enforced by construction, not
 * aspirational comments):
 *
 * 1. Budget. `budget` bounds the assembled `text` itself — the omission
 *    marker and the newlines that join segments count against it. This holds
 *    for BOTH strategies (the `head` strategy is a verbatim slice of exactly
 *    `budget` chars), so a consumer can rely on `text.length <= budget`
 *    without knowing which strategy produced the excerpt.
 *
 * 2. Accounting. `text` mixes surviving original characters with one
 *    omission marker, so `normalized.length - text.length` is NOT the number
 *    of omitted characters (the marker inflates the text). The books that do
 *    close, exactly, are:
 *        omittedChars + keptOriginalChars === normalized.length
 *    where `keptOriginalChars` counts only characters of `normalized` that
 *    survived into `text` (newlines inside a kept segment count; the marker
 *    and the joining newlines are overhead, not content). The marker always
 *    prints the final `omittedChars` — never a pre-truncation estimate.
 *
 * 3. Survival. The balanced strategy never cuts a picked salient line in
 *    half. When the assembly overruns the budget it sacrifices, in order:
 *    the earliest tail lines, then the tail end of the head window. Only if
 *    even a bare marker plus the salient text cannot fit (a budget smaller
 *    than the marker itself, or a single salient line too big for the whole
 *    budget) does it fall back to plain head semantics; `truncated` stays
 *    true so the loss is always visible.
 *
 * Everything here is a pure function of (text, options): the excerpt is
 * deterministic, so evidence records stay content-addressed and reproducible.
 *
 * @module dsh-proof/core/excerpt
 */
export type ExcerptStrategy = 'head' | 'balanced';
export interface ExcerptOptions {
    /**
     * Total character budget for the excerpt text — the omission marker and
     * the segment-joining newlines count against it (contract #1).
     */
    readonly budget: number;
    readonly strategy: ExcerptStrategy;
}
export interface Excerpt {
    readonly text: string;
    /** True when any content was dropped. */
    readonly truncated: boolean;
    /**
     * Characters of `normalized` that are NOT in `text`. Reconcile against
     * `keptOriginalChars`, never against `text.length` — the marker and joins
     * make `normalized.length - text.length` a wrong number by design.
     */
    readonly omittedChars: number;
    /**
     * Characters of `normalized` that ARE in `text` (marker and joins
     * excluded). Closes the books: `omittedChars + keptOriginalChars ===
     * normalized.length` (contract #2).
     */
    readonly keptOriginalChars: number;
}
export declare function isSalientLine(line: string): boolean;
/**
 * The line a reader (human or model) should look at first: the first salient
 * line when there is one, otherwise the first non-empty line.
 */
export declare function firstInformativeLine(text: string): string;
/**
 * Excerpt normalised output under a character budget.
 *
 * - `head` — the legacy behaviour: the first `budget` characters, verbatim.
 * - `balanced` — a head window plus the salient failure lines found after it
 *   plus a whole-line-aligned tail window, joined with an omission marker
 *   that accounts for every dropped character. The assembly is then FITTED
 *   to the budget by giving up tail lines and head-window tail first — the
 *   salient middle is never the thing that gets cut, so the module contract
 *   holds by construction instead of by a post-hoc slice.
 */
export declare function excerptOutput(normalized: string, options: ExcerptOptions): Excerpt;
//# sourceMappingURL=excerpt.d.ts.map