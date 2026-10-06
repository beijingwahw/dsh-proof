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
/**
 * Lines that carry failure information. Deliberately broad — over-matching
 * costs a few characters of budget; under-matching hides the reason a check
 * is red, which is the whole point of the excerpt.
 */
const SALIENCY_PATTERNS = [
    /\berrors?\b/i,
    /\bfail(?:ed|ing|ures?|ing)?\b/i,
    /✖|✗|⊗/,
    /\bassert(?:ion|ed|ions)?\b/i,
    /\bexpected\b/i,
    /\b(?:received|actual|got)\b/i,
    /\btraceback\b/i,
    /^\s*at\s+.+\(/,
    /\bfatal\b/i,
    /\bpanic(?:ked)?\b/i,
    /\b(?:timed?\s?out|timeout)\b/i,
    /\bdenied\b/i,
    /^not ok\b/,
];
export function isSalientLine(line) {
    return SALIENCY_PATTERNS.some(re => re.test(line));
}
/**
 * The line a reader (human or model) should look at first: the first salient
 * line when there is one, otherwise the first non-empty line.
 */
export function firstInformativeLine(text) {
    const lines = text.split('\n').filter(l => l.trim().length > 0);
    const salient = lines.find(isSalientLine);
    const chosen = salient ?? lines[0] ?? '';
    return chosen.length > 200 ? `${chosen.slice(0, 200)}…` : chosen;
}
function marker(omitted) {
    return `[... ${omitted} chars omitted ...]`;
}
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
export function excerptOutput(normalized, options) {
    // H-33: a non-finite budget is a configuration error, not a request. The
    // old clamp (`Math.max(16, NaN)` is NaN) silently returned an EMPTY text
    // with NaN accounting while outputDigest still addressed "something" — the
    // hardest bad-evidence shape to notice after the fact. Pure-function domain
    // discipline: refuse loudly at the boundary instead of laundering the NaN.
    if (!Number.isFinite(options.budget)) {
        throw new TypeError(`excerpt budget must be a finite number, got ${options.budget}`);
    }
    const budget = Math.max(16, Math.floor(options.budget));
    if (normalized.length <= budget) {
        return { text: normalized, truncated: false, omittedChars: 0, keptOriginalChars: normalized.length };
    }
    if (options.strategy === 'head') {
        // No marker is added, so every character of the text is original and the
        // accounting is exact by inspection.
        return {
            text: normalized.slice(0, budget),
            truncated: true,
            omittedChars: normalized.length - budget,
            keptOriginalChars: budget,
        };
    }
    const lines = normalized.split('\n');
    const offsets = [];
    let acc = 0;
    for (const line of lines) {
        offsets.push(acc);
        acc += line.length + 1;
    }
    const headLen = Math.max(1, Math.floor(budget * 0.3));
    // 1) Salient lines after the head window, in document order. The FIRST one
    //    is always kept when it fits within half the budget — the reason a
    //    check is red outranks both banner and epilogue. These picks are never
    //    trimmed later: contract #3 (survival) protects them.
    const salientCap = Math.max(0, Math.floor(budget * 0.4));
    const picked = [];
    let salientChars = 0;
    let first = true;
    lines.forEach((line, index) => {
        const start = offsets[index] ?? 0;
        if (start < headLen)
            return;
        if (line.trim().length === 0 || !isSalientLine(line))
            return;
        const cost = line.length + 1;
        const fits = salientChars + cost <= salientCap;
        const firstFits = first && line.length <= Math.floor(budget * 0.5);
        if (!fits && !firstFits)
            return;
        picked.push({ line, start });
        salientChars += cost;
        first = false;
    });
    // 2) Tail window: an initial whole-line-aligned guess at whatever budget
    //    seems to remain. The -32 reserves room for the marker and the joins;
    //    it only steers the guess — step 3 is what actually enforces the
    //    budget, so an underestimate here costs nothing but a shorter tail.
    const tailTarget = budget - headLen - salientChars - 32;
    let tailFrom = lines.length;
    let tailChars = 0;
    if (tailTarget >= 16) {
        tailFrom = lines.length - 1;
        for (let i = lines.length - 1; i >= 0; i -= 1) {
            if (tailChars >= tailTarget && tailChars > 0)
                break;
            tailChars += (lines[i] ?? '').length + 1;
            tailFrom = i;
        }
    }
    if (tailFrom < lines.length && (offsets[tailFrom] ?? 0) < headLen) {
        // Degenerate shape (e.g. the whole output is one huge line): there is no
        // line-aligned tail that starts after the head window. An honest
        // head+marker beats a tail that would double-count the head and break
        // the accounting.
        tailFrom = lines.length;
    }
    // 3) Fit the assembly to the budget. Priority: drop the earliest tail
    //    line, then shorten the head window from its end; picked salient lines
    //    are never touched. Every pass either returns or strictly advances
    //    `tailFrom` / retreats `headEnd` (both bounded), so this terminates —
    //    even when a dropped line only pays for a marker digit growing, the
    //    state still moves forward and the budget is eventually met.
    let headEnd = headLen;
    for (;;) {
        const tailStart = tailFrom < lines.length ? offsets[tailFrom] ?? normalized.length : normalized.length;
        const headPart = normalized.slice(0, headEnd);
        const tailPart = normalized.slice(tailStart);
        // Salient lines the aligned tail already shows in full are not restated
        // (no double count); the rest go between the marker and the tail.
        const kept2 = picked.filter(p => p.start < tailStart);
        const salientPart = kept2.map(p => p.line).join('\n');
        // Exact books (contract #2): the kept content is a chain of verbatim
        // segments of `normalized`. The kept char count is the SUM OF THE SEGMENT
        // LENGTHS — the newlines `salientPart`'s join manufactures between
        // non-adjacent picks are synthetic, not original (M-25: they used to be
        // booked as kept, over-reporting by one per surviving salient line minus
        // one, a wrong number written into signed evidence records). Where two
        // kept segments ARE adjacent in the original (a salient line directly
        // followed by the next kept salient line or by the tail window), the
        // newline joining them in the text IS that original newline, so the loop
        // below adds it back — only the newlines around the marker are synthetic
        // joins. Without that compensation, a salient line moving between the
        // tail and the salient block would silently lose one kept char (and a
        // budget increase could then keep fewer characters).
        let keptOriginal = headPart.length + tailPart.length;
        for (const p of kept2)
            keptOriginal += p.line.length;
        for (let k = 0; k < kept2.length; k += 1) {
            const cur = kept2[k];
            if (cur === undefined)
                break;
            const next = kept2[k + 1];
            const curEndPlusNewline = cur.start + cur.line.length + 1;
            if (next !== undefined) {
                if (curEndPlusNewline === next.start)
                    keptOriginal += 1;
            }
            else if (tailPart.length > 0 && curEndPlusNewline === tailStart) {
                keptOriginal += 1;
            }
        }
        // Segments are disjoint, and the text always carries them plus a marker
        // (>= 25 chars) plus the synthetic joins, so a fitting text implies
        // keptOriginal <= budget < normalized.length: the omission is strictly
        // positive and the marker states the exact final number.
        const omitted = normalized.length - keptOriginal;
        const parts = [];
        if (headPart.length > 0)
            parts.push(headPart);
        parts.push(marker(omitted));
        if (salientPart.length > 0)
            parts.push(salientPart);
        if (tailPart.length > 0)
            parts.push(tailPart);
        const text = parts.join('\n');
        // keptOriginal > 0: an excerpt that is nothing but a marker keeps no
        // evidence at all — the head-semantics fallback below strictly dominates
        // it, so keep shrinking (or fall back) instead of returning it.
        if (text.length <= budget && keptOriginal > 0) {
            return { text, truncated: true, omittedChars: omitted, keptOriginalChars: keptOriginal };
        }
        if (tailFrom < lines.length) {
            tailFrom += 1;
            continue;
        }
        if (headEnd > 0) {
            headEnd -= 1;
            continue;
        }
        // Pathological regime: the budget cannot even hold marker + salient
        // text. Head semantics keeps the budget honest, and `truncated` flags
        // that content was lost.
        return {
            text: normalized.slice(0, budget),
            truncated: true,
            omittedChars: normalized.length - budget,
            keptOriginalChars: budget,
        };
    }
}
//# sourceMappingURL=excerpt.js.map