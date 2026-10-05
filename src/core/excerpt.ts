/**
 * Evidence excerpting: how much of a check's output survives into the
 * evidence record, and *which* part.
 *
 * The failure this exists for: naive head truncation keeps the banner
 * ("✓ 50 passed") and cuts off exactly what the model needs to fix the bug —
 * the assertion, the diff, the stack trace, which in most test runners live
 * in the middle or at the end. v0.5 replaces it with a three-segment
 * excerpt: head + salient failure lines + tail, under one budget.
 *
 * Everything here is a pure function of (text, options): the excerpt is
 * deterministic, so evidence records stay content-addressed and reproducible.
 *
 * @module dsh-proof/core/excerpt
 */

export type ExcerptStrategy = 'head' | 'balanced'

export interface ExcerptOptions {
  /** Total character budget for the excerpt text. */
  readonly budget: number
  readonly strategy: ExcerptStrategy
}

export interface Excerpt {
  readonly text: string
  /** True when any content was dropped. */
  readonly truncated: boolean
  /** How many characters of the normalised output are not in the excerpt. */
  readonly omittedChars: number
}

/**
 * Lines that carry failure information. Deliberately broad — over-matching
 * costs a few characters of budget; under-matching hides the reason a check
 * is red, which is the whole point of the excerpt.
 */
const SALIENCY_PATTERNS: readonly RegExp[] = [
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
]

export function isSalientLine(line: string): boolean {
  return SALIENCY_PATTERNS.some(re => re.test(line))
}

/**
 * The line a reader (human or model) should look at first: the first salient
 * line when there is one, otherwise the first non-empty line.
 */
export function firstInformativeLine(text: string): string {
  const lines = text.split('\n').filter(l => l.trim().length > 0)
  const salient = lines.find(isSalientLine)
  const chosen = salient ?? lines[0] ?? ''
  return chosen.length > 200 ? `${chosen.slice(0, 200)}…` : chosen
}

function marker(omitted: number): string {
  return `[... ${omitted} chars omitted ...]`
}

/**
 * Excerpt normalised output under a character budget.
 *
 * - `head` — the legacy behaviour: the first `budget` characters, verbatim.
 * - `balanced` — head and tail windows plus the salient failure lines found
 *   between them, joined with omission markers that account for every
 *   dropped character. The composition is clamped so the result never
 *   exceeds the budget.
 */
export function excerptOutput(normalized: string, options: ExcerptOptions): Excerpt {
  const budget = Math.max(16, Math.floor(options.budget))
  if (normalized.length <= budget) {
    return { text: normalized, truncated: false, omittedChars: 0 }
  }
  if (options.strategy === 'head') {
    return { text: normalized.slice(0, budget), truncated: true, omittedChars: normalized.length - budget }
  }

  const lines = normalized.split('\n')
  const offsets: number[] = []
  let acc = 0
  for (const line of lines) {
    offsets.push(acc)
    acc += line.length + 1
  }

  const headLen = Math.max(1, Math.floor(budget * 0.3))
  const headText = normalized.slice(0, headLen)

  // 1) Salient lines after the head window, in document order. The FIRST one
  //    is always kept when it fits within half the budget — the reason a
  //    check is red outranks both banner and epilogue.
  const salientCap = Math.max(0, Math.floor(budget * 0.4))
  const picked: { line: string; start: number }[] = []
  let salientChars = 0
  let first = true
  lines.forEach((line, index) => {
    const start = offsets[index] ?? 0
    if (start < headLen) return
    if (line.trim().length === 0 || !isSalientLine(line)) return
    const cost = line.length + 1
    const fits = salientChars + cost <= salientCap
    const firstFits = first && line.length <= Math.floor(budget * 0.5)
    if (!fits && !firstFits) return
    picked.push({ line, start })
    salientChars += cost
    first = false
  })

  // 2) Tail window from whatever budget remains, aligned to whole lines.
  let tailTarget = budget - headLen - salientChars - 32
  let tailFrom = lines.length
  let tailChars = 0
  if (tailTarget >= 16) {
    tailFrom = lines.length - 1
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      if (tailChars >= tailTarget && tailChars > 0) break
      tailChars += (lines[i] ?? '').length + 1
      tailFrom = i
    }
  }
  const tailStartOffset = tailFrom < lines.length ? offsets[tailFrom] ?? normalized.length : normalized.length
  const tailText = normalized.slice(tailStartOffset)

  // 3) Drop salient lines the aligned tail already shows in full.
  const kept2 = picked.filter(p => p.start < tailStartOffset)
  const salientText = kept2.map(p => p.line).join('\n')

  const kept = headLen + tailText.length + salientText.length
  const omitted = Math.max(0, normalized.length - kept)
  const parts = kept2.length > 0
    ? [headText, marker(omitted), salientText, tailText]
    : [headText, marker(omitted), tailText]
  let text = parts.join('\n')
  // Hard clamp: line alignment must never push the excerpt past its budget.
  // Drop leading tail lines first, then slice — the salient middle is never
  // the thing that gets cut.
  while (text.length > budget && tailText.includes('\n')) {
    const trimmedTail = tailText.slice(tailText.indexOf('\n') + 1)
    text = (kept2.length > 0
      ? [headText, marker(omitted), salientText, trimmedTail]
      : [headText, marker(omitted), trimmedTail]).join('\n')
    break // single step is enough for realistic budgets; slice handles the rest
  }
  if (text.length > budget) text = text.slice(0, budget)
  return { text, truncated: true, omittedChars: omitted }
}
