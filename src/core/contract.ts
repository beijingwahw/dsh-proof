/**
 * Typed claim contracts (ε): a `proof_claim` stops being free text and becomes
 * a *kind*, and every kind binds the claim to a different set of evidence
 * obligations.
 *
 * Why kinds at all: "I refactored X" and "I added feature Y" and "it got
 * faster" are claims with completely different proof obligations, and a single
 * generic "no regressions" gate cannot tell them apart. A `behavior-preserving`
 * claim must show the public API surface did not move; a `behavior-adding`
 * claim must show every new source path is exercised by a passing check; a
 * `perf-budget` claim must show a benchmark measurement inside the stated
 * budget; a `docs-only` claim must show the change set really is documents —
 * and gets a capped confidence instead of machine checks; an `llm-jury`
 * claim (ι) outsources its verdict to Class B testimony entirely: it must
 * show a jury deliberation on the exact claim text, and that the active
 * verdict upholds it.
 *
 * Purity note: obligation verdicts are destined for the evidence chain, so
 * everything here is a pure function of its inputs — no clock, no randomness,
 * no filesystem — and every list that reaches a `detail` string is sorted
 * first, so the same input always yields the byte-identical verdict.
 *
 * @module dsh-proof/core/contract
 */

import type { CheckSpec } from './ports.ts'
import type { Baseline, Evidence } from './evidence.ts'
import { verdictOf } from './evidence.ts'
import { isGlobalInvalidator, matchesAny } from './impact.ts'
import { activeAttestations, claimIdOf, type Attestation, type JuryAttestation } from './attest.ts'

export type ClaimKind =
  | 'behavior-preserving'
  | 'behavior-adding'
  | 'perf-budget'
  | 'docs-only'
  /** ι: judged by Class B testimony, not machine checks (`skipChecks` is true for it). */
  | 'llm-jury'

/** The typed half of a `proof_claim`; `claim` itself stays human-readable. */
export interface ClaimContract {
  readonly kind: ClaimKind
  /** Human-readable statement of what was done (not the normative part). */
  readonly claim: string
  /** Required by `perf-budget`: the wall-clock budget a benchmark must beat. */
  readonly budgetMs?: number
  /** Required by `docs-only`: the self-review a human jury should check against. */
  readonly review?: string
  /** API-face entry points to cover; omitted means the engine derives them. */
  readonly entryPoints?: readonly string[]
}

/** One obligation under one contract: met or not, and what to do about it. */
export interface ObligationResult {
  readonly id: string
  readonly met: boolean
  /** Human-readable, model-actionable: when not met, says what is missing and how to fix it. */
  readonly detail: string
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

/** One file reachable from the API face: its path and its full text. */
export interface SurfaceEntry { readonly rel: string; readonly content: string }

/**
 * The exports a set of files makes public, as sorted, deduplicated
 * `'${rel}#${exportName}'` strings.
 *
 * Extraction is line-regex based and deliberately biased to OVER-report:
 * `behavior-preserving` requires the surface diff to be empty, so a missed
 * export is a missed breaking change (a wrong pass), while a phantom extra
 * export only makes an honest claim work harder (a wrong fail). When in doubt,
 * report.
 *
 * Five forms are recognised, per line:
 * 1. `export` named declarations (`const`/`let`/`var`/`function`/`class`/
 *    `abstract class`/`interface`/`type`/`enum`, plus `async`/`declare`/
 *    `function*`/`const enum` variants and multi-declarator `const a = 1, b = 2`);
 *    type annotations are tolerated — `export const x: number = 1` reports
 *    `x`, and a destructuring declarator reports the pattern's names but never
 *    its annotation (`export const { a }: Foo = o` reports `a`, not `Foo`);
 * 2. `export { a, b as c }` (single- or multi-line, `export type { … }` included);
 * 3. `export default …` → recorded as `#default`;
 * 4. `export * from …` → recorded as `#*` (a changed re-export face is a face
 *    change; `export * as ns from …` also records the `ns` binding);
 * 5. `export = …` (TS CommonJS) → recorded as `#=`.
 */
export function extractApiSurface(entries: readonly SurfaceEntry[]): string[] {
  const out = new Set<string>()
  for (const entry of entries) {
    for (const name of exportedNames(entry.content)) out.add(`${entry.rel}#${name}`)
  }
  return [...out].sort()
}

/** Set difference of two surfaces, both directions, sorted. */
export function diffApiSurface(
  before: readonly string[],
  after: readonly string[],
): { added: string[]; removed: string[] } {
  const b = new Set(before)
  const a = new Set(after)
  const added = [...a].filter(x => !b.has(x)).sort()
  const removed = [...b].filter(x => !a.has(x)).sort()
  return { added, removed }
}

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/
const RE_COMMENT_OR_BLANK = /^(?:$|\/\/|\/\*|\*)/

const RE_EXPORT_BRACE_OPEN = /^export\s*(?:type\s*)?\{/
const RE_EXPORT_DEFAULT = /^export\s+default\b/
const RE_EXPORT_STAR = /^export\s+\*(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*from\b/
const RE_EXPORT_EQUALS = /^export\s*=/
// `const\s+enum` must be tried before both `enum` and `const`, and
// `function\s*\*?` before a bare-name reading, or the wrong alternative wins.
const RE_NAMED_DECL = /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(const\s+enum|enum|function\s*\*?|class|interface|type|const|let|var)\s+(.+)$/

function isCommentLine(trimmed: string): boolean {
  return RE_COMMENT_OR_BLANK.test(trimmed)
}

/** All names one module's text exports (the `#name` parts, no rel prefix). */
function exportedNames(content: string): string[] {
  const names = new Set<string>()
  const lines = content.split('\n')
  let i = 0
  while (i < lines.length) {
    const trimmed = (lines[i] as string).trim()
    i += 1
    if (isCommentLine(trimmed)) continue

    // Form 2 — brace list, possibly spanning lines. Lines are folded into one
    // string until a `}` shows up (or the text ends: a truncated module then
    // still reports every name seen so far — the over-report direction).
    if (RE_EXPORT_BRACE_OPEN.test(trimmed)) {
      let text = trimmed
      while (!text.includes('}') && i < lines.length) {
        const next = (lines[i] as string).trim()
        if (!isCommentLine(next)) text += ` ${next}`
        i += 1
      }
      for (const name of braceListNames(text)) names.add(name)
      continue
    }
    // Form 3 — one default export per module, named `#default` whatever it is.
    if (RE_EXPORT_DEFAULT.test(trimmed)) {
      names.add('default')
      continue
    }
    // Form 4 — the wildcard face; `export * as ns` additionally binds `ns`.
    const star = RE_EXPORT_STAR.exec(trimmed)
    if (star !== null) {
      names.add('*')
      if (star[1] !== undefined) names.add(star[1])
      continue
    }
    // Form 5 — TS CommonJS `export = X` (anonymous object exports included).
    if (RE_EXPORT_EQUALS.test(trimmed)) {
      names.add('=')
      continue
    }
    // Form 1 — named declaration(s).
    const decl = RE_NAMED_DECL.exec(trimmed)
    if (decl !== null) {
      const keyword = (decl[1] as string).replace(/\s+/g, ' ')
      const rest = (decl[2] as string).trim()
      if (keyword === 'const' || keyword === 'let' || keyword === 'var') {
        for (const name of declaratorNames(rest)) names.add(name)
      } else {
        const name = /^([A-Za-z_$][\w$]*)/.exec(rest)?.[1]
        if (name !== undefined) names.add(name)
      }
    }
  }
  return [...names]
}

/**
 * Names from `export { a, b as c, d as "str-alias" }`. `b as c` exports the
 * *alias* `c` — that is the name importers bind — and a string alias is kept
 * verbatim (unquoted) because it is a legal export name.
 */
function braceListNames(text: string): string[] {
  const open = text.indexOf('{')
  if (open < 0) return []
  const close = text.indexOf('}', open)
  const body = close >= 0 ? text.slice(open + 1, close) : text.slice(open + 1)
  const out: string[] = []
  for (const raw of body.split(',')) {
    const segment = raw.trim()
    if (segment.length === 0) continue
    const aliased = /\bas\s+(.+)$/.exec(segment)
    const token = (aliased?.[1] ?? segment).trim()
    const quoted = /^(['"])(.*)\1$/.exec(token)
    if (quoted !== null) {
      // A string alias is an export name no identifier regex would accept;
      // taking it verbatim is exactly the over-report bias this extractor owes.
      if ((quoted[2] ?? '').length > 0) out.push(quoted[2] as string)
      continue
    }
    if (IDENTIFIER.test(token)) out.push(token)
  }
  return out
}

/**
 * Declarator names for `const/let/var`, annotation-tolerant. The declarator
 * list (`x = 1, y: T = 2`) is split on commas that sit *outside* every bracket
 * pair (paren/brace/bracket, string-literal aware), so an initializer's own
 * commas — arrow parameters, call arguments, object literals — never shatter a
 * declarator. Each segment is then read one of two ways:
 *
 * - a **plain declarator** counts when it *starts* with `identifier =`,
 *   `identifier: Type`, or ends after the bare identifier. The `:` arm is the
 *   point of the tolerance: a capture requiring `identifier =` silently
 *   dropped `export const x: number = 1` — the name vanished, the surface diff
 *   came back empty, and the api-surface-unchanged obligation was vacuously
 *   met for the most idiomatic TypeScript there is. The segment (not the raw
 *   line) is what the regex anchors on, which is also what keeps annotated
 *   arrow parameters (`(a: number, b: string) => …`) from leaking as phantom
 *   exports: they are inside the segment's parens, not at its head.
 * - a **destructuring declarator** (`{…}` / `[…]`) reports every pattern
 *   identifier *inside the group* — aliases, defaults, rest elements and
 *   nested patterns all report (over-inclusive, never blind) — and nothing
 *   after the group: the type annotation (`: Foo`) and initializer (`= obj`)
 *   that follow the closing bracket are not names, and reading them as such
 *   minted phantom exports.
 */
function declaratorNames(rest: string): string[] {
  const out: string[] = []
  for (const raw of splitDeclarators(rest)) {
    const segment = raw.trim()
    if (segment.length === 0) continue
    const head = segment[0] as string
    if (head === '{' || head === '[') {
      out.push(...patternNames(segment))
    } else {
      const name = /^([A-Za-z_$][\w$]*)\s*(?:[:=]|$)/.exec(segment)?.[1]
      if (name !== undefined) out.push(name)
    }
  }
  return out
}

/**
 * Split a declarator list on top-level commas only. Depth counts `(`/`[`/`{`
 * pairs; quoted spans (single, double, backtick) are skipped whole so a comma
 * or bracket inside a string alias or default value cannot fool the boundary
 * scan. Depth is clamped at zero so a stray closer degrades to "no more
 * splits" — the first declarator still reports — instead of desynchronising
 * every later boundary.
 */
function splitDeclarators(text: string): string[] {
  const segments: string[] = []
  let depth = 0
  let start = 0
  let i = 0
  while (i < text.length) {
    const ch = text[i] as string
    if (ch === '\'' || ch === '"' || ch === '`') { i = skipQuoted(text, i); continue }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1
    else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1)
    else if (ch === ',' && depth === 0) {
      segments.push(text.slice(start, i))
      start = i + 1
    }
    i += 1
  }
  segments.push(text.slice(start))
  return segments
}

/**
 * Index just past the quoted span starting at `start` (escapes honoured; an
 * unterminated quote swallows the rest of the text rather than resuming the
 * scan mid-string).
 */
function skipQuoted(text: string, start: number): number {
  const quote = text[start] as string
  let i = start + 1
  while (i < text.length) {
    const ch = text[i] as string
    if (ch === '\\') { i += 2; continue }
    if (ch === quote) return i + 1
    i += 1
  }
  return i
}

/**
 * Pattern identifiers of a destructuring declarator: every identifier token
 * between the opening `{`/`[` and its matching close (aliases `b: x` report
 * both sides, nested `{ a: { b } }` reports the inner names too), and nothing
 * beyond the close — the annotation and initializer that follow are not part
 * of the pattern.
 */
function patternNames(segment: string): string[] {
  const close = matchingClose(segment)
  const group = close < 0 ? segment : segment.slice(0, close)
  const out: string[] = []
  for (const token of group.split(/[^\w$]+/)) {
    if (IDENTIFIER.test(token)) out.push(token)
  }
  return out
}

/**
 * Index just past the bracket matching `segment[0]`, or `-1` when the group
 * never closes cleanly (malformed line): the caller then treats the whole
 * segment as pattern, which keeps the over-report bias on the side of naming
 * too much rather than going blind.
 */
function matchingClose(segment: string): number {
  const want = segment[0] === '{' ? '}' : ']'
  let depth = 0
  let i = 0
  while (i < segment.length) {
    const ch = segment[i] as string
    if (ch === '\'' || ch === '"' || ch === '`') { i = skipQuoted(segment, i); continue }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1
      if (depth === 0) return ch === want ? i + 1 : -1
      if (depth < 0) return -1
    }
    i += 1
  }
  return -1
}

// ---------------------------------------------------------------------------
// Docs classification
// ---------------------------------------------------------------------------

const DOC_EXTS: ReadonlySet<string> = new Set([
  '.md', '.markdown', '.txt', '.rst', '.adoc',
  '.png', '.jpg', '.gif', '.svg', '.webp', '.pdf',
])

/**
 * True when a path is a pure documentation / outside-config asset: a docs
 * extension AND not a global invalidator. The second clause matters because
 * `requirements-dev.txt` carries a docs extension while being exactly the kind
 * of dependency declaration whose change invalidates every check — a docs-only
 * claim over it would launder a config change past the jury. The invalidator
 * set is `GLOBAL_INVALIDATORS` from `core/impact.ts`, imported so the two
 * modules can never drift.
 */
export function isDocsPath(rel: string): boolean {
  const dot = rel.lastIndexOf('.')
  const ext = dot < 0 ? '' : rel.slice(dot).toLowerCase()
  return DOC_EXTS.has(ext) && !isGlobalInvalidator(rel)
}

/**
 * Mirrors `SOURCE_EXT` in `core/impact.ts` (which keeps it module-private to
 * avoid widening its export surface mid-batch): a RelPath counts as source
 * when its extension says code. Duplicated under this provenance note rather
 * than re-exported; keep the two in sync.
 */
const SOURCE_EXT = /\.(m|c)?(j|t)sx?$|\.py$|\.go$|\.rs$|\.java$|\.kt$|\.rb$|\.php$|\.cs$/

function isSourcePath(rel: string): boolean {
  return SOURCE_EXT.test(rel)
}

// ---------------------------------------------------------------------------
// Obligation evaluation
// ---------------------------------------------------------------------------

/** Everything `evaluateContract` needs; `graph` is accepted for engine
 * convenience but deliberately unused — verdicts must stay recomputable from
 * the evidence log alone, and a dependency graph is not evidence. */
export interface ContractInput {
  readonly contract: ClaimContract
  /** RelPaths changed this session. */
  readonly changed: readonly string[]
  /** Every discovered check. */
  readonly specs: readonly CheckSpec[]
  /** Evidence records produced by this run (may contain re-runs). */
  readonly records: readonly Evidence[]
  /** The baseline the run is differentially judged against, if one exists. */
  readonly baseline: Baseline | undefined
  /** Engine-read `baseline.apiSurface`; `undefined` = baseline predates capture. */
  readonly apiSurfaceBefore: readonly string[] | undefined
  /** Engine-computed current surface; `undefined` = engine did not provide it. */
  readonly apiSurfaceAfter: readonly string[] | undefined
  /** Engine dependency graph, tolerated for signature symmetry, never consulted. */
  readonly graph: unknown | undefined
  /**
   * Attestations read off the chain (ι), for `llm-jury` claims. Optional so
   * pre-ι callers (and every other kind) pass their old shape untouched;
   * `undefined` simply means "no testimony on record", which fails
   * `jury-delivered` rather than the whole evaluation. Shapes are re-validated
   * and gens resolved by `activeAttestations` — this input is chain data, not
   * a promise.
   */
  readonly attestations?: readonly Attestation[]
  /**
   * ο: latest evidence per check, read off the store by the engine
   * (`store.latest()`). `new-paths-covered` uses it as a *fallback*: a
   * changed source path with no covering pass among this run's records may
   * still be covered by the latest passing evidence on record. Organic
   * passes carry that coverage as-is — stale independent evidence is
   * stronger than fresh self-written evidence, so if the fallback opens at
   * all, refusing the organic case would be incoherent. Synthetic passes
   * (record `source`/`synthetic` markers) carry it visibly *discounted*:
   * met stays true, but the detail says so, and the Bayesian layer already
   * prices the underlying check lower. Optional and absent in pre-ο callers;
   * without it the obligation judges exactly as it did before.
   */
  readonly latestByCheckId?: ReadonlyMap<string, Evidence>
}

export interface ContractVerdict {
  readonly kind: ClaimKind
  /** `zero-regressions` first, then the kind's obligations in fixed order. */
  readonly obligations: readonly ObligationResult[]
  /** Present only for a fully-met docs-only contract: the jury's confidence cap. */
  readonly juryCappedConfidence?: number
  /** True only for docs-only and llm-jury: the engine may skip dispatching checks entirely. */
  readonly skipChecks: boolean
}

/**
 * Judge a typed claim against the evidence. Obligation ids are stable — the
 * engine and tooling wire on them — and their order is fixed: `zero-regressions`
 * always first, then the kind-specific obligations in the order the kinds are
 * documented. All multi-value details are sorted, so the verdict string is a
 * pure function of the input.
 */
export function evaluateContract(input: ContractInput, juryConfidenceCap = 0.8): ContractVerdict {
  const kind = input.contract.kind
  const obligations: ObligationResult[] = [zeroRegressionsObligation(input)]
  if (kind === 'behavior-preserving') {
    obligations.push(apiSurfaceObligation(input))
  } else if (kind === 'behavior-adding') {
    obligations.push(newPathsObligation(input))
  } else if (kind === 'perf-budget') {
    obligations.push(benchmarkEvidenceObligation(input), withinBudgetObligation(input))
  } else if (kind === 'llm-jury') {
    obligations.push(juryDeliveredObligation(input), juryUpholdsObligation(input))
  } else {
    obligations.push(docsOnlyChangesObligation(input), juryReviewObligation(input))
  }
  // The cap is emitted only next to a fully-met contract: a regression record
  // arriving under a docs-only claim must never share a verdict with a number.
  const allMet = obligations.every(o => o.met)
  return {
    kind,
    obligations,
    ...(kind === 'docs-only' && allMet ? { juryCappedConfidence: juryConfidenceCap } : {}),
    // llm-jury joins docs-only in skipping checks — but for the opposite
    // reason: docs-only has nothing worth measuring, llm-jury has *decided*
    // its verdict is testimony, and running checks anyway would let a machine
    // record quietly override (or launder) a jury the claim never asked for.
    skipChecks: kind === 'docs-only' || kind === 'llm-jury',
  }
}

/** Latest record per check — mirrors `EvidenceStore.latest()` (later wins). */
function latestByCheck(records: readonly Evidence[]): Map<string, Evidence> {
  const map = new Map<string, Evidence>()
  for (const record of records) map.set(record.checkId, record)
  return map
}

/** The shared floor: no check this run may have regressed against the baseline. */
function zeroRegressionsObligation(input: ContractInput): ObligationResult {
  // docs-only runs no checks (skipChecks), so "no regressions in records" is
  // vacuous there; the obligation is honestly re-homed onto docs-only-changes,
  // which is the check that actually binds for that kind. llm-jury gets the
  // same vacuous treatment (ι): a jury claim runs no machine checks either,
  // and its regression burden is carried by the deliberation obligations.
  const kind = input.contract.kind
  if ((kind === 'docs-only' || kind === 'llm-jury') && input.records.length === 0) {
    return {
      id: 'zero-regressions',
      met: true,
      detail: kind === 'docs-only'
        ? 'docs-only claims run no checks — the regression obligation is carried by docs-only-changes instead'
        : 'llm-jury claims run no machine checks — the regression obligation is carried by the jury deliberation (jury-delivered, jury-upholds) instead',
    }
  }
  const baselineById = new Map((input.baseline?.checks ?? []).map(e => [e.checkId, e]))
  const currentById = latestByCheck(input.records)
  const regressed: string[] = []
  let compared = 0
  for (const s of [...input.specs].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    const current = currentById.get(s.id)
    if (current === undefined) continue
    compared += 1
    if (verdictOf(baselineById.get(s.id), current) === 'regression') regressed.push(s.id)
  }
  if (regressed.length > 0) {
    return {
      id: 'zero-regressions',
      met: false,
      detail: `regressed check(s): ${regressed.sort().join(', ')} — fix the failure or revert the change before claiming`,
    }
  }
  return {
    id: 'zero-regressions',
    met: true,
    detail: compared === 0
      ? 'no check produced evidence this run — nothing to compare against the baseline'
      : `${compared} check(s) compared against the baseline, 0 regressions`,
  }
}

/** behavior-preserving: the public API face must not move in either direction. */
function apiSurfaceObligation(input: ContractInput): ObligationResult {
  if (input.apiSurfaceBefore === undefined) {
    return {
      id: 'api-surface-unchanged',
      met: false,
      detail: 'baseline predates API-surface capture — re-run proof_baseline to record an apiSurface, then claim behavior-preserving again',
    }
  }
  if (input.apiSurfaceAfter === undefined) {
    return {
      id: 'api-surface-unchanged',
      met: false,
      detail: 'engine did not provide the current API surface (apiSurfaceAfter undefined) — preservation cannot be attested',
    }
  }
  const { added, removed } = diffApiSurface(input.apiSurfaceBefore, input.apiSurfaceAfter)
  if (added.length === 0 && removed.length === 0) {
    return {
      id: 'api-surface-unchanged',
      met: true,
      detail: `API surface identical across ${input.apiSurfaceAfter.length} exported symbol(s)`,
    }
  }
  const parts: string[] = []
  if (added.length > 0) parts.push(`added: ${added.join(', ')}`)
  if (removed.length > 0) parts.push(`removed: ${removed.join(', ')}`)
  return { id: 'api-surface-unchanged', met: false, detail: `public API changed — ${parts.join('; ')}` }
}

/**
 * behavior-adding: every changed source path is covered by a passing check.
 *
 * Coverage has a primary and a fallback source (ο):
 * - **Primary** — a spec whose `paths` match the file and whose *latest
 *   record this run* is a pass. Unchanged from pre-ο behavior, except that
 *   a *synthetic* covering pass is named in the detail: the check that
 *   passed was written by a party to the claim, and "met" must not read as
 *   independent confirmation (the Bayesian layer already prices the check
 *   lower; the detail owes the same honesty to the human reader).
 * - **Fallback** — when this run produced no covering pass anywhere, the
 *   latest evidence on record (`input.latestByCheckId`) may still cover the
 *   file: an organic pass carries coverage directly — stale independent
 *   evidence is stronger than fresh self-written evidence, so if the
 *   fallback opens at all, refusing the organic case would be incoherent;
 *   a synthetic pass carries the same "covered by synthetic evidence
 *   (discounted)" annotation as a this-run one.
 *
 * The fallback never *un-covers* anything — it can only rescue paths the run
 * happened not to touch with a passing check.
 */
function newPathsObligation(input: ContractInput): ObligationResult {
  const currentById = latestByCheck(input.records)
  const sourceFiles = [...new Set(input.changed)].filter(isSourcePath).sort()
  if (sourceFiles.length === 0) {
    return { id: 'new-paths-covered', met: true, detail: 'no source paths in the change set' }
  }
  const runCovered: string[] = []
  const organicCovered: string[] = []
  const syntheticCovered: string[] = []
  const uncovered: string[] = []
  for (const file of sourceFiles) {
    // Fresh beats stale, organic beats synthetic: a this-run pass describes
    // the workspace as it is now; within a tier, an independent check's pass
    // is the stronger statement about the same workspace.
    if (hasCoveringPass(input, currentById, file, 'run')) { runCovered.push(file); continue }
    if (hasCoveringPass(input, currentById, file, 'run-synthetic')) { syntheticCovered.push(file); continue }
    if (hasCoveringPass(input, input.latestByCheckId, file, 'latest')) { organicCovered.push(file); continue }
    if (hasCoveringPass(input, input.latestByCheckId, file, 'latest-synthetic')) { syntheticCovered.push(file); continue }
    uncovered.push(file)
  }
  if (uncovered.length > 0) {
    return {
      id: 'new-paths-covered',
      met: false,
      detail: `not covered by any passing check: ${uncovered.join(', ')} — add a check whose paths cover them and make it pass`,
    }
  }
  if (syntheticCovered.length === 0 && organicCovered.length === 0) {
    return {
      id: 'new-paths-covered',
      met: true,
      detail: `all ${sourceFiles.length} changed source path(s) covered by a passing check`,
    }
  }
  // Fallback or synthetic coverage participated: say so, per bucket, in
  // fixed clause order so the detail is a pure function of the input.
  const clauses: string[] = [
    `${runCovered.length} by a passing check this run`,
  ]
  if (organicCovered.length > 0) {
    clauses.push(`${organicCovered.length} by the latest on-record pass`)
  }
  if (syntheticCovered.length > 0) {
    clauses.push(`${syntheticCovered.length} covered by synthetic evidence (discounted)`)
  }
  return {
    id: 'new-paths-covered',
    met: true,
    detail: `all ${sourceFiles.length} changed source path(s) covered: ${clauses.join(', ')}`,
  }
}

/**
 * Whether `file` has a covering pass in the given record map, at the wanted
 * tier: `'run'`/`'run-synthetic'` consult this run's latest-per-check
 * records, `'latest'`/`'latest-synthetic'` the engine-supplied
 * latest-on-record map; the `-synthetic` variants match only synthetic
 * checks, the plain ones only organic checks — the caller's tier ladder then
 * states the preference order once, instead of interleaving it with the
 * matching logic. Specs are scanned in id order (deterministic; any covering
 * pass in the class suffices).
 */
function hasCoveringPass(
  input: ContractInput,
  records: ReadonlyMap<string, Evidence> | undefined,
  file: string,
  tier: 'run' | 'run-synthetic' | 'latest' | 'latest-synthetic',
): boolean {
  if (records === undefined) return false
  const wantSynthetic = tier === 'run-synthetic' || tier === 'latest-synthetic'
  return input.specs.some(s =>
    matchesAny(file, s.paths)
    && records.get(s.id)?.status === 'pass'
    && isSyntheticRecord(input, records.get(s.id) as Evidence) === wantSynthetic)
}

/**
 * Whether a record addresses a synthetic check. The record's own markers are
 * the authority (`source` / `synthetic`, both written at makeEvidence time);
 * the spec pool is the fallback for pre-ο-shaped records that predate the
 * `source` field, so old logs stay interpretable against a live spec list.
 */
function isSyntheticRecord(input: ContractInput, record: Evidence): boolean {
  if (record.synthetic !== undefined) return true
  if (record.source !== undefined) return record.source === 'synthetic'
  return input.specs.some(s => s.id === record.checkId && s.source === 'synthetic')
}

/**
 * The benchmark records that can carry a perf-budget claim: latest per check,
 * decisive (`pass`|`fail` — a failed benchmark is still a measurement, it just
 * cannot be within budget), and benchmark-flavoured via either the record's
 * own kind or the spec it addressed (config minted the spec; the record may
 * predate a re-kind).
 */
function benchmarkRecords(input: ContractInput): Evidence[] {
  const specById = new Map(input.specs.map(s => [s.id, s]))
  const currentById = latestByCheck(input.records)
  return [...currentById.keys()].sort()
    .map(id => currentById.get(id) as Evidence)
    .filter(r =>
      (r.status === 'pass' || r.status === 'fail')
      && (r.kind === 'benchmark' || specById.get(r.checkId)?.kind === 'benchmark'))
}

/** perf-budget, obligation 1: a benchmark actually ran to a decisive outcome. */
function benchmarkEvidenceObligation(input: ContractInput): ObligationResult {
  const found = benchmarkRecords(input)
  if (found.length === 0) {
    return {
      id: 'benchmark-evidence',
      met: false,
      detail: 'no benchmark check produced decisive evidence this run — configure a check with kind: benchmark and let it finish',
    }
  }
  return { id: 'benchmark-evidence', met: true, detail: `benchmark evidence on record: ${found.map(r => r.checkId).join(', ')}` }
}

/** perf-budget, obligation 2: the measurement is inside the stated budget. */
function withinBudgetObligation(input: ContractInput): ObligationResult {
  const budget = input.contract.budgetMs
  if (budget === undefined) {
    return {
      id: 'within-budget',
      met: false,
      detail: 'perf-budget claim requires contract.budgetMs — state the number of milliseconds the benchmark must stay under',
    }
  }
  // H-29: a non-finite budget is not a budget. `1e999` parses to Infinity and
  // used to sail through (`durationMs > Infinity` is always false — the
  // obligation was vacuously met for any benchmark, so a performance claim's
  // budget component was decorative). Non-positive budgets are refused for
  // the same reason: a bound that cannot bind is a misdelivery of the
  // contract, and the honest answer is not-met with the fix stated.
  if (!Number.isFinite(budget) || budget <= 0) {
    return {
      id: 'within-budget',
      met: false,
      detail: `contract.budgetMs must be a finite positive number of milliseconds, got ${budget} — restate the budget the benchmark must actually stay under`,
    }
  }
  const found = benchmarkRecords(input)
  if (found.length === 0) {
    return { id: 'within-budget', met: false, detail: 'no benchmark evidence to compare against the budget — see benchmark-evidence' }
  }
  // NaN-safe comparison: a record whose durationMs is not a finite number
  // fails `<= budget` and lands in offenders (a NaN duration cannot be
  // "within" anything), instead of slipping past a `>` that is false for NaN.
  const offenders = found.filter(r => !(r.durationMs <= budget))
  if (offenders.length > 0) {
    return {
      id: 'within-budget',
      met: false,
      detail: `over budget: ${offenders.map(r => `${r.checkId} took ${r.durationMs}ms > ${budget}ms`).join('; ')}`,
    }
  }
  return { id: 'within-budget', met: true, detail: `${found.length} benchmark(s) within the ${budget}ms budget` }
}

/** docs-only, obligation 1: everything that changed really is a docs asset. */
function docsOnlyChangesObligation(input: ContractInput): ObligationResult {
  const changed = [...new Set(input.changed)].sort()
  if (changed.length === 0) {
    return { id: 'docs-only-changes', met: true, detail: 'change set is empty — nothing non-documentary to catch' }
  }
  const offenders = changed.filter(f => !isDocsPath(f))
  if (offenders.length === 0) {
    return { id: 'docs-only-changes', met: true, detail: `all ${changed.length} changed path(s) are docs-only assets` }
  }
  return {
    id: 'docs-only-changes',
    met: false,
    detail: `non-document change(s): ${offenders.join(', ')} — code changes need a different ClaimKind (e.g. behavior-adding) and its obligations`,
  }
}

/** docs-only, obligation 2: the author left a self-review for the jury. */
function juryReviewObligation(input: ContractInput): ObligationResult {
  const review = input.contract.review
  if (typeof review === 'string' && review.trim().length > 0) {
    return { id: 'jury-review', met: true, detail: `jury self-review on record: "${review.trim().slice(0, 120)}"` }
  }
  return {
    id: 'jury-review',
    met: false,
    detail: 'docs-only claims require contract.review — write down what a human reviewer should double-check',
  }
}

// ---------------------------------------------------------------------------
// llm-jury obligations (ι)
// ---------------------------------------------------------------------------

/**
 * The probability an upholding verdict must carry before the contract calls
 * the claim upheld. 0.5 is the coherence floor for "probability the claim is
 * true": an uphold below it is a juror contradicting its own number, and the
 * obligation owes the claim more than a coin-flip.
 */
const UPHOLD_PROBABILITY_MIN = 0.5

/**
 * The active Class B verdict for the contract's claim, or `undefined`.
 *
 * Bindings, deliberately narrow: the attestation's `claimId` must equal
 * `claimIdOf(contract.claim)` — testimony transfers between reworded claims
 * for free otherwise — and only `attest/jury` carries here; a human
 * endorsement is Class C evidence and must not satisfy a Class B obligation.
 * `activeAttestations` re-validates shapes and resolves appeal generations,
 * so a superseded (gen-lower) uphold cannot carry the obligation once a
 * re-deliberation exists.
 */
function activeJuryVerdict(input: ContractInput): JuryAttestation | undefined {
  const want = claimIdOf(input.contract.claim)
  const active = activeAttestations(input.attestations ?? [])
    .filter(att => att.claimId === want && att.kind === 'attest/jury')
  return active.length > 0 ? (active[0] as JuryAttestation) : undefined
}

/** llm-jury, obligation 1: a jury deliberation for this claim is on the chain. */
function juryDeliveredObligation(input: ContractInput): ObligationResult {
  const att = activeJuryVerdict(input)
  if (att === undefined) {
    return {
      id: 'jury-delivered',
      met: false,
      detail: 'no Class B jury verdict on record for this claim — call proof_jury with the claim, then proof_jury_submit to record the deliberation',
    }
  }
  // Any delivered verdict — including abstain — satisfies delivery: the
  // juror showed up and answered. Whether the answer *helps* the claim is
  // entirely jury-upholds' question; keeping the two apart is what lets an
  // abstention be honest evidence without being a pass.
  return {
    id: 'jury-delivered',
    met: true,
    detail: `jury deliberation on record: ${att.model} (gen ${att.gen}, independence: ${att.independence}, verdict: ${att.verdict})`,
  }
}

/** llm-jury, obligation 2: the active verdict upholds the claim at ≥ 0.5. */
function juryUpholdsObligation(input: ContractInput): ObligationResult {
  const att = activeJuryVerdict(input)
  if (att === undefined) {
    return { id: 'jury-upholds', met: false, detail: 'no jury verdict to uphold the claim — see jury-delivered' }
  }
  if (att.verdict === 'uphold') {
    // H-30 note: a coherent uphold carries p ≥ 0.5 by construction —
    // `parseJury` refuses the contradictory records at the chain-read
    // boundary — so this threshold branch is defense for records arriving
    // through other doors (pre-parsed inputs), not the chain path.
    if (att.probability >= UPHOLD_PROBABILITY_MIN) {
      return {
        id: 'jury-upholds',
        met: true,
        detail: `jury upholds at probability ${att.probability} (threshold ${UPHOLD_PROBABILITY_MIN})`,
      }
    }
    return {
      id: 'jury-upholds',
      met: false,
      detail: `jury said uphold but only at probability ${att.probability} < ${UPHOLD_PROBABILITY_MIN} — the claim needs a stronger verdict (or a better-evidenced re-deliberation)`,
    }
  }
  if (att.verdict === 'reject') {
    return {
      id: 'jury-upholds',
      met: false,
      detail: `jury verdict reject at probability ${att.probability} that the claim is true — the deliberation contradicts the claim`,
    }
  }
  return {
    id: 'jury-upholds',
    met: false,
    detail: `jury abstained at probability ${att.probability} — the materials were insufficient to uphold the claim; supply better context and re-deliberate`,
  }
}
