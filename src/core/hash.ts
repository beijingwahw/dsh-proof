/**
 * Canonicalisation + content addressing.
 *
 * Every evidence record is addressed by the digest of its *canonical* form, so
 * two runs that produced the same observable outcome collapse to the same id.
 * That is what makes an evidence chain recomputable: a reader can re-hash the
 * record and check it still addresses itself, and a `proofRoot` can be compared
 * across sessions without trusting the writer.
 *
 * @module dsh-proof/core/hash
 */

import { createHash } from 'node:crypto'

/**
 * Deterministic JSON: object keys sorted recursively, `undefined` dropped,
 * numbers normalised through `String()` so `-0` and `0` agree.
 */
export function canonicalJson(value: unknown): string {
  return stringify(value)
}

function stringify(value: unknown): string {
  if (value === null) return 'null'
  const t = typeof value
  if (t === 'number') return Number.isFinite(value as number) ? JSON.stringify(Object.is(value, -0) ? 0 : value) : 'null'
  if (t === 'boolean' || t === 'string') return JSON.stringify(value)
  if (t === 'bigint') return JSON.stringify(String(value))
  if (t === 'undefined' || t === 'function' || t === 'symbol') return 'null'
  if (Array.isArray(value)) return `[${value.map(stringify).join(',')}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort()
  return `{${keys.map(k => `${JSON.stringify(k)}:${stringify(obj[k])}`).join(',')}}`
}

/** SHA-256 of a UTF-8 string, hex-encoded. */
export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/** Content address of any canonicalisable value: `sha256(canonicalJson(v))`. */
export function addressOf(value: unknown): string {
  return sha256(canonicalJson(value))
}

/**
 * Merkle-style root over a set of addresses: the digest of the sorted,
 * newline-joined addresses. Order-independent, so re-derivation cannot be
 * faked by shuffling the evidence, and stable under re-runs.
 */
export function merkleRoot(addresses: Iterable<string>): string {
  const sorted = [...addresses].sort()
  return sha256(sorted.join('\n'))
}

/**
 * Roots substituted out of captured output before hashing, making evidence
 * location-independent: the same outcome on any machine, under any checkout
 * directory, yields the same digest — which is what cross-session dedupe,
 * cross-machine comparison, and third-party recomputation all rest on.
 * `root` (more specific) is replaced before `home` (less specific), so a
 * workspace under the user's home still collapses to `$WORKSPACE/...`.
 */
export interface NormalizeOptions {
  readonly root?: string
  readonly home?: string
}

export function normalizeOutput(raw: string, opts: NormalizeOptions = {}): string {
  let text = raw.replace(/\r\n/g, '\n')
  for (const variant of pathVariants(opts.root)) text = substituteLiteral(text, variant, '$WORKSPACE')
  for (const variant of pathVariants(opts.home)) text = substituteLiteral(text, variant, '$HOME')
  const lines = text
    .split('\n')
    .map(line => line.replace(/[ \t]+$/g, ''))
    .map(line => line.replace(/\b\d+(\.\d+)?\s?(ms|s|sec|secs|seconds|minutes|min)\b/gi, '<duration>'))
    .map(line => line.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<timestamp>'))
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return lines.join('\n')
}

/** A path and its slash-flipped twin, so Windows output matches in both styles. */
function pathVariants(path: string | undefined): string[] {
  if (path === undefined || path.length === 0) return []
  const flipped = path.replace(/\\/g, '/')
  return path === flipped ? [path] : [path, flipped]
}

/**
 * A root always appears in output as a *complete path prefix*, so a match is
 * only meaningful when it ends at a path boundary: separator, quote,
 * whitespace, or end of line/text. Without the anchor, root `/app` would chew
 * into `/application` and mint `$WORKSPACElication` — a false equivalence (or
 * false diff) between two different locations in a content-addressed digest.
 * The lookahead consumes nothing, so every legitimately-prefixed path
 * substitutes exactly as it did before the guard existed.
 */
const PATH_BOUNDARY = "(?=[/\\\\'\"`\\s]|$)"

function substituteLiteral(text: string, literal: string, placeholder: string): string {
  if (literal.length === 0) return text
  const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return text.replace(new RegExp(escaped + PATH_BOUNDARY, 'g'), placeholder)
}
