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
 * Normalise captured process output before hashing so that cosmetic churn does
 * not invalidate evidence: line endings unified, trailing whitespace stripped,
 * absolute workspace paths replaced with a placeholder, and lines carrying
 * timestamps/durations collapsed.
 */
export function normalizeOutput(raw: string, opts: { root?: string } = {}): string {
  let text = raw.replace(/\r\n/g, '\n')
  if (opts.root) {
    const escaped = opts.root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    text = text.replace(new RegExp(escaped, 'g'), '$WORKSPACE')
  }
  const lines = text
    .split('\n')
    .map(line => line.replace(/[ \t]+$/g, ''))
    .map(line => line.replace(/\b\d+(\.\d+)?\s?(ms|s|sec|secs|seconds|minutes|min)\b/gi, '<duration>'))
    .map(line => line.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<timestamp>'))
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return lines.join('\n')
}
