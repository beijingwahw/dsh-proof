/**
 * Tamper-evidence for the evidence log: a hash chain, signed checkpoints,
 * and an out-of-band anchor.
 *
 * Threat model this module exists for: the *agent itself* is the adversary.
 * Self-addressing alone (`audit()` re-hashing every record) only catches
 * naive tampering — an agent that can write files can rewrite the whole log
 * and recompute every self-consistent address with the very functions this
 * package exports. Three mechanisms close that hole:
 *
 * 1. **Hash chain** — every appended line carries `prev = sha256(previous
 *    line)`, so editing or removing any line breaks the link into the next.
 * 2. **Signed checkpoints** — a checkpoint records `{count, head}` and is
 *    signed with a host-held key the model cannot read (see `SignerPort`).
 *    The agent can chain-forge all day; it cannot forge a signature.
 * 3. **Out-of-band anchor** — the highest checkpoint ever written is also
 *    stored next to the key, outside the workspace. Truncating or rewinding
 *    the log to before that checkpoint is detected as a rewind.
 *
 * Honest limits: records appended *after* the last checkpoint are chain-
 * covered but not checkpoint-covered; that window is bounded by
 * `checkpointEvery`, and every baseline/verify/claim boundary closes it.
 *
 * @module dsh-proof/core/trust
 */

import { canonicalJson, sha256 } from './hash.ts'

/** `prev` of the first line ever appended to a log. */
export const GENESIS_PREV = sha256('dsh-proof/chain/genesis')

/** sha256 of one appended log line (excluding its trailing newline). */
export function lineDigest(line: string): string {
  return sha256(line)
}

/** What a checkpoint attests: how many records, and the chain head at that point. */
export interface CheckpointPayload {
  /** Evidence + marker records that precede this checkpoint. */
  readonly count: number
  /** Chain head digest when the checkpoint was appended. */
  readonly head: string
  /** Stable identity of the workspace this log belongs to, when known. */
  readonly workspaceKey: string | null
  readonly at: string
}

/** Out-of-band high-water mark, stored next to the signing key. */
export interface AnchorFile {
  readonly v: 1
  readonly keyId: string
  readonly count: number
  readonly head: string
  readonly sig: string
  readonly at: string
  /**
   * The workspace identity the signature commits to. Optional because anchors
   * written before this field existed are still valid high-water marks —
   * auditors skip (rather than fail) signature verification for them.
   */
  readonly workspaceKey?: string
}

export interface WalkedCheckpoint {
  /** Index of the checkpoint line within the log. */
  readonly index: number
  readonly payload: CheckpointPayload
  /** Detached signature over `canonicalJson(payload)`, when signed. */
  readonly sig: string | null
  readonly keyId: string | null
  /** Chain head the walker expected at this position. */
  readonly expectedHead: string
  /**
   * Records (evidence + marker lines) the walker counted *before* this
   * checkpoint line — exactly what an honest writer stamps into
   * `payload.count` (`EvidenceStore` does not count checkpoints themselves).
   * The self-reported count is judged against this walked count: an attacker
   * who rewrites the log can recompute `head` with this package's own
   * functions, but it cannot make a forged `count` survive comparison with
   * the walk — the walked count is derived, not self-declared.
   */
  readonly expectedCount: number
}

export type ChainMode = 'signed' | 'unsigned' | 'legacy'

export interface ChainWalk {
  /** `signed` once any checkpoint carries a signature; `legacy` for v1-only logs. */
  readonly mode: ChainMode
  /** Evidence + marker records seen (v1 and v2). */
  readonly records: number
  /** Line indexes whose `prev` does not match the previous line's digest. */
  readonly chainBreaks: readonly number[]
  /** Lines that are not valid v1/v2 envelopes. */
  readonly corruptLines: readonly number[]
  readonly checkpoints: readonly WalkedCheckpoint[]
  /**
   * Line indexes of checkpoints whose self-reported `count` the walk itself
   * refutes: not a non-negative safe integer, or not equal to the records
   * actually walked to that position. Purely structural failures (a non-number
   * count, a non-string head) stay in `corruptLines` — this list is for counts
   * that are well-shaped but *lying* (`1e999` parses to `Infinity` and passes
   * any `typeof` check, which is exactly the laundering trick).
   */
  readonly malformedCheckpoints: readonly number[]
  /** Records appended after the last well-formed checkpoint (0 when the tail is covered). */
  readonly tailRecords: number
}

/**
 * Walk the log and verify chain linkage. Pure: no I/O, no signature checks —
 * the store layer does cryptographic verification with its own signer.
 *
 * Chain rule: each v2 line's `prev` must equal the digest of the physically
 * previous line (of any kind), so legacy v1 lines participate in the chain
 * once a v2 line follows them.
 */
export function walkChain(lines: readonly string[]): ChainWalk {
  let sawV1 = false
  let sawV2 = false
  let records = 0
  const chainBreaks: number[] = []
  const corruptLines: number[] = []
  const checkpoints: WalkedCheckpoint[] = []
  const malformedCheckpoints: number[] = []

  let prevDigest = GENESIS_PREV
  lines.forEach((line, index) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch {
      corruptLines.push(index)
      prevDigest = lineDigest(line)
      return
    }
    const envelope = parsed as { v?: unknown; kind?: unknown; prev?: unknown; sig?: unknown; keyId?: unknown; payload?: unknown }
    if (envelope !== null && typeof envelope === 'object' && envelope.v === 1) {
      sawV1 = true
      if (envelope.kind === 'evidence' || envelope.kind === 'marker') records += 1
      prevDigest = lineDigest(line)
      return
    }
    if (envelope !== null && typeof envelope === 'object' && envelope.v === 2 && typeof envelope.prev === 'string'
      && typeof envelope.kind === 'string') {
      sawV2 = true
      if (envelope.prev !== prevDigest) chainBreaks.push(index)
      if (envelope.kind === 'checkpoint') {
        const payload = envelope.payload as Partial<CheckpointPayload>
        if (typeof payload?.count === 'number' && typeof payload?.head === 'string') {
          // Records walked to this line is the count an honest writer stamps
          // (checkpoints are not themselves counted), so the self-report is
          // judged against the walk, not against arithmetic the writer chose.
          const expectedCount = records
          checkpoints.push({
            index,
            payload: {
              count: payload.count,
              head: payload.head,
              workspaceKey: typeof payload.workspaceKey === 'string' ? payload.workspaceKey : null,
              at: typeof payload.at === 'string' ? payload.at : '',
            },
            sig: typeof envelope.sig === 'string' ? envelope.sig : null,
            keyId: typeof envelope.keyId === 'string' ? envelope.keyId : null,
            expectedHead: prevDigest,
            expectedCount,
          })
          if (!isWellFormedCount(payload.count, expectedCount)) malformedCheckpoints.push(index)
        } else {
          corruptLines.push(index)
        }
      } else if (envelope.kind === 'evidence' || envelope.kind === 'marker') {
        records += 1
      }
      prevDigest = lineDigest(line)
      return
    }
    corruptLines.push(index)
    prevDigest = lineDigest(line)
  })

  const mode: ChainMode = sawV2
    ? (checkpoints.some(cp => cp.sig !== null) ? 'signed' : 'unsigned')
    : (sawV1 ? 'legacy' : 'unsigned')
  // Tail cover is measured from the last checkpoint whose count the walk
  // corroborates. A forged count — inflated to Infinity or merely past the
  // truth — used to zero out the tail (`records - ∞` clamped to 0) and
  // launder a rewrite as "fully checkpoint-covered"; against the walked
  // `expectedCount` the same forgery is malformed and the true tail survives.
  // Honest logs are byte-identical: there `count === expectedCount`.
  const malformed = new Set(malformedCheckpoints)
  const lastGood = checkpoints.findLast(cp => !malformed.has(cp.index))
  const tailRecords = lastGood === undefined ? records : Math.max(0, records - lastGood.expectedCount)

  return { mode, records, chainBreaks, corruptLines, checkpoints, malformedCheckpoints, tailRecords }
}

/**
 * A checkpoint count is well-formed when it is a non-negative safe integer
 * equal to the records the walk counted to that position. Out-of-range or
 * fractional self-reports (`1e999` → `Infinity`, `-1`, `2.5`) and inflated or
 * deflated ones fail alike — the walked count is the only admissible truth.
 */
function isWellFormedCount(count: number, expectedCount: number): boolean {
  return Number.isSafeInteger(count) && count >= 0 && count === expectedCount
}

/** Parse and validate an anchor file's contents; `undefined` when unreadable. */
export function parseAnchor(raw: string | undefined): AnchorFile | undefined {
  if (raw === undefined) return undefined
  try {
    const value = JSON.parse(raw) as Partial<AnchorFile>
    if (value?.v !== 1) return undefined
    if (typeof value.keyId !== 'string' || typeof value.count !== 'number' || typeof value.head !== 'string') return undefined
    return {
      v: 1,
      keyId: value.keyId,
      count: value.count,
      head: value.head,
      sig: typeof value.sig === 'string' ? value.sig : '',
      at: typeof value.at === 'string' ? value.at : '',
      // Present only on newer anchors; absence is tolerated (older anchor,
      // sig check skipped by the audit layer, data checks still apply).
      ...(typeof value.workspaceKey === 'string' ? { workspaceKey: value.workspaceKey } : {}),
    }
  } catch {
    return undefined
  }
}

/** The exact bytes a checkpoint signature commits to. */
export function checkpointSignedData(payload: CheckpointPayload): string {
  return canonicalJson(payload)
}
