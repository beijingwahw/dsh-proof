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
  /**
   * Why this checkpoint carries no signature, as recorded by the writer at
   * append time: a transient signing failure, or a refusal under the
   * `SIG_REFUSED_PREFIX` banner (the writer's own audit found the physical
   * chain tampered and declined to lend the forged bytes its key). The
   * distinction is the only signal that separates an honest unsigned boundary
   * from an attacker's stripped signature — the walk surfaces it so the audit
   * layer (M-33/H-32) can adjudicate instead of guessing.
   */
  readonly sigError: string | null
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
   *
   * v0.22 (L-A1-11): v2 lines of an *unknown kind* are listed here too. No
   * honest writer emits a kind outside {evidence, marker, checkpoint}; a line
   * that parses, chains, and then claims a kind the protocol never defined is
   * smuggling payload through the walk's counting rules, and the audit must
   * see it rather than let it ride the chain silently.
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
    const envelope = parsed as { v?: unknown; kind?: unknown; prev?: unknown; sig?: unknown; keyId?: unknown; sigError?: unknown; payload?: unknown }
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
            sigError: typeof envelope.sigError === 'string' ? envelope.sigError : null,
            expectedHead: prevDigest,
            expectedCount,
          })
          if (!isWellFormedCount(payload.count, expectedCount)) malformedCheckpoints.push(index)
        } else {
          corruptLines.push(index)
        }
      } else if (envelope.kind === 'evidence' || envelope.kind === 'marker') {
        records += 1
      } else {
        // A v2 envelope of a kind no honest writer emits (L-A1-11): it chains
        // and parses, but nothing in the protocol vouches for what it is or
        // how it counts. Named as malformed — loud, not silent.
        malformedCheckpoints.push(index)
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

/**
 * v0.22 (H-32/M-33): the `sigError` banner under which the store records that
 * it *refused* to sign a checkpoint because its own pre-sign audit found the
 * physical chain tampered (H-27) — as opposed to a transient signing failure
 * ("key directory locked by a scanner"). The walk carries the string; the
 * audit splits the two into different channels with different `ok` semantics.
 */
export const SIG_REFUSED_PREFIX = 'refused-to-sign'

/**
 * v0.22 (H-09): the discriminated result of reading an anchor document.
 *
 * - no outcome at all (`undefined`) — no anchor file exists: a deployment
 *   fact, silent as ever.
 * - `problem: 'unparseable'` — a file exists but is not an anchor shape
 *   (garbage JSON, wrong version, missing/mistyped required fields). The
 *   out-of-band line of defence cannot be consulted: an auditor-side
 *   capability gap, surfaced as `anchorUnreadable`, never an accusation.
 * - `problem: 'invalid'` — anchor-shaped but in a state **no honest writer
 *   produces**: an empty `keyId`, a `count` outside the non-negative safe
 *   integers, or an empty/absent `sig` (the four-line disarm family — an
 *   honest anchor is only ever written after a successful `sign()`, so it
 *   always carries a non-empty signature and a count the writer actually
 *   walked). Such a file is tampering until proven otherwise: surfaced as
 *   `anchorInvalid` and a failing `ok`, never silently tolerated.
 * - `anchor` — a fully well-formed anchor; adjudicate it.
 */
export interface AnchorParseOutcome {
  readonly anchor?: AnchorFile
  readonly problem?: 'unparseable' | 'invalid'
}

/**
 * Parse an anchor document into a {@link AnchorParseOutcome}; `undefined`
 * means "no document at all" (no file / nothing to read).
 */
export function parseAnchorEx(raw: string | undefined): AnchorParseOutcome | undefined {
  if (raw === undefined) return undefined
  let value: Partial<AnchorFile>
  try {
    value = JSON.parse(raw) as Partial<AnchorFile>
  } catch {
    return { problem: 'unparseable' }
  }
  if (value === null || typeof value !== 'object' || value.v !== 1) return { problem: 'unparseable' }
  // Shape: the fields every anchor carries must be present with the right
  // type. `sig` is the exception — an absent signature is shape-legal text
  // but domain-dishonest (see below), so it is normalised here and charged
  // as `invalid`, keeping "cannot parse" and "parses but lies" separable.
  if (typeof value.keyId !== 'string' || typeof value.count !== 'number' || typeof value.head !== 'string') {
    return { problem: 'unparseable' }
  }
  if (value.workspaceKey !== undefined && typeof value.workspaceKey !== 'string') return { problem: 'unparseable' }
  const sig = typeof value.sig === 'string' ? value.sig : ''
  // Domain: no honest writer can produce these values (H-09). `-5`, `1e999`
  // and `2.5` counts, an empty keyId, a stripped signature — each is the
  // documented disarm recipe, and each now fails loudly instead of
  // silently switching the anchor's checks off.
  if (value.keyId === '' || sig === '' || !Number.isSafeInteger(value.count) || value.count < 0) {
    return { problem: 'invalid' }
  }
  return {
    anchor: {
      v: 1,
      keyId: value.keyId,
      count: value.count,
      head: value.head,
      sig,
      at: typeof value.at === 'string' ? value.at : '',
      // Present only on newer anchors; absence is tolerated (older anchor,
      // sig check reconstructed against workspaceKey: null by the audit
      // layer, data checks still apply).
      ...(typeof value.workspaceKey === 'string' ? { workspaceKey: value.workspaceKey } : {}),
    },
  }
}

/**
 * Parse and validate an anchor file's contents; `undefined` when unreadable
 * *or* when the document is a domain-invalid disarm shape (see
 * {@link parseAnchorEx} — callers that need the distinction use that).
 */
export function parseAnchor(raw: string | undefined): AnchorFile | undefined {
  return parseAnchorEx(raw)?.anchor
}

/** The exact bytes a checkpoint signature commits to. */
export function checkpointSignedData(payload: CheckpointPayload): string {
  return canonicalJson(payload)
}
