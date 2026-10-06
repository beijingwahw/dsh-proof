/**
 * Proof Transparency Log — the workspace checkpoints go public.
 *
 * The workspace evidence chain already ends every run in a signed checkpoint
 * `{count, head, workspaceKey, at}` (Ed25519 over canonical JSON, `keyId`
 * naming the signer). But a checkpoint only proves "this is where I was" — it
 * says nothing about whether the *history* leading there was ever rewritten.
 * This module turns the sequence of checkpoints into an append-only Merkle
 * log in the shape of RFC 6962 (certificate transparency), so that three
 * questions become independently checkable by anyone holding only public
 * data:
 *
 * 1. **Inclusion** — a given checkpoint is in the log at a given sequence
 *    number (`inclusionProof` / `verifyInclusion`).
 * 2. **Append-only** — the log never rewrote itself: every older signed tree
 *    head (STH) is still derivable from every newer one
 *    (`consistencyProof` / `verifyConsistency`).
 * 3. **Monotonic time** — sequence numbers only grow, and `savePtlHead`
 *    refuses to sign a head that rewinds size or timestamp.
 *
 * The log is a *dumb notary*: it does NOT verify the workspace signatures it
 * carries (that is the auditor's job, done with the workspace public key);
 * it performs ordered, byte-addressed appending and signs tree heads. Its
 * entire integrity story is "two people shown different histories can prove
 * the divergence" — the split-view detector: rewrite one entry in the middle
 * and the root moves, so one of the two STH signatures is provably not a
 * prefix of the other.
 *
 * **Why canonical JSON inside the leaf hash.** The leaf hash is taken over
 * `canonicalJson(entry)` — sorted keys, normalised numbers — never over
 * insertion-ordered `JSON.stringify`. A transparency log's whole value is
 * that *other implementations* (other languages, other auditors, RFC 6962
 * tooling) can recompute the same tree from the same entries; a byte order
 * that depends on which field the local serialiser happened to write first
 * would make every root implementation-private. Canonical bytes are the
 * interoperability contract.
 *
 * **Merkle semantics note.** `TransparencyLog.merkleRoot()` is the RFC 6962
 * *ordered* tree hash — NOT the order-independent set hash exported as
 * `merkleRoot` from `./hash.ts` (used for unordered evidence sets). Same
 * word, deliberately different mathematics: a transparency log must be
 * sensitive to entry ORDER (swapping two log lines is a different history
 * and must move the root), while an evidence set must not be. Callers
 * integrating this (T2/T3) must never substitute one for the other.
 *
 * **Implementation path.** The tree, audit paths, and consistency proofs are
 * *direct recursive translations* of RFC 6962 §2 (MTH), §2.1.1 (PATH) and
 * §2.1.2 (SUBPROOF) — k is the largest power of two smaller than n, the
 * recursion splits `[0,k)` / `[k,n)`, and the proof list appends the current
 * level's node after the recursive part, exactly as the RFC's `:` operator
 * does. Verification is implemented as the exact mirror of generation (a
 * fold that consumes the proof walking the same recursion), not as the
 * widely-miscopied iterative `fn/sn` variant; the mirror cannot drift from
 * the generator because it *is* the generator run backwards, and the test
 * suite pins it against the RFC's own §2.1.3 worked example. Producer
 * methods throw `RangeError` on bad indices (programmer error on data the
 * log itself owns); verifier functions are total and answer `false` to any
 * adversarial input, because a verifier must never crash on forgeries.
 *
 * Determinism: everything here is a pure function of its inputs. No clock
 * (timestamps are supplied and recorded, never generated), no randomness;
 * `node:crypto`'s SHA-256 and `Buffer` are the only environment used, same
 * discipline as `./hash.ts`.
 *
 * @module dsh-proof/core/transparency
 */

import { createHash } from 'node:crypto'
import { Buffer } from 'node:buffer'

import { canonicalJson, sha256 } from './hash.ts'
import type { FsPort } from './ports.ts'

// ---------------------------------------------------------------------------
// Log entries and leaf hashing (RFC 6962 §2, domain separation)
// ---------------------------------------------------------------------------

/** RFC 6962 domain-separation prefixes: leaves are 0x00, internal nodes 0x01. */
const LEAF_PREFIX = 0x00
const NODE_PREFIX = 0x01

/**
 * One checkpoint as appended to the transparency log: the workspace's own
 * signed checkpoint payload plus the signature the log hosts verbatim.
 * The log does not verify `sig` — it notarises bytes, and auditors adjudicate
 * them with the workspace public key identified by `keyId`.
 */
export interface PtlEntry {
  /** Format version. */
  readonly v: 1
  /** Workspace the checkpoint summarises. */
  readonly workspaceKey: string
  /** keyId of the workspace checkpoint signer. */
  readonly keyId: string
  /** Checkpoint payload: number of evidence records at `head`. */
  readonly count: number
  /** Checkpoint payload: chain head digest. */
  readonly head: string
  /** Checkpoint payload: ISO timestamp supplied by the workspace. */
  readonly at: string
  /** Workspace signature over the checkpoint bytes — hosted, not checked. */
  readonly sig: string
}

/** SHA-256 over raw bytes, hex-encoded — the module's only hash primitive. */
function h256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

/**
 * RFC 6962 leaf hash: `SHA-256(0x00 || canonicalJson(entry))`.
 *
 * The 0x00 domain-separation prefix (vs 0x01 for internal nodes) is what
 * gives the tree second-preimage resistance; the canonical-JSON body is what
 * keeps the leaf address computable by any implementation, not just this one.
 */
export function ptlLeafHash(entry: PtlEntry): string {
  return h256(Buffer.concat([Buffer.from([LEAF_PREFIX]), Buffer.from(canonicalJson(entry), 'utf8')]))
}

/** RFC 6962 internal node: `SHA-256(0x01 || left || right)` over the raw 32-byte digests. */
function nodeHash(leftHex: string, rightHex: string): string {
  return h256(Buffer.concat([Buffer.from([NODE_PREFIX]), Buffer.from(leftHex, 'hex'), Buffer.from(rightHex, 'hex')]))
}

/** `MTH({}) = SHA-256()` — the RFC's empty-tree root (hash of zero bytes). */
const EMPTY_TREE_ROOT = sha256('')

/** A sha256 hex digest (64 lowercase hex chars) — the shape of every proof node. */
function isHashShape(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value)
}

/** A non-negative safe integer — the shape of every size and index. */
function isSafeNat(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0
}

/**
 * The largest power of two strictly smaller than `n` (RFC 6962's k, i.e.
 * `k < n <= 2k`). Requires `n >= 2`. Computed with integer bit length, not
 * `Math.log2`, so it is exact up to the safe-integer range.
 */
function largestPowerOfTwoBelow(n: number): number {
  return 2 ** (31 - Math.clz32(n - 1))
}

// ---------------------------------------------------------------------------
// RFC 6962 §2 MTH, §2.1.1 PATH, §2.1.2 SUBPROOF — generation
// ---------------------------------------------------------------------------

/**
 * `MTH(D[lo:hi])` over pre-hashed leaves. The per-call memo makes repeated
 * proof generation over the same tree linear-ish instead of recomputing
 * subtree hashes; `merkleRoot()` itself needs no memo (a full-tree walk is
 * already one node visit per hash).
 */
function mth(leaves: readonly string[], lo: number, hi: number, memo: Map<string, string>): string {
  const n = hi - lo
  if (n === 0) return EMPTY_TREE_ROOT
  if (n === 1) return leaves[lo] as string
  const key = `${lo}:${hi}`
  const cached = memo.get(key)
  if (cached !== undefined) return cached
  const k = largestPowerOfTwoBelow(n)
  const root = nodeHash(mth(leaves, lo, lo + k, memo), mth(leaves, lo + k, hi, memo))
  memo.set(key, root)
  return root
}

/**
 * RFC 6962 §2.1.1 audit path for leaf `m` within `[lo, hi)`:
 *
 *     PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])   for m <  k
 *     PATH(m, D[n]) = PATH(m-k, D[k:n]) : MTH(D[0:k]) for m >= k
 *
 * Elements come out leaf-to-root (the recursive part first, the current
 * level's sibling appended after), exactly the RFC's `:` ordering.
 */
function auditPath(leaves: readonly string[], m: number, lo: number, hi: number, memo: Map<string, string>): string[] {
  const n = hi - lo
  if (n === 1) return []
  const k = largestPowerOfTwoBelow(n)
  if (m < k) {
    return [...auditPath(leaves, m, lo, lo + k, memo), mth(leaves, lo + k, hi, memo)]
  }
  return [...auditPath(leaves, m - k, lo + k, hi, memo), mth(leaves, lo, lo + k, memo)]
}

/**
 * RFC 6962 §2.1.2 SUBPROOF for the first `m` leaves of `[lo, hi)`.
 * `anchored` is the RFC's boolean b: when true, the subtree hash for an
 * exactly-m-sized range is already known to the *verifier* (it is the old
 * root the proof is anchored on) and emits no node; when false, the base
 * case emits the subtree root itself:
 *
 *     SUBPROOF(m, D[m], true)  = {}
 *     SUBPROOF(m, D[m], false) = {MTH(D[m])}
 *     SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b)  : MTH(D[k:n]) if m <= k
 *     SUBPROOF(m, D[n], b) = SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k]) if m > k
 *
 * Note the RFC's `false` on the m > k descent: once the old range spans the
 * split point, the left subtree is fully old, and the recursion must start
 * committing nodes because nothing above is "already known" anymore.
 */
function subProof(
  leaves: readonly string[], m: number, lo: number, hi: number, anchored: boolean, memo: Map<string, string>,
): string[] {
  const n = hi - lo
  if (m === n) return anchored ? [] : [mth(leaves, lo, hi, memo)]
  const k = largestPowerOfTwoBelow(n)
  if (m <= k) {
    return [...subProof(leaves, m, lo, lo + k, anchored, memo), mth(leaves, lo + k, hi, memo)]
  }
  return [...subProof(leaves, m - k, lo + k, hi, false, memo), mth(leaves, lo, lo + k, memo)]
}

// ---------------------------------------------------------------------------
// Verification — the exact mirror of generation, as a fold over the proof
// ---------------------------------------------------------------------------

/** Cursor into a proof list shared across the fold recursion. */
interface ProofCursor { i: number }

/**
 * Fold an audit path for leaf `m` in `[lo, hi)` into the reconstructed root,
 * or `null` when the proof runs out mid-structure. This walks the same
 * recursion as `auditPath` but combines instead of emitting, so generator and
 * verifier cannot disagree about ordering.
 */
function foldAuditPath(
  running: string, m: number, lo: number, hi: number, proof: readonly string[], pos: ProofCursor,
): string | null {
  const n = hi - lo
  if (n === 1) return running
  const k = largestPowerOfTwoBelow(n)
  if (m < k) {
    const left = foldAuditPath(running, m, lo, lo + k, proof, pos)
    if (left === null || pos.i >= proof.length) return null
    const sibling = proof[pos.i] as string
    pos.i += 1
    return nodeHash(left, sibling)
  }
  const right = foldAuditPath(running, m - k, lo + k, hi, proof, pos)
  if (right === null || pos.i >= proof.length) return null
  const sibling = proof[pos.i] as string
  pos.i += 1
  return nodeHash(sibling, right)
}

/**
 * The two roots a consistency proof reconstructs: `old` for the first-m
 * prefix (must end up equal to the verifier's old root) and `new` for the
 * whole range (must end up equal to the new root).
 */
interface ConsistencyFold { oldRoot: string; newRoot: string }

/**
 * Fold SUBPROOF's structure: recursing where the old range lives, consuming
 * one proof node per level to extend both running roots. `anchor` carries
 * the known old root for the RFC's b=true base case; `null` means every
 * node must come from the proof (b=false).
 */
function foldConsistency(
  m: number, lo: number, hi: number, anchor: string | null, proof: readonly string[], pos: ProofCursor,
): ConsistencyFold | null {
  const n = hi - lo
  if (m === n) {
    if (anchor !== null) return { oldRoot: anchor, newRoot: anchor }
    if (pos.i >= proof.length) return null
    const node = proof[pos.i] as string
    pos.i += 1
    return { oldRoot: node, newRoot: node }
  }
  const k = largestPowerOfTwoBelow(n)
  if (m <= k) {
    // Right subtree D[k:n] is new-only: it extends the new root, the old
    // root passes through untouched.
    const sub = foldConsistency(m, lo, lo + k, anchor, proof, pos)
    if (sub === null || pos.i >= proof.length) return null
    const right = proof[pos.i] as string
    pos.i += 1
    return { oldRoot: sub.oldRoot, newRoot: nodeHash(sub.newRoot, right) }
  }
  // Left subtree D[0:k] is fully old AND fully new: it prepends to both
  // roots, and the recursion loses its anchor (RFC b := false).
  const sub = foldConsistency(m - k, lo + k, hi, null, proof, pos)
  if (sub === null || pos.i >= proof.length) return null
  const left = proof[pos.i] as string
  pos.i += 1
  return { oldRoot: nodeHash(left, sub.oldRoot), newRoot: nodeHash(left, sub.newRoot) }
}

// ---------------------------------------------------------------------------
// Signed tree heads
// ---------------------------------------------------------------------------

/** The log operator's signed commitment to a tree state. */
export interface SignedTreeHead {
  /** keyId of the log operator (public-key identity of whoever runs the log). */
  readonly logId: string
  /** Number of entries committed. */
  readonly treeSize: number
  /** `MTH(entries[0:treeSize])`. */
  readonly root: string
  /** ISO timestamp supplied by the operator. */
  readonly at: string
  /** Operator signature over `sthSignedData` of these fields. */
  readonly sig: string
}

/** The exact bytes an STH signature commits to (canonical key order). */
export function sthSignedData(sth: Omit<SignedTreeHead, 'sig'>): string {
  return canonicalJson({ logId: sth.logId, treeSize: sth.treeSize, root: sth.root, at: sth.at })
}

/**
 * Verify an STH with the caller's signature check (the operator's public
 * key). Pure plumbing: signature over the signed data, nothing else.
 */
export async function verifyTreeHead(
  sth: SignedTreeHead,
  verify: (data: string, sig: string) => Promise<boolean>,
): Promise<boolean> {
  return (await verify(sthSignedData(sth), sth.sig)) === true
}

// ---------------------------------------------------------------------------
// The log itself
// ---------------------------------------------------------------------------

/**
 * An in-memory transparency log: an ordered, append-only list of checkpoint
 * entries with RFC 6962 proofs over their leaf hashes. Duplicate leaf hashes
 * are idempotent (a replayed checkpoint is the same event, not a new one),
 * which is what keeps restart-replays of a workspace's checkpoints from
 * polluting the sequence.
 */
export class TransparencyLog {
  private readonly _entries: PtlEntry[]
  private readonly _leafHashes: string[]
  private readonly _indexByLeafHash: Map<string, number>

  constructor(entries: readonly PtlEntry[] = []) {
    this._entries = [...entries]
    this._leafHashes = this._entries.map(entry => ptlLeafHash(entry))
    this._indexByLeafHash = new Map()
    for (let i = 0; i < this._leafHashes.length; i += 1) {
      const h = this._leafHashes[i] as string
      // First occurrence wins, so a duplicate built from a stored copy keeps
      // the sequence number the line was originally appended under.
      if (!this._indexByLeafHash.has(h)) this._indexByLeafHash.set(h, i)
    }
  }

  /** Number of entries appended so far. */
  get size(): number {
    return this._entries.length
  }

  /** The entries, in sequence order. */
  get entries(): readonly PtlEntry[] {
    return this._entries
  }

  /** RFC 6962 MTH over all leaves; the empty log's root is `SHA-256()`. */
  merkleRoot(): string {
    return mth(this._leafHashes, 0, this._leafHashes.length, new Map())
  }

  /**
   * Append one entry. A byte-identical replay (same leaf hash) appends
   * nothing and reports the existing sequence with `duplicate: true`; a new
   * entry gets sequence `size - 1` after appending (0-based).
   */
  append(entry: PtlEntry): { sequence: number; duplicate: boolean } {
    const h = ptlLeafHash(entry)
    const existing = this._indexByLeafHash.get(h)
    if (existing !== undefined) return { sequence: existing, duplicate: true }
    const sequence = this._entries.length
    this._entries.push(entry)
    this._leafHashes.push(h)
    this._indexByLeafHash.set(h, sequence)
    return { sequence, duplicate: false }
  }

  /**
   * RFC 6962 §2.1.1 audit path for `index` in the first `treeSize` entries.
   * `treeSize` defaults to the current size; passing a smaller value proves
   * inclusion against a historical STH. Throws `RangeError` on out-of-range
   * arguments — this is the producer side, operating on data the log owns.
   */
  inclusionProof(index: number, treeSize: number = this._entries.length): readonly string[] {
    if (!isSafeNat(index) || !isSafeNat(treeSize)) {
      throw new RangeError(`inclusionProof: index and treeSize must be non-negative integers`)
    }
    if (treeSize < 1 || treeSize > this._entries.length) {
      throw new RangeError(`inclusionProof: treeSize ${treeSize} outside the log (size ${this._entries.length})`)
    }
    if (index >= treeSize) {
      throw new RangeError(`inclusionProof: index ${index} outside treeSize ${treeSize}`)
    }
    return auditPath(this._leafHashes, index, 0, treeSize, new Map())
  }

  /**
   * RFC 6962 §2.1.2 consistency proof that the first `first` entries of the
   * first `second` entries form the old tree (`first === second` yields the
   * empty identity proof). RFC domain is `0 < m <= n`; a zero `first` is
   * rejected because consistency with an empty tree carries no information
   * the empty root does not. Throws `RangeError` on bad ranges.
   */
  consistencyProof(first: number, second: number): readonly string[] {
    if (!isSafeNat(first) || !isSafeNat(second)) {
      throw new RangeError(`consistencyProof: sizes must be non-negative integers`)
    }
    if (first < 1 || first > second || second > this._entries.length) {
      throw new RangeError(`consistencyProof: ${first}->${second} outside the log (size ${this._entries.length})`)
    }
    return subProof(this._leafHashes, first, 0, second, true, new Map())
  }
}

// ---------------------------------------------------------------------------
// Independent verifiers — total functions over adversarial input
// ---------------------------------------------------------------------------

/**
 * Verify an RFC 6962 inclusion proof: does `proof` fold `entry`'s leaf hash
 * at `index` up to `root` for a tree of `treeSize` leaves? Answers `false`
 * — never throws — for out-of-range indices, wrong-length proofs, non-hash
 * proof elements, and any mismatch, because a verifier faces forgeries and
 * must adjudicate them, not crash on them.
 */
export function verifyInclusion(
  entry: PtlEntry, index: number, treeSize: number, proof: readonly string[], root: string,
): boolean {
  if (!isSafeNat(index) || !isSafeNat(treeSize)) return false
  if (treeSize < 1 || index >= treeSize) return false
  if (proof.some(node => !isHashShape(node))) return false
  const pos: ProofCursor = { i: 0 }
  const computed = foldAuditPath(ptlLeafHash(entry), index, 0, treeSize, proof, pos)
  // pos.i === proof.length pins the exact expected length: a proof that is
  // too short leaves the cursor shy of the root; too long and the fold has
  // already failed structurally (null) or would consume past the tree.
  return computed !== null && pos.i === proof.length && computed === root
}

/**
 * Verify an RFC 6962 consistency proof: do `oldSize`/`oldRoot` still hold as
 * a prefix of `newSize`/`newRoot`? `newSize < oldSize` (a truncated log) is
 * adjudicated `false`, not thrown — it is exactly the forgery this function
 * exists to catch. `oldSize === newSize` is the identity case: valid only
 * with an empty proof and equal roots. `oldSize === 0` is outside the RFC's
 * domain (`0 < m`) and answers `false`.
 */
export function verifyConsistency(
  oldSize: number, oldRoot: string, newSize: number, newRoot: string, proof: readonly string[],
): boolean {
  if (!isSafeNat(oldSize) || !isSafeNat(newSize)) return false
  if (oldSize < 1 || newSize < oldSize) return false
  if (!isHashShape(oldRoot) || !isHashShape(newRoot)) return false
  if (proof.some(node => !isHashShape(node))) return false
  if (oldSize === newSize) return proof.length === 0 && oldRoot === newRoot
  const pos: ProofCursor = { i: 0 }
  const folded = foldConsistency(oldSize, 0, newSize, oldRoot, proof, pos)
  return folded !== null && pos.i === proof.length && folded.oldRoot === oldRoot && folded.newRoot === newRoot
}

// ---------------------------------------------------------------------------
// Storage — a thin JSONL + head-file layer over FsPort
// ---------------------------------------------------------------------------

/**
 * Layout descriptor for a transparency log on an FsPort: everything lives
 * under `dir` as
 *
 * - `ptl-entries.jsonl` — one `canonicalJson(PtlEntry)` per line, append order
 *   = sequence order; malformed lines are skipped on load (and counted),
 *   because one torn write must not render the whole log unreadable;
 * - `sth.json` — the latest signed tree head, written atomically.
 */
export interface PtlStorage { readonly dir: string }

const ENTRIES_FILENAME = 'ptl-entries.jsonl'
const HEAD_FILENAME = 'sth.json'

function under(dir: string, name: string): string {
  return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`
}

/** Parse one JSONL line into an entry; `undefined` when malformed. */
function parseEntryLine(line: string): PtlEntry | undefined {
  let value: unknown
  try {
    value = JSON.parse(line)
  } catch {
    return undefined
  }
  if (typeof value !== 'object' || value === null) return undefined
  const p = value as Record<string, unknown>
  if (p.v !== 1) return undefined
  if (
    typeof p.workspaceKey !== 'string' || typeof p.keyId !== 'string' || typeof p.head !== 'string'
    || typeof p.at !== 'string' || typeof p.sig !== 'string' || typeof p.count !== 'number'
    || !isSafeNat(p.count)
  ) return undefined
  // Rebuild from known fields only, so unknown extras on a stored line can
  // never smuggle bytes into the leaf hash: the canonical 7-field entry IS
  // the leaf, whatever the line additionally carried.
  return {
    v: 1,
    workspaceKey: p.workspaceKey,
    keyId: p.keyId,
    count: p.count,
    head: p.head,
    at: p.at,
    sig: p.sig,
  }
}

/** Parse sth.json's contents; `undefined` when absent or malformed. */
function parseSthFile(raw: string | undefined): SignedTreeHead | undefined {
  if (raw === undefined) return undefined
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return undefined
  }
  if (typeof value !== 'object' || value === null) return undefined
  const p = value as Record<string, unknown>
  if (
    typeof p.logId !== 'string' || typeof p.treeSize !== 'number' || !isSafeNat(p.treeSize)
    || typeof p.root !== 'string' || typeof p.at !== 'string' || typeof p.sig !== 'string'
  ) return undefined
  return { logId: p.logId, treeSize: p.treeSize, root: p.root, at: p.at, sig: p.sig }
}

/**
 * Load a log from `dir`. Malformed entry lines are skipped and reported in
 * `badLines` (the surviving prefix still verifies — a torn tail is not a
 * veto on the readable history); a missing or malformed `sth.json` loads as
 * `undefined`, meaning "no signed head on record yet" rather than "head
 * absent is an error".
 */
export async function loadPtl(
  fs: FsPort, dir: string,
): Promise<{ log: TransparencyLog; sth: SignedTreeHead | undefined; badLines: number }> {
  const lines = await fs.readLines(under(dir, ENTRIES_FILENAME))
  const entries: PtlEntry[] = []
  let badLines = 0
  for (const line of lines) {
    const entry = parseEntryLine(line)
    if (entry === undefined) {
      badLines += 1
      continue
    }
    entries.push(entry)
  }
  const sth = parseSthFile(await fs.readFile(under(dir, HEAD_FILENAME)))
  return { log: new TransparencyLog(entries), sth, badLines }
}

/**
 * Append one entry to the log in `dir` (load, dedupe by leaf hash, write the
 * line only when it is genuinely new). The line written is
 * `canonicalJson(entry)` — the same bytes the leaf hash committed to, so
 * what is stored is exactly what is proved.
 */
export async function appendPtlEntry(
  fs: FsPort, dir: string, entry: PtlEntry,
): Promise<{ sequence: number; duplicate: boolean }> {
  const { log } = await loadPtl(fs, dir)
  const { sequence, duplicate } = log.append(entry)
  if (!duplicate) await fs.appendLine(under(dir, ENTRIES_FILENAME), canonicalJson(entry))
  return { sequence, duplicate }
}

/**
 * Persist a signed tree head, refusing every rewind of the published head:
 *
 * - `treeSize` smaller than the stored one (a truncated log);
 * - same `treeSize` but a different `root` (a rewritten log);
 * - an `at` earlier than the stored one (timestamps must not go backwards;
 *   compared lexicographically, which orders same-format ISO-8601 stamps).
 *
 * Re-saving the identical head is allowed (idempotent). Any rewind throws:
 * once an operator has signed a head, the only honest next head extends it.
 */
export async function savePtlHead(fs: FsPort, dir: string, sth: SignedTreeHead): Promise<void> {
  const existing = parseSthFile(await fs.readFile(under(dir, HEAD_FILENAME)))
  if (
    existing !== undefined
    && (sth.treeSize < existing.treeSize
      || (sth.treeSize === existing.treeSize && sth.root !== existing.root)
      || sth.at < existing.at)
  ) {
    throw new Error('refusing to rewind the transparency head')
  }
  await fs.writeFile(under(dir, HEAD_FILENAME), canonicalJson(sth))
}
