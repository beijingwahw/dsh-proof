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
 * 3. **Monotonic time & governance** — sequence numbers only grow, and
 *    `savePtlHead` refuses every dishonest successor to a published head:
 *    size rewinds, same-size root swaps, timestamp rewinds (parsed as
 *    instants, refusing unparseable stamps), operator-identity flips, and
 *    — since v0.22 — any larger tree whose old→new prefix consistency
 *    cannot be proven from the entries on disk; and — since v0.23 (X-H-10)
 *    — a stored head whose own signature does not verify under the
 *    operator key the caller holds (a planted `sth.json` must never become
 *    the baseline the operator's next signature vouches for).
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
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { canonicalJson, sha256 } from "./hash.js";
// ---------------------------------------------------------------------------
// Log entries and leaf hashing (RFC 6962 §2, domain separation)
// ---------------------------------------------------------------------------
/** RFC 6962 domain-separation prefixes: leaves are 0x00, internal nodes 0x01. */
const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
/** SHA-256 over raw bytes, hex-encoded — the module's only hash primitive. */
function h256(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}
/**
 * RFC 6962 leaf hash: `SHA-256(0x00 || canonicalJson(entry))`.
 *
 * The 0x00 domain-separation prefix (vs 0x01 for internal nodes) is what
 * gives the tree second-preimage resistance; the canonical-JSON body is what
 * keeps the leaf address computable by any implementation, not just this one.
 */
export function ptlLeafHash(entry) {
    return h256(Buffer.concat([Buffer.from([LEAF_PREFIX]), Buffer.from(canonicalJson(entry), 'utf8')]));
}
/** RFC 6962 internal node: `SHA-256(0x01 || left || right)` over the raw 32-byte digests. */
function nodeHash(leftHex, rightHex) {
    return h256(Buffer.concat([Buffer.from([NODE_PREFIX]), Buffer.from(leftHex, 'hex'), Buffer.from(rightHex, 'hex')]));
}
/** `MTH({}) = SHA-256()` — the RFC's empty-tree root (hash of zero bytes). */
const EMPTY_TREE_ROOT = sha256('');
/** A sha256 hex digest (64 lowercase hex chars) — the shape of every proof node. */
function isHashShape(value) {
    return /^[0-9a-f]{64}$/.test(value);
}
/** A non-negative safe integer — the shape of every size and index. */
function isSafeNat(value) {
    return Number.isSafeInteger(value) && value >= 0;
}
/**
 * The largest power of two strictly smaller than `n` (RFC 6962's k, i.e.
 * `k < n <= 2k`). Requires `n >= 2`. Computed with integer bit length, not
 * `Math.log2`, so it is exact up to the safe-integer range.
 */
function largestPowerOfTwoBelow(n) {
    return 2 ** (31 - Math.clz32(n - 1));
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
function mth(leaves, lo, hi, memo) {
    const n = hi - lo;
    if (n === 0)
        return EMPTY_TREE_ROOT;
    if (n === 1)
        return leaves[lo];
    const key = `${lo}:${hi}`;
    const cached = memo.get(key);
    if (cached !== undefined)
        return cached;
    const k = largestPowerOfTwoBelow(n);
    const root = nodeHash(mth(leaves, lo, lo + k, memo), mth(leaves, lo + k, hi, memo));
    memo.set(key, root);
    return root;
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
function auditPath(leaves, m, lo, hi, memo) {
    const n = hi - lo;
    if (n === 1)
        return [];
    const k = largestPowerOfTwoBelow(n);
    if (m < k) {
        return [...auditPath(leaves, m, lo, lo + k, memo), mth(leaves, lo + k, hi, memo)];
    }
    return [...auditPath(leaves, m - k, lo + k, hi, memo), mth(leaves, lo, lo + k, memo)];
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
function subProof(leaves, m, lo, hi, anchored, memo) {
    const n = hi - lo;
    if (m === n)
        return anchored ? [] : [mth(leaves, lo, hi, memo)];
    const k = largestPowerOfTwoBelow(n);
    if (m <= k) {
        return [...subProof(leaves, m, lo, lo + k, anchored, memo), mth(leaves, lo + k, hi, memo)];
    }
    return [...subProof(leaves, m - k, lo + k, hi, false, memo), mth(leaves, lo, lo + k, memo)];
}
/**
 * Fold an audit path for leaf `m` in `[lo, hi)` into the reconstructed root,
 * or `null` when the proof runs out mid-structure. This walks the same
 * recursion as `auditPath` but combines instead of emitting, so generator and
 * verifier cannot disagree about ordering.
 */
function foldAuditPath(running, m, lo, hi, proof, pos) {
    const n = hi - lo;
    if (n === 1)
        return running;
    const k = largestPowerOfTwoBelow(n);
    if (m < k) {
        const left = foldAuditPath(running, m, lo, lo + k, proof, pos);
        if (left === null || pos.i >= proof.length)
            return null;
        const sibling = proof[pos.i];
        pos.i += 1;
        return nodeHash(left, sibling);
    }
    const right = foldAuditPath(running, m - k, lo + k, hi, proof, pos);
    if (right === null || pos.i >= proof.length)
        return null;
    const sibling = proof[pos.i];
    pos.i += 1;
    return nodeHash(sibling, right);
}
/**
 * Fold SUBPROOF's structure: recursing where the old range lives, consuming
 * one proof node per level to extend both running roots. `anchor` carries
 * the known old root for the RFC's b=true base case; `null` means every
 * node must come from the proof (b=false).
 */
function foldConsistency(m, lo, hi, anchor, proof, pos) {
    const n = hi - lo;
    if (m === n) {
        if (anchor !== null)
            return { oldRoot: anchor, newRoot: anchor };
        if (pos.i >= proof.length)
            return null;
        const node = proof[pos.i];
        pos.i += 1;
        return { oldRoot: node, newRoot: node };
    }
    const k = largestPowerOfTwoBelow(n);
    if (m <= k) {
        // Right subtree D[k:n] is new-only: it extends the new root, the old
        // root passes through untouched.
        const sub = foldConsistency(m, lo, lo + k, anchor, proof, pos);
        if (sub === null || pos.i >= proof.length)
            return null;
        const right = proof[pos.i];
        pos.i += 1;
        return { oldRoot: sub.oldRoot, newRoot: nodeHash(sub.newRoot, right) };
    }
    // Left subtree D[0:k] is fully old AND fully new: it prepends to both
    // roots, and the recursion loses its anchor (RFC b := false).
    const sub = foldConsistency(m - k, lo + k, hi, null, proof, pos);
    if (sub === null || pos.i >= proof.length)
        return null;
    const left = proof[pos.i];
    pos.i += 1;
    return { oldRoot: nodeHash(left, sub.oldRoot), newRoot: nodeHash(left, sub.newRoot) };
}
/** The exact bytes an STH signature commits to (canonical key order). */
export function sthSignedData(sth) {
    return canonicalJson({ logId: sth.logId, treeSize: sth.treeSize, root: sth.root, at: sth.at });
}
/**
 * Verify an STH with the caller's signature check (the operator's public
 * key). Pure plumbing: signature over the signed data, nothing else.
 */
export async function verifyTreeHead(sth, verify) {
    return (await verify(sthSignedData(sth), sth.sig)) === true;
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
    _entries;
    _leafHashes;
    _indexByLeafHash;
    constructor(entries = []) {
        this._entries = [...entries];
        this._leafHashes = this._entries.map(entry => ptlLeafHash(entry));
        this._indexByLeafHash = new Map();
        for (let i = 0; i < this._leafHashes.length; i += 1) {
            const h = this._leafHashes[i];
            // First occurrence wins, so a duplicate built from a stored copy keeps
            // the sequence number the line was originally appended under.
            if (!this._indexByLeafHash.has(h))
                this._indexByLeafHash.set(h, i);
        }
    }
    /** Number of entries appended so far. */
    get size() {
        return this._entries.length;
    }
    /** The entries, in sequence order. */
    get entries() {
        return this._entries;
    }
    /** RFC 6962 MTH over all leaves; the empty log's root is `SHA-256()`. */
    merkleRoot() {
        return mth(this._leafHashes, 0, this._leafHashes.length, new Map());
    }
    /**
     * Append one entry. A byte-identical replay (same leaf hash) appends
     * nothing and reports the existing sequence with `duplicate: true`; a new
     * entry gets sequence `size - 1` after appending (0-based).
     */
    append(entry) {
        const h = ptlLeafHash(entry);
        const existing = this._indexByLeafHash.get(h);
        if (existing !== undefined)
            return { sequence: existing, duplicate: true };
        const sequence = this._entries.length;
        this._entries.push(entry);
        this._leafHashes.push(h);
        this._indexByLeafHash.set(h, sequence);
        return { sequence, duplicate: false };
    }
    /**
     * RFC 6962 §2.1.1 audit path for `index` in the first `treeSize` entries.
     * `treeSize` defaults to the current size; passing a smaller value proves
     * inclusion against a historical STH. Throws `RangeError` on out-of-range
     * arguments — this is the producer side, operating on data the log owns.
     */
    inclusionProof(index, treeSize = this._entries.length) {
        if (!isSafeNat(index) || !isSafeNat(treeSize)) {
            throw new RangeError(`inclusionProof: index and treeSize must be non-negative integers`);
        }
        if (treeSize < 1 || treeSize > this._entries.length) {
            throw new RangeError(`inclusionProof: treeSize ${treeSize} outside the log (size ${this._entries.length})`);
        }
        if (index >= treeSize) {
            throw new RangeError(`inclusionProof: index ${index} outside treeSize ${treeSize}`);
        }
        return auditPath(this._leafHashes, index, 0, treeSize, new Map());
    }
    /**
     * RFC 6962 §2.1.2 consistency proof that the first `first` entries of the
     * first `second` entries form the old tree (`first === second` yields the
     * empty identity proof). RFC domain is `0 < m <= n`; a zero `first` is
     * rejected because consistency with an empty tree carries no information
     * the empty root does not. Throws `RangeError` on bad ranges.
     */
    consistencyProof(first, second) {
        if (!isSafeNat(first) || !isSafeNat(second)) {
            throw new RangeError(`consistencyProof: sizes must be non-negative integers`);
        }
        if (first < 1 || first > second || second > this._entries.length) {
            throw new RangeError(`consistencyProof: ${first}->${second} outside the log (size ${this._entries.length})`);
        }
        return subProof(this._leafHashes, first, 0, second, true, new Map());
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
export function verifyInclusion(entry, index, treeSize, proof, root) {
    if (!isSafeNat(index) || !isSafeNat(treeSize))
        return false;
    if (treeSize < 1 || index >= treeSize)
        return false;
    if (proof.some(node => !isHashShape(node)))
        return false;
    const pos = { i: 0 };
    const computed = foldAuditPath(ptlLeafHash(entry), index, 0, treeSize, proof, pos);
    // pos.i === proof.length pins the exact expected length: a proof that is
    // too short leaves the cursor shy of the root; too long and the fold has
    // already failed structurally (null) or would consume past the tree.
    return computed !== null && pos.i === proof.length && computed === root;
}
/**
 * Verify an RFC 6962 consistency proof: do `oldSize`/`oldRoot` still hold as
 * a prefix of `newSize`/`newRoot`? `newSize < oldSize` (a truncated log) is
 * adjudicated `false`, not thrown — it is exactly the forgery this function
 * exists to catch. `oldSize === newSize` is the identity case: valid only
 * with an empty proof and equal roots. `oldSize === 0` is outside the RFC's
 * domain (`0 < m`) and answers `false`.
 */
export function verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof) {
    if (!isSafeNat(oldSize) || !isSafeNat(newSize))
        return false;
    if (oldSize < 1 || newSize < oldSize)
        return false;
    if (!isHashShape(oldRoot) || !isHashShape(newRoot))
        return false;
    if (proof.some(node => !isHashShape(node)))
        return false;
    if (oldSize === newSize)
        return proof.length === 0 && oldRoot === newRoot;
    const pos = { i: 0 };
    const folded = foldConsistency(oldSize, 0, newSize, oldRoot, proof, pos);
    return folded !== null && pos.i === proof.length && folded.oldRoot === oldRoot && folded.newRoot === newRoot;
}
/**
 * The publish-face selection rule (v0.24, V4-M6): from candidates in LOG
 * ORDER (oldest first, so the array's last element is the newest), scan
 * newest → oldest and let the FIRST candidate whose `canVerify` callback
 * returns `true` win.
 *
 * Why this shape is policy, not convenience. The positional-last candidate is
 * the cheapest thing on the chain to forge (append one well-formed line
 * claiming any keyId with a garbage signature), so a selection that notarises
 * whatever is positionally last hands that line both a veto and a win:
 * first-VERIFIABLE-wins refuses the forgery (it does not verify) while still
 * publishing the newest checkpoint that does — fail-closed against forgeries,
 * available against denial-of-service. A `canVerify` that returns `false` OR
 * THROWS counts as a rejection: the selection never crashes on a forged
 * candidate, exactly as the verifier functions above never do.
 *
 * `canVerify` owns the key material — this function performs no I/O of its
 * own, so the same predicate serves every publisher face (the ptl CLI and
 * the engine's publishCheckpoint) with each face's own signer wiring.
 * Extracted from the CLI's inline loop (v0.23 W9-M5) precisely so the engine
 * face stops carrying a positional-findLast twin of it — the split the
 * v0.23 survey flagged as one face's fix never reaching the other.
 */
export async function selectPublishable(candidates, canVerify) {
    const rejected = [];
    for (let i = candidates.length - 1; i >= 0; i -= 1) {
        const candidate = candidates[i];
        let holds = false;
        try {
            holds = (await canVerify(candidate)) === true;
        }
        catch {
            holds = false; // a verifier that throws on a forgery has adjudicated it false
        }
        if (holds)
            return { chosen: candidate, rejected };
        rejected.push(candidate);
    }
    return { chosen: undefined, rejected };
}
const ENTRIES_FILENAME = 'ptl-entries.jsonl';
const HEAD_FILENAME = 'sth.json';
function under(dir, name) {
    return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`;
}
/** What a caller loses by proceeding when the head's bytes did not arrive. */
const HEAD_READ_CONSEQUENCE = 'treat an unreadable head as "no head on record" and sign over an unknown prior commitment.'
    + ' Retry, or restore sth.json from an out-of-band pinned copy.';
/** What a caller loses by proceeding when the entries' bytes did not arrive. */
const ENTRIES_READ_CONSEQUENCE = 'rewrite the log from an unread snapshot: a read failure must never masquerade'
    + ' as an empty log. Retry the publish, or restore the file from a known-good copy.';
/**
 * V4-L9 (v0.24): `readFile` answered `undefined` — adjudicate whether that
 * means ABSENT (the caller may proceed as a cold start) or FAILED (refuse).
 * `stat` alone cannot tell: `FsPort.stat` folds EVERY error — ENOENT and
 * EACCES/EBUSY alike — into `undefined`, so an existing file locked in a way
 * that fails BOTH its read and its stat used to be indistinguishable from a
 * file that was never there, and the caller proceeded on "absent" evidence
 * over a log it could not see. Absence is now proven POSITIVELY, through the
 * directory listing, in three steps:
 *
 * 1. `stat` still sees the file → present, unreadable → refuse;
 * 2. the directory LISTS: the file's name in it → present (read and stat
 *    both failed under it) → refuse; name absent → proven absent → proceed;
 * 3. the directory cannot be listed: if the directory itself is stat-able,
 *    absence is UNKNOWABLE → refuse; a directory with no evidence of
 *    existing at all is a fresh log directory (the write path creates it),
 *    and that is the honest cold start.
 *
 * Read failure is never downgraded to "not there"; unknown is never accepted
 * as absent.
 */
async function refuseWhenNotProvenAbsent(fs, dir, filename, path, consequence) {
    if ((await fs.stat(path)) !== undefined) {
        throw new Error(`${path} exists but could not be read (read failed; the file is present by stat) — refusing to ${consequence}`);
    }
    const listing = await fs.readDir(dir);
    if (listing !== undefined) {
        if (listing.includes(filename)) {
            throw new Error(`${path} exists but could not be read (the directory listing names ${filename} while its read and stat both failed)`
                + ` — refusing to ${consequence}`);
        }
        return; // the listing positively does not carry the file: genuinely absent
    }
    if ((await fs.stat(dir)) !== undefined) {
        throw new Error(`${path} cannot be proven absent: the directory ${dir} exists but cannot be listed, and the file's own read and stat failed`
            + ` — refusing to ${consequence}`
            + ' Unknown is not absent; retry, or restore from a known-good copy.');
    }
    // Nothing at this path can be shown to exist: a fresh log directory. The
    // caller's write creates the directory; this is the cold start.
}
/** Parse one JSONL line into an entry; `undefined` when malformed. */
function parseEntryLine(line) {
    let value;
    try {
        value = JSON.parse(line);
    }
    catch {
        return undefined;
    }
    if (typeof value !== 'object' || value === null)
        return undefined;
    const p = value;
    if (p.v !== 1)
        return undefined;
    if (typeof p.workspaceKey !== 'string' || typeof p.keyId !== 'string' || typeof p.head !== 'string'
        || typeof p.at !== 'string' || typeof p.sig !== 'string' || typeof p.count !== 'number'
        || !isSafeNat(p.count))
        return undefined;
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
    };
}
/** Parse sth.json's contents; `undefined` when absent or malformed. */
function parseSthFile(raw) {
    if (raw === undefined)
        return undefined;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        return undefined;
    }
    if (typeof value !== 'object' || value === null)
        return undefined;
    const p = value;
    if (typeof p.logId !== 'string' || typeof p.treeSize !== 'number' || !isSafeNat(p.treeSize)
        || typeof p.root !== 'string' || typeof p.at !== 'string' || typeof p.sig !== 'string')
        return undefined;
    return { logId: p.logId, treeSize: p.treeSize, root: p.root, at: p.at, sig: p.sig };
}
/**
 * Read the stored head with PUBLISHER discipline (v0.24). `loadPtl` reads
 * leniently — a missing or malformed head loads as `undefined` because a
 * VERIFIER must adjudicate, never crash. The publisher faces is the opposite
 * side of that coin: it is about to reason from the stored head as its trust
 * baseline and sign over what it anchors, so "the bytes are there but I
 * cannot parse them" is a refusal on BOTH readable-damage axes:
 *
 * - present but UNREADABLE (W9-M8/V4-L9, through refuseWhenNotProvenAbsent's
 *   positive-absence adjudication);
 * - present but UNPARSEABLE (Y-H-06, v0.24): X-H-10 closed the
 *   "shape-perfect planted head" — a stored head whose signature does not
 *   verify — but a head reduced to garbage (`{oops`, a truncated write, an
 *   empty file) still parsed to `undefined` and took the COLD-START branch:
 *   the operator's next append minted a fresh, genuinely-signed STH over a
 *   history whose prior commitment nobody could read. Unparseable is not
 *   "no head on record"; it is a head on record that cannot be consulted.
 *
 * Returns `undefined` ONLY for a head proven absent (or a directory with no
 * evidence of existing — the fresh-log cold start).
 */
async function readStoredHeadStrictly(fs, dir) {
    const headPath = under(dir, HEAD_FILENAME);
    const headRaw = await fs.readFile(headPath);
    if (headRaw === undefined) {
        await refuseWhenNotProvenAbsent(fs, dir, HEAD_FILENAME, headPath, HEAD_READ_CONSEQUENCE);
        return undefined;
    }
    const existing = parseSthFile(headRaw);
    if (existing === undefined) {
        throw new Error(`${headPath} exists but is not a parseable signed tree head (sth.json)`
            + ' — refusing to treat an unparseable head as "no head on record" (a cold start): planting unparseable bytes in sth.json'
            + ' is the cheapest residual of the X-H-10 attack (Y-H-06), and signing the log\'s next head would vouch for whatever'
            + ' commitment those bytes used to carry. Restore sth.json from an out-of-band pinned copy (a previously published STH),'
            + ' or retire this log directory and start a new one');
    }
    return existing;
}
/**
 * Load a log from `dir`. Malformed entry lines are skipped and reported in
 * `badLines` — a line reduced to whitespace by damage counts as bad, not as
 * "not there", so the corruption report cannot under-count (the loader
 * splits the raw file itself for exactly this reason: a port-level blank
 * filter would have deleted the evidence of the deletion). The surviving
 * prefix still verifies — a torn tail is not a veto on the readable
 * history. A missing or malformed `sth.json` loads as `undefined`, meaning
 * "no signed head on record yet" rather than "head absent is an error".
 *
 * `headOvercommits` is present and `true` exactly when the loaded head
 * promises more entries than the file holds (`sth.treeSize > entries`) —
 * the signature of a truncated or disconnected log, stated loudly instead
 * of being discovered as a producer-side `RangeError` by whoever asks for a
 * proof next.
 */
export async function loadPtl(fs, dir) {
    const raw = await fs.readFile(under(dir, ENTRIES_FILENAME));
    const entries = [];
    let badLines = 0;
    if (raw !== undefined) {
        const lines = raw.split('\n');
        if (lines.length > 0 && lines[lines.length - 1] === '')
            lines.pop(); // the newline-terminated file's trailing empty segment
        for (const line of lines) {
            const entry = parseEntryLine(line);
            if (entry === undefined) {
                badLines += 1;
                continue;
            }
            entries.push(entry);
        }
    }
    const sth = parseSthFile(await fs.readFile(under(dir, HEAD_FILENAME)));
    const headOvercommits = sth !== undefined && sth.treeSize > entries.length;
    return {
        log: new TransparencyLog(entries),
        sth,
        badLines,
        ...(headOvercommits ? { headOvercommits: true } : {}),
    };
}
/**
 * Serialise appends to one log directory within THIS process: the
 * load→dedupe→write section is a read-modify-write, and two in-flight calls
 * must not interleave their reads (the engine's own `ptlQueue` serialises
 * its publishes; this queue covers every other caller, including tests).
 * Cross-process races are closed by the write itself — see
 * `appendPtlEntryInternal`.
 */
const appendQueues = new Map();
/**
 * V4-L11 (v0.24): one queue per PHYSICAL log directory, not per spelling.
 * `log`, `log/`, `log//` and `log\` are the same directory to the host; as raw
 * map keys they were up to four queues, and two in-flight appends issued
 * under two spellings interleaved exactly the read-modify-write cycle the
 * queue exists to serialise (both read the same stale file, both wrote a
 * whole-file snapshot, and one line silently lost). Separator-level fold only
 * — backslashes fold to '/', repeated separators collapse, the trailing one
 * drops: over-merging two distinct keys costs a little needless
 * serialisation and is safe, under-merging two spellings of ONE directory is
 * the race. Case is deliberately not folded here: case policy is identity
 * policy (adapters' foldHostPath domain), and on a case-sensitive host two
 * case-colliding paths really are two logs.
 */
function appendQueueKey(dir) {
    return dir.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/+$/, '');
}
/**
 * Append one entry to the log in `dir` (load, dedupe by leaf hash, write the
 * line only when it is genuinely new). The line written is
 * `canonicalJson(entry)` — the same bytes the leaf hash committed to, so
 * what is stored is exactly what is proved.
 *
 * Two storage disciplines (v0.22):
 *
 * - **Torn tails refuse appends** (M-61). A previous crash can leave the
 *   file ending mid-line; appending behind it would splice the new entry
 *   onto the torn remainder — physically one line, parseable as neither —
 *   while reporting success. That silent publication loss is the exact
 *   failure a transparency log exists to prevent, so the append REFUSES,
 *   naming the repair (remove the partial final line or restore a
 *   known-good copy). `EvidenceStore.ensureTail` performs the analogous
 *   repair for the workspace chain; here refusal is the honest choice
 *   because the PTL has no chain of its own to record a repair on.
 * - **Atomic whole-file commit** (M-62). The write is a single
 *   `writeFile` of the full new contents — temp file + rename under
 *   `NodeFsPort`, the same pattern every atomic write in this package
 *   uses — so no interleaving of two writers can tear a line or leave a
 *   half-written file. A racing writer whose view went stale cannot corrupt
 *   the log either: its subsequent `savePtlHead` demands a consistency
 *   proof grounded in the entries on disk and refuses the stale view loudly
 *   instead of letting a rewritten history wear a fresh signature.
 */
export async function appendPtlEntry(fs, dir, entry) {
    const key = appendQueueKey(dir);
    const previous = appendQueues.get(key) ?? Promise.resolve();
    const next = previous.then(() => appendPtlEntryInternal(fs, dir, entry));
    appendQueues.set(key, next.then(() => undefined, () => undefined));
    return next;
}
async function appendPtlEntryInternal(fs, dir, entry) {
    const entriesPath = under(dir, ENTRIES_FILENAME);
    const { log } = await loadPtl(fs, dir);
    const { sequence, duplicate } = log.append(entry);
    if (duplicate)
        return { sequence, duplicate };
    const raw = await fs.readFile(entriesPath);
    // X-H-15b/W9-M8 (v0.23) + V4-L9 (v0.24): "does not exist" and "could not be
    // read" are different facts, and the write below can only tell them apart
    // if we do. FsPort.readFile folds every read failure (EBUSY/EPERM from an AV
    // scan, EISDIR, a transient lock) into `undefined` — the same answer it
    // gives for a file that was never there. Writing `${''}${line}` behind a
    // FAILED read would replace the whole log with one line: the exact
    // destruction a transparency log exists to make impossible. Absence is
    // therefore proven positively (stat, then the directory listing — see
    // refuseWhenNotProvenAbsent); when the file is present in any channel
    // while its bytes did not arrive, the append refuses loudly, and the
    // operator retries or restores while the history survives.
    if (raw === undefined) {
        await refuseWhenNotProvenAbsent(fs, dir, ENTRIES_FILENAME, entriesPath, ENTRIES_READ_CONSEQUENCE);
    }
    if (raw !== undefined && raw.length > 0 && !raw.endsWith('\n')) {
        throw new Error(`${entriesPath} ends in a torn (unterminated) line — refusing to append behind a partial write.`
            + ' Repair the tail (delete the partial final line, or restore the file from a known-good copy) and re-run the publish.');
    }
    await fs.writeFile(entriesPath, `${raw ?? ''}${canonicalJson(entry)}\n`);
    return { sequence, duplicate };
}
/**
 * Persist a signed tree head, refusing every way a new head could fail to
 * be an honest extension of the published one:
 *
 * - a different `logId` — the operator's public identity is part of what
 *   auditors pin; a silent identity flip mid-log would let a rewritten
 *   history wear a "fresh" operator's signature (M-60/A2-M3);
 * - a stored head over ZERO entries — no honest publisher of this log
 *   mints one (heads are signed after appends), and "extending" it would
 *   drive the consistency recursion outside its RFC 6962 domain (`0 < m`)
 *   as a producer-side RangeError (v0.23: adjudicated as a refusal instead
 *   of surfacing as a crash);
 * - a stored head whose own signature does not verify under the caller's
 *   operator key — the planted-head forgery X-H-10 closes (see
 *   {@link SavePtlHeadOptions.verifyExistingHead});
 * - a stored head that is present but UNPARSEABLE (Y-H-06, v0.24) —
 *   `{oops` in sth.json is not a cold start; an operator who signs over
 *   bytes nobody can read vouches for a commitment nobody can name;
 * - `treeSize` smaller than the stored one (a truncated log);
 * - same `treeSize` but a different `root` (a rewritten log);
 * - an `at` earlier than the stored one — timestamps are compared as
 *   PARSED instants (`Date.parse`), and a timestamp that does not parse is
 *   refused outright: a garbage `at` could wedge every later honest append
 *   behind a comparison that cannot be made;
 * - a LARGER `treeSize` whose old→new prefix consistency cannot be PROVEN
 *   from the entries on disk: a longer, rewritten history is precisely the
 *   forgery the consistency proof exists to catch, and signing it fresh
 *   would launder it (M-60). The proof is computed from the stored entries
 *   — a head over more entries than the file holds is refused before any
 *   producer-side `RangeError` can surface.
 *
 * Re-saving the identical head is allowed (idempotent). A log's FIRST head
 * (no stored head at all) is accepted without a consistency proof — there
 * is no prior commitment to extend. Any refusal throws, loudly: once an
 * operator has signed a head, the only honest next head extends it.
 */
export async function savePtlHead(fs, dir, sth, options) {
    const headPath = under(dir, HEAD_FILENAME);
    // Publisher discipline (W9-M8/V4-L9/Y-H-06): a head that is present but
    // unreadable must not be folded into "no head on record", and one that is
    // present but unparseable must not take the cold-start branch either —
    // both would sign over an unknown prior commitment (see
    // readStoredHeadStrictly).
    const existing = await readStoredHeadStrictly(fs, dir);
    if (existing !== undefined) {
        if (sth.logId !== existing.logId) {
            throw new Error(`refusing to change the transparency log operator (logId ${JSON.stringify(existing.logId)} -> ${JSON.stringify(sth.logId)})`
                + ' — operator rotation requires explicitly retiring this log directory and starting a new one');
        }
        if (existing.treeSize < 1) {
            // A planted `treeSize: 0` head used to surface as
            // `RangeError: consistencyProof: 0->N outside the log` from the
            // producer recursion — adjudicated here as a refusal (W9-H1 boundary).
            throw new Error(`refusing to extend a stored head over ${existing.treeSize} entries — no honest publisher of this log signs an empty tree`
                + ' (a stored size-0 head is damage or a planting; restore sth.json from an out-of-band pinned copy)');
        }
        // X-H-10: the stored head is the baseline every check below reasons from,
        // so its own signature is adjudicated FIRST — with the caller's operator
        // key, under the identity the logId check just pinned. Fail-closed on
        // every "cannot verify" shape: no callback, a throwing callback, a false
        // verdict.
        const verify = options?.verifyExistingHead;
        if (verify === undefined) {
            throw new Error(`refusing to sign a new head over the stored one (treeSize ${existing.treeSize}) without verifying the stored head's signature`
                + ' — no operator key was supplied (SavePtlHeadOptions.verifyExistingHead absent): uncertain = fail.'
                + ' The caller holds the operator key it is about to sign with; extend only heads that key can vouch for');
        }
        let existingHolds;
        try {
            existingHolds = await verify(existing);
        }
        catch (error) {
            throw new Error(`refusing to sign a new head: verifying the stored head's signature failed (${error instanceof Error ? error.message : String(error)})`
                + ' — restore sth.json from an out-of-band pinned copy before publishing again');
        }
        if (existingHolds !== true) {
            throw new Error(`refusing to sign a new head: the stored tree head's signature does not verify under the operator key (logId ${JSON.stringify(existing.logId)}, treeSize ${existing.treeSize})`
                + ' — sth.json is attacker-controllable storage, and a planted head whose signature does not hold is a forgery, not a baseline.'
                + ' Restore sth.json from an out-of-band pinned copy (a previously published STH) before publishing again');
        }
        const sthAt = Date.parse(sth.at);
        const existingAt = Date.parse(existing.at);
        if (!Number.isFinite(sthAt) || !Number.isFinite(existingAt)) {
            throw new Error(`refusing a head whose timestamp cannot be parsed as an instant (stored ${JSON.stringify(existing.at)}, new ${JSON.stringify(sth.at)})`);
        }
        const rewinds = sth.treeSize < existing.treeSize
            || (sth.treeSize === existing.treeSize && sth.root !== existing.root)
            || sthAt < existingAt;
        if (rewinds) {
            throw new Error('refusing to rewind the transparency head');
        }
        if (sth.treeSize > existing.treeSize) {
            const { log } = await loadPtl(fs, dir);
            if (log.size < sth.treeSize) {
                throw new Error(`refusing to sign a head over ${sth.treeSize} entries while the log holds ${log.size} — the head and the log are disconnected`);
            }
            const proof = log.consistencyProof(existing.treeSize, sth.treeSize);
            if (!verifyConsistency(existing.treeSize, existing.root, sth.treeSize, sth.root, proof)) {
                throw new Error(`refusing to sign a head that does not extend the published history`
                    + ` (no consistency proof from tree size ${existing.treeSize} to ${sth.treeSize} over the entries on disk)`);
            }
        }
    }
    await fs.writeFile(headPath, canonicalJson(sth));
}
/**
 * The PRE-MUTATION half of `savePtlHead`'s stored-head checks (v0.24,
 * V4-M5): everything about the stored head that would refuse the coming head
 * write, adjudicated BEFORE the caller appends anything, so a refusal cannot
 * leave the half-published state — an entry on the public log with no signed
 * head over it. `savePtlHead`'s rotation gate fires at head-write time, which
 * used to be AFTER `appendPtlEntry` had landed the line; this function moves
 * the readable-damage and operator-identity refusals to the other side of
 * the mutation:
 *
 * - a stored head that is present but unreadable (read failure ≠ absence);
 * - a stored head that is present but unparseable (Y-H-06: unparseable is
 *   not cold start);
 * - a stored head naming a DIFFERENT `logId` than the operator key about to
 *   sign (`operatorKeyId`) — the rotation refusal savePtlHead still enforces
 *   at write time as defence in depth.
 *
 * A log with no stored head (or one proven absent) passes: that publish
 * mints the log's first head. The stored head's SIGNATURE is not adjudicated
 * here — that check needs the key's verify capability, stays in
 * `savePtlHead`'s options contract, and is the caller's write-time gate.
 */
export async function preflightPtlHead(fs, dir, operatorKeyId) {
    const existing = await readStoredHeadStrictly(fs, dir);
    if (existing === undefined)
        return;
    if (existing.logId !== operatorKeyId) {
        throw new Error(`refusing to change the transparency log operator (logId ${JSON.stringify(existing.logId)} -> ${JSON.stringify(operatorKeyId)})`
            + ' — checked BEFORE anything was appended: operator rotation requires explicitly retiring this log directory and starting a new one');
    }
}
//# sourceMappingURL=transparency.js.map