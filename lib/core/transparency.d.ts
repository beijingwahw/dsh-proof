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
import type { FsPort } from './ports.ts';
/**
 * One checkpoint as appended to the transparency log: the workspace's own
 * signed checkpoint payload plus the signature the log hosts verbatim.
 * The log does not verify `sig` — it notarises bytes, and auditors adjudicate
 * them with the workspace public key identified by `keyId`.
 */
export interface PtlEntry {
    /** Format version. */
    readonly v: 1;
    /** Workspace the checkpoint summarises. */
    readonly workspaceKey: string;
    /** keyId of the workspace checkpoint signer. */
    readonly keyId: string;
    /** Checkpoint payload: number of evidence records at `head`. */
    readonly count: number;
    /** Checkpoint payload: chain head digest. */
    readonly head: string;
    /** Checkpoint payload: ISO timestamp supplied by the workspace. */
    readonly at: string;
    /** Workspace signature over the checkpoint bytes — hosted, not checked. */
    readonly sig: string;
}
/**
 * RFC 6962 leaf hash: `SHA-256(0x00 || canonicalJson(entry))`.
 *
 * The 0x00 domain-separation prefix (vs 0x01 for internal nodes) is what
 * gives the tree second-preimage resistance; the canonical-JSON body is what
 * keeps the leaf address computable by any implementation, not just this one.
 */
export declare function ptlLeafHash(entry: PtlEntry): string;
/** The log operator's signed commitment to a tree state. */
export interface SignedTreeHead {
    /** keyId of the log operator (public-key identity of whoever runs the log). */
    readonly logId: string;
    /** Number of entries committed. */
    readonly treeSize: number;
    /** `MTH(entries[0:treeSize])`. */
    readonly root: string;
    /** ISO timestamp supplied by the operator. */
    readonly at: string;
    /** Operator signature over `sthSignedData` of these fields. */
    readonly sig: string;
}
/** The exact bytes an STH signature commits to (canonical key order). */
export declare function sthSignedData(sth: Omit<SignedTreeHead, 'sig'>): string;
/**
 * Verify an STH with the caller's signature check (the operator's public
 * key). Pure plumbing: signature over the signed data, nothing else.
 */
export declare function verifyTreeHead(sth: SignedTreeHead, verify: (data: string, sig: string) => Promise<boolean>): Promise<boolean>;
/**
 * An in-memory transparency log: an ordered, append-only list of checkpoint
 * entries with RFC 6962 proofs over their leaf hashes. Duplicate leaf hashes
 * are idempotent (a replayed checkpoint is the same event, not a new one),
 * which is what keeps restart-replays of a workspace's checkpoints from
 * polluting the sequence.
 */
export declare class TransparencyLog {
    private readonly _entries;
    private readonly _leafHashes;
    private readonly _indexByLeafHash;
    constructor(entries?: readonly PtlEntry[]);
    /** Number of entries appended so far. */
    get size(): number;
    /** The entries, in sequence order. */
    get entries(): readonly PtlEntry[];
    /** RFC 6962 MTH over all leaves; the empty log's root is `SHA-256()`. */
    merkleRoot(): string;
    /**
     * Append one entry. A byte-identical replay (same leaf hash) appends
     * nothing and reports the existing sequence with `duplicate: true`; a new
     * entry gets sequence `size - 1` after appending (0-based).
     */
    append(entry: PtlEntry): {
        sequence: number;
        duplicate: boolean;
    };
    /**
     * RFC 6962 §2.1.1 audit path for `index` in the first `treeSize` entries.
     * `treeSize` defaults to the current size; passing a smaller value proves
     * inclusion against a historical STH. Throws `RangeError` on out-of-range
     * arguments — this is the producer side, operating on data the log owns.
     */
    inclusionProof(index: number, treeSize?: number): readonly string[];
    /**
     * RFC 6962 §2.1.2 consistency proof that the first `first` entries of the
     * first `second` entries form the old tree (`first === second` yields the
     * empty identity proof). RFC domain is `0 < m <= n`; a zero `first` is
     * rejected because consistency with an empty tree carries no information
     * the empty root does not. Throws `RangeError` on bad ranges.
     */
    consistencyProof(first: number, second: number): readonly string[];
}
/**
 * Verify an RFC 6962 inclusion proof: does `proof` fold `entry`'s leaf hash
 * at `index` up to `root` for a tree of `treeSize` leaves? Answers `false`
 * — never throws — for out-of-range indices, wrong-length proofs, non-hash
 * proof elements, and any mismatch, because a verifier faces forgeries and
 * must adjudicate them, not crash on them.
 */
export declare function verifyInclusion(entry: PtlEntry, index: number, treeSize: number, proof: readonly string[], root: string): boolean;
/**
 * Verify an RFC 6962 consistency proof: do `oldSize`/`oldRoot` still hold as
 * a prefix of `newSize`/`newRoot`? `newSize < oldSize` (a truncated log) is
 * adjudicated `false`, not thrown — it is exactly the forgery this function
 * exists to catch. `oldSize === newSize` is the identity case: valid only
 * with an empty proof and equal roots. `oldSize === 0` is outside the RFC's
 * domain (`0 < m`) and answers `false`.
 */
export declare function verifyConsistency(oldSize: number, oldRoot: string, newSize: number, newRoot: string, proof: readonly string[]): boolean;
/** The outcome of {@link selectPublishable}: what may enter the public log. */
export interface PublishableSelection<T> {
    /** The newest candidate whose `canVerify` returned `true`; `undefined` when none did. */
    readonly chosen: T | undefined;
    /** Every candidate tried and failed verification, in scan order (newest first). */
    readonly rejected: readonly T[];
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
export declare function selectPublishable<T>(candidates: readonly T[], canVerify: (candidate: T) => boolean | Promise<boolean>): Promise<PublishableSelection<T>>;
/**
 * Layout descriptor for a transparency log on an FsPort: everything lives
 * under `dir` as
 *
 * - `ptl-entries.jsonl` — one `canonicalJson(PtlEntry)` per line, append order
 *   = sequence order; malformed lines are skipped on load (and counted),
 *   because one torn write must not render the whole log unreadable;
 * - `sth.json` — the latest signed tree head, written atomically.
 */
export interface PtlStorage {
    readonly dir: string;
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
export declare function loadPtl(fs: FsPort, dir: string): Promise<{
    log: TransparencyLog;
    sth: SignedTreeHead | undefined;
    badLines: number;
    headOvercommits?: boolean;
}>;
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
export declare function appendPtlEntry(fs: FsPort, dir: string, entry: PtlEntry): Promise<{
    sequence: number;
    duplicate: boolean;
}>;
/**
 * Options for {@link savePtlHead} (v0.23, X-H-10).
 */
export interface SavePtlHeadOptions {
    /**
     * Adjudicate the STORED head's own signature before any new head is signed
     * over the history it anchors. The caller holds the operator key (both
     * production callers are about to sign with it anyway), so it hands the key
     * in as a callback: `true` iff `existing.sig` verifies under that key.
     *
     * Why the stored head must be verified at all: every refusal below (no
     * rewinds, no root swaps, prefix consistency) reasons FROM the stored head
     * as its trust anchor — and `sth.json` lives in the log directory, where a
     * log-writer can plant any self-consistent forgery it likes. Without this
     * check the operator's next honest append mints a fresh VALID signature
     * over the attacker's chosen baseline (the consistency proof is generated
     * and verified against the same planted bytes, so it always passes). With
     * it, extending a head nobody can vouch for is refused: restore the head
     * from an out-of-band pinned copy instead.
     *
     * Fail-closed by contract: a stored head that CANNOT be verified — no
     * callback supplied, or a callback that throws — is treated exactly like
     * one that fails verification ("uncertain = fail", the same discipline the
     * verify face applies to an unkeyed publication signature). A log's FIRST
     * head (nothing stored yet) needs no verification; there is no prior
     * commitment to extend.
     */
    readonly verifyExistingHead?: (sth: SignedTreeHead) => Promise<boolean>;
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
export declare function savePtlHead(fs: FsPort, dir: string, sth: SignedTreeHead, options?: SavePtlHeadOptions): Promise<void>;
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
export declare function preflightPtlHead(fs: FsPort, dir: string, operatorKeyId: string): Promise<void>;
//# sourceMappingURL=transparency.d.ts.map