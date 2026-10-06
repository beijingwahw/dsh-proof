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
/** `prev` of the first line ever appended to a log. */
export declare const GENESIS_PREV: string;
/**
 * sha256 of one appended log line (excluding its trailing newline).
 *
 * W1-L10 (v0.23): trailing `\r` is stripped before digesting. `JSON.stringify`
 * never emits a raw `\r` — a carriage return can only ride a line that was
 * externally re-terminated (git autocrlf, a CRLF editor) — so honest lines
 * hash identically with or without the strip and **every existing chain
 * digest is unchanged**. Without the normalization, one CRLF rewrite of the
 * file mass-invalidated every `prev` link: loud, but indistinguishable from
 * real tampering and unrecoverable by honest means. Chosen over the stricter
 * "a `\r`-carrying line is itself corrupt" reading precisely because it never
 * breaks an old chain: tolerance extends only to a byte no honest writer
 * ever produced. (A `\r` in the *middle* of a line is not a line terminator
 * and still changes the digest — mid-line edits remain fully detected.)
 *
 * V1-L13 (documented residual): the same tolerance means a trailing `\r`
 * APPENDED to a line is undetectable by any digest-based check — the chain
 * link, `headRef` witnesses and checkpoint heads all digest the stripped
 * form, and `JSON.parse` tolerates the trailing whitespace, so the edited
 * bytes parse, chain and address exactly like the honest ones. That is the
 * accepted price of never mass-invalidating an honest chain on a CRLF
 * rewrite; it buys no attacker anything (the edit changes no JSON value any
 * consumer reads), and it is pinned by the W1-L10 tests rather than silently
 * smoothed over. Everything but the terminator byte stays fully detected.
 */
export declare function lineDigest(line: string): string;
/** What a checkpoint attests: how many records, and the chain head at that point. */
export interface CheckpointPayload {
    /** Evidence + marker records that precede this checkpoint. */
    readonly count: number;
    /** Chain head digest when the checkpoint was appended. */
    readonly head: string;
    /** Stable identity of the workspace this log belongs to, when known. */
    readonly workspaceKey: string | null;
    readonly at: string;
}
/** Out-of-band high-water mark, stored next to the signing key. */
export interface AnchorFile {
    readonly v: 1;
    readonly keyId: string;
    readonly count: number;
    readonly head: string;
    readonly sig: string;
    readonly at: string;
    /**
     * The workspace identity the signature commits to. Optional because anchors
     * written before this field existed are still valid high-water marks —
     * auditors skip (rather than fail) signature verification for them.
     */
    readonly workspaceKey?: string;
}
export interface WalkedCheckpoint {
    /** Index of the checkpoint line within the log. */
    readonly index: number;
    readonly payload: CheckpointPayload;
    /** Detached signature over `canonicalJson(payload)`, when signed. */
    readonly sig: string | null;
    readonly keyId: string | null;
    /**
     * Why this checkpoint carries no signature, as recorded by the writer at
     * append time: a transient signing failure, or a refusal under the
     * `SIG_REFUSED_PREFIX` banner (the writer's own audit found the physical
     * chain tampered and declined to lend the forged bytes its key). The
     * distinction is the only signal that separates an honest unsigned boundary
     * from an attacker's stripped signature — the walk surfaces it so the audit
     * layer (M-33/H-32) can adjudicate instead of guessing.
     */
    readonly sigError: string | null;
    /** Chain head the walker expected at this position. */
    readonly expectedHead: string;
    /**
     * X-H-03 (v0.23): `payload.head !== expectedHead` — the checkpoint swears a
     * chain head the walk does not corroborate at its physical position. The
     * walk has always recorded `expectedHead`; this is the pre-computed verdict
     * over it, exported so the bundle/publish layers (verifyBundle,
     * transparency) consume ONE derivation instead of re-deriving — or, as the
     * survey found, not comparing at all. A legitimately-signed checkpoint
     * replayed or transplanted at another position is exactly the shape where
     * the signature verifies and only this flag says the position is a lie.
     *
     * Y-H-01 (v0.24): `EvidenceStore.latestSignedCheckpoint` /
     * `lastWellFormedCheckpoint` and `createVerifiedView().bestCheckpoint` now
     * EXCLUDE head-liars from selection outright — the publish predicate is
     * enforced where the candidate is chosen, not advised at the consumer.
     */
    readonly headLiared: boolean;
    /**
     * Records (evidence + marker lines) the walker counted *before* this
     * checkpoint line — exactly what an honest writer stamps into
     * `payload.count` (`EvidenceStore` does not count checkpoints themselves).
     * The self-reported count is judged against this walked count: an attacker
     * who rewrites the log can recompute `head` with this package's own
     * functions, but it cannot make a forged `count` survive comparison with
     * the walk — the walked count is derived, not self-declared.
     */
    readonly expectedCount: number;
}
export type ChainMode = 'signed' | 'unsigned' | 'legacy';
export interface ChainWalk {
    /** `signed` once any checkpoint carries a signature; `legacy` for v1-only logs. */
    readonly mode: ChainMode;
    /** Evidence + marker records seen (v1 and v2). */
    readonly records: number;
    /** Line indexes whose `prev` does not match the previous line's digest. */
    readonly chainBreaks: readonly number[];
    /** Lines that are not valid v1/v2 envelopes. */
    readonly corruptLines: readonly number[];
    readonly checkpoints: readonly WalkedCheckpoint[];
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
    readonly malformedCheckpoints: readonly number[];
    /** Records appended after the last well-formed checkpoint (0 when the tail is covered). */
    readonly tailRecords: number;
}
/**
 * Walk the log and verify chain linkage. Pure: no I/O, no signature checks —
 * the store layer does cryptographic verification with its own signer.
 *
 * Chain rule: each v2 line's `prev` must equal the digest of the physically
 * previous line (of any kind), so legacy v1 lines participate in the chain
 * once a v2 line follows them.
 *
 * V1-M8 (v0.24): the line-array contract is pinned here as the ONE
 * convention every chain-side consumer derives from — the node-ports
 * `readLines` semantics, blank lines removed. The v0.23 code trusted the
 * caller to hand in a filtered array, so the store face (filtered) and the
 * MCP face (a raw `split('\n')`) could disagree about whether a marker's
 * physical predecessor was a blank line — the same log, two faces, two
 * suspect verdicts. Normalising defensively at entry makes every caller
 * converge: an honest writer never emits blank lines, so filtering them can
 * never change an honest chain's walk, and all reported line indexes refer
 * to the normalised array.
 */
export declare function walkChain(input: readonly string[]): ChainWalk;
/**
 * v0.22 (H-32/M-33): the `sigError` banner under which the store records that
 * it *refused* to sign a checkpoint because its own pre-sign audit found the
 * physical chain tampered (H-27) — as opposed to a transient signing failure
 * ("key directory locked by a scanner"). The walk carries the string; the
 * audit splits the two into different channels with different `ok` semantics.
 */
export declare const SIG_REFUSED_PREFIX = "refused-to-sign";
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
    readonly anchor?: AnchorFile;
    readonly problem?: 'unparseable' | 'invalid';
}
/**
 * Parse an anchor document into a {@link AnchorParseOutcome}; `undefined`
 * means "no document at all" (no file / nothing to read).
 */
export declare function parseAnchorEx(raw: string | undefined): AnchorParseOutcome | undefined;
/**
 * Parse and validate an anchor file's contents; `undefined` when unreadable
 * *or* when the document is a domain-invalid disarm shape (see
 * {@link parseAnchorEx} — callers that need the distinction use that).
 */
export declare function parseAnchor(raw: string | undefined): AnchorFile | undefined;
/** The exact bytes a checkpoint signature commits to. */
export declare function checkpointSignedData(payload: CheckpointPayload): string;
//# sourceMappingURL=trust.d.ts.map