/**
 * APP/1.4 proof bundles — the portable exchange format for a dsh-proof
 * evidence chain.
 *
 * A bundle is the minimal set of artifacts a *third party* needs to
 * re-derive everything `core/trust.ts` can conclude about a session's log
 * without ever touching the workspace it came from: the JSONL log itself,
 * optionally the baseline document and the out-of-band anchor, plus a
 * manifest that names every file's digest and byte length.
 *
 * The verifier here trusts the producer for nothing. `verifyBundle` never
 * reads a clock, a file, or a network — every byte it adjudicates arrives in
 * the arguments — so a bundle can be audited on any machine, years later,
 * with the same verdict. The one thing it may consult outside the bundle is
 * the caller-supplied anchor signer: a key the *verifier* holds, which is
 * exactly the asymmetry that separates the prover from the auditor.
 *
 * Discipline (same as `src/core/` and `src/app/protocol.ts`): this module
 * imports nothing from `@deepseek-ai/*` — only `src/core/*`, the protocol
 * layer, and `node:` builtins.
 *
 * @module dsh-proof/app/bundle
 */
import type { ChainMode } from '../core/trust.ts';
import type { SignedTreeHead } from '../core/transparency.ts';
import type { BundleManifest } from './protocol.ts';
/** The log file every bundle carries; the format `core/trust.ts` walks. */
export declare const EVIDENCE_FILE = "evidence.jsonl";
/** The saved baseline document, when the session had one to export. */
export declare const BASELINE_FILE = "baseline.json";
/** The out-of-band high-water mark, when the session anchored its chain. */
export declare const ANCHOR_FILE = "anchor.json";
/** One manifest file entry: path, content digest, UTF-8 byte length. */
export type ManifestFileEntry = BundleManifest['files'][number];
/** What goes into a bundle. The log is mandatory; the rest are optional. */
export interface BundleInput {
    /** Full contents of the evidence log (`evidence.jsonl`). */
    readonly evidenceLog: string;
    /** Full contents of the saved baseline file, when exporting one. */
    readonly baselineJson?: string;
    /** Full contents of the out-of-band anchor file, when exporting one. */
    readonly anchorJson?: string;
}
/**
 * The transparency-log publication record a manifest may carry: where the
 * bundle's evidence chain was published in an append-only Proof Transparency
 * Log, so a third party can later prove the published history was not
 * quietly rewritten (a consistency proof between `publishedHead` and any
 * newer signed tree head cannot be forged for a rewritten log).
 *
 * `leafHash` binds the bundle's latest signed checkpoint to one log entry;
 * `publishedHead` is the signed tree head exactly as it stood at publication
 * time; `inclusionProof` is the auditor's merkle path at that tree size.
 */
export interface ManifestTransparency {
    /** Identity of the log the entry landed in (the log operator's key id). */
    readonly logId: string;
    /** Zero-based position of the entry in the log. */
    readonly sequence: number;
    /** `ptlLeafHash(entry)` — the value inclusion proofs attest. */
    readonly leafHash: string;
    /** The signed tree head at publication time. */
    readonly publishedHead: SignedTreeHead;
    /** Merkle inclusion path (node digests, bottom-up) at publication size. */
    readonly inclusionProof: readonly string[];
}
/**
 * A manifest that may carry a transparency publication record. The field is
 * optional and additive — bundles built before it existed verify exactly as
 * they always did.
 */
export type TransparentBundleManifest = BundleManifest & {
    readonly transparency?: ManifestTransparency;
};
/** Optional extras `buildBundle` can stamp into the manifest. */
export interface BundleExtras {
    /** Transparency-log publication record; absent means "not published". */
    readonly transparency?: ManifestTransparency;
}
/**
 * A portable proof bundle: the manifest (protocol header + file digests) and
 * the files themselves, keyed by path. JSON-serialisable as-is; `buildBundle`
 * fixes the key order (`manifest` first, then `files` in the canonical file
 * order) so two producers packing the same input emit identical bytes.
 */
export interface ProofBundle {
    readonly manifest: TransparentBundleManifest;
    readonly files: Record<string, string>;
}
/** The anchor facts a verifier could re-derive from the bundle alone. */
export interface BundleAnchor {
    readonly keyId: string;
    readonly count: number;
    readonly head: string;
    /** Whether the anchor's head agrees with the chain's last checkpoint. */
    readonly headMatchesChain: boolean;
}
/**
 * The verifier's view of the anchor key: the identity half of the
 * prover/auditor asymmetry. A signer the PRODUCER holds can mint checkpoints
 * and anchors; this object can only *check* them — a keyId to match against,
 * and a verify that adjudicates a detached signature over the exact bytes
 * `checkpointSignedData` serialises. `verify` may throw (a hostile or broken
 * key implementation must never crash the auditor): a throw counts as a
 * failed verification, never as a rejected promise.
 */
export interface BundleAnchorSigner {
    readonly keyId: string;
    readonly verify: (data: string, sig: string) => Promise<boolean>;
}
/**
 * The optional second argument `verifyBundle` accepts (v0.23, X-H-02): the
 * caller's anchor signer, without which the checkpoint-signature three-state
 * (`verified` / `invalid` / `unverified`) can never say anything but
 * `unverified`. Engines adjudicating submitted bundles pass the anchor key
 * they hold; direct callers may pass one too. The signer may also be passed
 * bare (the pre-options positional form) — both shapes below are accepted.
 */
export interface VerifyBundleOptions {
    /** The verifier's view of the key the bundle's signatures name. */
    readonly anchorSigner?: BundleAnchorSigner;
}
/**
 * What `verifyBundle` can report as a chain mode. `legacy`/`unsigned` come
 * verbatim from `walkChain`. `signed` is reported ONLY when at least one
 * checkpoint signature was actually adjudicated against a key the verifier
 * holds and every adjudication passed; a chain whose checkpoints merely
 * CARRY `sig` fields nobody checked is reported as `signed-unverified` —
 * "signatures exist" and "signatures were verified" are different claims,
 * and the mode must not make the second for free (v0.22, H-05).
 */
export type BundleChainMode = ChainMode | 'signed-unverified';
/**
 * Everything `verifyBundle` can tell you about a bundle. All fields are
 * derived from the bundle's own bytes (plus the optional signer); `problems`
 * is the aggregate verdict — empty means the bundle passed every check.
 */
export interface BundleVerification {
    /** Protocol dialect + implementation fingerprint are both recognised. */
    readonly protocolOk: boolean;
    /** Every manifest digest and byte length was recomputed and matched. */
    readonly manifestOk: boolean;
    /** Paths whose recomputed digest or byte length disagrees with the manifest. */
    readonly digestMismatches: readonly string[];
    /** Line indexes whose `prev` does not match the previous line's digest. */
    readonly chainBreaks: readonly number[];
    /** Line indexes that are not valid v1/v2 envelopes. */
    readonly corruptLines: readonly number[];
    /** Line indexes of checkpoints whose self-reported count the walk refutes (mirrored into `problems`). */
    readonly malformedCheckpoints: readonly number[];
    /** Records appended after the last checkpoint (chain-covered, not checkpoint-covered). */
    readonly tailRecords: number;
    /**
     * The COUNT (a plain `number`, v0.24 wording made explicit — this is NOT
     * an array and never was) of checkpoints whose self-declared `payload.head`
     * disagrees with the chain digest the walk computed at their position
     * (`expectedHead`), present and non-zero only when such checkpoints exist
     * (v0.23, X-H-03). An honest writer always stamps the walked head, so a
     * disagreement means the checkpoint was replayed from another chain
     * position or chains onto a rewritten prefix — a keyless contradiction,
     * named in `problems` whether or not a signer was at hand (each lying
     * checkpoint is named there individually, by line index — the line indexes
     * live in `problems`, not here), and charged against `checkpointSignature`
     * when the lying checkpoint's signature itself verified (a genuine
     * signature over a planted position is a replay, not proof of this chain).
     * Consumers must test `> 0` / truthiness — never `.length` or indexing,
     * both of which silently read `undefined` off a count.
     */
    readonly headLiars?: number;
    /** `legacy` / `unsigned` / `signed` / `signed-unverified` — see `BundleChainMode`. */
    readonly chainMode: BundleChainMode;
    /** Anchor facts, when the bundle carries an `anchor.json` that parses. */
    readonly anchor?: BundleAnchor;
    /** The baseline's own id, when the bundle carries a parseable `baseline.json`. */
    readonly baselineId?: string;
    /** Whether the baseline's `baselineId` still addresses its own material. */
    readonly baselineSelfAddressed: boolean;
    /**
     * Adjudication of the manifest's transparency record, when it carries one:
     * `recorded` (structurally valid) or `malformed` (with a problem naming
     * why). Structural only — see the transparency section of `verifyBundle`.
     */
    readonly transparency?: 'recorded' | 'malformed';
    /**
     * Whether the accepted dialect is a KNOWN ANCESTOR (e.g. `APP/1.3`)
     * rather than the current one. Present and `true` only when
     * `protocolOk` came from the fingerprint table, not the fast path — the
     * bundle verified clean, but under an older dialect, and readers deserve
     * to see that.
     */
    readonly legacyProtocol?: boolean;
    /**
     * Checkpoint-signature adjudication, present whenever the chain carries
     * signature-bearing checkpoints: `verified` (the verifier held the named
     * key and every checkpoint under it verified), `invalid` (at least one
     * failed — with a problem naming the line), or `unverified` (no key the
     * signatures name was at hand — a missing capability, never an
     * accusation, but the chain mode reports `signed-unverified` so nobody
     * mistakes presence of signatures for proof of them).
     */
    readonly checkpointSignature?: 'verified' | 'invalid' | 'unverified';
    /** Human-readable anomaly list; empty means the bundle verified clean. */
    readonly problems: readonly string[];
}
/**
 * Pack a proof bundle. Deterministic: the same input, workspace key and
 * timestamp always produce byte-identical JSON — `manifest` first, `files`
 * in the canonical order (`evidence.jsonl` → `baseline.json`? → `anchor.json`?),
 * manifest fields in `protocolHeader` order with `transparency` (when
 * supplied) appended last.
 *
 * `extras` is optional and additive; every pre-existing three-argument call
 * keeps its exact bytes.
 */
export declare function buildBundle(input: BundleInput, workspaceKey: string, createdAt: string, extras?: BundleExtras): ProofBundle;
/**
 * Verify a proof bundle end to end, trusting the producer for nothing.
 *
 * Pure: no I/O and no clock — every byte adjudicated arrives in the
 * arguments, so the same bundle always yields the same verdict. The returned
 * promise exists only because the optional anchor-signature check is async.
 *
 * Checks, in order:
 * 1. **Protocol identity** — fingerprint-match negotiation: the manifest
 *    speaks this module's `PROTOCOL_VERSION` with this implementation's
 *    `appFingerprint()` (fast path), or carries a coherent
 *    (version, fingerprint) pair for a KNOWN ancestor dialect (accepted,
 *    flagged `legacyProtocol`); anything else is refused with both digests
 *    and a migration path.
 * 2. **Manifest vs files** — every listed path must be one of the three
 *    bundle files (closed layout), present exactly once, with a matching
 *    digest and byte length; files the manifest does not list are anomalies.
 * 3. **Chain walk** — `walkChain` over the log's lines; breaks, corrupt
 *    lines and malformed checkpoints are passed through verbatim as
 *    problems; a log with no lines at all is itself a problem (an empty
 *    bundle is not a clean verdict), and so is a log whose lines carry ZERO
 *    evidence/marker records — a structurally intact, content-empty log
 *    (v0.23, W10-M5: the single `count: 0` checkpoint is the shape) is not
 *    verifiable evidence either. Signature-bearing checkpoints get their
 *    signatures actually adjudicated when the caller's signer holds the
 *    named key — otherwise the mode honestly says `signed-unverified`,
 *    never `signed`. Two walk-level facts ride the verdict as problems
 *    (v0.23): checkpoints whose `payload.head` disagrees with the walked
 *    `expectedHead` (X-H-03 — a replayed or rewritten position; when such a
 *    checkpoint's signature VERIFIED, the adjudication is charged invalid),
 *    and records riding behind the last checkpoint that no checkpoint
 *    covers (X-H-04 — `tailRecords` stays a field, but a covered-prefix
 *    bundle with an uncovered tail no longer reads as clean, which is the
 *    piggyback channel a forger appends self-chained records into).
 * 4. **Anchor** (when carried) — parsed with core's `parseAnchor`; its head
 *    is compared against the chain's last checkpoint. When the caller
 *    supplies a signer, the anchor's detached signature over
 *    `checkpointSignedData({count, head, workspaceKey, at})` is adjudicated
 *    under the same burden-of-proof rules as `EvidenceStore.audit()`: only a
 *    key that *is* the named keyId, over an anchor that *carries*
 *    `workspaceKey`, gets to refute — a missing capability is never an
 *    accusation. A verify that THROWS counts as failed, never as a rejected
 *    promise (v0.23, W10-L8). When the signature was not adjudicable, the
 *    anchor's identity fields (keyId, count, workspaceKey) are
 *    cross-checked against the chain and manifest instead — contradictions
 *    provable without any key. The keyId cross-check answers to the chain's
 *    signing identity even when the LAST checkpoint carries none (v0.23,
 *    W10-L9: a stripped final keyId no longer hides a foreign anchor key —
 *    the most recent signature-bearing checkpoint's keyId speaks for the
 *    chain).
 * 5. **Baseline** (when carried) — parsed; its `baselineId` must still
 *    address the same material `buildBaseline` hashed (`createdAt`,
 *    `workspace`, `checkIds`, `root`).
 * 6. **Transparency record** (when the manifest carries one) — structural
 *    adjudication only: shapes, ranges, the sequence-inside-the-tree and
 *    logId-agreement bounds, and the proof-length bound that can be judged
 *    from the manifest alone. Whether the entry actually sits in the log
 *    (leaf hash match, inclusion, consistency against the current head)
 *    requires the log itself, which a bundle deliberately does not carry —
 *    that adjudication belongs to the PTL CLI / MCP auditor holding the
 *    log, and this verifier must not pretend to have done it. One
 *    bundle-side contradiction is judged: a record without a signed
 *    checkpoint behind it could never have been published.
 */
export declare function verifyBundle(bundle: ProofBundle, options?: BundleAnchorSigner | VerifyBundleOptions): Promise<BundleVerification>;
//# sourceMappingURL=bundle.d.ts.map