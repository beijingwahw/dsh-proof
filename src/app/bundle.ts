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

import { Buffer } from 'node:buffer'

import { addressOf, sha256 } from '../core/hash.ts'
import { checkpointSignedData, parseAnchor, walkChain } from '../core/trust.ts'
import type { ChainMode } from '../core/trust.ts'
import type { SignedTreeHead } from '../core/transparency.ts'
import { adjudicateProtocol, protocolHeader, PROTOCOL_VERSION } from './protocol.ts'
import type { BundleManifest } from './protocol.ts'

/** The log file every bundle carries; the format `core/trust.ts` walks. */
export const EVIDENCE_FILE = 'evidence.jsonl'

/** The saved baseline document, when the session had one to export. */
export const BASELINE_FILE = 'baseline.json'

/** The out-of-band high-water mark, when the session anchored its chain. */
export const ANCHOR_FILE = 'anchor.json'

/**
 * Every path a manifest entry may name. The exchange format is a closed
 * three-file layout, not a directory tree: any unpacker that ever trusts a
 * manifest path to place a file would turn an unvalidated `../..` or an
 * absolute path into an arbitrary-write primitive, so the verifier refuses
 * every path outside the layout — absolute paths, `..` traversal, drive
 * letters, UNC prefixes and duplicates all fail alike by not being one of
 * the three canonical names.
 */
const BUNDLE_FILE_PATHS: ReadonlySet<string> = new Set([EVIDENCE_FILE, BASELINE_FILE, ANCHOR_FILE])

/** One manifest file entry: path, content digest, UTF-8 byte length. */
export type ManifestFileEntry = BundleManifest['files'][number]

/** What goes into a bundle. The log is mandatory; the rest are optional. */
export interface BundleInput {
  /** Full contents of the evidence log (`evidence.jsonl`). */
  readonly evidenceLog: string
  /** Full contents of the saved baseline file, when exporting one. */
  readonly baselineJson?: string
  /** Full contents of the out-of-band anchor file, when exporting one. */
  readonly anchorJson?: string
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
  readonly logId: string
  /** Zero-based position of the entry in the log. */
  readonly sequence: number
  /** `ptlLeafHash(entry)` — the value inclusion proofs attest. */
  readonly leafHash: string
  /** The signed tree head at publication time. */
  readonly publishedHead: SignedTreeHead
  /** Merkle inclusion path (node digests, bottom-up) at publication size. */
  readonly inclusionProof: readonly string[]
}

/**
 * A manifest that may carry a transparency publication record. The field is
 * optional and additive — bundles built before it existed verify exactly as
 * they always did.
 */
export type TransparentBundleManifest = BundleManifest & { readonly transparency?: ManifestTransparency }

/** Optional extras `buildBundle` can stamp into the manifest. */
export interface BundleExtras {
  /** Transparency-log publication record; absent means "not published". */
  readonly transparency?: ManifestTransparency
}

/**
 * A portable proof bundle: the manifest (protocol header + file digests) and
 * the files themselves, keyed by path. JSON-serialisable as-is; `buildBundle`
 * fixes the key order (`manifest` first, then `files` in the canonical file
 * order) so two producers packing the same input emit identical bytes.
 */
export interface ProofBundle {
  readonly manifest: TransparentBundleManifest
  readonly files: Record<string, string>
}

/** The anchor facts a verifier could re-derive from the bundle alone. */
export interface BundleAnchor {
  readonly keyId: string
  readonly count: number
  readonly head: string
  /** Whether the anchor's head agrees with the chain's last checkpoint. */
  readonly headMatchesChain: boolean
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
  readonly keyId: string
  readonly verify: (data: string, sig: string) => Promise<boolean>
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
  readonly anchorSigner?: BundleAnchorSigner
}

/**
 * Normalise the optional second argument: a bare signer, or an options
 * object carrying one. Anything without a non-empty string `keyId` and a
 * callable `verify` is treated as "no signer" — a malformed capability is a
 * missing capability, never a crash.
 */
function anchorSignerOf(option: unknown): BundleAnchorSigner | undefined {
  if (option === null || typeof option !== 'object') return undefined
  const candidate = 'anchorSigner' in option ? (option as { anchorSigner?: unknown }).anchorSigner : option
  if (candidate === null || typeof candidate !== 'object') return undefined
  const signer = candidate as Partial<BundleAnchorSigner>
  if (typeof signer.keyId !== 'string' || signer.keyId.length === 0) return undefined
  if (typeof signer.verify !== 'function') return undefined
  return { keyId: signer.keyId, verify: signer.verify as BundleAnchorSigner['verify'] }
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
export type BundleChainMode = ChainMode | 'signed-unverified'

/**
 * Everything `verifyBundle` can tell you about a bundle. All fields are
 * derived from the bundle's own bytes (plus the optional signer); `problems`
 * is the aggregate verdict — empty means the bundle passed every check.
 */
export interface BundleVerification {
  /** Protocol dialect + implementation fingerprint are both recognised. */
  readonly protocolOk: boolean
  /** Every manifest digest and byte length was recomputed and matched. */
  readonly manifestOk: boolean
  /** Paths whose recomputed digest or byte length disagrees with the manifest. */
  readonly digestMismatches: readonly string[]
  /** Line indexes whose `prev` does not match the previous line's digest. */
  readonly chainBreaks: readonly number[]
  /** Line indexes that are not valid v1/v2 envelopes. */
  readonly corruptLines: readonly number[]
  /** Line indexes of checkpoints whose self-reported count the walk refutes (mirrored into `problems`). */
  readonly malformedCheckpoints: readonly number[]
  /** Records appended after the last checkpoint (chain-covered, not checkpoint-covered). */
  readonly tailRecords: number
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
  readonly headLiars?: number
  /** `legacy` / `unsigned` / `signed` / `signed-unverified` — see `BundleChainMode`. */
  readonly chainMode: BundleChainMode
  /** Anchor facts, when the bundle carries an `anchor.json` that parses. */
  readonly anchor?: BundleAnchor
  /** The baseline's own id, when the bundle carries a parseable `baseline.json`. */
  readonly baselineId?: string
  /** Whether the baseline's `baselineId` still addresses its own material. */
  readonly baselineSelfAddressed: boolean
  /**
   * Adjudication of the manifest's transparency record, when it carries one:
   * `recorded` (structurally valid) or `malformed` (with a problem naming
   * why). Structural only — see the transparency section of `verifyBundle`.
   */
  readonly transparency?: 'recorded' | 'malformed'
  /**
   * Whether the accepted dialect is a KNOWN ANCESTOR (e.g. `APP/1.3`)
   * rather than the current one. Present and `true` only when
   * `protocolOk` came from the fingerprint table, not the fast path — the
   * bundle verified clean, but under an older dialect, and readers deserve
   * to see that.
   */
  readonly legacyProtocol?: boolean
  /**
   * Checkpoint-signature adjudication, present whenever the chain carries
   * signature-bearing checkpoints: `verified` (the verifier held the named
   * key and every checkpoint under it verified), `invalid` (at least one
   * failed — with a problem naming the line), or `unverified` (no key the
   * signatures name was at hand — a missing capability, never an
   * accusation, but the chain mode reports `signed-unverified` so nobody
   * mistakes presence of signatures for proof of them).
   */
  readonly checkpointSignature?: 'verified' | 'invalid' | 'unverified'
  /** Human-readable anomaly list; empty means the bundle verified clean. */
  readonly problems: readonly string[]
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
export function buildBundle(
  input: BundleInput,
  workspaceKey: string,
  createdAt: string,
  extras?: BundleExtras,
): ProofBundle {
  const files: Record<string, string> = {}
  const entries: ManifestFileEntry[] = []
  const pack = (path: string, contents: string): void => {
    files[path] = contents
    entries.push({ path, sha256: sha256(contents), bytes: Buffer.byteLength(contents, 'utf8') })
  }
  pack(EVIDENCE_FILE, input.evidenceLog)
  if (input.baselineJson !== undefined) pack(BASELINE_FILE, input.baselineJson)
  if (input.anchorJson !== undefined) pack(ANCHOR_FILE, input.anchorJson)
  const manifest: TransparentBundleManifest = {
    ...protocolHeader(workspaceKey, createdAt),
    ...(extras?.transparency !== undefined ? { transparency: extras.transparency } : {}),
    files: entries,
  }
  return { manifest, files }
}

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
export async function verifyBundle(
  bundle: ProofBundle,
  options?: BundleAnchorSigner | VerifyBundleOptions,
): Promise<BundleVerification> {
  const problems: string[] = []
  const anchorSigner = anchorSignerOf(options)

  // Untrusted input: the bundle may be hand-crafted, so read it defensively.
  const raw = (bundle ?? {}) as unknown as Partial<ProofBundle>
  const manifest = (raw.manifest ?? {}) as Partial<TransparentBundleManifest>
  const files = (raw.files ?? {}) as Record<string, string>

  // -- 1. protocol identity ------------------------------------------------
  // Fingerprint-match negotiation (v0.22): strict equality with the current
  // dialect is the fast path; a coherent (version, fingerprint) pair for any
  // KNOWN ancestor dialect accepts (the vocabularies never changed across
  // the genealogy, so the payload is interpretable byte-for-byte — flagged
  // via `legacyProtocol`); anything else refuses, naming BOTH digests so the
  // migration story is actionable instead of a bare "mismatch".
  const dialect = adjudicateProtocol(manifest.protocol, manifest.appFingerprint)
  const protocolOk = dialect.kind !== 'unknown'
  if (dialect.kind === 'unknown') {
    problems.push(
      `unsupported bundle protocol: ${JSON.stringify(dialect.protocol)} carries fingerprint ${JSON.stringify(dialect.fingerprint)},`
      + ` which no dialect this verifier speaks ever produced (current: ${PROTOCOL_VERSION} / ${dialect.currentFingerprint})`
      + ' — re-verify with the implementation that minted the bundle, or re-publish the bundle under the current dialect',
    )
  }

  // -- 2. manifest vs files ------------------------------------------------
  const digestMismatches: string[] = []
  const listed = new Set<string>()
  let manifestOk = true
  const entries = Array.isArray(manifest.files) ? manifest.files : undefined
  if (entries === undefined) {
    manifestOk = false
    problems.push('manifest.files is missing or not an array')
  } else {
    entries.forEach((entry, index) => {
      if (entry === null || typeof entry !== 'object'
        || typeof entry.path !== 'string' || typeof entry.sha256 !== 'string' || typeof entry.bytes !== 'number') {
        manifestOk = false
        problems.push(`malformed manifest entry at index ${index}`)
        return
      }
      // Closed layout (M-55): a bundle is exactly three files with fixed
      // names. Any other path — traversal, absolute, drive letter, UNC,
      // backslash tricks, or a second copy of a legal name — is refused
      // here, before it can be misread as file content to place on disk.
      if (!BUNDLE_FILE_PATHS.has(entry.path)) {
        manifestOk = false
        problems.push(
          `manifest entry at index ${index} names a path outside the bundle layout ("${entry.path}")`
          + ` — a bundle carries exactly ${EVIDENCE_FILE}, ${BASELINE_FILE} and ${ANCHOR_FILE}`,
        )
        return
      }
      if (listed.has(entry.path)) {
        manifestOk = false
        problems.push(`manifest lists ${entry.path} more than once`)
        return
      }
      listed.add(entry.path)
      const contents = files[entry.path]
      if (typeof contents !== 'string') {
        manifestOk = false
        digestMismatches.push(entry.path)
        problems.push(`manifest lists a file the bundle does not carry: ${entry.path}`)
        return
      }
      const actualDigest = sha256(contents)
      const actualBytes = Buffer.byteLength(contents, 'utf8')
      if (actualDigest !== entry.sha256) {
        manifestOk = false
        digestMismatches.push(entry.path)
        problems.push(`digest mismatch for ${entry.path}: manifest says ${entry.sha256}, bundle holds ${actualDigest}`)
      } else if (actualBytes !== entry.bytes) {
        manifestOk = false
        digestMismatches.push(entry.path)
        problems.push(`byte-size mismatch for ${entry.path}: manifest says ${entry.bytes}, bundle holds ${actualBytes}`)
      }
    })
  }
  const unlisted = Object.keys(files).filter(path => !listed.has(path)).sort()
  for (const path of unlisted) {
    manifestOk = false
    problems.push(`bundle carries a file the manifest does not list: ${path}`)
  }
  const evidenceLog = files[EVIDENCE_FILE]
  if (typeof evidenceLog !== 'string') {
    manifestOk = false
    problems.push(`bundle is missing ${EVIDENCE_FILE}`)
  }

  // -- 3. chain walk -------------------------------------------------------
  const lines = typeof evidenceLog === 'string' ? splitLogLines(evidenceLog) : []
  const walk = walkChain(lines)
  // An empty log is not a clean verdict (v0.22, closing the H-05 app-layer
  // pillar): a bundle that carries zero records and zero checkpoints has
  // nothing to verify, and "verified clean" must never be readable as
  // "proven something". The problem is explicit so downstream consumers
  // (delegation submissions) refuse it through their existing
  // problems-empty gate.
  if (typeof evidenceLog === 'string' && lines.length === 0) {
    problems.push('evidence log is empty: no records and no checkpoints — the bundle carries nothing to verify')
  }
  // W10-M5 (v0.23): zero LINES was already a problem; zero RECORDS is the
  // subtler shape — a log whose every line is a checkpoint (the single
  // `count: 0` checkpoint is the canonical form) walks clean, chains clean,
  // and carries no evidence whatsoever. Structure without content is not
  // verifiable evidence: the aggregate verdict must refuse to read as
  // "proven something" exactly as it does for the empty log.
  if (typeof evidenceLog === 'string' && lines.length > 0 && walk.records === 0) {
    problems.push(
      `evidence log carries no records: ${lines.length} line(s) but not one evidence or marker record`
      + ' — structurally intact and content-empty is not verifiable evidence',
    )
  }
  for (const index of walk.chainBreaks) {
    problems.push(`chain break at line ${index}: prev does not match the previous line's digest`)
  }
  for (const index of walk.corruptLines) {
    problems.push(`corrupt line at index ${index}: not a valid v1/v2 envelope`)
  }
  // H-05/B2-H1: core built `malformedCheckpoints` precisely to catch the
  // forged-count laundering shapes (`1e999`, inflated counts) that pass
  // every typeof check; dropping them here let a rewritten-but-rechained
  // log verify "clean". They are problems now, and ride the result field.
  for (const index of walk.malformedCheckpoints) {
    problems.push(`malformed checkpoint at line ${index}: its self-reported count does not match the records the walk counted`)
  }
  // X-H-04 (v0.23): the uncovered tail. `tailRecords` has always been
  // reported as a field; it was never a problem, so a forger could append
  // arbitrary self-chained records behind one signed checkpoint and ride
  // the covered prefix's clean verdict (the delegation path gates on
  // `problems`, which never saw the tail). Records riding behind the last
  // checkpoint are unverifiable BY that checkpoint — that is a problem now,
  // whenever the chain HAS a checkpoint to ride behind. A checkpoint-less
  // chain stays clean as ever: its `unsigned` mode already says nothing
  // vouches for it, and there is no covered prefix to launder through.
  if (walk.checkpoints.length > 0 && walk.tailRecords > 0) {
    problems.push(
      `${walk.tailRecords} record(s) ride behind the last checkpoint, unverifiable by it`
      + ' — the checkpointed prefix does not vouch for the tail',
    )
  }
  // X-H-03 (v0.23): the head-liar. An honest writer stamps the chain digest
  // at the checkpoint's position into `payload.head` — exactly what
  // `walkChain` recomputes as `expectedHead`. A checkpoint that disagrees
  // is either replayed from another position/chain (its signature may
  // verify: the payload WAS signed, somewhere else) or sits on a rewritten
  // prefix. The contradiction is keyless, so it is named whether or not a
  // signer was at hand; the crypto charge below only sharpens it.
  const headLiars = walk.checkpoints.filter(cp => cp.payload.head !== cp.expectedHead)
  for (const cp of headLiars) {
    problems.push(
      `checkpoint head does not match the walked chain position at line ${cp.index}`
      + ` (walk expected ${cp.expectedHead}, checkpoint declares ${cp.payload.head})`,
    )
  }

  // Checkpoint-signature adjudication (H-05): `walkChain` reports `signed`
  // for any checkpoint that merely CARRIES a `sig` — presence, not proof.
  // When the caller holds the named key, the signature is actually verified
  // (same three-state discipline as `EvidenceStore.audit()`: only a key we
  // hold, facing a checkpoint that names that very keyId, gets to refute);
  // when no held key matches, the honest answer is `unverified`, and the
  // chain mode says `signed-unverified` so no consumer mistakes signature
  // fields for verified signatures. X-H-03 (v0.23): a checkpoint whose
  // signature VERIFIES but whose head lies about its position is charged
  // invalid — a genuine signature over a planted position is a replay, not
  // proof of this chain. Supply side (X-H-02): the signer arrives via the
  // options object (or the legacy positional form), so engines and direct
  // callers alike can reach this code at all.
  let checkpointSignature: 'verified' | 'invalid' | 'unverified' | undefined
  let chainMode: BundleChainMode = walk.mode
  if (walk.mode === 'signed') {
    const adjudicable = anchorSigner === undefined ? [] : walk.checkpoints.filter(cp =>
      cp.sig !== null && cp.sig.length > 0 && cp.keyId === anchorSigner.keyId)
    if (adjudicable.length === 0) {
      checkpointSignature = 'unverified'
      chainMode = 'signed-unverified'
    } else {
      let allValid = true
      const verifiedIndexes = new Set<number>()
      for (const cp of adjudicable) {
        let valid: boolean
        try {
          valid = await anchorSigner!.verify(checkpointSignedData(cp.payload), cp.sig as string)
        } catch {
          // W10-L8 discipline on the checkpoint side too: a throwing key
          // implementation is a failed verification, never a crash.
          valid = false
        }
        if (valid) {
          verifiedIndexes.add(cp.index)
        } else {
          allValid = false
          problems.push(`checkpoint signature invalid at line ${cp.index} (keyId ${JSON.stringify(cp.keyId)})`)
        }
      }
      // X-H-03: the replay charge. The signature was minted over this exact
      // payload — but the walk just proved the payload's head does not name
      // this chain position, so the only honest source of the signature is
      // another log. Verified-and-lied invalidates the adjudication.
      const replayed = headLiars.filter(cp => verifiedIndexes.has(cp.index))
      if (replayed.length > 0) {
        allValid = false
        for (const cp of replayed) {
          problems.push(
            `checkpoint signature replays at line ${cp.index}: it verifies against the named key`
            + ' but its payload.head names another chain position — a replayed checkpoint, not proof of this chain',
          )
        }
      }
      checkpointSignature = allValid ? 'verified' : 'invalid'
    }
  }

  // -- 4. anchor (optional) -------------------------------------------------
  let anchor: BundleAnchor | undefined
  const anchorRaw = files[ANCHOR_FILE]
  if (typeof anchorRaw === 'string') {
    const parsed = parseAnchor(anchorRaw)
    if (parsed === undefined) {
      problems.push(`${ANCHOR_FILE} does not parse as a v1 anchor file`)
    } else {
      const lastCheckpoint = walk.checkpoints[walk.checkpoints.length - 1]
      const headMatchesChain = lastCheckpoint !== undefined && parsed.head === lastCheckpoint.payload.head
      if (lastCheckpoint === undefined) {
        problems.push(`${ANCHOR_FILE} present but the chain has no checkpoint to match its head against`)
      } else if (!headMatchesChain) {
        problems.push('anchor head does not match the last checkpoint head')
      }
      anchor = { keyId: parsed.keyId, count: parsed.count, head: parsed.head, headMatchesChain }
      // Signature adjudication, mirroring `EvidenceStore.audit()`: only a key
      // we actually hold, facing an anchor that names that very keyId and
      // carries the `workspaceKey` its signature commits to, may refute. No
      // signer, a foreign keyId, or a pre-workspaceKey anchor is a missing
      // capability — recorded as "not checked", never as forgery.
      const signatureAdjudicated = anchorSigner !== undefined
        && parsed.sig !== ''
        && parsed.workspaceKey !== undefined
        && parsed.keyId === anchorSigner.keyId
      if (signatureAdjudicated) {
        const signed = checkpointSignedData({
          count: parsed.count,
          head: parsed.head,
          workspaceKey: parsed.workspaceKey,
          at: parsed.at,
        })
        // W10-L8 (v0.23): a bare await here let a throwing key
        // implementation reject the whole verification promise — a hostile
        // or broken signer crashing its auditor is a denial-of-service
        // bypass of the verdict, the exact shape core's audit refuses. A
        // throw is a failed verification, nothing more.
        let valid: boolean
        try {
          valid = await anchorSigner!.verify(signed, parsed.sig)
        } catch {
          valid = false
        }
        if (!valid) problems.push('anchor signature invalid')
      } else if (lastCheckpoint !== undefined) {
        // The keyless floor (M-57): the signature covers count, head,
        // workspaceKey and at — so when it WAS adjudicated, its verdict
        // subsumes everything below (a passing signature cannot coexist
        // with a mismatched count). When it was NOT adjudicable (no signer,
        // foreign keyId, stripped sig), the anchor's identity fields are
        // still cross-checked against the chain and manifest — garbage
        // counts, foreign keyIds and workspace-key swaps are contradictions
        // provable without any key, and they stop riding along beside the
        // one affirmative boolean (`headMatchesChain`) as if they agreed.
        // W10-L9 (v0.23): the keyId the anchor must answer to is the
        // chain's SIGNING identity, not merely the last line's field. A
        // final checkpoint whose keyId was stripped (or never written — an
        // honestly unsigned boundary over a signed history) used to blank
        // this cross-check entirely, letting a foreign anchor keyId ride
        // beside the very checkpoints that name the real one. When the last
        // checkpoint carries no keyId, the most recent signature-bearing
        // checkpoint's keyId speaks for the chain instead.
        const chainKeyId = lastCheckpoint.keyId
          ?? walk.checkpoints.findLast(cp => cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null)?.keyId
        if (chainKeyId !== undefined && parsed.keyId !== chainKeyId) {
          problems.push(
            `anchor keyId ${JSON.stringify(parsed.keyId)} does not match the chain's signing keyId ${JSON.stringify(chainKeyId)}`,
          )
        }
        if (parsed.count !== lastCheckpoint.payload.count) {
          problems.push(
            `anchor count (${parsed.count}) does not match the last checkpoint's count (${lastCheckpoint.payload.count})`,
          )
        }
        if (parsed.workspaceKey !== undefined && parsed.workspaceKey !== manifest.workspaceKey) {
          problems.push(
            `anchor workspaceKey ${JSON.stringify(parsed.workspaceKey)} does not match the manifest's ${JSON.stringify(manifest.workspaceKey)}`,
          )
        }
      }
    }
  }

  // -- 5. baseline (optional) ------------------------------------------------
  let baselineId: string | undefined
  let baselineSelfAddressed = false
  const baselineRaw = files[BASELINE_FILE]
  if (typeof baselineRaw === 'string') {
    const parsed = parseBaselineDocument(baselineRaw)
    if (parsed === undefined) {
      problems.push(`${BASELINE_FILE} does not parse as a baseline document`)
    } else if (typeof parsed.baselineId !== 'string') {
      problems.push(`${BASELINE_FILE} carries no baselineId`)
    } else {
      baselineId = parsed.baselineId
      // Re-derive exactly what `buildBaseline` hashed: createdAt, the workspace
      // snapshot, the checkId list, and the merkle root. Key order is
      // irrelevant — `addressOf` canonicalises — but the field set is not.
      const material = baselineAddressMaterial(parsed)
      if (material === undefined) {
        problems.push('baseline is not self-addressed: its address material is malformed')
      } else {
        baselineSelfAddressed = addressOf(material) === parsed.baselineId
        if (!baselineSelfAddressed) {
          problems.push('baseline is not self-addressed: baselineId does not match the recomputed address')
        }
      }
    }
  }

  // -- 6. transparency record (optional) ------------------------------------
  // Structural adjudication ONLY (see the doc comment above): the manifest
  // alone can prove a record could never be valid — a leaf hash that is not
  // a digest, a sequence outside the published tree, a logId that disagrees
  // with the head it names, a proof longer than the tree has nodes to
  // explain, a published head missing its own fields. It cannot prove a
  // well-shaped record is *true*; that needs the log, and pretending
  // otherwise here would hand a forger a check the bundle never cashed.
  // One contradiction the bundle CAN prove without the log: a record claims
  // a checkpoint was published, and publication only ever mirrors a SIGNED
  // checkpoint — a bundled chain with no signature-bearing checkpoint can
  // never have been published honestly.
  let transparency: 'recorded' | 'malformed' | undefined
  const rawTransparency = manifest.transparency
  if (rawTransparency !== undefined) {
    const reason = transparencyMalformation(rawTransparency)
    if (reason === undefined) {
      transparency = 'recorded'
      const hasSignedCheckpoint = walk.checkpoints.some(cp => cp.sig !== null && cp.sig.length > 0)
      if (!hasSignedCheckpoint) {
        problems.push(
          'manifest carries a transparency record but the bundled chain has no signed checkpoint to have been published',
        )
      }
    } else {
      transparency = 'malformed'
      problems.push(`malformed transparency record: ${reason}`)
    }
  }

  return {
    protocolOk,
    manifestOk,
    digestMismatches,
    chainBreaks: [...walk.chainBreaks],
    corruptLines: [...walk.corruptLines],
    malformedCheckpoints: [...walk.malformedCheckpoints],
    tailRecords: walk.tailRecords,
    // V4-M1 (v0.24): the field is the COUNT of lying checkpoints (a number —
    // see the interface doc); the individual line indexes are already named
    // in `problems` above. Pinned as a count by test/22; the engine's
    // consumption side must read `> 0`, never shape it into an array.
    ...(headLiars.length > 0 ? { headLiars: headLiars.length } : {}),
    chainMode,
    ...(anchor !== undefined ? { anchor } : {}),
    ...(baselineId !== undefined ? { baselineId } : {}),
    baselineSelfAddressed,
    ...(transparency !== undefined ? { transparency } : {}),
    ...(dialect.kind === 'legacy' ? { legacyProtocol: true } : {}),
    ...(checkpointSignature !== undefined ? { checkpointSignature } : {}),
    problems,
  }
}

/**
 * Why a manifest's transparency record could never be valid, or `undefined`
 * when it is structurally sound. Pure shape/bound checking — no hashes over
 * material the bundle does not carry, no log lookups.
 */
function transparencyMalformation(value: unknown): string | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return 'not an object'
  const record = value as Partial<ManifestTransparency> & { publishedHead?: unknown; inclusionProof?: unknown }
  if (typeof record.logId !== 'string' || record.logId.length === 0) {
    return 'logId must be a non-empty string'
  }
  if (typeof record.sequence !== 'number' || !Number.isSafeInteger(record.sequence) || record.sequence < 0) {
    return 'sequence must be a non-negative safe integer'
  }
  if (typeof record.leafHash !== 'string' || !/^[0-9a-f]{64}$/.test(record.leafHash)) {
    return 'leafHash must be 64 lowercase hex characters'
  }
  const head = record.publishedHead
  if (head === null || typeof head !== 'object' || Array.isArray(head)) {
    return 'publishedHead must be an object'
  }
  const published = head as Partial<SignedTreeHead>
  if (typeof published.logId !== 'string' || published.logId.length === 0) {
    return 'publishedHead.logId must be a non-empty string'
  }
  // treeSize >= 1: a head over zero leaves attests nothing, and a proof bound
  // computed from it (ceil(log2 0) + 1) would be meaningless.
  if (typeof published.treeSize !== 'number' || !Number.isSafeInteger(published.treeSize) || published.treeSize < 1) {
    return 'publishedHead.treeSize must be a positive safe integer'
  }
  // M-56: sequence must sit INSIDE the tree the record pins — the manifest
  // proves this contradiction on its own (a one-leaf tree has no entry 999).
  if (record.sequence >= published.treeSize) {
    return `sequence ${record.sequence} is not below the published tree size ${published.treeSize}`
  }
  // M-56: the record's logId and the head it pins must name the same log.
  if (record.logId !== published.logId) {
    return `record logId ${JSON.stringify(record.logId)} does not match publishedHead.logId ${JSON.stringify(published.logId)}`
  }
  if (typeof published.root !== 'string' || !/^[0-9a-f]{64}$/.test(published.root)) {
    return 'publishedHead.root must be 64 lowercase hex characters'
  }
  if (typeof published.at !== 'string' || published.at.length === 0) {
    return 'publishedHead.at must be a non-empty string'
  }
  if (typeof published.sig !== 'string' || published.sig.length === 0) {
    return 'publishedHead.sig must be a non-empty string'
  }
  const proof = record.inclusionProof
  if (!Array.isArray(proof) || proof.some(node => typeof node !== 'string' || !/^[0-9a-f]{64}$/.test(node))) {
    return 'inclusionProof must be an array of 64-hex digest strings'
  }
  // A merkle tree of N leaves explains at most ceil(log2(N)) + 1 proof nodes;
  // anything longer can never be a valid path, whatever the log later says.
  const maxNodes = Math.ceil(Math.log2(published.treeSize)) + 1
  if (proof.length > maxNodes) {
    return `inclusionProof has ${proof.length} nodes but a tree of ${published.treeSize} leaves explains at most ${maxNodes}`
  }
  return undefined
}

/** Split a log into lines, dropping the trailing empty line of a newline-terminated file. */
function splitLogLines(log: string): string[] {
  const lines = log.split('\n')
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

/** Parse `baseline.json` defensively; `undefined` when it is not an object. */
function parseBaselineDocument(raw: string): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(raw) as unknown
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
    return value as Record<string, unknown>
  } catch {
    return undefined
  }
}

/**
 * The exact material `buildBaseline` addresses, re-derived from a parsed
 * baseline document. `undefined` when a required field is malformed — a
 * document whose material cannot even be reconstructed is not self-addressed.
 */
function baselineAddressMaterial(parsed: Record<string, unknown>): unknown {
  if (typeof parsed.createdAt !== 'string' || typeof parsed.root !== 'string') return undefined
  const workspace = parsed.workspace
  if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return undefined
  const checks = parsed.checks
  if (!Array.isArray(checks)) return undefined
  return {
    createdAt: parsed.createdAt,
    workspace,
    checkIds: checks.map(check => (check === null || typeof check !== 'object' ? undefined : (check as { checkId?: unknown }).checkId)),
    root: parsed.root,
  }
}
