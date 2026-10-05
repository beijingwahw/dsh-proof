/**
 * APP/1.0 proof bundles — the portable exchange format for a dsh-proof
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
import { appFingerprint, protocolHeader } from './protocol.ts'
import type { BundleManifest } from './protocol.ts'

/** The log file every bundle carries; the format `core/trust.ts` walks. */
export const EVIDENCE_FILE = 'evidence.jsonl'

/** The saved baseline document, when the session had one to export. */
export const BASELINE_FILE = 'baseline.json'

/** The out-of-band high-water mark, when the session anchored its chain. */
export const ANCHOR_FILE = 'anchor.json'

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
 * A portable proof bundle: the manifest (protocol header + file digests) and
 * the files themselves, keyed by path. JSON-serialisable as-is; `buildBundle`
 * fixes the key order (`manifest` first, then `files` in the canonical file
 * order) so two producers packing the same input emit identical bytes.
 */
export interface ProofBundle {
  readonly manifest: BundleManifest
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
  /** Records appended after the last checkpoint (chain-covered, not checkpoint-covered). */
  readonly tailRecords: number
  /** `legacy` / `unsigned` / `signed`, passed through from `walkChain`. */
  readonly chainMode: ChainMode
  /** Anchor facts, when the bundle carries an `anchor.json` that parses. */
  readonly anchor?: BundleAnchor
  /** The baseline's own id, when the bundle carries a parseable `baseline.json`. */
  readonly baselineId?: string
  /** Whether the baseline's `baselineId` still addresses its own material. */
  readonly baselineSelfAddressed: boolean
  /** Human-readable anomaly list; empty means the bundle verified clean. */
  readonly problems: readonly string[]
}

/**
 * Pack a proof bundle. Deterministic: the same input, workspace key and
 * timestamp always produce byte-identical JSON — `manifest` first, `files`
 * in the canonical order (`evidence.jsonl` → `baseline.json`? → `anchor.json`?),
 * manifest fields in `protocolHeader` order.
 */
export function buildBundle(input: BundleInput, workspaceKey: string, createdAt: string): ProofBundle {
  const files: Record<string, string> = {}
  const entries: ManifestFileEntry[] = []
  const pack = (path: string, contents: string): void => {
    files[path] = contents
    entries.push({ path, sha256: sha256(contents), bytes: Buffer.byteLength(contents, 'utf8') })
  }
  pack(EVIDENCE_FILE, input.evidenceLog)
  if (input.baselineJson !== undefined) pack(BASELINE_FILE, input.baselineJson)
  if (input.anchorJson !== undefined) pack(ANCHOR_FILE, input.anchorJson)
  const manifest: BundleManifest = { ...protocolHeader(workspaceKey, createdAt), files: entries }
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
 * 1. **Protocol identity** — the manifest speaks `APP/1.0` and carries this
 *    implementation's `appFingerprint()`. A dialect we cannot reproduce must
 *    be refused, not guessed at.
 * 2. **Manifest vs files** — every listed path is present with a matching
 *    digest and byte length; files the manifest does not list are anomalies.
 * 3. **Chain walk** — `walkChain` over the log's lines; breaks and corrupt
 *    lines are passed through verbatim as problems.
 * 4. **Anchor** (when carried) — parsed with core's `parseAnchor`; its head
 *    is compared against the chain's last checkpoint. When the caller
 *    supplies a signer, the anchor's detached signature over
 *    `checkpointSignedData({count, head, workspaceKey, at})` is adjudicated
 *    under the same burden-of-proof rules as `EvidenceStore.audit()`: only a
 *    key that *is* the named keyId, over an anchor that *carries*
 *    `workspaceKey`, gets to refute — a missing capability is never an
 *    accusation.
 * 5. **Baseline** (when carried) — parsed; its `baselineId` must still
 *    address the same material `buildBaseline` hashed (`createdAt`,
 *    `workspace`, `checkIds`, `root`).
 */
export async function verifyBundle(
  bundle: ProofBundle,
  anchorSigner?: { keyId: string; verify: (data: string, sig: string) => Promise<boolean> },
): Promise<BundleVerification> {
  const problems: string[] = []

  // Untrusted input: the bundle may be hand-crafted, so read it defensively.
  const raw = (bundle ?? {}) as unknown as Partial<ProofBundle>
  const manifest = (raw.manifest ?? {}) as Partial<BundleManifest>
  const files = (raw.files ?? {}) as Record<string, string>

  // -- 1. protocol identity ------------------------------------------------
  const protocolOk = manifest.protocol === 'APP/1.0' && manifest.appFingerprint === appFingerprint()
  if (manifest.protocol !== 'APP/1.0') {
    problems.push(`unsupported bundle protocol: ${JSON.stringify(manifest.protocol)} (expected "APP/1.0")`)
  } else if (manifest.appFingerprint !== appFingerprint()) {
    problems.push('app fingerprint mismatch: the manifest was produced by a different implementation')
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
  for (const index of walk.chainBreaks) {
    problems.push(`chain break at line ${index}: prev does not match the previous line's digest`)
  }
  for (const index of walk.corruptLines) {
    problems.push(`corrupt line at index ${index}: not a valid v1/v2 envelope`)
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
      if (
        anchorSigner !== undefined
        && parsed.sig !== ''
        && parsed.workspaceKey !== undefined
        && parsed.keyId === anchorSigner.keyId
      ) {
        const signed = checkpointSignedData({
          count: parsed.count,
          head: parsed.head,
          workspaceKey: parsed.workspaceKey,
          at: parsed.at,
        })
        if (!(await anchorSigner.verify(signed, parsed.sig))) problems.push('anchor signature invalid')
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

  return {
    protocolOk,
    manifestOk,
    digestMismatches,
    chainBreaks: [...walk.chainBreaks],
    corruptLines: [...walk.corruptLines],
    tailRecords: walk.tailRecords,
    chainMode: walk.mode,
    ...(anchor !== undefined ? { anchor } : {}),
    ...(baselineId !== undefined ? { baselineId } : {}),
    baselineSelfAddressed,
    problems,
  }
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
