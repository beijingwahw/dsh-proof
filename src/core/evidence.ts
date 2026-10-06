/**
 * The evidence layer: content-addressed records over an append-only log.
 *
 * Design mirrors DSH's own session-log rule — "everything the model saw must be
 * reconstructable from the log". Here the invariant is stricter: *every claim
 * the model makes must be recomputable from the evidence log*. The log is
 * append-only; a `baseline` or `proof` is just a named view over it.
 *
 * Since v0.2 the log is also tamper-evident against its own writer: every
 * line carries `prev = sha256(previous line)` (a hash chain), checkpoints
 * are signed by a host-held key (see `core/trust.ts`), the highest
 * checkpoint is mirrored to an anchor file outside the workspace, and the
 * baseline file's digest is recorded in the chain when it is saved.
 *
 * @module dsh-proof/core/evidence
 */

import type { CheckKind, CheckSource, CheckSpec, Clock, FsPort, SignerPort, WorkspacePort } from './ports.ts'
import { addressOf, merkleRoot, normalizeOutput, sha256 } from './hash.ts'
import type { NormalizeOptions } from './hash.ts'
import { GENESIS_PREV, SIG_REFUSED_PREFIX, checkpointSignedData, lineDigest, parseAnchorEx, walkChain } from './trust.ts'
import type { AnchorFile, ChainWalk, WalkedCheckpoint } from './trust.ts'
import { excerptOutput, type ExcerptOptions } from './excerpt.ts'
import type { SyntheticEvidenceMeta } from './synthetic.ts'

export type CheckStatus = 'pass' | 'fail' | 'error' | 'timeout' | 'aborted' | 'skipped'

/** One observed run of one check. Addressed by its own canonical digest. */
export interface Evidence {
  readonly evidenceId: string
  readonly checkId: string
  readonly label: string
  readonly kind: CheckKind
  readonly command: readonly string[]
  /**
   * Which discovery source minted the addressed check (ο). Participates in
   * the content address, so the record says — without consulting any live
   * spec pool — whether it came from `package.json`, `config`, or was
   * `synthetic` (agent-constructed; see `core/synthetic.ts`). Downstream
   * verdicts key on this instead of re-deriving provenance: an evidence log
   * must stay interpretable from its own bytes.
   */
  readonly source?: CheckSource
  readonly status: CheckStatus
  readonly exitCode: number | null
  readonly durationMs: number
  /** sha256 of `normalizeOutput(output)` — content addressing without storing the noise. */
  readonly outputDigest: string
  /** Excerpt of the normalised output under the configured budget (v0.5). */
  readonly outputHead: string
  /** True when the excerpt dropped content (`[... N chars omitted ...]` markers account for it). */
  readonly outputTruncated?: boolean
  /** How many normalised characters are not in the excerpt. */
  readonly outputOmittedChars?: number
  /**
   * ο: present only on synthetic-check records — the verbatim script digest,
   * sandbox tier, screen findings and authorship. Participates in the content
   * address, so the record *self-certifies what ran*: two runs with the same
   * observable outcome but different scripts are two different pieces of
   * evidence, and neither can borrow the other's pass.
   */
  readonly synthetic?: SyntheticEvidenceMeta
  /**
   * τ: what of the change set *this record's own run* actually executed —
   * the executed/uncovered split of the V8 coverage the check's process left
   * behind (see `core/coverage.ts`). Like `synthetic`, it participates in the
   * content address: a record cannot claim to have exercised a change it
   * never ran, and two records with the same green output but different
   * execution footprints are two different pieces of evidence. Absent on
   * pre-τ records and on runs without instrumentation.
   */
  readonly coverage?: {
    readonly changedExecuted: readonly string[]
    readonly changedUncovered: readonly string[]
  }
  readonly recordedAt: string
  /** Workspace state when the evidence was produced. */
  readonly workspace: WorkspaceSnapshot
}

export interface WorkspaceSnapshot {
  readonly head: string | null
  readonly dirty: readonly string[]
  /** Digest of the dirty-file set, so "the same dirt" compares equal. */
  readonly dirtDigest: string
  /**
   * sha256 of each dirty file's *content* at snapshot time. Baseline checks
   * ran against the working tree as it was, so these digests — not the
   * commit — are the anchor change-set resolution diffs against (v0.3).
   */
  readonly dirtyDigests?: Readonly<Record<string, string>>
  /**
   * M-34: the git queries behind this snapshot FAILED — `head: null` and
   * `dirty: []` mean "unobservable", not "clean tree, no commits". The old
   * behaviour content-addressed that blind guess as if it were a fact; the
   * flag rides the snapshot (and therefore the record's address) so every
   * consumer can tell a clean tree from a blinded one. Absent on honest
   * snapshots, so every existing address is untouched.
   */
  readonly gitDegraded?: boolean
}

/** A named, ordered collection of evidence records. */
export interface Baseline {
  readonly baselineId: string
  readonly createdAt: string
  readonly workspace: WorkspaceSnapshot
  /** checkId -> evidence, in discovery order. */
  readonly checks: readonly Evidence[]
  /** Merkle root over the evidence addresses — the baseline's fingerprint. */
  readonly root: string
}

/**
 * Verdict about one check, derived purely from a baseline and fresh evidence.
 *
 * The lattice is three-valued. Every verdict is either *credit*
 * (`still-passing`, `fixed`, a decisively-run `new-check`), *blame*
 * (`regression`, `still-failing`, `new-failure`) or *neither*
 * (`indeterminate`, `not-run`, a `new-check` that never ran). `indeterminate`
 * is the honest middle: at least one side of the comparison produced no
 * decisive result (`skipped`, `timeout`, `aborted`, `error`), so the check
 * deserves neither credit nor blame. Blame requires a decisive baseline pass;
 * credit requires a decisive baseline fail — anything less is unknown, and
 * unknown is never silently rounded up to "ok".
 */
export type CheckVerdict =
  | 'still-passing'
  | 'still-failing'
  | 'regression'
  | 'fixed'
  | 'new-failure'
  | 'new-check'
  | 'not-run'
  | 'indeterminate'

export interface CheckReport {
  readonly checkId: string
  readonly label: string
  readonly kind: CheckKind
  readonly verdict: CheckVerdict
  readonly baseline?: Evidence
  readonly current?: Evidence
  /** Files changed in this session that fall inside this check's impact set. */
  readonly attributedTo: readonly string[]
  /** Suspect files that changed *outside* the agent's tool stream (v0.3). */
  readonly externalSuspects?: readonly string[]
}

export type ProofGrade = 'proven' | 'unproven' | 'regressed' | 'no-baseline' | 'stale'

export interface ProofReport {
  readonly grade: ProofGrade
  readonly root: string
  readonly baselineRoot: string | null
  readonly baselineCreatedAt: string | null
  readonly generatedAt: string
  readonly workspace: WorkspaceSnapshot
  /** Only the checks the change set actually touches. */
  readonly checks: readonly CheckReport[]
  /** Everything discovered, whether or not it was run. */
  readonly discovered: number
  /** Checks whose evidence is missing after an incremental run. */
  readonly unverified: readonly string[]
  /**
   * H5②: baseline checks whose definitions vanished from discovery (the
   * pool was edited). Optional so pre-v0.16 reports and the jury assemblers
   * stay byte-compatible; `assembleProof` always emits it.
   */
  readonly vanished?: readonly string[]
  readonly summary: {
    readonly passing: number
    readonly failing: number
    readonly regressions: number
    readonly fixed: number
    readonly preExisting: number
    readonly newChecks: number
    /** Checks where at least one side of the comparison was non-decisive — neither credit nor blame. */
    readonly indeterminate: number
  }
  /** Regressions in plain language, ready to inject into the agent's context. */
  readonly regressions: readonly string[]
}

const HEAD_CHARS = 2000
const DEFAULT_EXCERPT: ExcerptOptions = { budget: HEAD_CHARS, strategy: 'head' }

// ---------------------------------------------------------------------------
// Producing evidence
// ---------------------------------------------------------------------------

export interface RunOutcome {
  readonly status: CheckStatus
  readonly exitCode: number | null
  readonly durationMs: number
  readonly output: string
}

/**
 * Turn one observed run into an addressable evidence record.
 *
 * ο: the trailing `synthetic` parameter is the self-certifying metadata for
 * agent-constructed checks (script digest, sandbox tier, screen findings,
 * authorship). It rides into the content address like every other field —
 * the point is exactly that a record cannot claim a script it did not run.
 * Optional and last, so every pre-ο call site is untouched.
 *
 * τ: the trailing `coverage` parameter (after `synthetic`, same pattern)
 * carries the executed/uncovered split of the change set for this run, when
 * the check ran under V8 coverage instrumentation. It too rides into the
 * address; every pre-τ call site is untouched.
 */
export function makeEvidence(
  spec: CheckSpec,
  outcome: RunOutcome,
  workspace: WorkspaceSnapshot,
  clock: Clock,
  excerpt: ExcerptOptions = DEFAULT_EXCERPT,
  canonical: NormalizeOptions = {},
  synthetic?: SyntheticEvidenceMeta,
  coverage?: Evidence['coverage'],
): Evidence {
  // Canonical roots make the record location-independent: the same outcome
  // under any checkout directory (or user home) hashes to the same address.
  const normalized = normalizeOutput(outcome.output, canonical)
  const exc = excerptOutput(normalized, excerpt)
  const base = {
    checkId: spec.id,
    label: spec.label,
    kind: spec.kind,
    command: spec.command,
    // The spec's source is part of the record itself (see the field): a log
    // reader learns "this pass was synthetic" from the record's own bytes.
    source: spec.source,
    status: outcome.status,
    exitCode: outcome.exitCode,
    durationMs: outcome.durationMs,
    outputDigest: sha256(normalized),
    outputHead: exc.text,
    ...(exc.truncated ? { outputTruncated: true, outputOmittedChars: exc.omittedChars } : {}),
    ...(synthetic !== undefined ? { synthetic } : {}),
    ...(coverage !== undefined ? { coverage } : {}),
    recordedAt: new Date(clock.now()).toISOString(),
    workspace,
  }
  return { ...base, evidenceId: addressOf(base) }
}

export function snapshotWorkspace(workspace: WorkspacePort): Promise<WorkspaceSnapshot>
export function snapshotWorkspace(head: string | null, dirty: readonly string[]): WorkspaceSnapshot
export function snapshotWorkspace(
  a: WorkspacePort | string | null,
  b?: readonly string[],
): Promise<WorkspaceSnapshot> | WorkspaceSnapshot {
  if (typeof a === 'object' && a !== null && 'gitHead' in a) {
    const ws = a
    return (async () => {
      // M-34: a failed git query is a fact about observability, not a clean
      // tree. The old `.catch(() => null/[])` folds "index.lock timed out"
      // into "no commits, nothing dirty" — a false state that then rides
      // every record's content address as if it were measured truth. The
      // failure now travels beside the snapshot as `gitDegraded`.
      let degraded = false
      const head = await ws.gitHead().catch(() => { degraded = true; return null })
      const dirty = await ws.gitDirty().catch(() => { degraded = true; return [] as string[] })
      const snapshot = snapshotWorkspace(head, dirty)
      return degraded ? { ...snapshot, gitDegraded: true } : snapshot
    })()
  }
  const head = a as string | null
  const dirty = [...(b ?? [])].sort()
  // W1-M8 (v0.23): length-prefixed encoding, not `join('\n')`. POSIX file
  // names may contain `\n`, so `['a\nb']` and `['a', 'b']` hashed equal —
  // "the same dirt" compared equal for different dirty sets. Each component
  // is spelled `<length>:<exactly length chars>`, which is uniquely parseable,
  // so the concatenation is injective over the list. The empty list still
  // digests the empty string (a clean tree keeps its old digest); every other
  // set now hashes differently than the v0.22 formula, which only affects
  // FUTURE records' addresses — stored records keep their recorded digest and
  // still address themselves under it.
  return { head, dirty, dirtDigest: sha256(dirty.map(p => `${p.length}:${p}`).join('')) }
}

// ---------------------------------------------------------------------------
// Baselines
// ---------------------------------------------------------------------------

export function buildBaseline(records: readonly Evidence[], workspace: WorkspaceSnapshot, clock: Clock): Baseline {
  const root = merkleRoot(records.map(r => r.evidenceId))
  const material = {
    createdAt: new Date(clock.now()).toISOString(),
    workspace,
    checkIds: records.map(r => r.checkId),
    root,
  }
  return {
    baselineId: addressOf(material),
    createdAt: material.createdAt,
    workspace,
    checks: records,
    root,
  }
}

// ---------------------------------------------------------------------------
// The append-only, hash-chained evidence log
// ---------------------------------------------------------------------------

export const DEFAULT_LOG_RELPATH = '.proof/evidence.jsonl'
export const DEFAULT_BASELINE_RELPATH = '.proof/baseline.json'

/** Trust wiring for an EvidenceStore: signing, anchoring, checkpoint cadence. */
export interface StoreTrust {
  /** Lazily resolved host signer; `undefined` results in an unsigned chain. */
  readonly signer?: () => Promise<SignerPort | undefined>
  /** Where the out-of-band anchor lives (outside the agent-writable area). */
  readonly anchorPath?: string
  /** Stable identity of the workspace, committed into checkpoints. */
  readonly workspaceKey?: string
  /** Append a checkpoint automatically after this many records. */
  readonly checkpointEvery?: number
}

/** Everything `audit()` can tell you about the log's integrity. */
export interface AuditReport {
  readonly ok: boolean
  /** Evidence records in the log. */
  readonly total: number
  /** checkIds whose payload no longer addresses itself. */
  readonly corrupt: readonly string[]
  /**
   * M15: the anchor file EXISTS but could not be parsed as an anchor
   * (malformed JSON, wrong shape, wrong version). Pure visibility signal —
   * it deliberately does NOT fail `ok`, because an unreadable anchor is a
   * missing capability on the auditor's side, not a provable forgery in the
   * log; but a reader MUST be able to see that the out-of-band defence line
   * (rewind/monotonicity) was not checked. An absent anchor (no file) stays
   * silent as before: "never anchored" is a deployment fact, not a defect.
   * Optional so hand-built reports from older surfaces keep satisfying the
   * type; `audit()` always emits it.
   */
  readonly anchorUnreadable?: boolean
  readonly chain: {
    readonly mode: 'signed' | 'unsigned' | 'legacy'
    readonly breaks: readonly number[]
    readonly checkpoints: number
    /** Checkpoints whose signature this host's key actively refutes — a forgery charge. */
    readonly badCheckpoints: readonly number[]
    /**
     * Checkpoints that carry a signature this host cannot adjudicate: no
     * signer is configured (key lost / different machine), or the checkpoint
     * names a different keyId. A missing capability is not an accusation.
     */
    readonly unverifiableCheckpoints: readonly number[]
    /**
     * Checkpoints carrying no signature while a signer is active on this
     * audit host — a charge. The one shape moved OUT of the charge is the
     * keyless adoption era (see `unsignedEraCheckpoints`): a completely
     * naked line below the first verified checkpoint of the now-held key.
     */
    readonly unsignedCheckpoints: readonly number[]
    readonly headMismatches: readonly number[]
    /**
     * M-33/H-32 (v0.22): checkpoints the *writer itself* recorded as
     * un-signable at append time — a transient signing failure ("key
     * directory locked by a scanner"). Visible, deliberately NOT a failing
     * `ok` charge once a later checkpoint of the same key carries a verified
     * signature (the recovery witness): an honest blip must not red the audit
     * forever, or operators learn to ignore the red. Without the witness the
     * line is indistinguishable from a stripped signature and stays in
     * `unsignedCheckpoints`.
     */
    readonly sigErrorCheckpoints?: readonly number[]
    /**
     * H-27/H-32 (v0.22): checkpoints written unsigned because the store
     * REFUSED to sign — its pre-sign audit found the physical chain rewritten
     * or inflated and declined to lend the forged bytes the host key. A
     * refusal is the store accusing its own log; the accusation is always
     * visible here.
     *
     * Y-H-02 (v0.24): the charge is now GENERATIONALLY SLICED — a refusal
     * fails `ok` only while its generation is unrecovered, i.e. until a
     * later checkpoint of the same key verifies or this process re-anchors
     * over it (see `refusedToSignPardoned`). v0.23 billed every refusal
     * forever, so one honest race, one crash between `mark` and `checkpoint`,
     * or one attacker line (V1-M7) permanently capped every future grade at
     * stale through the X-H-09 consumers — the documented "re-anchor and
     * resume" recovery was a no-op that itself minted fresh refusal rows.
     */
    readonly refusedToSign?: readonly number[]
    /**
     * Y-H-02 (v0.24): the subset of {@link refusedToSign} whose generation
     * has recovered — a later same-key checkpoint with a verified signature
     * exists, or this process wrote a `baseline/*` re-anchor marker after the
     * refusal. The scar stays visible in `refusedToSign`; it no longer fails
     * `ok`. Always emitted (empty when clean) by `audit()`.
     */
    readonly refusedToSignPardoned?: readonly number[]
    /**
     * Y-H-02 (v0.24): the keyless ADOPTION era, made visible without being a
     * charge — completely naked checkpoints (no sig, no sigError, no keyId;
     * only writable while no signer was configured) sitting below the FIRST
     * verified checkpoint of the key this audit host now holds. Before the
     * slice these rows lived in `unsignedCheckpoints` forever, so adopting a
     * signer was a one-way door to a permanent red the documented re-anchor
     * could never heal. Naked lines ABOVE the boundary are not this era (an
     * attacker's appended fake; stripping an honest checkpoint's signature
     * leaves its `keyId` behind) and stay charged. Always emitted (empty
     * when clean) by `audit()`.
     */
    readonly unsignedEraCheckpoints?: readonly number[]
    /**
     * Checkpoints whose self-reported `count` the walk itself refutes — not a
     * non-negative safe integer, or not equal to the records actually walked
     * to that position (see `walkChain`). Signature-independent by design: a
     * checkpoint can be perfectly cryptographic for a key this host cannot
     * adjudicate and still be lying about its count. Optional in the type so
     * hand-built reports from older surfaces keep satisfying it; `audit()`
     * always emits it (empty when clean).
     */
    readonly malformedCheckpoints?: readonly number[]
    /**
     * Line indexes that are not valid v1/v2 envelopes at all (unparseable
     * JSON, wrong envelope shape) — the raw `walkChain` channel the `ok`
     * formula has always consumed but the report never surfaced, so callers
     * could see breaks and bad signatures but not WHICH lines were garbage.
     * Optional for the same hand-built-report compatibility reason;
     * `audit()` always emits it (empty when clean).
     */
    readonly corruptLines?: readonly number[]
    /** Records after the last checkpoint — chain-covered, not checkpoint-covered. */
    readonly tailRecords: number
    /** The log ends before the best checkpoint the anchor remembers. */
    readonly rewind: boolean
    readonly anchorMismatch: boolean
    /** The anchor file failed its own signature check — its data was tampered with. */
    readonly anchorForged: boolean
    /**
     * H-09 (v0.22): the anchor file parses but is in a state no honest writer
     * produces — empty `keyId`, count outside the safe non-negative integers,
     * empty/absent `sig` (the four-line disarm family). Unlike
     * `anchorUnreadable` (an auditor-side capability gap), an invalid anchor
     * is tampering until proven otherwise and FAILS `ok`: the old behaviour
     * silently disabled the rewind/mismatch line of defence instead.
     */
    readonly anchorInvalid?: boolean
    /** The baseline file no longer matches the digest recorded in the chain. */
    readonly baselineTampered: boolean
    /**
     * H-32/M-A1-5 (v0.22): line indexes of *protected* markers (attest/*,
     * baseline/*) whose self-declared chain position (`headRef`) contradicts
     * their physical predecessor — the shape a replayed, moved, or
     * out-of-band-appended marker has. Visible only: suspect is "cannot vouch
     * for this line", not a proven forgery, so it does not by itself fail
     * `ok`; consumers of protected markers (κ fusion, baseline digests) must
     * exclude them from trust decisions instead of reading last-wins.
     */
    readonly suspectMarkers?: readonly number[]
  }
}

interface LogEnvelope {
  readonly v: 1 | 2
  readonly kind: 'evidence' | 'marker' | 'checkpoint'
  readonly at: string
  readonly payload: unknown
  /** v2: digest of the physically previous line. */
  readonly prev?: string
  readonly sig?: string
  readonly keyId?: string
  readonly sigError?: string
}

/**
 * v0.18: the checkpoint a transparency-log publish mirrors — the payload the
 * signature covers, the key that signed it, the detached signature, and the
 * line index it lives at. Returned by `EvidenceStore.latestSignedCheckpoint`.
 */
export interface SignedCheckpointView {
  /** The exact bytes-level material the signature commits to ({count, head, workspaceKey, at}). */
  readonly payload: { readonly count: number; readonly head: string; readonly workspaceKey: string | null; readonly at: string }
  /** The signing key's identity (which key the signature must verify under). */
  readonly keyId: string
  /** Detached signature over `checkpointSignedData(payload)`. */
  readonly sig: string
  /** Index of the checkpoint line within the evidence log. */
  readonly index: number
}

// ---------------------------------------------------------------------------
// Marker read-back with tamper-evidence metadata (H-32/M-A1-5, v0.22)
// ---------------------------------------------------------------------------

/**
 * Marker labels whose payloads feed *trust decisions* (κ attestation fusion,
 * baseline integrity, identity adoption, SLA accounting, jury verdicts,
 * synthetic-check minting), so an injected or replayed line under them is
 * worth forging: every `attest/*` verdict, the `baseline/*` summary family,
 * the `delegation/*` DAG, and `proof/verified`. Writes under these labels
 * carry a `headRef` witness; readers can filter by it (see
 * {@link _readMarkers}).
 *
 * V1-M9 (v0.24): the list is the single source of truth matched against the
 * CONSUMERS that claim to rely on suspect filtering. v0.23 shipped four
 * consumers reading labels the list never covered, making their
 * `excludeSuspect` reads a dead channel — one out-of-band append per label
 * forged host-adoption edges (`agent-team/delegated`), SLA quotes
 * (`economics/quote`), jury verdicts (`claim/jury`) and synthetic-check
 * requests (`synthetic/requested`). Labels join this list exactly when a
 * consumer's trust decision reads them; informational labels stay out so
 * the witness bytes stay minimal.
 *
 * P5 (pattern-five termination): `synthetic/run` joins — the v0.24 leftover
 * of exactly that survey. The run marker is what lets a conjured offer join
 * verification (`syntheticSpecs` mints a spec only for a request whose
 * claimId+entry appears under `synthetic/run`), which is a trust decision:
 * an out-of-band twin under it promoted a never-executed script into the
 * live check pool unflagged, while its sibling `synthetic/requested` was
 * already protected. headRef compatibility follows the late-adopted-label
 * rule every V1-M9 label already lives under: writes go through
 * `markInternal`, so every fresh `synthetic/run` carries the witness
 * automatically (write-side uniformity — no call site changes); pre-adoption
 * logs carry none, read suspect, and are governed by the generational
 * fallback — an all-legacy label degrades and keeps reading, a mixed
 * generation excludes the headRef-less rows from the trusted pool exactly
 * like `synthetic/requested`'s rule. Accepted and documented, not silently
 * smoothed over: re-running the conjured check re-mints a witnessed marker.
 */
export function isProtectedMarkerLabel(label: unknown): boolean {
  return typeof label === 'string'
    && (label.startsWith('attest/')
      || label.startsWith('baseline/')
      || label.startsWith('delegation/')
      || label === 'proof/verified'
      || label === 'agent-team/delegated'
      || label === 'economics/quote'
      || label === 'claim/jury'
      || label === 'synthetic/requested'
      || label === 'synthetic/run')
}

/**
 * X-H-08 (v0.23): the `baseline/*` labels that *change what the log believes
 * about the baseline document* — `baseline/saved` (a new file's digest became
 * the remembered truth) and `baseline/established` (the engine took a fresh
 * anchor, with its own tamper/degradation metadata). An out-of-band append
 * under either label re-defines the baseline the next session verifies
 * against, which is why the pre-sign audit refuses to lend the host key over
 * foreign ones (see `preSignAudit`; v0.25's U1-H1 widened that refusal roster
 * to the full `isProtectedMarkerLabel` list — this predicate now scopes only
 * the Y-H-02 re-anchor recovery witness and the read-time baseline
 * authorship demand). Informational `baseline/*` labels beyond these two
 * (none today) would need the same treatment before being added.
 */
export function isBaselineMarkerLabel(label: unknown): boolean {
  return label === 'baseline/saved' || label === 'baseline/established'
}

/** One marker line, read back with its tamper-evidence metadata. */
export interface MarkerRecord {
  /** Index of the marker line within the log. */
  readonly index: number
  readonly label: string
  readonly payload: Record<string, unknown>
  /**
   * True when a protected marker's `headRef` (the chain head the writer saw
   * at append time) does not match the digest of the line physically before
   * it — the shape of a marker that was replayed at another position, moved,
   * or appended out of band. NOT a proven forgery (a forger that re-chains
   * the whole log can forge a consistent `headRef` too — only signatures
   * close that); it means "this line cannot vouch for where it sits", and
   * trust decisions must skip it rather than read it last-wins.
   */
  readonly suspect: boolean
}

/**
 * Every marker line in a log snapshot, in order, with suspect flags.
 *
 * @internal The single-pass parsing core BOTH trust-decision surfaces derive
 * from (v0.24, Y-H-03): `EvidenceStore.markersWith`/`audit` and
 * `createVerifiedView().markers` call this same function, so suspect
 * adjudication cannot fork between the store face and the view face.
 * v0.25.1 (U4-H1): the export is GONE. The underscore prefix used to mark
 * "the one accepted escape hatch", and four production consumers (index.ts,
 * the DSH attest tools, both adapter faces) walked through it — each
 * hand-assembling view semantics from raw lines while the claims contract
 * stayed green on a regex that deliberately ignored the underscore. The
 * module-private core now has exactly two sanctioned exits: the store/view
 * reads (engine-holding processes) and {@link readChainMarkers} (the
 * engine-less adapter faces). Trust decisions go through the store or the
 * view, never around them.
 *
 * V1-M8 (v0.24): the line-array contract is the node-ports `readLines`
 * convention — blank lines removed. Blank lines are normalised away here
 * defensively, so a caller handing in a raw `split('\n')` and a caller
 * handing in `readLines` output derive the SAME marker indexes and the SAME
 * `previousLineDigest` (previously the two array conventions produced two
 * different suspect verdicts for one physical log).
 *
 * Pure over the given lines — callers hand in the same physical snapshot the
 * rest of their judgement used (the TOCTOU rule: one read, many derivations).
 * `options.label` filters to one label; `options.excludeSuspect` drops
 * suspect lines (the shape κ fusion and baseline-digest reads want: the
 * honest writer's line survives, the attacker's appended twin does not).
 */
function _readMarkers(lines: readonly string[], options: { readonly label?: string; readonly excludeSuspect?: boolean } = {}): MarkerRecord[] {
  const normalized = lines.filter(line => line.trim().length > 0)
  const out: MarkerRecord[] = []
  normalized.forEach((line, index) => {
    const envelope = parseEnvelope(line)
    if (envelope?.kind !== 'marker') return
    const payload = envelope.payload as { label?: unknown }
    if (typeof payload?.label !== 'string') return
    if (options.label !== undefined && payload.label !== options.label) return
    const suspect = isProtectedMarkerLabel(payload.label) && headRefOf(payload) !== previousLineDigest(normalized, index)
    if (options.excludeSuspect === true && suspect) return
    out.push({ index, label: payload.label, payload: payload as Record<string, unknown>, suspect })
  })
  return out
}

/**
 * The one PUBLIC read that carries the H-32 position verdict over a caller's
 * own line snapshot (v0.25.1, U4-H1) — the formal replacement for the retired
 * `_readMarkers` export, not an escape hatch: importing it is a declared,
 * contract-pinned decision, not an accident of naming.
 *
 * WHO MAY USE IT: processes that hold NO engine and NO store. The adapter
 * faces (claude-code hooks, opencode plugin) re-derive `lastBaselineDigest`'s
 * trusted-first selection over their own `readFile` snapshot because their
 * runtime contract carries no fs port and no store wiring — for them this is
 * the only door. Every engine-holding consumer must instead read through
 * `EvidenceStore.markersWith` or `createVerifiedView().markers`: the same
 * single-pass core, plus the generational fallback and the epoch bound this
 * thin read deliberately does NOT re-implement (a hand-rolled fallback beside
 * the view's is exactly how two faces come to disagree about what exists).
 * test/32 claim 1b pins the importer set to the two adapter files.
 *
 * Pure over the given lines; blank lines are normalised away (V1-M8), so a
 * raw `split('\n')` and a `readLines` snapshot derive the same indexes and
 * the same verdicts. `options.label` filters to one label; suspect records
 * stay in the result (flagged) so a caller can apply its own trusted-first
 * degradation, `options.excludeSuspect: true` drops them instead.
 */
export function readChainMarkers(
  lines: readonly string[],
  options: { readonly label?: string; readonly excludeSuspect?: boolean } = {},
): MarkerRecord[] {
  return _readMarkers(lines, options)
}

/**
 * The line indexes a marker pass flags as suspect. Module-private: the audit
 * report's `suspectMarkers` channel is the visible surface, and per-line
 * queries belong on the store/view reads (the old exported
 * `isSuspectMarker` rescanned the whole log per call — the O(n²)~O(n³)
 * amplification the verified view exists to kill — and had no production
 * callers left; removed in v0.24).
 */
function suspectIndexesOf(markers: readonly MarkerRecord[]): readonly number[] {
  return markers.filter(m => m.suspect).map(m => m.index)
}

function headRefOf(payload: Record<string, unknown>): string | undefined {
  return typeof payload.headRef === 'string' ? payload.headRef : undefined
}

/** The digest a v2 line at `index` must chain to (digest of the physically previous line). */
function previousLineDigest(lines: readonly string[], index: number): string | undefined {
  return index === 0 ? GENESIS_PREV : lineDigest(lines[index - 1] as string)
}

/** Content-addressed, append-only, hash-chained evidence store backed by a JSONL file. */
export class EvidenceStore {
  private readonly fs: FsPort
  private readonly logPath: string
  private readonly baselinePath: string
  private readonly clock: Clock
  private readonly trust: StoreTrust
  private readonly cache = new Map<string, Evidence>()

  private tailReady = false
  private tail = GENESIS_PREV
  private recordsSoFar = 0
  private sinceCheckpoint = 0
  private signerPromise: Promise<SignerPort | undefined> | undefined
  /**
   * W1-M3 (v0.23): the failure of the most recent signer-provider attempt,
   * when that attempt REJECTED. The memoized promise settles `undefined` for
   * both "no signer yet" and "provider failed" (the M15 retry semantics
   * require the failure not be cached); this side channel carries WHICH of
   * the two it was, so `checkpointInternal` can record a transient provider
   * failure on the sigError channel instead of writing a naked unsigned
   * checkpoint. Consumed on first read — a later `undefined` resolution is a
   * fresh answer, not this failure.
   */
  private signerResolveError: string | undefined
  /**
   * X-H-08 (v0.23), widened v0.25 (U1-H1): digests of every PROTECTED-marker
   * line THIS process wrote (via `mark`/`saveBaseline` — every protected label
   * flows through `markInternal`, so the set is closed over this process's own
   * writes by construction). v0.23 collected only the baseline family; the
   * laundering the pre-sign audit exists to stop was therefore open under
   * every OTHER protected label: a between-sessions append of a headRef-
   * correct `attest/*` / `delegation/*` / `proof/verified` / `claim/jury` /
   * `economics/quote` / `synthetic/*` line was absorbed by `ensureTail` and
   * then notarised by the host's own next checkpoint — the floor launders the
   * tail at the moment it is minted. Content addressing makes the set
   * replay-proof: an attacker re-appending one of these lines verbatim keeps
   * its digest but breaks the chain (its `prev` still points at its original
   * predecessor); altering anything to re-chain it changes the digest out of
   * the set. See `preSignAudit`.
   */
  private readonly selfProtectedMarkers = new Set<string>()
  /**
   * Single-flight tail for every log-mutating operation. Two concurrent
   * `append`/`mark`/`checkpoint` calls both read the same `this.tail`, both
   * build envelopes chained to it, and the second line's `prev` then points at
   * a line that no longer exists — the chain is broken by *correct* code
   * racing itself. Serialising the write section (tail read → append → tail
   * update) makes the interleaving impossible; reads stay concurrent.
   */
  private tailQueue: Promise<unknown> = Promise.resolve()

  constructor(fs: FsPort, logPath: string, baselinePath: string, clock: Clock, trust: StoreTrust = {}) {
    this.fs = fs
    this.logPath = logPath
    this.baselinePath = baselinePath
    this.clock = clock
    this.trust = trust
  }

  static atWorkspace(fs: FsPort, logPath: string, clock: Clock): EvidenceStore {
    return new EvidenceStore(fs, `${logPath}/${DEFAULT_LOG_RELPATH}`, `${logPath}/${DEFAULT_BASELINE_RELPATH}`, clock)
  }

  /**
   * V1-M8 (v0.24): the ONE internal log-read — node-ports `readLines`
   * semantics (blank lines removed), enforced rather than assumed. Every
   * store-internal consumer and the verified view derive their line arrays
   * from here, so no face of the store can grow a private array convention.
   */
  private async logLines(): Promise<string[]> {
    return (await this.fs.readLines(this.logPath)).filter(line => line.trim().length > 0)
  }

  /**
   * Load the chain state from disk exactly once — the one full scan the first
   * mutation pays for. The same pass also re-indexes every existing evidence
   * address into the dedupe cache (so append idempotency survives restarts,
   * not just the process lifetime) and repairs a torn *tail* line if the
   * previous process died mid-`appendLine`.
   */
  private async ensureTail(): Promise<void> {
    if (this.tailReady) return
    let lines = await this.logLines()
    // A crash mid-`appendLine` leaves a torn final line: a valid prefix, no
    // closing brace, unparseable JSON. That is the physical signature of a
    // crash — an adversary rewrites *whole* lines — so the tail is rewritten
    // away (atomic replace) and the repair itself is recorded on the chain,
    // keeping every later line linked to the new tail. Damage anywhere but
    // the last line is NOT repaired: mid-log corruption may be tampering and
    // must keep failing audit.
    const torn = lines[lines.length - 1]
    let droppedChars: number | undefined
    if (torn !== undefined && torn.trim().length > 0 && !parsesAsJson(torn)) {
      droppedChars = torn.length
      lines = lines.slice(0, -1)
      await this.fs.writeFile(this.logPath, lines.length === 0 ? '' : `${lines.join('\n')}\n`)
    }
    let lastCheckpointIndex = -1
    let records = 0
    lines.forEach((line, index) => {
      const envelope = parseEnvelope(line)
      if (envelope === undefined) return
      if (envelope.kind === 'checkpoint') lastCheckpointIndex = index
      if (envelope.kind === 'evidence' || envelope.kind === 'marker') records += 1
      // Cross-process idempotency for free: the scan already touches every
      // evidence payload, so collecting its address costs nothing extra.
      // V1-L11 (v0.24): only SELF-ADDRESSING rows enter the dedupe cache —
      // an out-of-band twin row (same id, doctored payload, chained fine)
      // used to overwrite the honest entry by last-wins and could then
      // "dedupe" the honest re-append away. A row that cannot re-derive its
      // own id is never a cache answer for that id.
      if (envelope.kind === 'evidence') {
        const payload = envelope.payload as { evidenceId?: unknown }
        if (typeof payload?.evidenceId === 'string' && selfAddresses(payload as Evidence)) {
          this.cache.set(payload.evidenceId, payload as Evidence)
        }
      }
    })
    const last = lines[lines.length - 1]
    this.tail = last === undefined ? GENESIS_PREV : lineDigest(last)
    this.recordsSoFar = records
    this.sinceCheckpoint = lines
      .slice(lastCheckpointIndex + 1)
      .filter(line => {
        const envelope = parseEnvelope(line)
        return envelope?.kind === 'evidence' || envelope?.kind === 'marker'
      }).length
    this.tailReady = true
    if (droppedChars !== undefined) {
      // `markInternal`, not `mark`: ensureTail only runs inside the queue, and
      // re-entering it would self-deadlock. `tailReady` is already true, so
      // the marker chains straight from the repaired tail.
      await this.markInternal('log/recovered-partial-tail', { droppedChars })
    }
  }

  private async resolveSigner(): Promise<SignerPort | undefined> {
    return (await this.resolveSignerEx()).signer
  }

  /**
   * W1-M3 (v0.23): the adjudicated form of `resolveSigner`. A provider that
   * REJECTS is a transient signing-capability failure — the same social
   * reality as `sign()` throwing (M-33: an AV scan holding the key directory)
   * — and the checkpoint boundary must record it on the sigError channel
   * rather than writing a naked unsigned line that `unsignedCheckpoints`
   * charges forever (no keyId, hence no possible recovery witness: one
   * transient blip and the audit could never go green again, which is how
   * operators learn to ignore reds). Memoization semantics are M15's, bitten
   * open: only a SUCCESSFUL resolution is cached; a rejection or an empty
   * resolution is retried on the next boundary.
   */
  private async resolveSignerEx(): Promise<{ readonly signer?: SignerPort; readonly error?: string }> {
    if (this.trust.signer === undefined) return {}
    if (this.signerPromise === undefined) {
      const attempt = this.trust.signer().then(
        signer => {
          if (signer === undefined) this.signerPromise = undefined // no signer yet — ask again next time
          return signer
        },
        error => {
          this.signerPromise = undefined // transient failure — retry on the next checkpoint
          this.signerResolveError = errorMessage(error) // but THIS boundary must record it (W1-M3)
          return undefined
        },
      )
      this.signerPromise = attempt
    }
    const signer = await this.signerPromise
    if (signer !== undefined) return { signer }
    const error = this.signerResolveError
    this.signerResolveError = undefined
    return error === undefined ? {} : { error }
  }

  /**
   * Run `op` as the one and only log-mutating operation in flight. The queue
   * swallows the previous operation's rejection (it was already delivered to
   * its own caller) so one failed write cannot deadlock every later one;
   * `op`'s own outcome — result or rejection — reaches its caller untouched.
   */
  private enqueue<T>(op: () => Promise<T>): Promise<T> {
    const next = this.tailQueue.then(op)
    // The chain only tracks *completion*, never the outcome: a rejected op
    // must not poison the queue for the operations queued behind it.
    this.tailQueue = next.catch(() => undefined)
    return next
  }

  /**
   * Append one evidence record. Re-appending an existing address is a no-op —
   * in this process *and* across restarts: the first log scan re-indexes
   * every address already on disk, so replaying a log against a fresh store
   * instance cannot duplicate records.
   */
  append(evidence: Evidence): Promise<void> {
    // The dedupe check lives inside the queued section: two racing appends of
    // the same address must both see the cache update from whichever wins.
    return this.enqueue(() => this.appendInternal(evidence))
  }

  private async appendInternal(evidence: Evidence): Promise<void> {
    await this.ensureTail()
    // After ensureTail the cache covers both this process's earlier appends
    // and — via the initial log scan — every address already on disk, so the
    // no-op promise holds across restarts, not just within one process. (The
    // queued section still serialises two racing appends of the same address:
    // the loser re-runs this check after the winner's cache update.)
    if (this.cache.has(evidence.evidenceId)) return
    const envelope: LogEnvelope = {
      v: 2,
      kind: 'evidence',
      at: new Date(this.clock.now()).toISOString(),
      prev: this.tail,
      payload: evidence,
    }
    await this.writeEnvelope(envelope)
    this.cache.set(evidence.evidenceId, evidence)
    this.recordsSoFar += 1
    this.sinceCheckpoint += 1
    await this.maybeCheckpoint()
  }

  /** Append a free-form marker (session boundaries, decisions). */
  mark(label: string, data: Record<string, unknown> = {}): Promise<void> {
    return this.enqueue(() => this.markInternal(label, data))
  }

  private async markInternal(label: string, data: Record<string, unknown>): Promise<void> {
    await this.ensureTail()
    // W1-M6 (v0.23): `label` is store-owned, exactly like `headRef` below.
    // The old `{ label, ...data }` spread let any caller (or any future caller
    // that forwards user-shaped objects, the way `economics/quote` spreads a
    // quote) re-brand the line: `mark('session/start', { label: 'attest/human' })`
    // landed as an attest marker. The accidental defence — a re-branded
    // protected label lacked headRef and read back suspect — only held while
    // no caller ever spread, which is not a property of the API. The caller's
    // `label` key is dropped before the payload is built; honest callers never
    // sent one, so their bytes (label first, then data, then headRef) are
    // unchanged.
    const { label: _callerLabel, ...callerData } = data
    const envelope: LogEnvelope = {
      v: 2,
      kind: 'marker',
      at: new Date(this.clock.now()).toISOString(),
      prev: this.tail,
      // H-32/M-A1-5: protected markers carry the chain head the writer saw at
      // append time, written AFTER the caller data so no field can override
      // the witness; it equals the line's own `prev` for every honest write —
      // a marker replayed at, moved to, or injected at another position
      // contradicts it and reads back as suspect (see `_readMarkers`).
      payload: { label, ...callerData, ...(isProtectedMarkerLabel(label) ? { headRef: this.tail } : {}) },
    }
    await this.writeEnvelope(envelope)
    // X-H-08/U1-H1: remember the digest of every protected-marker line THIS
    // process wrote — the author set the pre-sign audit's unvouched-marker
    // rule (see `preSignAudit`) checks foreign lines against. Every protected
    // label's write flows through here, so the in-process honest path can
    // never refuse on its own markers.
    if (isProtectedMarkerLabel(label)) this.selfProtectedMarkers.add(this.tail)
    this.recordsSoFar += 1
    this.sinceCheckpoint += 1
    await this.maybeCheckpoint()
  }

  /**
   * Append a signed checkpoint and refresh the out-of-band anchor.
   *
   * A checkpoint commits to "the chain head, after N records". Without the
   * host's key the writer of the log cannot produce a new one, and without the
   * anchor the log cannot be quietly rewound past the last checkpoint.
   */
  checkpoint(): Promise<void> {
    return this.enqueue(() => this.checkpointInternal())
  }

  private async checkpointInternal(): Promise<void> {
    await this.ensureTail()
    const resolved = await this.resolveSignerEx()
    const signer = resolved.signer
    // H-27: never lend the host key to bytes that arrived behind the queue's
    // back. A signature is the one thing a rewriter cannot forge — and a
    // checkpoint signed over a rewritten chain would lift the out-of-band
    // anchor ONTO the forgery, after which the audit's rewind/mismatch
    // channels would be answering to the attack itself. The boundary signs
    // only after its own walk of the PHYSICAL log comes back clean and the
    // anchor still recognises the chain; otherwise the refusal itself goes
    // on the record (unsigned, banner-marked) and the anchor is not moved.
    if (signer !== undefined) {
      const problems = await this.preSignAudit(signer)
      if (problems !== undefined) {
        await this.recordRefusedCheckpoint(problems, signer)
        return
      }
    }
    const payload = {
      count: this.recordsSoFar,
      head: this.tail,
      workspaceKey: this.trust.workspaceKey ?? null,
      at: new Date(this.clock.now()).toISOString(),
    }
    let sig: string | undefined
    let keyId: string | undefined
    let sigError: string | undefined
    if (signer !== undefined) {
      try {
        sig = await signer.sign(checkpointSignedData(payload))
        keyId = signer.keyId
      } catch (error) {
        // Loud degradation: an unsigned checkpoint that should have been
        // signed is recorded as such and fails audit while a signer is
        // active. M-33: the keyId rides along even without a signature — the
        // audit uses it to demand a later verified signature of the same key
        // (the recovery witness) before excusing the line as an honest
        // transient failure rather than a stripped signature.
        sigError = errorMessage(error)
        keyId = signer.keyId
      }
    } else if (resolved.error !== undefined) {
      // W1-M3 (v0.23): the provider itself failed transiently — the same
      // loud-degradation channel as a failing `sign()` above, instead of a
      // naked unsigned line `unsignedCheckpoints` could never pardon (no
      // keyId means no possible recovery witness; one blip red the audit
      // forever). No keyId is stamped because a provider that never resolved
      // never named one — the boundary documents the failure, and the next
      // boundary (M15 retry semantics) signs again.
      sigError = resolved.error
    }
    const envelope: LogEnvelope = {
      v: 2,
      kind: 'checkpoint',
      at: payload.at,
      prev: this.tail,
      payload,
      ...(sig !== undefined ? { sig, keyId } : sigError !== undefined ? { sigError, keyId } : {}),
    }
    await this.writeEnvelope(envelope)
    this.sinceCheckpoint = 0
    if (signer !== undefined && sig !== undefined && this.trust.anchorPath !== undefined) {
      // `workspaceKey` rides along so a later audit can re-derive the exact
      // signed bytes from the anchor alone (see `audit`). Older anchors that
      // predate the field simply skip signature verification instead of
      // failing it.
      const anchor = {
        v: 1 as const,
        keyId: signer.keyId,
        count: payload.count,
        head: payload.head,
        sig,
        at: payload.at,
        ...(typeof payload.workspaceKey === 'string' ? { workspaceKey: payload.workspaceKey } : {}),
      }
      await this.fs.writeFile(this.trust.anchorPath, JSON.stringify(anchor, null, 2))
    }
  }

  /**
   * H-27: the pre-sign audit — walk the physical bytes and refuse to sign if
   * anything about them is not what this store wrote. Returns the joined
   * problems (the refusal reason), or `undefined` when the chain is fit to
   * sign. Deliberately narrow: only *tamper-shape* signals refuse. A past
   * unsigned checkpoint (transient signing failure) or an unverifiable
   * foreign one is NOT a reason to refuse — those have their own channels,
   * and refusing on them would make recovery from an honest blip impossible.
   *
   * X-H-08 (v0.23) adds the one *authorship* signal: a PROTECTED-marker line
   * sitting on the checkpoint-uncovered tail that THIS process never wrote
   * (see `selfProtectedMarkers`; v0.25 widened the roster from the baseline
   * family to every label trust decisions read). See the rule's full comment
   * inline below.
   */
  private async preSignAudit(signer: SignerPort): Promise<string | undefined> {
    const lines = await this.logLines()
    const walk = walkChain(lines)
    const problems: string[] = []
    if (walk.chainBreaks.length > 0) problems.push(`chain-breaks@${walk.chainBreaks.join(',')}`)
    if (walk.corruptLines.length > 0) problems.push(`corrupt-lines@${walk.corruptLines.join(',')}`)
    if (walk.malformedCheckpoints.length > 0) problems.push(`malformed@${walk.malformedCheckpoints.join(',')}`)
    const headLiars = walk.checkpoints.filter(cp => cp.headLiared)
    if (headLiars.length > 0) problems.push(`head-liars@${headLiars.map(cp => cp.index).join(',')}`)
    const physicalTail = lines.length === 0 ? GENESIS_PREV : lineDigest(lines[lines.length - 1] as string)
    if (physicalTail !== this.tail) problems.push('physical-tail-moved-behind-the-queue')
    // Our own key must not already be vouching for a lie on this chain: a
    // checkpoint that names this signer but fails its signature is a forged
    // use of the host identity, and signing on top of it would bury it.
    // The same pass derives the vouching boundary the X-H-08 rule below
    // measures the tail against: the LAST checkpoint of THIS key whose
    // signature this host actually verified. Only a verified signature of
    // the host key vouches — a bare checkpoint line, or one under a foreign
    // keyId, is appendable by anyone and must not launder what trails it.
    let vouchedIndex = -1
    for (const cp of walk.checkpoints) {
      if (cp.sig === null || cp.keyId !== signer.keyId) continue
      let honest: boolean
      try {
        honest = await signer.verify(checkpointSignedData(cp.payload), cp.sig)
      } catch {
        honest = false
      }
      if (honest) vouchedIndex = cp.index
      else { problems.push(`refuted-signature@${cp.index}`); break }
    }
    // X-H-08 (v0.23), widened v0.25 (U1-H1): cross-session tail absorption.
    // Between sessions (no store process alive — CLI invocations, MCP server
    // restarts) an append of well-formed, correctly-chained, headRef-correct
    // lines is invisible to every shape check above: nothing breaks, nothing
    // lies structurally, and the next process's ensureTail absorbs the bytes
    // as honest history. v0.23 refused to notarise exactly one append — a
    // foreign `baseline/saved`/`baseline/established` marker — leaving the
    // identical laundering open under every OTHER protected label: a forged
    // `attest/jury {verdict:'uphold', probability:0.999}`, a planted
    // `delegation/created`, a never-executed `synthetic/run` (all with the
    // headRef anyone who reads the log can compute) rode into the vouched
    // prefix under the host's own next checkpoint, because the floor launders
    // whatever sits BELOW it the moment it is minted. The roster is now the
    // full `isProtectedMarkerLabel` list — the labels trust decisions read.
    //
    // The rule: per protected label, the NEWEST marker line physically after
    // the last host-verified checkpoint (the signed tail — the only prefix
    // the key already vouches for) must be one THIS process wrote (see
    // `selfProtectedMarkers`). Newest-per-label, because marker reads are
    // last-wins: an older foreign line sitting beneath a newer self-written
    // one is a dead letter — it no longer answers anything — while a foreign
    // line that IS the newest of its label is a live claim nobody authored,
    // and the store refuses to lend it the key.
    //
    // Boundary notes, deliberately conservative and testable:
    // - Both attack windows are covered by position alone: appended while a
    //   process is alive (after the last verified checkpoint, before this
    //   one) AND appended between sessions. The alternative sketched in the
    //   survey — keying on the baseline file's mtime being later than engine
    //   start — covers only part of the second window, needs cross-clock
    //   comparability a shared or copied workspace cannot promise, and is
    //   untestable against an in-memory clock; authorship-plus-position
    //   catches strictly more of the marker channel, so mtime is not
    //   consulted.
    // - Honest restarts do not refuse: every boundary verb checkpoints over
    //   its own protected markers before the next read runs, so a previous
    //   session's markers always sit at-or-below a verified checkpoint, and
    //   THIS process's own newest markers are in the author set by
    //   construction (every write goes through `markInternal`).
    // - The narrow honest casualty — a session dying between a protected
    //   `mark(...)` and the checkpoint that was to cover it (conjure's two
    //   halves, an un-checkpointed quote), or one whose checkpoint landed
    //   only as a sigError line (which vouches nothing) — leaves a
    //   foreign-newest marker behind; the next session refuses ONCE and the
    //   documented recovery is superseding: write a newer SELF-authored
    //   marker of the same label (re-run the conjured check, quote again,
    //   `saveBaseline`/establish for the baseline family), and signing
    //   resumes. (A deployment that adds a signer to a previously unsigned
    //   workspace takes exactly one such refusal, on the first boundary,
    //   before re-anchoring — by design.)
    // - There is no automatic pardon beyond superseding, on purpose: any
    //   pardon the store itself grants for an un-authored newest claim is a
    //   pardon an attacker can forge the shape of. The refusal line stays on
    //   the record (audit red via refusedToSign) even after recovery — the
    //   store accused its log once, and the accusation is history.
    const lastOfLabel = new Map<string, { index: number; self: boolean }>()
    lines.forEach((line, index) => {
      if (index <= vouchedIndex) return
      const envelope = parseEnvelope(line)
      if (envelope?.kind !== 'marker') return
      const markerPayload = envelope.payload as { label?: unknown }
      if (typeof markerPayload?.label !== 'string' || !isProtectedMarkerLabel(markerPayload.label)) return
      lastOfLabel.set(markerPayload.label, { index, self: this.selfProtectedMarkers.has(lineDigest(line)) })
    })
    const unvouched = [...lastOfLabel.values()].filter(last => !last.self).map(last => last.index).sort((a, b) => a - b)
    if (unvouched.length > 0) problems.push(`unvouched-protected-marker@${unvouched.join(',')}`)
    // The anchor is the out-of-band high-water mark this checkpoint is about
    // to move. A disarmed anchor file (H-09) must not be quietly overwritten
    // by a fresh one — the tampering stays visible until a human looks. And
    // an anchor the physical chain can no longer answer exactly (H-08) means
    // the anchored prefix is gone: signing here would launder the rewrite.
    const anchorOutcome = this.trust.anchorPath === undefined ? undefined : parseAnchorEx(await this.fs.readFile(this.trust.anchorPath))
    if (anchorOutcome?.problem === 'invalid') {
      problems.push('anchor-file-invalid')
    } else if (anchorOutcome?.anchor !== undefined) {
      const answer = answerAnchor(walk.checkpoints, walk.malformedCheckpoints, anchorOutcome.anchor)
      if (answer.rewind) problems.push('anchor-rewind')
      else if (answer.mismatch) problems.push('anchor-mismatch')
    }
    return problems.length === 0 ? undefined : problems.join('; ')
  }

  /**
   * H-27: record a refused boundary — the checkpoint lands unsigned with the
   * `SIG_REFUSED_PREFIX` banner (the store accusing its own log), plus a
   * marker naming the reasons, so both the audit and marker readers can see
   * WHY nothing was signed. The store's tail/counter state re-syncs to the
   * physical bytes (they moved behind the queue's back; pretending otherwise
   * would just chain the next honest append onto a lie).
   */
  private async recordRefusedCheckpoint(problems: string, signer: SignerPort): Promise<void> {
    const lines = await this.logLines()
    const walk = walkChain(lines)
    this.tail = lines.length === 0 ? GENESIS_PREV : lineDigest(lines[lines.length - 1] as string)
    this.recordsSoFar = walk.records
    const at = new Date(this.clock.now()).toISOString()
    const payload = {
      count: this.recordsSoFar,
      head: this.tail,
      workspaceKey: this.trust.workspaceKey ?? null,
      at,
    }
    await this.writeEnvelope({
      v: 2,
      kind: 'checkpoint',
      at,
      prev: this.tail,
      payload,
      sigError: `${SIG_REFUSED_PREFIX}: ${problems}`,
      keyId: signer.keyId,
    })
    // Written directly (not via `markInternal`): the cadence hook must not
    // re-enter the checkpoint path this refusal came from, and the refusal
    // is already its own record — no need to double-count it as pending.
    await this.writeEnvelope({
      v: 2,
      kind: 'marker',
      at,
      prev: this.tail,
      payload: { label: 'trust/checkpoint-refused', reason: problems },
    })
    this.recordsSoFar += 1
    this.sinceCheckpoint = 0
  }

  /** Must only be called from inside a queued operation (would self-deadlock). */
  private async maybeCheckpoint(): Promise<void> {
    const every = this.trust.checkpointEvery
    if (every !== undefined && every > 0 && this.sinceCheckpoint >= every) {
      await this.checkpointInternal()
    }
  }

  private async writeEnvelope(envelope: LogEnvelope): Promise<void> {
    const line = JSON.stringify(envelope)
    await this.fs.appendLine(this.logPath, line)
    this.tail = lineDigest(line)
  }

  /**
   * Every evidence record ever appended, in log order.
   *
   * V1-L11 (v0.24): a row is admitted only when it still addresses itself
   * (`addressOf(payload minus id) === id`). Evidence rows have no suspect
   * regime of their own (the marker/twin asymmetry the survey named), so an
   * out-of-band twin — same id, doctored payload, chained correctly — used
   * to win `latest()` last-wins and poison priors/exports until some later
   * audit ran. The read-time check makes the honest row the only answer for
   * its id on every face. `audit()` still collects unaddressing rows into
   * its `corrupt` channel (the charge needs to SEE the bad row); this is the
   * read-trust half of the pair.
   */
  async all(): Promise<Evidence[]> {
    const lines = await this.logLines()
    const out: Evidence[] = []
    for (const line of lines) {
      const parsed = parseEnvelope(line)
      if (parsed?.kind !== 'evidence') continue
      const ev = parsed.payload as Evidence
      if (typeof ev?.evidenceId !== 'string' || !selfAddresses(ev)) continue
      this.cache.set(ev.evidenceId, ev)
      out.push(ev)
    }
    return out
  }

  /** Latest evidence for each check, in first-seen check order. */
  async latest(): Promise<Map<string, Evidence>> {
    const all = await this.all()
    const map = new Map<string, Evidence>()
    for (const ev of all) map.set(ev.checkId, ev) // later entries win
    return map
  }

  /**
   * Verify the log's integrity end to end: per-record self-addressing, hash
   * chain linkage, checkpoint signatures, anchor monotonicity, and the
   * baseline file digest recorded at save time.
   */
  async audit(): Promise<AuditReport> {
    // M-32 (TOCTOU): ONE physical snapshot of the log, every judgement
    // derived from those same bytes. The old shape walked one read and then
    // re-read the file for `all()`, so a concurrent writer could hand each
    // consumer a different log — each snapshot internally consistent, the
    // combination wrong. The anchor and baseline files are likewise each
    // read once and pinned for the whole audit.
    const lines = await this.logLines()
    const walk = walkChain(lines)
    // Y-H-03 (v0.24): the marker derivations below (suspect channel AND the
    // baseline/saved binding) come from the SAME single pass the store's
    // public marker reads and the verified view use — one rule, one parse,
    // no face can fork it.
    const markers = _readMarkers(lines)
    const all: Evidence[] = []
    for (const line of lines) {
      const parsed = parseEnvelope(line)
      if (parsed?.kind !== 'evidence') continue
      const ev = parsed.payload as Evidence
      if (typeof ev?.evidenceId === 'string') {
        all.push(ev)
      }
    }

    const corrupt: string[] = []
    for (const ev of all) {
      const { evidenceId, ...rest } = ev
      // The audit answers hostile bytes with a report, never a throw: a
      // payload carrying values the canonical form refuses (a `1e999`
      // duration, say) cannot have its address recomputed at all, which is
      // the strongest possible form of "does not address itself".
      let addressed: string
      try {
        addressed = addressOf(rest)
      } catch {
        addressed = '<uncanonicalisable payload>'
      }
      if (addressed !== evidenceId) corrupt.push(ev.checkId)
    }

    const signer = await this.resolveSigner()
    const badCheckpoints: number[] = []
    const unverifiableCheckpoints: number[] = []
    const unsignedCheckpoints: number[] = []
    const sigErrorCheckpoints: number[] = []
    const refusedToSign: number[] = []
    const refusedToSignPardoned: number[] = []
    const unsignedEraCheckpoints: number[] = []
    const headMismatches: number[] = []
    // Signatures of the key this host actually holds, verified once: they
    // feed the forgery charge below, the recovery witnesses that separate an
    // honest transient failure / refused generation from a live one, and the
    // adoption boundary below.
    const verifiedOwn = new Set<number>()
    if (signer !== undefined) {
      for (const cp of walk.checkpoints) {
        if (cp.sig === null || cp.keyId !== signer.keyId) continue
        let honest: boolean
        try {
          honest = await signer.verify(checkpointSignedData(cp.payload), cp.sig)
        } catch {
          honest = false
        }
        if (honest) verifiedOwn.add(cp.index)
      }
    }
    let lastVerifiedOwn = -1
    for (const index of verifiedOwn) if (index > lastVerifiedOwn) lastVerifiedOwn = index
    const firstVerifiedOwn = verifiedOwn.size > 0 ? Math.min(...verifiedOwn) : Number.POSITIVE_INFINITY
    // Y-H-02 (v0.24): the re-anchor witness for the refusal slicing below —
    // line indexes of baseline-family marker rows THIS process wrote (the
    // digest set `markInternal` collects, U1-H1-widened; the label filter
    // keeps the witness baseline-specific — the documented recovery for the
    // baseline family). Computed lazily: only a log that actually refused
    // needs it.
    const selfBaselineMarkerLines = new Set<number>()
    if (refusedPendingProbe(walk)) {
      lines.forEach((line, index) => {
        if (!this.selfProtectedMarkers.has(lineDigest(line))) return
        const envelope = parseEnvelope(line)
        const payload = envelope?.payload as { label?: unknown } | undefined
        if (envelope?.kind === 'marker' && isBaselineMarkerLabel(payload?.label)) selfBaselineMarkerLines.add(index)
      })
    }
    for (const cp of walk.checkpoints) {
      if (cp.headLiared) headMismatches.push(cp.index)
      if (cp.sig === null) {
        // H-27/H-32: a signature-less line is three different facts, and the
        // writer's own on-chain sigError note is what tells them apart.
        if (cp.sigError !== null && cp.sigError.startsWith(SIG_REFUSED_PREFIX)) {
          // The store itself refused to sign — its own audit found the chain
          // tampered. The store accusing its own log stays the loudest
          // signal the audit has, and the refusal line itself is always
          // visible. Y-H-02 (v0.24) adds the GENERATIONAL SLICE to the
          // charge: a refusal is a charge against its GENERATION — the span
          // until the chain is re-anchored — not against the deployment for
          // ever. The line stops failing `ok` exactly when a recovery the
          // store can actually see has happened: a LATER checkpoint of this
          // key whose signature this host verified (signing resumed over a
          // chain the pre-sign audit accepted), or a `baseline/saved` /
          // `baseline/established` marker THIS process wrote after the
          // refusal (the documented re-anchor: saveBaseline supersedes the
          // un-authored claim the refusal named). Without either witness the
          // refusal is live and `ok` fails — an un-recovered accusation is
          // still an accusation. This is the same recovery-witness social
          // contract sigErrorCheckpoints already honour (M-33): an honest
          // blip must be recoverable, or operators learn to ignore reds —
          // v0.23 made one honest race or one attacker line red the
          // deployment FOREVER while the X-H-09 consumers capped every
          // future grade at stale, which is its own vulnerability.
          refusedToSign.push(cp.index)
          const witnessed = [...verifiedOwn].some(i => i > cp.index)
            || [...selfBaselineMarkerLines].some(i => i > cp.index)
          if (witnessed) refusedToSignPardoned.push(cp.index)
          continue
        }
        if (cp.sigError !== null) {
          // A writer-attested transient failure ("key directory locked by a
          // scanner"). Excused into the visible, non-failing channel ONLY
          // with a recovery witness: a LATER checkpoint of the same key
          // whose signature this host verified — the honest blip is always
          // followed by a healed boundary. Without the witness, "transient
          // failure" is exactly the cover story an attacker who stripped a
          // signature would plant, so the line stays charged as unsigned.
          // Hosts that cannot adjudicate the key at all (keyless, foreign)
          // cannot demand the witness either — visible, not an accusation.
          const own = signer !== undefined && cp.keyId === signer.keyId
          const witness = !own || [...verifiedOwn].some(i => i > cp.index)
          ;(witness ? sigErrorCheckpoints : unsignedCheckpoints).push(cp.index)
          continue
        }
        if (signer !== undefined) {
          // Y-H-02 (v0.24): the ADOPTION boundary. A completely naked line
          // (no sig, no sigError, no keyId) is one this store's writer can
          // only produce while NO signer is configured — the keyless era of
          // a deployment that later adds a trust directory. Charging those
          // lines forever made signer adoption a one-way door to a permanent
          // red (every keyless-era boundary failed `ok` on every later
          // audit, so the documented "adopt a key and re-anchor" recovery
          // never recovered). The slice: naked lines BELOW the first
          // verified checkpoint of the now-held key belong to the keyless
          // generation — visible on their own channel, deliberately not a
          // charge (the re-anchored prefix is exactly what the new key
          // vouches for). A naked line a signer-era store could not have
          // written ABOVE that boundary (an attacker's appended fake
          // checkpoint, or a stripped honest one — stripping `sig` leaves
          // `keyId` behind, so a fully-naked line above the boundary is not
          // a stripped honest shape) stays charged.
          if (cp.keyId === null && cp.index < firstVerifiedOwn) unsignedEraCheckpoints.push(cp.index)
          else unsignedCheckpoints.push(cp.index)
        }
        continue
      }
      // Three-state adjudication: only a key we actually hold, facing a
      // checkpoint that names that very key, gets to *refute* a signature.
      // No signer at all (key lost, different machine) or a foreign keyId is
      // a missing capability — recorded as unverifiable, never as forgery:
      // charging the log with tampering because *we* cannot check it would
      // invert the burden of proof. Rewind cover does not need the key: the
      // anchor's exact-pair comparison below still bounds the log (H-08) —
      // an unverifiable checkpoint can no more answer the anchor positively
      // than a refuted one could.
      if (signer === undefined || cp.keyId !== signer.keyId) {
        unverifiableCheckpoints.push(cp.index)
        continue
      }
      // A payload the canonical form refuses to serialise (the `1e999`
      // count-laundering trick) cannot be the bytes ANY honest signature
      // covers — signatures are made over canonical bytes, and these bytes
      // have none. Refuted; and the audit keeps reporting instead of
      // throwing, because a hostile log must never be able to crash its
      // auditor — that would be a denial-of-service bypass of the whole
      // verdict.
      if (!verifiedOwn.has(cp.index)) badCheckpoints.push(cp.index)
    }

    let rewind = false
    let anchorMismatch = false
    let anchorForged = false
    let anchorUnreadable = false
    let anchorInvalid = false
    const anchorRaw = this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath)
    const anchorOutcome = parseAnchorEx(anchorRaw)
    // M15/H-09: a file that exists but cannot be consulted splits in two. A
    // document that is not an anchor shape at all (garbage JSON, wrong
    // version) is an auditor-side capability gap — visible as
    // `anchorUnreadable`, deliberately NOT an `ok` failure. A document that
    // IS anchor-shaped but in a state no honest writer produces (empty
    // keyId, count outside the safe non-negative integers, empty/absent sig
    // — the four-line disarm family) is tampering until proven otherwise:
    // `anchorInvalid`, and the audit fails. Silently tolerating it is how a
    // 4-line edit switched the whole out-of-band defence line off.
    if (anchorRaw !== undefined) {
      if (anchorOutcome === undefined || anchorOutcome.problem === 'unparseable') anchorUnreadable = true
      else if (anchorOutcome.problem === 'invalid') anchorInvalid = true
    }
    const anchor = anchorOutcome?.anchor
    if (anchor !== undefined) {
      // H-08: the anchor is answered ONLY by the exact pair it remembers — a
      // well-formed checkpoint of its own key at (anchor.count, anchor.head).
      // Honest stores write that pair to the chain and the anchor file in
      // the same breath, so an honest log always answers, key or no key.
      // Under the exact-pair rule, "answering" means reproducing the
      // anchored prefix byte-for-byte (the head is a chain hash over
      // everything before it) — a rewritten log with an impersonated
      // anchor-key checkpoint and an inflated count no longer gets to skip
      // the comparison, which is what the old size-based rule allowed on
      // keyless audit hosts. Unanswered, the direction tells the story:
      // below (or nothing) is a rewind suspicion; at-or-above-but-different
      // is a mismatch.
      const answer = answerAnchor(walk.checkpoints, walk.malformedCheckpoints, anchor)
      rewind = answer.rewind
      anchorMismatch = answer.mismatch
      // The anchor is signed data too, and it is the one artifact the agent
      // cannot recompute — tampering with its fields while keeping the sig is
      // exactly the attack the signature exists for. Adjudicated when this
      // host holds the writing key; an anchor missing `workspaceKey` is
      // verified against the only honest pre-field form (workspaceKey: null
      // — the bytes the old writer actually signed), so honest old anchors
      // still verify while a STRIPPED modern one cannot (H-09).
      if (anchor.sig !== '' && signer !== undefined && anchor.keyId === signer.keyId) {
        // Same refusal discipline as the checkpoint loop above: anchor fields
        // the canonical form will not serialise cannot be the bytes the
        // honest writer signed over, and the audit reports rather than
        // throwing on hostile input.
        let forged: boolean
        try {
          const signed = checkpointSignedData({
            count: anchor.count,
            head: anchor.head,
            workspaceKey: anchor.workspaceKey ?? null,
            at: anchor.at,
          })
          forged = !(await signer.verify(signed, anchor.sig))
        } catch {
          forged = true
        }
        if (forged) anchorForged = true
      }
    }

    let baselineTampered = false
    const baselineRaw = await this.fs.readFile(this.baselinePath)
    if (baselineRaw !== undefined) {
      // H-23: two independent integrity checks on the baseline file.
      //
      // (0) Y-H-09 (v0.24): AUTHORSHIP, at read time. The marker about to
      // answer for the chain must be one this process wrote OR one sitting
      // at-or-below a checkpoint of this host's key whose signature this
      // host verified — the prefix the key already vouched for. v0.23
      // detected an out-of-band `baseline/saved` absorption only at the NEXT
      // signing boundary (preSignAudit), so a keyless deployment never
      // detected it at all and a keyed one minted verdicts against the
      // poisoned baseline before the refusal landed. The absorption is now
      // `baselineTampered` the moment any reader looks: verdict paths cap,
      // `loadBaseline` refuses, no notarisation required. Keyless audit
      // hosts cannot run the check (no key to vouch with — a capability
      // gap, not an accusation) and keep the v0.23 shape-plus-digest rule.
      //
      // (1) Chain binding — the file bytes must still be the bytes the last
      // HONEST `baseline/saved` marker remembers (H-32: appended twin markers
      // are suspect and do not get to answer for the chain; when every marker
      // is suspect — a log written before the headRef witness existed — the
      // last one still speaks, so upgraded deployments are never worse than
      // before). This is the half that catches a REBUILT-consistent forgery
      // (the attacker re-runs the package's own address/merkle functions)
      // and the stripped non-addressing field (`scriptDigests`, `apiSurface`)
      // that no canonical check can see.
      // (2) Canonical self-consistency — a document that claims to be a
      // baseline must be able to re-derive its own id (every record still
      // addresses itself, root and baselineId still agree). This is the
      // half that catches the lazy edit (payload doctored, ids kept) when no
      // marker can be consulted at all.
      const answering = lastBaselineMarker(markers.filter(m => m.label === 'baseline/saved'))
      // Y-H-09 scope: the authorship demand speaks for THIS host's key. A
      // host holding a DIFFERENT key than every signed checkpoint on the
      // chain is a borrowed pair of eyes (a capability gap, not an
      // accusation — the three-state rule the anchor channels follow); the
      // digest and canonical rules below still apply to it, the vouch
      // demand does not.
      const signedCps = walk.checkpoints.filter(cp => cp.sig !== null)
      const allSignedForeign = signer !== undefined && signedCps.length > 0
        && signedCps.every(cp => cp.keyId !== signer.keyId)
      const authorised = signer !== undefined && !allSignedForeign
        ? baselineMarkerAuthorised(answering, lines, this.selfProtectedMarkers, lastVerifiedOwn)
        : true
      if (!authorised) {
        baselineTampered = true
      } else {
        const saved = baselineDigestOf(answering)
        if (saved !== undefined && sha256(baselineRaw) !== saved) baselineTampered = true
        else {
          const verified = verifyBaselineDocument(baselineRaw)
          if (verified.claimed && verified.baseline === undefined) baselineTampered = true
        }
      }
    }

    const refusalCharged = refusedToSign.filter(i => !refusedToSignPardoned.includes(i))
    const chain = {
      mode: walk.mode,
      breaks: walk.chainBreaks,
      checkpoints: walk.checkpoints.length,
      badCheckpoints,
      unverifiableCheckpoints,
      unsignedCheckpoints,
      headMismatches,
      sigErrorCheckpoints,
      refusedToSign,
      refusedToSignPardoned,
      unsignedEraCheckpoints,
      malformedCheckpoints: walk.malformedCheckpoints,
      corruptLines: walk.corruptLines,
      tailRecords: walk.tailRecords,
      rewind,
      anchorMismatch,
      anchorForged,
      anchorInvalid,
      baselineTampered,
      suspectMarkers: suspectIndexesOf(markers),
    }
    // `unverifiableCheckpoints` deliberately does NOT fail the audit: a key we
    // no longer hold must not turn into a forgery verdict against the log.
    // Every *refutable* claim — corruption, breaks, forged signatures, head
    // mismatches, malformed counts, unsigned-while-signed, a signing refusal,
    // rewind, anchor mismatch/forgery/invalid, baseline substitution — does.
    // `sigErrorCheckpoints` (honest transient failures with a recovery
    // witness) and `suspectMarkers` (cannot-vouch lines) are visible without
    // failing `ok`: the first is a recovered blip, the second an unproven
    // suspicion whose trust-side exclusion happens at the consumers. Y-H-02
    // (v0.24): `refusedToSign` rows are likewise visible without failing `ok`
    // once their generation recovered (see `refusedToSignPardoned`); the
    // keyless-era adoption slice of `unsignedCheckpoints` (naked lines below
    // the first verified checkpoint of the held key) is the same
    // visible-not-failing shape.
    const ok = corrupt.length === 0
      && walk.corruptLines.length === 0
      && walk.chainBreaks.length === 0
      && badCheckpoints.length === 0
      && headMismatches.length === 0
      && walk.malformedCheckpoints.length === 0
      && unsignedCheckpoints.length === 0
      && refusalCharged.length === 0
      && !rewind
      && !anchorMismatch
      && !anchorForged
      && !anchorInvalid
      && !baselineTampered
      // L-A1-11: a v1-only chain carries no prev linkage at all — an
      // anchorless audit of one has nothing integrity-shaped it could honestly
      // pass. It stays fully READABLE (`all`/`total`); `ok` simply no longer
      // vouches for bytes the chain never linked.
      && walk.mode !== 'legacy'
    // `anchorUnreadable` deliberately does NOT enter the `ok` formula (see
    // the field): an anchor this host cannot parse is not evidence of
    // tampering in the log, and failing `ok` on it would conflate "cannot
    // check" with "checked and refuted". Readers consult the flag itself.
    return { ok, total: all.length, corrupt, anchorUnreadable, chain }
  }

  /**
   * The last *signature-bearing* checkpoint on the chain, selected with the
   * audit's own "best" semantics — the checkpoint a transparency-log publish
   * (v0.18) mirrors into a public, independently verifiable artifact.
   *
   * Selection, mirroring `audit`'s anchor answering rule exactly:
   *
   * - Candidates are well-formed checkpoints (a count the walk itself refutes
   *   is excluded — publishing a lying self-report is not "latest", it is
   *   laundering) that carry a non-empty `sig` AND a non-null `keyId` AND —
   *   Y-H-01 (v0.24) — do not lie about their position (`headLiared`). A
   *   legitimately-signed checkpoint transplanted or replayed at another
   *   position swears a head the walk does not corroborate; v0.23 selected
   *   it (the signature is honest over a payload lying about WHERE) and the
   *   engine/CLI publish paths notarised the transplant into the transparency
   *   log. The publish predicate `signature === 'verified' && !headLiared`
   *   is now enforced where the candidate is chosen.
   * - When the out-of-band anchor exists and names a key, the LAST checkpoint
   *   by that very key wins — never a positionally-later checkpoint under some
   *   foreign keyId an attacker appended. No checkpoint of the anchored key at
   *   all means `undefined`: the anchor is the out-of-band high-water mark of
   *   OUR key, and nothing on this chain is entitled to stand in for it.
   *   v0.22 (H-09): an anchor file that exists but is unparseable OR in the
   *   domain-invalid disarm state also means `undefined` — a store whose
   *   out-of-band mark cannot be consulted has nothing publishable, and the
   *   publish path must fail loudly rather than silently fall back to
   *   any-key selection on exactly the hosts an attacker has been at.
   * - Without an anchor (never anchored / audited anchor-less), the last
   *   signed well-formed non-liar checkpoint of any key is the honest answer.
   * - No signed checkpoint at all → `undefined` (an unsigned chain has nothing
   *   publishable; the caller reports that as a precondition, not a crash).
   *
   * Y-H-03/V1-L10 (v0.24): the selection is the shared single-pass core —
   * ONE physical read feeds the walk, the anchor adjudication and the
   * choice; `createVerifiedView().bestCheckpoint` and
   * `lastWellFormedCheckpoint` derive from the same function, so no face can
   * select by a different rule (or re-read the log between selection and
   * walk, the v0.23 double-snapshot that could silently default
   * `headLiared` to false).
   */
  async latestSignedCheckpoint(): Promise<SignedCheckpointView | undefined> {
    const { best } = await this.selectFromWalk(true)
    return best === undefined ? undefined : signedCheckpointViewOf(best)
  }

  /**
   * v0.22 (H-32/M-A1-5): every marker under one label, in log order, with
   * tamper-evidence metadata — the RAW read (suspect lines included, flagged;
   * `excludeSuspect: true` drops them). This is the marker read-back the
   * store owns; the POOLING decision (trusted vs the generational fallback)
   * belongs to {@link createVerifiedView}.markers, which derives from the
   * same single-pass core (Y-H-03, v0.24) — suspect adjudication cannot fork
   * between the two faces.
   */
  async markersWith(label: string, options: { readonly excludeSuspect?: boolean } = {}): Promise<MarkerRecord[]> {
    return _readMarkers(await this.logLines(), { label, excludeSuspect: options.excludeSuspect })
  }

  /**
   * @internal One physical snapshot of the log lines, normalised to the
   * readLines array contract (blank lines removed — V1-M8), for the verified
   * read layer ({@link createVerifiedView}) — so its `markers`/
   * `bestCheckpoint` judgements derive from bytes the store itself read, not
   * a second fs path the caller wires up. Not a general API: readers that
   * need raw lines should say what they trust via the view.
   */
  async rawLines(): Promise<readonly string[]> {
    return this.logLines()
  }

  /**
   * @internal The store's own signer provider (trust wiring), so
   * {@link createVerifiedView} can adjudicate signatures by default when the
   * caller does not inject one. `undefined` when the store was built without
   * signing configured — the view then reports `unverifiable`, never guesses.
   */
  hostSigner(): (() => Promise<SignerPort | undefined>) | undefined {
    return this.trust.signer
  }

  /**
   * @internal Y-H-03/V1-L10 (v0.24): the ONE checkpoint-selection core every
   * "best checkpoint" consumer derives from — ONE normalised physical read
   * feeds the walk, the anchor adjudication AND the selection, so the store's
   * public reads and {@link createVerifiedView}.bestCheckpoint cannot select
   * by different rules or against different bytes. `requireSigned` picks the
   * publish-shaped pool (sig + keyId, `latestSignedCheckpoint` /
   * `bestCheckpointCore`) or the training-anchor pool (any well-formed
   * checkpoint, `lastWellFormedCheckpoint`); both pools exclude malformed
   * counts and — Y-H-01 — head liars.
   *
   * P5: the read/walk/anchor trinity is shared verbatim with
   * {@link publishableCandidatesCore} (see `selectionSnapshot`) — the single
   * answer and the candidate sequence draw from one snapshot per call, so
   * the two faces cannot disagree about the bytes or the anchor state.
   */
  private async selectFromWalk(requireSigned: boolean): Promise<{ readonly best?: WalkedCheckpoint; readonly anchorUnusable: boolean }> {
    const { walk, anchor, anchorUnusable } = await this.selectionSnapshot()
    if (anchorUnusable) return { anchorUnusable: true }
    return { best: selectBestCheckpoint(walk, anchor, requireSigned), anchorUnusable: false }
  }

  /**
   * @internal The shared one-read selection snapshot: physical lines (the
   * readLines convention), the chain walk, and the adjudicated anchor — or
   * the loud `anchorUnusable` state (unparseable OR domain-invalid, the
   * H-09/W1-M7 shapes) under which nothing is publishable.
   */
  private async selectionSnapshot(): Promise<{ readonly walk: ChainWalk; readonly anchor?: AnchorFile; readonly anchorUnusable: boolean }> {
    const walk = walkChain(await this.logLines())
    const anchorRaw = this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath)
    const anchorOutcome = parseAnchorEx(anchorRaw)
    if (anchorRaw !== undefined && anchorOutcome?.anchor === undefined) {
      // The loud-undefined anchor states (H-09/W1-M7): unparseable OR
      // domain-invalid. Nothing is publishable; never a silent any-key
      // fallback on exactly the hosts an attacker has been at.
      return { walk, anchorUnusable: true }
    }
    return { walk, anchor: anchorOutcome?.anchor, anchorUnusable: false }
  }

  /**
   * @internal The view-facing form of the selection core: one read, the
   * selected publish candidate, and the conservative head-liar verdict. The
   * verdict comes from the SAME walk that produced the selection (V1-L10:
   * v0.23's second read could misalign against a concurrent truncation and
   * silently default `headLiared` to false — the wrong direction); when the
   * walk cannot corroborate a selection at all the answer defaults TRUE
   * (treated as lying), never the other way.
   */
  async bestCheckpointCore(): Promise<{ readonly best?: SignedCheckpointView; readonly headLiared: boolean }> {
    const { best } = await this.selectFromWalk(true)
    if (best === undefined) return { headLiared: true }
    return { best: signedCheckpointViewOf(best), headLiared: best.headLiared === true }
  }

  /**
   * @internal P5: the view-facing candidate core behind
   * {@link createVerifiedView}.publishableCandidates — ONE physical snapshot
   * (the same `selectionSnapshot` the single selection draws from), every
   * structurally publishable checkpoint under the anchor-key rule, in
   * DESCENDING (newest-first) order. Structural means: well-formed count,
   * position corroborated (`headLiared` false — Y-H-01's exclusion, so no
   * consumer of the sequence can notarise a transplant by forgetting the
   * predicate), signature-bearing (`sig` + `keyId` present, so a key-holder
   * downstream CAN verify). The signature itself is deliberately NOT
   * adjudicated here — the sequence exists precisely so a consumer whose
   * adjudication of `candidates[0]` fails (refuted, or a key this host does
   * not hold) can walk down to the next candidate with its own verifier
   * (transparency's `selectPublishable` first-verifiable-wins). The
   * loud-undefined anchor states answer `[]`, the exact `latestSignedCheckpoint`
   * `undefined` rule — never a silent any-key pool.
   */
  async publishableCandidatesCore(): Promise<readonly SignedCheckpointView[]> {
    const { walk, anchor, anchorUnusable } = await this.selectionSnapshot()
    if (anchorUnusable) return []
    return publishableCandidateList(walk, anchor).map(signedCheckpointViewOf)
  }

  /**
   * v0.22 (L-A1-10): the last well-formed checkpoint, selected with the
   * audit's own anchor-answering rule — when the out-of-band anchor exists
   * and names a key, ONLY that key's well-formed checkpoints are candidates
   * (and none of them existing returns `undefined`, the attack state where a
   * rewound chain has nothing anchored to say). Anchor-less chains keep the
   * any-key semantics. Consumers that used to fall back to "the last
   * well-formed checkpoint of any key" (training export anchors) should use
   * this so a rewritten chain cannot smuggle a foreign checkpoint into an
   * anchor-shaped decision.
   *
   * W1-M7 (v0.23): an anchor file that exists but cannot be consulted —
   * unparseable OR domain-invalid — is a loud `undefined`, exactly the
   * `latestSignedCheckpoint` rule, instead of a silent fall-back to the
   * any-key pool. No anchor file at all keeps the any-key semantics: "never
   * anchored" is a deployment fact.
   *
   * Y-H-01 (v0.24): head liars are excluded here too — a transplanted
   * checkpoint must not anchor a training export any more than a publish.
   */
  async lastWellFormedCheckpoint(): Promise<{ count: number; head: string; keyId: string | null; index: number } | undefined> {
    const { best } = await this.selectFromWalk(false)
    if (best === undefined) return undefined
    return { count: best.payload.count, head: best.payload.head, keyId: best.keyId, index: best.index }
  }

  async saveBaseline(baseline: Baseline): Promise<void> {
    const contents = JSON.stringify(baseline, null, 2)
    await this.fs.writeFile(this.baselinePath, contents)
    // The baseline file is a plain JSON document — an adversary with write
    // access could replace it wholesale. Recording its digest in the chain
    // (and checkpointing right after) makes any later substitution detectable.
    await this.mark('baseline/saved', { digest: sha256(contents), bytes: contents.length })
    await this.checkpoint()
  }

  /**
   * H-23 (v0.22): loading a baseline is now an integrity decision, not a
   * shape check. The document must (1) canonically re-derive its own id —
   * every record still addresses itself, the merkle root over the recorded
   * addresses still matches, the id still covers the same material
   * `buildBaseline` hashed — and (2) still be the bytes the last non-suspect
   * `baseline/saved` marker remembers. A document that fails either returns
   * `undefined`: stripped non-addressing fields (`scriptDigests`,
   * `apiSurface`), doctored payloads under kept ids, and rebuilt-consistent
   * forgeries all read as "no baseline" to the consumer instead of as a
   * fresh truth to verify against. (`audit()` surfaces the same findings as
   * `baselineTampered`; this method is the load-path half the engine
   * consumes.)
   *
   * Y-H-09 (v0.24): the authorship check moved UP to this read. When this
   * host holds the signing key, the `baseline/saved` marker about to answer
   * for the chain must be self-authored by this process or vouched by a
   * verified same-key checkpoint at-or-after it — a pseudo-absorption (the
   * X-H-08 shape: out-of-band twin marker + doctored file, both perfectly
   * shaped) previously loaded as a fresh truth and only met its refusal at
   * the NEXT signing boundary, minting verdicts against the poisoned bytes
   * first (and never on a keyless deployment). It now loads as `undefined`
   * at the moment of reading. Keyless stores keep the v0.23 rule — without
   * a key nothing can vouch, and a capability gap is not an accusation.
   */
  async loadBaseline(): Promise<Baseline | undefined> {
    const raw = await this.fs.readFile(this.baselinePath)
    if (raw === undefined) return undefined
    const verified = verifyBaselineDocument(raw)
    if (!verified.claimed || verified.baseline === undefined) return undefined
    // Chain binding: only when the chain actually remembers a save. No
    // marker at all (a baseline placed by a flow that never recorded one,
    // or a log lost independently) degrades to the canonical check above
    // rather than to a false accusation.
    const lines = await this.logLines()
    const answering = lastBaselineMarker(_readMarkers(lines, { label: 'baseline/saved' }))
    if (answering !== undefined) {
      const signer = await this.resolveSigner()
      if (signer !== undefined) {
        // Same Y-H-09 scope as audit(): a host whose key signs nothing on
        // this chain is a borrowed pair of eyes — digest/canonical rules
        // apply, the vouch demand does not.
        const signedCps = walkChain(lines).checkpoints.filter(cp => cp.sig !== null)
        const allSignedForeign = signedCps.length > 0 && signedCps.every(cp => cp.keyId !== signer.keyId)
        if (!allSignedForeign) {
          const lastVerifiedOwn = await this.lastVerifiedOwnIndex(lines, signer)
          if (!baselineMarkerAuthorised(answering, lines, this.selfProtectedMarkers, lastVerifiedOwn)) return undefined
        }
      }
      const saved = baselineDigestOf(answering)
      if (saved !== undefined && sha256(raw) !== saved) return undefined
    }
    return verified.baseline
  }

  /**
   * @internal Y-H-09 (v0.24): the line index of the LAST checkpoint of this
   * host's key whose signature actually verified (-1 when none) — the
   * vouching boundary baseline-marker authorship is judged against. Shared
   * by the read paths; `audit` derives the same number from its own
   * adjudication pass.
   */
  private async lastVerifiedOwnIndex(lines: readonly string[], signer: SignerPort): Promise<number> {
    let last = -1
    for (const cp of walkChain(lines).checkpoints) {
      if (cp.sig === null || cp.keyId !== signer.keyId) continue
      let honest: boolean
      try {
        honest = await signer.verify(checkpointSignedData(cp.payload), cp.sig)
      } catch {
        honest = false
      }
      if (honest && cp.index > last) last = cp.index
    }
    return last
  }
}

// ---------------------------------------------------------------------------
// The verified read layer (v0.23) — the one trust surface over the raw log
// ---------------------------------------------------------------------------

/** One marker as the verified read layer admits it. */
export interface VerifiedMarkerView {
  /** Index of the marker line within the log. */
  readonly index: number
  readonly label: string
  readonly payload: Record<string, unknown>
  /**
   * The H-32 position test: the line's `headRef` does not match its physical
   * predecessor. In a non-degraded generation suspect markers are simply not
   * admitted (they stay visible via `audit().chain.suspectMarkers`); this
   * flag is therefore only meaningful on degraded-generation records.
   */
  readonly suspect: boolean
  /**
   * X-H-06 (v0.23): present exactly when this record was admitted by the
   * generational fallback — EVERY marker under the label is suspect, the
   * shape of a log written before the headRef witness existed. The fallback
   * reads them anyway (last-wins, lastBaselineDigest's rule): an upgraded
   * deployment keeps exactly the history it had, instead of every protected
   * marker evaporating into `delegation/*` DAG loss and `task-1` aliasing.
   * Consumers that must refuse degraded trust can test for it.
   */
  readonly degraded?: true
}

/** {@link VerifiedChainView.markers} result. */
export interface VerifiedMarkers {
  /**
   * The trusted pool in log order, filtered to the `[sinceLine, maxLine]`
   * window when either bound is given (`sinceLine`: index >= sinceLine, the
   * baseline-generation epoch floor; `maxLine`: index <= maxLine, its
   * symmetric ceiling — P5: a consumer anchoring on "the state as of line N"
   * (a checkpoint boundary, an incident marker) reads exactly the pool that
   * existed at N, without re-slicing the log itself).
   */
  readonly records: readonly VerifiedMarkerView[]
  /** True when the pool is a degraded (all-suspect legacy) generation. */
  readonly degraded: boolean
  /** Last-wins trusted read — the last element of `records`, for lastBaselineDigest-shaped consumers. */
  readonly last: VerifiedMarkerView | undefined
}

/** How the best checkpoint's signature fared under adjudication. */
export type BestCheckpointSignature =
  /** Selected and verified under the very key it names. */
  | 'verified'
  /** The key this checkpoint names actively refutes the signature — a forgery charge; publish paths must treat as none. */
  | 'refuted'
  /** No signer available (or it names a foreign key): a missing capability — the checkpoint data is still returned so downstream holders of the key can verify (X-H-10). */
  | 'unverifiable'
  /** No publishable candidate at all (also the loud-undefined anchor states of `latestSignedCheckpoint`). */
  | 'none'

/** {@link VerifiedChainView.bestCheckpoint} result. */
export interface BestCheckpoint {
  readonly signature: BestCheckpointSignature
  /** The selected checkpoint (absent only for `none`). */
  readonly checkpoint?: SignedCheckpointView
  /**
   * X-H-03 (v0.23): the selected checkpoint swears a head the walk does not
   * corroborate at its position (`payload.head !== expectedHead`) — the
   * replay/transplant shape. The signature can be perfectly honest over a
   * payload that is lying about WHERE; publish and delegation paths must
   * treat `signature === 'verified' && headLiared` as refuse, exactly as
   * `preSignAudit`'s own head-liars rule does before signing.
   */
  readonly headLiared?: boolean
}

/** Options for {@link createVerifiedView}. */
export interface VerifiedViewOptions {
  /**
   * Resolves the signer signatures are adjudicated under. Defaults to the
   * store's own trust wiring (`hostSigner()`); inject one when the caller
   * holds a different (e.g. anchor) key than the store writes with.
   */
  readonly signerProvider?: () => Promise<SignerPort | undefined>
}

/**
 * v0.23: the unified verified read layer — the ONLY surface trust decisions
 * should read markers and checkpoints through. Kills the "wired to a dead
 * channel" family at the root: instead of every consumer hand-rolling
 * its own parse + suspect + fallback (and each forgetting one of the three —
 * the survey's X-H-01/X-H-06/X-M-18 findings), the three judgements live
 * here, once:
 *
 * - `markers` — one physical read, one pass (the engine's per-marker
 *   `isSuspectMarker` rescans were O(n²)~O(n³)); suspect position
 *   adjudication; the generational fallback so legacy logs degrade instead
 *   of evaporating; an optional `sinceLine` epoch window (baseline-generation
 *   aware consumers pass the anchoring line's index) and its symmetric
 *   `maxLine` ceiling (P5: "the pool as of line N" reads — both bounds apply
 *   to the TRUSTED pool, so a suspect twin outside the window can never
 *   re-enter by window arithmetic).
 * - `bestCheckpoint` — `latestSignedCheckpoint`'s selection with the
 *   signature actually ADJUDICATED (`verified`/`refuted`/`unverifiable`)
 *   and the X-H-03 head-liar mirror. Y-H-01 (v0.24): the publish predicate
 *   `signature === 'verified' && headLiared !== true` is enforced by the
 *   SELECTION itself — a head liar is never a candidate, so no consumer can
 *   forget the second half of the predicate.
 * - `publishableCandidates` — P5: the candidate SEQUENCE behind
 *   `bestCheckpoint`. The single-selection shape is newest-first with a
 *   de-facto one-vote veto: when the newest structurally-publishable
 *   checkpoint fails ADJUDICATION (refuted signature, or a key this host
 *   does not hold), `bestCheckpoint` answers `refuted`/`unverifiable` and
 *   every consumer of the single answer refuses — even when an older,
 *   perfectly verifiable checkpoint sits right below it on the chain. The
 *   sequence face exposes that fallback: every well-formed, position-
 *   corroborated, signature-bearing candidate (the same pool
 *   `selectBestCheckpoint` draws from, under the same anchor-key rule), in
 *   DESCENDING order, signatures NOT adjudicated here — the consumer walks
 *   it newest-first with its own verifier (transparency's
 *   `selectPublishable` first-verifiable-wins semantics, living in the
 *   evidence layer). `bestCheckpoint` is exactly `candidates[0]` adjudicated
 *   — the two faces cannot disagree about which checkpoint is newest.
 *   API-contract warning (F6, v0.25): `candidates[0]` is the NEWEST
 *   structurally-publishable checkpoint, NOT a verdict — the pool checks
 *   structure only (well-formed count, non-liar position, sig + keyId
 *   present), never that the signature verifies. A consumer that publishes
 *   `candidates[0]` without adjudicating it publishes a possibly-refutable
 *   line; every in-repo consumer verifies before use.
 * - `audit` — passthrough, so verdict paths stop cherry-picking single
 *   channels (X-H-09's `audit.ok` consumption lands on this surface).
 *
 * v0.24 (Y-H-03): the store's own public reads (`markersWith`,
 * `latestSignedCheckpoint`, `lastWellFormedCheckpoint`, `audit`'s marker
 * channels) derive from the SAME module-private cores this view uses — one
 * rule, two entry points, zero forking surface.
 */
export interface VerifiedChainView {
  markers(label: string, options?: { readonly sinceLine?: number; readonly maxLine?: number }): Promise<VerifiedMarkers>
  bestCheckpoint(): Promise<BestCheckpoint>
  publishableCandidates(): Promise<readonly SignedCheckpointView[]>
  audit(): Promise<AuditReport>
}

/**
 * Build the {@link VerifiedChainView} over a store. Pure read layer: it never
 * mutates the log, never resolves a signer for writing, and holds no state
 * between calls — every call takes its own physical snapshot (the M-32
 * one-read-many-derivations discipline, one judgement per snapshot).
 */
export function createVerifiedView(store: EvidenceStore, options: VerifiedViewOptions = {}): VerifiedChainView {
  const signerProvider = options.signerProvider ?? store.hostSigner()
  return {
    async markers(label, markerOptions = {}): Promise<VerifiedMarkers> {
      // ONE physical read, ONE pass: _readMarkers collects every line of the
      // label with its suspect verdict in a single scan (W1-L12/X-M-18: the
      // old per-marker isSuspectMarker calls re-parsed the whole log each
      // time). The pool decision is then pure.
      const lines = await store.rawLines()
      const all = _readMarkers(lines, { label })
      const trusted = all.filter(m => !m.suspect)
      // X-H-06 generational fallback, lastBaselineDigest's rule lifted from
      // "the last digest" to the whole record list: trusted markers win;
      // when the label has NO non-suspect marker at all (a log written
      // before the headRef witness existed — every marker of every label is
      // then suspect), the legacy list is read degraded rather than dropped,
      // and last-wins consumers get the physically last record as before.
      //
      // V1-M5/M6 (v0.24): the fallback only reaches DOWN — at or below the
      // last checkpoint of the view's key whose signature actually verified
      // (the prefix the key vouched for). v0.23's pool was "every suspect
      // marker of the label", which could not tell "history written before
      // the headRef witness existed" from "a headRef-less line appended
      // AFTER the anchor today": an injected `delegation/created` (or any
      // protected label) joined the degraded pool, became its physically
      // last member, and last-wins consumers (DAGs, obligation graphs)
      // consumed the forgery as legacy history. A suspect line ABOVE the
      // epoch bound is fresh, not legacy — it does not enter the pool.
      // Without a verifiable checkpoint there is no bound to defend with
      // (pure legacy log, or a keyless view — no key, no adjudication; a
      // capability gap is not an accusation), and the whole suspect
      // population reads degraded exactly as before.
      const signer = signerProvider === undefined ? undefined : await signerProvider().catch(() => undefined)
      const bound = signer === undefined ? undefined : await verifiedEpochBound(lines, signer)
      const legacy = bound === undefined
        ? all.filter(m => m.suspect)
        : all.filter(m => m.suspect && m.index <= bound)
      const degraded = trusted.length === 0 && legacy.length > 0
      const pool = degraded ? legacy : trusted
      const sinceLine = markerOptions.sinceLine
      const maxLine = markerOptions.maxLine
      // P5: both window bounds are applied INLINE on the already-adjudicated
      // pool (no second pass, no second read) — the window selects within the
      // trusted/degraded pool decision, never around it, so a suspect twin
      // outside the window stays out and a degraded generation inside the
      // window still carries its `degraded` marking.
      const inWindow = (m: MarkerRecord): boolean =>
        (sinceLine === undefined || m.index >= sinceLine)
        && (maxLine === undefined || m.index <= maxLine)
      const records = pool.filter(inWindow)
        .map(m => (degraded ? { ...m, degraded: true as const } : m))
      return { records, degraded, last: records[records.length - 1] }
    },

    async bestCheckpoint(): Promise<BestCheckpoint> {
      // Y-H-03/V1-L10 (v0.24): selection AND head-liar verdict come from the
      // store's shared single-read core — one physical snapshot, one walk,
      // no second read to misalign. The core's verdict defaults conservative
      // (true) whenever it cannot corroborate; the Y-H-01 filter means a
      // selected candidate is never a liar, so `headLiared` is false on
      // every non-`none` answer by construction.
      const { best, headLiared } = await store.bestCheckpointCore()
      if (best === undefined) return { signature: 'none' }
      const signer = signerProvider === undefined ? undefined : await signerProvider().catch(() => undefined)
      if (signer === undefined || signer.keyId !== best.keyId) {
        // X-H-10 half: the payload, keyId and detached sig ride along so the
        // transparency layer (which holds the publishing key) can verify the
        // old head itself — "cannot adjudicate" must not mean "no data".
        return { signature: 'unverifiable', checkpoint: best, headLiared }
      }
      let honest: boolean
      try {
        honest = await signer.verify(checkpointSignedData(best.payload), best.sig)
      } catch {
        honest = false // hostile input discipline: the auditor reports, never throws
      }
      return honest
        ? { signature: 'verified', checkpoint: best, headLiared }
        : { signature: 'refuted', checkpoint: best, headLiared }
    },

    /**
     * P5: the candidate sequence behind {@link bestCheckpoint} — see the
     * interface doc. One snapshot per call (the store's shared selection
     * core); `candidates[0]` is always the checkpoint `bestCheckpoint` would
     * select, so the sequence is a strictly-more-informed view of the same
     * selection, never a second opinion that can fork from it.
     */
    async publishableCandidates(): Promise<readonly SignedCheckpointView[]> {
      return store.publishableCandidatesCore()
    },

    audit: (): Promise<AuditReport> => store.audit(),
  }
}

/**
 * @internal V1-M5/M6 (v0.24): the epoch bound of the generational fallback —
 * the line index of the LAST checkpoint of `signer`'s key whose signature
 * actually verified over the given snapshot, or `undefined` when the walk has
 * no checkpoint that can serve as a bound (no checkpoints at all, or none
 * this key can adjudicate).
 *
 * U2-H1 (v0.25): the loop now skips malformed-count and head-liar
 * checkpoints, aligning it with the two derivations that already did —
 * `checkpointPool`/`selectBestCheckpoint` (the selection faces) and the
 * engine's `vouchedFloor` (the key/liar/malformed scan-back). The bound
 * guards the invariant "a suspect line ABOVE the epoch bound is fresh, not
 * legacy — it
 * does not enter the degraded pool": a TRANSPLANTED honest checkpoint (an
 * original signed line re-appended at the tail, `prev` re-chained) still
 * verifies under the key — the signature covers {count, head, workspaceKey,
 * at}, not the envelope's position — but the walk flags it `headLiared`
 * (and its count falls behind → malformed). v0.24's bound counted it anyway,
 * so the transplant raised the bound above a fresh headRef-less twin and the
 * twin entered the degraded pool as physically-last. A line whose position
 * or count the walk refutes cannot vouch for the content below it, whatever
 * its signature says.
 */
async function verifiedEpochBound(lines: readonly string[], signer: SignerPort): Promise<number | undefined> {
  const walk = walkChain(lines)
  if (walk.checkpoints.length === 0) return undefined
  const malformed = new Set(walk.malformedCheckpoints)
  let bound: number | undefined
  for (const cp of walk.checkpoints) {
    if (malformed.has(cp.index) || cp.headLiared) continue
    if (cp.sig === null || cp.keyId !== signer.keyId) continue
    let honest: boolean
    try {
      honest = await signer.verify(checkpointSignedData(cp.payload), cp.sig)
    } catch {
      honest = false
    }
    if (honest && (bound === undefined || cp.index > bound)) bound = cp.index
  }
  return bound
}

/**
 * @internal Y-H-01 (v0.24): the one selection pass every "best checkpoint"
 * consumer shares (the store's public reads and the verified view). Excludes
 * malformed counts and head liars from the pool BEFORE the anchor-key rule;
 * `requireSigned` picks the publish-shaped pool (sig + keyId) or the
 * training-anchor pool (any well-formed checkpoint).
 */
function selectBestCheckpoint(walk: ChainWalk, anchor: AnchorFile | undefined, requireSigned: boolean): WalkedCheckpoint | undefined {
  const pool = checkpointPool(walk, requireSigned)
  if (pool.length === 0) return undefined
  if (anchor !== undefined && anchor.keyId !== '') {
    return pool.findLast(cp => cp.keyId === anchor.keyId)
  }
  return pool[pool.length - 1]
}

/**
 * @internal The structurally-publishable pool both selection faces draw
 * from: well-formed counts (the walk corroborates the self-report), positions
 * the walk corroborates (`headLiared` false — Y-H-01), and — under
 * `requireSigned` — a signature and keyId a downstream key-holder can verify
 * under. Malformed and lying checkpoints are not "candidates that fail";
 * they are not candidates at all.
 */
function checkpointPool(walk: ChainWalk, requireSigned: boolean): WalkedCheckpoint[] {
  const malformed = new Set(walk.malformedCheckpoints)
  return walk.checkpoints.filter(cp =>
    !malformed.has(cp.index)
    && !cp.headLiared
    && (!requireSigned || (cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null)))
}

/**
 * @internal P5: the publish candidate sequence — the requireSigned pool
 * under the anchor-key rule (an anchor naming a key restricts candidates to
 * that key's checkpoints, exactly `selectBestCheckpoint`'s rule; anchor-less
 * keeps the any-key semantics), in DESCENDING order so a consumer scanning
 * with its own verifier (transparency's `selectPublishable` first-verifiable-
 * wins) reaches the newest verifiable checkpoint first. `selectBestCheckpoint`
 * over the same inputs is always `list[0]`.
 */
function publishableCandidateList(walk: ChainWalk, anchor: AnchorFile | undefined): WalkedCheckpoint[] {
  const pool = checkpointPool(walk, true)
  const keyed = anchor !== undefined && anchor.keyId !== '' ? pool.filter(cp => cp.keyId === anchor.keyId) : pool
  return [...keyed].reverse()
}

/** @internal Narrow a walked checkpoint to the publish-facing view shape. */
function signedCheckpointViewOf(best: WalkedCheckpoint): SignedCheckpointView {
  if (best.sig === null || best.keyId === null) {
    // Unreachable from selectBestCheckpoint's requireSigned pool (sig and
    // keyId are guaranteed non-null there); kept for type-narrowing honesty.
    throw new Error('signedCheckpointViewOf: selected checkpoint carries no signature')
  }
  return {
    payload: {
      count: best.payload.count,
      head: best.payload.head,
      workspaceKey: best.payload.workspaceKey,
      at: best.payload.at,
    },
    keyId: best.keyId,
    sig: best.sig,
    index: best.index,
  }
}

/** @internal Y-H-02: whether the walk carries any refusal line (gates the lazy authorship scan). */
function refusedPendingProbe(walk: ChainWalk): boolean {
  return walk.checkpoints.some(cp => cp.sig === null && cp.sigError !== null && cp.sigError.startsWith(SIG_REFUSED_PREFIX))
}

/**
 * H-32/M-A1-5: the `baseline/saved` marker that gets to answer for the
 * chain. Last-wins among NON-suspect markers carrying a digest — an
 * attacker's appended twin (carrying the digest of a doctored file) cannot
 * vouch for its position on the chain, so it does not get to answer. When
 * every digest-carrying marker is suspect (a log written before the headRef
 * witness existed), the last one still speaks: upgraded deployments keep
 * exactly the detection they had, never less. The digest itself is read via
 * {@link baselineDigestOf}; the marker (not just its digest) is returned so
 * the Y-H-09 authorship check can judge the ANSWERING line.
 */
function lastBaselineMarker(markers: readonly MarkerRecord[]): MarkerRecord | undefined {
  const withDigest = markers.filter(m => typeof m.payload.digest === 'string')
  const trusted = withDigest.filter(m => !m.suspect)
  const pool = trusted.length > 0 ? trusted : withDigest
  return pool[pool.length - 1]
}

/** The digest the answering `baseline/saved` marker remembers, when it carries one. */
function baselineDigestOf(marker: MarkerRecord | undefined): string | undefined {
  return marker === undefined || typeof marker.payload.digest !== 'string' ? undefined : marker.payload.digest
}

/**
 * Y-H-09 (v0.24): whether the answering `baseline/saved` marker is
 * AUTHORISED to answer for the chain — written by THIS process, or sitting
 * at-or-below a checkpoint of this host's key whose signature this host
 * verified (the prefix the key already vouched for). A marker that is
 * neither is a live claim nobody authored on the covered tail: the X-H-08
 * pseudo-absorption shape, charged at READ time instead of at the next
 * signing boundary. Callers scope the demand first (keyless hosts and
 * foreign-key auditors are borrowed eyes — see `audit`/`loadBaseline`); an
 * absent marker (`undefined`) degrades to the canonical/digest rules, never
 * a manufactured accusation.
 */
function baselineMarkerAuthorised(
  marker: MarkerRecord | undefined,
  lines: readonly string[],
  selfDigests: ReadonlySet<string>,
  lastVerifiedOwn: number,
): boolean {
  if (marker === undefined) return true
  if (selfDigests.has(lineDigest(lines[marker.index] ?? ''))) return true
  return marker.index <= lastVerifiedOwn
}

/**
 * V1-L11 (v0.24): whether an evidence payload still addresses itself — the
 * read-time trust check `all()`/`latest()` and the dedupe cache admit rows
 * by. Hostile payloads the canonical form refuses to serialise are not
 * self-addressing by the strongest possible reading.
 */
function selfAddresses(ev: Evidence): boolean {
  const { evidenceId, ...rest } = ev
  try {
    return addressOf(rest) === evidenceId
  } catch {
    return false
  }
}

/**
 * H-08: how the log answers an out-of-band anchor. The anchor is answered
 * ONLY by a well-formed checkpoint of the anchor's own key carrying the
 * EXACT (count, head) pair it remembers — an honest store writes that pair
 * to the chain and mirrors it to the anchor file in the same breath, so an
 * honest log always answers, on a keyless audit host exactly as much as on
 * one that holds the key. When nothing answers, the direction tells the
 * story: a best answer below the anchored count (or no candidate at all) is
 * a rewind suspicion — a truncated or rewound log; a candidate at-or-above
 * the anchored count that is not the anchored pair is a mismatch — an
 * inflated self-report trying to answer an anchor whose prefix it never
 * contained, or an equal count with a different head.
 */
function answerAnchor(
  checkpoints: readonly WalkedCheckpoint[],
  malformedCheckpoints: readonly number[],
  anchor: AnchorFile,
): { rewind: boolean; mismatch: boolean } {
  const malformed = new Set(malformedCheckpoints)
  const candidates = checkpoints.filter(cp => !malformed.has(cp.index) && cp.keyId === anchor.keyId)
  const answered = candidates.some(cp => cp.payload.count === anchor.count && cp.payload.head === anchor.head)
  if (answered) return { rewind: false, mismatch: false }
  const best = candidates[candidates.length - 1]
  if (best === undefined || best.payload.count < anchor.count) return { rewind: true, mismatch: false }
  return { rewind: false, mismatch: true }
}

/**
 * H-23 (v0.22): verify a baseline document against its own canonical
 * identity. `claimed` is true when the document presents itself as a
 * baseline at all (`baselineId` string or `checks` array); `baseline` is the
 * parsed document only when it is BOTH well-shaped and internally
 * consistent — every record still addresses itself under the package's own
 * `addressOf`, the merkle root over the recorded addresses still matches the
 * `root` the id covers, and recomputing `buildBaseline`'s material from the
 * parsed fields reproduces `baselineId` byte-for-byte. A claimed document
 * that fails any of that is the lazy-edit shape (payload doctored, ids
 * kept): `claimed: true, baseline: undefined`, which `audit()` reports as
 * `baselineTampered` and `loadBaseline()` refuses.
 */
function verifyBaselineDocument(raw: string): { claimed: boolean; baseline?: Baseline } {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { claimed: false }
  }
  if (parsed === null || typeof parsed !== 'object') return { claimed: false }
  const doc = parsed as Record<string, unknown>
  const claimed = typeof doc.baselineId === 'string' || Array.isArray(doc.checks)
  if (!claimed || !Array.isArray(doc.checks) || typeof doc.baselineId !== 'string') {
    return { claimed }
  }
  for (const check of doc.checks) {
    if (check === null || typeof check !== 'object') return { claimed: true }
    const record = check as Record<string, unknown>
    if (typeof record.evidenceId !== 'string') return { claimed: true }
    const { evidenceId, ...rest } = record
    let addressed: string
    try {
      addressed = addressOf(rest)
    } catch {
      return { claimed: true } // uncanonicalisable payload: the strongest "does not address itself"
    }
    if (addressed !== evidenceId) return { claimed: true }
  }
  let id: string | undefined
  try {
    const root = merkleRoot(doc.checks.map(c => (c as Record<string, unknown>).evidenceId as string))
    id = addressOf({
      createdAt: doc.createdAt,
      workspace: doc.workspace,
      checkIds: doc.checks.map(c => (c as Record<string, unknown>).checkId),
      root,
    })
  } catch {
    return { claimed: true }
  }
  return id === doc.baselineId ? { claimed: true, baseline: parsed as Baseline } : { claimed: true }
}

function parseEnvelope(line: string): LogEnvelope | undefined {
  try {
    const value = JSON.parse(line) as LogEnvelope
    if (!value || (value.v !== 1 && value.v !== 2)) return undefined
    return value
  } catch {
    return undefined
  }
}

/**
 * Whether the line is complete JSON at all. Torn-write recovery keys on this:
 * a truncated line cannot parse, while tampering usually leaves *valid* JSON
 * (rewritten envelopes) — so an unparseable tail is treated as crash residue
 * and anything else is left for audit to adjudicate.
 */
function parsesAsJson(line: string): boolean {
  try {
    JSON.parse(line)
    return true
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/** Statuses that settle the check's question. Everything else is "ran, but no conclusion". */
const DECISIVE_STATUSES: ReadonlySet<CheckStatus> = new Set(['pass', 'fail'])

/**
 * Whether a status is a decisive answer (`pass`/`fail`). `skipped`, `timeout`,
 * `aborted` and `error` all mean the check ran without producing — or never
 * got the chance to produce — a verdict, and the knowledge lattice treats
 * them identically: unknown.
 */
export function isDecisiveStatus(status: CheckStatus | undefined): boolean {
  return status !== undefined && DECISIVE_STATUSES.has(status)
}

/**
 * Baseline-differential verdict: the entire point of the plugin.
 *
 * `regression` is reserved for "it passed before *this work* and fails now" —
 * a failing check that was already failing at baseline is `still-failing` and
 * must never be charged to the current session. And since the knowledge
 * lattice is three-valued, neither direction of the comparison may borrow
 * certainty from the other: a check that was *skipped* at baseline (budget
 * exhausted before it ever ran) can neither prove a regression nor credit a
 * fix, so it lands on `indeterminate` — the old behaviour of rounding
 * "never ran" up to "ok" manufactured verdicts out of nothing.
 */
export function verdictOf(baseline: Evidence | undefined, current: Evidence | undefined): CheckVerdict {
  const b = baseline?.status
  const c = current?.status
  if (c === undefined) return b === undefined ? 'new-check' : 'not-run'
  // No baseline record at all: the current run is the only knowledge we have,
  // so a decisive outcome can still be stated (as credit or as new breakage);
  // a non-decisive one cannot.
  if (b === undefined) {
    if (!isDecisiveStatus(c)) return 'indeterminate'
    return c === 'pass' ? 'new-check' : 'new-failure'
  }
  // A baseline that produced no decisive result (skipped/timeout/aborted/
  // error) is not a pass to regress from nor a fail to fix — whatever the
  // current run says, credit and blame both require two decisive sides.
  if (!isDecisiveStatus(b) || !isDecisiveStatus(c)) return 'indeterminate'
  if (b === 'pass' && c === 'pass') return 'still-passing'
  if (b === 'fail' && c === 'fail') return 'still-failing'
  if (b === 'pass' && c === 'fail') return 'regression'
  return 'fixed'
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  try { return String(error) } catch { return '<unprintable>' }
}

export type { CheckStatus as EvidenceCheckStatus }
