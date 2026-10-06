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
import { GENESIS_PREV, SIG_REFUSED_PREFIX, checkpointSignedData, lineDigest, parseAnchor, parseAnchorEx, walkChain } from './trust.ts'
import type { AnchorFile, WalkedCheckpoint } from './trust.ts'
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
     * refusal is the store accusing its own log; it always fails `ok`.
     */
    readonly refusedToSign?: readonly number[]
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
 * baseline integrity), so an injected or replayed line under them is worth
 * forging: every `attest/*` verdict, and the `baseline/*` summary family.
 * Writes under these labels carry a `headRef` witness; readers can filter by
 * it (see {@link readMarkers}).
 */
export function isProtectedMarkerLabel(label: unknown): boolean {
  return typeof label === 'string'
    && (label.startsWith('attest/')
      || label.startsWith('baseline/')
      || label.startsWith('delegation/')
      || label === 'proof/verified')
}

/**
 * X-H-08 (v0.23): the `baseline/*` labels that *change what the log believes
 * about the baseline document* — `baseline/saved` (a new file's digest became
 * the remembered truth) and `baseline/established` (the engine took a fresh
 * anchor, with its own tamper/degradation metadata). An out-of-band append
 * under either label re-defines the baseline the next session verifies
 * against, which is why the pre-sign audit refuses to lend the host key over
 * foreign ones (see `preSignAudit`). Informational `baseline/*` labels beyond
 * these two (none today) would need the same treatment before being added.
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
 * @internal Single-pass parsing primitive over raw lines. Kept exported for
 * tests and for `EvidenceStore` internals; the trust-decision read surface is
 * {@link createVerifiedView} (v0.23) — engine and tool consumers migrate there
 * so suspect adjudication, the generational fallback and the single-read
 * discipline live in exactly one place.
 *
 * Pure over the given lines — callers hand in the same physical snapshot the
 * rest of their judgement used (the TOCTOU rule: one read, many derivations).
 * `options.label` filters to one label; `options.excludeSuspect` drops
 * suspect lines (the shape κ fusion and baseline-digest reads want: the
 * honest writer's line survives, the attacker's appended twin does not).
 */
export function readMarkers(lines: readonly string[], options: { readonly label?: string; readonly excludeSuspect?: boolean } = {}): MarkerRecord[] {
  const out: MarkerRecord[] = []
  lines.forEach((line, index) => {
    const envelope = parseEnvelope(line)
    if (envelope?.kind !== 'marker') return
    const payload = envelope.payload as { label?: unknown }
    if (typeof payload?.label !== 'string') return
    if (options.label !== undefined && payload.label !== options.label) return
    const suspect = isProtectedMarkerLabel(payload.label) && headRefOf(payload) !== previousLineDigest(lines, index)
    if (options.excludeSuspect === true && suspect) return
    out.push({ index, label: payload.label, payload: payload as Record<string, unknown>, suspect })
  })
  return out
}

/**
 * @internal The line indexes {@link readMarkers} would flag as suspect.
 * Tests and the audit report consume this; trust decisions belong on
 * {@link createVerifiedView}.
 */
export function suspectMarkerIndexes(lines: readonly string[]): readonly number[] {
  return readMarkers(lines).filter(m => m.suspect).map(m => m.index)
}

/**
 * @internal Whether the marker line at `index` is suspect under the H-32
 * rule. NOTE: each call re-scans the whole log — never call it in a loop over
 * markers (W1-L12/X-M-18: that is the O(n²)~O(n³) read amplification the
 * verified view exists to kill). Kept for the engine's legacy read paths
 * during migration and for tests.
 */
export function isSuspectMarker(lines: readonly string[], index: number): boolean {
  return suspectMarkerIndexes(lines).includes(index)
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
   * X-H-08 (v0.23): digests of every `baseline/saved` / `baseline/established`
   * marker line THIS process wrote (via `mark`/`saveBaseline`). Content
   * addressing makes the set replay-proof: an attacker re-appending one of
   * these lines verbatim keeps its digest but breaks the chain (its `prev`
   * still points at its original predecessor); altering anything to re-chain
   * it changes the digest out of the set. See `preSignAudit`.
   */
  private readonly selfBaselineMarkers = new Set<string>()
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

  static atWorkspace(fs: FsPort, root: string, clock: Clock): EvidenceStore {
    return new EvidenceStore(fs, `${root}/${DEFAULT_LOG_RELPATH}`, `${root}/${DEFAULT_BASELINE_RELPATH}`, clock)
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
    let lines = await this.fs.readLines(this.logPath)
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
      if (envelope.kind === 'evidence') {
        const payload = envelope.payload as { evidenceId?: unknown }
        if (typeof payload?.evidenceId === 'string') this.cache.set(payload.evidenceId, payload as Evidence)
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
      // contradicts it and reads back as suspect (see `readMarkers`).
      payload: { label, ...callerData, ...(isProtectedMarkerLabel(label) ? { headRef: this.tail } : {}) },
    }
    await this.writeEnvelope(envelope)
    // X-H-08: remember the digest of every baseline-family marker line THIS
    // process wrote — the author set the pre-sign audit's unvouched-marker
    // rule (see `preSignAudit`) checks foreign lines against.
    if (isBaselineMarkerLabel(label)) this.selfBaselineMarkers.add(this.tail)
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
   * X-H-08 (v0.23) adds the one *authorship* signal: a `baseline/saved` or
   * `baseline/established` marker line sitting on the checkpoint-uncovered
   * tail that THIS process never wrote (see `selfBaselineMarkers`). See the
   * rule's full comment inline below.
   */
  private async preSignAudit(signer: SignerPort): Promise<string | undefined> {
    const lines = await this.fs.readLines(this.logPath)
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
    // X-H-08 (v0.23): cross-session tail absorption. Between sessions (no
    // store process alive — CLI invocations, MCP server restarts) an append
    // of well-formed, correctly-chained, headRef-correct lines is invisible
    // to every shape check above: nothing breaks, nothing lies structurally,
    // and the next process's ensureTail absorbs the bytes as honest history.
    // The one append whose laundering matters most is a foreign
    // `baseline/saved`/`baseline/established` marker: it re-defines the
    // baseline the next session verifies against, and the host key signing
    // the next checkpoint would notarise it and lift the anchor over it.
    //
    // The rule: per baseline-family label, the NEWEST marker line physically
    // after the last host-verified checkpoint (the signed tail — the only
    // prefix the key already vouches for) must be one THIS process wrote
    // (see `selfBaselineMarkers`). Newest-per-label, because marker reads
    // are last-wins: an older foreign line sitting beneath a newer
    // self-written one is a dead letter — it no longer answers anything —
    // while a foreign line that IS the newest of its label is a live claim
    // nobody authored, and the store refuses to lend it the key.
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
    // - Honest restarts do not refuse: `saveBaseline` writes its marker and
    //   checkpoints in the same breath, so a previous session's baseline
    //   markers always sit at-or-below a verified checkpoint, and THIS
    //   process's own newest markers are in the author set by construction.
    // - The narrow honest casualty — a session dying between
    //   `mark('baseline/…')` and its checkpoint, or one whose checkpoint
    //   landed only as a sigError line (which vouches nothing) — leaves a
    //   foreign-newest marker behind; the next session refuses ONCE and the
    //   documented recovery is the re-anchor flow: `saveBaseline` (or the
    //   engine's establish) writes a newer SELF-authored marker, superseding
    //   the orphan, and signing resumes. (A deployment that adds a signer to
    //   a previously unsigned workspace takes exactly one such refusal, on
    //   the first boundary, before re-anchoring — by design.)
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
      if (typeof markerPayload?.label !== 'string' || !isBaselineMarkerLabel(markerPayload.label)) return
      lastOfLabel.set(markerPayload.label, { index, self: this.selfBaselineMarkers.has(lineDigest(line)) })
    })
    const unvouched = [...lastOfLabel.values()].filter(last => !last.self).map(last => last.index).sort((a, b) => a - b)
    if (unvouched.length > 0) problems.push(`unvouched-baseline-marker@${unvouched.join(',')}`)
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
    const lines = await this.fs.readLines(this.logPath)
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

  /** Every evidence record ever appended, in log order. */
  async all(): Promise<Evidence[]> {
    const lines = await this.fs.readLines(this.logPath)
    const out: Evidence[] = []
    for (const line of lines) {
      const parsed = parseEnvelope(line)
      if (parsed?.kind !== 'evidence') continue
      const ev = parsed.payload as Evidence
      if (typeof ev?.evidenceId === 'string') {
        this.cache.set(ev.evidenceId, ev)
        out.push(ev)
      }
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
    const lines = await this.fs.readLines(this.logPath)
    const walk = walkChain(lines)
    const all: Evidence[] = []
    for (const line of lines) {
      const parsed = parseEnvelope(line)
      if (parsed?.kind !== 'evidence') continue
      const ev = parsed.payload as Evidence
      if (typeof ev?.evidenceId === 'string') {
        this.cache.set(ev.evidenceId, ev)
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
    const headMismatches: number[] = []
    // Signatures of the key this host actually holds, verified once: they
    // feed both the forgery charge below and the recovery witness that
    // separates an honest transient signing failure from a stripped one.
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
    for (const cp of walk.checkpoints) {
      if (cp.headLiared) headMismatches.push(cp.index)
      if (cp.sig === null) {
        // H-27/H-32: a signature-less line is three different facts, and the
        // writer's own on-chain sigError note is what tells them apart.
        if (cp.sigError !== null && cp.sigError.startsWith(SIG_REFUSED_PREFIX)) {
          // The store itself refused to sign — its own audit found the chain
          // tampered. The store accusing its own log is the strongest signal
          // the audit has; it always fails `ok`.
          refusedToSign.push(cp.index)
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
        if (signer !== undefined) unsignedCheckpoints.push(cp.index)
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
      // (1) Chain binding — the file bytes must still be the bytes the last
      // HONEST `baseline/saved` marker remembers (H-32: appended twin markers
      // are suspect and do not get to answer for the chain; when every
      // marker is suspect — a log written before the headRef witness existed
      // — the last one still speaks, so upgraded deployments are never worse
      // than before). This is the half that catches a REBUILT-consistent
      // forgery (the attacker re-runs the package's own address/merkle
      // functions) and the stripped non-addressing field (`scriptDigests`,
      // `apiSurface`) that no canonical check can see.
      // (2) Canonical self-consistency — a document that claims to be a
      // baseline must be able to re-derive its own id (every record still
      // addresses itself, root and baselineId still agree). This is the
      // half that catches the lazy edit (payload doctored, ids kept) when no
      // marker can be consulted at all.
      const saved = lastBaselineDigest(readMarkers(lines, { label: 'baseline/saved' }))
      if (saved !== undefined && sha256(baselineRaw) !== saved) baselineTampered = true
      else {
        const verified = verifyBaselineDocument(baselineRaw)
        if (verified.claimed && verified.baseline === undefined) baselineTampered = true
      }
    }

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
      malformedCheckpoints: walk.malformedCheckpoints,
      corruptLines: walk.corruptLines,
      tailRecords: walk.tailRecords,
      rewind,
      anchorMismatch,
      anchorForged,
      anchorInvalid,
      baselineTampered,
      suspectMarkers: suspectMarkerIndexes(lines),
    }
    // `unverifiableCheckpoints` deliberately does NOT fail the audit: a key we
    // no longer hold must not turn into a forgery verdict against the log.
    // Every *refutable* claim — corruption, breaks, forged signatures, head
    // mismatches, malformed counts, unsigned-while-signed, a signing refusal,
    // rewind, anchor mismatch/forgery/invalid, baseline substitution — does.
    // `sigErrorCheckpoints` (honest transient failures with a recovery
    // witness) and `suspectMarkers` (cannot-vouch lines) are visible without
    // failing `ok`: the first is a recovered blip, the second an unproven
    // suspicion whose trust-side exclusion happens at the consumers.
    const ok = corrupt.length === 0
      && walk.corruptLines.length === 0
      && walk.chainBreaks.length === 0
      && badCheckpoints.length === 0
      && headMismatches.length === 0
      && walk.malformedCheckpoints.length === 0
      && unsignedCheckpoints.length === 0
      && refusedToSign.length === 0
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
   *   laundering) that carry a non-empty `sig` AND a non-null `keyId`.
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
   *   signed well-formed checkpoint of any key is the honest answer.
   * - No signed checkpoint at all → `undefined` (an unsigned chain has nothing
   *   publishable; the caller reports that as a precondition, not a crash).
   */
  async latestSignedCheckpoint(): Promise<SignedCheckpointView | undefined> {
    const lines = await this.fs.readLines(this.logPath)
    const walk = walkChain(lines)
    const malformed = new Set(walk.malformedCheckpoints)
    const signed = walk.checkpoints.filter(cp =>
      cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null && !malformed.has(cp.index))
    if (signed.length === 0) return undefined
    const anchorRaw = this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath)
    if (anchorRaw !== undefined && parseAnchor(anchorRaw) === undefined) return undefined
    const anchor = parseAnchor(anchorRaw)
    const best = anchor !== undefined && anchor.keyId !== ''
      ? [...signed].findLast(cp => cp.keyId === anchor.keyId) ?? undefined
      : signed[signed.length - 1]
    if (best === undefined) return undefined
    if (best.sig === null || best.keyId === null) return undefined // narrowed for the caller; the filter above already guarantees both
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

  /**
   * v0.22 (H-32/M-A1-5): every marker under one label, in log order, with
   * tamper-evidence metadata. This is the marker read-back the store now
   * owns, so trust-decision consumers (κ attestation fusion, baseline
   * digests) do not have to re-parse raw lines last-wins. Pass
   * `excludeSuspect: true` to see only markers whose position on the chain
   * their own `headRef` can vouch for — the honest writer's line survives an
   * attacker's appended twin, because only the attacker's contradicts its
   * physical predecessor.
   */
  async markersWith(label: string, options: { readonly excludeSuspect?: boolean } = {}): Promise<MarkerRecord[]> {
    return readMarkers(await this.fs.readLines(this.logPath), { label, excludeSuspect: options.excludeSuspect })
  }

  /**
   * @internal One physical snapshot of the log lines, for the verified read
   * layer ({@link createVerifiedView}) — so its `markers`/`bestCheckpoint`
   * judgements derive from bytes the store itself read, not a second fs path
   * the caller wires up. Not a general API: readers that need raw lines
   * should say what they trust via the view.
   */
  async rawLines(): Promise<readonly string[]> {
    return this.fs.readLines(this.logPath)
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
   * unparseable OR domain-invalid — is now a loud `undefined`, exactly the
   * `latestSignedCheckpoint` rule, instead of a silent fall-back to the
   * any-key pool (which let a foreign checkpoint win the training anchor on
   * precisely the hosts an attacker had been at). No anchor file at all
   * keeps the any-key semantics: "never anchored" is a deployment fact.
   */
  async lastWellFormedCheckpoint(): Promise<{ count: number; head: string; keyId: string | null; index: number } | undefined> {
    const walk = walkChain(await this.fs.readLines(this.logPath))
    const malformed = new Set(walk.malformedCheckpoints)
    const candidates = walk.checkpoints.filter(cp => !malformed.has(cp.index))
    if (candidates.length === 0) return undefined
    const anchorRaw = this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath)
    const anchorOutcome = parseAnchorEx(anchorRaw)
    if (anchorRaw !== undefined && anchorOutcome?.anchor === undefined) return undefined
    const anchor = anchorOutcome?.anchor
    const pool = anchor !== undefined && anchor.keyId !== ''
      ? candidates.filter(cp => cp.keyId === anchor.keyId)
      : candidates
    const best = pool[pool.length - 1]
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
    const saved = lastBaselineDigest(readMarkers(await this.fs.readLines(this.logPath), { label: 'baseline/saved' }))
    if (saved !== undefined && sha256(raw) !== saved) return undefined
    return verified.baseline
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
  /** The trusted pool in log order, filtered to `sinceLine` when given. */
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
 * channel" family at the root: instead of every consumer hand-rolling its
 * own parse + suspect + fallback (and each forgetting one of the three —
 * the survey's X-H-01/X-H-06/X-M-18 findings), the three judgements live
 * here, once:
 *
 * - `markers` — one physical read, one pass (the engine's per-marker
 *   `isSuspectMarker` rescans were O(n²)~O(n³)); suspect position
 *   adjudication; the generational fallback so legacy logs degrade instead
 *   of evaporating; an optional `sinceLine` epoch window (baseline-generation
 *   aware consumers pass the anchoring line's index).
 * - `bestCheckpoint` — `latestSignedCheckpoint`'s selection with the
 *   signature actually ADJUDICATED (`verified`/`refuted`/`unverifiable`)
 *   and the X-H-03 head-liar mirror. The publish predicate is:
 *   `signature === 'verified' && headLiared !== true`.
 * - `audit` — passthrough, so verdict paths stop cherry-picking single
 *   channels (X-H-09's `audit.ok` consumption lands on this surface).
 */
export interface VerifiedChainView {
  markers(label: string, options?: { readonly sinceLine?: number }): Promise<VerifiedMarkers>
  bestCheckpoint(): Promise<BestCheckpoint>
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
      // ONE physical read, ONE pass: readMarkers collects every line of the
      // label with its suspect verdict in a single scan (W1-L12/X-M-18: the
      // old per-marker isSuspectMarker calls re-parsed the whole log each
      // time). The pool decision is then pure.
      const all = readMarkers(await store.rawLines(), { label })
      const trusted = all.filter(m => !m.suspect)
      // X-H-06 generational fallback, lastBaselineDigest's rule lifted from
      // "the last digest" to the whole record list: trusted markers win;
      // when the ENTIRE label population is suspect (a log written before
      // the headRef witness existed — every marker of every label is then
      // suspect), the full list is read degraded rather than dropped, and
      // last-wins consumers get the physically last record as before.
      const degraded = trusted.length === 0 && all.length > 0
      const pool = degraded ? all : trusted
      const sinceLine = markerOptions.sinceLine
      const records = (sinceLine === undefined ? pool : pool.filter(m => m.index >= sinceLine))
        .map(m => (degraded ? { ...m, degraded: true as const } : m))
      return { records, degraded, last: records[records.length - 1] }
    },

    async bestCheckpoint(): Promise<BestCheckpoint> {
      // Selection is exactly `latestSignedCheckpoint`'s (anchor-key rule,
      // malformed exclusion, loud undefined on an unusable anchor) — the
      // audit's own "best" semantics; the view then adds what selection
      // alone never did: adjudication of the selected signature and the
      // head-liar mirror.
      const best = await store.latestSignedCheckpoint()
      if (best === undefined) return { signature: 'none' }
      // Second read for the walk — append-only growth keeps the selected
      // index stable, so a concurrent append cannot misalign the two; the
      // flag is derived from the same walk the audit's headMismatches uses.
      const walked = walkChain(await store.rawLines()).checkpoints.find(cp => cp.index === best.index)
      const headLiared = walked?.headLiared ?? false
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

    audit: (): Promise<AuditReport> => store.audit(),
  }
}

/**
 * H-32/M-A1-5: the digest the chain actually remembers for the baseline
 * file. Last-wins among NON-suspect `baseline/saved` markers — an attacker's
 * appended twin (carrying the digest of a doctored file) cannot vouch for
 * its position on the chain, so it does not get to answer. When every marker
 * is suspect (a log written before the headRef witness existed), the last
 * one still speaks: upgraded deployments keep exactly the detection they
 * had, never less.
 */
function lastBaselineDigest(markers: readonly MarkerRecord[]): string | undefined {
  const withDigest = markers.filter(m => typeof m.payload.digest === 'string')
  const trusted = withDigest.filter(m => !m.suspect)
  const pool = trusted.length > 0 ? trusted : withDigest
  const last = pool[pool.length - 1]
  return last === undefined ? undefined : last.payload.digest as string
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
