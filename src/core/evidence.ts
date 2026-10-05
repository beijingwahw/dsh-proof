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
import { GENESIS_PREV, checkpointSignedData, lineDigest, parseAnchor, walkChain } from './trust.ts'
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
 */
export function makeEvidence(
  spec: CheckSpec,
  outcome: RunOutcome,
  workspace: WorkspaceSnapshot,
  clock: Clock,
  excerpt: ExcerptOptions = DEFAULT_EXCERPT,
  canonical: NormalizeOptions = {},
  synthetic?: SyntheticEvidenceMeta,
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
      const head = await ws.gitHead().catch(() => null)
      const dirty = await ws.gitDirty().catch(() => [])
      return snapshotWorkspace(head, dirty)
    })()
  }
  const head = a as string | null
  const dirty = [...(b ?? [])].sort()
  return { head, dirty, dirtDigest: sha256(dirty.join('\n')) }
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
    /** Records after the last checkpoint — chain-covered, not checkpoint-covered. */
    readonly tailRecords: number
    /** The log ends before the best checkpoint the anchor remembers. */
    readonly rewind: boolean
    readonly anchorMismatch: boolean
    /** The anchor file failed its own signature check — its data was tampered with. */
    readonly anchorForged: boolean
    /** The baseline file no longer matches the digest recorded in the chain. */
    readonly baselineTampered: boolean
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
    if (this.trust.signer === undefined) return undefined
    this.signerPromise ??= this.trust.signer().catch(() => undefined)
    return this.signerPromise
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
    const envelope: LogEnvelope = {
      v: 2,
      kind: 'marker',
      at: new Date(this.clock.now()).toISOString(),
      prev: this.tail,
      payload: { label, ...data },
    }
    await this.writeEnvelope(envelope)
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
    const payload = {
      count: this.recordsSoFar,
      head: this.tail,
      workspaceKey: this.trust.workspaceKey ?? null,
      at: new Date(this.clock.now()).toISOString(),
    }
    const signer = await this.resolveSigner()
    let sig: string | undefined
    let keyId: string | undefined
    let sigError: string | undefined
    if (signer !== undefined) {
      try {
        sig = await signer.sign(checkpointSignedData(payload))
        keyId = signer.keyId
      } catch (error) {
        // Loud degradation: an unsigned checkpoint that should have been
        // signed is recorded as such and fails audit while a signer is active.
        sigError = errorMessage(error)
      }
    }
    const envelope: LogEnvelope = {
      v: 2,
      kind: 'checkpoint',
      at: payload.at,
      prev: this.tail,
      payload,
      ...(sig !== undefined ? { sig, keyId } : {}),
      ...(sigError !== undefined ? { sigError } : {}),
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
    const lines = await this.fs.readLines(this.logPath)
    const walk = walkChain(lines)
    const all = await this.all()

    const corrupt: string[] = []
    for (const ev of all) {
      const { evidenceId, ...rest } = ev
      if (addressOf(rest) !== evidenceId) corrupt.push(ev.checkId)
    }

    const signer = await this.resolveSigner()
    const badCheckpoints: number[] = []
    const unverifiableCheckpoints: number[] = []
    const unsignedCheckpoints: number[] = []
    const headMismatches: number[] = []
    for (const cp of walk.checkpoints) {
      if (cp.payload.head !== cp.expectedHead) headMismatches.push(cp.index)
      if (cp.sig === null) {
        if (signer !== undefined) unsignedCheckpoints.push(cp.index)
        continue
      }
      // Three-state adjudication: only a key we actually hold, facing a
      // checkpoint that names that very key, gets to *refute* a signature.
      // No signer at all (key lost, different machine) or a foreign keyId is
      // a missing capability — recorded as unverifiable, never as forgery:
      // charging the log with tampering because *we* cannot check it would
      // invert the burden of proof. Rewind cover does not need the key: the
      // anchor's count/head comparison below still bounds the log.
      if (signer === undefined || cp.keyId !== signer.keyId) {
        unverifiableCheckpoints.push(cp.index)
        continue
      }
      if (!(await signer.verify(checkpointSignedData(cp.payload), cp.sig))) badCheckpoints.push(cp.index)
    }

    let rewind = false
    let anchorMismatch = false
    let anchorForged = false
    const anchor = parseAnchor(this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath))
    if (anchor !== undefined) {
      const best = walk.checkpoints[walk.checkpoints.length - 1]
      if (best === undefined || best.payload.count < anchor.count) rewind = true
      else if (best.payload.count === anchor.count && best.payload.head !== anchor.head) anchorMismatch = true
      // The anchor is signed data too, and it is the one artifact the agent
      // cannot recompute — tampering with its fields while keeping the sig is
      // exactly the attack the signature exists for. Only adjudicated when
      // this host holds the writing key AND the anchor carries every field
      // the signature commits to; anchors predating `workspaceKey` skip the
      // check (count/head monotonicity still applies) rather than fail it.
      if (
        anchor.sig !== '' && signer !== undefined
        && anchor.keyId === signer.keyId
        && anchor.workspaceKey !== undefined
      ) {
        const signed = checkpointSignedData({
          count: anchor.count,
          head: anchor.head,
          workspaceKey: anchor.workspaceKey,
          at: anchor.at,
        })
        if (!(await signer.verify(signed, anchor.sig))) anchorForged = true
      }
    }

    let baselineTampered = false
    const baselineRaw = await this.fs.readFile(this.baselinePath)
    const saved = lastMarkerDigest(lines, 'baseline/saved')
    if (baselineRaw !== undefined && saved !== undefined && sha256(baselineRaw) !== saved) baselineTampered = true

    const chain = {
      mode: walk.mode,
      breaks: walk.chainBreaks,
      checkpoints: walk.checkpoints.length,
      badCheckpoints,
      unverifiableCheckpoints,
      unsignedCheckpoints,
      headMismatches,
      tailRecords: walk.tailRecords,
      rewind,
      anchorMismatch,
      anchorForged,
      baselineTampered,
    }
    // `unverifiableCheckpoints` deliberately does NOT fail the audit: a key we
    // no longer hold must not turn into a forgery verdict against the log.
    // Every *refutable* claim — corruption, breaks, forged signatures, head
    // mismatches, unsigned-while-signed, rewind, anchor mismatch/forgery,
    // baseline substitution — does.
    const ok = corrupt.length === 0
      && walk.corruptLines.length === 0
      && walk.chainBreaks.length === 0
      && badCheckpoints.length === 0
      && headMismatches.length === 0
      && unsignedCheckpoints.length === 0
      && !rewind
      && !anchorMismatch
      && !anchorForged
      && !baselineTampered
    return { ok, total: all.length, corrupt, chain }
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

  async loadBaseline(): Promise<Baseline | undefined> {
    const raw = await this.fs.readFile(this.baselinePath)
    if (raw === undefined) return undefined
    try {
      const parsed = JSON.parse(raw) as Baseline
      return typeof parsed?.baselineId === 'string' && Array.isArray(parsed.checks) ? parsed : undefined
    } catch {
      return undefined
    }
  }
}

function lastMarkerDigest(lines: readonly string[], label: string): string | undefined {
  let digest: string | undefined
  for (const line of lines) {
    const envelope = parseEnvelope(line)
    if (envelope?.kind !== 'marker') continue
    const payload = envelope.payload as { label?: unknown; digest?: unknown }
    if (payload?.label === label && typeof payload?.digest === 'string') digest = payload.digest
  }
  return digest
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
