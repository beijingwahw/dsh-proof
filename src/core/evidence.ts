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

import type { CheckKind, CheckSpec, Clock, FsPort, SignerPort, WorkspacePort } from './ports.ts'
import { addressOf, canonicalJson, merkleRoot, normalizeOutput, sha256 } from './hash.ts'
import { GENESIS_PREV, checkpointSignedData, lineDigest, parseAnchor, walkChain } from './trust.ts'
import { excerptOutput, type ExcerptOptions } from './excerpt.ts'

export type CheckStatus = 'pass' | 'fail' | 'error' | 'timeout' | 'aborted' | 'skipped'

/** One observed run of one check. Addressed by its own canonical digest. */
export interface Evidence {
  readonly evidenceId: string
  readonly checkId: string
  readonly label: string
  readonly kind: CheckKind
  readonly command: readonly string[]
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

/** Verdict about one check, derived purely from a baseline and fresh evidence. */
export type CheckVerdict =
  | 'still-passing'
  | 'still-failing'
  | 'regression'
  | 'fixed'
  | 'new-failure'
  | 'new-check'
  | 'not-run'

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

/** Turn one observed run into an addressable evidence record. */
export function makeEvidence(
  spec: CheckSpec,
  outcome: RunOutcome,
  workspace: WorkspaceSnapshot,
  clock: Clock,
  excerpt: ExcerptOptions = DEFAULT_EXCERPT,
): Evidence {
  const normalized = normalizeOutput(outcome.output, {})
  const exc = excerptOutput(normalized, excerpt)
  const base = {
    checkId: spec.id,
    label: spec.label,
    kind: spec.kind,
    command: spec.command,
    status: outcome.status,
    exitCode: outcome.exitCode,
    durationMs: outcome.durationMs,
    outputDigest: sha256(normalized),
    outputHead: exc.text,
    ...(exc.truncated ? { outputTruncated: true, outputOmittedChars: exc.omittedChars } : {}),
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
    readonly badCheckpoints: readonly number[]
    readonly unsignedCheckpoints: readonly number[]
    readonly headMismatches: readonly number[]
    /** Records after the last checkpoint — chain-covered, not checkpoint-covered. */
    readonly tailRecords: number
    /** The log ends before the best checkpoint the anchor remembers. */
    readonly rewind: boolean
    readonly anchorMismatch: boolean
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

  /** Load the chain tail (and record counts) from disk exactly once. */
  private async ensureTail(): Promise<void> {
    if (this.tailReady) return
    const lines = await this.fs.readLines(this.logPath)
    let lastCheckpointIndex = -1
    let records = 0
    lines.forEach((line, index) => {
      const envelope = parseEnvelope(line)
      if (envelope === undefined) return
      if (envelope.kind === 'checkpoint') lastCheckpointIndex = index
      if (envelope.kind === 'evidence' || envelope.kind === 'marker') records += 1
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
  }

  private async resolveSigner(): Promise<SignerPort | undefined> {
    if (this.trust.signer === undefined) return undefined
    this.signerPromise ??= this.trust.signer().catch(() => undefined)
    return this.signerPromise
  }

  /** Append one evidence record. Re-appending an existing address is a no-op. */
  async append(evidence: Evidence): Promise<void> {
    if (this.cache.has(evidence.evidenceId)) return
    await this.ensureTail()
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
  async mark(label: string, data: Record<string, unknown> = {}): Promise<void> {
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
   * host's key the writer of the log cannot produce a new one, and without
   * the anchor the log cannot be quietly rewound past the last checkpoint.
   */
  async checkpoint(): Promise<void> {
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
      const anchor = { v: 1, keyId: signer.keyId, count: payload.count, head: payload.head, sig, at: payload.at }
      await this.fs.writeFile(this.trust.anchorPath, JSON.stringify(anchor, null, 2))
    }
  }

  private async maybeCheckpoint(): Promise<void> {
    const every = this.trust.checkpointEvery
    if (every !== undefined && every > 0 && this.sinceCheckpoint >= every) {
      await this.checkpoint()
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
    const unsignedCheckpoints: number[] = []
    const headMismatches: number[] = []
    for (const cp of walk.checkpoints) {
      if (cp.payload.head !== cp.expectedHead) headMismatches.push(cp.index)
      if (cp.sig === null) {
        if (signer !== undefined) unsignedCheckpoints.push(cp.index)
      } else {
        const okSig = signer !== undefined && await signer.verify(checkpointSignedData(cp.payload), cp.sig)
        if (!okSig) badCheckpoints.push(cp.index)
      }
    }

    let rewind = false
    let anchorMismatch = false
    const anchor = parseAnchor(this.trust.anchorPath === undefined ? undefined : await this.fs.readFile(this.trust.anchorPath))
    if (anchor !== undefined) {
      const best = walk.checkpoints[walk.checkpoints.length - 1]
      if (best === undefined || best.payload.count < anchor.count) rewind = true
      else if (best.payload.count === anchor.count && best.payload.head !== anchor.head) anchorMismatch = true
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
      unsignedCheckpoints,
      headMismatches,
      tailRecords: walk.tailRecords,
      rewind,
      anchorMismatch,
      baselineTampered,
    }
    const ok = corrupt.length === 0
      && walk.corruptLines.length === 0
      && walk.chainBreaks.length === 0
      && badCheckpoints.length === 0
      && headMismatches.length === 0
      && unsignedCheckpoints.length === 0
      && !rewind
      && !anchorMismatch
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

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/**
 * Baseline-differential verdict: the entire point of the plugin.
 *
 * `regression` is reserved for "it passed before *this work* and fails now" —
 * a failing check that was already failing at baseline is `still-failing` and
 * must never be charged to the current session.
 */
export function verdictOf(baseline: Evidence | undefined, current: Evidence | undefined): CheckVerdict {
  const b = baseline?.status
  const c = current?.status
  const ok = (s: CheckStatus | undefined) => s === 'pass' || s === 'skipped'
  if (c === undefined) return b === undefined ? 'new-check' : 'not-run'
  if (b === undefined) return ok(c) ? 'new-check' : 'new-failure'
  if (ok(b) && ok(c)) return 'still-passing'
  if (!ok(b) && !ok(c)) return 'still-failing'
  if (ok(b) && !ok(c)) return 'regression'
  return 'fixed'
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  try { return String(error) } catch { return '<unprintable>' }
}

export type { CheckStatus as EvidenceCheckStatus }
