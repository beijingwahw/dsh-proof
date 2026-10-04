/**
 * The evidence layer: content-addressed records over an append-only log.
 *
 * Design mirrors DSH's own session-log rule — "everything the model saw must be
 * reconstructable from the log". Here the invariant is stricter: *every claim
 * the model makes must be recomputable from the evidence log*. The log is
 * append-only; a `baseline` or `proof` is just a named view over it.
 *
 * @module dsh-proof/core/evidence
 */

import type { CheckKind, CheckSpec, Clock, FsPort, WorkspacePort } from './ports.ts'
import { addressOf, merkleRoot, normalizeOutput, sha256 } from './hash.ts'

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
  /** First `headChars` characters of normalised output, for humans. */
  readonly outputHead: string
  readonly recordedAt: string
  /** Workspace state when the evidence was produced. */
  readonly workspace: WorkspaceSnapshot
}

export interface WorkspaceSnapshot {
  readonly head: string | null
  readonly dirty: readonly string[]
  /** Digest of the dirty-file set, so "the same dirt" compares equal. */
  readonly dirtDigest: string
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
): Evidence {
  const normalized = normalizeOutput(outcome.output, {})
  const base = {
    checkId: spec.id,
    label: spec.label,
    kind: spec.kind,
    command: spec.command,
    status: outcome.status,
    exitCode: outcome.exitCode,
    durationMs: outcome.durationMs,
    outputDigest: sha256(normalized),
    outputHead: normalized.slice(0, HEAD_CHARS),
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
// The append-only evidence log
// ---------------------------------------------------------------------------

export const DEFAULT_LOG_RELPATH = '.proof/evidence.jsonl'
export const DEFAULT_BASELINE_RELPATH = '.proof/baseline.json'

interface LogEnvelope {
  readonly v: 1
  readonly kind: 'evidence' | 'marker'
  readonly at: string
  readonly payload: unknown
}

/** Content-addressed, append-only evidence store backed by a JSONL file. */
export class EvidenceStore {
  private readonly fs: FsPort
  private readonly logPath: string
  private readonly baselinePath: string
  private readonly clock: Clock
  private readonly cache = new Map<string, Evidence>()

  constructor(fs: FsPort, logPath: string, baselinePath: string, clock: Clock) {
    this.fs = fs
    this.logPath = logPath
    this.baselinePath = baselinePath
    this.clock = clock
  }

  static atWorkspace(fs: FsPort, root: string, clock: Clock): EvidenceStore {
    return new EvidenceStore(fs, `${root}/${DEFAULT_LOG_RELPATH}`, `${root}/${DEFAULT_BASELINE_RELPATH}`, clock)
  }

  /** Append one evidence record. Re-appending an existing address is a no-op. */
  async append(evidence: Evidence): Promise<void> {
    if (this.cache.has(evidence.evidenceId)) return
    const envelope: LogEnvelope = { v: 1, kind: 'evidence', at: new Date(this.clock.now()).toISOString(), payload: evidence }
    await this.fs.appendLine(this.logPath, JSON.stringify(envelope))
    this.cache.set(evidence.evidenceId, evidence)
  }

  /** Append a free-form marker (session boundaries, decisions). */
  async mark(label: string, data: Record<string, unknown> = {}): Promise<void> {
    const envelope: LogEnvelope = { v: 1, kind: 'marker', at: new Date(this.clock.now()).toISOString(), payload: { label, ...data } }
    await this.fs.appendLine(this.logPath, JSON.stringify(envelope))
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

  /** Verify the log's internal consistency: every record still addresses itself. */
  async audit(): Promise<{ ok: boolean; total: number; corrupt: string[] }> {
    const all = await this.all()
    const corrupt: string[] = []
    for (const ev of all) {
      const { evidenceId, ...rest } = ev
      if (addressOf(rest) !== evidenceId) corrupt.push(ev.checkId)
    }
    return { ok: corrupt.length === 0, total: all.length, corrupt }
  }

  async saveBaseline(baseline: Baseline): Promise<void> {
    await this.fs.writeFile(this.baselinePath, JSON.stringify(baseline, null, 2))
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

function parseEnvelope(line: string): LogEnvelope | undefined {
  try {
    const value = JSON.parse(line) as LogEnvelope
    return value && value.v === 1 ? value : undefined
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

export type { CheckStatus as EvidenceCheckStatus }
