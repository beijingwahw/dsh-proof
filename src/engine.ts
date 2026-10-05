/**
 * `ProofEngine` — the domain façade.
 *
 * Wires the pure core together behind one imperative API the DSH adapter (or
 * any other host) can call. Holds no Cordis types; the host injects ports.
 *
 * Trust wiring (v0.2): when `trustDir` (or a `signer` provider) is supplied,
 * the store hash-chains every line, signs checkpoints with a host-held
 * Ed25519 key, and mirrors the highest checkpoint to an out-of-band anchor
 * — see `core/trust.ts` for the adversary model. An absolute `evidenceDir`
 * is used as-is, which is how hosts keep the log outside the agent's
 * writable workspace.
 *
 * @module dsh-proof/engine
 */

import type {
  Baseline, CheckSpec, Clock, CommandPort, DependencyGraph, Evidence,
  FsPort, ProofReport, RelPath, SelectionResult, SignerPort, WorkspacePort, WorkspaceSnapshot,
} from './core/index.ts'
import {
  EvidenceStore, VerificationRunner, assembleBaseline, assembleProof,
  buildDependencyGraph, discoverChecks, selectAffectedChecks, snapshotWorkspace,
} from './core/index.ts'
import type { AuditReport } from './core/evidence.ts'
import type { AttributedCheck } from './core/regression.ts'
import type { CheckConfigEntry, DiscoverOptions } from './core/checks.ts'
import { NodeCommandPort, NodeEd25519Signer, NodeFsPort, GitWorkspace, SystemClock } from './node-ports.ts'

export interface EngineOptions {
  readonly root: string
  /**
   * Where evidence lives. Relative paths resolve against the workspace root
   * (legacy, agent-writable); absolute paths are used as-is so hosts can keep
   * the log under DSH_HOME instead.
   */
  readonly evidenceDir?: string
  /** Host-side trust root (signing keys + anchors), outside the workspace. */
  readonly trustDir?: string
  /** Stable workspace identity committed into checkpoints and anchors. */
  readonly workspaceKey?: string
  /** Append a signed checkpoint after every N records (boundaries always do). */
  readonly checkpointEvery?: number
  /** Explicit signer provider; overrides trustDir-derived Ed25519. */
  readonly signer?: () => Promise<SignerPort | undefined>
  readonly autoDiscover?: boolean
  readonly checks?: readonly CheckConfigEntry[]
  readonly checkTimeoutMs?: number
  readonly verifyBudgetMs?: number
  readonly concurrency?: number
  readonly impactGraph?: boolean
  readonly impactGraphLimit?: number
  readonly headChars?: number
  readonly clock?: Clock
  readonly fs?: FsPort
  readonly commands?: CommandPort
  readonly workspace?: WorkspacePort
}

export interface VerifyOptions {
  /** Explicit change set. Defaults to `git status --porcelain` + baseline drift. */
  readonly changed?: readonly RelPath[]
  readonly signal?: AbortSignal
  /** Force the full check set regardless of impact analysis. */
  readonly all?: boolean
  readonly onProgress?: (label: string, index: number, total: number) => void
}

export interface VerifyOutcome {
  readonly report: ProofReport
  readonly checks: readonly AttributedCheck[]
  readonly selection: SelectionResult
  readonly changed: readonly RelPath[]
}

function isAbsolutePath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

export class ProofEngine {
  readonly root: string
  private readonly fs: FsPort
  private readonly commands: CommandPort
  private readonly workspace: WorkspacePort
  private readonly clock: Clock
  private readonly store: EvidenceStore
  private readonly runner: VerificationRunner

  private specs: CheckSpec[] = []
  private graph: DependencyGraph | undefined
  private baselineSeen = false
  private signerPromise: Promise<SignerPort | undefined> | undefined
  private readonly options: {
    evidenceDir: string
    autoDiscover: boolean
    checks: readonly CheckConfigEntry[]
    checkTimeoutMs: number
    verifyBudgetMs: number
    concurrency: number
    impactGraph: boolean
    impactGraphLimit: number
    headChars: number
  }

  constructor(options: EngineOptions) {
    this.root = options.root
    this.clock = options.clock ?? new SystemClock()
    this.fs = options.fs ?? new NodeFsPort()
    this.commands = options.commands ?? new NodeCommandPort()
    this.workspace = options.workspace ?? new GitWorkspace(options.root, this.commands, this.clock)
    const evidenceDir = options.evidenceDir ?? '.proof'
    const storeDir = isAbsolutePath(evidenceDir)
      ? evidenceDir.replace(/[\/]+$/, '')
      : `${options.root.replace(/[\/]+$/, '')}/${evidenceDir}`
    const workspaceKey = options.workspaceKey ?? 'default'
    const signerProvider = options.signer
      ?? (options.trustDir !== undefined ? () => this.loadSigner(`${options.trustDir}/keys`) : undefined)
    this.store = new EvidenceStore(
      this.fs,
      `${storeDir}/evidence.jsonl`,
      `${storeDir}/baseline.json`,
      this.clock,
      {
        ...(signerProvider !== undefined ? { signer: signerProvider } : {}),
        ...(options.trustDir !== undefined ? { anchorPath: `${options.trustDir}/anchors/${workspaceKey}/anchor.json` } : {}),
        workspaceKey,
        checkpointEvery: options.checkpointEvery ?? 25,
      },
    )
    this.runner = new VerificationRunner(this.commands, this.workspace, this.clock)
    this.options = {
      evidenceDir,
      autoDiscover: options.autoDiscover ?? true,
      checks: options.checks ?? [],
      checkTimeoutMs: options.checkTimeoutMs ?? 120_000,
      verifyBudgetMs: options.verifyBudgetMs ?? 300_000,
      concurrency: options.concurrency ?? 2,
      impactGraph: options.impactGraph ?? true,
      impactGraphLimit: options.impactGraphLimit ?? 20_000,
      headChars: options.headChars ?? 2_000,
    }
  }

  /** Host-held Ed25519 signer under the trust root; degrades to unsigned on failure. */
  private loadSigner(dir: string): Promise<SignerPort | undefined> {
    this.signerPromise ??= NodeEd25519Signer.load(dir).catch(() => undefined)
    return this.signerPromise
  }

  // -- discovery ----------------------------------------------------------

  /** Discover (or return cached) objective checks. */
  async loadChecks(force = false): Promise<CheckSpec[]> {
    if (this.specs.length > 0 && !force) return this.specs
    const discoverOptions: DiscoverOptions = {
      checks: this.options.checks,
      timeoutMs: this.options.checkTimeoutMs,
    }
    this.specs = this.options.autoDiscover
      ? await discoverChecks(this.fs, this.root, discoverOptions)
      : await discoverChecks(this.fs, this.root, { ...discoverOptions, checks: this.options.checks.map(c => ({ ...c, exclusive: true })) })
    return this.specs
  }

  /** Build (or return cached) the reverse-dependency graph. */
  async loadGraph(force = false): Promise<DependencyGraph | undefined> {
    if (!this.options.impactGraph) return undefined
    if (this.graph !== undefined && !force) return this.graph
    const files = await this.fs.walk(this.root, {
      limit: this.options.impactGraphLimit,
      ignoreDirs: ['node_modules', '.git', 'dist', 'build', 'out', 'target', 'coverage', '.next', '.venv', 'venv', '__pycache__', 'vendor', '.proof', 'lib', '.turbo', '.cache'],
    })
    this.graph = await buildDependencyGraph(this.fs, this.root, files, { limit: this.options.impactGraphLimit })
    return this.graph
  }

  // -- evidence -----------------------------------------------------------

  get storeView(): EvidenceStore { return this.store }

  /** The filesystem port in use, for hosts that want to share it. */
  get fsView(): FsPort { return this.fs }

  /** Checks discovered so far without triggering discovery. */
  cachedChecks(): readonly CheckSpec[] { return this.specs }

  /** Synchronous baseline-presence probe for prompt assembly (no I/O). */
  hasBaselineSync(): boolean { return this.baselineSeen }

  async baseline(): Promise<Baseline | undefined> {
    const loaded = await this.store.loadBaseline()
    if (loaded !== undefined) this.baselineSeen = true
    return loaded
  }

  async workspaceSnapshot(): Promise<WorkspaceSnapshot> {
    return snapshotWorkspace(this.workspace)
  }

  /** Latest evidence per check. */
  async latestEvidence(): Promise<Map<string, Evidence>> {
    return this.store.latest()
  }

  /** Integrity check of the evidence log: chain, signatures, anchor, baseline. */
  async audit(): Promise<AuditReport> {
    return this.store.audit()
  }

  // -- the two verbs ------------------------------------------------------

  /** Run every discovered check and record the result as the new baseline. */
  async establishBaseline(options: { signal?: AbortSignal; onProgress?: VerifyOptions['onProgress'] } = {}): Promise<{ baseline: Baseline; records: readonly Evidence[] }> {
    const specs = await this.loadChecks()
    const batch = await this.runner.run(specs, {
      concurrency: this.options.concurrency,
      totalBudgetMs: this.options.verifyBudgetMs,
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      ...(options.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
        : {}),
    })
    for (const record of batch.records) await this.store.append(record)
    // saveBaseline records the file digest into the chain and checkpoints.
    const baseline = assembleBaseline(specs, batch.records, batch.workspace, this.clock)
    await this.store.saveBaseline(baseline)
    await this.store.mark('baseline/established', { baselineId: baseline.baselineId, root: baseline.root, checks: batch.records.length })
    await this.store.checkpoint()
    return { baseline, records: batch.records }
  }

  /** Re-run the checks this change set made stale, and grade the claim. */
  async verify(options: VerifyOptions = {}): Promise<VerifyOutcome> {
    const specs = await this.loadChecks()
    const graph = await this.loadGraph()
    const changed = await this.resolveChanged(options.changed)
    const selection = options.all
      ? { affected: specs, untouched: [], forcedAll: true, closure: changed, uncertain: false }
      : selectAffectedChecks(specs, changed, graph)

    const batch = await this.runner.run(selection.affected, {
      concurrency: this.options.concurrency,
      totalBudgetMs: this.options.verifyBudgetMs,
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      ...(options.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
        : {}),
    })
    for (const record of batch.records) await this.store.append(record)

    const baseline = await this.store.loadBaseline()
    const { report, checks } = assembleProof({
      specs,
      baseline,
      records: batch.records,
      changed,
      ...(graph !== undefined ? { graph } : {}),
      workspace: batch.workspace,
      clock: this.clock,
      requireFullCoverage: true,
      ...(options.all === true ? { forceAll: true } : {}),
    })
    await this.store.mark('proof/verified', {
      grade: report.grade, root: report.root, changed: changed.length,
      regressions: report.summary.regressions,
    })
    // Every claim-grade boundary closes the checkpoint window.
    await this.store.checkpoint()
    return { report, checks, selection, changed }
  }

  /** Which files this session changed, relative to the workspace root. */
  private async resolveChanged(explicit?: readonly RelPath[]): Promise<RelPath[]> {
    if (explicit !== undefined) return [...new Set(explicit)].sort()
    // Without a git ref anchor the honest approximation is every path the
    // working tree reports as dirty. Over-attribution costs a re-run;
    // under-attribution hides a break, so we err wide on purpose.
    const dirty = await this.workspace.gitDirty().catch(() => [])
    return [...new Set(dirty)].sort()
  }
}
