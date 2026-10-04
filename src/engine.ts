/**
 * `ProofEngine` — the domain façade.
 *
 * Wires the pure core together behind one imperative API the DSH adapter (or
 * any other host) can call. Holds no Cordis types; the host injects ports.
 *
 * @module dsh-proof/engine
 */

import type {
  Baseline, CheckSpec, Clock, CommandPort, DependencyGraph, Evidence,
  FsPort, ProofReport, RelPath, SelectionResult, WorkspacePort, WorkspaceSnapshot,
} from './core/index.ts'
import {
  EvidenceStore, VerificationRunner, assembleBaseline, assembleProof,
  buildDependencyGraph, discoverChecks, selectAffectedChecks, snapshotWorkspace,
} from './core/index.ts'
import type { AttributedCheck } from './core/regression.ts'
import type { CheckConfigEntry, DiscoverOptions } from './core/checks.ts'
import { NodeCommandPort, NodeFsPort, GitWorkspace, SystemClock } from './node-ports.ts'

export interface EngineOptions {
  readonly root: string
  readonly evidenceDir?: string
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
    this.store = new EvidenceStore(
      this.fs,
      `${options.root}/${evidenceDir}/evidence.jsonl`,
      `${options.root}/${evidenceDir}/baseline.json`,
      this.clock,
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

  /** Integrity check of the evidence log: every record still addresses itself. */
  async audit(): Promise<{ ok: boolean; total: number; corrupt: string[] }> {
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
    const baseline = assembleBaseline(specs, batch.records, batch.workspace, this.clock)
    await this.store.saveBaseline(baseline)
    await this.store.mark('baseline/established', { baselineId: baseline.baselineId, root: baseline.root, checks: batch.records.length })
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
