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
  Baseline, ChangeProvenance, ChangeSetResolution, CheckSpec, Clock, CommandPort,
  DefinitionResolverPort, DependencyGraph, Evidence, FsPort, ProofReport,
  RelPath, SelectionResult, SignerPort, WorkspacePort, WorkspaceSnapshot,
} from './core/index.ts'
import {
  DEFAULT_IGNORE_DIRS, EvidenceStore, VerificationRunner, assembleBaseline,
  assembleProof, buildDependencyGraph, discoverChecks, resolveChangeSet,
  selectAffectedChecks, sha256, snapshotWorkspace,
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
  /** LSP-backed resolver for precise, alias-aware impact edges (v0.4). */
  readonly resolver?: DefinitionResolverPort
  /** Maximum language-server round-trips per graph build. */
  readonly lspQueryBudget?: number
  /** How output is excerpted into evidence records (v0.5). */
  readonly excerptStrategy?: 'head' | 'balanced'
  readonly headChars?: number
  /** User home directory, canonicalised to `$HOME` in evidence (v0.6). */
  readonly homeDir?: string
  /**
   * Line logger for degradation warnings (E2: trust downgrades must be
   * visible, not just recorded). Hosts wire this to their verbose channel;
   * without it the warning still lands in the evidence chain.
   */
  readonly logger?: (message: string) => void
  /** Emit degradation warnings through `logger`. */
  readonly verbose?: boolean
  readonly clock?: Clock
  readonly fs?: FsPort
  readonly commands?: CommandPort
  readonly workspace?: WorkspacePort
}

export interface VerifyOptions {
  /** Explicit change set. Defaults to a content-anchored diff against the baseline. */
  readonly changed?: readonly RelPath[]
  /** Paths the agent's tool stream touched, for provenance classification. */
  readonly touched?: readonly RelPath[]
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
  /** How the change set was derived and who each change belongs to (v0.3). */
  readonly attribution: ChangeSetResolution
  /**
   * Git facts were unavailable for change-set resolution, so the full check
   * set was forced (E3). Present only on the degraded path; hosts surface it
   * so "we ran everything because we couldn't tell what moved" stays loud.
   */
  readonly degraded?: true
}

/**
 * What `establishBaseline` hands back: the assembled baseline plus, when the
 * batch aborted, a non-addressing flag. The flag rides on top of the
 * `buildBaseline` product and never enters any hash material — it says "this
 * object was never persisted", which the persisted form cannot say about
 * itself.
 */
export type EngineBaseline = Baseline & { readonly aborted?: true }

function isAbsolutePath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

/** Bounded, printable reason a signer load failed — chains store text, not errors. */
function failureText(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : String(reason)
  return text.slice(0, 200)
}

/**
 * Parallel contract: `ChangeSetResolution` grows `degraded?: true` when git
 * facts were unavailable. Read structurally rather than off the declared type
 * so the engine consumes the flag the moment the core lands it, without
 * coupling this module's compilation to the core's edit cadence.
 */
function resolutionDegraded(attribution: ChangeSetResolution): boolean {
  return (attribution as { degraded?: unknown }).degraded === true
}

/** Beyond this many dirty files the per-file digest pass is skipped (conservative mode). */
const WORKSPACE_DIGEST_CAP = 2000

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
  private readonly resolver: DefinitionResolverPort | undefined
  private readonly logger: ((message: string) => void) | undefined
  private readonly verbose: boolean
  private readonly options: {
    evidenceDir: string
    autoDiscover: boolean
    checks: readonly CheckConfigEntry[]
    checkTimeoutMs: number
    verifyBudgetMs: number
    concurrency: number
    impactGraph: boolean
    impactGraphLimit: number
    lspQueryBudget: number
    excerptStrategy: 'head' | 'balanced'
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
    // E2: whichever provider wins (host-injected or trustDir-derived), it is
    // wrapped so a load failure can never pass silently — the downgrade itself
    // becomes a chain marker, and the verbose channel gets a line.
    const rawSignerProvider = options.signer
      ?? (options.trustDir !== undefined ? () => this.loadSigner(`${options.trustDir}/keys`) : undefined)
    const signerProvider = rawSignerProvider !== undefined ? () => this.watchSigner(rawSignerProvider) : undefined
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
    this.runner = new VerificationRunner(this.commands, this.workspace, this.clock, {
      excerpt: { budget: options.headChars ?? 2_000, strategy: options.excerptStrategy ?? 'balanced' },
      canonical: {
        root: options.root,
        ...(options.homeDir !== undefined ? { home: options.homeDir } : {}),
      },
    })
    this.resolver = options.resolver
    this.logger = options.logger
    this.verbose = options.verbose ?? false
    this.options = {
      evidenceDir,
      autoDiscover: options.autoDiscover ?? true,
      checks: options.checks ?? [],
      checkTimeoutMs: options.checkTimeoutMs ?? 120_000,
      verifyBudgetMs: options.verifyBudgetMs ?? 300_000,
      concurrency: options.concurrency ?? 2,
      impactGraph: options.impactGraph ?? true,
      impactGraphLimit: options.impactGraphLimit ?? 20_000,
      lspQueryBudget: options.lspQueryBudget ?? 400,
      excerptStrategy: options.excerptStrategy ?? 'balanced',
      headChars: options.headChars ?? 2_000,
    }
  }

  /** Host-held Ed25519 signer under the trust root; rejects when unavailable. */
  private loadSigner(dir: string): Promise<SignerPort | undefined> {
    return NodeEd25519Signer.load(dir)
  }

  /**
   * Any signer provider, watched: a load failure degrades the chain to
   * unsigned (that part the store already did), but the degradation itself
   * must be observable — a silent downgrade is indistinguishable from an
   * honest unsigned deployment, and the audit cannot flag what it cannot see.
   *
   * The marker is fired, not awaited: the store calls its provider from inside
   * a queued `checkpoint()`, so awaiting `mark` here would queue it behind the
   * very checkpoint that is resolving us — a self-deadlock. Firing it is safe
   * precisely because the store's single-flight tail (core/evidence.ts)
   * serialises the marker after that checkpoint completes: no two envelopes
   * can ever point at the same chain tail. The marker therefore lands one
   * queue-slot later than the degradation was noticed, which costs nothing —
   * it is a fact about the signer, not about the checkpoint's position.
   */
  private watchSigner(load: () => Promise<SignerPort | undefined>): Promise<SignerPort | undefined> {
    this.signerPromise ??= (async () => {
      try {
        return await load()
      } catch (reason) {
        const error = failureText(reason)
        if (this.verbose && this.logger !== undefined) {
          this.logger(`[dsh-proof] trust degraded: checkpoint signer unavailable (${error}) — chain continues unsigned`)
        }
        void this.store.mark('trust/signer-unavailable', { error })
          .catch(() => { /* the log itself is unwritable; nothing more to record */ })
        return undefined
      }
    })()
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
      // E4: one ignore list, owned by discovery (checks.ts) — a second
      // hand-maintained copy here had already drifted. The only local
      // addition is 'lib': this repo's own build output lands there
      // (tsconfig.build.json), and dependency edges into compiled artifacts
      // would make every build a whole-graph invalidator.
      ignoreDirs: [...DEFAULT_IGNORE_DIRS, 'lib'],
    })
    this.graph = await buildDependencyGraph(this.fs, this.root, files, {
      limit: this.options.impactGraphLimit,
      ...(this.resolver !== undefined ? { resolver: this.resolver, lspQueryBudget: this.options.lspQueryBudget } : {}),
    })
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

  /**
   * Run every discovered check and record the result as the new baseline.
   *
   * E1: a batch that did not observe every check to completion must not
   * become THE anchor — later regression judgments would run against a
   * half-built truth. The observed facts still land in the chain (evidence is
   * never discarded), the abort is marked, the checkpoint window is closed,
   * but no baseline file is written: the next verify then honestly reports
   * `no-baseline` instead of silently anchoring on an accident.
   */
  async establishBaseline(options: { signal?: AbortSignal; onProgress?: VerifyOptions['onProgress'] } = {}): Promise<{ baseline: EngineBaseline; records: readonly Evidence[] }> {
    const specs = await this.loadChecks()
    // The detailed snapshot digests every dirty file's content: baseline checks
    // ran against the working tree as it was, so those bytes — not the commit —
    // are what later change-set resolution diffs against.
    const snapshot = await this.snapshotWorkspaceDetailed()
    const batch = await this.runner.run(specs, {
      concurrency: this.options.concurrency,
      totalBudgetMs: this.options.verifyBudgetMs,
      workspace: snapshot,
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      ...(options.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
        : {}),
    })
    // Facts first: whatever was observed is appended, abort or not.
    for (const record of batch.records) await this.store.append(record)
    const baseline = assembleBaseline(specs, batch.records, snapshot, this.clock)
    // Two honest abort signals: the batch-level flag (a cancelled run — some
    // checks were never even attempted) and any record that came back
    // `aborted` (a check whose process was killed mid-flight). Either means
    // the run did not observe everything, so it must not anchor anything.
    const aborted = batch.aborted === true || batch.records.some(r => r.status === 'aborted')
    if (aborted) {
      await this.store.mark('baseline/aborted', {
        baselineId: baseline.baselineId,
        root: baseline.root,
        ran: batch.records.length,
        discovered: specs.length,
      })
      await this.store.checkpoint()
      return { baseline: { ...baseline, aborted: true }, records: batch.records }
    }
    // saveBaseline records the file digest into the chain and checkpoints.
    await this.store.saveBaseline(baseline)
    await this.store.mark('baseline/established', { baselineId: baseline.baselineId, root: baseline.root, checks: batch.records.length })
    await this.store.checkpoint()
    return { baseline, records: batch.records }
  }

  /** Re-run the checks this change set made stale, and grade the claim. */
  async verify(options: VerifyOptions = {}): Promise<VerifyOutcome> {
    const specs = await this.loadChecks()
    const graph = await this.loadGraph()
    const baseline = await this.store.loadBaseline()
    const attribution = await this.resolveChanges(options, baseline)
    const changed = attribution.changed
    const provenance = new Map<RelPath, ChangeProvenance>(
      attribution.records.map(r => [r.path, r.provenance] as [RelPath, ChangeProvenance]),
    )
    // E3: when git facts were unavailable, the derived change set cannot be
    // trusted to narrow the run — an under-reported change set hides breaks.
    // Force the full check set through the same `forced` path `all` uses, and
    // surface the degradation on the outcome so the honesty is visible, not
    // just structural.
    const degraded = resolutionDegraded(attribution) || await this.gitFactsUnavailable()
    const forceAll = options.all === true || degraded
    // NOTE (E5, deliberate duplication): assembleProof recomputes its own
    // internal selection from the same inputs — the report owns that
    // projection. Deduplicating would mean threading a precomputed selection
    // through AssembleInput (core surface, out of this module's hands), so the
    // extra call here stays: it is what feeds VerifyOutcome.selection.
    const selection = forceAll
      ? { affected: specs, untouched: [], forcedAll: true, closure: changed, uncertain: false, precision: 'forced' as const }
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

    const { report, checks } = assembleProof({
      specs,
      baseline,
      records: batch.records,
      changed,
      ...(graph !== undefined ? { graph } : {}),
      ...(provenance.size > 0 ? { provenance } : {}),
      workspace: batch.workspace,
      clock: this.clock,
      requireFullCoverage: true,
      ...(forceAll ? { forceAll: true } : {}),
    })
    await this.store.mark('proof/verified', {
      grade: report.grade, root: report.root, changed: changed.length,
      attribution: attribution.method,
      preExistingExcluded: attribution.preExistingExcluded.length,
      regressions: report.summary.regressions,
    })
    // Every claim-grade boundary closes the checkpoint window.
    await this.store.checkpoint()
    return { report, checks, selection, changed, attribution, ...(degraded ? { degraded: true as const } : {}) }
  }

  /**
   * Defensive backstop for E3: the change-set resolution is growing its own
   * `degraded` flag, but a resolution that has not (yet) been taught to emit
   * it must not let a git-invisible workspace silently narrow verification —
   * every git-dependent fact would come back empty and look like "nothing
   * changed". An absent capability means "git available" per the port
   * contract, so only an explicit `false` (or a probe that itself fails —
   * conservative direction is the full run) forces the check set.
   */
  private async gitFactsUnavailable(): Promise<boolean> {
    if (this.workspace.gitAvailable === undefined) return false
    try {
      return await this.workspace.gitAvailable() === false
    } catch {
      return true
    }
  }

  /**
   * Which files moved since the baseline, and who moved them. Explicit sets
   * are honoured as-is; otherwise the resolution is content-anchored to the
   * baseline's working-tree snapshot, with the plain dirty set as the
   * git-less fallback. Over-attribution costs a re-run; under-attribution
   * hides a break, so unknowns err towards inclusion.
   */
  private async resolveChanges(options: VerifyOptions, baseline: Baseline | undefined): Promise<ChangeSetResolution> {
    return resolveChangeSet({
      fs: this.fs,
      workspace: this.workspace,
      ...(options.changed !== undefined ? { explicit: options.changed } : {}),
      ...(baseline !== undefined
        ? {
            baseline: {
              head: baseline.workspace.head,
              dirty: baseline.workspace.dirty,
              ...(baseline.workspace.dirtyDigests !== undefined ? { dirtyDigests: baseline.workspace.dirtyDigests } : {}),
            },
          }
        : {}),
      ...(options.touched !== undefined ? { touched: options.touched } : {}),
    })
  }

  /** Snapshot with content digests of the dirty set (capped; skipped when huge). */
  private async snapshotWorkspaceDetailed(): Promise<WorkspaceSnapshot> {
    const head = await this.workspace.gitHead().catch(() => null)
    const dirty = [...new Set(await this.workspace.gitDirty().catch(() => []))].sort()
    const dirtDigest = sha256(dirty.join('\n'))
    if (dirty.length > WORKSPACE_DIGEST_CAP) return { head, dirty, dirtDigest }
    const dirtyDigests: Record<string, string> = {}
    for (const rel of dirty) {
      const content = await this.fs.readFile(`${this.root}/${rel}`)
      if (content !== undefined) dirtyDigests[rel] = sha256(content)
    }
    return { head, dirty, dirtDigest, dirtyDigests }
  }
}
