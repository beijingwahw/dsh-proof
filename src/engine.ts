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
  Baseline, ChangeProvenance, ChangeSetResolution, CheckSpec, CheckStatus, Clock, CommandPort,
  DefinitionResolverPort, DependencyGraph, Evidence, FsPort, RelPath,
  SelectionResult, SignerPort, WorkspacePort, WorkspaceSnapshot,
} from './core/index.ts'
import {
  DEFAULT_IGNORE_DIRS, EvidenceStore, VerificationRunner, addressOf, assembleBaseline,
  assembleProof, buildDependencyGraph, discoverChecks, isDecisiveStatus,
  resolveChangeSet, selectAffectedChecks, sha256, snapshotWorkspace,
  claimProbability, computePriors, posteriorHealthy, rankByInformationGain,
  summarizeHistory,
} from './core/index.ts'
import type {
  CheckPrior, ClaimModel, ConfidenceBasis, ConfidenceInput, GradedProofReport,
} from './core/index.ts'
// core/index.ts re-exports the stable surface; `forcedSelection` is consumed
// here straight from its module (the core barrel is not this batch's to edit).
import { forcedSelection, extractImportSites } from './core/impact.ts'
import type { AuditReport } from './core/evidence.ts'
import type { AttributedCheck } from './core/regression.ts'
import type { CheckConfigEntry, DiscoverOptions } from './core/checks.ts'
// ζ: the typed claim contract (ε's core/contract.ts) and the jury report
// assembler are consumed straight from their modules — the core barrel is not
// this batch's to edit, and a direct import keeps the dependency explicit.
import { evaluateContract, extractApiSurface } from './core/contract.ts'
import type { ClaimContract, ClaimKind, ObligationResult, SurfaceEntry } from './core/contract.ts'
import { assembleJuryReport, applyCoverageGate } from './core/report.ts'
// κ: graded evidence (ι's core/attest.ts) consumed straight from its module —
// same discipline as the contract import above: the core barrel is not this
// batch's to edit, and a direct import keeps the dependency explicit.
import {
  DEFAULT_TRUST_WEIGHTS, activeAttestations, attestationFactor, attestationsFor,
  claimIdOf, fuseConfidence,
} from './core/attest.ts'
import type { Attestation, TrustWeights } from './core/attest.ts'
// π: the PTC-synthesis primitives (ο's core/synthetic.ts) consumed straight
// from the module — same discipline as the contract/attest imports above: the
// core barrel is not this batch's to edit, and a direct import keeps the
// dependency on `core/synthetic.ts` explicit.
import {
  FORBIDDEN_CAPABILITIES, SYNTHETIC_DIR_DEFAULT, SYNTHETIC_TEMPLATE,
  sandboxEntryFor, screenScript, syntheticSpec,
} from './core/synthetic.ts'
import type { SyntheticEvidenceMeta, SyntheticRequest } from './core/synthetic.ts'
// υ: the V8 execution-coverage domain (τ's core/coverage.ts) — parse, summarise
// and gate, consumed straight from its module (same discipline as the
// contract/attestation/synthetic imports above: the core barrel is not this
// batch's to edit, and a direct import keeps the dependency explicit).
// `applyCoverageGate` — the report-side half of the τ contract — lives in
// core/report.ts and rides that module's existing import.
import {
  coverageGate, parseV8CoverageReport, summarizeCoverage,
} from './core/coverage.ts'
import type { CoverageSummary } from './core/coverage.ts'
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
  /**
   * Verification scheduling strategy (β). `bayesian` (default): rank the
   * affected checks by information gain per cost, run them in waves, and stop
   * once the claim posterior crosses `certifyTarget`. `set`: the legacy
   * whole-batch run with legacy grading — the behavioural escape hatch.
   */
  readonly scheduler?: 'bayesian' | 'set'
  /** Claim-probability target for bayesian certification — the p in `proven (p≈0.97)`. */
  readonly certifyTarget?: number
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
  /**
   * Entry points (workspace-relative) for the baseline API-surface snapshot
   * (ζ). Empty/absent = derive from the project's `package.json` `main`,
   * `exports["."]` and `types` fields. Explicit entries are used as-is.
   */
  readonly apiEntryPoints?: readonly string[]
  /**
   * Confidence ceiling for docs-only jury self-attestation (ζ). Mirrors the
   * plugin config's `juryConfidenceCap` (default 0.8).
   */
  readonly juryConfidenceCap?: number
  /**
   * κ: Class B (LLM jury) trust weight — the log-odds exponent applied to a
   * jury verdict's own probability. Mirrors the plugin config's `classBTrust`
   * (default 0.7).
   */
  readonly classBTrust?: number
  /**
   * κ: Class C (human) trust weight — same exponent semantics over the human
   * probability (0.95). Mirrors the plugin config's `classCTrust` (default
   * 0.9).
   */
  readonly classCTrust?: number
  /**
   * π: sandbox directory for conjured tests, relative to the workspace root.
   * Mirrors the plugin config's `syntheticDir` (default '.proof-synthetic').
   */
  readonly syntheticDir?: string
  /**
   * π: false-pass rate priced into synthetic checks' posteriors — P(observed
   * pass | actually broken) for a test authored by the claim's interested
   * party. Mirrors the plugin config's `syntheticFalsePass` (default 0.15).
   */
  readonly syntheticFalsePass?: number
  /** π: cooperative timeout for one conjured-test run (default 60s). */
  readonly syntheticTimeoutMs?: number
  /**
   * υ: V8 execution-coverage gating mode — `observe` (default: gate only when
   * coverage data exists; no data degrades visibly to basis `'none'`),
   * `require` (no data is itself disqualifying), or `off` (no injection, no
   * gating, byte-identical to pre-υ behaviour). Mirrors the plugin config's
   * `coverage` field; the long design note lives there (config.ts).
   */
  readonly coverage?: 'observe' | 'require' | 'off'
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
  readonly report: GradedProofReport
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
  /**
   * Bayesian wave-plan metadata (β). Present only when the bayesian scheduler
   * actually planned waves — never on the forced/'set' whole-batch path, and
   * never when nothing was affected.
   */
  readonly schedule?: {
    readonly mode: 'bayesian'
    /** Waves actually dispatched. */
    readonly waves: number
    /** Why the plan ended before every affected check ran; null when it ran to completion. */
    readonly stoppedEarly: 'certified' | 'failed' | 'budget' | null
    /** Checks the plan deliberately never dispatched, each with the prior it rests on. */
    readonly skippedByPlan: ReadonlyArray<{ checkId: string; priorHealthy: number }>
  }
  /**
   * υ: what the execution-coverage dimension said about the change set.
   * Present whenever coverage collection ran (modes `observe`/`require`),
   * absent in `off`. `basis: 'none'` is the honest "no data was produced"
   * (fake command ports, non-Node toolchains) — under `observe` it gates
   * nothing, under `require` it is itself the disqualification.
   */
  readonly coverage?: {
    /** `'v8'` — real profiles were read; `'none'` — no data this run. */
    readonly basis: 'v8' | 'none'
    /** Changed files no decisively-passing check actually executed. */
    readonly uncovered: readonly string[]
    /** How many changed files were observed executing. */
    readonly executedCount: number
  }
}

/**
 * What `establishBaseline` hands back: the assembled baseline plus, when the
 * batch aborted, a non-addressing flag. The flag rides on top of the
 * `buildBaseline` product and never enters any hash material — it says "this
 * object was never persisted", which the persisted form cannot say about
 * itself.
 *
 * ζ: the baseline may additionally carry `apiSurface` — the workspace's
 * exported-API fingerprint at baseline time. Like `aborted`, it is a
 * non-addressing attachment: `buildBaseline`'s `baselineId` hashes only
 * {createdAt, workspace, checkIds, root}, so the extra field changes nothing
 * about identity, round-trips through saveBaseline/loadBaseline, and reads
 * back as `undefined` from pre-ζ baseline files.
 */
export type EngineBaseline = Baseline & {
  readonly apiSurface?: readonly string[]
  readonly aborted?: true
}

/** ζ: what `verifyContract` judged a typed claim against, beyond the run. */
export interface ContractSummary {
  readonly kind: ClaimKind
  readonly obligations: readonly ObligationResult[]
  /** Present when the verdict was jury-capped (docs-only self-attestation). */
  readonly juryConfidenceCap?: number
  /**
   * κ: the on-chain Class B/C witnesses whose factors were fused into this
   * verdict's confidence — one entry per *active* attestation for the claim
   * (highest gen wins; appeals override). Present exactly when at least one
   * active witness exists for the claim's id. `verdict` is the jury verdict
   * ('uphold'|'reject'|'abstain') or the human decision ('endorse'|'reject').
   */
  readonly attestations?: ReadonlyArray<{
    readonly class: 'B' | 'C'
    readonly gen: number
    readonly verdict?: string
    readonly factor: number
  }>
}

/** ζ: `verify`'s options grown by the claim contract under judgment. */
export type ContractVerifyOptions = VerifyOptions & { readonly contract: ClaimContract }

/** ζ: `verify`'s outcome grown by the contract verdict. */
export type ContractVerifyOutcome = VerifyOutcome & { readonly contract: ContractSummary }

/**
 * π: what `conjureRun` reports back to the model-facing tool.
 *
 * `status: 'skipped'` means the script was REFUSED at screening and never
 * ran — the findings then ride `screened` and the refusal reason
 * `outputHead`; nothing is written to the chain in that case.
 */
export interface ConjureRunResult {
  /** The synthetic check's identity (stable per claim + entry). */
  readonly checkId: string
  /** The executed record's status, or `'skipped'` for a screening refusal. */
  readonly status: CheckStatus
  /** sha256 of the script as it existed at execution (or refusal) time. */
  readonly scriptDigest: string
  /** Screening findings; empty when the script screened clean. */
  readonly screened: readonly string[]
  /** The execution regime the evidence records. */
  readonly sandbox: SyntheticEvidenceMeta['sandbox']
  /** Excerpt of the run's output, or the refusal reason. */
  readonly outputHead: string
}

/**
 * π: narrow one `synthetic/requested` marker payload back into a
 * `SyntheticRequest`. Malformed payloads (older chains, foreign writes)
 * return `undefined` and are skipped by every consumer — a marker that
 * cannot prove its own shape cannot mint a spec or authorise a run.
 */
function syntheticRequestOf(payload: Record<string, unknown>): SyntheticRequest | undefined {
  const { claimId, claim, paths, entry, requestedAt } = payload as Record<string, unknown>
  if (typeof claimId !== 'string' || typeof claim !== 'string' || typeof entry !== 'string' || typeof requestedAt !== 'number') {
    return undefined
  }
  if (!Array.isArray(paths) || !paths.every(p => typeof p === 'string')) return undefined
  return { claimId, claim, paths, entry, requestedAt }
}

function isAbsolutePath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

/**
 * ζ: workspace-relative path canonicalisation (slash folding + `.`/`..`
 * collapse) — the same discipline `core/impact.ts` applies internally, kept
 * local because that module's helpers are not exported and are not this
 * batch's to touch.
 */
function normalizeRel(path: string): string {
  const segments: string[] = []
  for (const segment of path.replace(/\\/g, '/').split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') segments.pop()
    else segments.push(segment)
  }
  return segments.join('/')
}

/** ζ: directory part of a workspace-relative path ('' at the root). */
function dirnameRel(path: string): string {
  const idx = path.lastIndexOf('/')
  return idx < 0 ? '' : path.slice(0, idx)
}

/**
 * ζ: existence-probe order for one declared package entry. The declared path
 * is tried as-is (extension stripped and restored, so `dist/index.js` also
 * probes its `.ts`/`.d.ts` siblings), then the `src/` equivalent of a
 * compiled layout (`dist/x.js` → `src/x.ts`). First candidate with a readable
 * file wins — the surface is built on probes, never on speculation.
 */
function entryCandidates(declared: string): string[] {
  const clean = declared.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '')
  if (clean.length === 0) return []
  const noExt = clean.replace(/\.(d\.|m\.|c\.)?(t|j)sx?$/i, '')
  const inSrc = noExt.startsWith('src/') ? noExt : `src/${noExt.replace(/^(dist|lib|build|out)\//, '')}`
  const out: string[] = []
  for (const ext of ['', '.ts', '.tsx', '.d.ts', '.js', '.jsx', '.mjs', '.cjs']) {
    out.push(`${noExt}${ext}`)
    out.push(`${inSrc}${ext}`)
  }
  return [...new Set(out)]
}

/** ζ: union two check lists by id, preserving first-seen (selection) order. */
function unionChecks(primary: readonly CheckSpec[], extra: readonly CheckSpec[]): CheckSpec[] {
  const seen = new Set<string>()
  const out: CheckSpec[] = []
  for (const item of [...primary, ...extra]) {
    if (seen.has(item.id)) continue
    seen.add(item.id)
    out.push(item)
  }
  return out
}

/**
 * υ: re-address one runner record over its execution-coverage attachment —
 * exactly π's synthetic-metadata move in `conjureRun`: strip the plain
 * address, add the field, re-derive `evidenceId` over the enriched body
 * (canonical JSON sorts keys, so field order cannot leak into the digest),
 * and the chain only ever sees the self-addressing enriched record. The
 * attachment shape is `Evidence['coverage']` itself (τ's evidence.ts field):
 * content-addressed, so a record cannot claim an execution its address does
 * not encode.
 */
function attachEvidenceCoverage(record: Evidence, coverage: NonNullable<Evidence['coverage']>): Evidence {
  const { evidenceId: plainAddress, ...body } = record
  void plainAddress
  return { ...body, coverage, evidenceId: addressOf({ ...body, coverage }) }
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

/** ζ: import-closure bounds for the API-surface snapshot. */
const API_SURFACE_MAX_DEPTH = 10
const API_SURFACE_MAX_FILES = 500

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
  /** κ: where the evidence log physically lives — marker payloads (attestations) are read back through it. */
  private readonly logPath: string
  /** κ: trust weights for Class B/C evidence, synthesised from config passthrough. */
  private readonly trustWeights: TrustWeights
  /** υ: the evidence store's physical directory — coverage staging lives beside it. */
  private readonly storeDir: string
  private readonly options: {
    evidenceDir: string
    autoDiscover: boolean
    checks: readonly CheckConfigEntry[]
    checkTimeoutMs: number
    verifyBudgetMs: number
    concurrency: number
    scheduler: 'bayesian' | 'set'
    certifyTarget: number
    impactGraph: boolean
    impactGraphLimit: number
    lspQueryBudget: number
    excerptStrategy: 'head' | 'balanced'
    headChars: number
    apiEntryPoints: readonly string[]
    juryConfidenceCap: number
    syntheticDir: string
    syntheticFalsePass: number
    syntheticTimeoutMs: number
    coverage: 'observe' | 'require' | 'off'
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
    // κ: kept separately — EvidenceStore exposes no marker read-back, and the
    // attestation pass below reads the raw marker lines through the same fs
    // port instead of growing the store's public surface mid-batch.
    this.logPath = `${storeDir}/evidence.jsonl`
    // υ: coverage staging roots itself next to the evidence it annotates.
    this.storeDir = storeDir
    // κ: trust weights for graded evidence. The exponents come from config;
    // the human probability rides the shared default so B and C factors stay
    // comparable no matter how a deployment tunes the exponents.
    this.trustWeights = {
      classB: options.classBTrust ?? DEFAULT_TRUST_WEIGHTS.classB,
      classC: options.classCTrust ?? DEFAULT_TRUST_WEIGHTS.classC,
      humanProbability: DEFAULT_TRUST_WEIGHTS.humanProbability,
    }
    const workspaceKey = options.workspaceKey ?? 'default'
    // E2: whichever provider wins (host-injected or trustDir-derived), it is
    // wrapped so a load failure can never pass silently — the downgrade itself
    // becomes a chain marker, and the verbose channel gets a line.
    const rawSignerProvider = options.signer
      ?? (options.trustDir !== undefined ? () => this.loadSigner(`${options.trustDir}/keys`) : undefined)
    const signerProvider = rawSignerProvider !== undefined ? () => this.watchSigner(rawSignerProvider) : undefined
    this.store = new EvidenceStore(
      this.fs,
      this.logPath,
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
      // β: bayesian waves are the default product stance; 'set' is the escape
      // hatch for deployments that must reproduce pre-β behaviour exactly.
      scheduler: options.scheduler ?? 'bayesian',
      certifyTarget: options.certifyTarget ?? 0.97,
      impactGraph: options.impactGraph ?? true,
      impactGraphLimit: options.impactGraphLimit ?? 20_000,
      lspQueryBudget: options.lspQueryBudget ?? 400,
      excerptStrategy: options.excerptStrategy ?? 'balanced',
      headChars: options.headChars ?? 2_000,
      // ζ: API-surface wiring — [] means "derive from package.json", and the
      // jury cap mirrors the plugin config default when the host says nothing.
      apiEntryPoints: options.apiEntryPoints ?? [],
      juryConfidenceCap: options.juryConfidenceCap ?? 0.8,
      // π: PTC-synthesis wiring — the sandbox directory, the synthetic β,
      // and the conjured-test timeout. Defaults mirror core/synthetic.ts and
      // the plugin config; SYNTHETIC_DIR_DEFAULT is the one source of truth
      // for the directory name both sides must agree on.
      syntheticDir: options.syntheticDir ?? SYNTHETIC_DIR_DEFAULT,
      syntheticFalsePass: options.syntheticFalsePass ?? 0.15,
      syntheticTimeoutMs: options.syntheticTimeoutMs ?? 60_000,
      // υ: coverage gating mode — observe by default: real Node check processes
      // get execution-coverage honesty, data-less environments degrade visibly
      // to basis 'none' instead of being blocked on data they cannot produce.
      coverage: options.coverage ?? 'observe',
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
      // υ: baselines do NOT inject coverage (v1): a baseline is a measurement
      // of the workspace's checks, not a claim about a change set — there is
      // no "changed" to gate on yet, and skipping the injection saves a disk
      // write per check. Verification owns the coverage dimension.
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      ...(options.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
        : {}),
    })
    // Facts first: whatever was observed is appended, abort or not.
    for (const record of batch.records) await this.store.append(record)
    const baseline = assembleBaseline(specs, batch.records, snapshot, this.clock)
    // ζ: the API-surface snapshot rides on the baseline as a non-addressing
    // attachment (see EngineBaseline) — computed after `buildBaseline` has
    // minted the id, so baseline identity is untouched by the extra field.
    // `undefined` ("no surface could be derived honestly") attaches nothing:
    // a wrong surface would be worse than none, and old readers simply see a
    // baseline without the field.
    const apiSurface = await this.computeApiSurface()
    const anchored: EngineBaseline = apiSurface === undefined ? baseline : { ...baseline, apiSurface }
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
      return { baseline: { ...anchored, aborted: true }, records: batch.records }
    }
    // saveBaseline records the file digest into the chain and checkpoints.
    await this.store.saveBaseline(anchored)
    await this.store.mark('baseline/established', {
      baselineId: baseline.baselineId,
      root: baseline.root,
      checks: batch.records.length,
      // ζ: whether this baseline carries an API surface is a chain fact —
      // a later `api-surface-unchanged` judgment rests on it.
      apiSurface: apiSurface !== undefined ? apiSurface.length : null,
    })
    await this.store.checkpoint()
    return { baseline: anchored, records: batch.records }
  }

  /** Re-run the checks this change set made stale, and grade the claim. */
  async verify(options: VerifyOptions = {}): Promise<VerifyOutcome> {
    const discovered = await this.loadChecks()
    const graph = await this.loadGraph()
    // π: conjured tests join the verification pool as ordinary specs — every
    // synthetic request the chain shows was actually executed. A workspace
    // with none on chain gets the empty union and behaves bit-for-bit as
    // before; one with them gets them selected, priced (raised β) and
    // re-executed exactly like an organic check (P5).
    const specs = unionChecks(discovered, await this.syntheticSpecs())
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
    // NOTE (E5): assembleProof recomputes its own internal selection from the
    // same inputs — the report owns that projection, and deduplicating would
    // mean threading a precomputed selection through AssembleInput (core
    // surface, out of this module's hands). The extra call here stays: it is
    // what feeds VerifyOutcome.selection. The two paths cannot drift apart on
    // the forced branch, though: both construct it through the single
    // `forcedSelection` factory (core/impact.ts).
    const selection = forceAll
      ? forcedSelection(specs, changed)
      : selectAffectedChecks(specs, changed, graph)

    // β: the sanity constitution keeps the whole-batch path mandatory wherever
    // certainty is owed — `all`, degraded git facts, and the 'set' escape
    // hatch all run every affected check to completion. Only a healthy,
    // non-forced, bayesian-scheduled run may stop early on evidence.
    const bayesian = this.options.scheduler !== 'set' && !forceAll

    // One verification, one workspace snapshot: waves and the whole-batch path
    // alike stamp every record (and the report) with the state verification
    // started from, not with per-wave re-reads that could drift mid-run.
    const snapshot = await this.workspaceSnapshot()

    // υ: this run's coverage scratch tree — created before the machine checks
    // run, read and removed after they settle. The directory name (a clock
    // nonce) is physical staging only: it never enters any hash material, so
    // the same verification re-run against a different clock still addresses
    // its evidence identically.
    const coverageDir = await this.prepareCoverageDir()

    const records: Evidence[] = []
    let schedule: VerifyOutcome['schedule']
    let confidence: ConfidenceInput | undefined
    if (bayesian && selection.affected.length > 0) {
      const plan = await this.runBayesianSchedule(selection.affected, changed, graph, snapshot, options, coverageDir)
      records.push(...plan.records)
      schedule = plan.schedule
      confidence = plan.confidence
    } else {
      // Priors must snapshot the log BEFORE this run appends to it — history
      // is what the check brought to the table, not what it did just now.
      const priors = await this.priorsFor(selection.affected, changed, graph)
      const batch = await this.runner.run(selection.affected, {
        concurrency: this.options.concurrency,
        totalBudgetMs: this.options.verifyBudgetMs,
        workspace: snapshot,
        ...(coverageDir !== undefined ? { coverageDir } : {}),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        ...(options.onProgress !== undefined
          ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
          : {}),
      })
      records.push(...batch.records)
      // Even the whole-batch path earns its confidence number — display only:
      // grading on this path stays binary (requireFullCoverage below).
      confidence = this.updateFactors(priors, batch.records, selection.affected.length > 0)
    }

    // υ: collect coverage and re-address the records BEFORE the first append —
    // the coverage attachment is content-addressing material (π's synthetic
    // precedent), so the chain must never first see a plain record and then
    // its enriched twin. With no data (or mode 'off') the records pass through
    // untouched and this is exactly the pre-υ append.
    const collected = await this.collectRunCoverage(records, changed, coverageDir)
    for (const record of collected.records) await this.store.append(record)

    const { report: machineReport, checks } = assembleProof({
      specs,
      baseline,
      records: collected.records,
      changed,
      ...(graph !== undefined ? { graph } : {}),
      ...(provenance.size > 0 ? { provenance } : {}),
      workspace: snapshot,
      clock: this.clock,
      requireFullCoverage: !bayesian,
      ...(forceAll ? { forceAll: true } : {}),
      ...(confidence !== undefined ? { confidence } : {}),
    })

    // υ: execution-coverage gating — after the machine grade, before anything
    // else speaks. Plain verify() has no attestation fusion (v0.9 semantics
    // locked), so here "gate the machine evidence" is the whole story: an
    // observed-but-never-executed change (or, under `require`, the absence of
    // any observation at all) turns `proven` into `unproven`, and the summary
    // mounts on the report either way — `basis: 'none'` stays visible rather
    // than silently absent, because "could not measure" is a fact a reader of
    // a proof deserves to see.
    const report = this.gateByCoverage(machineReport, collected.summary)

    await this.store.mark('proof/verified', {
      grade: report.grade, root: report.root, changed: changed.length,
      attribution: attribution.method,
      preExistingExcluded: attribution.preExistingExcluded.length,
      regressions: report.summary.regressions,
      // β: the wave plan's footprint rides the marker — what stopped it and
      // how much of the plan never ran are chain facts, like everything else.
      ...(schedule !== undefined
        ? {
            scheduler: schedule.mode,
            waves: schedule.waves,
            stoppedEarly: schedule.stoppedEarly ?? 'completed',
            plannedSkips: schedule.skippedByPlan.length,
            confidence: report.confidence ?? null,
          }
        : {}),
      // υ: what the coverage dimension said at this boundary.
      ...(collected.summary !== undefined
        ? { coverage: this.coverageMarkerPayload(collected.summary) }
        : {}),
    })
    // Every claim-grade boundary closes the checkpoint window.
    await this.store.checkpoint()
    return {
      report, checks, selection, changed, attribution,
      ...(degraded ? { degraded: true as const } : {}),
      ...(schedule !== undefined ? { schedule } : {}),
      ...(collected.summary !== undefined
        ? {
            coverage: {
              basis: collected.summary.basis,
              uncovered: [...collected.summary.changedUncovered],
              executedCount: collected.summary.changedExecuted.length,
            },
          }
        : {}),
    }
  }

  /**
   * ζ: verify a typed claim contract — the objective run plus the obligations
   * the claim's kind imposes on top of it.
   *
   * - docs-only never runs a single check. The claim is judged by jury review
   *   (self-attestation, structurally capped at `juryConfidenceCap`), the
   *   verdict lands on the chain as a `claim/jury` marker, and the report is
   *   the jury report: grade exactly "did every obligation hold", confidence
   *   the capped number, basis `jury-only`.
   * - llm-jury (κ) likewise never runs a single check (skipChecks): the claim
   *   is judged by the *chain's* active Class B/C attestations for its
   *   claimId — highest gen wins, so an appeal overrides. Confidence is the
   *   product of the class-weighted attestation factors (the machine factor
   *   is the neutral 1); `proven` demands every obligation met AND that
   *   product clearing `certifyTarget`. The verdict summary lands as a
   *   `claim/jury` marker carrying claimId, gen, verdict, probability,
   *   factor, model and independence — the full prompt/output text already
   *   lives in the attest marker.
   * - Every other kind runs its whole affected set to decisive outcomes (the
   *   whole-batch regime — a contract's obligations need the evidence, and a
   *   bayesian planned skip could leave precisely the check the claim rests
   *   on unobserved). perf-budget additionally unions *every* benchmark
   *   check into the run set: a performance claim must produce fresh
   *   benchmark evidence whether or not impact analysis considers the
   *   harness affected. Obligations are then evaluated against the fresh
   *   records with the API surface diffed against the baseline, and a
   *   `proven` run carrying any unmet obligation is downgraded to `stale` —
   *   the engine never co-signs more than the obligations allow. When the
   *   chain holds active B/C attestations for the claim (κ), their factors
   *   multiply into the machine confidence (basis `attested`) — a factor can
   *   only discount the number, never rescue a grade the machine run did not
   *   earn.
   */
  async verifyContract(options: ContractVerifyOptions): Promise<ContractVerifyOutcome> {
    const { contract, ...rest } = options
    const specs = await this.loadChecks()
    const baseline = await this.store.loadBaseline()

    // -- docs-only: the jury path -------------------------------------------
    if (contract.kind === 'docs-only') {
      // `changed` is still resolved honestly (the jury's `docs-only-changes`
      // obligation judges the real change set), and `specs`/`baseline` are
      // handed to the evaluator as context — but no command ever runs.
      const attribution = await this.resolveChanges(rest, baseline)
      const changed = attribution.changed
      const verdict = evaluateContract(
        {
          contract,
          changed,
          specs,
          records: [],
          // ContractInput's context fields are required-but-nullable: an
          // explicit `undefined` is the honest "not available here". The jury
          // path judges neither regressions-from-records nor the API surface.
          baseline,
          apiSurfaceBefore: undefined,
          apiSurfaceAfter: undefined,
          graph: undefined,
        },
        this.options.juryConfidenceCap,
      )
      const confidence = verdict.juryCappedConfidence ?? this.options.juryConfidenceCap
      const report = assembleJuryReport({
        contract,
        obligations: verdict.obligations,
        confidence,
        workspace: await this.workspaceSnapshot(),
        clock: this.clock,
      })
      // docs-only never goes through check selection. The `selection` below is
      // a legal minimal placeholder that says exactly that: nothing affected,
      // everything untouched, no graph consulted — `precision: 'forced'`
      // names the regime, `forcedAll: false` records that no run was forced
      // (none happened at all).
      const selection: SelectionResult = {
        affected: [],
        untouched: [...specs],
        forcedAll: false,
        closure: [...changed],
        uncertain: false,
        precision: 'forced',
      }
      await this.store.mark('claim/jury', {
        claim: contract.claim,
        // 200-character review summary: enough to audit what the jury was
        // told, short enough to keep markers cheap.
        review: (contract.review ?? '').slice(0, 200),
        grade: report.grade,
        unmet: verdict.obligations.filter(o => !o.met).map(o => o.id),
      })
      await this.store.checkpoint()
      return {
        report,
        checks: [],
        selection,
        changed,
        attribution,
        contract: {
          kind: verdict.kind,
          obligations: verdict.obligations,
          juryConfidenceCap: confidence,
        },
      }
    }

    // -- llm-jury: B/C attestation decides, no commands (κ) ------------------
    //
    // Same skeleton as docs-only (skipChecks is true for llm-jury, so no
    // command ever runs), but the judge is the *chain*, not the author: the
    // active on-chain attestation(s) for this claim — highest gen wins, so an
    // appeal overrides its predecessor — supply the evidence, and the
    // confidence is the fused product of their class-weighted factors. The
    // machine factor is the neutral 1 (nothing ran), so the number is exactly
    // Π attestationFactor: a strong jury upholding at p=0.99 still pays
    // 0.99^0.7 ≈ 0.993, and certification needs that product to clear
    // `certifyTarget` on top of every obligation holding.
    if (contract.kind === 'llm-jury') {
      const claimId = claimIdOf(contract.claim)
      const active = attestationsFor(await this.activeAttestationsAll(), claimId)
      // `changed` is resolved honestly (context for the evaluator), and
      // `specs`/`baseline` are handed over — but no command ever runs.
      const attribution = await this.resolveChanges(rest, baseline)
      const changed = attribution.changed
      const verdict = evaluateContract(
        {
          contract,
          changed,
          specs,
          records: [],
          baseline,
          apiSurfaceBefore: undefined,
          apiSurfaceAfter: undefined,
          graph: undefined,
          ...(active.length > 0 ? { attestations: [...active] } : {}),
        },
        this.options.juryConfidenceCap,
      )
      const fused = this.attestationProduct(active)
      const unmet = verdict.obligations.filter(o => !o.met)
      const grade: GradedProofReport['grade'] =
        unmet.length === 0 && fused >= this.options.certifyTarget ? 'proven' : 'stale'
      // Basis: nothing machine-made speaks, so an active Class B witness makes
      // this jury-only; a human witness alone (or none at all) keeps the
      // jury-report default rather than claiming a machine factor it never had.
      const basis: ConfidenceBasis = active.length === 0 || active.some(a => a.kind === 'attest/jury')
        ? 'jury-only'
        : 'attested'
      const jury = assembleJuryReport({
        contract,
        obligations: verdict.obligations,
        confidence: fused,
        workspace: await this.workspaceSnapshot(),
        clock: this.clock,
      })
      // Engine-side overwrite (κ): the jury assembler's grade rule is "all
      // obligations met"; the fused regime additionally demands the certify
      // target, so the engine owns the final grade and basis here.
      const report: GradedProofReport = { ...jury, grade, confidenceBasis: basis }
      const selection: SelectionResult = {
        affected: [],
        untouched: [...specs],
        forcedAll: false,
        closure: [...changed],
        uncertain: false,
        precision: 'forced',
      }
      const winner = active[0]
      await this.store.mark('claim/jury', {
        claim: contract.claim,
        claimId,
        grade,
        unmet: unmet.map(o => o.id),
        // κ: attestation summary for the boundary marker — the full
        // prompt/output text already lives in the attest marker itself, so
        // this records only what the grade rode on.
        ...(winner === undefined
          ? { attestations: 0 }
          : winner.kind === 'attest/jury'
            ? {
                gen: winner.gen,
                verdict: winner.verdict,
                probability: winner.probability,
                factor: attestationFactor(winner, this.trustWeights),
                model: winner.model,
                independence: winner.independence,
              }
            : {
                gen: winner.gen,
                verdict: winner.decision,
                factor: attestationFactor(winner, this.trustWeights),
                approver: winner.approver,
              }),
      })
      await this.store.checkpoint()
      return {
        report,
        checks: [],
        selection,
        changed,
        attribution,
        contract: {
          kind: verdict.kind,
          obligations: verdict.obligations,
          ...(active.length > 0 ? { attestations: this.attestationSummary(active) } : {}),
        },
      }
    }

    // -- every other kind: the run, then the contract on top of it ---------
    const graph = await this.loadGraph()
    // π: same union as verify() — executed conjured tests join the pool as
    // ordinary specs, so a behavior-adding claim can cover its new paths
    // with them (the contract's new-paths-covered fallback consumes the
    // chain's latest synthetic evidence through `latestByCheckId` below).
    const pool = unionChecks(specs, await this.syntheticSpecs())
    const attribution = await this.resolveChanges(rest, baseline)
    const changed = attribution.changed
    const provenance = new Map<RelPath, ChangeProvenance>(
      attribution.records.map(r => [r.path, r.provenance] as [RelPath, ChangeProvenance]),
    )
    const degraded = resolutionDegraded(attribution) || await this.gitFactsUnavailable()
    const forceAll = rest.all === true || degraded
    const selection = forceAll
      ? forcedSelection(pool, changed)
      : selectAffectedChecks(pool, changed, graph)

    const runSpecs = contract.kind === 'perf-budget'
      ? unionChecks(selection.affected, pool.filter(s => s.kind === 'benchmark'))
      : selection.affected

    const snapshot = await this.workspaceSnapshot()
    // υ: same coverage staging as verify() — the machine legs of a contract
    // claim are ordinary checks and earn the same execution-coverage honesty.
    const coverageDir = await this.prepareCoverageDir()
    // Whole-batch over the (possibly benchmark-extended) run set, with the
    // same priors/confidence display the 'set' path uses — see method note.
    const priors = await this.priorsFor(runSpecs, changed, graph)
    const batch = await this.runner.run(runSpecs, {
      concurrency: this.options.concurrency,
      totalBudgetMs: this.options.verifyBudgetMs,
      workspace: snapshot,
      ...(coverageDir !== undefined ? { coverageDir } : {}),
      ...(rest.signal !== undefined ? { signal: rest.signal } : {}),
      ...(rest.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => rest.onProgress!(ev.label, i, total) }
        : {}),
    })
    // υ: collect + re-address before the first append — see verify().
    const collected = await this.collectRunCoverage(batch.records, changed, coverageDir)
    for (const record of collected.records) await this.store.append(record)
    const confidence = this.updateFactors(priors, batch.records, runSpecs.length > 0)

    const { report: machineReport, checks } = assembleProof({
      specs: pool,
      baseline,
      records: collected.records,
      changed,
      ...(graph !== undefined ? { graph } : {}),
      ...(provenance.size > 0 ? { provenance } : {}),
      workspace: snapshot,
      clock: this.clock,
      requireFullCoverage: true,
      ...(forceAll ? { forceAll: true } : {}),
      ...(confidence !== undefined ? { confidence } : {}),
    })

    // υ: execution-coverage gating — pinned order: after the machine grade,
    // BEFORE the obligations cap and the κ attestation fusion. Coverage is a
    // machine-evidence dimension, so it is judged with the machine verdict,
    // not after the human/jury witnesses have spoken; and the placement is
    // load-bearing for the fusion semantics below — a claim coverage knocked
    // down to `unproven` can no longer be endorsement-unlocked, because the
    // unlock condition demands grade `stale` (residual risk the human can
    // accept). "The change never executed" is not residual risk; it is missing
    // work, and exactly like an unmet obligation, endorsement cannot pay for
    // work. The two locks agree by construction.
    let graded = this.gateByCoverage(machineReport, collected.summary)

    // The contract is judged against the freshest facts: this run's records,
    // the surface as the workspace has it NOW, and the surface as the
    // baseline remembers it (absent on pre-ζ baselines — the evaluator
    // decides what that missing honesty costs the obligation). ContractInput's
    // context fields are required-but-nullable, so both sides are handed over
    // explicitly, `undefined` included.
    //
    // π: `latestByCheckId` additionally hands the evaluator the chain's
    // latest evidence per check — the synthetic fallback for new-paths-
    // covered rests on it, because a conjured test's own execution record
    // (proof_conjure_run) lives on the chain, not necessarily in this run's
    // batch.
    const apiSurfaceAfter = await this.computeApiSurface()
    const apiSurfaceBefore = (baseline as EngineBaseline | undefined)?.apiSurface
    const verdict = evaluateContract(
      {
        contract,
        changed,
        specs: pool,
        records: collected.records,
        latestByCheckId: await this.store.latest(),
        baseline,
        apiSurfaceBefore: apiSurfaceBefore === undefined ? undefined : [...apiSurfaceBefore],
        apiSurfaceAfter: apiSurfaceAfter === undefined ? undefined : [...apiSurfaceAfter],
        graph,
      },
      this.options.juryConfidenceCap,
    )
    const unmet = verdict.obligations.filter(o => !o.met)
    // A proven run is still only as proven as its obligations allow: any unmet
    // one caps the grade at `stale`. Confidence and basis keep what the run
    // earned (the number says what was measured, the obligations say what is
    // missing); grades already worse than `proven` keep their more honest
    // verdict untouched.
    if (graded.grade === 'proven' && unmet.length > 0) {
      graded = { ...graded, grade: 'stale' as const }
    }

    // κ: attestation fusion for machine kinds. The machine grade and
    // confidence are already on the table; active B/C witnesses for this
    // claim now speak about the WHOLE claim, so they enter as the reliability
    // mixture (`fuseConfidence`), not as product factors: a jury asserting a
    // high probability can carry a certification across the target gap, a
    // rejecting witness crashes the number, and a human endorsement leaves
    // the number untouched — its power is risk acceptance, applied to the
    // GRADE below, because an approval seam transfers responsibility, not
    // certainty (its asserted constant can never outrun a 0.97 target).
    // Grades the machine run did not earn regressions for stay exactly what
    // they were: no witness unlocks a regressed claim. Plain `verify()` never
    // consults attestations at all (v0.9 semantics locked).
    const claimActive = attestationsFor(await this.activeAttestationsAll(), claimIdOf(contract.claim))
    if (claimActive.length > 0 && graded.confidence !== undefined) {
      let fused = graded.confidence
      for (const att of claimActive) fused = fuseConfidence(fused, att, this.trustWeights)
      const machineDecisive = batch.records.some(r => isDecisiveStatus(r.status))
      const endorsed = claimActive.some(a => a.kind === 'attest/human' && a.decision === 'endorse')
      // Risk acceptance unlocks ONLY the target gap: every obligation met,
      // nothing regressed, nothing newly failing — the machine said "0.94 and
      // I cannot cross 0.97", and the human took the residual. An unmet
      // obligation or a regression is not residual risk; it is missing work,
      // and endorsement cannot pay for work.
      const endorsementUnlock = endorsed
        && graded.grade === 'stale'
        && unmet.length === 0
        && graded.summary.regressions === 0
        && !checks.some(c => c.verdict === 'new-failure')
      graded = {
        ...graded,
        confidence: fused,
        grade: endorsementUnlock ? 'proven' as const : graded.grade,
        confidenceBasis: ProofEngine.fusedBasis(machineDecisive, claimActive),
      }
      // The symmetric lock: an explicit negative verdict (a human 'reject', a
      // jury 'reject') does not merely dent the number — a claim a sworn
      // witness denies cannot keep a grade the number no longer supports.
      // Endorsement is excluded from the trigger: it never moved the number,
      // so it cannot demote on its own.
      const denied = claimActive.some(a =>
        a.kind === 'attest/human' ? a.decision === 'reject' : a.verdict === 'reject')
      if (denied && graded.grade === 'proven' && fused < this.options.certifyTarget) {
        graded = { ...graded, grade: 'stale' as const }
      }
    }

    await this.store.mark('proof/verified', {
      grade: graded.grade,
      root: graded.root,
      changed: changed.length,
      attribution: attribution.method,
      preExistingExcluded: attribution.preExistingExcluded.length,
      regressions: graded.summary.regressions,
      // ζ: the contract summary rides the boundary marker — kind, the
      // unmet obligation ids, and whether the verdict was jury-capped.
      contract: {
        kind: verdict.kind,
        unmet: unmet.map(o => o.id),
        jury: verdict.skipChecks,
        // κ: which witnesses were fused in, when any were.
        ...(claimActive.length > 0 ? { attestations: this.attestationSummary(claimActive) } : {}),
      },
      // υ: what the coverage dimension said at this boundary.
      ...(collected.summary !== undefined
        ? { coverage: this.coverageMarkerPayload(collected.summary) }
        : {}),
    })
    await this.store.checkpoint()
    return {
      report: graded,
      checks,
      selection,
      changed,
      attribution,
      ...(degraded ? { degraded: true as const } : {}),
      ...(collected.summary !== undefined
        ? {
            coverage: {
              basis: collected.summary.basis,
              uncovered: [...collected.summary.changedUncovered],
              executedCount: collected.summary.changedExecuted.length,
            },
          }
        : {}),
      contract: {
        kind: verdict.kind,
        obligations: verdict.obligations,
        ...(verdict.juryCappedConfidence !== undefined
          ? { juryConfidenceCap: verdict.juryCappedConfidence }
          : {}),
        // κ: the fused-in witnesses, for hosts surfacing who vouched.
        ...(claimActive.length > 0 ? { attestations: this.attestationSummary(claimActive) } : {}),
      },
    }
  }

  // -- PTC synthesis (π) ------------------------------------------------------

  /**
   * π: open a conjure request — the request/execution protocol's first half.
   *
   * The claim's identity (claimId) and its covered paths are committed to
   * the chain BEFORE any script exists: `synthetic/requested` carries the
   * full request plus `scriptDigest: null`, because at request time there is
   * nothing to digest yet. Locking the request first is what makes the
   * later "request–execution swap" detectable: `conjureRun` digests
   * whatever is on disk at execution time, so a script substituted between
   * the two calls runs under its OWN digest, visibly.
   *
   * The scaffold template is written next to where the real entry will go
   * (`<entry>.template.mjs` — the suffix keeps the scaffold itself out of
   * any accidental execution), and the returned instruction tells the model
   * exactly what to do with it.
   */
  async conjureRequest(input: { claim: string; paths: readonly string[] }): Promise<{ request: SyntheticRequest; template: string; instruction: string }> {
    const claimId = claimIdOf(input.claim)
    // seq = requests already on the chain for THIS claim: re-conjuring the
    // same claim mints a fresh entry (t0, t1, …) instead of overwriting the
    // previous test's history.
    const seq = (await this.markersWith('synthetic/requested')).filter(p => p.claimId === claimId).length
    const entry = sandboxEntryFor(claimId, seq)
    const request: SyntheticRequest = {
      claimId,
      claim: input.claim,
      paths: [...input.paths],
      entry,
      // Epoch millis from the engine's clock — the module owns no clock by
      // design, and the request's timestamp must be as reproducible (and as
      // chain-addressable) as every other byte of the marker.
      requestedAt: this.clock.now(),
    }
    const entryDir = dirnameRel(entry)
    await this.fs.mkdirp(entryDir.length === 0 ? this.syntheticRoot() : `${this.syntheticRoot()}/${entryDir}`)
    await this.fs.writeFile(`${this.syntheticRoot()}/${entry}.template.mjs`, SYNTHETIC_TEMPLATE)
    await this.store.mark('synthetic/requested', { ...request, scriptDigest: null })
    const instruction = [
      `Conjured-test sandbox ready for the claim "${input.claim}" (covers: ${request.paths.join(', ') || 'no paths'}).`,
      `1. Copy ${this.options.syntheticDir}/${entry}.template.mjs to ${this.options.syntheticDir}/${entry}.`,
      '2. Replace the placeholder assertion with a real executable test of the claim: exit code 0 proves it, anything else fails it.',
      `3. Read and write files only inside ${this.options.syntheticDir}/ — a script importing ${FORBIDDEN_CAPABILITIES.join(', ')} is refused at screening and never runs.`,
      `4. Call proof_conjure_run with this exact claim text and entry ${entry}: the verifier screens and executes the script itself and records the evidence.`,
    ].join('\n')
    return { request, template: SYNTHETIC_TEMPLATE, instruction }
  }

  /**
   * π: execute one conjured script — the request/execution protocol's second
   * half.
   *
   * Order of defenses: (1) a matching `synthetic/requested` marker must
   * already be on the chain — execution without a recorded request is
   * exactly the "test conjured out of thin air after the fact" move this
   * protocol exists to prevent (and it double-serves as path validation:
   * only entries the engine itself minted can match); (2) the script must
   * exist on disk; (3) `screenScript` must pass — a refusal returns the
   * findings WITHOUT executing and WITHOUT writing anything to the chain
   * (the rejection travels in the tool result; a refused test is not
   * evidence of anything except its own refusal).
   *
   * The execution itself goes through the plugin's own CommandPort via the
   * VerificationRunner — the agent cannot forge the result, it can only
   * influence the test's truth value (write a stronger or weaker assertion),
   * and that is precisely what the synthetic β prices. The runner's plain
   * record is then re-addressed with the synthetic metadata (scriptDigest,
   * sandbox regime, screening findings, authorship): the metadata
   * participates in content addressing, so the same output from two
   * different scripts is two different pieces of evidence.
   */
  async conjureRun(input: { claim: string; entry: string }): Promise<ConjureRunResult> {
    const claimId = claimIdOf(input.claim)
    const payload = (await this.markersWith('synthetic/requested'))
      .find(p => p.claimId === claimId && p.entry === input.entry)
    const request = payload === undefined ? undefined : syntheticRequestOf(payload)
    if (request === undefined) {
      throw new Error(`conjureRun: no synthetic/requested marker for claimId ${claimId} with entry ${input.entry} — call proof_conjure_request first`)
    }
    const spec = syntheticSpec(request, this.options.syntheticDir, this.options.syntheticTimeoutMs)
    const source = await this.fs.readFile(`${this.syntheticRoot()}/${input.entry}`)
    if (source === undefined) {
      throw new Error(`conjureRun: no script at ${this.options.syntheticDir}/${input.entry} — copy the scaffold ${input.entry}.template.mjs and fill in the assertion first`)
    }
    // The digest is computed from the file AS IT IS NOW: the request locked
    // claimId/entry/paths with a null digest precisely so a script swapped
    // between request and run cannot hide — whatever runs is what is hashed.
    const scriptDigest = sha256(source)
    const screening = screenScript(source)
    if (!screening.ok) {
      return {
        checkId: spec.id,
        status: 'skipped',
        scriptDigest,
        screened: [...screening.findings],
        sandbox: 'screened-subprocess',
        outputHead: `screening refused: ${screening.findings.join('; ')}`,
      }
    }
    // One spec, one run, no caller signal: the cooperative timeout on the
    // spec (syntheticTimeoutMs) is the only budget.
    const snapshot = await this.workspaceSnapshot()
    const batch = await this.runner.run([spec], { workspace: snapshot })
    const record = batch.records[0]
    if (record === undefined) throw new Error('conjureRun: the verification runner produced no record')
    const meta: SyntheticEvidenceMeta = {
      scriptDigest,
      // The host's ptc-runtime seam (executing inside a sandboxed PTC
      // runtime instead of a screened subprocess) is deliberately not wired
      // in this version: no host adapter reports it yet, and a regime label
      // must be an observation, not an aspiration. Probe point for the host
      // adaptation layer — until then the honest value is what actually
      // happened: a screened subprocess.
      sandbox: 'screened-subprocess',
      screened: [...screening.findings],
      author: 'agent',
    }
    // Re-address the runner's record over its synthetic metadata (the runner
    // cannot know the digest): same body, same canonicalisation, one extra
    // field — audit recomputes exactly this address from the stored record.
    const { evidenceId: plainAddress, ...body } = record
    void plainAddress
    const evidence: Evidence = { ...body, synthetic: meta, evidenceId: addressOf({ ...body, synthetic: meta }) }
    await this.store.append(evidence)
    await this.store.mark('synthetic/run', {
      claimId,
      entry: input.entry,
      checkId: evidence.checkId,
      scriptDigest,
      screened: [...screening.findings],
      sandbox: meta.sandbox,
      status: evidence.status,
      exitCode: evidence.exitCode,
    })
    return {
      checkId: evidence.checkId,
      status: evidence.status,
      scriptDigest,
      screened: [...screening.findings],
      sandbox: meta.sandbox,
      outputHead: evidence.outputHead,
    }
  }

  /** π: `<root>/<syntheticDir>` — where every conjured sandbox lives. */
  private syntheticRoot(): string {
    return `${this.root.replace(/[\/]+$/, '')}/${this.options.syntheticDir.replace(/^\/+/, '').replace(/[\/]+$/, '')}`
  }

  /**
   * π: every marker payload on the chain under one label, in log order. The
   * store exposes no marker read-back, so — exactly like the attestation
   * pass (κ) — the raw log lines are parsed here through the same fs port.
   * Any read failure degrades to "no markers" rather than failing the caller.
   */
  private async markersWith(label: string): Promise<Record<string, unknown>[]> {
    try {
      const out: Record<string, unknown>[] = []
      for (const line of await this.fs.readLines(this.logPath)) {
        let envelope: { kind?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(line) as { kind?: unknown; payload?: unknown }
        } catch {
          continue
        }
        if (envelope?.kind !== 'marker') continue
        const payload = envelope.payload as { label?: unknown } | undefined
        if (payload?.label === label) out.push(payload as Record<string, unknown>)
      }
      return out
    } catch {
      return []
    }
  }

  /**
   * π: the synthetic specs currently on the chain — every conjured test that
   * has actually been executed at least once (a request without a run is an
   * offer, not a check; verify must not silently execute an unexecuted
   * offer). They join verification as ordinary specs (P5): selection matches
   * their paths, the runner re-executes their sandbox entry like any other
   * check, and computePriors prices their history with the raised synthetic
   * β — the false-pass risk of a test written by the claim's own author.
   */
  private async syntheticSpecs(): Promise<CheckSpec[]> {
    const requested = await this.markersWith('synthetic/requested')
    if (requested.length === 0) return []
    const ran = new Set(
      (await this.markersWith('synthetic/run')).map(p => `${String(p.claimId)}\0${String(p.entry)}`),
    )
    const out: CheckSpec[] = []
    for (const payload of requested) {
      const request = syntheticRequestOf(payload)
      if (request === undefined) continue
      if (!ran.has(`${request.claimId}\0${request.entry}`)) continue
      out.push(syntheticSpec(request, this.options.syntheticDir, this.options.syntheticTimeoutMs))
    }
    return out
  }

  // -- execution coverage (υ) ----------------------------------------------------

  /**
   * υ: create this run's coverage scratch directory — `${storeDir}/coverage/<clock
   * nonce>` — or `undefined` when the mode injects nothing (`off`). The nonce
   * only keeps concurrent/sequential runs from sharing subdirectories; it is
   * physical staging and deliberately never enters any hash material, so run
   * identity stays a function of the evidence alone. An mkdirp failure is
   * swallowed: the children then fail to write their profiles, collection
   * finds no data, and observe mode degrades to basis `'none'` — the honest
   * answer, not a crashed verification.
   */
  private async prepareCoverageDir(): Promise<string | undefined> {
    if (this.options.coverage === 'off') return undefined
    const dir = `${this.storeDir}/coverage/${this.clock.now()}`
    try {
      await this.fs.mkdirp(dir)
    } catch {
      /* unwritable staging → no coverage data this run */
    }
    return dir
  }

  /**
   * υ: read one verification run's V8 profiles back, re-address the records
   * they speak for, and hand the caller both — collection order:
   *
   *   1. per decisively-passing record, read its spec's subdirectory (the
   *      runner names it `sha256(checkId).slice(0,16)`, re-derived here from
   *      the record's own checkId — no spec pool needed);
   *   2. parse every `coverage-*.json` and union the workspace-relative
   *      executed files into ONE set per record — `summarizeCoverage`'s
   *      executedSets unit is "what this check executed", not "what this one
   *      profile happened to contain";
   *   3. attach the per-record coverage view (changed ∩ executed / changed −
   *      executed) by RE-ADDRESSING the record — π's synthetic precedent: the
   *      attachment is content-addressing material, so the enriched record is
   *      a different piece of evidence from the plain one and audit must be
   *      able to recompute exactly this address from the stored bytes;
   *   4. remove the scratch tree (best effort — `removeDir` is an optional
   *      FsPort capability; a MemoryFs without it is fine, `?.` and on we go);
   *   5. summarise the whole change set against the collected executed sets.
   *
   * The empty-set subtlety in step 2 is the blind-spot detector: a check that
   * produced real coverage data naming NO workspace file still contributes a
   * (possibly empty) executed set — data existed and said "the change was
   * never executed". Only a record with NO parseable profile at all (fake
   * command ports, non-Node processes) contributes nothing, which is what
   * keeps the gate's `basis: 'none'` branch honest.
   */
  private async collectRunCoverage(
    records: readonly Evidence[],
    changed: readonly RelPath[],
    coverageDir: string | undefined,
  ): Promise<{ records: Evidence[]; summary: CoverageSummary | undefined }> {
    if (coverageDir === undefined) return { records: [...records], summary: undefined }
    const executedSets: string[][] = []
    const out: Evidence[] = []
    for (const record of records) {
      // Only a decisively passing check speaks for execution coverage: a fail
      // already sank the grade on its own, and non-decisive outcomes may have
      // died before V8 flushed any profile — half-execution proves nothing.
      if (record.status !== 'pass') {
        out.push(record)
        continue
      }
      const dir = `${coverageDir}/${sha256(record.checkId).slice(0, 16)}`
      const executed = new Set<string>()
      let dataFound = false
      for (const name of (await this.fs.readDir(dir)) ?? []) {
        if (!/^coverage-.*\.json$/.test(name)) continue
        const content = await this.fs.readFile(`${dir}/${name}`)
        if (content === undefined) continue
        try {
          const parsed = parseV8CoverageReport(content, this.root)
          if (parsed === undefined) continue
          dataFound = true
          for (const file of parsed.executed) executed.add(file)
        } catch {
          /* one unparseable profile is not the run's verdict */
        }
      }
      if (!dataFound) {
        out.push(record)
        continue
      }
      executedSets.push([...executed].sort())
      out.push(changed.length > 0
        ? attachEvidenceCoverage(record, {
            changedExecuted: changed.filter(f => executed.has(f)),
            changedUncovered: changed.filter(f => !executed.has(f)),
          })
        : record)
    }
    // Staging is disposable by contract: collected, then removed. A failure
    // here costs nothing — the next run re-creates the tree. `removeDir` is an
    // optional FsPort capability; a MemoryFs without it is fine, `?.` and on.
    await this.fs.removeDir?.(coverageDir).catch(() => { /* staging; nothing to salvage */ })
    const summary = summarizeCoverage({ changed: [...changed], executedSets })
    return { records: out, summary }
  }

  /**
   * υ: gate one machine report by its coverage summary. `undefined` summary
   * (mode `off`) returns the report untouched; otherwise `coverageGate` +
   * `applyCoverageGate` decide the grade and mount the summary — always, even
   * at basis `'none'` and even when the gate does not block: a proof that
   * carries its coverage blind spot visibly is the entire point of observe
   * mode.
   */
  private gateByCoverage(report: GradedProofReport, summary: CoverageSummary | undefined): GradedProofReport {
    if (summary === undefined) return report
    return applyCoverageGate(report, coverageGate(summary, this.options.coverage), summary)
  }

  /** υ: the coverage dimension's one-line footprint for boundary markers. */
  private coverageMarkerPayload(summary: CoverageSummary): Record<string, unknown> {
    return {
      mode: this.options.coverage,
      basis: summary.basis,
      executed: summary.changedExecuted.length,
      uncovered: summary.changedUncovered.length,
    }
  }

  // -- graded evidence (κ) ----------------------------------------------------

  /**
   * Every *active* attestation on the chain: marker payloads under the
   * 'attest/jury' / 'attest/human' labels, deduplicated per claimId by
   * highest gen (an appeal overrides its predecessor), deterministically
   * ordered. The store exposes no marker read-back, so the raw log lines are
   * parsed here through the same fs port — the least invasive route that
   * leaves `EvidenceStore`'s public surface untouched. Any read or parse
   * failure degrades to "no witnesses" rather than failing verification.
   */
  private async activeAttestationsAll(): Promise<Attestation[]> {
    try {
      const payloads: unknown[] = []
      for (const line of await this.fs.readLines(this.logPath)) {
        let envelope: { kind?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(line) as { kind?: unknown; payload?: unknown }
        } catch {
          continue
        }
        if (envelope?.kind !== 'marker') continue
        const payload = envelope.payload as { label?: unknown } | undefined
        if (payload?.label === 'attest/jury' || payload?.label === 'attest/human') payloads.push(payload)
      }
      return activeAttestations(payloads)
    } catch {
      // An unreadable log cannot veto verification — it simply has no
      // witnesses to fuse. (The log's own integrity is `audit()`'s charge.)
      return []
    }
  }

  /** κ: Π attestationFactor over the active witnesses — the neutral 1 when empty. */
  private attestationProduct(active: readonly Attestation[]): number {
    let product = 1
    for (const att of active) product *= attestationFactor(att, this.trustWeights)
    return product
  }

  /**
   * κ: one-line summary per active witness, for `ContractSummary.attestations`
   * and the boundary markers. Class, generation, verdict and the exact factor
   * the fusion paid — everything a host needs to show who vouched, and how
   * hard, without re-reading the full attest payloads.
   */
  private attestationSummary(active: readonly Attestation[]): NonNullable<ContractSummary['attestations']> {
    return active.map(att => ({
      class: att.kind === 'attest/jury' ? 'B' as const : 'C' as const,
      gen: att.gen,
      verdict: att.kind === 'attest/jury' ? att.verdict : att.decision,
      factor: attestationFactor(att, this.trustWeights),
    }))
  }

  /**
   * κ: which regime a fused number was earned under. No machine-decisive
   * record with a Class B witness active is `jury-only` (the verdict is the
   * jury's, machines never spoke); every other fusion — machine evidence plus
   * any witness, or a lone Class C witness — is `attested`.
   */
  private static fusedBasis(hasMachineDecisive: boolean, active: readonly Attestation[]): ConfidenceBasis {
    if (!hasMachineDecisive && active.some(a => a.kind === 'attest/jury')) return 'jury-only'
    return 'attested'
  }

  // -- API surface (ζ) ------------------------------------------------------

  /**
   * The workspace's exported-API fingerprint: `file#export` lines over every
   * module reachable from the package entry points along import edges — the
   * first honest approximation of "what this package exports" (the entry
   * itself plus the internal modules its public surface stands on).
   *
   * `undefined` is the honest answer when no entry point resolves: the rule
   * is *rather no surface than a wrong one* — a mis-derived surface would
   * make every later `api-surface-unchanged` judgment wrong in both
   * directions. Reachability is a bounded BFS over import sites extracted
   * from file contents (depth ≤ 10, files ≤ 500); when the bounds truncate
   * the closure, the truncation is recorded on the chain, because a snapshot
   * that silently stops halfway is a wrong surface with extra steps.
   */
  private async computeApiSurface(): Promise<readonly string[] | undefined> {
    try {
      const entries = await this.resolveEntryPoints()
      if (entries.length === 0) return undefined
      const reachable = new Set<string>()
      let frontier = [...entries].sort()
      let depth = 0
      let truncated = false
      while (frontier.length > 0 && !truncated) {
        if (depth >= API_SURFACE_MAX_DEPTH) { truncated = true; break }
        const next: string[] = []
        for (const rel of frontier) {
          if (reachable.size >= API_SURFACE_MAX_FILES) { truncated = true; break }
          if (reachable.has(rel)) continue
          const content = await this.fs.readFile(`${this.root}/${rel}`)
          if (content === undefined) continue
          reachable.add(rel)
          for (const site of extractImportSites(content)) {
            if (site.kind !== 'relative') continue
            const resolved = await this.resolveModuleSpecifier(rel, site.specifier)
            if (resolved !== undefined && !reachable.has(resolved)) next.push(resolved)
          }
        }
        frontier = [...new Set(next)].sort()
        depth += 1
      }
      if (reachable.size === 0) return undefined
      const surfaceEntries: SurfaceEntry[] = []
      for (const rel of [...reachable].sort()) {
        const content = await this.fs.readFile(`${this.root}/${rel}`)
        if (content !== undefined) surfaceEntries.push({ rel, content })
      }
      if (truncated) {
        await this.store.mark('api-surface/truncated', {
          files: reachable.size,
          limit: API_SURFACE_MAX_FILES,
          depth: API_SURFACE_MAX_DEPTH,
        })
      }
      return extractApiSurface(surfaceEntries)
    } catch {
      // Surface derivation is an attachment, never a load-bearing leg: any
      // failure means "no surface this time", not a broken baseline/verify.
      return undefined
    }
  }

  /**
   * Entry points for the surface. Explicit `apiEntryPoints` config wins (used
   * as-is, filtered to files that actually exist); otherwise the entries
   * declared in `package.json` — `main`, then `exports["."]` (a string, or
   * the object's `types`/`default`/`import`/`require` conditions), then
   * `types`/`typings` — are each resolved by existence probing (see
   * `entryCandidates`). All declarations failing to resolve means no entries,
   * which means no surface — see `computeApiSurface` for why that is the
   * right failure.
   */
  private async resolveEntryPoints(): Promise<string[]> {
    const exists = async (rel: string): Promise<boolean> =>
      await this.fs.readFile(`${this.root}/${rel}`) !== undefined
    if (this.options.apiEntryPoints.length > 0) {
      const out: string[] = []
      for (const entry of this.options.apiEntryPoints) {
        const rel = normalizeRel(entry)
        if (rel.length > 0 && !out.includes(rel) && await exists(rel)) out.push(rel)
      }
      return out
    }
    const raw = await this.fs.readFile(`${this.root}/package.json`)
    if (raw === undefined) return []
    let pkg: Record<string, unknown>
    try {
      pkg = JSON.parse(raw) as Record<string, unknown>
    } catch {
      return []
    }
    const declared: string[] = []
    const add = (value: unknown): void => {
      if (typeof value === 'string' && value.length > 0) declared.push(value)
    }
    add(pkg.main)
    const dot = (pkg.exports as Record<string, unknown> | undefined)?.['.']
    if (typeof dot === 'string') add(dot)
    else if (dot !== null && typeof dot === 'object') {
      const conditions = dot as Record<string, unknown>
      add(conditions.types)
      add(conditions.default)
      add(conditions.import)
      add(conditions.require)
    }
    add(pkg.types)
    add(pkg.typings)
    const out: string[] = []
    for (const value of declared) {
      for (const candidate of entryCandidates(value)) {
        if (await exists(candidate)) { out.push(candidate); break }
      }
    }
    return [...new Set(out)]
  }

  /** Resolve one relative import against its importer, existence-backed. */
  private async resolveModuleSpecifier(from: string, specifier: string): Promise<string | undefined> {
    const joined = normalizeRel(`${dirnameRel(from)}/${specifier}`)
    if (joined.length === 0) return undefined
    const candidates = [
      joined,
      `${joined}.ts`, `${joined}.tsx`, `${joined}.js`, `${joined}.jsx`, `${joined}.mjs`, `${joined}.cjs`,
      `${joined}/index.ts`, `${joined}/index.tsx`, `${joined}/index.js`,
    ]
    for (const candidate of candidates) {
      if (await this.fs.readFile(`${this.root}/${candidate}`) !== undefined) return candidate
    }
    return undefined
  }

  /**
   * β: the bayesian wave plan. Ranks the not-yet-run checks by expected
   * information gain per unit cost, dispatches a wave of `concurrency` of
   * them, folds each decisive outcome into the running claim model, and stops
   * the moment one of three things happens, checked in this order:
   *
   *   (a) the claim posterior crosses `certifyTarget` — certified, the rest
   *       of the plan becomes a planned skip resting on its prior;
   *   (b) a decisive failure lands — the assertion is dead, attribution
   *       evidence is already sufficient, remaining checks cannot rescue it;
   *   (c) the budget drains or the caller aborts.
   *
   * Non-decisive outcomes (timeout/aborted/error/skipped) never update a
   * factor: the check keeps its prior and stays counted as undecided.
   */
  private async runBayesianSchedule(
    affected: readonly CheckSpec[],
    changed: readonly RelPath[],
    graph: DependencyGraph | undefined,
    snapshot: WorkspaceSnapshot,
    options: VerifyOptions,
    coverageDir?: string,
  ): Promise<{ records: Evidence[]; schedule: NonNullable<VerifyOutcome['schedule']>; confidence: ConfidenceInput }> {
    const priors = await this.priorsFor(affected, changed, graph)
    const target = this.options.certifyTarget
    const specById = new Map(affected.map(c => [c.id, c] as const))
    const factors = new Map<string, number>()
    for (const prior of priors.values()) factors.set(prior.checkId, prior.priorHealthy)
    const model: ClaimModel = { factors }
    const pending = new Map<string, CheckPrior>(priors)

    const records: Evidence[] = []
    const runCheckIds = new Set<string>()
    const started = this.clock.now()
    // Behind a call on purpose: `signal.aborted` is live state that flips while
    // a wave is awaited, and TS would otherwise keep the loop-top narrowing
    // ("not aborted") across the await and flag the post-wave re-read as
    // unreachable.
    const signalAborted = (): boolean => options.signal?.aborted === true
    let waves = 0
    let settled = 0
    let stoppedEarly: 'certified' | 'failed' | 'budget' | null = null

    while (pending.size > 0) {
      // (c) pre-wave: a plan that cannot afford its next wave must not start it.
      if (signalAborted() || this.clock.now() - started >= this.options.verifyBudgetMs) {
        stoppedEarly = 'budget'
        break
      }
      const ordered = rankByInformationGain(pending, model)
      const wave = ordered.slice(0, Math.max(1, Math.min(this.options.concurrency, pending.size)))
      const waveSpecs = wave
        .map(step => specById.get(step.checkId))
        .filter((c): c is CheckSpec => c !== undefined)
      const remainingBudgetMs = Math.max(0, this.options.verifyBudgetMs - (this.clock.now() - started))
      const batch = await this.runner.run(waveSpecs, {
        concurrency: this.options.concurrency,
        totalBudgetMs: remainingBudgetMs,
        workspace: snapshot,
        ...(coverageDir !== undefined ? { coverageDir } : {}),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        ...(options.onProgress !== undefined
          ? { onEvidence: (ev, index) => options.onProgress!(ev.label, settled + index, affected.length) }
          : {}),
      })
      waves += 1

      let decisiveFail = false
      for (const record of batch.records) {
        // υ: no per-wave append anymore — the caller collects coverage and
        // re-addresses every record BEFORE the first append (the attachment
        // changes the evidence address, so the chain must never hold the
        // plain record and its enriched twin). Nothing is lost by deferring:
        // the wave loop reads no log state after this point, the priors were
        // snapshotted before wave one, and a store failure mid-plan throws
        // out of the deferred append exactly as it threw out of this one.
        records.push(record)
        runCheckIds.add(record.checkId)
        pending.delete(record.checkId)
        const prior = priors.get(record.checkId)
        if (prior === undefined) continue
        if (record.status === 'pass' || record.status === 'fail') {
          factors.set(record.checkId, posteriorHealthy(prior, record.status))
          if (record.status === 'fail') decisiveFail = true
        }
        // every other status: the factor keeps its prior — undecided, not
        // acquitted and not condemned.
      }
      settled += batch.records.length

      // Early stops, in the design's priority order: certify, then blame,
      // then resources.
      if (claimProbability(model) >= target) {
        stoppedEarly = 'certified'
        break
      }
      if (decisiveFail) {
        stoppedEarly = 'failed'
        break
      }
      if (batch.aborted || signalAborted() || this.clock.now() - started >= this.options.verifyBudgetMs) {
        stoppedEarly = 'budget'
        break
      }
    }

    const skippedByPlan = [...pending.keys()].sort().map(checkId => ({
      checkId,
      priorHealthy: priors.get(checkId)?.priorHealthy ?? 0,
    }))
    return {
      records,
      schedule: { mode: 'bayesian' as const, waves, stoppedEarly, skippedByPlan },
      confidence: { target, factors, runCheckIds, skippedByPlan },
    }
  }

  /**
   * Priors over one affected set: history summarised from the whole evidence
   * log, priced with a quarter of the per-check timeout as the fallback cost
   * of a check that has never been observed.
   */
  private async priorsFor(
    affected: readonly CheckSpec[],
    changed: readonly RelPath[],
    graph: DependencyGraph | undefined,
  ): Promise<Map<string, CheckPrior>> {
    const history = summarizeHistory(await this.store.all())
    return computePriors({
      specs: affected,
      changed,
      // Required-but-nullable in PriorInput: `undefined` degrades impact
      // strength to path matching alone, exactly the no-graph semantics.
      graph,
      history,
      fallbackCostMs: this.options.checkTimeoutMs / 4,
      // π: the raised false-pass rate for agent-authored checks — computePriors
      // applies it to source 'synthetic' specs only; organic checks keep the
      // fixed organic β.
      syntheticFalsePass: this.options.syntheticFalsePass,
    })
  }

  /**
   * Fold one whole batch's outcomes into the factor map (display path): each
   * decisive outcome earns its posterior, everything else keeps its prior.
   */
  private updateFactors(priors: Map<string, CheckPrior>, records: readonly Evidence[], hasFactors: boolean): ConfidenceInput | undefined {
    if (!hasFactors) return undefined
    const factors = new Map<string, number>()
    const runCheckIds = new Set<string>()
    for (const prior of priors.values()) factors.set(prior.checkId, prior.priorHealthy)
    for (const record of records) {
      runCheckIds.add(record.checkId)
      const prior = priors.get(record.checkId)
      if (prior === undefined) continue
      if (record.status === 'pass' || record.status === 'fail') {
        factors.set(record.checkId, posteriorHealthy(prior, record.status))
      }
    }
    return { target: this.options.certifyTarget, factors, runCheckIds, skippedByPlan: [] }
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
