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
  Baseline, ChangeProvenance, ChangeSetResolution, CheckSpec, CheckStatus, CheckVerdict, Clock,
  CommandPort, DefinitionResolverPort, DependencyGraph, Evidence, FsPort, ProofGrade, RelPath,
  SelectionResult, SignerPort, WorkspacePort, WorkspaceSnapshot,
} from './core/index.ts'
import {
  DEFAULT_IGNORE_DIRS, EvidenceStore, VerificationRunner, addressOf, assembleBaseline,
  assembleProof, buildDependencyGraph, canonicalJson, discoverChecks, isDecisiveStatus,
  parseAnchor, resolveChangeSet, selectAffectedChecks, sha256, snapshotWorkspace,
  claimProbability, computePriors, posteriorHealthy, rankByInformationGain,
  summarizeHistory, verdictOf, walkChain,
} from './core/index.ts'
import { checkpointSignedData } from './core/trust.ts'
import type {
  CheckPrior, ClaimModel, ConfidenceBasis, ConfidenceInput, GradedProofReport,
} from './core/index.ts'
// H-03: the drifted-body β default rides the engine's option the same way
// `syntheticFalsePass` does, consumed straight from its module — the core
// barrel is not this batch's to edit, and a direct import keeps the one
// number one number.
import { DRIFTED_FALSE_PASS_DEFAULT } from './core/bayes.ts'
// core/index.ts re-exports the stable surface; `forcedSelection` is consumed
// here straight from its module (the core barrel is not this batch's to edit).
import { forcedSelection, extractImportSites } from './core/impact.ts'
import type { AuditReport } from './core/evidence.ts'
import { isSuspectMarker } from './core/evidence.ts'
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
// v0.18: the transparency-log domain (PTL entries, signed tree heads, Merkle
// proofs). Consumed straight from its module — the same discipline as the
// contract/attestation/synthetic/coverage imports above: the core barrel is
// not this batch's to edit, and a direct import keeps the dependency explicit.
import {
  appendPtlEntry, loadPtl, ptlLeafHash, savePtlHead, sthSignedData,
} from './core/transparency.ts'
import type { PtlEntry, SignedTreeHead } from './core/transparency.ts'
// v0.19: the responsibility-DAG domain (core/obligations.ts) — obligations,
// submissions and verdict composition, consumed straight from the module.
// Same discipline as the contract/attest/synthetic/coverage imports above:
// the core barrel is not this batch's to edit, and a direct import keeps the
// dependency explicit.
import {
  bundleFingerprint, composeTaskVerdict, detectCycles, obligationIdOf,
} from './core/obligations.ts'
import type { ComposedVerdict, DagNode, DelegationSubmission, TaskObligation } from './core/obligations.ts'
// v0.20: the training-distillation domain (core/training.ts). The engine owns
// the export SEAM — chain state in, DistillInput assembled, TrainingSet out to
// files — while the core owns the distillation itself. Consumed straight from
// the module, the same discipline as the contract/attest/synthetic/coverage
// imports above: the core barrel is not this batch's to edit.
import { distillTrainingSet } from './core/training.ts'
import type { SampleFidelity, TrainingManifest, TrainingSample } from './core/training.ts'
// v0.21: the engine-economics domain (E1's core/economics.ts) — run ledgers
// (what a verification spent and what the spend bought) and SLA pricing (what
// a proven grade underwrites). The engine owns the seams: this run's records,
// the scheduler's prior/posterior trajectory and the consumed-witness count
// feed the ledger; input defense and the `economics/quote` marker wrap
// `priceSla`. Consumed straight from the module, the same discipline as the
// contract/attest/synthetic/coverage/training imports above: the core barrel
// is not this batch's to edit.
import { priceSla, summarizeRunLedger } from './core/economics.ts'
import type { RateCard, RunLedger, SlaQuote } from './core/economics.ts'
// v0.19: the ONE engine→app edge, deliberate. `verifyBundle` is the
// authoritative implementation of the APP bundle exchange format (manifest
// digests, chain walk, anchor adjudication), and `submitDelegation` must
// adjudicate a submitted bundle under exactly that authority rather than the
// engine growing a second, drift-prone copy of the same rules. No cycle:
// app/bundle.ts depends only on src/core/* and its sibling protocol.ts —
// never on the engine.
import { EVIDENCE_FILE, verifyBundle } from './app/bundle.ts'
import type { ProofBundle } from './app/bundle.ts'
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
  /**
   * v0.18: directory of the public transparency log (PTL) this engine
   * publishes signed checkpoints to (`publishCheckpoint`). Absent = the
   * feature is off and `publishCheckpoint` throws a clean configuration
   * error. The directory is owned by the transparency-log operator, not by
   * the agent — hosts place it under the trust root, outside the workspace.
   */
  readonly ptlDir?: string
  /**
   * v0.18: provider for the transparency-log OPERATOR key — the key that
   * signs SignedTreeHeads over the published log. Deliberately a separate
   * key from the workspace chain signer (`signer`): the chain signer speaks
   * for the host over its own evidence log; the operator key speaks for the
   * LOG OPERATOR over the public Merkle tree, and rotating one must never
   * rotate the other. When omitted, the engine defaults to an Ed25519 key
   * loaded from `<ptlDir>/operator-key` (created on first use), with v0.17
   * M15 resolution semantics: only a successful load is cached.
   */
  readonly ptlSigner?: () => Promise<SignerPort | undefined>
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
  /**
   * H-03: false-pass rate priced into checks whose script body DRIFTED from
   * the body the baseline digested — an unreviewed body replacing one the
   * baseline had vouched for. Default `DRIFTED_FALSE_PASS_DEFAULT` (0.5),
   * deliberately above the synthetic tier for the same reason the synthetic
   * tier is above the organic one: the hand that owns the claim chose these
   * bytes, and nobody screened them. Overridable modelling guess, never a
   * `BAYES_CONSTANTS` law (see core/bayes.ts).
   */
  readonly driftedFalsePass?: number
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
  /**
   * H9b: a shell-class tool ran this session (`WorkspaceWatch.sessionShellUsed`).
   * Path extraction cannot see through a command string, so "not in `touched`"
   * no longer proves "changed outside the agent" — those changes classify as
   * `'unknown'` instead of `'external'` (see `ChangeSetInput.uncertainExternal`).
   */
  readonly shellUsedSince?: boolean
  readonly signal?: AbortSignal
  /** Force the full check set regardless of impact analysis. */
  readonly all?: boolean
  readonly onProgress?: (label: string, index: number, total: number) => void
  /**
   * M19b: the claim text this verification answers — what the tool-side
   * `claim` parameter was for. Bounded to 200 characters and recorded on the
   * `proof/verified` boundary marker when non-empty, so the chain says WHAT
   * was proven, not only that something was.
   */
  readonly claim?: string
  /**
   * v0.21: price this run. When supplied, the outcome carries an `economics`
   * block — the run's ledger (compute spent, assertions bought, per-dollar
   * efficiency) plus the claim-probability trajectory the scheduler moved it
   * through. Absent = absent: the outcome's shape without the option is
   * unchanged, so consumers that never asked see nothing new. The rate card
   * is validated at the verb boundary BEFORE any check runs — a negative
   * price must refuse the run, not silently price it backwards.
   */
  readonly economics?: { readonly rate: RateCard }
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
    /**
     * Checks the plan left resting on their priors, each with that prior:
     * deliberately never dispatched, or (H2) dispatched without producing a
     * decisive answer — both are "no verdict from this run", which is exactly
     * what the report's `unverified` list and `basisFor`'s planned-skip
     * accounting consume them for.
     */
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
  /**
   * H5: check definitions whose script body changed since the baseline
   * (package.json scripts — the id says `npm run test`, the digest says what
   * `test` said). Each one was force-re-run regardless of impact analysis and
   * priced at the synthetic false-pass tier: the baseline's green under that
   * id was earned by a *different body*, and an interested party rewriting
   * `"test": "vitest run"` into a no-op carries at least the false-pass risk
   * of a self-authored test. Present only when at least one check drifted.
   */
  readonly scriptDrift?: readonly string[]
  /** H5②: baseline checks whose definitions vanished from discovery. */
  readonly vanished?: readonly string[]
  /**
   * H-23: the run consumed an audit that found the baseline file no longer
   * matches the digest the chain recorded under `baseline/saved` — every
   * comparison this run made against that baseline (change-set resolution,
   * script digests, the API surface) judged suspect bytes. Present only on
   * the tampered path: the run forced the full check set AND its grade is
   * capped at `stale`; the boundary marker carries the same flag so the
   * degradation is a chain fact, not just a return value.
   */
  readonly baselineTampered?: true
  /**
   * v0.21: what this run cost and what it bought — present exactly when the
   * caller supplied `economics.rate`. `ledger` prices the run (compute ms,
   * assertions, per-dollar efficiency over the records THIS run produced);
   * `priorProbability`/`posteriorProbability` are the bayesian scheduler's
   * session-start (Π priors) and final (Π factors) claim probabilities —
   * `null` on the whole-batch path, where the confidence number is
   * display-only and no wave plan certified anything (`verifyContract`'s
   * machine path is the one exception: its posterior is the final, possibly
   * attestation-fused confidence the verdict rode on).
   */
  readonly economics?: {
    readonly ledger: RunLedger
    readonly priorProbability: number | null
    readonly posteriorProbability: number | null
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
  /**
   * H5: the script *bodies* that answered at baseline time — checkId →
   * sha256(script body) for every discovered spec that carries a digest (the
   * package.json discovery path). Same non-addressing discipline as
   * `apiSurface`: `baselineId` hashes none of it, the field round-trips
   * through save/load, and a pre-H5 baseline file reads back `undefined` —
   * comparison then honestly degrades to "drift undetectable" rather than
   * guessing (see `detectScriptDrift`).
   */
  readonly scriptDigests?: Readonly<Record<string, string>>
  /**
   * H6: this baseline's dirty-file snapshot was built with a FAILED git query
   * — the dirty list is empty because it was unobservable, not because the
   * tree was clean. Kept beside the baseline (never inside `WorkspaceSnapshot`,
   * which is hash material for `baselineId`); verify folds it into its
   * degraded synthesis, forcing the full check set.
   */
  readonly snapshotDegraded?: true
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
 * v0.18: what one transparency-log publish produced. The entry mirrors the
 * latest signed checkpoint into the public Merkle tree; the SignedTreeHead is
 * the operator's signature over that tree ({logId, treeSize, root, at}); the
 * inclusion proof lets any third party verify the entry is committed by the
 * root WITHOUT trusting the publisher. `duplicate: true` means the exact
 * checkpoint was already on the public log — the tree is unchanged, and the
 * returned values describe the entry's existing position.
 */
export interface PublishOutcome {
  /** Position of the entry in the public log (0-based leaf index). */
  readonly sequence: number
  /** True when the checkpoint was already published — the tree did not grow. */
  readonly duplicate: boolean
  /** The entry's Merkle leaf hash (`ptlLeafHash(entry)`). */
  readonly leafHash: string
  /** Leaves in the tree after this publish. */
  readonly treeSize: number
  /** Merkle root over every published leaf. */
  readonly root: string
  /** Stable identity of the public log the STH speaks for. */
  readonly logId: string
  /** ISO timestamp of the SignedTreeHead (NOT of the mirrored checkpoint). */
  readonly at: string
  /** Audit path from the entry's leaf to the root. */
  readonly inclusionProof: readonly string[]
  /** The operator-signed tree head, also persisted as the log's head file. */
  readonly sth: SignedTreeHead
}

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

/** v0.19: what `delegateTask` minted and committed to the chain. */
export interface DelegateTaskResult {
  /** Engine-minted sequence identity (`task-<n>`), unique on this chain. */
  readonly taskId: string
  /** `obligationIdOf(obligation)` — the responsibility's content address. */
  readonly obligationId: string
  /** The obligation exactly as it rode the `delegation/created` marker. */
  readonly obligation: TaskObligation
}

/** v0.19: what `submitDelegation` recorded, and what the DAG composes over it. */
export interface SubmitDelegationResult {
  /** The submission exactly as it rode the `delegation/verdict` marker. */
  readonly submission: DelegationSubmission
  /** Verdict composed over the whole rebuilt DAG, with NO own-workspace grade. */
  readonly composed: ComposedVerdict
}

/**
 * v0.19: what `taskVerdict` rebuilt and concluded. `nodes` is the full DAG
 * the verdict was composed over (so hosts can surface the sub-tree, not just
 * the grade) and `cycles` is the defense-in-depth report — empty on any
 * chain this engine alone wrote to.
 */
export interface TaskVerdictResult {
  readonly composed: ComposedVerdict
  readonly nodes: readonly DagNode[]
  readonly cycles: string[]
  /**
   * H-11: ownGrade self-reports that exceeded what this chain's evidence
   * supports (the latest `proof/verified` marker's grade), one line each.
   * A self-report is testimony, never measurement: the composed verdict
   * rides the chain-derived grade, and an inflated claim is recorded here
   * and echoed into the composed blockers rather than silently ignored —
   * or worse, believed.
   */
  readonly discrepancies?: readonly string[]
}

/**
 * v0.20: knobs for `exportTrainingData`. Both behavioural defaults are the
 * conservative ones — the export would rather withhold than over-share:
 * `fidelity` defaults to `'private'` (no output text in samples; digests only)
 * and `provenanceFilter` defaults to `'agent-only'` (behaviour labels stay
 * pure; records the agent cannot be attributed stay out).
 */
export interface TrainingExportOptions {
  /**
   * How much output text the samples carry. `'private'` (default) strips the
   * excerpt and keeps only the digest; `'full'` keeps `outputExcerpt`.
   */
  readonly fidelity?: SampleFidelity
  /**
   * Behaviour-label purity filter handed to distillation. `'agent-only'`
   * (default) keeps only agent-attributable verification behaviour; `'all'
   * keeps everything. When the chain carries no provenance to filter by, the
   * filter cannot fire — distillation runs unfiltered and the manifest still
   * records the requested value (an honest downgrade, not a silent lie).
   */
  readonly provenanceFilter?: 'agent-only' | 'all'
  /**
   * The change set the samples are contextualised against. Default: the
   * changed-path list recorded on the latest `proof/verified` marker — which
   * today's markers do not carry (they record the count), so the honest
   * default for our own chains is no change-set context.
   */
  readonly changedPaths?: readonly string[]
  /** Dataset license, recorded on the manifest verbatim when given. */
  readonly license?: string
  /**
   * When given, the export also lands on disk as two files: `<path>` (one
   * canonical-JSON sample per line, JSONL) and `<path>.manifest.json` (the
   * single manifest document). Both go through the fs port's atomic
   * `writeFile`; the parent directory is created first.
   */
  readonly path?: string
}

/**
 * v0.20: the chain state an export is pinned to — what a dataset consumer
 * checks a re-derived merkle root against. `count`/`head` are the last
 * checkpoint's self-attestation ({@link EvidenceStore.latestSignedCheckpoint}
 * semantics: the latest signed checkpoint when one exists, otherwise the last
 * well-formed checkpoint of an unsigned chain); `keyId` names the signing key
 * and is absent when no signed checkpoint backs the anchor.
 */
export interface TrainingAnchor {
  /** Evidence + marker records the checkpoint commits to. */
  readonly count: number
  /** Chain head digest at the checkpoint. */
  readonly head: string
  /** The signing key's identity, when the anchor is a signed checkpoint. */
  readonly keyId?: string
}

/** v0.20: what `exportTrainingData` produced. */
export interface TrainingExportResult {
  readonly manifest: TrainingManifest
  readonly samples: readonly TrainingSample[]
  readonly anchor: TrainingAnchor
}

/**
 * π: narrow one `synthetic/requested` marker payload back into a
 * `SyntheticRequest`. Malformed payloads (older chains, foreign writes)
 * return `undefined` and are skipped by every consumer — a marker that
 * cannot prove its own shape cannot mint a spec or authorise a run.
 *
 * M-01/L3 hardening: `entry` must be a name this engine could have minted
 * (`sandboxEntryFor`'s exact shape — `synthetic-<hex claimId>-<seq>.mjs`), so
 * a foreign marker can never smuggle `../../evil.mjs` or an absolute path
 * into the spec pool's `node <entry>` command line.
 */
const SYNTHETIC_ENTRY_RE = /^synthetic-[0-9a-f]+-\d+\.mjs$/
function syntheticRequestOf(payload: Record<string, unknown>): SyntheticRequest | undefined {
  const { claimId, claim, paths, entry, requestedAt } = payload as Record<string, unknown>
  if (typeof claimId !== 'string' || typeof claim !== 'string' || typeof entry !== 'string' || typeof requestedAt !== 'number') {
    return undefined
  }
  if (!SYNTHETIC_ENTRY_RE.test(entry)) return undefined
  if (!Array.isArray(paths) || !paths.every(p => typeof p === 'string')) return undefined
  return { claimId, claim, paths, entry, requestedAt }
}

/**
 * v0.19: the `ProofGrade` vocabulary as a runtime set, so a foreign
 * `claimedGrade`/`ownGrade` string (tool boundary, hostile caller) is
 * refused BY VALUE, never trusted by type. Mirrors `ProofGrade` in
 * core/evidence.ts — the engine owns no grades of its own.
 */
const DELEGATION_GRADES: ReadonlySet<string> = new Set([
  'proven', 'unproven', 'regressed', 'no-baseline', 'stale',
])

/**
 * v0.19: narrow one `delegation/created` marker payload back into a
 * `TaskObligation`. Same rule as `syntheticRequestOf`: a marker that cannot
 * prove its own shape mints nothing — a malformed obligation cannot join the
 * responsibility DAG, define a taskId, or authorise a submission.
 */
function obligationOf(payload: Record<string, unknown>): TaskObligation | undefined {
  const { v, taskId, parentTaskId, claim, acceptance, issuedAt, issuedByWorkspace } = payload as Record<string, unknown>
  if (v !== 1
    || typeof taskId !== 'string' || taskId.length === 0
    || typeof claim !== 'string'
    || typeof issuedAt !== 'string'
    || typeof issuedByWorkspace !== 'string') {
    return undefined
  }
  if (parentTaskId !== undefined && typeof parentTaskId !== 'string') return undefined
  if (acceptance !== undefined && typeof acceptance !== 'string') return undefined
  return {
    v: 1,
    taskId,
    ...(parentTaskId !== undefined ? { parentTaskId } : {}),
    claim,
    ...(acceptance !== undefined ? { acceptance } : {}),
    issuedAt,
    issuedByWorkspace,
  }
}

/**
 * v0.19: narrow one `delegation/verdict` marker's submission payload back
 * into a `DelegationSubmission`. Structural only — whether the submission
 * may lift its parent's verdict is the composer's judgment (core), never the
 * parser's.
 */
function submissionOf(value: unknown): DelegationSubmission | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const {
    childWorkspace, bundleRoot, claimedGrade, artifactVerified,
    transparencyVerified, problems, submittedAt,
  } = value as Record<string, unknown>
  if (typeof childWorkspace !== 'string'
    || (bundleRoot !== null && bundleRoot !== undefined && typeof bundleRoot !== 'string')
    || typeof claimedGrade !== 'string' || !DELEGATION_GRADES.has(claimedGrade)
    || typeof artifactVerified !== 'boolean'
    || typeof submittedAt !== 'string') {
    return undefined
  }
  if (transparencyVerified !== undefined && typeof transparencyVerified !== 'boolean') return undefined
  if (problems !== undefined && (!Array.isArray(problems) || !problems.every(p => typeof p === 'string'))) return undefined
  return {
    childWorkspace,
    bundleRoot: bundleRoot === null ? null : bundleRoot as string,
    claimedGrade: claimedGrade as ProofGrade,
    artifactVerified,
    ...(transparencyVerified !== undefined ? { transparencyVerified } : {}),
    ...(problems !== undefined ? { problems: [...problems as string[]] } : {}),
    submittedAt,
  }
}

/**
 * v0.19: shape-narrow an untrusted submitted value into a `ProofBundle` far
 * enough that every field the ENGINE itself reads — `manifest.files` (the
 * bundle fingerprint), `manifest.workspaceKey` (the child identity), `files`
 * (the contents `verifyBundle` adjudicates) — is present with the right
 * type. Deep adjudication (digests, chain walk, anchor, baseline
 * self-addressing) stays with `verifyBundle`, the exchange format's
 * authoritative verifier; this is only the "can this even be read" gate, and
 * anything failing it is a caller error, not a forged proof to grade.
 */
function delegationBundleOf(value: unknown): ProofBundle {
  const failure = 'submitDelegation: bundle is malformed — expected an APP proof bundle '
    + '{ manifest: { workspaceKey, files: [{path, sha256}, ...] }, files: { [path]: contents } }'
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(failure)
  const { manifest, files } = value as { manifest?: unknown; files?: unknown }
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error(failure)
  if (files === null || typeof files !== 'object' || Array.isArray(files)) throw new Error(failure)
  const { workspaceKey, files: entries } = manifest as { workspaceKey?: unknown; files?: unknown }
  if (typeof workspaceKey !== 'string' || workspaceKey.length === 0) throw new Error(failure)
  if (!Array.isArray(entries)
    || !entries.every(e => e !== null && typeof e === 'object' && !Array.isArray(e)
      && typeof (e as { path?: unknown }).path === 'string'
      && typeof (e as { sha256?: unknown }).sha256 === 'string')) {
    throw new Error(failure)
  }
  for (const contents of Object.values(files as Record<string, unknown>)) {
    if (typeof contents !== 'string') throw new Error(failure)
  }
  return value as ProofBundle
}

/**
 * H-16: how strongly a grade speaks, for "does this claim exceed its
 * evidence" comparisons (submission `claimedGrade` caps, `taskVerdict`
 * self-report caps). `proven` outranks everything; `stale` (a finished but
 * unproving run) outranks the never-proven pair; `unproven`, `no-baseline`
 * and `regressed` are all "no green claim" and never cap each other — an
 * explicitly declared bad state is honest news, never an inflation.
 */
function gradeRank(grade: ProofGrade): number {
  if (grade === 'proven') return 3
  if (grade === 'stale') return 2
  return 1
}

/** H-05: split a bundle's evidence log into walkable lines (trailing blank dropped). */
function bundleLogLines(log: string): string[] {
  const lines = log.split('\n')
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

/**
 * v0.20: the changed-path LIST from the latest `proof/verified` marker — only
 * when a writer actually recorded the list there. The boundary markers this
 * engine writes today carry the COUNT (`changed: changed.length`, see
 * `verify`), so for our own chains this returns `undefined` and the export
 * degrades honestly to no change-set context rather than inventing one. The
 * structural read keeps the seam forward-compatible: the day a boundary
 * marker carries the list itself, the export picks it up unmodified.
 */
function markerChangedPaths(payload: Record<string, unknown> | undefined): readonly string[] | undefined {
  if (payload === undefined) return undefined
  const changed = payload.changed
  if (!Array.isArray(changed) || !changed.every(p => typeof p === 'string')) return undefined
  return [...changed]
}

/**
 * v0.20: path→provenance from the latest `proof/verified` marker's
 * attribution payload — again only when the payload carries per-path
 * attribution (an object of path → 'agent' | 'external' | 'explicit' |
 * 'unknown'). This engine's own markers record the resolution METHOD there
 * (a string), so today the answer is `undefined`: distillation runs
 * unfiltered while the manifest still records the requested
 * `provenanceFilter` — the downgrade is visible, not silent.
 */
function markerProvenance(payload: Record<string, unknown> | undefined): Map<string, ChangeProvenance> | undefined {
  if (payload === undefined) return undefined
  const attribution = payload.attribution
  if (attribution === null || typeof attribution !== 'object' || Array.isArray(attribution)) return undefined
  const out = new Map<string, ChangeProvenance>()
  for (const [path, value] of Object.entries(attribution)) {
    if (value === 'agent' || value === 'external' || value === 'explicit' || value === 'unknown') {
      out.set(path, value)
    }
  }
  return out.size > 0 ? out : undefined
}

/**
 * M12: the note prepended to a record whose exit code claimed success without
 * the scaffold's protocol line — the honest first line of an output that lied
 * by omission.
 */
const SYNTHETIC_PROTOCOL_NOTE = 'protocol line missing: scaffolded scripts must end with SYNTHETIC: PASS/FAIL'

/**
 * M12: does the run's normalised output carry the scaffold's own verdict
 * line? The judgement of a conjured script is the *protocol*, not the exit
 * code alone: the scaffold's contract says a passing script ends with a
 * `SYNTHETIC: PASS` line, and an empty script (or one that merely
 * `process.exit(0)`s) satisfies the exit code while proving nothing. The
 * check reads the record's excerpt of the normalised output line by line, so
 * a protocol line buried mid-noise does not count — the line IS the verdict.
 */
function hasSyntheticProtocolPassLine(outputHead: string): boolean {
  return outputHead.split(/\r?\n/).some(line => line.trim() === 'SYNTHETIC: PASS')
}

function isAbsolutePath(p: string): boolean {
  // M-35: `\\server\share\...` (backslash UNC) is an absolute path too —
  // without this branch a UNC evidenceDir folded into `<root>\server\...`
  // and the log silently landed back inside the agent-writable workspace,
  // the exact inversion of the "hosts keep the log outside" promise.
  return /^([A-Za-z]:[\\/]|\\\\|\/)/.test(p)
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
 * M19b: bounded, non-empty text for a boundary marker (≤200 characters), or
 * `undefined` when the caller said nothing — absent stays absent on the
 * chain; no empty fields are minted for parameters that were not passed.
 */
function markerText(value: string | undefined): string | undefined {
  const trimmed = value?.trim()
  return trimmed !== undefined && trimmed.length > 0 ? trimmed.slice(0, 200) : undefined
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

/**
 * H6: read the baseline's non-addressing snapshot-degradation flag — same
 * structural read as `resolutionDegraded`, for the same reason (the flag may
 * have been written by an engine a beat older than the reader).
 */
function baselineSnapshotDegraded(baseline: Baseline | undefined): boolean {
  return (baseline as { snapshotDegraded?: unknown } | undefined)?.snapshotDegraded === true
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
  /** v0.18: the transparency log's directory, when publishing is configured. */
  private readonly ptlDir: string | undefined
  /** v0.18: operator-key provider for SignedTreeHeads (default: `<ptlDir>/operator-key`). */
  private readonly ptlSignerProvider: (() => Promise<SignerPort | undefined>) | undefined
  /** v0.18: M15 memoization for the operator signer — only a SUCCESSFUL load is cached. */
  private ptlSignerPromise: Promise<SignerPort | undefined> | undefined
  /** v0.18: bounded reason the last operator-signer resolution failed, for the clean throw. */
  private ptlSignerError: string | undefined
  /**
   * v0.18: single-flight for every PTL-mutating operation. Two racing
   * `publishCheckpoint` calls would both `loadPtl` at the same size and both
   * append — the public log would then carry the same leaf twice and the tree
   * would grow on a duplicate. Same discipline as the store's tail queue:
   * serialise the read–append–sign section; reads elsewhere stay concurrent.
   */
  private ptlQueue: Promise<unknown> = Promise.resolve()
  private readonly resolver: DefinitionResolverPort | undefined
  private readonly logger: ((message: string) => void) | undefined
  private readonly verbose: boolean
  /** v0.18: the stable workspace identity checkpoints (and PTL entries) carry. */
  private readonly workspaceKey: string
  /**
   * H-05/H-10: the out-of-band anchor file this engine's store consults
   * (`<trustDir>/anchors/<workspaceKey>/anchor.json`), retained so the
   * delegation verbs can read the obligation minter's trust root directly.
   */
  private readonly trustDir: string | undefined
  private readonly anchorPath: string | undefined
  /**
   * H-10: the (watched) signer provider the store was configured with.
   * `waiveDelegation`'s anchor-key authorization resolves it to ask "does
   * THIS host hold the key the anchor names?" — an absent provider answers
   * no, which is the conservative direction for a risk-acceptance verb.
   */
  private readonly signerProvider: (() => Promise<SignerPort | undefined>) | undefined
  /** H-17: per-run sequence for coverage staging directory names (physical only, never hash material). */
  private coverageRunSeq = 0
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
    driftedFalsePass: number
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
    // v0.18: transparency-log wiring. `ptlDir` is normalised once (trailing
    // slashes folded — every composition below is `${ptlDir}/...`). The
    // operator-signer default lives OUTSIDE the published log dir (H-07's
    // self-reference lesson: a key stored beside the log it notarises can be
    // rewritten together with it): `<trustDir>/ptl-operator-key` first — the
    // same default the ptl CLI resolves — with the legacy `<ptlDir>/operator-key`
    // honoured when only that exists, so an existing deployment's STHs keep
    // their identity. NodeEd25519Signer.load bootstraps on first use.
    this.workspaceKey = workspaceKey
    this.ptlDir = options.ptlDir !== undefined ? options.ptlDir.replace(/[\/]+$/, '') : undefined
    this.ptlSignerProvider = options.ptlSigner
      ?? (this.ptlDir !== undefined
        ? () => this.loadPtlOperatorKey()
        : undefined)
    // E2: whichever provider wins (host-injected or trustDir-derived), it is
    // wrapped so a load failure can never pass silently — the downgrade itself
    // becomes a chain marker, and the verbose channel gets a line.
    const rawSignerProvider = options.signer
      ?? (options.trustDir !== undefined ? () => this.loadSigner(`${options.trustDir}/keys`) : undefined)
    const signerProvider = rawSignerProvider !== undefined ? () => this.watchSigner(rawSignerProvider) : undefined
    // H-05/H-10: the delegation verbs need the minter's trust root; the store
    // keeps its own copy private, so the engine retains the derivation. The
    // bare dir is kept too — the PTL operator-key default resolves under it.
    this.trustDir = options.trustDir
    this.anchorPath = options.trustDir !== undefined
      ? `${options.trustDir}/anchors/${workspaceKey}/anchor.json`
      : undefined
    this.signerProvider = signerProvider
    this.store = new EvidenceStore(
      this.fs,
      this.logPath,
      `${storeDir}/baseline.json`,
      this.clock,
      {
        ...(signerProvider !== undefined ? { signer: signerProvider } : {}),
        ...(this.anchorPath !== undefined ? { anchorPath: this.anchorPath } : {}),
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
      // H-03: the unreviewed-body tier — see EngineOptions.driftedFalsePass.
      driftedFalsePass: options.driftedFalsePass ?? DRIFTED_FALSE_PASS_DEFAULT,
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
   * The PTL operator key, resolved where the ptl CLI resolves it:
   * `<trustDir>/ptl-operator-key` (outside the published log dir — a key that
   * lives beside the log it notarises can be rewritten together with that
   * log), falling back to the legacy `<ptlDir>/operator-key` when only that
   * exists so an existing deployment's STH signatures keep their keyId. With
   * neither on disk the preferred location bootstraps on first use.
   */
  private async loadPtlOperatorKey(): Promise<SignerPort | undefined> {
    if (this.ptlDir === undefined) return undefined
    const candidates = [
      ...(this.trustDir !== undefined ? [`${this.trustDir}/ptl-operator-key`] : []),
      `${this.ptlDir}/ptl-operator-key`,
      `${this.ptlDir}/operator-key`,
    ]
    for (const dir of candidates) {
      if (await this.fs.stat(dir) !== undefined) return NodeEd25519Signer.load(dir)
    }
    return NodeEd25519Signer.load(candidates[0]!)
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
    // Only a *successful* resolution is memoized. A transient load failure
    // (AV lock, a key dir that appears a moment later) must not poison the
    // whole engine instance: the store retries its provider on the next
    // checkpoint (v0.17 M15), and caching the undefined here would defeat
    // that retry — every later checkpoint would reuse the cached failure.
    this.signerPromise ??= (async () => {
      try {
        const signer = await load()
        if (signer === undefined) this.signerPromise = undefined
        return signer
      } catch (reason) {
        const error = failureText(reason)
        if (this.verbose && this.logger !== undefined) {
          this.logger(`[dsh-proof] trust degraded: checkpoint signer unavailable (${error}) — chain continues unsigned`)
        }
        void this.store.mark('trust/signer-unavailable', { error })
          .catch(() => { /* the log itself is unwritable; nothing more to record */ })
        this.signerPromise = undefined
        return undefined
      }
    })()
    return this.signerPromise
  }

  // -- discovery ----------------------------------------------------------

  /**
   * Discover (or return cached) objective checks.
   *
   * M7 freshness contract: the engine's own verbs (`establishBaseline`,
   * `verify`, `verifyContract`) always pass `force` — discovery reads a
   * handful of manifest files (package.json and the like), so re-discovering
   * per verb costs next to nothing, and a script added to the workspace
   * mid-session cannot silently stay out of the pool (an un-discovered check
   * never runs and never blocks a grade — the exact hole the force closes).
   * Cheap status views keep the instance cache via `cachedChecks()` or a
   * plain `loadChecks()`.
   */
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
    // M8: the walk result is consumed whole — `files` feeds the builder, and
    // the walk's own `truncated` travels in through `walkTruncated`, where it
    // ORs into `graph.truncated`. The builder cannot detect this truncation
    // itself (its `limit` may never fire while the file list is still a
    // prefix of the workspace), and a graph that silently reasons over a
    // partial node set is the false-proven shape the flag exists to kill.
    const walked = await this.fs.walk(this.root, {
      limit: this.options.impactGraphLimit,
      // E4: one ignore list, owned by discovery (checks.ts) — a second
      // hand-maintained copy here had already drifted. The only local
      // addition is 'lib': this repo's own build output lands there
      // (tsconfig.build.json), and dependency edges into compiled artifacts
      // would make every build a whole-graph invalidator.
      ignoreDirs: [...DEFAULT_IGNORE_DIRS, 'lib'],
    })
    this.graph = await buildDependencyGraph(this.fs, this.root, walked.files, {
      limit: this.options.impactGraphLimit,
      ...(walked.truncated ? { walkTruncated: true } : {}),
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

  // -- transparency log (v0.18) -----------------------------------------------

  /**
   * v0.18: publish the latest signed checkpoint to the public transparency
   * log and mint an operator-signed tree head over it.
   *
   * The publish is a MIRROR, not a re-derivation: the entry carries the
   * checkpoint's own {count, head, at, sig, keyId} (the exact bytes the
   * host's signature already committed to), keyed by THIS engine's
   * workspaceKey, and nothing else. Because the entry is a pure function of
   * the checkpoint, republishing the same checkpoint mints the byte-identical
   * leaf — detected as `duplicate: true` and the tree does not grow, so the
   * public log cannot be padded by re-publishing.
   *
   * Preconditions, each failing with a clean throw (never a half-published
   * tree):
   * - `ptlDir` configured — otherwise 'transparency log not configured'.
   * - a signed checkpoint exists on the chain (baseline/verify produce one;
   *   an unsigned chain has nothing publishable).
   * - the operator signer resolves — a SignedTreeHead cannot be unsigned.
   *
   * Order of operations: load → (append + reload) → sign STH over the tree
   * {logId, treeSize, root, at} → persist the head → inclusion proof for the
   * entry's (possibly pre-existing) sequence. All under the PTL single-flight
   * queue — see `ptlQueue`.
   */
  async publishCheckpoint(): Promise<PublishOutcome> {
    return this.enqueuePtl(() => this.publishCheckpointInternal())
  }

  private enqueuePtl<T>(op: () => Promise<T>): Promise<T> {
    const next = this.ptlQueue.then(op)
    // Completion, never outcome: a rejected publish must not poison the queue
    // for the publishes queued behind it (the store's tail queue discipline).
    this.ptlQueue = next.catch(() => undefined)
    return next
  }

  private async publishCheckpointInternal(): Promise<PublishOutcome> {
    if (this.ptlDir === undefined) {
      throw new Error('transparency log not configured (ptlDir) — pass EngineOptions.ptlDir to enable publishCheckpoint')
    }
    const checkpoint = await this.store.latestSignedCheckpoint()
    if (checkpoint === undefined) {
      throw new Error(
        'no signed checkpoint on the evidence chain — establish a baseline or run a verification first '
        + '(publishCheckpoint mirrors the latest SIGNED checkpoint; an unsigned chain has nothing publishable)',
      )
    }
    // N-5 (red team): the engine face notarises only what it can stand
    // behind — the CLI face verifies the selected checkpoint's own signature
    // before publishing, and this face must not be the weaker twin. When the
    // workspace signer is loadable and the checkpoint claims THIS engine's
    // keyId, the signature is adjudicated: a garbage-signature checkpoint (a
    // log-writer's forgery riding the anchor-key filter) is refused
    // publication instead of being notarised into the public tree.
    if (this.signerProvider !== undefined) {
      const signer = await this.signerProvider().catch(() => undefined)
      if (signer !== undefined && signer.keyId === checkpoint.keyId
        && !(await signer.verify(checkpointSignedData(checkpoint.payload), checkpoint.sig))) {
        throw new Error(
          `refusing to publish: the selected checkpoint's signature does not verify under its own keyId (${checkpoint.keyId}) — the evidence chain carries a forged signature`,
        )
      }
    }
    // Precondition before any mutation: a publish that cannot end in a signed
    // tree head must not leave a headless entry on the public log.
    const operator = await this.resolvePtlSigner()
    if (operator === undefined) {
      throw new Error(
        `transparency log operator signer unavailable${this.ptlSignerError !== undefined ? ` (${this.ptlSignerError})` : ' (no ptlSigner provider)'}`
        + ' — a SignedTreeHead cannot be minted unsigned',
      )
    }
    // Pure function of the checkpoint: `at` comes from the payload, not from
    // the clock, so the same checkpoint always addresses to the same leaf —
    // appendPtlEntry dedupes by leaf hash, which is what keeps a re-publish
    // from padding the tree.
    const entry: PtlEntry = {
      v: 1,
      workspaceKey: this.workspaceKey,
      keyId: checkpoint.keyId,
      count: checkpoint.payload.count,
      head: checkpoint.payload.head,
      at: checkpoint.payload.at,
      sig: checkpoint.sig,
    }
    const { sequence, duplicate } = await appendPtlEntry(this.fs, this.ptlDir, entry)
    // Reload through the same loader a third-party verifier will use: the
    // outcome's treeSize/root/proof describe the tree AS PERSISTED, never an
    // in-memory projection of it.
    const { log } = await loadPtl(this.fs, this.ptlDir)
    // Per the STH contract, `logId` names the OPERATOR key that signed the
    // head — it is how a verifier knows whose signature to adjudicate under.
    const unsignedHead = {
      logId: operator.keyId,
      treeSize: log.size,
      root: log.merkleRoot(),
      at: new Date(this.clock.now()).toISOString(),
    }
    // Even a duplicate publish re-signs the head: the STH is an independent
    // operator assertion over the (unchanged) tree, stamped with its own `at`.
    // Re-asserting the same root under a fresh signature is harmless; quietly
    // returning a stale head would smuggle an old timestamp into a new answer.
    // (savePtlHead enforces exactly this: same tree must not rewind its root
    // or timestamp.)
    const sth: SignedTreeHead = { ...unsignedHead, sig: await operator.sign(sthSignedData(unsignedHead)) }
    await savePtlHead(this.fs, this.ptlDir, sth)
    return {
      sequence,
      duplicate,
      leafHash: ptlLeafHash(entry),
      treeSize: sth.treeSize,
      root: sth.root,
      logId: sth.logId,
      at: sth.at,
      inclusionProof: [...log.inclusionProof(sequence)],
      sth,
    }
  }

  /**
   * v0.18: resolve the operator signer with v0.17 M15 semantics — only a
   * SUCCESSFUL resolution is memoized. A rejected or empty resolution resets
   * the memo (the next publish retries the provider, so a transient key-dir
   * lock heals on the next boundary) and, unlike the store's signer, the
   * failure text is kept: publishing has no unsigned degradation to fall back
   * on, so the next attempt's clean throw can name the actual reason.
   */
  private async resolvePtlSigner(): Promise<SignerPort | undefined> {
    if (this.ptlSignerProvider === undefined) return undefined
    if (this.ptlSignerPromise === undefined) {
      const attempt = this.ptlSignerProvider().then(
        signer => {
          if (signer === undefined) this.ptlSignerPromise = undefined // not provisioned yet — ask again next time
          return signer
        },
        reason => {
          this.ptlSignerError = failureText(reason)
          this.ptlSignerPromise = undefined // transient failure — retry on the next publish
          return undefined
        },
      )
      this.ptlSignerPromise = attempt
    }
    return this.ptlSignerPromise
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
  async establishBaseline(options: {
    signal?: AbortSignal
    onProgress?: VerifyOptions['onProgress']
    /** M19b: why this anchor was taken (≤200 characters), recorded on the `baseline/established` marker when non-empty. */
    reason?: string
  } = {}): Promise<{ baseline: EngineBaseline; records: readonly Evidence[] }> {
    // H-23: consume the chain's own audit BEFORE anchoring over it. A
    // tampered predecessor baseline is exactly what a fresh anchor heals —
    // but the healing must be a loud chain fact, not a silent overwrite:
    // the marker below records that this anchor superseded suspect bytes.
    const supersededTampered = (await this.store.audit()).chain.baselineTampered
    if (supersededTampered && this.verbose && this.logger !== undefined) {
      this.logger('[dsh-proof] baseline superseded: the previous baseline file failed its chain-recorded digest — this anchor replaces it')
    }
    // N-6 (red team): a re-anchor can launder a mutated script body into a
    // fresh trust identity — drift dies with the old baseline and the new one
    // inherits the check id's earned history wholesale. Whether to GATE that
    // is a design decision this batch does not make; the FACT is not
    // optional: a check id anchoring under a different script body than the
    // prior baseline recorded becomes a chain fact any reviewer can see.
    const priorBaseline = await this.store.loadBaseline()
    const priorScriptDigests = (priorBaseline as EngineBaseline | undefined)?.scriptDigests
    // M7: an anchoring run re-discovers — the baseline must reflect the
    // checks the workspace declares NOW, not whatever an earlier verb cached.
    const specs = await this.loadChecks(true)
    // The detailed snapshot digests every dirty file's content: baseline checks
    // ran against the working tree as it was, so those bytes — not the commit —
    // are what later change-set resolution diffs against. H6: a FAILED dirty
    // query no longer masquerades as "clean" — the rejection travels beside the
    // snapshot (see snapshotWorkspaceDetailed) and lands on the baseline as the
    // non-addressing `snapshotDegraded` attachment.
    const { snapshot, dirtyQueryFailed } = await this.snapshotWorkspaceDetailed()
    if (dirtyQueryFailed && this.verbose && this.logger !== undefined) {
      this.logger('[dsh-proof] baseline degraded: the git dirty query failed — the dirty snapshot is empty because it was unobservable, not because the tree was clean')
    }
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
    // M-08: a cooperative-budget overrun is a fact the chain can name — an
    // in-flight check that finished after the wall-clock budget is real
    // evidence, but a baseline assembled under an exceeded budget says so,
    // instead of absorbing the overrun silently. (The bayesian wave loop
    // deliberately does NOT mark this: per-wave remaining-budget overruns are
    // the scheduler's normal cooperative behaviour, not an exception.)
    if (batch.budgetExceeded) {
      if (this.verbose && this.logger !== undefined) {
        this.logger('[dsh-proof] budget exceeded: checks finished after the wall-clock budget — the evidence is real, the schedule was not')
      }
      await this.store.mark('budget/exceeded', { ran: batch.ranIds.length, budgetMs: this.options.verifyBudgetMs })
    }
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
    // H5: lock the script bodies that answered under each id. Non-addressing
    // like `apiSurface` (see EngineBaseline.scriptDigests): only specs that
    // carry a digest are recorded, so a workspace with no enumerable script
    // bodies attaches nothing and comparison later honestly degrades.
    const scriptDigests: Record<string, string> = {}
    for (const s of specs) {
      if (s.scriptDigest !== undefined) scriptDigests[s.id] = s.scriptDigest
    }
    const anchored: EngineBaseline = {
      ...baseline,
      ...(apiSurface !== undefined ? { apiSurface } : {}),
      ...(Object.keys(scriptDigests).length > 0 ? { scriptDigests } : {}),
      ...(dirtyQueryFailed ? { snapshotDegraded: true as const } : {}),
    }
    // Three honest abort signals, all the same fact — the run did not observe
    // everything, so it must not anchor anything: the batch-level flag (a
    // cancelled run — some checks were never even attempted), any record that
    // came back `aborted` (a check whose process was killed mid-flight), and
    // (H12) any record that never got its turn or never finished answering —
    // `skipped` on a drained budget, `timeout` past the per-check clock. M-36:
    // `error` joins them — a spawn failure is "no answer" in exactly the sense
    // DECISIVE_STATUSES says so, and an environment-dead suite (every command
    // ENOENT) must not anchor a "healthy" baseline the way a starved one
    // cannot. A half-observed baseline would silently become THE truth later
    // judgments regress against, which is exactly what E1 exists to prevent.
    const aborted = batch.aborted === true
      || batch.records.some(r => r.status === 'aborted' || r.status === 'skipped' || r.status === 'timeout' || r.status === 'error')
    if (aborted) {
      await this.store.mark('baseline/aborted', {
        baselineId: baseline.baselineId,
        root: baseline.root,
        ran: batch.records.length,
        discovered: specs.length,
        // H12: why the anchor was refused — the batch observed fewer checks
        // than it completed, whatever the cause (cancel, budget, timeout).
        reason: 'incomplete-observation',
      })
      await this.store.checkpoint()
      return { baseline: { ...anchored, aborted: true }, records: batch.records }
    }
    // saveBaseline records the file digest into the chain and checkpoints.
    await this.store.saveBaseline(anchored)
    // N-6: the script-body mutation fact itself — ids whose body changed
    // under this anchor, on the record where the identity swap happened.
    const scriptMutations = priorScriptDigests === undefined ? [] : Object.keys(scriptDigests)
      .filter(id => priorScriptDigests[id] !== undefined && priorScriptDigests[id] !== scriptDigests[id])
    if (scriptMutations.length > 0) {
      await this.store.mark('baseline/script-mutation', {
        baselineId: baseline.baselineId,
        mutated: scriptMutations.length,
        ids: scriptMutations.slice(0, 20),
      })
    }
    // M19b: the caller's reason for anchoring (bounded, only when said).
    const reason = markerText(options.reason)
    await this.store.mark('baseline/established', {
      baselineId: baseline.baselineId,
      root: baseline.root,
      checks: batch.records.length,
      ...(reason !== undefined ? { reason } : {}),
      // ζ: whether this baseline carries an API surface is a chain fact —
      // a later `api-surface-unchanged` judgment rests on it.
      apiSurface: apiSurface !== undefined ? apiSurface.length : null,
      // H5: how many script bodies were locked; H6: whether the snapshot was
      // built blind. Both are chain facts the same way — drift detection and
      // degradation synthesis downstream rest on them.
      scriptDigests: Object.keys(scriptDigests).length,
      ...(dirtyQueryFailed ? { snapshotDegraded: true as const } : {}),
      // H-23: this anchor replaced a baseline the audit found tampered —
      // the healing is itself a chain fact.
      ...(supersededTampered ? { supersededTampered: true as const } : {}),
    })
    await this.store.checkpoint()
    return { baseline: anchored, records: batch.records }
  }

  /** Re-run the checks this change set made stale, and grade the claim. */
  async verify(options: VerifyOptions = {}): Promise<VerifyOutcome> {
    // v0.21: refuse a backwards price card BEFORE anything runs — a run whose
    // ledger would lie about its own cost is worse than no ledger at all.
    if (options.economics !== undefined) this.assertRateCard(options.economics.rate, 'verify')
    // M7: verification judges the workspace as it is now — a check added
    // since the last verb must be in the pool this run, or it would neither
    // run nor block the grade.
    const discovered = await this.loadChecks(true)
    const graph = await this.loadGraph()
    // π: conjured tests join the verification pool as ordinary specs — every
    // synthetic request the chain shows was actually executed. A workspace
    // with none on chain gets the empty union and behaves bit-for-bit as
    // before; one with them gets them selected, priced (raised β) and
    // re-executed exactly like an organic check (P5).
    const syntheticPool = await this.syntheticSpecs()
    const specs = unionChecks(discovered, syntheticPool)
    const baseline = await this.store.loadBaseline()
    // H-23: the run is about to judge the workspace against this baseline —
    // consult the chain's own audit first. A baseline whose bytes no longer
    // match the digest recorded under `baseline/saved` makes every
    // comparison against it suspect (change resolution, script digests, the
    // API surface), so the run forces the full set AND caps its grade: the
    // degradation is visible on the outcome, the marker and the verbose
    // channel, never silently absorbed.
    const baselineTampered = (await this.store.audit()).chain.baselineTampered
    if (baselineTampered && this.verbose && this.logger !== undefined) {
      this.logger('[dsh-proof] baseline degraded: the baseline file failed its chain-recorded digest — comparisons against it are suspect; re-establish the baseline')
    }
    // H5: which discovered checks now answer under a DIFFERENT script body than
    // the one the baseline greened. Independent of the change set on purpose —
    // the agent's report of what it touched cannot veto what the manifest says.
    const scriptDrifted = this.detectScriptDrift(discovered, baseline)
    if (scriptDrifted.size > 0) this.warnScriptDrift(scriptDrifted)
    const vanished = this.detectVanishedChecks(discovered, baseline)
    if (vanished.length > 0 && this.verbose && this.logger !== undefined) {
      this.logger(`dsh-proof: ${vanished.length} baseline check(s) vanished from discovery — definitions were removed; rebuild the baseline`)
    }
    const attribution = await this.resolveChanges(options, baseline)
    const changed = attribution.changed
    const provenance = new Map<RelPath, ChangeProvenance>(
      attribution.records.map(r => [r.path, r.provenance] as [RelPath, ChangeProvenance]),
    )
    // E3/H6: when git facts were unavailable (this run, or the run that built
    // the baseline's snapshot), the derived change set cannot be trusted to
    // narrow the run — an under-reported change set hides breaks. Force the
    // full check set through the same `forced` path `all` uses, and surface
    // the degradation on the outcome so the honesty is visible, not just
    // structural. The three legs: the resolution's own degraded flag (B1),
    // the baseline's snapshot-degraded attachment (H6 — anchored blind), and a
    // lost HEAD with git still claimed available (H6 — `changedSince` is
    // wholly blind without a ref to diff against). H-23 adds the fourth: a
    // baseline the audit found tampered.
    const degraded = resolutionDegraded(attribution)
      || baselineSnapshotDegraded(baseline)
      || baselineTampered
      || await this.gitFactsUnavailable()
      || await this.gitHeadMissing()
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

    // H5: drifted definitions join the run set REGARDLESS of impact analysis —
    // the same union the perf-budget path applies to benchmark checks: the
    // baseline's green under that id was earned by a different script body, so
    // resting on it (or skipping it as "not affected") would let a rewritten
    // `"test"` script borrow a verdict it never earned.
    const driftSpecs = specs.filter(s => scriptDrifted.has(s.id))
    const runSet = driftSpecs.length > 0 ? unionChecks(selection.affected, driftSpecs) : selection.affected

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
    // nonce plus a per-run sequence, H-17) is physical staging only: it never
    // enters any hash material, so the same verification re-run against a
    // different clock still addresses its evidence identically. The staging
    // object carries `spawnedAt` — the mtime floor every collected profile
    // must clear (H-17's forgery defense, enforced in `collectRunCoverage`).
    const coverageStaging = await this.prepareCoverageDir()

    const records: Evidence[] = []
    let schedule: VerifyOutcome['schedule']
    let confidence: ConfidenceInput | undefined
    // v0.21: the ledger's inputs, filled by whichever regime ran. The
    // whole-batch path prices NO probability trajectory (its confidence is
    // display-only — grading stayed binary), so its prior/posterior stay
    // null while the per-check factors still ride the ledger.
    let ledgerPriors: ReadonlyMap<string, CheckPrior> | undefined
    let priorProbability: number | null = null
    let posteriorProbability: number | null = null
    if (bayesian && runSet.length > 0) {
      const plan = await this.runBayesianSchedule(runSet, changed, graph, snapshot, options, coverageStaging?.dir, scriptDrifted)
      records.push(...plan.records)
      schedule = plan.schedule
      confidence = plan.confidence
      ledgerPriors = plan.priors
      priorProbability = plan.priorProbability
      posteriorProbability = plan.posteriorProbability
    } else {
      // Priors must snapshot the log BEFORE this run appends to it — history
      // is what the check brought to the table, not what it did just now.
      const priors = await this.priorsFor(runSet, changed, graph, scriptDrifted)
      ledgerPriors = runSet.length > 0 ? priors : undefined
      const batch = await this.runner.run(runSet, {
        concurrency: this.options.concurrency,
        totalBudgetMs: this.options.verifyBudgetMs,
        workspace: snapshot,
        ...(coverageStaging !== undefined ? { coverageDir: coverageStaging.dir } : {}),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        ...(options.onProgress !== undefined
          ? { onEvidence: (ev, i, total) => options.onProgress!(ev.label, i, total) }
          : {}),
      })
      records.push(...batch.records)
      // M-08: whole-batch overrun is the exception worth naming on-chain (see
      // the baseline site for the wave-loop carve-out).
      if (batch.budgetExceeded) {
        if (this.verbose && this.logger !== undefined) {
          this.logger('[dsh-proof] budget exceeded: checks finished after the wall-clock budget — the evidence is real, the schedule was not')
        }
        await this.store.mark('budget/exceeded', { ran: batch.ranIds.length, budgetMs: this.options.verifyBudgetMs })
      }
      // Even the whole-batch path earns its confidence number — display only:
      // grading on this path stays binary (requireFullCoverage below).
      confidence = this.updateFactors(priors, batch.records, runSet.length > 0)
    }

    // υ: collect coverage and re-address the records BEFORE the first append —
    // the coverage attachment is content-addressing material (π's synthetic
    // precedent), so the chain must never first see a plain record and then
    // its enriched twin. With no data (or mode 'off') the records pass through
    // untouched and this is exactly the pre-υ append.
    // M-01: same discipline one layer down — the synthetic body digest is
    // pinned on before the coverage attachment re-addresses on top of it, so
    // the chain only ever sees the fully self-addressing record.
    const syntheticallyAddressed = await this.reattachSyntheticMeta(records, syntheticPool)
    const collected = await this.collectRunCoverage(syntheticallyAddressed, changed, coverageStaging)
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
      ...(vanished.length > 0 ? { vanished } : {}),
    })

    // υ: execution-coverage gating — after the machine grade, before anything
    // else speaks. Plain verify() has no attestation fusion (v0.9 semantics
    // locked), so here "gate the machine evidence" is the whole story: an
    // observed-but-never-executed change (or, under `require`, the absence of
    // any observation at all) turns `proven` into `unproven`, and the summary
    // mounts on the report either way — `basis: 'none'` stays visible rather
    // than silently absent, because "could not measure" is a fact a reader of
    // a proof deserves to see.
    let report = this.gateByCoverage(machineReport, collected.summary)
    // H-23: a run that judged suspect bytes may not certify. `proven` caps at
    // `stale` ("re-establish and re-verify"); worse grades keep their more
    // honest verdict untouched.
    if (baselineTampered && report.grade === 'proven') {
      report = { ...report, grade: 'stale' as const }
    }

    // M19b: what the caller claims this run proves, when they said so.
    const claimText = markerText(options.claim)
    // v0.21: the ledger, when the caller asked to price the run — computed
    // before the boundary marker so the chain carries the price (E3's
    // proof_economics replays it from here). Caliber of `humanReviewItems`:
    // plain verify() fuses NO testimony (v0.9 semantics are locked —
    // attestations never touch this verb's grade or confidence), so the
    // honest count of B/C witnesses consumed by THIS judgment is zero.
    // (verifyContract is where witnesses actually fuse; its ledger counts
    // them there.)
    const economics = options.economics !== undefined
      ? this.runEconomics(
        options.economics.rate,
        collected.records,
        this.ledgerFactorsOf(ledgerPriors, confidence?.factors),
        priorProbability,
        posteriorProbability,
        0,
      )
      : undefined
    await this.store.mark('proof/verified', {
      grade: report.grade, root: report.root, changed: changed.length,
      attribution: attribution.method,
      preExistingExcluded: attribution.preExistingExcluded.length,
      regressions: report.summary.regressions,
      ...(claimText !== undefined ? { claim: claimText } : {}),
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
      // H5: which definitions drifted, when any did — a chain fact exactly
      // like the wave plan's footprint above.
      ...(scriptDrifted.size > 0 ? { scriptDrift: [...scriptDrifted].sort() } : {}),
      // H5②: which anchored checks lost their definitions — same visibility.
      ...(vanished.length > 0 ? { vanished } : {}),
      // H-23: the run's baseline failed its chain-recorded digest — the
      // grade above is capped and the run was forced; both facts are the
      // chain's to know.
      ...(baselineTampered ? { baselineTampered: true as const } : {}),
      // v0.21: the priced run rides the marker — a priced run is a chain
      // fact (proof_economics replays exactly these bytes).
      ...(economics !== undefined ? { economics } : {}),
    })
    // Every claim-grade boundary closes the checkpoint window.
    await this.store.checkpoint()
    return {
      report, checks, selection, changed, attribution,
      ...(degraded ? { degraded: true as const } : {}),
      ...(baselineTampered ? { baselineTampered: true as const } : {}),
      ...(economics !== undefined ? { economics } : {}),
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
      ...(scriptDrifted.size > 0 ? { scriptDrift: [...scriptDrifted].sort() } : {}),
      ...(vanished.length > 0 ? { vanished } : {}),
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
    // v0.21: same boundary rule as verify() — a malformed price card refuses
    // the verb before any path (jury or machine) spends anything.
    if (rest.economics !== undefined) this.assertRateCard(rest.economics.rate, 'verifyContract')
    // M7: a claim verdict re-discovers, exactly like plain verify() — the
    // obligations are judged against the workspace's current check pool.
    const specs = await this.loadChecks(true)
    const baseline = await this.store.loadBaseline()
    // H-23: same audit gate as verify() — the claim is about to be judged
    // against this baseline's bytes, and a baseline the chain's own audit
    // refutes (recorded digest ≠ file bytes) makes every path below suspect.
    // Every path consumes the flag: the jury paths degrade visibly (M-04's
    // missing `degraded` semantics ride along), the machine path degrades,
    // caps `proven` at `stale`, and keeps endorsement from paying for it.
    const baselineTampered = (await this.store.audit()).chain.baselineTampered
    if (baselineTampered && this.verbose && this.logger !== undefined) {
      this.logger('[dsh-proof] baseline degraded: the baseline file failed its chain-recorded digest — comparisons against it are suspect; re-establish the baseline')
    }
    // H5: drift detection runs for every contract kind (cheap, pure), though
    // only the machine path below can act on it — the jury paths run no
    // checks, so there is nothing to re-run and nothing to discount.
    const scriptDrifted = this.detectScriptDrift(specs, baseline)
    if (scriptDrifted.size > 0) this.warnScriptDrift(scriptDrifted)
    const vanished = this.detectVanishedChecks(specs, baseline)
    if (vanished.length > 0 && this.verbose && this.logger !== undefined) {
      this.logger(`dsh-proof: ${vanished.length} baseline check(s) vanished from discovery — definitions were removed; rebuild the baseline`)
    }

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
      let report = assembleJuryReport({
        contract,
        obligations: verdict.obligations,
        confidence,
        workspace: await this.workspaceSnapshot(),
        clock: this.clock,
      })
      // M-04: the jury paths owe the same degraded honesty the machine path
      // pays — a git-blind resolution (or an H-23 tampered baseline) under a
      // `docs-only-changes` obligation would otherwise judge an unobservable
      // change set and hand back a capped-proven verdict with no flag at all.
      // H-23: and a tampered baseline caps `proven` at `stale` here too —
      // "the change set is documentary" was decided against suspect bytes.
      const degraded = resolutionDegraded(attribution)
        || baselineSnapshotDegraded(baseline)
        || baselineTampered
        || await this.gitFactsUnavailable()
        || await this.gitHeadMissing()
      if (baselineTampered && report.grade === 'proven') {
        report = { ...report, grade: 'stale' as const }
      }
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
        // M-04/H-23: the jury path's honesty flags ride the marker — a
        // degraded resolution or a tampered baseline is a fact about what
        // this verdict was judged against.
        ...(degraded ? { degraded: true as const } : {}),
        ...(baselineTampered ? { baselineTampered: true as const } : {}),
      })
      await this.store.checkpoint()
      // v0.21: a docs-only verdict consumed no machine compute and no B/C
      // testimony (the self-attestation cap is the author's own, priced as
      // such by being left out of `humanReviewItems`), so its ledger prices
      // an honest zero and no factor trajectory exists.
      const economics = rest.economics !== undefined
        ? this.runEconomics(rest.economics.rate, [], undefined, null, null, 0)
        : undefined
      return {
        report,
        checks: [],
        selection,
        changed,
        attribution,
        ...(degraded ? { degraded: true as const } : {}),
        ...(baselineTampered ? { baselineTampered: true as const } : {}),
        ...(economics !== undefined ? { economics } : {}),
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
    // `certifyTarget` on top of every obligation holding. M10: a human
    // *endorsement* is excluded from that product (risk acceptance, not
    // probability transfer — see `attestationProduct`); a reject keeps its
    // veto weight.
    if (contract.kind === 'llm-jury') {
      const claimId = claimIdOf(contract.claim)
      // H-32: the κ fusion consumes only attestations the evidence layer has
      // NOT flagged suspect; the flag count rides the boundary marker so a
      // reader sees how much testimony was withheld and why.
      const { active: allActive, suspect: suspectAttestations } = await this.activeAttestationsAll()
      const active = attestationsFor(allActive, claimId)
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
      // M-04: the jury path's degraded honesty; H-23: a tampered baseline
      // caps the jury grade at `stale` — the obligations were judged against
      // suspect bytes.
      const degraded = resolutionDegraded(attribution)
        || baselineSnapshotDegraded(baseline)
        || baselineTampered
        || await this.gitFactsUnavailable()
        || await this.gitHeadMissing()
      const grade: GradedProofReport['grade'] =
        unmet.length === 0 && fused >= this.options.certifyTarget && !baselineTampered ? 'proven' : 'stale'
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
        // M-04/H-23/H-32: what this verdict was judged against, and how much
        // testimony the suspect channel withheld.
        ...(degraded ? { degraded: true as const } : {}),
        ...(baselineTampered ? { baselineTampered: true as const } : {}),
        ...(suspectAttestations > 0 ? { suspectAttestations } : {}),
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
      // v0.21: llm-jury consumed no machine compute, but its judge IS the
      // chain's active testimony — `humanReviewItems` counts exactly the B/C
      // witnesses this verdict rested on. No factor model ran, so the
      // probability trajectory stays null (the fused product is testimony
      // arithmetic, not a scheduler posterior).
      const economics = rest.economics !== undefined
        ? this.runEconomics(rest.economics.rate, [], undefined, null, null, active.length)
        : undefined
      return {
        report,
        checks: [],
        selection,
        changed,
        attribution,
        ...(degraded ? { degraded: true as const } : {}),
        ...(baselineTampered ? { baselineTampered: true as const } : {}),
        ...(economics !== undefined ? { economics } : {}),
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
    const syntheticPool = await this.syntheticSpecs()
    const pool = unionChecks(specs, syntheticPool)
    const attribution = await this.resolveChanges(rest, baseline)
    const changed = attribution.changed
    const provenance = new Map<RelPath, ChangeProvenance>(
      attribution.records.map(r => [r.path, r.provenance] as [RelPath, ChangeProvenance]),
    )
    const degraded = resolutionDegraded(attribution)
      || baselineSnapshotDegraded(baseline)
      || baselineTampered
      || await this.gitFactsUnavailable()
      || await this.gitHeadMissing()
    const forceAll = rest.all === true || degraded
    const selection = forceAll
      ? forcedSelection(pool, changed)
      : selectAffectedChecks(pool, changed, graph)

    // H5: drifted definitions join the run set regardless of impact analysis —
    // the same rule as verify() (and stacked under the perf-budget benchmark
    // union the same way). The obligations below are judged against THIS run's
    // fresh records, so a drifted check's re-executed evidence is what the
    // contract consumes — the discount rides the confidence number.
    const driftSpecs = pool.filter(s => scriptDrifted.has(s.id))
    const runSpecs = driftSpecs.length > 0
      ? unionChecks(
        contract.kind === 'perf-budget'
          ? unionChecks(selection.affected, pool.filter(s => s.kind === 'benchmark'))
          : selection.affected,
        driftSpecs,
      )
      : contract.kind === 'perf-budget'
        ? unionChecks(selection.affected, pool.filter(s => s.kind === 'benchmark'))
        : selection.affected

    const snapshot = await this.workspaceSnapshot()
    // υ: same coverage staging as verify() — the machine legs of a contract
    // claim are ordinary checks and earn the same execution-coverage honesty
    // (and the same H-17 per-run staging + mtime window).
    const coverageStaging = await this.prepareCoverageDir()
    // Whole-batch over the (possibly benchmark-extended, possibly
    // drift-extended) run set, with the same priors/confidence display the
    // 'set' path uses — see method note.
    const priors = await this.priorsFor(runSpecs, changed, graph, scriptDrifted)
    const batch = await this.runner.run(runSpecs, {
      concurrency: this.options.concurrency,
      totalBudgetMs: this.options.verifyBudgetMs,
      workspace: snapshot,
      ...(coverageStaging !== undefined ? { coverageDir: coverageStaging.dir } : {}),
      ...(rest.signal !== undefined ? { signal: rest.signal } : {}),
      ...(rest.onProgress !== undefined
        ? { onEvidence: (ev, i, total) => rest.onProgress!(ev.label, i, total) }
        : {}),
    })
    // M-08: same whole-batch overrun naming as verify()/establishBaseline().
    if (batch.budgetExceeded) {
      if (this.verbose && this.logger !== undefined) {
        this.logger('[dsh-proof] budget exceeded: checks finished after the wall-clock budget — the evidence is real, the schedule was not')
      }
      await this.store.mark('budget/exceeded', { ran: batch.ranIds.length, budgetMs: this.options.verifyBudgetMs })
    }
    // υ: collect + re-address before the first append — see verify(). M-01:
    // the synthetic body digest is pinned on first, same order as verify().
    const syntheticallyAddressed = await this.reattachSyntheticMeta(batch.records, syntheticPool)
    const collected = await this.collectRunCoverage(syntheticallyAddressed, changed, coverageStaging)
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
      ...(vanished.length > 0 ? { vanished } : {}),
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
    //
    // H3: the gate verdict is kept beside the gated report, because
    // `applyCoverageGate` expresses "blocked" only as a proven → unproven
    // demotion — a report that was already `stale` (or capped to it by the
    // obligations below) shows nothing. The endorsement unlock reads the
    // verdict itself, so a coverage-blocked claim cannot be endorsed around
    // the τ gate through the stale door.
    const coverageSummary = collected.summary
    let coverageBlocked = false
    let graded = machineReport
    if (coverageSummary !== undefined) {
      const gate = coverageGate(coverageSummary, this.options.coverage)
      coverageBlocked = gate.blocked
      graded = applyCoverageGate(machineReport, gate, coverageSummary)
    }

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
    // H-23: a claim judged against a tampered baseline may not certify —
    // `proven` caps at `stale` (re-anchor and re-verify), and the cap sits
    // BEFORE the κ fusion below so neither a witness nor the endorsement
    // unlock can pay a claim whose baseline bytes the chain itself refutes.
    if (baselineTampered && graded.grade === 'proven') {
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
    // H-32: suspect attestations are excluded from the fusion (the channel is
    // position test — see `isSuspectMarker`); the count rides the boundary
    // marker so a reader sees the withheld testimony.
    const { active: allActive, suspect: suspectAttestations } = await this.activeAttestationsAll()
    const claimActive = attestationsFor(allActive, claimIdOf(contract.claim))
    // v0.21: the ledger's `humanReviewItems` counts the B/C witnesses that
    // actually fused into this verdict's confidence — zero when no active
    // witness exists or the machine run earned no confidence number to fuse
    // into, `claimActive.length` when the fusion loop below ran.
    let consumedWitnesses = 0
    if (claimActive.length > 0 && graded.confidence !== undefined) {
      consumedWitnesses = claimActive.length
      let fused = graded.confidence
      for (const att of claimActive) fused = fuseConfidence(fused, att, this.trustWeights)
      const machineDecisive = batch.records.some(r => isDecisiveStatus(r.status))
      const endorsed = claimActive.some(a => a.kind === 'attest/human' && a.decision === 'endorse')
      // H3: endorsement accepts RESIDUAL RISK, it never pays for work. The
      // unlock therefore demands the work be complete on every axis: every
      // check verified to a decisive outcome (no `unverified` — checks that
      // were skipped, timed out or never dispatched are unfinished work, not
      // residual risk), the coverage gate not blocking (an unexecuted change
      // is missing work too — see the H3 note above), every obligation met,
      // nothing regressed, nothing newly failing. That leaves exactly the
      // machine's own words: "0.94, and I cannot cross 0.97" — and the human
      // took the remainder. H-04 closes the two completeness doors the
      // enumeration missed: `vanished` (a baseline check whose definition
      // was deleted is a hole in the pool, not residual risk — report.ts
      // caps its grade at `stale`, and one endorsement used to lift it back
      // to `proven` while the report still listed the vanished id) and
      // `scriptDrifted` (a check answering under a body the baseline never
      // vouched for is exactly the missing-work shape the drift discount
      // prices; an un-re-anchored body is not residual risk either). H-23
      // adds the integrity door: a tampered baseline is not residual risk.
      const endorsementUnlock = endorsed
        && graded.grade === 'stale'
        && unmet.length === 0
        && graded.unverified.length === 0
        && !coverageBlocked
        && graded.summary.regressions === 0
        && !checks.some(c => c.verdict === 'new-failure')
        && vanished.length === 0
        && scriptDrifted.size === 0
        && !baselineTampered
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

    // M19b: the caller's claim text for this verdict, when supplied — the
    // contract's own claim already lives in the attest/jury markers.
    const claimText = markerText(rest.claim)
    // v0.21: the machine path's ledger. `posteriorProbability` is the FINAL
    // confidence — the machine product after the κ fusion above (the number
    // the grade actually rode on); the whole-batch regime has no scheduler
    // prior product, so `priorProbability` stays null. Per-check factors ride
    // the ledger from the same priors/updateFactors pair verify()'s 'set'
    // path uses.
    const economics = rest.economics !== undefined
      ? this.runEconomics(
        rest.economics.rate,
        collected.records,
        this.ledgerFactorsOf(runSpecs.length > 0 ? priors : undefined, confidence?.factors),
        null,
        typeof graded.confidence === 'number' ? graded.confidence : null,
        consumedWitnesses,
      )
      : undefined
    await this.store.mark('proof/verified', {
      grade: graded.grade,
      root: graded.root,
      changed: changed.length,
      attribution: attribution.method,
      preExistingExcluded: attribution.preExistingExcluded.length,
      regressions: graded.summary.regressions,
      ...(claimText !== undefined ? { claim: claimText } : {}),
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
      // H5: which definitions drifted, when any did.
      ...(scriptDrifted.size > 0 ? { scriptDrift: [...scriptDrifted].sort() } : {}),
      // H-23/H-32: the integrity flags this verdict was judged under.
      ...(baselineTampered ? { baselineTampered: true as const } : {}),
      ...(suspectAttestations > 0 ? { suspectAttestations } : {}),
    })
    await this.store.checkpoint()
    return {
      report: graded,
      checks,
      selection,
      changed,
      attribution,
      ...(degraded ? { degraded: true as const } : {}),
      ...(baselineTampered ? { baselineTampered: true as const } : {}),
      ...(economics !== undefined ? { economics } : {}),
      ...(collected.summary !== undefined
        ? {
            coverage: {
              basis: collected.summary.basis,
              uncovered: [...collected.summary.changedUncovered],
              executedCount: collected.summary.changedExecuted.length,
            },
          }
        : {}),
      ...(scriptDrifted.size > 0 ? { scriptDrift: [...scriptDrifted].sort() } : {}),
      ...(vanished.length > 0 ? { vanished } : {}),
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

  // -- SLA pricing (v0.21) --------------------------------------------------

  /**
   * v0.21: price one proof grade as a service-level agreement — what it would
   * cost to underwrite "this claim holds" at the confidence the evidence
   * reached. The pricing itself is `core/economics.ts`'s (`priceSla`); the
   * engine owns the boundary and the chain:
   *
   * - input defense FIRST — grade (the `ProofGrade` vocabulary, by value),
   *   confidence (a probability, [0,1]) and the rate card (non-negative
   *   prices) are validated before anything is priced or written, so a
   *   refused quote leaves the chain untouched;
   * - the FULL quote lands as an `economics/quote` marker — a price that
   *   cannot be audited is a number, not a quote, and the quote's own bytes
   *   are the auditable thing (premium inputs, decision, exclusions, terms);
   * - determinism is the pricing module's: the same inputs mint the same
   *   `quoteId`, so a re-quote is detectable as one, never mistaken for a
   *   re-price. The returned `marker: true` tag says the quote is on-chain;
   *   the marker payload is the quote verbatim.
   */
  async slaQuote(input: {
    /** The grade being priced — must be one of the `ProofGrade` vocabulary. */
    readonly grade: ProofGrade
    /** The confidence the evidence reached; omit for the grade's own default. */
    readonly confidence?: number
    /** What a breach would cost the underwriter, in `rate.currency`. */
    readonly coverageAmount: number
    readonly rate: RateCard
    readonly deductible?: number
    readonly minPremium?: number
  }): Promise<SlaQuote & { marker: true }> {
    if (typeof input.grade !== 'string' || !DELEGATION_GRADES.has(input.grade)) {
      throw new Error(`slaQuote: grade must be one of ${[...DELEGATION_GRADES].join(' | ')} — got ${JSON.stringify(input.grade)}`)
    }
    if (input.confidence !== undefined
      && (typeof input.confidence !== 'number' || !Number.isFinite(input.confidence)
        || input.confidence < 0 || input.confidence > 1)) {
      throw new Error('slaQuote: confidence must be a finite number in [0, 1] when provided')
    }
    if (typeof input.coverageAmount !== 'number' || !Number.isFinite(input.coverageAmount) || input.coverageAmount <= 0) {
      throw new Error('slaQuote: coverageAmount must be a finite positive number')
    }
    if (input.deductible !== undefined
      && (typeof input.deductible !== 'number' || !Number.isFinite(input.deductible) || input.deductible < 0)) {
      throw new Error('slaQuote: deductible must be a finite non-negative number when provided')
    }
    if (input.minPremium !== undefined
      && (typeof input.minPremium !== 'number' || !Number.isFinite(input.minPremium) || input.minPremium < 0)) {
      throw new Error('slaQuote: minPremium must be a finite non-negative number when provided')
    }
    this.assertRateCard(input.rate, 'slaQuote')
    // M-03: a quote prices evidence that EXISTS. `grade`/`confidence` are
    // caller inputs, so before anything is priced or written, the chain must
    // carry a `proof/verified` marker that actually reached this grade —
    // otherwise the `economics/quote` marker is a free forgery: "proven at
    // p=0.999" minted by whoever called the verb, underwritten by nothing.
    // The anchor is the LATEST marker carrying the quoted grade (a grade is
    // quotable as long as the chain once honestly reached it; recency of the
    // evidence itself is the underwriter's judgement, priced by confidence).
    const graded = (await this.markersWith('proof/verified'))
      .filter(m => m.grade === input.grade)
    if (graded.length === 0) {
      throw new Error(
        `slaQuote: no proof/verified marker on this chain carries grade "${input.grade}" — an SLA prices evidence the chain reached, not a grade the caller asserts (run a verification first)`,
      )
    }
    const quote = priceSla({
      grade: input.grade,
      ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
      coverageAmount: input.coverageAmount,
      rate: input.rate,
      ...(input.deductible !== undefined ? { deductible: input.deductible } : {}),
      ...(input.minPremium !== undefined ? { minPremium: input.minPremium } : {}),
    })
    await this.store.mark('economics/quote', { ...quote })
    return { ...quote, marker: true as const }
  }

  /**
   * v0.21: rate-card defense shared by every economics-wired verb. A price
   * card is host input at a trust boundary, so it is refused BY VALUE —
   * currency must be the one the ledger speaks, and every rate must be a
   * finite non-negative number. Negative prices are not "discounts": a
   * negative computePerMs makes spending money REDUCE cost, and a negative
   * humanReviewPerItem pays the ledger for consuming review.
   */
  private assertRateCard(rate: RateCard, verb: string): void {
    if (rate === null || typeof rate !== 'object') {
      throw new Error(`${verb}: rate must be a RateCard object { currency, computePerMs, humanReviewPerItem? }`)
    }
    if (rate.currency !== 'USD') {
      throw new Error(`${verb}: rate.currency must be 'USD' — got ${JSON.stringify(rate.currency)}`)
    }
    if (typeof rate.computePerMs !== 'number' || !Number.isFinite(rate.computePerMs) || rate.computePerMs < 0) {
      throw new Error(`${verb}: rate.computePerMs must be a finite non-negative number`)
    }
    if (rate.humanReviewPerItem !== undefined
      && (typeof rate.humanReviewPerItem !== 'number' || !Number.isFinite(rate.humanReviewPerItem)
        || rate.humanReviewPerItem < 0)) {
      throw new Error(`${verb}: rate.humanReviewPerItem must be a finite non-negative number when provided`)
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
      '2. Replace the placeholder assertion with a real executable test of the claim: exit code 0 AND a final SYNTHETIC: PASS line prove it — a passing exit code without the protocol line is recorded as an error.',
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
      // M19a: the model-facing tool is `proof_conjure` (the request opener);
      // the old text named a tool that does not exist.
      throw new Error(`conjureRun: no synthetic/requested marker for claimId ${claimId} with entry ${input.entry} — call proof_conjure first`)
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
    let record = batch.records[0]
    if (record === undefined) throw new Error('conjureRun: the verification runner produced no record')
    // M12: exit code 0 is only half of the scaffold contract — the other half
    // is the protocol line. A script that exits clean without saying
    // `SYNTHETIC: PASS` proved nothing (an empty script, a bare
    // `process.exit(0)`), so the record is rewritten to `error` with the
    // breach named on the output's first line, and the re-addressing below
    // folds the honest verdict into the evidence's own address. Non-pass
    // records (fail/timeout/…) keep their status: their protocol story is
    // already told by their outcome.
    if (record.status === 'pass' && !hasSyntheticProtocolPassLine(record.outputHead)) {
      record = {
        ...record,
        status: 'error',
        outputHead: `${SYNTHETIC_PROTOCOL_NOTE}\n${record.outputHead}`,
      }
    }
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
      // H-32/N-4: position-based suspect test (see activeAttestationsAll) —
      // a marker the chain no longer corroborates is not read as fact here.
      const lines = await this.fs.readLines(this.logPath)
      for (let i = 0; i < lines.length; i += 1) {
        let envelope: { kind?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(lines[i]!) as { kind?: unknown; payload?: unknown }
        } catch {
          continue
        }
        if (envelope?.kind !== 'marker') continue
        const payload = envelope.payload as { label?: unknown } | undefined
        if (payload?.label !== label) continue
        if (isSuspectMarker(lines, i)) continue
        out.push(payload as Record<string, unknown>)
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
      // M-01: the re-dispatch gate re-screens the CURRENT bytes. Screening
      // ran once, at conjureRun, over the bytes that existed then; a script
      // rewritten since (the forbidden import added after the fact) must be
      // refused HERE too — "a script importing … is refused at screening and
      // never runs" is a promise about every execution, not the first one.
      // The refusal is a chain fact, loudly: the spec simply does not join
      // the pool, and the marker says why.
      const source = await this.fs.readFile(`${this.syntheticRoot()}/${request.entry}`)
      if (source !== undefined) {
        const screening = screenScript(source)
        if (!screening.ok) {
          await this.store.mark('synthetic/refused', {
            claimId: request.claimId,
            entry: request.entry,
            findings: [...screening.findings],
          })
          continue
        }
      }
      out.push(syntheticSpec(request, this.options.syntheticDir, this.options.syntheticTimeoutMs))
    }
    return out
  }

  /**
   * M-01: pin the executed script's digest onto a re-dispatched synthetic
   * record. `conjureRun` addresses its record over the script's own bytes
   * (`Evidence.synthetic`); the verify re-dispatch path used to lose that —
   * the record joined the chain without saying WHICH body produced it, and
   * the content-addressing guarantee ("two runs with the same outcome but
   * different scripts are two different pieces of evidence") silently held
   * only for the first execution. This re-reads the entry at collection time
   * and re-addresses exactly like `conjureRun`/`attachEvidenceCoverage` do.
   */
  private async reattachSyntheticMeta(
    records: readonly Evidence[],
    pool: readonly CheckSpec[],
  ): Promise<Evidence[]> {
    const syntheticIds = new Set(pool.filter(s => s.source === 'synthetic').map(s => s.id))
    const recordsToAttach = records.filter(r => syntheticIds.has(r.checkId))
    if (recordsToAttach.length === 0) return [...records]
    // The synthetic specs carry their entry as part of the command — re-derive
    // it from the spec pool rather than re-reading the marker channel.
    const entryByCheckId = new Map<string, string>()
    for (const s of pool) {
      if (s.source !== 'synthetic') continue
      const entry = s.command[s.command.length - 1]
      if (typeof entry === 'string') entryByCheckId.set(s.id, entry)
    }
    const metaByCheckId = new Map<string, SyntheticEvidenceMeta>()
    for (const record of recordsToAttach) {
      const entry = entryByCheckId.get(record.checkId)
      if (entry === undefined) continue
      const source = await this.fs.readFile(`${this.syntheticRoot()}/${entry}`)
      if (source === undefined) continue
      metaByCheckId.set(record.checkId, {
        scriptDigest: sha256(source),
        sandbox: 'screened-subprocess',
        screened: [],
        author: 'agent',
      })
    }
    if (metaByCheckId.size === 0) return [...records]
    return records.map(record => {
      const meta = metaByCheckId.get(record.checkId)
      if (meta === undefined || record.synthetic !== undefined) return record
      const { evidenceId: plainAddress, ...body } = record
      void plainAddress
      return { ...body, synthetic: meta, evidenceId: addressOf({ ...body, synthetic: meta }) }
    })
  }

  // -- execution coverage (υ) ----------------------------------------------------

  /**
   * υ: create this run's coverage scratch directory — `${storeDir}/coverage/<clock
   * nonce>-<run sequence>` — or `undefined` when the mode injects nothing
   * (`off`). H-17: the directory is named per-run (clock nonce + a monotonic
   * sequence, so two same-millisecond runs cannot share staging) and CLEARED
   * before the run: any file that survives into collection was either written
   * during this run's window or is dropped with the whole run's coverage
   * (see `collectRunCoverage`). Staging identity is physical only — never any
   * hash material — so run identity stays a function of the evidence alone.
   * An mkdirp failure is swallowed: the children then fail to write their
   * profiles, collection finds no data, and observe mode degrades to basis
   * `'none'` — the honest answer, not a crashed verification.
   *
   * `spawnedAt` is the run's mtime floor: the clock reading taken before the
   * checked processes were dispatched, against which every collected profile
   * file's mtime is judged (H-17's forgery defense — a profile that predates
   * the run was planted, not produced).
   */
  private async prepareCoverageDir(): Promise<{ dir: string; spawnedAt: number } | undefined> {
    if (this.options.coverage === 'off') return undefined
    const dir = `${this.storeDir}/coverage/${this.clock.now()}-${++this.coverageRunSeq}`
    try {
      // H-17: clear-before-use. A leftover (or attacker-planted) tree from a
      // previous run must not survive into this run's collection window.
      await this.fs.removeDir?.(dir).catch(() => { /* staging; regeneration is cheap */ })
      await this.fs.mkdirp(dir)
    } catch {
      /* unwritable staging → no coverage data this run */
    }
    return { dir, spawnedAt: this.clock.now() }
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
   *      profile happened to contain"; a URL repeated across or within
   *      profiles enters the set once (a `Set` from the first line — the
   *      duplicate entry a forger pads a profile with buys nothing);
   *   3. attach the per-record coverage view (changed ∩ executed / changed −
   *      executed) by RE-ADDRESSING the record — π's synthetic precedent: the
   *      attachment is content-addressing material, so the enriched record is
   *      a different piece of evidence from the plain one and audit must be
   *      able to recompute exactly this address from the stored bytes;
   *   4. remove the scratch tree (best effort — `removeDir` is an optional
   *      FsPort capability; a MemoryFs without it is fine, `?.` and on we go);
   *   5. summarise the whole change set against the collected executed sets.
   *
   * H-17 forgery defense, before step 2 touches a single byte: the checked
   * process can read `NODE_V8_COVERAGE` from its own environment and write a
   * forged profile itself, so "a file in the directory" is not evidence. Two
   * windows bound what collection admits — the profile's mtime must fall in
   * [spawnedAt, collectedAt] (a file stamped before the run was dispatched
   * was planted, not produced; one stamped after collection is not this
   * run's either) — and the staging tree was cleared before the run, so a
   * pre-existing file had to be written DURING this run's window to count.
   * ONE untrusted profile poisons the whole run's coverage (dropped entire,
   * records pass through unattached, the summary degrades to basis 'none')
   * and the fact lands on the chain as `coverage/untrusted`: half-trusted
   * coverage is exactly the shape a forger would want to keep.
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
    staging: { dir: string; spawnedAt: number } | undefined,
  ): Promise<{ records: Evidence[]; summary: CoverageSummary | undefined }> {
    if (staging === undefined) return { records: [...records], summary: undefined }
    const collectedAt = this.clock.now()
    const executedSets: string[][] = []
    const out: Evidence[] = []
    let untrustedProfiles = 0
    for (const record of records) {
      // Only a decisively passing check speaks for execution coverage: a fail
      // already sank the grade on its own, and non-decisive outcomes may have
      // died before V8 flushed any profile — half-execution proves nothing.
      if (record.status !== 'pass') {
        out.push(record)
        continue
      }
      // N-3 (red team): under `require` — the strict tier — coverage vouched
      // by a SYNTHETIC check does not satisfy the gate. In-run profile
      // forgery is undetectable in general (H-17's honest limit: the window
      // bounds its ends, not its interior); what `require` can refuse is the
      // compounding interested party — a check the claiming agent authored
      // vouching for its own execution. The strict tier accepts execution
      // witnesses it did not have to trust the claim's author for. Observe
      // mode keeps counting synthetic coverage — it only narrates.
      if (this.options.coverage === 'require' && record.synthetic !== undefined) {
        out.push(record)
        continue
      }
      const dir = `${staging.dir}/${sha256(record.checkId).slice(0, 16)}`
      const executed = new Set<string>()
      let dataFound = false
      for (const name of (await this.fs.readDir(dir)) ?? []) {
        if (!/^coverage-.*\.json$/.test(name)) continue
        const path = `${dir}/${name}`
        // H-17: the mtime window — see the method note. `stat` is a mandatory
        // FsPort capability; a file whose stat cannot even be read was not
        // produced by an honest V8 flush either.
        const stat = await this.fs.stat(path)
        if (stat === undefined || stat.mtimeMs < staging.spawnedAt || stat.mtimeMs > collectedAt) {
          untrustedProfiles += 1
          continue
        }
        const content = await this.fs.readFile(path)
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
    // H-17: one untrusted profile drops the WHOLE run's coverage — the
    // re-addressed attachments above are unwound, the summary degrades to
    // basis 'none', and the marker names the fact. (Basis 'none' under
    // `observe` gates nothing, under `require` it is the disqualification —
    // the conservative direction either way.)
    if (untrustedProfiles > 0) {
      await this.store.mark('coverage/untrusted', {
        reason: 'profile file mtime outside this run\'s window — coverage untrusted, collection dropped',
        rejected: untrustedProfiles,
        windowMs: collectedAt - staging.spawnedAt,
      })
      // Staging is disposable by contract: collected, then removed. A failure
      // here costs nothing — the next run re-creates the tree.
      await this.fs.removeDir?.(staging.dir).catch(() => { /* staging; nothing to salvage */ })
      return { records: [...records], summary: summarizeCoverage({ changed: [...changed], executedSets: [] }) }
    }
    // Staging is disposable by contract: collected, then removed. A failure
    // here costs nothing — the next run re-creates the tree. `removeDir` is an
    // optional FsPort capability; a MemoryFs without it is fine, `?.` and on.
    await this.fs.removeDir?.(staging.dir).catch(() => { /* staging; nothing to salvage */ })
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

  // -- responsibility DAG (v0.19) ----------------------------------------------

  /**
   * v0.19: delegate a task — mint the obligation and commit it to the chain
   * BEFORE any work starts. The `delegation/created` marker payload IS the
   * obligation (a chain fact, exactly like `synthetic/requested`): identity,
   * claim, acceptance criteria, issuing workspace, timestamp.
   *
   * `taskId` is an engine-minted sequence number (`task-<n>`, n =
   * `delegation/created` markers already on chain + 1) — deliberately not
   * content-derived, because a responsibility is an act, not a text:
   * delegating the same claim twice is two obligations.
   *
   * `parentTaskId`, when given, must name an obligation already on the
   * chain (edges only point backwards in time), and the resulting edge set
   * is run through `detectCycles` as defense in depth — the parent-must-
   * already-exist rule already makes a cycle unreachable through this verb
   * alone, but the day any other writer joins the graph, the backstop turns
   * a silent cycle into a loud refusal.
   */
  async delegateTask(input: {
    claim: string
    parentTaskId?: string
    acceptance?: string
  }): Promise<DelegateTaskResult> {
    if (typeof input.claim !== 'string' || input.claim.trim().length === 0) {
      throw new Error('delegateTask: claim must be a non-empty string')
    }
    if (input.parentTaskId !== undefined
      && (typeof input.parentTaskId !== 'string' || input.parentTaskId.length === 0)) {
      throw new Error('delegateTask: parentTaskId must be a non-empty string when provided')
    }
    if (input.acceptance !== undefined && typeof input.acceptance !== 'string') {
      throw new Error('delegateTask: acceptance must be a string when provided')
    }
    const existing = await this.delegationObligations()
    if (input.parentTaskId !== undefined && !existing.some(o => o.taskId === input.parentTaskId)) {
      throw new Error(`delegateTask: parentTaskId "${input.parentTaskId}" does not exist — delegate the parent task first`)
    }
    // The RAW marker count defines the sequence (not the parsed-obligation
    // count): a malformed created-marker still consumed a place on the chain,
    // and a taskId colliding with a marker we could not parse would be worse
    // than a gap in the numbering.
    const taskId = `task-${(await this.markersWith('delegation/created')).length + 1}`
    // An acceptance that says nothing attaches nothing (M19b discipline: no
    // empty fields are minted for parameters that were not meaningfully set).
    const acceptance = input.acceptance !== undefined ? markerText(input.acceptance) : undefined
    const obligation: TaskObligation = {
      v: 1,
      taskId,
      ...(input.parentTaskId !== undefined ? { parentTaskId: input.parentTaskId } : {}),
      claim: input.claim,
      ...(acceptance !== undefined ? { acceptance } : {}),
      issuedAt: new Date(this.clock.now()).toISOString(),
      // The workspace that opened the obligation is THIS engine's stable
      // identity — the same key checkpoints, anchors and PTL entries carry.
      issuedByWorkspace: this.workspaceKey,
    }
    const cycles = detectCycles([...existing, obligation])
    if (cycles.length > 0) {
      throw new Error(`delegateTask: adding this delegation would close a cycle in the responsibility graph (${cycles.join(' <- ')})`)
    }
    await this.store.mark('delegation/created', { ...obligation })
    return { taskId, obligationId: obligationIdOf(obligation), obligation }
  }

  /**
   * v0.19: submit a delegation result — the child side of the handshake.
   * The bundle is adjudicated by `verifyBundle` (the APP/1.1 authority — see
   * the import note), and what it proved becomes the `delegation/verdict`
   * marker's submission: who submitted, the bundle fingerprint the verdict
   * anchors to, what grade the child CLAIMS, and whether the artifact itself
   * verified.
   *
   * H-05 trust root: `verifyBundle`'s six checks are all self-consistency
   * checks, so the engine additionally demands the bundle's evidence chain
   * carry a SIGNED checkpoint — naming the obligation minter's anchor key
   * when this chain has one (the minter's anchor is the root the child's
   * proof must answer to), or at least any well-formed signed checkpoint
   * when the minter never anchored (an anchor-less deployment still refuses
   * wholly unsigned evidence, which an empty-log forger cannot supply).
   * Unanchored evidence caps the derived grade at 'unproven' and the
   * submission carries the pinned problem 'bundle evidence not anchored'.
   *
   * `claimedGrade` honesty boundary: the engine cannot re-run the child's
   * checks (they ran in another workspace, against another baseline), so the
   * default derivation is deliberately two-valued — an anchored, clean
   * bundle carrying a baseline is what the child CALLS 'proven'; anything
   * less derives 'no-baseline' (or 'unproven' unanchored). Every finer grade
   * ('unproven', 'stale', 'regressed') is a workspace-local judgment the
   * submitter may DECLARE explicitly; a declared grade the artifact's
   * evidence exceeds is capped to what the evidence derives, with the
   * discrepancy recorded on the submission, and a declared 'proven' over an
   * artifact that FAILED verification is left for the composer (core/
   * obligations.ts) to charge as forgery — the harsher, more honest verdict.
   *
   * The returned `composed` verdict is pure delegation synthesis — the
   * own-workspace grade map is EMPTY. The parent's own evidence (its local
   * `verify()` outcome) enters through `taskVerdict`, which derives it from
   * the chain rather than believing the caller.
   */
  async submitDelegation(input: {
    taskId: string
    bundle: unknown
    byWorkspace?: string
    claimedGrade?: ProofGrade
  }): Promise<SubmitDelegationResult> {
    if (typeof input.taskId !== 'string' || input.taskId.length === 0) {
      throw new Error('submitDelegation: taskId must be a non-empty string')
    }
    if (input.byWorkspace !== undefined
      && (typeof input.byWorkspace !== 'string' || input.byWorkspace.trim().length === 0)) {
      throw new Error('submitDelegation: byWorkspace must be a non-empty string when provided')
    }
    if (input.claimedGrade !== undefined && !DELEGATION_GRADES.has(input.claimedGrade)) {
      throw new Error(`submitDelegation: claimedGrade must be one of ${[...DELEGATION_GRADES].join(' | ')} — got ${JSON.stringify(input.claimedGrade)}`)
    }
    const obligationExists = (await this.delegationObligations()).some(o => o.taskId === input.taskId)
    if (!obligationExists) {
      throw new Error(`submitDelegation: no delegation/created marker for taskId ${input.taskId} — call delegateTask first`)
    }
    // Shape-narrowed before anything touches it: `verifyBundle` defends its
    // own reads, but the engine reads manifest.files and manifest.workspaceKey
    // itself (fingerprint, child identity) and must not reach into shapes it
    // has not proven.
    const bundle = delegationBundleOf(input.bundle)
    const verification = await verifyBundle(bundle)
    const artifactVerified = verification.problems.length === 0
      && verification.manifestOk
      && verification.chainBreaks.length === 0
    // H-05: the artifact's TRUST ROOT. Every `verifyBundle` check so far is a
    // self-consistency check — digests match the manifest, the chain walks,
    // the anchor agrees with the chain the bundle itself carries — so a
    // bundle built from scratch out of whole cloth verifies "clean", and a
    // self-reported proven over it composed to a zero-blocker proven. The
    // missing question is: does the bundle's evidence chain carry a SIGNED
    // checkpoint naming the key the obligation's minter anchored? A signature
    // is the one thing an empty-log forger cannot self-supply.
    const walk = walkChain(bundleLogLines(bundle.files[EVIDENCE_FILE] ?? ''))
    const malformed = new Set(walk.malformedCheckpoints)
    const signedKeyIds = new Set(walk.checkpoints
      .filter(cp => cp.sig !== null && cp.keyId !== null && !malformed.has(cp.index))
      .map(cp => cp.keyId as string))
    const anchorKey = await this.obligationAnchorKeyId()
    const evidenceAnchored = anchorKey !== undefined
      ? signedKeyIds.has(anchorKey)
      : signedKeyIds.size > 0
    // The grade the bundle's evidence can actually support: proven only when
    // the artifact is self-consistent, carries a baseline AND is anchored to
    // the minter's key; no-baseline for an anchored bundle without one; and
    // capped at unproven — no matter how clean the self-consistency — when
    // the evidence has no verifiable root.
    const derivedGrade: ProofGrade = !evidenceAnchored
      ? 'unproven'
      : artifactVerified && verification.baselineId !== undefined ? 'proven' : 'no-baseline'
    const problems: string[] = []
    if (!evidenceAnchored) {
      problems.push(anchorKey !== undefined
        ? `bundle evidence not anchored: no signed checkpoint on the bundle's chain names the obligation anchor key ${anchorKey}`
        : 'bundle evidence not anchored: the issuing chain carries no anchor key, and the bundle has no signed checkpoint at all')
    }
    // `claimedGrade` honesty boundary: a claim that exceeds what the evidence
    // derives is capped and the discrepancy recorded — never believed, never
    // silently dropped. (A claim over an artifact that FAILED verification is
    // left exactly as declared: the composer's forgery charge is the harsher
    // and more honest verdict there, and capping would only launder it.)
    let claimedGrade: ProofGrade = input.claimedGrade ?? derivedGrade
    if (artifactVerified && gradeRank(claimedGrade) > gradeRank(derivedGrade)) {
      problems.push(`claimedGrade ${claimedGrade} exceeds the bundle evidence (${derivedGrade})`)
      claimedGrade = derivedGrade
    }
    problems.push(...verification.problems)
    const bounded = problems.slice(0, 5)
    const submission: DelegationSubmission = {
      childWorkspace: input.byWorkspace ?? bundle.manifest.workspaceKey,
      bundleRoot: bundleFingerprint(bundle.manifest.files),
      claimedGrade,
      artifactVerified,
      ...(bounded.length > 0 ? { problems: bounded } : {}),
      submittedAt: new Date(this.clock.now()).toISOString(),
    }
    await this.store.mark('delegation/verdict', { taskId: input.taskId, submission })
    // Composed over the WHOLE rebuilt graph — the marker above is part of it,
    // so the returned verdict already includes this submission.
    const composed = composeTaskVerdict(input.taskId, await this.delegationGraph(), new Map<string, ProofGrade>())
    return { submission, composed }
  }

  /**
   * v0.19: compose a task's verdict over the whole responsibility DAG
   * rebuilt from the chain (`delegation/created` + `delegation/verdict` +
   * `delegation/waive`).
   *
   * H-11: `ownGrade` is a DECLARATION, never a measurement. The composed
   * verdict's own-workspace leg derives from the chain — the latest
   * `proof/verified` marker's grade, the freshest locally-earned verdict
   * this engine itself wrote — and the caller's self-report can only say
   * less than the evidence, never more: a report that exceeds the derived
   * grade is recorded (returned as `discrepancies`, echoed into the composed
   * blockers) and the derived grade stands. With no marker on the chain
   * there is no own evidence at all: a self-reported 'proven' is a
   * discrepancy and the composition proceeds pure-delegation, judged by the
   * children's submissions alone.
   *
   * `cycles` is the defense-in-depth report: empty on any chain this engine
   * alone wrote to, populated the moment a foreign edge closed a loop.
   */
  async taskVerdict(input: { taskId: string; ownGrade?: ProofGrade }): Promise<TaskVerdictResult> {
    if (typeof input.taskId !== 'string' || input.taskId.length === 0) {
      throw new Error('taskVerdict: taskId must be a non-empty string')
    }
    if (input.ownGrade !== undefined && !DELEGATION_GRADES.has(input.ownGrade)) {
      throw new Error(`taskVerdict: ownGrade must be one of ${[...DELEGATION_GRADES].join(' | ')} — got ${JSON.stringify(input.ownGrade)}`)
    }
    const nodes = await this.delegationGraph()
    if (!nodes.some(n => n.obligation.taskId === input.taskId)) {
      throw new Error(`taskVerdict: taskId ${input.taskId} does not exist on this chain — delegateTask first`)
    }
    const cycles = detectCycles(nodes.map(n => n.obligation))
    // H-11: the own-workspace leg, derived from the chain's own latest
    // verdict — structurally read (the marker channel is untrusted input
    // like every other log reader here).
    const verdictMarkers = await this.markersWith('proof/verified')
    const latest = verdictMarkers.length > 0 ? verdictMarkers[verdictMarkers.length - 1] : undefined
    const derived: ProofGrade | undefined = typeof latest?.grade === 'string'
      && DELEGATION_GRADES.has(latest.grade)
      ? latest.grade as ProofGrade
      : undefined
    const discrepancies: string[] = []
    if (input.ownGrade !== undefined) {
      if (derived !== undefined && gradeRank(input.ownGrade) > gradeRank(derived)) {
        discrepancies.push(`ownGrade self-report '${input.ownGrade}' exceeds the chain's evidence-derived grade '${derived}' — the derived grade stands`)
      } else if (derived === undefined && gradeRank(input.ownGrade) > 1) {
        discrepancies.push(`ownGrade self-report '${input.ownGrade}' has no proof/verified marker on this chain to stand on — no own evidence exists to lift`)
      }
    }
    const ownGrades = derived !== undefined
      ? new Map<string, ProofGrade>([[input.taskId, derived]])
      : new Map<string, ProofGrade>()
    const composed = composeTaskVerdict(input.taskId, nodes, ownGrades)
    return {
      composed: discrepancies.length > 0
        ? { ...composed, blockers: [...composed.blockers, ...discrepancies.map(d => `${input.taskId}: ${d}`)] }
        : composed,
      nodes,
      cycles,
      ...(discrepancies.length > 0 ? { discrepancies } : {}),
    }
  }

  /**
   * v0.19: waive a task's obligation — record the risk acceptance, nothing
   * more. The engine only keeps the books: whether a waiver may lift a
   * verdict is the composer's judgment (core/obligations.ts), and a waiver
   * over a FORGED or REGRESSED child is recorded here exactly like any
   * other — the composition layer is the one that refuses it. `by` and
   * `reason` are mandatory and non-empty: an anonymous or unexplained
   * acceptance of risk is not an acceptance, it is an erasure.
   *
   * H-10: the acceptance itself must be AUTHORIZED. `by` names the party
   * accepting the risk, and the only parties who may are the OBLIGATION'S
   * ISSUER (`issuedByWorkspace` — the workspace that opened the obligation
   * owns the risk of leaving it unmet) or this host when it holds the
   * anchor key (the operator of the chain the obligation was minted on).
   * Anyone else's waiver is refused loudly AND recorded: a rejected
   * risk-acceptance attempt is itself a fact the chain should keep.
   */
  async waiveDelegation(input: { taskId: string; by: string; reason: string }): Promise<void> {
    if (typeof input.taskId !== 'string' || input.taskId.length === 0) {
      throw new Error('waiveDelegation: taskId must be a non-empty string')
    }
    if (typeof input.by !== 'string' || input.by.trim().length === 0) {
      throw new Error('waiveDelegation: by must be a non-empty string')
    }
    if (typeof input.reason !== 'string' || input.reason.trim().length === 0) {
      throw new Error('waiveDelegation: reason must be a non-empty string')
    }
    const obligation = (await this.delegationObligations()).find(o => o.taskId === input.taskId)
    if (obligation === undefined) {
      throw new Error(`waiveDelegation: no delegation/created marker for taskId ${input.taskId}`)
    }
    // H-10: authenticate the acceptor before the books are opened.
    const by = input.by.trim()
    if (by !== obligation.issuedByWorkspace && !(await this.holdsAnchorKey())) {
      await this.store.mark('delegation/waive-refused', {
        taskId: input.taskId,
        by: by.slice(0, 200),
        issuedByWorkspace: obligation.issuedByWorkspace,
      })
      throw new Error(
        `waiveDelegation: "${by.slice(0, 200)}" may not waive ${input.taskId} — only the issuing workspace `
        + `(${obligation.issuedByWorkspace}) or the holder of its anchor key may accept this risk`,
      )
    }
    await this.store.mark('delegation/waive', {
      taskId: input.taskId,
      by: by.slice(0, 200),
      reason: input.reason.trim().slice(0, 200),
      at: new Date(this.clock.now()).toISOString(),
    })
  }

  /**
   * v0.19: every `TaskObligation` on the chain, in log order. Malformed
   * `delegation/created` payloads mint nothing (the `syntheticRequestOf`
   * rule) — but note `delegateTask` still counts them for the sequence, so
   * a skipped marker costs a taskId number, never a collision.
   */
  private async delegationObligations(): Promise<TaskObligation[]> {
    const out: TaskObligation[] = []
    for (const payload of await this.markersWith('delegation/created')) {
      const obligation = obligationOf(payload)
      if (obligation !== undefined) out.push(obligation)
    }
    return out
  }

  /**
   * v0.19: rebuild the full responsibility DAG from the chain — obligations
   * from `delegation/created`, the LATEST submission per task from
   * `delegation/verdict` (log order, so a re-submission overwrites its
   * predecessor — the appeal discipline attestations follow), and the LATEST
   * waiver from `delegation/waive`. Markers that cannot prove their shape,
   * and verdict/waive markers naming unknown tasks, are skipped: they can
   * neither mint obligations nor mutate the ones that exist.
   */
  private async delegationGraph(): Promise<DagNode[]> {
    const nodes = new Map<string, DagNode>()
    for (const obligation of await this.delegationObligations()) {
      nodes.set(obligation.taskId, { obligation })
    }
    for (const payload of await this.markersWith('delegation/verdict')) {
      const { taskId, submission } = payload as Record<string, unknown>
      if (typeof taskId !== 'string') continue
      const parsed = submissionOf(submission)
      const node = nodes.get(taskId)
      if (parsed === undefined || node === undefined) continue
      nodes.set(taskId, { ...node, submission: parsed })
    }
    for (const payload of await this.markersWith('delegation/waive')) {
      const { taskId, by, reason, at } = payload as Record<string, unknown>
      if (typeof taskId !== 'string' || typeof by !== 'string'
        || typeof reason !== 'string' || typeof at !== 'string') continue
      const node = nodes.get(taskId)
      if (node === undefined) continue
      nodes.set(taskId, { ...node, waiver: { by, reason, at } })
    }
    return [...nodes.values()]
  }

  /**
   * H-05: the trust root a submitted bundle's evidence must answer to — the
   * keyId of THIS workspace's anchor (the obligation minter's out-of-band
   * root), falling back to the key our own chain's last signed checkpoint
   * names (the anchor mirrors exactly that checkpoint, so the two agree on
   * any honest deployment; the fallback keeps anchor-less-but-signed hosts
   * demanding *some* signature instead of nothing). `undefined` = this
   * deployment has no key at all, and the weaker "any signed checkpoint"
   * rule applies — still strictly more than the nothing v0.21 demanded.
   */
  private async obligationAnchorKeyId(): Promise<string | undefined> {
    if (this.anchorPath !== undefined) {
      const raw = await this.fs.readFile(this.anchorPath)
      if (raw !== undefined) {
        const anchor = parseAnchor(raw)
        if (anchor !== undefined && anchor.keyId !== '') return anchor.keyId
      }
    }
    return (await this.store.latestSignedCheckpoint())?.keyId
  }

  /**
   * H-10: does THIS host hold the anchor key? The one authorization besides
   * the issuing workspace's name: an operator on the machine that holds the
   * key the anchor names can accept the risk of the obligations that key's
   * chain minted. No signer wired, no anchor deployed, an anchor that will
   * not parse, or a different key — all answer false, the conservative
   * direction for a risk-acceptance verb.
   */
  private async holdsAnchorKey(): Promise<boolean> {
    if (this.signerProvider === undefined || this.anchorPath === undefined) return false
    const raw = await this.fs.readFile(this.anchorPath)
    if (raw === undefined) return false
    const anchor = parseAnchor(raw)
    if (anchor === undefined || anchor.keyId === '') return false
    try {
      const signer = await this.signerProvider()
      return signer !== undefined && signer.keyId === anchor.keyId
    } catch {
      return false
    }
  }

  // -- training export (v0.20) ----------------------------------------------------

  /**
   * v0.20: distil the evidence chain into an RL/SFT training dataset
   * (`dsh-training/1`). The engine owns the seam — everything below is chain
   * state translated into `DistillInput`; the distillation itself is
   * `core/training.ts`'s.
   *
   * - **audit first (H-13)** — the export REFUSES a chain that fails its own
   *   integrity audit (`store.audit()`), loudly, before any sample is
   *   distilled: a dataset is "no annotator graded and no model
   *   self-reported" only as long as the bytes it distils from are the bytes
   *   the chain committed to. A tampered log would otherwise distil into a
   *   perfectly self-consistent poisoned dataset.
   * - **records** — the store's log SLICED to the current baseline's anchor
   *   (H-13): only records produced AFTER the anchoring batch enter the
   *   dataset. The anchoring batch itself is an observation of the OLD state
   *   — self-comparing it against the baseline it built used to mint
   *   reward-1.0 positive samples out of thin air (the self-proof loop), and
   *   weeks-old records paired with today's changedPaths used to read as
   *   "this change held" across a time window that never happened.
   * - **baselineVerdicts** — the loaded baseline's checks folded into the
   *   verdict vocabulary. `Baseline.checks` holds evidence RECORDS (not
   *   verdicts), so each is narrowed through `verdictOf(record, record)`: the
   *   self-comparison yields `still-passing` for a decisive pass,
   *   `still-failing` for a decisive fail and `indeterminate` for anything
   *   non-decisive — exactly "what the baseline believed about this check".
   * - **changedPaths** — the caller's explicit set (canonicalised) or, by
   *   default, the latest `proof/verified` marker's changed list; our markers
   *   record the count, so the honest default is no context (see
   *   `markerChangedPaths`).
   * - **provenance** — per-path attribution from the same marker, when the
   *   payload carries it; absent → distillation runs unfiltered (see
   *   `markerProvenance`). The manifest's `provenanceFilter` records the
   *   REQUESTED value either way.
   *
   * Idempotent re-runs (H-14): the full sliced record set is handed to
   * distillation verbatim — same-content sample deduplication is the
   * distiller's (core/training.ts), so a green workspace re-verified N times
   * cannot water the reward table with N byte-identical "still-passing"
   * positives.
   *
   * `options.path`, when given, is CONFINED to the workspace (H-16): the path
   * must be workspace-relative — absolute paths and any `..` segment are
   * refused loudly, and both files (the JSONL samples, one `canonicalJson`
   * line each, and the single manifest document) land under the engine's
   * root through the fs port's atomic `writeFile`. An empty chain is a legal
   * export: zero counts, zero samples, anchor `{count: 0, head: ''}`.
   */
  async exportTrainingData(options: TrainingExportOptions = {}): Promise<TrainingExportResult> {
    // H-13: the audit gate. Refuse — loudly, writing nothing — rather than
    // distil a dataset whose integrity story cannot be told.
    const audit = await this.store.audit()
    if (!audit.ok || audit.chain.baselineTampered) {
      const reasons: string[] = []
      if (audit.corrupt.length > 0) reasons.push(`${audit.corrupt.length} corrupt record(s)`)
      if (audit.chain.breaks.length > 0) reasons.push(`${audit.chain.breaks.length} chain break(s)`)
      if (audit.chain.corruptLines?.length) reasons.push(`${audit.chain.corruptLines.length} corrupt line(s)`)
      if (audit.chain.badCheckpoints.length > 0) reasons.push(`${audit.chain.badCheckpoints.length} forged checkpoint signature(s)`)
      if (audit.chain.headMismatches.length > 0) reasons.push(`${audit.chain.headMismatches.length} head mismatch(es)`)
      if (audit.chain.malformedCheckpoints?.length) reasons.push(`${audit.chain.malformedCheckpoints.length} malformed checkpoint(s)`)
      if (audit.chain.unsignedCheckpoints.length > 0) reasons.push(`${audit.chain.unsignedCheckpoints.length} unsigned checkpoint(s) on a signed chain`)
      if (audit.chain.rewind) reasons.push('the log ends before the anchored high-water mark (rewind)')
      if (audit.chain.anchorMismatch) reasons.push('the anchor disagrees with the chain it anchors')
      if (audit.chain.anchorForged) reasons.push('the anchor file failed its own signature check')
      if (audit.chain.baselineTampered) reasons.push('the baseline file no longer matches its chain-recorded digest')
      throw new Error(
        `exportTrainingData: the evidence chain failed its integrity audit (${reasons.join('; ')}) `
        + '— refusing to distil a dataset from untrusted bytes',
      )
    }
    const fidelity: SampleFidelity = options.fidelity ?? 'private'
    const provenanceFilter: 'agent-only' | 'all' = options.provenanceFilter ?? 'agent-only'
    const allRecords = await this.store.all()
    const baseline = await this.store.loadBaseline()
    // H-13: slice to the anchoring batch. The baseline's LAST check record
    // marks the anchor position in the log; everything after it is post-
    // anchor behaviour this baseline judged. No baseline (or an anchor record
    // the log cannot find) keeps the honest subset: with no baseline there is
    // nothing to time-order against, and a baseline whose records vanished
    // from the log is the audit's problem, not a reason to guess an ordering.
    const anchorRecord = baseline !== undefined && baseline.checks.length > 0
      ? baseline.checks[baseline.checks.length - 1]
      : undefined
    const anchorIndex = anchorRecord === undefined
      ? -1
      : allRecords.findLastIndex(r => r.evidenceId === anchorRecord.evidenceId)
    const records = anchorIndex >= 0
      ? allRecords.slice(anchorIndex + 1)
      : anchorRecord === undefined
        ? allRecords
        : []
    const baselineVerdicts = new Map<string, CheckVerdict>()
    for (const record of baseline?.checks ?? []) {
      baselineVerdicts.set(record.checkId, verdictOf(record, record))
    }
    const markers = await this.markersWith('proof/verified')
    const latestMarker = markers.length > 0 ? markers[markers.length - 1] : undefined
    const markerPaths = markerChangedPaths(latestMarker)
    const changedPaths: readonly string[] = options.changedPaths !== undefined
      ? this.canonicalChanged(options.changedPaths)
      : markerPaths !== undefined
        ? [...new Set(markerPaths)].sort()
        : []
    const provenance = markerProvenance(latestMarker)
    const training = distillTrainingSet({
      records,
      baselineVerdicts,
      changedPaths,
      workspaceKey: this.workspaceKey,
      fidelity,
      // Handed over even when no provenance map could be recovered: F1's own
      // manifest records this value verbatim, and under 'agent-only' the
      // filter only fires on an `external` attribution it can actually see —
      // absent provenance means nothing to void, not a silently broader set.
      provenanceFilter,
      ...(provenance !== undefined ? { provenance } : {}),
      generatedAt: new Date(this.clock.now()).toISOString(),
      ...(options.license !== undefined ? { license: options.license } : {}),
    })
    const manifest: TrainingManifest = training.manifest
    const anchor = await this.trainingAnchor()
    if (options.path !== undefined) {
      // H-16: the export path is workspace-relative, no exceptions. The
      // checked-out workspace is the audited area; an export that could name
      // `../../evidence.jsonl` or an absolute host path would hand the
      // caller a write primitive the whole guard stack never sees.
      const rel = this.exportRelPath(options.path)
      const dir = dirnameRel(rel)
      if (dir.length > 0) await this.fs.mkdirp(`${this.root}/${dir}`)
      const lines = training.samples.map(sample => canonicalJson(sample))
      await this.fs.writeFile(`${this.root}/${rel}`, lines.length > 0 ? `${lines.join('\n')}\n` : '')
      await this.fs.writeFile(`${this.root}/${rel}.manifest.json`, `${canonicalJson(manifest)}\n`)
    }
    return { manifest, samples: training.samples, anchor }
  }

  /**
   * H-16: validate and normalise one caller-supplied export path to a
   * workspace-relative form. Refuses, loudly, on: empty paths, absolute
   * paths (drive letters, `/`-roots and — M-35's lesson — `\\server` UNC
   * roots), and ANY `..` segment (over-strict on purpose: a dotdot that
   * happens to re-enter the workspace is indistinguishable, at this trust
   * boundary, from one that escapes it, and the caller can always name the
   * direct spelling).
   */
  private exportRelPath(path: string): string {
    if (path.length === 0) {
      throw new Error('exportTrainingData: path must be a non-empty workspace-relative path')
    }
    if (isAbsolutePath(path)) {
      throw new Error(`exportTrainingData: path must be workspace-relative — absolute paths are refused (${JSON.stringify(path.slice(0, 80))})`)
    }
    if (path.replace(/\\/g, '/').split('/').includes('..')) {
      throw new Error('exportTrainingData: path must stay inside the workspace — ".." segments are refused; name the workspace-relative path directly')
    }
    const normalized = normalizeRel(path)
    if (normalized.length === 0) {
      throw new Error('exportTrainingData: path must name a file, not a directory')
    }
    // N-2 (red team): case is not a boundary — on the case-insensitive
    // filesystems most agents run on, `.PROOF/evidence.jsonl` IS the store,
    // and an export that truncates the evidence log destroys the very chain
    // that anchors the dataset. The comparison folds case, separators and
    // Win32 trailing-dot/space deformation — the same folds the adapter
    // guard's comparisons make.
    const foldHost = (p: string): string => p.replace(/\\/g, '/')
      .split('/')
      .map(segment => segment.replace(/[. ]+$/, '').toLowerCase())
      .filter(segment => segment.length > 0)
      .join('/')
    const foldedTarget = foldHost(`${this.root}/${normalized}`)
    const foldedStore = foldHost(this.storeDir)
    if (foldedStore.length > 0 && (foldedTarget === foldedStore || foldedTarget.startsWith(`${foldedStore}/`))) {
      throw new Error(
        `exportTrainingData: path resolves into the evidence store (${path}) — the dataset may not overwrite the chain that anchors it; export to a path outside the store`,
      )
    }
    return normalized
  }

  /**
   * v0.20: the export's chain anchor. Primary source is
   * `latestSignedCheckpoint` — the audit's own "best checkpoint" selection —
   * which yields {count, head} plus the signing key's id. Unsigned chains
   * (and signed deployments whose signer failed to load) fall back to a raw
   * `walkChain` over the log: the LAST well-formed checkpoint's {count, head}
   * with no keyId — the honest answer for a chain with no signature to name.
   * No checkpoint at all anchors at {0, ''}: an empty dataset over an empty
   * log, distinguishable from a checkpointed one by count alone.
   */
  private async trainingAnchor(): Promise<TrainingAnchor> {
    const signed = await this.store.latestSignedCheckpoint()
    if (signed !== undefined) {
      return { count: signed.payload.count, head: signed.payload.head, keyId: signed.keyId }
    }
    const walk = walkChain(await this.fs.readLines(this.logPath))
    const malformed = new Set(walk.malformedCheckpoints)
    const last = walk.checkpoints.findLast(cp => !malformed.has(cp.index))
    return last === undefined
      ? { count: 0, head: '' }
      : { count: last.payload.count, head: last.payload.head }
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
   *
   * H-32: markers the evidence layer flags `suspect` (bound to a chain
   * position the walk no longer corroborates) are EXCLUDED from the fusion
   * and counted instead — the count rides the boundary markers so the
   * withheld testimony stays visible in the narrative.
   */
  private async activeAttestationsAll(): Promise<{ active: Attestation[]; suspect: number }> {
    try {
      const payloads: unknown[] = []
      let suspect = 0
      // H-32/N-4: the suspect test is the evidence layer's POSITION check
      // (does this marker's headRef match its physical predecessor?), not a
      // field anyone could echo back — an appended attest twin contradicts
      // its position and never reaches the fusion.
      const lines = await this.fs.readLines(this.logPath)
      for (let i = 0; i < lines.length; i += 1) {
        let envelope: { kind?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(lines[i]!) as { kind?: unknown; payload?: unknown }
        } catch {
          continue
        }
        if (envelope?.kind !== 'marker') continue
        const payload = envelope.payload as { label?: unknown } | undefined
        if (payload?.label !== 'attest/jury' && payload?.label !== 'attest/human') continue
        if (isSuspectMarker(lines, i)) {
          suspect += 1
          continue
        }
        payloads.push(payload)
      }
      return { active: activeAttestations(payloads), suspect }
    } catch {
      // An unreadable log cannot veto verification — it simply has no
      // witnesses to fuse. (The log's own integrity is `audit()`'s charge.)
      return { active: [], suspect: 0 }
    }
  }

  /**
   * κ: Π attestationFactor over the active witnesses — the neutral 1 when
   * empty.
   *
   * M10: a human *endorsement* never enters the product. Endorsement is risk
   * acceptance, not a probability transfer — the machine path's
   * `fuseConfidence` keeps the number untouched for exactly that reason, and
   * the product used to contradict it: a B uphold at 0.99 certifies alone
   * (0.99^0.7 ≈ 0.993 ≥ 0.97), yet adding a human endorsement multiplied in
   * 0.95^0.9 ≈ 0.955 and *demoted* the claim to stale — backing a claim made
   * it worse, the exact inversion of what a Class C witness is for. Rejects
   * still multiply: the veto is a probability statement (the human asserts
   * the claim is false at their error rate) and keeps its full weight.
   */
  private attestationProduct(active: readonly Attestation[]): number {
    let product = 1
    for (const att of active) {
      if (att.kind === 'attest/human' && att.decision === 'endorse') continue
      product *= attestationFactor(att, this.trustWeights)
    }
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
   * factor: the check keeps its prior and stays counted as undecided — and
   * (H2) it stays IN the plan, because an unanswered check is unfinished, not
   * acquitted; a later wave may re-ask it. When everything still pending has
   * already been asked without getting an answer, the plan ends as
   * budget-starved, never as certified: a posterior that crossed the target
   * on priors alone certified nothing. Certification additionally demands
   * that the stopping wave itself produced at least one decisive record.
   */
  private async runBayesianSchedule(
    affected: readonly CheckSpec[],
    changed: readonly RelPath[],
    graph: DependencyGraph | undefined,
    snapshot: WorkspaceSnapshot,
    options: VerifyOptions,
    coverageDir?: string,
    /** H5: drifted checks, priced at the synthetic tier inside `priorsFor`. */
    drifted?: ReadonlySet<string>,
  ): Promise<{
    records: Evidence[]
    schedule: NonNullable<VerifyOutcome['schedule']>
    confidence: ConfidenceInput
    /**
     * v0.21: the claim probability at session start — Π priors over the plan,
     * snapshotted before wave one (the same `claimProbability` arithmetic the
     * stop conditions use, so the ledger's "before" and the scheduler's own
     * baseline are one number, not two that can drift).
     */
    priorProbability: number
    /**
     * v0.21: the FINAL claim probability — Π final factors (posteriors for
     * decisive checks, priors for everything the plan left resting). This is
     * exactly the number the report's `confidence` carries, by construction.
     */
    posteriorProbability: number
    /** v0.21: the plan's priors, for the ledger's per-check {prior, posterior} factors. */
    priors: ReadonlyMap<string, CheckPrior>
  }> {
    const priors = await this.priorsFor(affected, changed, graph, drifted)
    const target = this.options.certifyTarget
    const specById = new Map(affected.map(c => [c.id, c] as const))
    const factors = new Map<string, number>()
    for (const prior of priors.values()) factors.set(prior.checkId, prior.priorHealthy)
    const model: ClaimModel = { factors }
    // v0.21: the "before" number, priced once, before any wave can move it.
    const priorProbability = claimProbability(model)
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
    // H2: checks dispatched without receiving a decisive answer. They stay in
    // `pending` (unfinished, not acquitted), so a later wave can retry them;
    // this set is what keeps the retries from looping forever when every
    // attempt lands timeout/aborted/error/skipped.
    const attemptedNonDecisive = new Set<string>()

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
      let waveDecisive = 0
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
        if (isDecisiveStatus(record.status)) {
          // The check answered: it leaves the plan and its factor becomes
          // the posterior.
          waveDecisive += 1
          pending.delete(record.checkId)
          const prior = priors.get(record.checkId)
          if (prior === undefined) continue
          if (record.status === 'pass' || record.status === 'fail') {
            factors.set(record.checkId, posteriorHealthy(prior, record.status))
            if (record.status === 'fail') decisiveFail = true
          }
        } else {
          // H2: no answer (timeout/aborted/error/skipped) — the check stays
          // in the plan with its prior: undecided, not acquitted and not
          // condemned. Deleting it here is what let a later "certified" stop
          // rest on checks this run never actually heard from.
          attemptedNonDecisive.add(record.checkId)
        }
      }
      settled += batch.records.length

      // Early stops, in the design's priority order: certify, then blame,
      // then resources.
      //
      // H2: certification needs at least one decisive observation from THIS
      // wave. A posterior crossing the target on priors alone (every dispatch
      // this wave landed timeout/error/skip) certified nothing — the loop
      // continues, and the all-attempted guard below ends it honestly as
      // 'budget'.
      if (claimProbability(model) >= target && waveDecisive > 0) {
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
      // H2 dead-loop guard: everything still pending has already been
      // attempted without producing an answer — another wave would re-ask
      // the same silent checks and learn nothing. That is a starved run, and
      // it is reported as one ('budget'), never as a certification.
      if (pending.size > 0 && [...pending.keys()].every(id => attemptedNonDecisive.has(id))) {
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
      // v0.21: the trajectory the wave plan moved the claim through — from
      // the Π-priors snapshot above to the final factor product. (Equal to
      // the report's `confidence`, which `assembleProof` derives from the
      // same final factor map.)
      priorProbability,
      posteriorProbability: claimProbability(model),
      priors,
    }
  }

  /**
   * Priors over one affected set: history summarised from the whole evidence
   * log, priced with a quarter of the per-check timeout as the fallback cost
   * of a check that has never been observed.
   *
   * H-03: a drifted check's OLD-BODY history is not evidence for the new
   * body. The β discount used to be a one-shot rewrite while the learned
   * prior (≈0.836 after five green runs) kept compounding — a tampered
   * `"test": "node -e \"\""` borrowed the old body's green and one forged
   * pass crossed the default 0.97 target. Two moves close it:
   *
   * - **time-sliced history** — for every drifted id, only records stamped
   *   AFTER the chain first recorded that id's drift are summarised. First
   *   detection: no such records exist, so the id prices at the cold prior
   *   (ρ = 1/5, π = 1 − 0.2·impact ≤ 0.9 — and any factor ≤ 0.9 caps the
   *   claim product below the 0.97 target, M-05's unanswered-drift shape
   *   included). Later runs: the NEW body re-earns its prior honestly, pass
   *   by pass, from its own records alone.
   * - **the unreviewed-body β** (`driftedFalsePass`, default 0.5 — above the
   *   synthetic tier: these bytes replaced a body the baseline had vouched
   *   for, chosen by the hand that owns the claim, screened by no one) — so
   *   a single new-body pass posterior lands ≈0.94, visibly short of 0.97;
   *   re-certification takes multiple honest observations or a fresh
   *   baseline.
   */
  private async priorsFor(
    affected: readonly CheckSpec[],
    changed: readonly RelPath[],
    graph: DependencyGraph | undefined,
    drifted?: ReadonlySet<string>,
  ): Promise<Map<string, CheckPrior>> {
    const all = await this.store.all()
    // H-03: slice each drifted id's history to its post-drift records. An
    // id the chain has never recorded as drifted-yet (first detection, this
    // run) has no boundary and therefore no admissible history at all.
    const driftSeenAt = drifted !== undefined && drifted.size > 0
      ? await this.scriptDriftFirstSeen()
      : undefined
    const usable = driftSeenAt === undefined
      ? all
      : all.filter(record => {
        if (!drifted?.has(record.checkId)) return true
        const firstSeen = driftSeenAt.get(record.checkId)
        return firstSeen !== undefined && record.recordedAt > firstSeen
      })
    const history = summarizeHistory(usable)
    const priors = computePriors({
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
    if (drifted === undefined || drifted.size === 0) return priors
    const out = new Map<string, CheckPrior>()
    for (const [checkId, prior] of priors) {
      out.set(checkId, drifted.has(checkId)
        ? { ...prior, falsePass: this.options.driftedFalsePass }
        : prior)
    }
    return out
  }

  /**
   * H-03: the envelope `at` where each checkId's script drift FIRST became a
   * chain fact (the first `proof/verified` marker carrying it in
   * `scriptDrift`) — the time boundary between the old body's records and
   * the new body's. Drift markers repeat on every verify while the body
   * stays un-re-anchored; only the first sighting is the boundary.
   */
  private async scriptDriftFirstSeen(): Promise<Map<string, string>> {
    const seen = new Map<string, string>()
    try {
      for (const line of await this.fs.readLines(this.logPath)) {
        let envelope: { kind?: unknown; at?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(line) as { kind?: unknown; at?: unknown; payload?: unknown }
        } catch {
          continue
        }
        if (envelope?.kind !== 'marker') continue
        const payload = envelope.payload as { label?: unknown; scriptDrift?: unknown } | undefined
        if (payload?.label !== 'proof/verified' || !Array.isArray(payload.scriptDrift)) continue
        if (typeof envelope.at !== 'string') continue
        for (const id of payload.scriptDrift) {
          if (typeof id === 'string' && !seen.has(id)) seen.set(id, envelope.at)
        }
      }
    } catch {
      /* unreadable log → no boundary is knowable → drifted ids price fully cold */
    }
    return seen
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
   * v0.21: per-check {prior, posterior} pairs for the run ledger — assembled
   * from the priors the run priced (`priorsFor`) and the FINAL factor map
   * (`runBayesianSchedule`'s live model, or `updateFactors`' fold on the
   * whole-batch path — both leave a posterior for decisive checks and the
   * prior for everything else). Only checkIds present in BOTH maps ride: a
   * factor without a prior cannot speak to what was purchased, and a prior
   * without a factor says the run never modeled it. Sorted for ledger
   * determinism (content-addressing discipline: these numbers are quotable).
   */
  private ledgerFactorsOf(
    priors: ReadonlyMap<string, CheckPrior> | undefined,
    finalFactors: ReadonlyMap<string, number> | undefined,
  ): ReadonlyArray<{ checkId: string; prior: number; posterior: number }> | undefined {
    if (priors === undefined || finalFactors === undefined) return undefined
    const out: { checkId: string; prior: number; posterior: number }[] = []
    for (const checkId of [...priors.keys()].sort()) {
      const prior = priors.get(checkId)
      const posterior = finalFactors.get(checkId)
      if (prior === undefined || posterior === undefined) continue
      out.push({ checkId, prior: prior.priorHealthy, posterior })
    }
    return out.length > 0 ? out : undefined
  }

  /**
   * v0.21: assemble one run's economics block — the ledger plus the
   * probability trajectory it was handed. The records are THIS run's own
   * (the caller passes the coverage-enriched set the chain actually holds);
   * `humanReviewItems` counts the B/C witnesses the consuming verdict
   * actually fused (0 for plain `verify`, whose v0.9 semantics consult no
   * testimony); null probabilities are OMITTED from the ledger input rather
   * than passed as null, so the core's optional fields keep meaning "this
   * run has no such number", not "this run has a null one".
   */
  private runEconomics(
    rate: RateCard,
    records: readonly Evidence[],
    factors: ReadonlyArray<{ checkId: string; prior: number; posterior: number }> | undefined,
    priorProbability: number | null,
    posteriorProbability: number | null,
    humanReviewItems: number,
  ): NonNullable<VerifyOutcome['economics']> {
    return {
      ledger: summarizeRunLedger({
        records,
        rate,
        ...(factors !== undefined ? { factors } : {}),
        ...(priorProbability !== null ? { priorProbability } : {}),
        ...(posteriorProbability !== null ? { posteriorProbability } : {}),
        humanReviewItems,
      }),
      priorProbability,
      posteriorProbability,
    }
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
   * H6: git claims to be available but the HEAD ref is gone. `changedSince`
   * has nothing to diff against without a ref — every committed change since
   * the (now unreachable) baseline commit is invisible — so the run is forced
   * exactly like any other git-blind path. Only consulted when git is believed
   * usable: a definitive `gitAvailable() === false` already fired through
   * `gitFactsUnavailable`, and a probe that throws is conservatively treated
   * as "not usable" there (this method then adds nothing). A `gitHead()` that
   * itself rejects is the same blindness and reports `true`.
   */
  private async gitHeadMissing(): Promise<boolean> {
    if (this.workspace.gitAvailable !== undefined) {
      try {
        if (await this.workspace.gitAvailable() === false) return false
      } catch {
        return false
      }
    }
    try {
      return await this.workspace.gitHead() === null
    } catch {
      return true
    }
  }

  /**
   * H5: which checks now answer under a different script body than the one
   * the baseline recorded. Drift = the baseline carries a digest for the id
   * AND the discovered spec carries a different one. Anything less is NOT
   * drift: a pre-H5 baseline (no `scriptDigests` attachment at all) or a spec
   * without a digest (config entries, non-npm ecosystems) leaves the
   * comparison honestly undetectable — no guess, no charge, behaviour
   * byte-identical to pre-H5. A recorded digest whose check no longer
   * discovers is the *disappeared check* hole (baseline reconciliation), a
   * separate defect with separate machinery — deliberately not conflated here.
   */
  private detectScriptDrift(specs: readonly CheckSpec[], baseline: Baseline | undefined): Set<string> {
    const recorded = (baseline as EngineBaseline | undefined)?.scriptDigests
    if (recorded === undefined) return new Set()
    const drifted = new Set<string>()
    for (const spec of specs) {
      if (spec.scriptDigest === undefined) continue
      const was = Object.prototype.hasOwnProperty.call(recorded, spec.id)
        ? recorded[spec.id]
        : undefined
      if (was !== undefined && was !== spec.scriptDigest) drifted.add(spec.id)
    }
    return drifted
  }

  /**
   * H5②: the other half of definition reconciliation — checks the baseline
   * anchored whose ids discovery no longer produces. Deleting a failing
   * check's definition must not quietly shrink the report back to green:
   * the vanished ids surface on the outcome, the boundary marker, and the
   * grade (`assembleProof` blocks `proven` while any are missing).
   */
  private detectVanishedChecks(specs: readonly CheckSpec[], baseline: Baseline | undefined): string[] {
    if (baseline === undefined) return []
    const known = new Set(specs.map(s => s.id))
    return baseline.checks
      .map(entry => entry.checkId)
      .filter(id => !known.has(id))
      .sort()
  }

  /**
   * H5: drift is a degradation of trust in a definition, so it follows E2's
   * visibility rule — a line on the verbose channel (when wired), and the
   * chain always carries the fact through the `proof/verified` boundary
   * marker this method's callers extend.
   */
  private warnScriptDrift(drifted: ReadonlySet<string>): void {
    if (this.verbose && this.logger !== undefined) {
      this.logger(`[dsh-proof] ${drifted.size} check definition(s) changed since baseline (script drift) — re-run and discounted`)
    }
  }

  /**
   * M18: canonicalise one host-supplied change path to the '/'-separated
   * workspace-relative form every downstream consumer speaks — impact
   * closure, path filters, the coverage executed-set match. Hosts hand over
   * whatever their platform produced (`src\a.ts`, `./src/a.ts`, a
   * root-anchored `C:\repo\src\a.ts`), and an unnormalised entry silently
   * matches nothing: the change reads uncovered, the selection reads empty.
   * `normalizeRel` folds separators and `.`/`..` segments; root-anchored
   * spellings fold against the engine's own root first (the
   * `toWorkspaceRelative` discipline), and a path anchoring outside the root
   * keeps its normalised form rather than being dropped — over-attribution
   * costs a re-run, under-attribution hides a break.
   */
  private canonicalChanged(paths: readonly RelPath[]): RelPath[] {
    const root = this.root.replace(/\\/g, '/').replace(/\/+$/, '')
    const fold = (path: string): string => {
      const slashed = path.replace(/\\/g, '/')
      if ((/^[A-Za-z]:\//.test(slashed) || slashed.startsWith('/'))
        && slashed.toLowerCase().startsWith(`${root.toLowerCase()}/`)) {
        return normalizeRel(slashed.slice(root.length + 1))
      }
      return normalizeRel(slashed)
    }
    return [...new Set(paths.map(fold).filter(p => p.length > 0))].sort()
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
      // M18: "honoured as-is" means the SET is the caller's, not the
      // spellings — each path is canonicalised first (see canonicalChanged),
      // so backslash/`./`/root-anchored forms stop silently never matching.
      ...(options.changed !== undefined ? { explicit: this.canonicalChanged(options.changed) } : {}),
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
      // H9b: a shell ran this session — absence from `touched` is no longer
      // proof of an external edit, so classification demotes to 'unknown'.
      ...(options.shellUsedSince === true ? { uncertainExternal: true } : {}),
    })
  }

  /**
   * Snapshot with content digests of the dirty set (capped; skipped when huge).
   *
   * H6: a rejected dirty query is no longer folded into "clean" (`[]`). The
   * failure cannot live in the snapshot itself — `WorkspaceSnapshot` is hash
   * material for `baselineId`, and a flag there would re-identify every
   * baseline — so it travels beside the snapshot and `establishBaseline`
   * records it as the non-addressing `snapshotDegraded` attachment. The dirty
   * list is still empty: content-anchored resolution can only *over*-report
   * from a blind dirty list, and verify's degraded synthesis forces the full
   * check set anyway (the conservative direction either way).
   */
  private async snapshotWorkspaceDetailed(): Promise<{ snapshot: WorkspaceSnapshot; dirtyQueryFailed: boolean }> {
    const head = await this.workspace.gitHead().catch(() => null)
    let dirtyQueryFailed = false
    const dirty = [...new Set(await this.workspace.gitDirty().catch(() => {
      dirtyQueryFailed = true
      return [] as string[]
    }))].sort()
    const dirtDigest = sha256(dirty.join('\n'))
    if (dirty.length > WORKSPACE_DIGEST_CAP) return { snapshot: { head, dirty, dirtDigest }, dirtyQueryFailed }
    const dirtyDigests: Record<string, string> = {}
    for (const rel of dirty) {
      const content = await this.fs.readFile(`${this.root}/${rel}`)
      if (content !== undefined) dirtyDigests[rel] = sha256(content)
    }
    return { snapshot: { head, dirty, dirtDigest, dirtyDigests }, dirtyQueryFailed }
  }
}
