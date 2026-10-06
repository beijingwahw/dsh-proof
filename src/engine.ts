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
  DefinitionResolverPort, DependencyGraph, Evidence, FsPort, ProofGrade, RelPath,
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
// v0.19: the ONE engine→app edge, deliberate. `verifyBundle` is the
// authoritative implementation of the APP bundle exchange format (manifest
// digests, chain walk, anchor adjudication), and `submitDelegation` must
// adjudicate a submitted bundle under exactly that authority rather than the
// engine growing a second, drift-prone copy of the same rules. No cycle:
// app/bundle.ts depends only on src/core/* and its sibling protocol.ts —
// never on the engine.
import { verifyBundle } from './app/bundle.ts'
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
    // v0.18: transparency-log wiring. `ptlDir` is normalised once (trailing
    // slashes folded — every composition below is `${ptlDir}/...`); the
    // operator-signer default loads an Ed25519 key from `<ptlDir>/operator-key`
    // (NodeEd25519Signer.load bootstraps it on first use, the same rule the
    // workspace chain key follows under trustDir).
    this.workspaceKey = workspaceKey
    this.ptlDir = options.ptlDir !== undefined ? options.ptlDir.replace(/[\/]+$/, '') : undefined
    this.ptlSignerProvider = options.ptlSigner
      ?? (this.ptlDir !== undefined
        ? () => NodeEd25519Signer.load(`${this.ptlDir}/operator-key`)
        : undefined)
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
    // `skipped` on a drained budget, `timeout` past the per-check clock. A
    // half-observed baseline would silently become THE truth later judgments
    // regress against, which is exactly what E1 exists to prevent.
    const aborted = batch.aborted === true
      || batch.records.some(r => r.status === 'aborted' || r.status === 'skipped' || r.status === 'timeout')
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
    })
    await this.store.checkpoint()
    return { baseline: anchored, records: batch.records }
  }

  /** Re-run the checks this change set made stale, and grade the claim. */
  async verify(options: VerifyOptions = {}): Promise<VerifyOutcome> {
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
    const specs = unionChecks(discovered, await this.syntheticSpecs())
    const baseline = await this.store.loadBaseline()
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
    // wholly blind without a ref to diff against).
    const degraded = resolutionDegraded(attribution)
      || baselineSnapshotDegraded(baseline)
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
    // nonce) is physical staging only: it never enters any hash material, so
    // the same verification re-run against a different clock still addresses
    // its evidence identically.
    const coverageDir = await this.prepareCoverageDir()

    const records: Evidence[] = []
    let schedule: VerifyOutcome['schedule']
    let confidence: ConfidenceInput | undefined
    if (bayesian && runSet.length > 0) {
      const plan = await this.runBayesianSchedule(runSet, changed, graph, snapshot, options, coverageDir, scriptDrifted)
      records.push(...plan.records)
      schedule = plan.schedule
      confidence = plan.confidence
    } else {
      // Priors must snapshot the log BEFORE this run appends to it — history
      // is what the check brought to the table, not what it did just now.
      const priors = await this.priorsFor(runSet, changed, graph, scriptDrifted)
      const batch = await this.runner.run(runSet, {
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
      confidence = this.updateFactors(priors, batch.records, runSet.length > 0)
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
    const report = this.gateByCoverage(machineReport, collected.summary)

    // M19b: what the caller claims this run proves, when they said so.
    const claimText = markerText(options.claim)
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
    // M7: a claim verdict re-discovers, exactly like plain verify() — the
    // obligations are judged against the workspace's current check pool.
    const specs = await this.loadChecks(true)
    const baseline = await this.store.loadBaseline()
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
    // `certifyTarget` on top of every obligation holding. M10: a human
    // *endorsement* is excluded from that product (risk acceptance, not
    // probability transfer — see `attestationProduct`); a reject keeps its
    // veto weight.
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
    const degraded = resolutionDegraded(attribution)
      || baselineSnapshotDegraded(baseline)
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
    // claim are ordinary checks and earn the same execution-coverage honesty.
    const coverageDir = await this.prepareCoverageDir()
    // Whole-batch over the (possibly benchmark-extended, possibly
    // drift-extended) run set, with the same priors/confidence display the
    // 'set' path uses — see method note.
    const priors = await this.priorsFor(runSpecs, changed, graph, scriptDrifted)
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
      // H3: endorsement accepts RESIDUAL RISK, it never pays for work. The
      // unlock therefore demands the work be complete on every axis: every
      // check verified to a decisive outcome (no `unverified` — checks that
      // were skipped, timed out or never dispatched are unfinished work, not
      // residual risk), the coverage gate not blocking (an unexecuted change
      // is missing work too — see the H3 note above), every obligation met,
      // nothing regressed, nothing newly failing. That leaves exactly the
      // machine's own words: "0.94, and I cannot cross 0.97" — and the human
      // took the remainder. Under the current full-coverage contract wiring
      // (`requireFullCoverage: true` on the machine run above) a stale grade
      // coincides with `unverified > 0`, so this branch is in fact
      // unreachable today; it is kept because it is the honest *shape* of
      // the rule — the day a confidence-tiered contract path lets a fully
      // completed run land just under the target, this is the seam where a
      // human may accept it — and as regression armor against ever widening
      // the unlock again.
      const endorsementUnlock = endorsed
        && graded.grade === 'stale'
        && unmet.length === 0
        && graded.unverified.length === 0
        && !coverageBlocked
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

    // M19b: the caller's claim text for this verdict, when supplied — the
    // contract's own claim already lives in the attest/jury markers.
    const claimText = markerText(rest.claim)
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
   * `claimedGrade` honesty boundary: the engine cannot re-run the child's
   * checks (they ran in another workspace, against another baseline), so the
   * default derivation is deliberately two-valued — a clean bundle carrying
   * a baseline is what the child CALLS 'proven', anything else defaults to
   * 'no-baseline'. Every finer grade ('unproven', 'stale', 'regressed') is a
   * workspace-local judgment the submitter must DECLARE explicitly; the
   * composer (core/obligations.ts) then treats a declared grade the artifact
   * cannot back as forgery, which is exactly where an inflated claim belongs.
   *
   * The returned `composed` verdict is pure delegation synthesis — the
   * own-workspace grade map is EMPTY. The parent's own evidence (its local
   * `verify()` outcome) enters through `taskVerdict`'s `ownGrade`, whose
   * consumer owns that judgment.
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
    const claimedGrade: ProofGrade = input.claimedGrade
      ?? (artifactVerified && verification.baselineId !== undefined ? 'proven' : 'no-baseline')
    const problems = verification.problems.slice(0, 5)
    const submission: DelegationSubmission = {
      childWorkspace: input.byWorkspace ?? bundle.manifest.workspaceKey,
      bundleRoot: bundleFingerprint(bundle.manifest.files),
      claimedGrade,
      artifactVerified,
      ...(problems.length > 0 ? { problems } : {}),
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
   * `delegation/waive`). `ownGrade`, when given, is THIS workspace's own
   * locally-earned grade for the task — the one leg submission cannot
   * supply, because the parent's own evidence never left the parent's chain.
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
    const ownGrades = input.ownGrade !== undefined
      ? new Map<string, ProofGrade>([[input.taskId, input.ownGrade]])
      : new Map<string, ProofGrade>()
    const composed = composeTaskVerdict(input.taskId, nodes, ownGrades)
    return { composed, nodes, cycles }
  }

  /**
   * v0.19: waive a task's obligation — record the risk acceptance, nothing
   * more. The engine only keeps the books: whether a waiver may lift a
   * verdict is the composer's judgment (core/obligations.ts), and a waiver
   * over a FORGED or REGRESSED child is recorded here exactly like any
   * other — the composition layer is the one that refuses it. `by` and
   * `reason` are mandatory and non-empty: an anonymous or unexplained
   * acceptance of risk is not an acceptance, it is an erasure.
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
    const exists = (await this.delegationObligations()).some(o => o.taskId === input.taskId)
    if (!exists) {
      throw new Error(`waiveDelegation: no delegation/created marker for taskId ${input.taskId}`)
    }
    await this.store.mark('delegation/waive', {
      taskId: input.taskId,
      by: input.by.trim().slice(0, 200),
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
  ): Promise<{ records: Evidence[]; schedule: NonNullable<VerifyOutcome['schedule']>; confidence: ConfidenceInput }> {
    const priors = await this.priorsFor(affected, changed, graph, drifted)
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
    }
  }

  /**
   * Priors over one affected set: history summarised from the whole evidence
   * log, priced with a quarter of the per-check timeout as the fallback cost
   * of a check that has never been observed.
   *
   * H5: drifted checks are re-priced at the synthetic false-pass tier — the
   * same β `PriorInput.syntheticFalsePass` charges a conjured test. A script
   * body rewritten after the baseline carries at least the false-pass risk of
   * a test authored by an interested party: whatever green it now reports, the
   * body is new, unreviewed, and chosen by the same hand that owns the claim.
   * The re-price is a map rewrite (core/bayes.ts is not this batch's to edit):
   * every other parameter — learned failure tendency, flake rate, impact —
   * keeps what history honestly said about the OLD body's sensor behaviour.
   */
  private async priorsFor(
    affected: readonly CheckSpec[],
    changed: readonly RelPath[],
    graph: DependencyGraph | undefined,
    drifted?: ReadonlySet<string>,
  ): Promise<Map<string, CheckPrior>> {
    const history = summarizeHistory(await this.store.all())
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
        ? { ...prior, falsePass: this.options.syntheticFalsePass }
        : prior)
    }
    return out
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
