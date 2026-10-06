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
import type { Baseline, ChangeSetResolution, CheckSpec, CheckStatus, Clock, CommandPort, DefinitionResolverPort, DependencyGraph, Evidence, FsPort, ProofGrade, RelPath, SelectionResult, SignerPort, WorkspacePort, WorkspaceSnapshot } from './core/index.ts';
import { EvidenceStore } from './core/index.ts';
import type { GradedProofReport } from './core/index.ts';
import type { AuditReport } from './core/evidence.ts';
import type { VerifiedMarkerView } from './core/evidence.ts';
import type { AttributedCheck } from './core/regression.ts';
import type { CheckConfigEntry } from './core/checks.ts';
import type { ClaimContract, ClaimKind, ObligationResult } from './core/contract.ts';
import type { SyntheticEvidenceMeta, SyntheticRequest } from './core/synthetic.ts';
import type { SignedTreeHead } from './core/transparency.ts';
import type { ComposedVerdict, DagNode, DelegationSubmission, TaskObligation } from './core/obligations.ts';
import type { SampleFidelity, TrainingManifest, TrainingSample } from './core/training.ts';
import type { RateCard, RunLedger, SlaQuote } from './core/economics.ts';
export interface EngineOptions {
    readonly root: string;
    /**
     * Where evidence lives. Relative paths resolve against the workspace root
     * (legacy, agent-writable); absolute paths are used as-is so hosts can keep
     * the log under DSH_HOME instead.
     */
    readonly evidenceDir?: string;
    /** Host-side trust root (signing keys + anchors), outside the workspace. */
    readonly trustDir?: string;
    /** Stable workspace identity committed into checkpoints and anchors. */
    readonly workspaceKey?: string;
    /** Append a signed checkpoint after every N records (boundaries always do). */
    readonly checkpointEvery?: number;
    /** Explicit signer provider; overrides trustDir-derived Ed25519. */
    readonly signer?: () => Promise<SignerPort | undefined>;
    /**
     * v0.18: directory of the public transparency log (PTL) this engine
     * publishes signed checkpoints to (`publishCheckpoint`). Absent = the
     * feature is off and `publishCheckpoint` throws a clean configuration
     * error. The directory is owned by the transparency-log operator, not by
     * the agent — hosts place it under the trust root, outside the workspace.
     */
    readonly ptlDir?: string;
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
    readonly ptlSigner?: () => Promise<SignerPort | undefined>;
    readonly autoDiscover?: boolean;
    readonly checks?: readonly CheckConfigEntry[];
    readonly checkTimeoutMs?: number;
    readonly verifyBudgetMs?: number;
    readonly concurrency?: number;
    /**
     * Verification scheduling strategy (β). `bayesian` (default): rank the
     * affected checks by information gain per cost, run them in waves, and stop
     * once the claim posterior crosses `certifyTarget`. `set`: the legacy
     * whole-batch run with legacy grading — the behavioural escape hatch.
     */
    readonly scheduler?: 'bayesian' | 'set';
    /** Claim-probability target for bayesian certification — the p in `proven (p≈0.97)`. */
    readonly certifyTarget?: number;
    readonly impactGraph?: boolean;
    readonly impactGraphLimit?: number;
    /** LSP-backed resolver for precise, alias-aware impact edges (v0.4). */
    readonly resolver?: DefinitionResolverPort;
    /** Maximum language-server round-trips per graph build. */
    readonly lspQueryBudget?: number;
    /** How output is excerpted into evidence records (v0.5). */
    readonly excerptStrategy?: 'head' | 'balanced';
    readonly headChars?: number;
    /** User home directory, canonicalised to `$HOME` in evidence (v0.6). */
    readonly homeDir?: string;
    /**
     * Line logger for degradation warnings (E2: trust downgrades must be
     * visible, not just recorded). Hosts wire this to their verbose channel;
     * without it the warning still lands in the evidence chain.
     */
    readonly logger?: (message: string) => void;
    /** Emit degradation warnings through `logger`. */
    readonly verbose?: boolean;
    /**
     * Entry points (workspace-relative) for the baseline API-surface snapshot
     * (ζ). Empty/absent = derive from the project's `package.json` `main`,
     * `exports["."]` and `types` fields. Explicit entries are used as-is.
     */
    readonly apiEntryPoints?: readonly string[];
    /**
     * Confidence ceiling for docs-only jury self-attestation (ζ). Mirrors the
     * plugin config's `juryConfidenceCap` (default 0.8).
     */
    readonly juryConfidenceCap?: number;
    /**
     * κ: Class B (LLM jury) trust weight — the log-odds exponent applied to a
     * jury verdict's own probability. Mirrors the plugin config's `classBTrust`
     * (default 0.7).
     */
    readonly classBTrust?: number;
    /**
     * κ: Class C (human) trust weight — same exponent semantics over the human
     * probability (0.95). Mirrors the plugin config's `classCTrust` (default
     * 0.9).
     */
    readonly classCTrust?: number;
    /**
     * π: sandbox directory for conjured tests, relative to the workspace root.
     * Mirrors the plugin config's `syntheticDir` (default '.proof-synthetic').
     */
    readonly syntheticDir?: string;
    /**
     * π: false-pass rate priced into synthetic checks' posteriors — P(observed
     * pass | actually broken) for a test authored by the claim's interested
     * party. Mirrors the plugin config's `syntheticFalsePass` (default 0.15).
     */
    readonly syntheticFalsePass?: number;
    /**
     * H-03: false-pass rate priced into checks whose script body DRIFTED from
     * the body the baseline digested — an unreviewed body replacing one the
     * baseline had vouched for. Default `DRIFTED_FALSE_PASS_DEFAULT` (0.5),
     * deliberately above the synthetic tier for the same reason the synthetic
     * tier is above the organic one: the hand that owns the claim chose these
     * bytes, and nobody screened them. Overridable modelling guess, never a
     * `BAYES_CONSTANTS` law (see core/bayes.ts).
     */
    readonly driftedFalsePass?: number;
    /** π: cooperative timeout for one conjured-test run (default 60s). */
    readonly syntheticTimeoutMs?: number;
    /**
     * υ: V8 execution-coverage gating mode — `observe` (default: gate only when
     * coverage data exists; no data degrades visibly to basis `'none'`),
     * `require` (no data is itself disqualifying), or `off` (no injection, no
     * gating, byte-identical to pre-υ behaviour). Mirrors the plugin config's
     * `coverage` field; the long design note lives there (config.ts).
     */
    readonly coverage?: 'observe' | 'require' | 'off';
    readonly clock?: Clock;
    readonly fs?: FsPort;
    readonly commands?: CommandPort;
    readonly workspace?: WorkspacePort;
}
export interface VerifyOptions {
    /** Explicit change set. Defaults to a content-anchored diff against the baseline. */
    readonly changed?: readonly RelPath[];
    /** Paths the agent's tool stream touched, for provenance classification. */
    readonly touched?: readonly RelPath[];
    /**
     * H9b: a shell-class tool ran this session (`WorkspaceWatch.sessionShellUsed`).
     * Path extraction cannot see through a command string, so "not in `touched`"
     * no longer proves "changed outside the agent" — those changes classify as
     * `'unknown'` instead of `'external'` (see `ChangeSetInput.uncertainExternal`).
     */
    readonly shellUsedSince?: boolean;
    readonly signal?: AbortSignal;
    /** Force the full check set regardless of impact analysis. */
    readonly all?: boolean;
    readonly onProgress?: (label: string, index: number, total: number) => void;
    /**
     * M19b: the claim text this verification answers — what the tool-side
     * `claim` parameter was for. Bounded to 200 characters and recorded on the
     * `proof/verified` boundary marker when non-empty, so the chain says WHAT
     * was proven, not only that something was.
     */
    readonly claim?: string;
    /**
     * v0.21: price this run. When supplied, the outcome carries an `economics`
     * block — the run's ledger (compute spent, assertions bought, per-dollar
     * efficiency) plus the claim-probability trajectory the scheduler moved it
     * through. Absent = absent: the outcome's shape without the option is
     * unchanged, so consumers that never asked see nothing new. The rate card
     * is validated at the verb boundary BEFORE any check runs — a negative
     * price must refuse the run, not silently price it backwards.
     */
    readonly economics?: {
        readonly rate: RateCard;
    };
}
export interface VerifyOutcome {
    readonly report: GradedProofReport;
    readonly checks: readonly AttributedCheck[];
    readonly selection: SelectionResult;
    readonly changed: readonly RelPath[];
    /** How the change set was derived and who each change belongs to (v0.3). */
    readonly attribution: ChangeSetResolution;
    /**
     * Git facts were unavailable for change-set resolution, so the full check
     * set was forced (E3). Present only on the degraded path; hosts surface it
     * so "we ran everything because we couldn't tell what moved" stays loud.
     */
    readonly degraded?: true;
    /**
     * Bayesian wave-plan metadata (β). Present only when the bayesian scheduler
     * actually planned waves — never on the forced/'set' whole-batch path, and
     * never when nothing was affected.
     */
    readonly schedule?: {
        readonly mode: 'bayesian';
        /** Waves actually dispatched. */
        readonly waves: number;
        /** Why the plan ended before every affected check ran; null when it ran to completion. */
        readonly stoppedEarly: 'certified' | 'failed' | 'budget' | null;
        /**
         * Checks the plan left resting on their priors, each with that prior:
         * deliberately never dispatched, or (H2) dispatched without producing a
         * decisive answer — both are "no verdict from this run", which is exactly
         * what the report's `unverified` list and `basisFor`'s planned-skip
         * accounting consume them for.
         */
        readonly skippedByPlan: ReadonlyArray<{
            checkId: string;
            priorHealthy: number;
        }>;
    };
    /**
     * υ: what the execution-coverage dimension said about the change set.
     * Present whenever coverage collection ran (modes `observe`/`require`),
     * absent in `off`. `basis: 'none'` is the honest "no data was produced"
     * (fake command ports, non-Node toolchains) — under `observe` it gates
     * nothing, under `require` it is itself the disqualification.
     */
    readonly coverage?: {
        /** `'v8'` — real profiles were read; `'none'` — no data this run. */
        readonly basis: 'v8' | 'none';
        /** Changed files no decisively-passing check actually executed. */
        readonly uncovered: readonly string[];
        /** How many changed files were observed executing. */
        readonly executedCount: number;
    };
    /**
     * H5: check definitions whose script body changed since the baseline
     * (package.json scripts — the id says `npm run test`, the digest says what
     * `test` said). Each one was force-re-run regardless of impact analysis and
     * priced at the synthetic false-pass tier: the baseline's green under that
     * id was earned by a *different body*, and an interested party rewriting
     * `"test": "vitest run"` into a no-op carries at least the false-pass risk
     * of a self-authored test. Present only when at least one check drifted.
     */
    readonly scriptDrift?: readonly string[];
    /** H5②: baseline checks whose definitions vanished from discovery. */
    readonly vanished?: readonly string[];
    /**
     * H-23: the run consumed an audit that found the baseline file no longer
     * matches the digest the chain recorded under `baseline/saved` — every
     * comparison this run made against that baseline (change-set resolution,
     * script digests, the API surface) judged suspect bytes. Present only on
     * the tampered path: the run forced the full check set AND its grade is
     * capped at `stale`; the boundary marker carries the same flag so the
     * degradation is a chain fact, not just a return value.
     */
    readonly baselineTampered?: true;
    /**
     * X-H-09 (v0.23): this run's evidence chain failed its own integrity audit
     * on an axis beyond the tampered baseline (broken linkage, forged
     * checkpoint signatures, rewind, anchor disagreement). Present only on the
     * failed-audit path: the run forced the full check set AND its grade is
     * capped at `stale` — the chain under this verdict failed its own audit,
     * and the boundary marker carries the same flag so the degradation is a
     * chain fact, not just a return value.
     */
    readonly auditFailed?: true;
    /**
     * Y-H-09 (v0.24): the newest baseline-defining marker sits above the
     * checkpoint-covered prefix (the X-H-08 absorption shape) — the run was
     * degraded and its grade capped at `stale` BEFORE minting, rather than
     * letting a pre-sign refusal arrive one boundary too late. Distinct from
     * `auditFailed`/`baselineTampered`: those are the audit's charges; this is
     * the engine's pre-verdict determination over the vouched prefix. Present
     * only on the suspect path.
     */
    readonly baselineAbsorptionSuspect?: true;
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
        readonly ledger: RunLedger;
        readonly priorProbability: number | null;
        readonly posteriorProbability: number | null;
    };
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
    readonly apiSurface?: readonly string[];
    /**
     * H5: the script *bodies* that answered at baseline time — checkId →
     * sha256(script body) for every discovered spec that carries a digest (the
     * package.json discovery path). Same non-addressing discipline as
     * `apiSurface`: `baselineId` hashes none of it, the field round-trips
     * through save/load, and a pre-H5 baseline file reads back `undefined` —
     * comparison then honestly degrades to "drift undetectable" rather than
     * guessing (see `detectScriptDrift`).
     */
    readonly scriptDigests?: Readonly<Record<string, string>>;
    /**
     * H6: this baseline's dirty-file snapshot was built with a FAILED git query
     * — the dirty list is empty because it was unobservable, not because the
     * tree was clean. Kept beside the baseline (never inside `WorkspaceSnapshot`,
     * which is hash material for `baselineId`); verify folds it into its
     * degraded synthesis, forcing the full check set.
     */
    readonly snapshotDegraded?: true;
    readonly aborted?: true;
};
/** ζ: what `verifyContract` judged a typed claim against, beyond the run. */
export interface ContractSummary {
    readonly kind: ClaimKind;
    readonly obligations: readonly ObligationResult[];
    /** Present when the verdict was jury-capped (docs-only self-attestation). */
    readonly juryConfidenceCap?: number;
    /**
     * κ: the on-chain Class B/C witnesses whose factors were fused into this
     * verdict's confidence — one entry per *active* attestation for the claim
     * (highest gen wins; appeals override). Present exactly when at least one
     * active witness exists for the claim's id. `verdict` is the jury verdict
     * ('uphold'|'reject'|'abstain') or the human decision ('endorse'|'reject').
     */
    readonly attestations?: ReadonlyArray<{
        readonly class: 'B' | 'C';
        readonly gen: number;
        readonly verdict?: string;
        readonly factor: number;
    }>;
}
/** ζ: `verify`'s options grown by the claim contract under judgment. */
export type ContractVerifyOptions = VerifyOptions & {
    readonly contract: ClaimContract;
};
/** ζ: `verify`'s outcome grown by the contract verdict. */
export type ContractVerifyOutcome = VerifyOutcome & {
    readonly contract: ContractSummary;
};
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
    readonly sequence: number;
    /** True when the checkpoint was already published — the tree did not grow. */
    readonly duplicate: boolean;
    /** The entry's Merkle leaf hash (`ptlLeafHash(entry)`). */
    readonly leafHash: string;
    /** Leaves in the tree after this publish. */
    readonly treeSize: number;
    /** Merkle root over every published leaf. */
    readonly root: string;
    /** Stable identity of the public log the STH speaks for. */
    readonly logId: string;
    /** ISO timestamp of the SignedTreeHead (NOT of the mirrored checkpoint). */
    readonly at: string;
    /** Audit path from the entry's leaf to the root. */
    readonly inclusionProof: readonly string[];
    /** The operator-signed tree head, also persisted as the log's head file. */
    readonly sth: SignedTreeHead;
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
    readonly checkId: string;
    /** The executed record's status, or `'skipped'` for a screening refusal. */
    readonly status: CheckStatus;
    /** sha256 of the script as it existed at execution (or refusal) time. */
    readonly scriptDigest: string;
    /** Screening findings; empty when the script screened clean. */
    readonly screened: readonly string[];
    /** The execution regime the evidence records. */
    readonly sandbox: SyntheticEvidenceMeta['sandbox'];
    /** Excerpt of the run's output, or the refusal reason. */
    readonly outputHead: string;
}
/** v0.19: what `delegateTask` minted and committed to the chain. */
export interface DelegateTaskResult {
    /** Engine-minted sequence identity (`task-<n>`), unique on this chain. */
    readonly taskId: string;
    /** `obligationIdOf(obligation)` — the responsibility's content address. */
    readonly obligationId: string;
    /** The obligation exactly as it rode the `delegation/created` marker. */
    readonly obligation: TaskObligation;
}
/** v0.19: what `submitDelegation` recorded, and what the DAG composes over it. */
export interface SubmitDelegationResult {
    /** The submission exactly as it rode the `delegation/verdict` marker. */
    readonly submission: DelegationSubmission;
    /** Verdict composed over the whole rebuilt DAG, with NO own-workspace grade. */
    readonly composed: ComposedVerdict;
}
/**
 * v0.19: what `taskVerdict` rebuilt and concluded. `nodes` is the full DAG
 * the verdict was composed over (so hosts can surface the sub-tree, not just
 * the grade) and `cycles` is the defense-in-depth report — empty on any
 * chain this engine alone wrote to.
 */
export interface TaskVerdictResult {
    readonly composed: ComposedVerdict;
    readonly nodes: readonly DagNode[];
    readonly cycles: string[];
    /**
     * H-11: ownGrade self-reports that exceeded what this chain's evidence
     * supports (the latest `proof/verified` marker's grade), one line each.
     * A self-report is testimony, never measurement: the composed verdict
     * rides the chain-derived grade, and an inflated claim is recorded here
     * and echoed into the composed blockers rather than silently ignored —
     * or worse, believed.
     */
    readonly discrepancies?: readonly string[];
    /**
     * v0.25 (K1): how many `delegation/*` and `proof/verified` markers the
     * vouched floor withheld from this verdict — appended above the last
     * checkpoint this host's key verified, structurally valid, priced at
     * nothing. Present only when the count is non-zero: an honest chain
     * (everything below the floor) sees no field at all.
     */
    readonly aboveFloorMarkers?: number;
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
    readonly fidelity?: SampleFidelity;
    /**
     * Behaviour-label purity filter handed to distillation. `'agent-only'`
     * (default) keeps only agent-attributable verification behaviour; `'all'
     * keeps everything. When the chain carries no provenance to filter by, the
     * filter cannot fire — distillation runs unfiltered and the manifest still
     * records the requested value (an honest downgrade, not a silent lie).
     */
    readonly provenanceFilter?: 'agent-only' | 'all';
    /**
     * The change set the samples are contextualised against. Default: the
     * changed-path list recorded on the latest `proof/verified` marker — which
     * today's markers do not carry (they record the count), so the honest
     * default for our own chains is no change-set context.
     */
    readonly changedPaths?: readonly string[];
    /** Dataset license, recorded on the manifest verbatim when given. */
    readonly license?: string;
    /**
     * When given, the export also lands on disk as two files: `<path>` (one
     * canonical-JSON sample per line, JSONL) and `<path>.manifest.json` (the
     * single manifest document). Both go through the fs port's atomic
     * `writeFile`; the parent directory is created first.
     */
    readonly path?: string;
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
    readonly count: number;
    /** Chain head digest at the checkpoint. */
    readonly head: string;
    /** The signing key's identity, when the anchor is a signed checkpoint. */
    readonly keyId?: string;
}
/** v0.20: what `exportTrainingData` produced. */
export interface TrainingExportResult {
    readonly manifest: TrainingManifest;
    readonly samples: readonly TrainingSample[];
    readonly anchor: TrainingAnchor;
}
export declare class ProofEngine {
    readonly root: string;
    private readonly fs;
    private readonly commands;
    private readonly workspace;
    private readonly clock;
    private readonly store;
    private readonly runner;
    /**
     * Y-H-03 (v0.24): the ONE verified read surface — every marker trust read
     * (`markersWith`, attestation fusion) and the publish/training checkpoint
     * selection below goes through it, so suspect adjudication, the
     * generational fallback and signature three-state adjudication live in
     * exactly one place (core/evidence.ts) instead of N hand-rolled twins.
     * Built once at construction over the store's own trust wiring.
     */
    private readonly verified;
    private specs;
    private graph;
    private baselineSeen;
    private signerPromise;
    /** v0.18: the transparency log's directory, when publishing is configured. */
    private readonly ptlDir;
    /** v0.18: operator-key provider for SignedTreeHeads (default: `<ptlDir>/operator-key`). */
    private readonly ptlSignerProvider;
    /** v0.18: M15 memoization for the operator signer — only a SUCCESSFUL load is cached. */
    private ptlSignerPromise;
    /** v0.18: bounded reason the last operator-signer resolution failed, for the clean throw. */
    private ptlSignerError;
    /**
     * v0.18: single-flight for every PTL-mutating operation. Two racing
     * `publishCheckpoint` calls would both `loadPtl` at the same size and both
     * append — the public log would then carry the same leaf twice and the tree
     * would grow on a duplicate. Same discipline as the store's tail queue:
     * serialise the read–append–sign section; reads elsewhere stay concurrent.
     */
    private ptlQueue;
    private readonly resolver;
    private readonly logger;
    private readonly verbose;
    /** v0.18: the stable workspace identity checkpoints (and PTL entries) carry. */
    private readonly workspaceKey;
    /**
     * H-05/H-10: the out-of-band anchor file this engine's store consults
     * (`<trustDir>/anchors/<workspaceKey>/anchor.json`), retained so the
     * delegation verbs can read the obligation minter's trust root directly.
     */
    private readonly trustDir;
    private readonly anchorPath;
    /**
     * H-10: the (watched) signer provider the store was configured with.
     * `waiveDelegation`'s anchor-key authorization resolves it to ask "does
     * THIS host hold the key the anchor names?" — an absent provider answers
     * no, which is the conservative direction for a risk-acceptance verb.
     */
    private readonly signerProvider;
    /** H-17: per-run sequence for coverage staging directory names (physical only, never hash material). */
    private coverageRunSeq;
    /** κ: where the evidence log physically lives — marker payloads (attestations) are read back through it. */
    private readonly logPath;
    /** κ: trust weights for Class B/C evidence, synthesised from config passthrough. */
    private readonly trustWeights;
    /** υ: the evidence store's physical directory — coverage staging lives beside it. */
    private readonly storeDir;
    private readonly options;
    constructor(options: EngineOptions);
    /** Host-held Ed25519 signer under the trust root; rejects when unavailable. */
    private loadSigner;
    /**
     * The PTL operator key, resolved where the ptl CLI resolves it:
     * `<trustDir>/ptl-operator-key` (outside the published log dir — a key that
     * lives beside the log it notarises can be rewritten together with that
     * log), falling back to the legacy `<ptlDir>/operator-key` when only that
     * exists so an existing deployment's STH signatures keep their keyId. With
     * neither on disk the preferred location bootstraps on first use.
     */
    private loadPtlOperatorKey;
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
    private watchSigner;
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
    loadChecks(force?: boolean): Promise<CheckSpec[]>;
    /** Build (or return cached) the reverse-dependency graph. */
    loadGraph(force?: boolean): Promise<DependencyGraph | undefined>;
    get storeView(): EvidenceStore;
    /** The filesystem port in use, for hosts that want to share it. */
    get fsView(): FsPort;
    /** Checks discovered so far without triggering discovery. */
    cachedChecks(): readonly CheckSpec[];
    /** Synchronous baseline-presence probe for prompt assembly (no I/O). */
    hasBaselineSync(): boolean;
    baseline(): Promise<Baseline | undefined>;
    workspaceSnapshot(): Promise<WorkspaceSnapshot>;
    /** Latest evidence per check. */
    latestEvidence(): Promise<Map<string, Evidence>>;
    /** Integrity check of the evidence log: chain, signatures, anchor, baseline. */
    audit(): Promise<AuditReport>;
    /**
     * Y-H-09 (v0.24): absorption suspicion — the baseline a verdict is about
     * to judge against was last re-defined by a marker line ABOVE the prefix
     * the host key has vouched for (the X-H-08 cross-session absorption
     * shape). v0.23 detected this only at the NEXT checkpoint boundary — the
     * pre-sign audit refuses to sign and the refusal lands AFTER the verdict
     * already minted `proven` over the absorbed bytes; on signer-less
     * deployments it was never detected at all (preSignAudit never runs).
     * This determination is consumed BEFORE the verdict is minted: the run is
     * degraded, `proven` caps at `stale`, and the fact rides the boundary
     * marker — never a post-hoc refusal the report has already outrun.
     *
     * Division of labour with the store layer (G2, v0.24): the audit now
     * charges an unauthorised ANSWERING `baseline/saved` marker as
     * `baselineTampered` at read time (and `loadBaseline` refuses it) — that
     * determination is consumed through the existing `baselineTampered` flag
     * below and this method yields to it (no double charge). What remains for
     * the engine-side derivation is the residue G2's read-time rule does not
     * reach: signer-LESS deployments (no key ever vouches, `baselineTampered`
     * keeps its v0.23 shape+digest semantics) and an unvouched
     * `baseline/established` tail marker (the label preSignAudit also refuses
     * over, but no saved marker answers for). The interim rule mirrors the
     * pre-sign audit's: the NEWEST baseline-family marker must sit
     * at-or-below the last host-VERIFIED checkpoint (or, on a deployment that
     * wires no signer at all, at-or-below the last checkpoint line of any
     * kind — the unsigned era's weaker but non-zero boundary). An honest
     * writer marks and checkpoints in the same breath, so an honest chain
     * always answers false; the flag firing means a baseline-defining line is
     * sitting on the tail nobody's signature covers.
     */
    private baselineAbsorptionSuspect;
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
    publishCheckpoint(): Promise<PublishOutcome>;
    private enqueuePtl;
    private publishCheckpointInternal;
    /**
     * v0.25 (V4-M6, engine half): the publish fallback — `selectPublishable`
     * semantics for the engine face, reached only when the positional-last
     * selection (`bestCheckpoint()`) failed adjudication. Mirrors the ptl CLI
     * face's rule shape for shape: well-formed non-liar signed candidates,
     * anchor-key pool when an anchor answers (own-key pool otherwise), then
     * the newest → oldest scan where the FIRST candidate whose signature
     * actually verifies under the key it names wins.
     *
     * The DoS this closes: one appended twin (well-formed checkpoint line,
     * this host's own keyId, garbage signature) used to hold `refuted` over
     * the whole verb — every honest checkpoint below it unpublishable. The
     * twin is still never notarised (fail-closed against forgeries); the
     * honest work below it is (available against denial of service).
     *
     * Every refusal here is loud and lands on the chain
     * (`ptl/publish-unadjudicated`) — and when the scan SKIPS newer
     * candidates to publish an older honest one, the skipped lines land there
     * too (W2-M3: a genuinely forged signature never passes unnoticed, even
     * when an honest predecessor outvotes it).
     */
    private selectPublishableCheckpoint;
    /**
     * X-H-11/N-5 (v0.23): a publish that cannot adjudicate its own checkpoint's
     * signature refuses loudly, and the refusal is a CHAIN fact before it is a
     * throw — one `ptl/publish-unadjudicated` marker per refused attempt,
     * carrying the reason. The marker is fired, not awaited: this runs inside
     * the PTL single-flight queue, and the store's own tail queue serialises
     * the line after whatever checkpoint is in flight (the `watchSigner`
     * discipline). Silent skips are exactly how the weaker-twin face shipped.
     */
    private refusePublishUnadjudicated;
    /**
     * v0.18: resolve the operator signer with v0.17 M15 semantics — only a
     * SUCCESSFUL resolution is memoized. A rejected or empty resolution resets
     * the memo (the next publish retries the provider, so a transient key-dir
     * lock heals on the next boundary) and, unlike the store's signer, the
     * failure text is kept: publishing has no unsigned degradation to fall back
     * on, so the next attempt's clean throw can name the actual reason.
     */
    private resolvePtlSigner;
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
    establishBaseline(options?: {
        signal?: AbortSignal;
        onProgress?: VerifyOptions['onProgress'];
        /** M19b: why this anchor was taken (≤200 characters), recorded on the `baseline/established` marker when non-empty. */
        reason?: string;
    }): Promise<{
        baseline: EngineBaseline;
        records: readonly Evidence[];
    }>;
    /** Re-run the checks this change set made stale, and grade the claim. */
    verify(options?: VerifyOptions): Promise<VerifyOutcome>;
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
    verifyContract(options: ContractVerifyOptions): Promise<ContractVerifyOutcome>;
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
    slaQuote(input: {
        /** The grade being priced — must be one of the `ProofGrade` vocabulary. */
        readonly grade: ProofGrade;
        /** The confidence the evidence reached; omit for the grade's own default. */
        readonly confidence?: number;
        /** What a breach would cost the underwriter, in `rate.currency`. */
        readonly coverageAmount: number;
        readonly rate: RateCard;
        readonly deductible?: number;
        readonly minPremium?: number;
    }): Promise<SlaQuote & {
        marker: true;
    }>;
    /**
     * v0.21: rate-card defense shared by every economics-wired verb. A price
     * card is host input at a trust boundary, so it is refused BY VALUE —
     * currency must be the one the ledger speaks, and every rate must be a
     * finite non-negative number. Negative prices are not "discounts": a
     * negative computePerMs makes spending money REDUCE cost, and a negative
     * humanReviewPerItem pays the ledger for consuming review.
     */
    private assertRateCard;
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
    conjureRequest(input: {
        claim: string;
        paths: readonly string[];
    }): Promise<{
        request: SyntheticRequest;
        template: string;
        instruction: string;
    }>;
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
    conjureRun(input: {
        claim: string;
        entry: string;
    }): Promise<ConjureRunResult>;
    /** π: `<root>/<syntheticDir>` — where every conjured sandbox lives. */
    private syntheticRoot;
    /**
     * π: every marker under one label, in log order — now Y-H-03 (v0.24) a thin
     * pass-through over the ONE verified view, which owns the suspect position
     * test AND the X-H-06 generational fallback (an upgraded pre-v0.22 chain
     * whose markers carry no headRef witness at all reads degraded rather than
     * evaporating). The v0.23 hand-rolled two-read twin (excludeSuspect, then
     * raw fallback) is retired: the semantics are identical, the derivation is
     * single-sourced.
     *
     * V3-M3 (v0.24): a read FAILURE no longer degrades to `[]`. The old
     * `catch { return [] }` made a transient EBUSY/AV-scan failure read as "no
     * markers" — conservative for proof/verified consumers, but exactly wrong
     * for the sequence minting in `delegateTask`/`conjureRequest`, which would
     * re-mint `task-1` as an alias over live obligations. Reading the log is
     * now allowed to fail the verb, loudly.
     *
     * v0.25 (K1): this is the UNBOUNDED read — allocation and protocol
     * consumers only. Sequence minting (`delegateTask`'s max+1 taskId scan,
     * `conjureRequest`'s per-claim count) must see every number the log ever
     * named, vouched or not, because a re-minted number aliases a live id even
     * when the burned marker priced nothing; and the conjure protocol
     * (`conjureRun`'s request lookup, `syntheticSpecs`) rides above the floor
     * BY DESIGN on honest chains — `synthetic/requested`/`synthetic/run` are
     * not checkpointed between the two halves of the protocol, and the
     * synthetic β + screening + sandbox price their authorship. Every TRUST
     * decision over a marker label goes through `vouchedMarkersWith` instead.
     */
    private markersWith;
    /**
     * π: the synthetic specs currently on the chain — every conjured test that
     * has actually been executed at least once (a request without a run is an
     * offer, not a check; verify must not silently execute an unexecuted
     * offer). They join verification as ordinary specs (P5): selection matches
     * their paths, the runner re-executes their sandbox entry like any other
     * check, and computePriors prices their history with the raised synthetic
     * β — the false-pass risk of a test written by the claim's own author.
     */
    private syntheticSpecs;
    /**
     * M-01: pin the executed script's digest onto a re-dispatched synthetic
     * record. `conjureRun` addresses its record over the script's own bytes
     * (`Evidence.synthetic`); the verify re-dispatch path used to lose that —
     * the record joined the chain without saying WHICH body produced it, and
     * the content-addressing guarantee ("two runs with the same outcome but
     * different scripts are two different pieces of evidence") silently held
     * only for the first execution. This re-reads the entry at collection time
     * and re-addresses exactly like `conjureRun`/`attachEvidenceCoverage` do.
     *
     * X-H-05 (v0.23): a script that VANISHED between request and re-dispatch
     * (the deterministic self-delete exploit: `fs.rmSync(import.meta.url)`)
     * used to leave its record silently meta-less — no `synthetic` field, so
     * every downstream keyed on that field (N-3's require-tier exclusion, the
     * interested-party discount) missed exactly the records authored by the
     * party willing to delete their tracks. A vanished script is now an
     * on-chain `error` record that names the fact: the run cannot vouch for a
     * body it can no longer read, and a self-deleting pass is not a pass.
     */
    private reattachSyntheticMeta;
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
    private prepareCoverageDir;
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
    private collectRunCoverage;
    /**
     * υ: gate one machine report by its coverage summary. `undefined` summary
     * (mode `off`) returns the report untouched; otherwise `coverageGate` +
     * `applyCoverageGate` decide the grade and mount the summary — always, even
     * at basis `'none'` and even when the gate does not block: a proof that
     * carries its coverage blind spot visibly is the entire point of observe
     * mode.
     */
    private gateByCoverage;
    /** υ: the coverage dimension's one-line footprint for boundary markers. */
    private coverageMarkerPayload;
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
    delegateTask(input: {
        claim: string;
        parentTaskId?: string;
        acceptance?: string;
    }): Promise<DelegateTaskResult>;
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
    submitDelegation(input: {
        taskId: string;
        bundle: unknown;
        byWorkspace?: string;
        claimedGrade?: ProofGrade;
    }): Promise<SubmitDelegationResult>;
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
     * X-H-07 (v0.23): "pure delegation" is now literal. A leaf task — no
     * submission, no children, no own marker — composed `proven` with zero
     * blockers through the composer's `ownGrade ?? 'proven'` default; the
     * core's leaf-aware own-grade input now feeds that shape `unproven`
     * (G9's obligations.ts), so the verdict is `stale` on a named blocker:
     * nothing was ever shown.
     *
     * X-H-18 (v0.23): regression is not waivable and not drownable — the
     * lattice's own priority (`ownGrade === 'regressed'` composes `regressed`
     * over missing children, and the recursive path lands a child's honest
     * 'regressed' claim the same way) makes broken work outrank missing work
     * at every level: a waiver excuses only the latter.
     *
     * `cycles` is the defense-in-depth report: empty on any chain this engine
     * alone wrote to, populated the moment a foreign edge closed a loop.
     */
    taskVerdict(input: {
        taskId: string;
        ownGrade?: ProofGrade;
    }): Promise<TaskVerdictResult>;
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
    waiveDelegation(input: {
        taskId: string;
        by: string;
        reason: string;
    }): Promise<void>;
    /**
     * v0.19: every `TaskObligation` on the chain, in log order. Malformed
     * `delegation/created` payloads mint nothing (the `syntheticRequestOf`
     * rule) — but note `delegateTask` still counts them for the sequence, so
     * a skipped marker costs a taskId number, never a collision.
     */
    private delegationObligations;
    /**
     * v0.19: rebuild the full responsibility DAG from the chain — obligations
     * from `delegation/created`, the LATEST submission per task from
     * `delegation/verdict` (log order, so a re-submission overwrites its
     * predecessor — the appeal discipline attestations follow), and the LATEST
     * waiver from `delegation/waive`. Markers that cannot prove their shape,
     * and verdict/waive markers naming unknown tasks, are skipped: they can
     * neither mint obligations nor mutate the ones that exist.
     *
     * v0.25 (K1): every label enters through the floor-bounded read — a
     * shape-legal `delegation/verdict`/`delegation/waive` appended above the
     * vouched checkpoint mutates no node, and `aboveFloor` counts everything
     * withheld so `taskVerdict` can name it instead of hiding it.
     */
    private delegationGraph;
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
    private obligationAnchorKeyId;
    /**
     * H-10: does THIS host hold the anchor key? The one authorization besides
     * the issuing workspace's name: an operator on the machine that holds the
     * key the anchor names can accept the risk of the obligations that key's
     * chain minted. No signer wired, no anchor deployed, an anchor that will
     * not parse, or a different key — all answer false, the conservative
     * direction for a risk-acceptance verb.
     */
    private holdsAnchorKey;
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
    exportTrainingData(options?: TrainingExportOptions): Promise<TrainingExportResult>;
    /**
     * H-16: validate and normalise one caller-supplied export path to a
     * workspace-relative form. Refuses, loudly, on: empty paths, absolute
     * paths (drive letters, `/`-roots and — M-35's lesson — `\\server` UNC
     * roots), and ANY `..` segment (over-strict on purpose: a dotdot that
     * happens to re-enter the workspace is indistinguishable, at this trust
     * boundary, from one that escapes it, and the caller can always name the
     * direct spelling).
     */
    private exportRelPath;
    /**
     * v0.20: the export's chain anchor. Primary source is
     * `latestSignedCheckpoint` — the audit's own "best checkpoint" selection —
     * which yields {count, head} plus the signing key's id. Unsigned chains
     * (and signed deployments whose signer failed to load) fall back to the
     * STORE's `lastWellFormedCheckpoint` — v0.24 (M-4): W1-M7's
     * anchor-answering selection (anchor-key pool, loud `undefined` on an
     * anchor file that exists but cannot be consulted), replacing this
     * module's hand-rolled any-key walk, which let a damaged-anchor host
     * smuggle a foreign, forged-but-well-formed checkpoint into the dataset
     * manifest's chain anchor on exactly the machines an attacker had been at.
     * No checkpoint at all anchors at {0, ''}: an empty dataset over an empty
     * log, distinguishable from a checkpointed one by count alone.
     *
     * Y-H-01 (v0.24): a checkpoint whose declared head contradicts its walked
     * position (the transplant shape) never anchors a dataset — the export's
     * audit gate already refuses such chains (headMismatches fail `ok`), and
     * the corroboration below keeps the predicate true of the selection
     * itself, belt-and-braces.
     */
    private trainingAnchor;
    /**
     * Every *active* attestation on the chain: marker payloads under the
     * 'attest/jury' / 'attest/human' labels, deduplicated per claimId by
     * highest gen (an appeal overrides its predecessor), deterministically
     * ordered.
     *
     * Y-H-03 (v0.24): the read is the ONE verified view's — this used to be the
     * engine's last hand-rolled marker parse, and it was missing the X-H-06
     * generational fallback (V3-M2): a pre-v0.22 chain's attest markers carry
     * no headRef witness, so EVERY one read suspect, the κ fusion starved and
     * endorsement unlock evaporated for any upgraded deployment. The view
     * admits the whole label population degraded when no honest marker
     * survives, so legacy deployments keep exactly the witnesses they had.
     *
     * Visibility note: in a non-degraded generation the view simply does not
     * admit suspect lines, so the old `suspect` count is not derivable from it
     * — an appended twin's exclusion stays visible through
     * `audit().chain.suspectMarkers` (the store's global channel), and the
     * degraded generation is reported here as `degraded` so the boundary
     * marker can carry that fact.
     */
    private activeAttestationsAll;
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
    private attestationProduct;
    /**
     * κ: one-line summary per active witness, for `ContractSummary.attestations`
     * and the boundary markers. Class, generation, verdict and the exact factor
     * the fusion paid — everything a host needs to show who vouched, and how
     * hard, without re-reading the full attest payloads.
     */
    private attestationSummary;
    /**
     * κ: which regime a fused number was earned under. No machine-decisive
     * record with a Class B witness active is `jury-only` (the verdict is the
     * jury's, machines never spoke); every other fusion — machine evidence plus
     * any witness, or a lone Class C witness — is `attested`.
     */
    private static fusedBasis;
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
    private computeApiSurface;
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
    private resolveEntryPoints;
    /** Resolve one relative import against its importer, existence-backed. */
    private resolveModuleSpecifier;
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
    private runBayesianSchedule;
    /**
     * Y-H-05 (v0.24), widened in v0.25 (K1): the line index of the NEWEST
     * checkpoint this host's key actually VERIFIED — the vouched prefix
     * boundary. Records above it ride the log outside any signature the host
     * vouched for, so judgment-class reads (priors history, training-record
     * slices, quote anchors, and — since v0.25 — every trust-consumed marker
     * label: κ fusion, the delegation DAG, drift epochs, own-leg verdicts)
     * refuse them: fresh appends above the floor are STRUCTURALLY invalid for
     * trust, however well-formed their shape.
     *
     * v0.25 (K1): the boundary is a SCAN-BACK, not the positional-last
     * selection. v0.24 derived it from `bestCheckpoint()` — whose selection is
     * one candidate, the positional last — so one appended twin with a garbage
     * signature under this host's own keyId flipped the selection to
     * `refuted` and the FLOOR ITSELF to `undefined`: the eviction of exactly
     * one bad line used to un-vouch the entire honest prefix, re-admitting
     * every forged marker above the real boundary. The floor is now the newest
     * checkpoint of this host's key whose signature verifies under that key —
     * the same derivation the evidence layer's own epoch bound uses for the
     * generational fallback (`verifiedEpochBound`), with deliberate widenings
     * on this face: head-liared and malformed-count checkpoints are not
     * boundary candidates here, because a line whose position or count the
     * walk refutes cannot vouch for the content below it even when its
     * signature is genuine (U2-H1 aligned the epoch bound to the same rule);
     * and since v0.25's repair round (U1-L5) neither is a checkpoint signed
     * for a FOREIGN workspace, however genuine its signature under this key —
     * the W9-M5 laundering judgement, applied to the floor itself. On an
     * honest chain the two derivations agree byte-for-byte (the last
     * checkpoint is the verified one); they differ only under attack, where
     * v0.25 keeps the floor v0.24 dropped.
     *
     * `undefined` when the chain offers no verified checkpoint: an unsigned
     * deployment has no notarisation layer to demand, a keyless host cannot
     * demand one of a foreign key (a missing capability is never an
     * accusation), and a REFUTED-everywhere chain is the audit's forgery
     * charge to answer, not a coverage boundary to inherit. In all three
     * states the pre-boundary read stays exactly what it was — a deployment
     * that runs without keys has, as a deployment fact, no floor and reads
     * the whole log (the `mode: 'unsigned'` statement it made at setup;
     * `audit()` already says it).
     */
    private vouchedFloor;
    /**
     * v0.25 (K1): the floor-bounded marker read — the ONE shape every TRUST
     * decision over a marker label enters through. The verified view already
     * refuses suspect positions and bounds the degraded legacy pool; this adds
     * the third and final cut: on a chain that CAN vouch (a host-verified
     * checkpoint exists), a non-suspect marker ABOVE the vouched floor is a
     * fresh append nobody's signature covers — pattern 5, the shape-legal
     * forgery that passes every structural check — and prices nothing.
     *
     * Keyless/unsigned deployments read the whole label population (floor
     * `undefined` — the deployment fact `vouchedFloor` documents); honest
     * signed chains never notice the cut, because every boundary verb
     * checkpoints over its own markers before the next read runs.
     *
     * The excluded lines are returned, not silently dropped: `withheld` feeds
     * the above-floor COUNT the boundary markers and the verbose narrative
     * carry ("3 markers ride above the last verified checkpoint and price
     * nothing"). Sequence MINTING (`delegateTask`'s max+1, `conjureRequest`'s
     * per-claim count) deliberately still reads the unbounded pool through
     * `markersWith` — an appended marker's number is burned whether or not
     * anyone vouches for it, and re-minting a live number is the aliasing
     * evil V3-M3/X-H-06 closed; allocation is not a trust decision.
     */
    /**
     * v0.26: the floor-bounded read, public for the TOOL face. `proof_jury`
     * binds the deliberation prompt verbatim from the pending request marker —
     * a trust consumption (an out-of-band forged request above the vouched
     * floor must not choose the prompt), so the tools face reads through the
     * same floor the engine's own consumers read through. Allocation reads
     * (gen numbering, seq counters) stay on the unbounded `markersWith`.
     */
    vouchedMarkers(label: string): Promise<{
        readonly records: readonly VerifiedMarkerView[];
        readonly withheld: readonly VerifiedMarkerView[];
        readonly degraded: boolean;
        readonly floor: number | undefined;
    }>;
    private vouchedMarkersWith;
    /**
     * v0.25 (K1): the above-floor narrative line — visible counting, never
     * silent eviction. One verbose line per judgement site; the boundary
     * markers carry the count as a field (see `aboveFloorAttestations` /
     * `aboveFloorMarkers`), so the fact is on the chain even when no logger
     * is wired.
     */
    private logAboveFloor;
    /**
     * Y-H-05 (v0.24): every evidence record with its physical line position —
     * ONE read, ONE pass (the TOCTOU rule), so consumers slice by position
     * (vouched-floor coverage, drift boundaries, export anchors) without
     * re-reading the log per judgement. A repeated address keeps its FIRST
     * position only: append idempotency makes honest repeats impossible, so a
     * repeated line is an appended twin, and the twin never moves a boundary
     * (the V3-M6 rule lifted from the export slice to the shared primitive).
     */
    private indexedEvidenceRecords;
    /**
     * U2-H2 (v0.25): the vouched-floor-bounded form of `store.latest()` —
     * latest-per-check computed over the vouched prefix only. The raw read is
     * a whole-log last-wins map with no position concept, so an out-of-band
     * self-addressing, correctly-chained `pass` row appended above the last
     * checkpoint won it (audit green the whole time — tail rows are not
     * charges) and fed `evaluateContract`'s new-paths-covered fallback; this
     * is Y-H-05's `priorsFor` shape applied to the verdict side. First
     * position per id (the `indexedEvidenceRecords` twin rule: an appended
     * twin never moves a boundary), unsigned deployments read the whole log.
     */
    private vouchedLatestByCheckId;
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
    private priorsFor;
    /**
     * H-03/X-H-01/X-H-19: where each checkId's script-drift epoch begins —
     * the LINE INDEX of the LAST verified `proof/verified` marker, in the
     * CURRENT baseline's epoch, that carries the id in `scriptDrift`. This is
     * the time boundary between the previous body's records and the new
     * body's; `priorsFor` admits a drifted id's records only at positions
     * strictly after it. Drift markers repeat on every verify while the body
     * stays un-re-anchored.
     *
     * v0.24 (V3-M1): LAST sighting wins, not first. The v0.23 first-sighting
     * boundary was the loophole for in-place body swapping: drift to body B1,
     * re-earn a green history across N verifies, then swap to B2 — every B1
     * record sat after the FIRST sighting and B2 inherited the green history
     * wholesale ("its own records alone" broken; the unreviewed-body β was a
     * one-shot rewrite while the learned prior kept compounding). The last
     * drift marker is the newest body-generation statement the chain carries:
     * records after it are that generation's own, and a body change re-cuts
     * the boundary for free — the epoch floor below still isolates
     * cross-generation loops (drift→re-anchor→drift).
     *
     * X-H-01 (v0.23): this used to be the engine's one raw, unfiltered scan of
     * the marker channel — an out-of-band line with an early `at` moved the
     * boundary into the previous body's green history and one forged pass
     * crossed the certify target. The read is now G2's single-pass verified
     * one (`readMarkers` + `excludeSuspect`): an appended twin cannot vouch
     * for its physical position, so it cannot set the boundary. Suspect-only
     * logs (pre-v0.22 upgrades) yield no boundary at all — drifted ids then
     * price fully cold, the conservative direction for a prior.
     *
     * The same single pass also indexes every evidence record's position
     * (`evidenceIndexById`) so the consumer's filter compares positions, not
     * timestamps — one read, two derivations (the TOCTOU rule).
     */
    private scriptDriftFirstSeen;
    /**
     * Fold one whole batch's outcomes into the factor map (display path): each
     * decisive outcome earns its posterior, everything else keeps its prior.
     */
    private updateFactors;
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
    private ledgerFactorsOf;
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
    private runEconomics;
    /**
     * Defensive backstop for E3: the change-set resolution is growing its own
     * `degraded` flag, but a resolution that has not (yet) been taught to emit
     * it must not let a git-invisible workspace silently narrow verification —
     * every git-dependent fact would come back empty and look like "nothing
     * changed". An absent capability means "git available" per the port
     * contract, so only an explicit `false` (or a probe that itself fails —
     * conservative direction is the full run) forces the check set.
     */
    private gitFactsUnavailable;
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
    private gitHeadMissing;
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
    private detectScriptDrift;
    /**
     * H5②: the other half of definition reconciliation — checks the baseline
     * anchored whose ids discovery no longer produces. Deleting a failing
     * check's definition must not quietly shrink the report back to green:
     * the vanished ids surface on the outcome, the boundary marker, and the
     * grade (`assembleProof` blocks `proven` while any are missing).
     */
    private detectVanishedChecks;
    /**
     * H5: drift is a degradation of trust in a definition, so it follows E2's
     * visibility rule — a line on the verbose channel (when wired), and the
     * chain always carries the fact through the `proof/verified` boundary
     * marker this method's callers extend.
     */
    private warnScriptDrift;
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
    private canonicalChanged;
    /**
     * Which files moved since the baseline, and who moved them. Explicit sets
     * are honoured as-is; otherwise the resolution is content-anchored to the
     * baseline's working-tree snapshot, with the plain dirty set as the
     * git-less fallback. Over-attribution costs a re-run; under-attribution
     * hides a break, so unknowns err towards inclusion.
     */
    private resolveChanges;
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
    private snapshotWorkspaceDetailed;
}
//# sourceMappingURL=engine.d.ts.map