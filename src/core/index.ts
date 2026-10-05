/**
 * Public surface of the `dsh-proof` domain core.
 *
 * Nothing in here imports `@deepseek-ai/*`. The DSH adapter lives in
 * `../dsh/`, and the test suite in `../../test/` proves the same core runs
 * without a harness.
 *
 * @module dsh-proof/core
 */

export type {
  CheckKind, CheckSource, CheckSpec, Clock, CommandPort, CommandResult,
  CommandRunOptions, FileStat, FsPort, SignerPort, WalkOptions, WorkspacePort,
} from './ports.ts'

export {
  addressOf, canonicalJson, merkleRoot, normalizeOutput, sha256,
} from './hash.ts'

export {
  GENESIS_PREV, checkpointSignedData, lineDigest, parseAnchor, walkChain,
  type AnchorFile, type ChainMode, type ChainWalk, type CheckpointPayload,
  type WalkedCheckpoint,
} from './trust.ts'

export {
  DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS, checkId, discoverChecks,
  type CheckConfigEntry, type DiscoverOptions,
} from './checks.ts'

export {
  DEFAULT_BASELINE_RELPATH, DEFAULT_LOG_RELPATH, EvidenceStore,
  buildBaseline, makeEvidence, snapshotWorkspace, verdictOf,
  type AuditReport, type Baseline, type CheckReport, type CheckStatus,
  type CheckVerdict, type Evidence, type ProofGrade, type ProofReport,
  type RunOutcome, type StoreTrust, type WorkspaceSnapshot,
} from './evidence.ts'

export {
  GLOBAL_INVALIDATORS, attributeChange, buildDependencyGraph, extractImports,
  impactClosure, isGlobalInvalidator, matches, matchesAny, selectAffectedChecks,
  type DependencyGraph, type RelPath, type SelectionResult,
} from './impact.ts'

export {
  attributeChecks, proofNarrative, regressionNarrative,
  type AttributedCheck, type AttributionInput,
} from './regression.ts'

export {
  resolveChangeSet,
  type ChangeProvenance, type ChangeRecord, type ChangeSetInput,
  type ChangeSetMethod, type ChangeSetResolution,
} from './changeset.ts'

export {
  assembleBaseline, assembleProof, type AssembleInput, type AssembleResult,
} from './report.ts'

export {
  VerificationRunner, type BatchResult, type RunnerOptions,
} from './runner.ts'
