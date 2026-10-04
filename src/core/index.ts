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
  CommandRunOptions, FileStat, FsPort, WalkOptions, WorkspacePort,
} from './ports.ts'

export {
  addressOf, canonicalJson, merkleRoot, normalizeOutput, sha256,
} from './hash.ts'

export {
  DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS, checkId, discoverChecks,
  type CheckConfigEntry, type DiscoverOptions,
} from './checks.ts'

export {
  DEFAULT_BASELINE_RELPATH, DEFAULT_LOG_RELPATH, EvidenceStore,
  buildBaseline, makeEvidence, snapshotWorkspace, verdictOf,
  type Baseline, type CheckReport, type CheckStatus, type CheckVerdict,
  type Evidence, type ProofGrade, type ProofReport, type RunOutcome,
  type WorkspaceSnapshot,
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
  assembleBaseline, assembleProof, type AssembleInput, type AssembleResult,
} from './report.ts'

export {
  VerificationRunner, type BatchResult, type RunnerOptions,
} from './runner.ts'
