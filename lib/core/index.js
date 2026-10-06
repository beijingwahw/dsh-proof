/**
 * Public surface of the `dsh-proof` domain core.
 *
 * Nothing in here imports `@deepseek-ai/*`. The DSH adapter lives in
 * `../dsh/`, and the test suite in `../../test/` proves the same core runs
 * without a harness.
 *
 * @module dsh-proof/core
 */
export { addressOf, canonicalJson, merkleRoot, normalizeOutput, sha256, } from "./hash.js";
export { DEFAULT_TRUST_WEIGHTS, JURY_RUBRIC, RUBRIC_V1, activeAttestations, attestationFactor, attestationsFor, claimIdOf, juryPrompt, } from "./attest.js";
export { GENESIS_PREV, checkpointSignedData, lineDigest, parseAnchor, walkChain, } from "./trust.js";
export { DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS, checkId, discoverChecks, } from "./checks.js";
export { diffApiSurface, evaluateContract, extractApiSurface, isDocsPath, } from "./contract.js";
export { DEFAULT_BASELINE_RELPATH, DEFAULT_LOG_RELPATH, EvidenceStore, buildBaseline, isDecisiveStatus, makeEvidence, snapshotWorkspace, verdictOf, } from "./evidence.js";
export { GLOBAL_INVALIDATORS, attributeChange, buildDependencyGraph, extractImports, extractImportSites, impactClosure, isGlobalInvalidator, matches, matchesAny, selectAffectedChecks, } from "./impact.js";
export { attributeChecks, proofNarrative, regressionNarrative, } from "./regression.js";
export { resolveChangeSet, } from "./changeset.js";
export { excerptOutput, firstInformativeLine, isSalientLine, } from "./excerpt.js";
// τ: the coverage-aware-proof pure domain — V8 report parsing, change-set
// summarisation and the gate that keeps "green but never executed" honest.
export { coverageGate, parseV8CoverageReport, summarizeCoverage, } from "./coverage.js";
export { applyCoverageGate, assembleBaseline, assembleProof, } from "./report.js";
export { VerificationRunner, } from "./runner.js";
export { BAYES_CONSTANTS, claimProbability, computePriors, posteriorHealthy, rankByInformationGain, summarizeHistory, } from "./bayes.js";
// ο: the synthetic-evidence domain — scaffold, request, capability screen,
// spec minting and the self-certifying metadata synthetic records carry.
// (bayes/contract/evidence need no new export points of their own: the
// synthetic surface they consume is exactly these types, PriorInput's new
// optional knob and Evidence's new optional fields ride types already
// exported above.)
export { FORBIDDEN_CAPABILITIES, SYNTHETIC_DIR_DEFAULT, SYNTHETIC_TEMPLATE, sandboxEntryFor, screenScript, syntheticSpec, } from "./synthetic.js";
//# sourceMappingURL=index.js.map