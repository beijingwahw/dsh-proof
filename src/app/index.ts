/**
 * Public surface of the `dsh-proof` app layer — the framework-free faces.
 *
 * Two families live here: the APP/1.0 protocol artifacts (`protocol.ts` for
 * the frozen vocabularies and fingerprint, `bundle.ts` for the portable
 * exchange format a third party audits) and the MCP server that serves the
 * same verification engine to agents outside DeepSeek Harness. The one module
 * deliberately NOT re-exported is `mcp-entry.ts`: it is a process entry, not
 * a library — importers get `runMcpServer` and wire their own deps.
 *
 * Same discipline as `src/core/index.ts`: nothing under this directory
 * imports `@deepseek-ai/*`, so any host can consume the standard and the
 * stdio server without the harness.
 *
 * @module dsh-proof/app
 */

export {
  BUNDLE_MEDIA_TYPE, CHAIN_MODES, CHECK_STATUSES, CLAIM_KINDS, GRADE_VALUES,
  LEGACY_PROTOCOL_VERSIONS, PROOF_MEDIA_TYPE, PROTOCOL_NAME, PROTOCOL_VERSION, VERDICT_VALUES,
  adjudicateProtocol, appFingerprint, appFingerprintOfVersion, knownDialects, protocolHeader,
  type BundleManifest, type KnownDialect, type ProtocolAdjudication,
} from './protocol.ts'

export {
  ANCHOR_FILE, BASELINE_FILE, EVIDENCE_FILE, buildBundle, verifyBundle,
  type BundleAnchor, type BundleAnchorSigner, type BundleChainMode, type BundleExtras,
  type BundleInput, type BundleVerification, type ManifestFileEntry, type ManifestTransparency,
  type ProofBundle, type TransparentBundleManifest, type VerifyBundleOptions,
} from './bundle.ts'

// The MCP face: the frozen five-tool contract, the pure per-message
// dispatcher, the stdio loop, and the deps a host assembles to run them.
// MCP_SERVER_NAME / MCP_DEFAULT_VERSION stay unexported here — they are the
// server's own identity, not part of the embedding API.
export {
  MCP_TOOLS, createMcpHandler, runMcpServer,
  type McpEngineDeps,
} from './mcp-server.ts'

// v0.18: the transparency-log domain the bundle manifest (`transparency`
// record) and the MCP tools (`proof_publish` / `proof_log_verify`) publish
// into. Re-exported from the app barrel — not the core barrel — because it
// is the audit vocabulary of the artifacts this layer defines: a third party
// holding a bundle with a transparency record needs exactly these functions
// to adjudicate it against any log copy. The write path (appendPtlEntry /
// savePtlHead) and the CLI entry (ptl-entry.ts) stay unexported — appending
// is the operator's job, and `ptl-entry` is a process entry like
// `mcp-entry`, not a library.
export {
  TransparencyLog, loadPtl, ptlLeafHash, sthSignedData, verifyConsistency,
  verifyInclusion, verifyTreeHead,
  type PtlEntry, type SignedTreeHead,
} from '../core/transparency.ts'
