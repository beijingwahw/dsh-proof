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
export { BUNDLE_MEDIA_TYPE, CHAIN_MODES, CHECK_STATUSES, CLAIM_KINDS, GRADE_VALUES, LEGACY_PROTOCOL_VERSIONS, PROOF_MEDIA_TYPE, PROTOCOL_NAME, PROTOCOL_VERSION, VERDICT_VALUES, adjudicateProtocol, appFingerprint, appFingerprintOfVersion, knownDialects, protocolHeader, type BundleManifest, type KnownDialect, type ProtocolAdjudication, } from './protocol.ts';
export { ANCHOR_FILE, BASELINE_FILE, EVIDENCE_FILE, buildBundle, verifyBundle, type BundleAnchor, type BundleAnchorSigner, type BundleChainMode, type BundleExtras, type BundleInput, type BundleVerification, type ManifestFileEntry, type ManifestTransparency, type ProofBundle, type TransparentBundleManifest, type VerifyBundleOptions, } from './bundle.ts';
export { MCP_TOOLS, createMcpHandler, runMcpServer, type McpEngineDeps, } from './mcp-server.ts';
export { TransparencyLog, loadPtl, ptlLeafHash, sthSignedData, verifyConsistency, verifyInclusion, verifyTreeHead, type PtlEntry, type SignedTreeHead, } from '../core/transparency.ts';
//# sourceMappingURL=index.d.ts.map