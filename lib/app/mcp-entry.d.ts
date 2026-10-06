#!/usr/bin/env node
/**
 * MCP server entry — a standalone process any harness can spawn.
 *
 * Assembles the ProofEngine from environment variables (no Cordis, no DSH
 * host, no plugin config schema) and hands it to `runMcpServer` over stdio.
 * The assembly mirrors src/index.ts's plugin wiring minus every DSH-specific
 * seam (LSP resolver, workspace watcher, hooks, prompt section), with every
 * default taken from config.ts so the two faces stay behaviourally identical
 * unless an operator says otherwise through the environment.
 *
 * Environment (the shared DSH_PROOF_* contract, resolved through
 * adapters/shared/paths.ts's `resolveAdapterEnv` — the ONE parse, so this
 * face cannot drift from the adapter hooks that guard the same store; that
 * drift was H-21: a hook watching `.evi` while this server wrote `.proof`):
 *   DSH_PROOF_ROOT            workspace root the server verifies (default cwd)
 *   DSH_PROOF_TRUST_DIR       trust root for keys/anchors (default $DSH_HOME/proof,
 *                             the same derivation src/index.ts applies). MUST be
 *                             absolute (v0.23, X-H-15): a relative trust root —
 *                             or a relative DSH_HOME it derives from — is a loud
 *                             startup error, never a CWD-relative silent landing
 *   DSH_PROOF_EVIDENCE_STORE  'host' (default; evidence outside the workspace)
 *                             or 'workspace' (evidence inside it). Any OTHER
 *                             non-empty value is a loud startup error — a
 *                             misspelled 'Workspace' silently selecting host
 *                             mode used to move the real log out from under
 *                             the guard without a word.
 *   DSH_PROOF_EVIDENCE_DIR    workspace-mode store segment (default '.proof'),
 *                             the same variable the adapter hooks honour
 *   DSH_PROOF_PTL_DIR         transparency-log directory for proof_publish /
 *                             proof_log_verify (default <trustRoot>/ptl). When
 *                             set explicitly it MUST be absolute (v0.23,
 *                             W10-M2) — same rule, same reason as the trust
 *                             root above — and when the RESOLVED directory
 *                             sits inside the workspace the server warns on
 *                             stderr at startup (v0.24, V4-M7: the operator
 *                             key candidates under it land in the
 *                             agent-writable area; the warning is the
 *                             M-47 containment rule, never a silent pass)
 *   DSH_PROOF_SERVER_VERSION  serverInfo.version override (default
 *                             MCP_DEFAULT_VERSION from mcp-server.ts)
 *   DSH_HOME                  harness home used by the trust-root default
 *
 * Shutdown: stdin EOF ends the read loop (the harness closed the pipe). This
 * entry also installs SIGINT/SIGTERM handlers that end the loop the same way
 * — a signal stops READING, the in-flight message finishes, then the process
 * exits — instead of a default kill that can tear a store append or a check
 * subprocess cleanup in half. A second signal exits immediately.
 *
 * @module dsh-proof/app/mcp-entry
 */
/**
 * v0.23 (X-H-15 entry half + W10-M2): a trust-root-shaped path must be
 * ABSOLUTE, or the server refuses to start.
 *
 * Why: a relative `DSH_PROOF_TRUST_DIR` (or a relative `DSH_HOME`, from
 * which the trust-root default derives) resolves against whatever the
 * current working directory happens to be — the spawned server inherits the
 * harness's CWD, so the SAME environment silently pointed the keys, anchors
 * and operator key at a different physical directory on every spawn, and a
 * workspace-mode CWD put the private key PEM inside the agent-writable
 * workspace (guard lifted, key beside the data it notarises). The PTL
 * directory (`DSH_PROOF_PTL_DIR`) is the same shape of input: a relative
 * spelling once escaped every trust-boundary check and resolved per-CWD.
 *
 * Exported so the other entries (and the wiring tests) pin the SAME rule —
 * a fail-fast check is only as good as every face applying it.
 */
export declare function assertAbsoluteTrustRoot(value: string, name: string): string;
//# sourceMappingURL=mcp-entry.d.ts.map