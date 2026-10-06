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
 * Environment:
 *   DSH_PROOF_ROOT            workspace root the server verifies (default cwd)
 *   DSH_PROOF_TRUST_DIR       trust root for keys/anchors (default $DSH_HOME/proof,
 *                             the same derivation src/index.ts applies)
 *   DSH_PROOF_EVIDENCE_STORE  'host' (default; evidence outside the workspace)
 *                             or 'workspace' (evidence at .proof inside it)
 *   DSH_PROOF_PTL_DIR         transparency-log directory for proof_publish /
 *                             proof_log_verify (default <trustRoot>/ptl)
 *   DSH_PROOF_SERVER_VERSION  serverInfo.version override (default '0.14.0')
 *   DSH_HOME                  harness home used by the trust-root default
 *
 * @module dsh-proof/app/mcp-entry
 */

import { homedir } from 'node:os'
import * as nodePath from 'node:path'

import { sha256 } from '../core/hash.ts'
import { ProofEngine } from '../engine.ts'
import {
  GitWorkspace, NodeCommandPort, NodeEd25519Signer, NodeFsPort, SystemClock,
} from '../node-ports.ts'
import { MCP_DEFAULT_VERSION, runMcpServer } from './mcp-server.ts'

/**
 * The harness home directory — copied from src/index.ts's dshHome() so the
 * standalone server and the plugin derive the SAME trust root from the SAME
 * environment. If index.ts's rule ever moves, this mirror must move with it.
 */
function dshHome(): string {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv
  return nodePath.join(homedir(), '.dsh')
}

/**
 * Windows drive letter or leading slash — engine.ts's private absolute-path
 * test, mirrored exactly as src/index.ts mirrors it for `evidenceLogPath`.
 * The entry must derive the physical store path by the same rule the engine
 * used for its own copy, or the MCP tools would read a different log than the
 * one the engine appends to.
 */
function isAbsoluteHostPath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

function envString(name: string): string | undefined {
  const value = process.env[name]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

async function main(): Promise<void> {
  const root = envString('DSH_PROOF_ROOT') ?? process.cwd()
  // Trust root: keys and anchors live with the host, never in the workspace —
  // same precedence as the plugin (env wins, then DSH_HOME-derived default).
  const trustRoot = envString('DSH_PROOF_TRUST_DIR') ?? nodePath.join(dshHome(), 'proof')
  const evidenceStore = envString('DSH_PROOF_EVIDENCE_STORE') === 'workspace' ? 'workspace' : 'host'
  // v0.18 (§6): the public transparency log. Default <trustRoot>/ptl — beside
  // the keys and anchors, never inside the agent-writable workspace, so the
  // published tree and the operator key (<ptlDir>/operator-key) live on the
  // host side of the trust boundary. An explicit DSH_PROOF_PTL_DIR wins.
  const ptlDir = envString('DSH_PROOF_PTL_DIR') ?? nodePath.join(trustRoot, 'ptl')
  const workspaceKey = sha256(root).slice(0, 16)
  // Host mode keeps evidence under the trust root (outside the workspace);
  // workspace mode puts it back at config.ts's default '.proof', relative.
  const evidenceDir = evidenceStore === 'workspace'
    ? '.proof'
    : nodePath.join(trustRoot, 'workspaces', workspaceKey)
  // The engine's own storeDir derivation (engine.ts constructor): absolute
  // evidence dirs are used as-is, relative ones resolve against the root.
  const storeDir = isAbsoluteHostPath(evidenceDir)
    ? evidenceDir.replace(/[\/]+$/, '')
    : `${root.replace(/[\/]+$/, '')}/${evidenceDir}`

  const commands = new NodeCommandPort()
  const clock = new SystemClock()
  const engine = new ProofEngine({
    root,
    evidenceDir,
    trustDir: trustRoot,
    workspaceKey,
    // config.ts defaults, one for one.
    checkpointEvery: 25,
    fs: new NodeFsPort(),
    commands,
    workspace: new GitWorkspace(root, commands, clock),
    clock,
    // The trust wiring is explicit here: the Ed25519 signer loads from
    // <trustRoot>/keys, exactly the provider the engine would build from
    // trustDir on its own — stated plainly so the assembly reads complete.
    signer: () => NodeEd25519Signer.load(nodePath.join(trustRoot, 'keys')),
    autoDiscover: true,
    checks: [],
    checkTimeoutMs: 120_000,
    verifyBudgetMs: 300_000,
    concurrency: 2,
    scheduler: 'bayesian',
    certifyTarget: 0.97,
    impactGraph: true,
    impactGraphLimit: 20_000,
    excerptStrategy: 'balanced',
    // config.ts's normalizeHome default is true: canonicalise $HOME in
    // captured evidence for privacy and cross-machine comparability.
    homeDir: homedir(),
    juryConfidenceCap: 0.8,
    classBTrust: 0.7,
    classCTrust: 0.9,
    syntheticDir: '.proof-synthetic',
    syntheticFalsePass: 0.15,
    syntheticTimeoutMs: 60_000,
    coverage: 'observe',
    // v0.18: publishing is ON by default in the standalone face — the operator
    // key (<ptlDir>/operator-key) bootstraps on first publish, exactly like
    // the workspace chain key under <trustRoot>/keys.
    ptlDir,
  })

  await runMcpServer({
    engine,
    // Physical artifact locations derived with the engine's own rules (the
    // engine exports neither the paths nor their derivation): the log and
    // baseline sit in the store dir, the anchor in the trust root keyed by
    // workspace identity — engine.ts's EvidenceStore layout verbatim.
    evidenceLogPath: `${storeDir}/evidence.jsonl`,
    baselinePath: `${storeDir}/baseline.json`,
    anchorPath: `${trustRoot}/anchors/${workspaceKey}/anchor.json`,
    workspaceKey,
    ptlDir,
    serverVersion: envString('DSH_PROOF_SERVER_VERSION') ?? MCP_DEFAULT_VERSION,
  })
}

main().catch((error: unknown) => {
  // stdout belongs to the protocol; a fatal startup error goes to stderr and
  // a non-zero exit code, so the spawning harness sees a dead server rather
  // than a silently half-alive one.
  console.error(`[agent-proof-protocol] fatal: ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  process.exitCode = 1
})
