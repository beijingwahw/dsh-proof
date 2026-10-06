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
 *                             the same derivation src/index.ts applies)
 *   DSH_PROOF_EVIDENCE_STORE  'host' (default; evidence outside the workspace)
 *                             or 'workspace' (evidence inside it). Any OTHER
 *                             non-empty value is a loud startup error — a
 *                             misspelled 'Workspace' silently selecting host
 *                             mode used to move the real log out from under
 *                             the guard without a word.
 *   DSH_PROOF_EVIDENCE_DIR    workspace-mode store segment (default '.proof'),
 *                             the same variable the adapter hooks honour
 *   DSH_PROOF_PTL_DIR         transparency-log directory for proof_publish /
 *                             proof_log_verify (default <trustRoot>/ptl)
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

import { homedir } from 'node:os'
import * as nodePath from 'node:path'

import { ProofEngine } from '../engine.ts'
import {
  GitWorkspace, NodeCommandPort, NodeEd25519Signer, NodeFsPort, SystemClock,
} from '../node-ports.ts'
import { deriveProofPaths, resolveAdapterEnv } from '../adapters/shared/paths.ts'
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

/** One clean line on stderr + a non-zero exit code for a fatal startup error. */
function failStartup(message: string): never {
  process.stderr.write(`[agent-proof-protocol] fatal: ${message}\n`)
  process.exit(1)
}

async function main(): Promise<void> {
  // H-21 (v0.22): the DSH_PROOF_* contract is parsed by the shared resolver
  // — the same function the Claude Code hooks and the OpenCode plugin use —
  // so a variable means the same thing in the guard process and in this
  // server process. Precedence (env beats code default) is layered HERE.
  const resolved = resolveAdapterEnv(process.env)
  const root = resolved.root ?? process.cwd()
  // Trust root: keys and anchors live with the host, never in the workspace —
  // same precedence as the plugin (env wins, then DSH_HOME-derived default).
  const trustRoot = resolved.trustRoot ?? nodePath.join(dshHome(), 'proof')
  // The evidence store mode is a two-value switch: anything else non-empty is
  // an operator error, and a silent fallback to host mode would point the
  // guard at a phantom store while the real log writes elsewhere.
  if (resolved.evidenceStore !== undefined
    && resolved.evidenceStore !== 'host' && resolved.evidenceStore !== 'workspace') {
    failStartup(`DSH_PROOF_EVIDENCE_STORE must be 'host' or 'workspace' (got ${JSON.stringify(resolved.evidenceStore)}) — refusing to guess where evidence lives`)
  }
  const evidenceStore = resolved.evidenceStore === 'workspace' ? 'workspace' : 'host'
  // v0.18 (§6): the public transparency log. Default <trustRoot>/ptl — beside
  // the keys and anchors, never inside the agent-writable workspace, so the
  // published tree and the operator key (<ptlDir>/operator-key) live on the
  // host side of the trust boundary. An explicit DSH_PROOF_PTL_DIR wins.
  const ptlDir = (() => {
    const explicit = process.env.DSH_PROOF_PTL_DIR
    return typeof explicit === 'string' && explicit.length > 0 ? explicit : nodePath.join(trustRoot, 'ptl')
  })()
  // M-39/H-21 (MCP half): the workspace identity is derived through the SAME
  // derivation the adapters use — normalised root spelling, legacy-key
  // fallback probe included — instead of a raw sha256(root) that spelled the
  // root differently from the hooks' derivation and split one workspace into
  // two stores. Every artifact location below comes from that derivation, so
  // the server and the guards can never disagree about where evidence lives.
  const paths = deriveProofPaths({
    root,
    trustRoot,
    evidenceStore,
    ...(resolved.evidenceDir !== undefined && resolved.evidenceDir.length > 0 ? { evidenceDir: resolved.evidenceDir } : {}),
  })
  const workspaceKey = paths.workspaceKey
  // Host mode keeps evidence under the trust root (outside the workspace);
  // workspace mode honours DSH_PROOF_EVIDENCE_DIR (config.ts's '.proof'
  // default), normalized exactly as deriveProofPaths normalizes the segment.
  const evidenceDir = evidenceStore === 'workspace'
    ? paths.evidenceDir
    : paths.logDir
  // The engine's own storeDir derivation (engine.ts constructor): absolute
  // evidence dirs are used as-is, relative ones resolve against the root —
  // paths.logDir IS that dir, derived once, shared by guards and server.

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
    // key (<ptlDir>/operator-key) bootstraps on first publish, exactly like the
    // workspace chain key under <trustRoot>/keys.
    ptlDir,
  })

  // Graceful shutdown (v0.22): a signal ends the read loop — the in-flight
  // message completes, the process then exits on its own — instead of the
  // default kill tearing a store append in half. A second signal is force.
  const server = runMcpServer({
    engine,
    // Physical artifact locations, all from the one shared derivation above
    // (guards and server cannot disagree about where evidence lives).
    evidenceLogPath: paths.logPath,
    baselinePath: paths.baselinePath,
    anchorPath: paths.anchorPath,
    workspaceKey,
    ptlDir,
    trustRoot,
    serverVersion: (() => {
      const explicit = process.env.DSH_PROOF_SERVER_VERSION
      return typeof explicit === 'string' && explicit.length > 0 ? explicit : MCP_DEFAULT_VERSION
    })(),
  })
  let signalCount = 0
  const onSignal = (): void => {
    signalCount += 1
    if (signalCount > 1) process.exit(0)
    // Ends the read loop the same way stdin EOF does: the current message
    // finishes, then runMcpServer resolves and main() returns.
    process.stdin.destroy()
  }
  process.on('SIGINT', onSignal)
  process.on('SIGTERM', onSignal)
  await server
}

main().catch((error: unknown) => {
  // stdout belongs to the protocol; a fatal startup error goes to stderr and
  // a non-zero exit code, so the spawning harness sees a dead server rather
  // than a silently half-alive one.
  console.error(`[agent-proof-protocol] fatal: ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  process.exitCode = 1
})
