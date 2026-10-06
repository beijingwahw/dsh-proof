/**
 * Physical artifact locations for a host adapter (Claude Code, OpenCode, …).
 *
 * Adapter hooks do not share an address space with the MCP server that runs
 * the engine — every hook invocation is its own process — so the only way the
 * two sides can agree on where the evidence log, the baseline and the anchor
 * live is to derive those paths from the same inputs by the same rules. This
 * module IS that rule set, mirroring the engine's private derivations
 * (engine.ts constructor) and the standalone MCP entry's assembly
 * (app/mcp-entry.ts) so a hook process and a server process land on the same
 * bytes without either being able to ask the other.
 *
 * The evidence-store guard here (`touchesEvidencePath`) compares paths
 * case-insensitively and slash-insensitively on both sides — the same H10
 * fold src/index.ts's guard applies, so adapter hooks and the DSH plugin
 * agree on what "inside the evidence store" means (see the guard's own
 * comment for the lockstep rule).
 *
 * @module dsh-proof/adapters/shared/paths
 */

import { homedir } from 'node:os'
import * as nodePath from 'node:path'

import { sha256 } from '../../core/hash.ts'
import { toWorkspaceRelative } from '../../dsh/observe.ts'

/** Every location a host adapter needs, in one derivable bundle. */
export interface ProofPaths {
  /** Workspace root, POSIX-style ('/' separators, drive letters kept). */
  readonly root: string
  /** Host-side trust root (keys, anchors, adapter sessions) — outside the workspace. */
  readonly trustRoot: string
  /** 'workspace' keeps evidence inside the project; 'host' (default) moves it under trustRoot. */
  readonly evidenceStore: 'host' | 'workspace'
  /** The evidence store's relative segment inside the workspace (e.g. '.proof'). */
  readonly evidenceDir: string
  /** Directory holding evidence.jsonl + baseline.json. */
  readonly logDir: string
  /** The hash-chained evidence log. */
  readonly logPath: string
  /** The anchored baseline the gates probe for. */
  readonly baselinePath: string
  /** Out-of-band anchor directory (engine.ts's `${trustDir}/anchors/<key>` layout). */
  readonly anchorDir: string
  /** The anchor file checkpoints mirror to. */
  readonly anchorPath: string
  /** Where adapters persist per-session watcher snapshots. */
  readonly sessionDir: string
  /** Stable workspace identity: sha256(root).slice(0, 16), as index.ts/mcp-entry.ts mint it. */
  readonly workspaceKey: string
}

/**
 * Windows drive letter or leading slash — engine.ts's private absolute-path
 * test, mirrored exactly as src/index.ts and app/mcp-entry.ts mirror it. The
 * store-dir derivation must agree with the engine's or adapters would read a
 * different log than the one the engine appends to.
 */
function isAbsoluteHostPath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

/** Fold backslashes to '/' — ProofPaths speaks one separator style everywhere. */
function toPosix(p: string): string {
  return p.replace(/\\/g, '/')
}

/**
 * The harness home directory — mcp-entry.ts:39-43's derivation, mirrored so a
 * spawned MCP server and an adapter hook derive the SAME trust root from the
 * SAME environment. If that rule ever moves, this mirror must move with it.
 */
function dshHome(): string {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv
  return nodePath.join(homedir(), '.dsh')
}

/**
 * Derive every adapter-facing artifact path from a host's configuration.
 *
 * - `root` defaults to `process.cwd()` (what harnesses set as the session
 *   workspace, mirroring index.ts's `hostWorkspaceRoot` fallback).
 * - `trustRoot` defaults to `$DSH_HOME/proof` with `DSH_HOME` itself defaulting
 *   to `~/.dsh` — the mcp-entry derivation, byte for byte.
 * - `evidenceStore` switches to 'workspace' only on the exact string, like
 *   mcp-entry's env parse; anything else means host mode.
 * - `evidenceDir` is the workspace-mode relative segment (default '.proof').
 */
export function deriveProofPaths(env: {
  root?: string
  trustRoot?: string
  evidenceStore?: string
  evidenceDir?: string
} = {}): ProofPaths {
  // The workspace key hashes the root EXACTLY as the host spells it — before
  // POSIX normalisation. index.ts and mcp-entry.ts compute sha256(root) on the
  // raw string, and on Windows that raw string is backslashed; normalising
  // first would mint a different key and silently point the adapter's gates at
  // a different `workspaces/<key>` directory than the one the MCP server
  // actually writes to. Byte-parity with the host beats a pretty input.
  const rawRoot = env.root !== undefined && env.root.length > 0 ? env.root : process.cwd()
  const workspaceKey = sha256(rawRoot).slice(0, 16)
  const root = toPosix(rawRoot).replace(/\/+$/, '')
  const trustRoot = toPosix(
    env.trustRoot !== undefined && env.trustRoot.length > 0 ? env.trustRoot : nodePath.join(dshHome(), 'proof'),
  ).replace(/\/+$/, '')
  const evidenceStore: 'host' | 'workspace' = env.evidenceStore === 'workspace' ? 'workspace' : 'host'
  // The segment form used by the guard's comparisons: strip a './' prefix and
  // trailing slashes (index.ts:168's normalisation). An absolute evidenceDir is
  // left as-is here — the guard then simply never matches it, which is honest:
  // an absolute store is by construction not an agent-relative path.
  const configured = env.evidenceDir !== undefined && env.evidenceDir.length > 0 ? env.evidenceDir : '.proof'
  const evidenceDir = toPosix(configured).replace(/^\.\/+/, '').replace(/\/+$/, '')

  // logDir mirrors the engine's own storeDir rule (engine.ts constructor):
  // host mode parks evidence under the trust root keyed by workspace identity
  // (mcp-entry.ts:70-77), workspace mode resolves the relative segment against
  // the root. Deriving it any other way would split the log across two dirs.
  const logDir = evidenceStore === 'host'
    ? `${trustRoot}/workspaces/${workspaceKey}`
    : (isAbsoluteHostPath(configured)
        ? toPosix(configured).replace(/\/+$/, '')
        : `${root}/${evidenceDir}`)

  return {
    root,
    trustRoot,
    evidenceStore,
    evidenceDir,
    logDir,
    logPath: `${logDir}/evidence.jsonl`,
    baselinePath: `${logDir}/baseline.json`,
    // engine.ts:489: the anchor lives in the trust root, keyed by the same
    // workspace identity the checkpoints commit to.
    anchorDir: `${trustRoot}/anchors/${workspaceKey}`,
    anchorPath: `${trustRoot}/anchors/${workspaceKey}/anchor.json`,
    sessionDir: `${trustRoot}/adapter-sessions`,
    workspaceKey,
  }
}

/**
 * Collapse `.` and `..` segments in a workspace-relative path (`a/../b` ->
 * `b`). A leading `..` that would escape the root is kept — index.ts:408-416's
 * rule — so a path that leaves the workspace never comes out looking like it
 * is inside it (the caller's comparison then honestly fails to match).
 */
function collapseSegments(rel: string): string {
  const out: string[] = []
  for (const segment of rel.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..' && out.length > 0 && out[out.length - 1] !== '..') out.pop()
    else out.push(segment)
  }
  return out.join('/')
}

/**
 * Does a candidate tool-call path land inside the evidence store this
 * workspace is configured to protect?
 *
 * Semantics mirror index.ts's guard (the H10 fold, both sides): project the
 * candidate onto the workspace's relative space (absolute host paths, either
 * slash flavour, `.`/`..` detours collapsed; a path escaping the root keeps
 * its leading `..` and therefore never matches). Both sides are compared
 * `toLowerCase()`d. On a Windows host, `.PROOF/evidence.jsonl` names the same
 * file as `.proof/evidence.jsonl`, and a case-sensitive comparison let the
 * agent walk the guard by changing one letter's case. The price is that on a
 * genuinely case-sensitive filesystem a sibling `.PROOF` directory would also
 * match — an over-deny that costs one blocked call, versus an under-deny that
 * costs the evidence log the whole plugin exists to keep honest. index.ts
 * folds the same way (case AND backslashes) since the H10 batch — the two
 * guards are deliberately in lockstep; if one learns a new normalisation,
 * the other must learn it in the same batch.
 *
 * The `evidenceDir` segment is additionally backslash-folded here even though
 * `deriveProofPaths` already hands it over POSIX-spelled: a hand-assembled
 * `ProofPaths` (a host adapter, a future entry point) must not be able to
 * re-open the `'.\proof'`-vs-`./proof` hole index.ts closed — defence in
 * depth on the segment that names the store.
 *
 * Host mode never matches: the store lives outside the workspace, so nothing
 * the agent can name relatively is it (and absolute foreign paths already
 * fail `toWorkspaceRelative`).
 */
export function touchesEvidencePath(candidate: string, paths: ProofPaths): boolean {
  if (paths.evidenceStore !== 'workspace') return false
  const rel = toWorkspaceRelative(candidate, paths.root)
  if (rel === undefined) return false
  const target = collapseSegments(rel).toLowerCase()
  const evidence = collapseSegments(paths.evidenceDir.replace(/\\/g, '/')).toLowerCase()
  return target === evidence || target.startsWith(`${evidence}/`)
}
