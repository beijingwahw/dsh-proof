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
 * fold src/index.ts's guard applies — plus the Win32 name deformations the
 * H10 batch missed (trailing dots/spaces per segment, H-25), so adapter hooks
 * and the DSH plugin agree on what "inside the evidence store" means (see the
 * guard's own comment for the lockstep rule).
 *
 * `resolveAdapterEnv` is the ONE place the DSH_PROOF_* environment contract
 * is parsed. Both host adapters consume it, and app/mcp-entry.ts (F9) aligns
 * with the same variable names through it — a variable only one face reads is
 * a forked deployment, not a configuration (H-21).
 *
 * @module dsh-proof/adapters/shared/paths
 */

import { existsSync } from 'node:fs'
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
  /** Where adapters persist per-session watcher snapshots — isolated per workspaceKey (H-19). */
  readonly sessionDir: string
  /** Stable workspace identity: sha256(normalised root).slice(0, 16) — see {@link normalizeWorkspaceRoot}. */
  readonly workspaceKey: string
}

/**
 * Windows drive letter, drive-letter path, or either UNC slash flavour
 * (`\\server\share` and `//server/share`) — engine.ts's private
 * absolute-path test plus the UNC spellings that test used to miss (H-25:
 * a backslashed UNC used to read as "relative", silently parking the store
 * INSIDE the workspace the operator asked to keep it out of). Mirrored by
 * src/index.ts and app/mcp-entry.ts; the store-dir derivation must agree
 * with the engine's or adapters would read a different log than the one the
 * engine appends to.
 */
function isAbsoluteHostPath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|[\\/]{2})/.test(p)
}

/** Fold backslashes to '/' — ProofPaths speaks one separator style everywhere. */
function toPosix(p: string): string {
  return p.replace(/\\/g, '/')
}

/**
 * Canonical spelling for workspace IDENTITY (H-25 / M-39): backslashes fold
 * to '/', a Windows drive letter folds to lowercase, trailing slashes drop.
 * The pre-v0.23 key hashed the root exactly as the host spelled it, so one
 * directory legitimately arrived as four identities (`C:\proj`, `C:/proj`,
 * `c:\proj`, `C:\proj\`) and gates, engine and MCP server silently split
 * their stores. Hashing THIS form makes spelling variants one identity.
 *
 * Exported so index.ts / mcp-entry.ts (which mint the same key from
 * process.cwd() or DSH_PROOF_ROOT) can hash the identical string — the
 * byte-parity rule now lives in one function instead of N mirrors.
 */
export function normalizeWorkspaceRoot(raw: string): string {
  const posix = toPosix(raw).replace(/\/+$/, '')
  // Drive-letter case: `C:/ws` and `c:/ws` are the same directory on every
  // filesystem that spells drives this way. Nothing else folds here — POSIX
  // roots stay case-sensitive, deliberately.
  return /^([A-Za-z]):\//.test(posix) ? posix.slice(0, 1).toLowerCase() + posix.slice(1) : posix
}

/** The identity pair a root carries: the canonical spelling's key and the pre-v0.23 raw-hash key. */
export function workspaceKeyPair(rawRoot: string): { readonly normalized: string; readonly legacy: string } {
  return {
    normalized: sha256(normalizeWorkspaceRoot(rawRoot)).slice(0, 16),
    legacy: sha256(rawRoot).slice(0, 16),
  }
}

/**
 * Best-effort stderr: diagnostics must never take the derivation down, and
 * must never be silently swallowed either (the "warn + narrative" rule).
 */
function defaultWarn(line: string): void {
  try {
    process.stderr.write(`${line}\n`)
  } catch {
    /* a closed stderr is not a reason to fail path derivation */
  }
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

/** Knobs for {@link deriveProofPaths}: the disk probe and diagnostics sink. */
export interface DeriveOptions {
  /**
   * Existence probe over the real filesystem. Default: `fs.existsSync`
   * guarded to `false`. Only consulted when the normalised and legacy
   * workspace keys DIFFER (a Windows-flavoured root); a pure derivation can
   * pass `{ pure: true }` and skip it.
   */
  readonly exists?: (p: string) => boolean
  /** Diagnostics sink, one line per call. Default: best-effort process.stderr. */
  readonly warn?: (line: string) => void
  /** Skip the on-disk identity probe: the key is then always the normalised one. */
  readonly pure?: boolean
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
 *
 * Identity (H-25): the workspace key hashes {@link normalizeWorkspaceRoot}'s
 * output. Existing on-disk state is never orphaned: when the normalised key
 * has no anchor/workspace directory but the LEGACY (raw-hash) key does, the
 * legacy key stays in use and one stderr line explains the migration. Probe
 * order is anchors first (the engine's out-of-band commitment), then
 * workspaces (baselines exist without a signer too).
 *
 * Sessions (H-19): `sessionDir` is per-workspaceKey, so the same session id
 * in two workspaces can never observe into one ledger.
 */
export function deriveProofPaths(
  env: {
    root?: string
    trustRoot?: string
    evidenceStore?: string
    evidenceDir?: string
  } = {},
  options: DeriveOptions = {},
): ProofPaths {
  const warn = options.warn ?? defaultWarn
  const rawRoot = env.root !== undefined && env.root.length > 0 ? env.root : process.cwd()
  const root = toPosix(rawRoot).replace(/\/+$/, '')
  const trustRoot = toPosix(
    env.trustRoot !== undefined && env.trustRoot.length > 0 ? env.trustRoot : nodePath.join(dshHome(), 'proof'),
  ).replace(/\/+$/, '')
  const evidenceStore: 'host' | 'workspace' = env.evidenceStore === 'workspace' ? 'workspace' : 'host'

  // -- identity: normalised spelling, with a legacy fallback probe ------------
  const pair = workspaceKeyPair(rawRoot)
  let workspaceKey = pair.normalized
  if (pair.normalized !== pair.legacy && options.pure !== true) {
    const exists = options.exists ?? ((p: string) => {
      try {
        return existsSync(p)
      } catch {
        return false
      }
    })
    const stateAt = (key: string): boolean =>
      exists(`${trustRoot}/anchors/${key}`) || exists(`${trustRoot}/workspaces/${key}`)
    if (stateAt(pair.normalized)) {
      // Fresh-canonical or already migrated: nothing to say.
    } else if (stateAt(pair.legacy)) {
      workspaceKey = pair.legacy
      warn(`dsh-proof: workspace identity for ${root} still lives under the pre-normalisation key `
        + `${pair.legacy} (anchors/workspaces on disk pre-date path normalisation); keeping it so existing `
        + `state is not orphaned. Re-baselining once will migrate the store to the normalised key.`)
    }
    // Neither exists: a fresh workspace takes the canonical normalised key.
  }

  // -- the trust boundary is a claim, and claims get checked loudly -----------
  // config.ts documents "trust root must stay outside every agent-writable
  // workspace"; this is where both values are finally known at once, so the
  // containment check lives here (M-47: warn + narrative, never silent). The
  // comparison case-folds: the same Windows directory arrives in both drive
  // cases across processes, and a case-sensitive check here would silently
  // miss exactly the deployment it exists to catch.
  const foldedRoot = root.toLowerCase()
  const foldedTrust = trustRoot.toLowerCase()
  if (foldedTrust === foldedRoot || foldedTrust.startsWith(`${foldedRoot}/`)) {
    warn(`dsh-proof: TRUST ROOT ${trustRoot} is INSIDE the workspace ${root} — keys, anchors and adapter `
      + `sessions land in the agent-writable area the trust boundary exists to exclude. Move the trust `
      + `root outside the workspace (DSH_PROOF_TRUST_DIR); treating this deployment as untrusted.`)
  }

  // The segment form used by the guard's comparisons: strip a './' prefix and
  // trailing slashes (index.ts:168's normalisation). An absolute evidenceDir is
  // left as-is here — the guard then simply never matches it, which is honest:
  // an absolute store is by construction not an agent-relative path.
  const configured = env.evidenceDir !== undefined && env.evidenceDir.length > 0 ? env.evidenceDir : '.proof'
  const stripped = toPosix(configured).replace(/^\.\/+/, '').replace(/\/+$/, '')
  // '.' / './' collapse to the empty segment (the store IS the workspace
  // root — M-48); the guard treats that case specially, and the derivation
  // says what it means instead of leaving a bare '.' around.
  const evidenceDir = stripped === '.' ? '' : stripped
  if (evidenceStore === 'workspace' && evidenceDir === '') {
    // M-48: '.' / '' collapse to an empty segment — the store IS the workspace
    // root and the segment comparison below could never match. config.ts's
    // schema rejects this spelling; this is the defence-in-depth that keeps
    // the two artifact FILES named by the derivation guarded regardless.
    warn(`dsh-proof: evidenceDir ${JSON.stringify(configured)} collapses to the workspace root; the guard `
      + `falls back to protecting the artifact files (evidence.jsonl / baseline.json) by name. `
      + `Set evidenceDir to a real subdirectory (schema default '.proof').`)
  }

  // logDir mirrors the engine's own storeDir rule (engine.ts constructor):
  // host mode parks evidence under the trust root keyed by workspace identity
  // (mcp-entry.ts:70-77), workspace mode resolves the relative segment against
  // the root. Deriving it any other way would split the log across two dirs.
  const logDir = evidenceStore === 'host'
    ? `${trustRoot}/workspaces/${workspaceKey}`
    : (isAbsoluteHostPath(configured)
        ? toPosix(configured).replace(/\/+$/, '')
        : (evidenceDir === '' ? root : `${root}/${evidenceDir}`))

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
    // H-19: one ledger per workspace — a session id is host-scoped, and two
    // workspaces sharing a flat directory let a same-id session cross-pollute
    // observations (and pre-burn each other's one-time notices).
    sessionDir: `${trustRoot}/adapter-sessions/${workspaceKey}`,
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
 * Fold one Win32 name deformation the H10 fold missed (H-25): Win10-and-older
 * CreateFile strips trailing dots and spaces from EVERY segment, so
 * `.proof./evidence.jsonl` opened `.proof/evidence.jsonl`. Folding before the
 * comparison is over-deny on hosts that do not deform (one blocked call),
 * under-deny costs the chain — the same trade the case fold already makes.
 */
function foldTrailingDotsAndSpaces(segments: string): string {
  return segments
    .split('/')
    .map(segment => segment.replace(/[. ]+$/, ''))
    .filter(segment => segment.length > 0)
    .join('/')
}

/** The artifact file names the store is, whatever segment spellings collapse to. */
const ARTIFACT_FILE_NAMES = ['evidence.jsonl', 'baseline.json']

/**
 * Does a candidate tool-call path land inside the evidence store this
 * workspace is configured to protect?
 *
 * Semantics mirror index.ts's guard (the H10 fold, both sides): project the
 * candidate onto the workspace's relative space (absolute host paths, either
 * slash flavour — drive OR UNC, `.`/`..` detours collapsed; a path escaping
 * the root keeps its leading `..` and therefore never matches). Both sides
 * are compared `toLowerCase()`d, and since H-25 each segment additionally
 * folds its trailing dots/spaces (the Win32 deformation the case fold
 * missed). On a Windows host, `.PROOF/evidence.jsonl` AND `.proof./…` name
 * the same file as `.proof/evidence.jsonl`; a case- or dot-sensitive
 * comparison let the agent walk the guard by changing one letter's case. The
 * price is that on a genuinely case-sensitive filesystem a sibling `.PROOF`
 * directory would also match — an over-deny that costs one blocked call,
 * versus an under-deny that costs the evidence log the whole plugin exists
 * to keep honest. index.ts folds the same way since the H10 batch — the two
 * guards are deliberately in lockstep; if one learns a new normalisation,
 * the other must learn it in the same batch.
 *
 * The `evidenceDir` segment is additionally backslash-folded here even though
 * `deriveProofPaths` already hands it over POSIX-spelled: a hand-assembled
 * `ProofPaths` (a host adapter, a future entry point) must not be able to
 * re-open the `'.\proof'`-vs-`./proof` hole index.ts closed — defence in
 * depth on the segment that names the store.
 *
 * A degenerate segment ('.', '' — the store IS the workspace root, M-48)
 * cannot be prefix-matched, so the guard narrows to what the store concretely
 * IS there: the artifact file names themselves.
 *
 * Host mode matches only ABSOLUTE candidates: the store lives outside the
 * workspace, so nothing the agent can name relatively is it — but an absolute
 * path into the trust-side store is exactly the H-26 write the guard exists
 * to refuse. Callers that can see both identity spellings (a migrated
 * deployment may still hold its store under the legacy workspace key) sweep
 * both with {@link absoluteInside} directly, as the gates do.
 */

/**
 * Lexical absolute-path containment, folded the way the guard's other
 * comparisons fold: separators unified, `..`/`.` segments collapsed, Win32
 * trailing-dot/space deformation folded, case folded (the same over-deny
 * price the workspace-side folds already pay — under-deny costs the chain).
 * A relative candidate never contains an absolute dir.
 */
export function absoluteInside(candidate: string, dir: string): boolean {
  if (candidate.length === 0 || dir.length === 0) return false
  const fold = (p: string): string =>
    foldTrailingDotsAndSpaces(collapseSegments(p.replace(/\\/g, '/'))).toLowerCase()
  const c = fold(candidate)
  const d = fold(dir)
  return d.length > 0 && (c === d || c.startsWith(`${d}/`))
}

export function touchesEvidencePath(candidate: string, paths: ProofPaths): boolean {
  if (paths.evidenceStore !== 'workspace') {
    return absoluteInside(candidate, paths.logDir)
  }
  let rel = toWorkspaceRelative(candidate, paths.root)
  if (rel === undefined && candidate.length > 0 && paths.root.startsWith('/')) {
    // H-25 fallback projection: a slash-rooted workspace (POSIX or UNC) whose
    // CANDIDATE spells the root with different case (`//SERVER/SHARE/ws/…`
    // vs root `//server/share/ws`) used to project to undefined here — the
    // root-level case hole that re-opened the segment-level H10 fix. Drive
    // roots already fold case inside toWorkspaceRelative; this is the same
    // fold for slash roots, applied only when the primary projection missed.
    // Over-deny on a genuinely case-sensitive filesystem is the same price
    // the case fold below already pays; under-deny costs the chain.
    const normalized = candidate.replace(/\\/g, '/')
    const foldedRoot = paths.root.toLowerCase()
    if (normalized.toLowerCase().startsWith(`${foldedRoot}/`)) {
      rel = normalized.slice(paths.root.length + 1)
    }
  }
  if (rel === undefined) return false
  const target = foldTrailingDotsAndSpaces(collapseSegments(rel)).toLowerCase()
  const evidence = foldTrailingDotsAndSpaces(
    collapseSegments(paths.evidenceDir.replace(/\\/g, '/')),
  ).toLowerCase()
  if (evidence === '') {
    return ARTIFACT_FILE_NAMES.includes(target)
  }
  return target === evidence || target.startsWith(`${evidence}/`)
}

// ---------------------------------------------------------------------------
// The shared environment contract (H-21)
// ---------------------------------------------------------------------------

/**
 * What the DSH_PROOF_* environment spells, parsed once. THE contract for
 * every face that configures dsh-proof through environment variables —
 * the Claude Code hooks, the OpenCode plugin, and app/mcp-entry.ts (which
 * must honour the same variable names or the guard and the server protect
 * different stores: H-21/B3-H1).
 *
 * Semantics (shared, so two faces cannot drift):
 * - `DSH_PROOF_ROOT` / `DSH_PROOF_TRUST_DIR` / `DSH_PROOF_EVIDENCE_DIR`:
 *   non-empty strings pass through, absent/empty mean "not set".
 * - `DSH_PROOF_EVIDENCE_STORE`: only the exact string `'workspace'` means
 *   workspace mode; everything else (including unset) is host mode.
 * - `DSH_PROOF_REQUIRE_BASELINE`: `'off' | 'warn' | 'ask'` only; an invalid
 *   value is `undefined` so the caller's default (config.ts's 'warn')
 *   applies — never a crash, never a silent stricter/weaker mode.
 * - `DSH_PROOF_DRIFT` / `DSH_PROOF_ENFORCE_TURN_END`: default-on flags; the
 *   off spellings are `'0'`, `'false'`, `'no'`, `'off'` (case-insensitive —
 *   pre-v0.23 only the exact `'0'` turned a flag off, so `false` meant ON).
 */
export interface AdapterEnvValues {
  readonly root?: string
  readonly trustRoot?: string
  readonly evidenceStore?: string
  readonly evidenceDir?: string
  readonly requireBaseline?: 'off' | 'warn' | 'ask'
  readonly driftDetection?: boolean
  readonly enforceTurnEnd?: boolean
}

/** The flag spellings that turn a default-on switch off. */
const FLAG_OFF = new Set(['0', 'false', 'no', 'off'])

/**
 * Parse the shared DSH_PROOF_* contract from one environment object. Pure:
 * no defaults beyond "unset", no I/O — callers layer their own precedence
 * (options beat environment beats code default) on top of exactly these
 * values. Name is contract-frozen: every face must resolve through THIS
 * function so a variable cannot mean two things in two processes.
 */
export function resolveAdapterEnv(env: NodeJS.ProcessEnv | Record<string, string | undefined>): AdapterEnvValues {
  const string = (name: string): string | undefined => {
    const value = env[name]
    return typeof value === 'string' && value.length > 0 ? value : undefined
  }
  const flag = (name: string): boolean | undefined => {
    const value = env[name]
    if (typeof value !== 'string' || value.length === 0) return undefined
    return !FLAG_OFF.has(value.trim().toLowerCase())
  }
  const requireBaseline = env.DSH_PROOF_REQUIRE_BASELINE
  return {
    root: string('DSH_PROOF_ROOT'),
    trustRoot: string('DSH_PROOF_TRUST_DIR'),
    evidenceStore: string('DSH_PROOF_EVIDENCE_STORE'),
    evidenceDir: string('DSH_PROOF_EVIDENCE_DIR'),
    requireBaseline: requireBaseline === 'off' || requireBaseline === 'warn' || requireBaseline === 'ask'
      ? requireBaseline
      : undefined,
    driftDetection: flag('DSH_PROOF_DRIFT'),
    enforceTurnEnd: flag('DSH_PROOF_ENFORCE_TURN_END'),
  }
}
