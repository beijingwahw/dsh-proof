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
 * through {@link foldHostPath} — THE one fold (X-H-12): device-namespace
 * prefixes (`\\?\`), separators, drive-relative forms, per-segment Win32
 * deformations, case and `..`/`.` detours all fold in that single function,
 * on both sides of every comparison. The guards used to carry private folds
 * (case in one, trailing dots in another, nothing anywhere for device
 * prefixes or drive-relative forms), and every seam between them was a
 * working bypass (W11/W12: real NTFS write into the store through `\\?\`
 * while all four lexical layers compared as false). src/index.ts's guard
 * mirrors the same rule set — if either face learns a new normalisation, the
 * other must learn it in the same batch (the lockstep rule, see the guard's
 * own comment).
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
 * Windows drive letter, drive-letter path, backslash-UNC, or any leading
 * slash — ENGINE.TS's private absolute-path test VERBATIM (`[A-Za-z]:[\/]`,
 * `\\\\`, `\/`), plus the forward-slash UNC spelling that test folds through
 * its `\/` arm anyway (H-25: a backslashed UNC used to read as "relative",
 * silently parking the store INSIDE the workspace the operator asked to keep
 * it out of). The store-dir derivation must agree with the engine's or
 * adapters would read a different log than the one the engine appends to.
 *
 * V5-M6 (v0.24): exported, and src/index.ts's private third mirror RETIRED
 * onto it — that mirror lacked the backslash-UNC arm (`\\server\share\store`
 * read as a relative segment and was glued onto the workspace root), so a
 * UNC evidenceDir silently produced a garbage evidenceLogPath. One rule, one
 * spelling of the rule, consumed by both faces; if engine.ts's rule ever
 * moves, this mirror must move with it (M-65's glue, now literal).
 */
export function isAbsoluteHostPath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|[\\/]{2}|\/)/.test(p)
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
 * Fail loudly on a RELATIVE trust root (X-H-15).
 *
 * Exported for the standalone entry faces (app/mcp-entry.ts and friends) that
 * parse `DSH_PROOF_TRUST_DIR` / `DSH_HOME` before they derive anything: call
 * this the moment the value is known, so a relative spelling kills the
 * process with a message naming the variable, instead of silently resolving
 * against the CWD (an agent-writable workspace) and writing the signing keys
 * into the sandbox. `deriveProofPaths` runs the same assertion itself — a
 * face that forgets to call this still cannot slip through. Drive-RELATIVE
 * forms (`C:rel`) count as relative: they resolve against the per-drive
 * current directory, which is the workspace for the hook process.
 */
export function assertAbsoluteTrustRoot(trustRoot: string): void {
  const posix = toPosix(trustRoot)
  if (!isAbsoluteHostPath(stripDevicePrefix(posix)) && !posix.startsWith('/')) {
    throw new Error(
      `dsh-proof: trust root ${JSON.stringify(trustRoot)} is a RELATIVE path — it would resolve against the `
      + `process working directory (an agent-writable workspace), silently moving keys, anchors and the host-mode `
      + `evidence store inside the sandbox the trust boundary exists to exclude. Set DSH_PROOF_TRUST_DIR (or `
      + `DSH_HOME) to an absolute path outside every workspace.`,
    )
  }
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
 * X-H-15: a relative `trustRoot` (from the argument or from a relative
 * DSH_HOME) THROWS here — see {@link assertAbsoluteTrustRoot}. The
 * derivation itself stays free of filesystem reads: the only disk contact is
 * the optional on-disk identity probe below, which `{ pure: true }` skips.
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
  // X-H-15: a RELATIVE trust root (DSH_PROOF_TRUST_DIR or DSH_HOME) resolves
  // against the process working directory — an agent-writable workspace —
  // which silently moves keys, anchors and the host-mode evidence store
  // INSIDE the sandbox the trust boundary exists to exclude (the M-47
  // containment check was blind to it: 'rel/trust' does not start with the
  // root, so it never warned). Fail loudly at derivation time instead.
  assertAbsoluteTrustRoot(trustRoot)
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
        // W11-M5: the adapter session ledger is the THIRD trust-side state.
        // Without this probe a legacy deployment whose anchors/workspaces
        // migrate to the normalised key would flip `sessionDir` with no
        // migration and no announcement — shellUsed, firedNotices and every
        // fingerprint silently orphaned, and the drift narrative back to
        // authoritatively accusing the agent of external edits a shell it had
        // already owned up to.
        || exists(`${trustRoot}/adapter-sessions/${key}`)
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
  // comparison goes through the one fold since X-H-12: device-prefixed and
  // backslash spellings of the same directory (`\\?\C:\ws\.trust` vs `C:/ws`)
  // must not slip the check by spelling themselves differently on each side.
  const foldedRoot = foldHostPath(root)
  const foldedTrust = foldHostPath(trustRoot)
  if (foldedTrust === foldedRoot || foldedTrust.startsWith(`${foldedRoot}/`)) {
    warn(`dsh-proof: TRUST ROOT ${trustRoot} is INSIDE the workspace ${root} — keys, anchors and adapter `
      + `sessions land in the agent-writable area the trust boundary exists to exclude. Move the trust `
      + `root outside the workspace (DSH_PROOF_TRUST_DIR); treating this deployment as untrusted.`)
  }

  // The segment form used by the guard's comparisons: strip a './' prefix and
  // trailing slashes (index.ts:168's normalisation). A DRIVE-absolute
  // evidenceDir is rejected by config.ts's schema since V5-M3 (the same
  // `(?![A-Za-z]:)` arm syntheticDir has) — the runtime here leaves an
  // absolute spelling as-is and the workspace-mode guard then honestly never
  // matches it: an absolute store is not an agent-relative path. (The schema
  // still admits a backslash-UNC spelling — `(?!\/)` only rejects the
  // forward slash — and the same honesty applies to it; the loud first line
  // is the schema, this is the defence-in-depth underneath.)
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
 * Strip a Win32 device-namespace prefix (`\\?\`, `\\.\`, and either slash
 * flavour; `\\?\UNC\server\share` folds to the UNC form) from a
 * backslash-normalised path. `\\?\C:\ws\.proof\x` is passed through to
 * CreateFile VERBATIM by Node's fs — the prefix is not decoration, it is a
 * second spelling of the same file the lexical guards used to compare against
 * as raw text (`//?/c:/ws/...` matched nothing) while the write itself landed
 * (X-H-12, W11 devpath PoC: real NTFS write into the store through this exact
 * spelling). Stripped here, before any comparison, the device form and the
 * plain form fold to one string.
 */
function stripDevicePrefix(posixPath: string): string {
  const unc = posixPath.replace(/^\/\/\?\/unc\//i, '//')
  return unc.replace(/^\/\/[?.]\//i, '')
}

/**
 * The CWD of one drive, folded — or undefined when the process CWD is not on
 * that drive (or cannot be read). Win32 keeps a per-drive current directory:
 * `C:foo` means "foo on drive C, relative to C's current directory", which
 * for the CWD's own drive IS `process.cwd()`.
 */
function cwdOfDrive(driveLetter: string): string | undefined {
  let cwd: string
  try {
    cwd = process.cwd()
  } catch {
    return undefined
  }
  const posix = toPosix(cwd).replace(/\/+$/, '')
  const match = /^([A-Za-z]):/.exec(posix)
  const drive = match?.[1]
  return drive !== undefined && drive.toLowerCase() === driveLetter.toLowerCase() ? posix : undefined
}

/**
 * Segment-level folds over a backslash-normalised, prefix-stripped path:
 * Win32 trailing-dot/space deformation per segment (H-25: `.proof.` IS
 * `.proof`), `.`/`..` lexical collapse, empty-segment collapse. The leading
 * root shape survives ('/', '//', 'c:/'); a leading `..` on a RELATIVE path is
 * kept (it marks a path escaping the base — index.ts's rule: the caller's
 * comparison must be able to honestly fail to match), while `..` above an
 * absolute root is dropped (`C:/..` cannot go higher than `C:/`).
 */
function foldSegments(path: string): string {
  if (path === '') return ''
  const segments = path.split('/')
  const first = segments[0] ?? ''
  const second = segments[1] ?? ''
  let index = 0
  let prefix: string
  if (first === '') {
    // One leading empty segment: POSIX root ('/abs'); two: UNC ('//srv/share').
    prefix = second === '' ? '//' : '/'
    index = second === '' ? 2 : 1
  } else if (/^[A-Za-z]:$/.test(first)) {
    prefix = `${first}/`
    index = 1
  } else {
    prefix = ''
  }
  const out: string[] = []
  for (; index < segments.length; index++) {
    const raw = segments[index] ?? ''
    // Traversal tokens are path-parser syntax, not names — they must be
    // consumed BEFORE the Win32 trailing-dot fold (which would otherwise
    // strip '..' down to '' and silently turn a detour into a no-op).
    if (raw === '.' || raw === '..') {
      const top = out.length > 0 ? out[out.length - 1] : undefined
      if (raw === '..' && top !== undefined && top !== '..') out.pop()
      else if (raw === '..' && prefix === '') out.push('..')
      // '.' is a no-op; '..' above an absolute root has no 'up' and drops.
      continue
    }
    const segment = raw.replace(/[. ]+$/, '')
    if (segment === '' || segment === '.') continue
    out.push(segment)
  }
  return prefix + out.join('/')
}

/**
 * THE one fold for host-path comparison (X-H-12): every guard in this module
 * and in gates.ts compares `foldHostPath` outputs, never raw spellings — the
 * pre-v0.23 guards each carried a private fold (case here, trailing dots
 * there, no prefix strip anywhere), and W11/W12 kept finding the seam between
 * them. One spelling in, one comparison string out:
 *
 * - `\\?\` / `\\.\` device prefixes stripped (either slash flavour, `UNC`
 *   sub-prefix folded to the UNC form) — the verbatim passthrough that made
 *   device-spelled writes invisible to four layers of lexical guards.
 * - backslashes folded to '/'.
 * - drive-relative `C:foo` projected onto the C-drive's current directory —
 *   for the hook process that directory IS the workspace root (the host
 *   contract), so `C:.proof/x` becomes the absolute store path it really
 *   names. A drive the process CWD is not on gets the drive root
 *   (`q:/foo`) — fresh-process semantics for the per-drive CWD; an inherited
 *   `=X:` environment variable pointing elsewhere is the documented residual
 *   approximation (over-deny direction, vanishing corner).
 * - drive letter and every segment lowercased: on Windows `.PROOF` is
 *   `.proof`; on a genuinely case-sensitive filesystem a case-colliding
 *   sibling also matches — the same over-deny price the H10 fold already
 *   paid, now paid uniformly in ONE place. (IDENTITY hashing is NOT this
 *   function: {@link normalizeWorkspaceRoot} keeps POSIX case-sensitive on
 *   purpose; this fold is for guard comparison only.)
 * - per-segment trailing dots/spaces folded (Win32 deformation, H-25).
 * - `.`/`..` segments lexically collapsed (leading `..` on a relative path
 *   kept as the escape marker).
 * - NUL truncation modelled: everything after the first NUL never reaches a
 *   native host's filename API, so the fold keeps the prefix the OS would
 *   keep (`.proof/evidence.jsonl\0junk` folds to `.proof/evidence.jsonl`)
 *   instead of rejecting the string outright (rejecting was the under-deny:
 *   a truncated write into the store compared as "not a path").
 *
 * No length cap, deliberately: the pre-fold guards blanked out on candidates
 * over 4096 bytes exactly when the `\\?\` prefix made such paths writable —
 * the cap and the attack were the same feature.
 *
 * RESIDUAL, comment-pinned (V5-L1 / W11-L-F): Win32 8.3 short names
 * (`EVIDEN~1.JSO`) are NOT folded. Expanding one is a filesystem QUERY, not
 * a lexical rule — the fold is pure by contract (every consumer compares
 * strings, several in synchronous gates), and Node exposes no
 * GetShortPathName. Pinned by test on a Windows volume where short-name
 * generation is off (the modern default): `dir /x` shows no alias for
 * `evidence.jsonl`, so the attack requires a volume with 8.3 creation
 * enabled AND the short spelling of an artifact — at which point the textual
 * sweep's bare-name needles are equally blind and the structured guard is
 * the only honest layer left. If a future fold learns short names, it must
 * do so for BOTH sides of every comparison in the same batch.
 */
export function foldHostPath(p: string): string {
  if (p.length === 0) return ''
  const truncated = p.includes('\0') ? p.slice(0, p.indexOf('\0')) : p
  let s = stripDevicePrefix(toPosix(truncated))
  const drive = /^([A-Za-z]):(.*)$/.exec(s)
  const driveLetter = drive?.[1]
  const rest0 = drive?.[2]
  if (driveLetter !== undefined && rest0 !== undefined && !rest0.startsWith('/')) {
    const rest = rest0.replace(/^\.\//, '')
    const cwd = cwdOfDrive(driveLetter)
    s = cwd !== undefined
      ? (rest === '' ? cwd : `${cwd}/${rest}`)
      : `${driveLetter.toLowerCase()}:/${rest}`
  }
  return foldSegments(s.toLowerCase())
}

/** The artifact file names the store is, whatever segment spellings collapse to. */
const ARTIFACT_FILE_NAMES = ['evidence.jsonl', 'baseline.json']

/**
 * Does a candidate tool-call path land inside the evidence store this
 * workspace is configured to protect?
 *
 * Semantics mirror index.ts's guard, through {@link foldHostPath} — the ONE
 * fold both faces are contractually in lockstep on: project the candidate
 * onto the workspace's relative space (absolute host paths, either slash
 * flavour, drive OR UNC, device prefixes stripped, drive-relative forms
 * projected against the hook CWD, `.`/`..` detours collapsed; a path escaping
 * the root keeps its leading `..` and therefore never matches), then compare
 * case-folded segments. On a Windows host, `.PROOF/evidence.jsonl`,
 * `.proof./…` AND `\\?\C:\ws\.proof\…` name the same file as
 * `.proof/evidence.jsonl`; a comparison that missed any one of those
 * spellings let the agent walk the guard by respelling one letter, one dot or
 * one prefix. The price is that on a genuinely case-sensitive filesystem a
 * sibling `.PROOF` directory also matches — an over-deny that costs one
 * blocked call, versus an under-deny that costs the evidence log the whole
 * plugin exists to keep honest. If either guard face learns a new
 * normalisation, the other must learn it in the same batch.
 *
 * The `evidenceDir` segment folds here too even though `deriveProofPaths`
 * usually hands it over POSIX-spelled: a hand-assembled `ProofPaths` (a host
 * adapter, a future entry point) must not be able to re-open the
 * `'.\proof'`-vs-`./proof` hole index.ts closed — defence in depth on the
 * segment that names the store.
 *
 * A degenerate segment ('.', '', or anything that collapses to it like
 * 'a/..' — M-48/L-H) cannot be prefix-matched, so the guard narrows to what
 * the store concretely IS there: the artifact file names themselves.
 *
 * Host mode matches only ABSOLUTE candidates: the store lives outside the
 * workspace, so nothing the agent can name relatively is it — but an absolute
 * path into the trust-side store is exactly the H-26 write the guard exists
 * to refuse. Callers that can see both identity spellings (a migrated
 * deployment may still hold its store under the legacy workspace key) sweep
 * both with {@link absoluteInside} directly, as the gates do.
 */

/**
 * Lexical absolute-path containment, folded by {@link foldHostPath} on BOTH
 * sides (the one fold): separators unified, device prefixes stripped,
 * drive-relative forms projected, `..`/`.` collapsed, Win32
 * trailing-dot/space deformation folded, case folded (the over-deny price —
 * one blocked call on a case-sensitive host — versus an under-deny that costs
 * the chain). A relative candidate never contains an absolute dir; a
 * drive-relative candidate (`C:foo`, X-H-12) becomes the absolute path the OS
 * will really open, so it compares like any other.
 */
export function absoluteInside(candidate: string, dir: string): boolean {
  if (candidate.length === 0 || dir.length === 0) return false
  const c = foldHostPath(candidate)
  const d = foldHostPath(dir)
  return d.length > 0 && (c === d || c.startsWith(`${d}/`))
}

/**
 * Project a candidate onto the workspace's relative space using the one fold
 * (replaces the observe.ts projection + the H-25 case fallback this guard
 * used to chain): both sides fold first, so drive roots, slash roots and UNC
 * roots all compare case-insensitively without a second code path. Relative
 * candidates are workspace-relative by definition (the hook process resolves
 * them against its CWD, which the host contract fixes at the workspace root).
 * A path that escapes the root keeps its leading `..` and therefore never
 * matches (index.ts's rule).
 */
function workspaceRelativeOf(candidate: string, root: string): string | undefined {
  const c = foldHostPath(candidate)
  if (c === '') return undefined
  if (!(/^([a-z]:\/|\/\/|\/)/.test(c))) return c
  const r = foldHostPath(root)
  if (r === '') return undefined
  if (c === r) return ''
  return c.startsWith(`${r}/`) ? c.slice(r.length + 1) : undefined
}

export function touchesEvidencePath(candidate: string, paths: ProofPaths): boolean {
  if (paths.evidenceStore !== 'workspace') {
    return absoluteInside(candidate, paths.logDir)
  }
  const rel = workspaceRelativeOf(candidate, paths.root)
  if (rel === undefined) return false
  const target = rel
  const evidence = foldHostPath(paths.evidenceDir)
  if (evidence === '') {
    return ARTIFACT_FILE_NAMES.includes(target)
  }
  return target === evidence || target.startsWith(`${evidence}/`)
}

// ---------------------------------------------------------------------------
// The shared guard-target set (Y-H-11 / V5-M1)
// ---------------------------------------------------------------------------

/**
 * Y-H-11 (v0.24): the Ed25519 signing-key pair's file names (node-ports'
 * spellings — the signer loads them from `<trustRoot>/keys`). A string value
 * naming either is worth refusing wherever it points — the key pair IS the
 * trust fabric (whoever holds the private half can forge every checkpoint
 * signature), and no legitimate workspace file carries these names. Exported
 * here so BOTH guard faces (gates.ts and src/index.ts) refuse the same names:
 * pre-v0.24 only the DSH plugin face listed them, and
 * `cp <trust>/keys/proof-signing-key.pem x` sailed through the adapter hooks
 * measured. Matched as segment-boundaried substrings after separator/case
 * folding by `shellCommandMentionsPath`; if node-ports ever renames a key
 * file, this list must move with it (grep-anchored there).
 */
export const SIGNING_KEY_FILE_NAMES: readonly string[] = [
  'proof-signing-key.pem', 'proof-signing-key.pub.pem',
]

/** What {@link guardedTargets} needs: where the store is, and where trust lives. */
export interface GuardedTargetOptions {
  readonly evidenceStore: 'host' | 'workspace'
  readonly evidenceDir: string
  /**
   * The host trust root, when the caller knows it — adds the trust-side
   * artifacts (host-mode store, anchors, session ledgers, signing keys) to
   * the target set. Optional for callers that only reproduce the historical
   * workspace-store contract.
   */
  readonly trustRoot?: string
}

/**
 * Every spelling of the store and trust artifacts a shell command must not
 * name — THE one target-set constructor both guard faces consume (V5-M1,
 * v0.24). Pre-v0.24 gates.ts and index.ts each hand-rolled this list and it
 * forked three ways the audit could drive a command through: the adapter
 * face missed the bare `<trust>/workspaces/<key>` DIRECTORY (`rm -rf` of the
 * whole store passed), BOTH faces missed the signing-key file names (Y-H-11)
 * and every `~`/env spelling of the default trust root (`rm -rf ~/.dsh/proof`
 * passed everywhere — no absolute needle matches a variable). One function,
 * consumed by both faces, so the two nets cannot drift apart again.
 *
 * Targets are FOLDED spellings (`foldHostPath`): `shellCommandMentionsPath`
 * folds the haystack the same way, so one spelling per target is enough
 * (`.proof/evidence.jsonl` also catches `.PROOF\EVIDENCE.JSONL`). The set:
 * - workspace mode: the store segment, its two artifact files, and the
 *   root-anchored spellings an absolute command would use (a degenerate
 *   segment — M-48 — narrows to the artifact file names themselves);
 * - trust side (either store mode, when `trustRoot` is known): the host-mode
 *   store DIRECTORY and files under BOTH identity keys (a migrated
 *   deployment still holds state under the legacy one), the anchor dirs, the
 *   adapter session ledgers, the `keys` directory, and — always — the two
 *   bare signing-key file names (Y-H-11: the names themselves are refused
 *   wherever they point);
 * - when the trust root IS the default `$DSH_HOME/proof` (DSH_HOME itself
 *   defaulting to `~/.dsh`), the `~`/`$DSH_HOME`/`$HOME` spellings of it:
 *   the textual sweep does no variable expansion, so the literal forms are
 *   listed (zero false positives in the default deployment — no legitimate
 *   command writes there; a custom trust root keeps its absolute needle).
 */
export function guardedTargets(root: string, options: GuardedTargetOptions): string[] {
  const targets: string[] = []
  if (options.evidenceStore === 'workspace') {
    const dir = foldHostPath(options.evidenceDir)
    if (dir !== '') {
      // The bare store directory, the artifacts inside it, and the
      // root-anchored spellings an absolute command would use.
      targets.push(dir, `${dir}/evidence.jsonl`, `${dir}/baseline.json`)
    } else {
      // Degenerate segment (M-48): the store IS the workspace root; guard the
      // artifact file names themselves.
      targets.push('evidence.jsonl', 'baseline.json')
    }
    const anchored = foldHostPath(`${root.replace(/\/+$/, '')}/${options.evidenceDir}`)
    targets.push(anchored, `${anchored}/evidence.jsonl`, `${anchored}/baseline.json`)
  }
  if (options.trustRoot !== undefined && options.trustRoot.length > 0) {
    // Trust-side artifacts are never legitimately agent-writable in EITHER
    // store mode: the anchor mirrors every checkpoint, the host-mode store
    // lives here, the adapter session ledgers record the shellUsed/firedNotices
    // facts the drift narrative speaks with (W11-M3), and the signing keys
    // under `keys/` are the trust fabric itself (Y-H-11). Both identity keys
    // are listed: a migrated deployment still holds state under the legacy one.
    const trust = foldHostPath(options.trustRoot)
    if (trust !== '') {
      const pair = workspaceKeyPair(root)
      for (const key of pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy]) {
        targets.push(
          // V5-M1: the BARE store directory joins the two files — `rm -rf`
          // of the whole store names no file inside it.
          `${trust}/workspaces/${key}`,
          `${trust}/workspaces/${key}/evidence.jsonl`,
          `${trust}/workspaces/${key}/baseline.json`,
          `${trust}/anchors/${key}`,
          `${trust}/adapter-sessions/${key}`,
        )
      }
      // The engine's default signer directory (engine.ts loads Ed25519 from
      // `<trustDir>/keys`; the standalone MCP entry assembles the same path).
      targets.push(`${trust}/keys`)
      // V5-M1: the variable spellings of the DEFAULT trust root. The textual
      // sweep expands nothing, so `rm -rf ~/.dsh/proof` — which erases keys,
      // anchors, stores and session ledgers in one command — needs its
      // literals listed. Armed only when the configured trust root IS the
      // default; a custom root keeps its absolute needle (and its operator
      // knows its own spelling).
      if (trust === foldHostPath(`${dshHome()}/proof`)) {
        targets.push('~/.dsh/proof', '$dsh_home/proof', '${dsh_home}/proof', '$home/.dsh/proof')
      }
    }
  }
  // Y-H-11: the bare signing-key file names guard every mode and every trust
  // spelling — no legitimate workspace file carries these names, so a mention
  // of either is worth refusing wherever it points.
  targets.push(...SIGNING_KEY_FILE_NAMES)
  return [...new Set(targets)].filter(t => t.length > 0)
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
 * - `DSH_PROOF_REQUIRE_BASELINE`: `'off' | 'warn' | 'ask'` only, matched
 *   case-insensitively after a trim (W11-L10 — 'ASK' used to silently fall
 *   to the caller's 'warn' default); an invalid value is `undefined` so the
 *   caller's default (config.ts's 'warn') applies — never a crash, never a
 *   silent stricter/weaker mode.
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
  // W11-L10: the ladder value folds case + surrounding whitespace before the
  // match — 'ASK' / 'ask\n' used to fall to undefined, and the hooks' and
  // plugin's `?? 'warn'` default then SILENTLY DOWNGRADED ask→warn, violating
  // this module's own "never a silent stricter/weaker mode" rule two lines up.
  // Invalid values are still undefined (caller default applies); flag
  // spellings above already fold the same way, now the ladder does too.
  const requireBaselineRaw = env.DSH_PROOF_REQUIRE_BASELINE
  const requireBaseline = typeof requireBaselineRaw === 'string'
    ? requireBaselineRaw.trim().toLowerCase()
    : undefined
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
