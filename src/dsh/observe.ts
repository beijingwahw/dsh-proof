/**
 * Workspace truth tracking: which files the agent actually moved, and which
 * files moved behind its back.
 *
 * The failure this exists for: the user edits a file in their IDE (or a build
 * step, a formatter, a background process does), and the agent keeps reasoning
 * about the version it read ten minutes ago. "改了一个地方，另一个地方坏了".
 *
 * Method: record a content fingerprint whenever a tool reports a path, then
 * compare against the filesystem at turn boundaries. Files whose fingerprint
 * moved without a corresponding tool call are drift, and drift is injected as
 * corrective context rather than silently ignored.
 *
 * @module dsh-proof/dsh/observe
 */

import type { ToolExecution, ToolExecutionResult } from '../vendor/dsh-tools.ts'
import type { FsPort } from '../core/ports.ts'
import { sha256 } from '../core/hash.ts'

/**
 * Tools whose arguments name files this plugin should fingerprint.
 *
 * `source` is deliberately absent: across real tool surfaces it far more often
 * carries *content* (the old text of a search/replace, a snippet to analyse)
 * than a path, and a snippet containing `/` or `.` sails through
 * `looksLikePath` — recording an external edit as the agent's work. The
 * tradeoff, accepted here: a tool that genuinely names a path under `source`
 * contributes one file less to fingerprints, which drift detection still
 * catches at the turn boundary; a content key misclassified as a path wrongly
 * indicts the agent, which nothing downstream corrects. Take the miss, not
 * the false charge. Callers that must not miss (the evidence guard) pass
 * `{contentKeys: true}` to re-admit the key.
 */
const PATH_KEYS = ['path', 'file', 'file_path', 'filePath', 'target', 'filename', 'dest', 'destination', 'notebook_path', 'dir']
const PATH_ARRAY_KEYS = ['paths', 'files', 'targets', 'globs', 'patterns']

/**
 * X-H-14 (v0.23): key matching is CASE-INSENSITIVE. Hosts spell the same key
 * as `FileName`, `FILE_PATH` or `Path` — the case-sensitive `includes` used to
 * extract nothing from `{FileName: '.proof/evidence.jsonl'}`, so even the
 * guard's over-detecting `contentKeys` view could not see a store write the
 * tool named under one capital letter. Values keep their case (only the ROOT
 * comparison folds); keys fold here, once, into the sets `pathsIn` consults.
 */
const PATH_KEY_SET = new Set(PATH_KEYS.map(key => key.toLowerCase()))
const PATH_ARRAY_KEY_SET = new Set(PATH_ARRAY_KEYS.map(key => key.toLowerCase()))

/**
 * Tool-name classification — the single source both adapter layers consult
 * (the pre-execute gates in index.ts / gates.ts and the read/write split
 * below). It lives here so the watcher cannot drift from the gates again.
 *
 * H-01 (v0.23): the classification is an ANCHORED NAME LIST, not a word
 * pattern. The pre-v0.23 regex required a mutation verb to be delimited by
 * `^|[_-]`, so the camelCase names real hosts ship (`MultiEdit`,
 * `NotebookEdit` — both documented Claude Code mutators) matched nothing,
 * and because the gates are allowlist-shaped ("not a mutation → pass
 * through") those names walked every pre-execute gate while carrying a
 * `file_path` straight into the evidence store. Names are now enumerated;
 * anything the lists do not recognize is classified as a MUTATION — the
 * conservative charge — so an unrecognized write tool can only cost the
 * agent an over-recorded touch, never an unguarded write. Only a name on
 * the read-only list may classify as a read.
 */

/**
 * Explicitly recognized mutation tool names (matched case-insensitively,
 * whole-name anchored). The list is documentation plus override: unknown
 * names default to mutation anyway, but an explicit entry wins even if a
 * future read-only addition ever collided with it.
 */
export const MUTATION_TOOL_NAMES: readonly string[] = [
  // Claude Code's documented mutators (adapters/claude-code/hooks.ts) — the
  // camelCase names the old delimited-verb pattern could not see.
  'edit', 'write', 'multiedit', 'notebookedit',
  // Common host spellings seen across tool surfaces.
  'writefile', 'applypatch', 'createfile', 'deletefile', 'removefile',
  'movefile', 'renamefile', 'strreplace', 'replacetext',
  // Legacy bare verbs the pre-v0.23 pattern matched as whole names.
  'create', 'patch', 'delete', 'remove', 'move', 'rename', 'mkdir', 'touch',
  'apply', 'install', 'update', 'upsert',
]

/**
 * Shell-class tool names (matched case-insensitively, whole-name anchored):
 * calls that execute an arbitrary host command — which can mutate anything,
 * through a `command` string this observer deliberately does not parse.
 */
export const SHELL_TOOL_NAMES: readonly string[] = [
  'bash', 'shell', 'exec', 'run_code', 'run_command', 'terminal', 'process',
  // W13-M8 (v0.23): 'task' is gone. Hosts spell their todo/planner tools
  // 'task' far more often than their shell, and the name used to flip the
  // session's shellUsed fact — permanently demoting every later "changed
  // outside your tool calls" to "indistinguishable" on the strength of a
  // checklist call. A host whose 'task' really is a runner still lands in the
  // mutation class (unknown names default there); only the shell FACT is no
  // longer minted from the name alone.
  'npm', 'pnpm', 'yarn', 'pip', 'cargo', 'go', 'make',
  // Host spellings the pre-v0.23 enum missed (Gemini et al.) — their calls
  // never flipped the session's shellUsed fact, silently keeping the H9b
  // "changed outside your tool calls" accusation alive.
  'execute_command', 'run_shell_command', 'shell_exec',
]

/**
 * Read-only tool names (matched case-insensitively). The ONLY names that
 * classify as reads — camelCase host spellings (`Read`, `Grep`, `View`,
 * `Glob`, `LS`, `WebFetch`) fold onto their lowercase forms.
 */
export const READ_ONLY_TOOL_NAMES: readonly string[] = [
  'read', 'read_file', 'view', 'cat', 'grep', 'glob', 'ls', 'list',
  'search', 'search_files', 'find', 'show', 'head', 'tail', 'webfetch',
]

const MUTATION_SET = new Set(MUTATION_TOOL_NAMES)
const SHELL_SET = new Set(SHELL_TOOL_NAMES)
const READ_ONLY_SET = new Set(READ_ONLY_TOOL_NAMES)

const foldName = (toolName: string): string => toolName.toLowerCase()

/** Tools whose calls constitute a workspace mutation. */
export const MUTATION_TOOL_RE = anchoredPatternOf(MUTATION_TOOL_NAMES)
/** Tools that execute arbitrary host commands (which can mutate anything). */
export const SHELL_TOOL_RE = anchoredPatternOf(SHELL_TOOL_NAMES)

/** An anchored, case-insensitive full-name pattern over an explicit list. */
function anchoredPatternOf(names: readonly string[]): RegExp {
  return new RegExp(`^(?:${names.map(escapeRegExp).join('|')})$`, 'i')
}

/** Quote regex metacharacters so a listed name anchors a literal. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** True when a tool call of this name can move workspace state. */
export function isMutationToolName(toolName: string): boolean {
  const folded = foldName(toolName)
  if (MUTATION_SET.has(folded) || SHELL_SET.has(folded)) return true
  if (READ_ONLY_SET.has(folded)) return false
  // Unknown names default to *mutation* (H-01): the gates only ever hold a
  // call back when this says yes, so an unrecognized write tool must land on
  // the guarded side, never the pass-through side.
  return true
}

/** True when a tool call of this name runs an arbitrary host command. */
export function isShellToolName(toolName: string): boolean {
  return SHELL_SET.has(foldName(toolName))
}

/**
 * H-02: does a command string mention any of the guarded targets?
 *
 * The command string is the one argument shape `pathsIn` structurally cannot
 * see (a `bash {command: 'echo x > .proof/evidence.jsonl'}` names no path
 * key), so the evidence-store guard needs a conservative textual sweep: path
 * separators are normalized (`\` → `/`, both spell a redirect target on
 * Windows), everything is case-folded the way the guard's path comparison
 * already folds (H10), and any target appearing as a *segment-delimited*
 * substring — the bare store directory, a file inside it, or a trusted file
 * name such as `evidence.jsonl` / `baseline.json` / `anchor.json` / the
 * signing-key files — is a hit.
 *
 * X-H-13 (v0.23): the match is segment-boundaried, not a raw substring. The
 * END of a hit requires the next character (if any) to be outside
 * `[A-Za-z0-9_-]` — a dot stays a clean end, so the Win32 trailing-dot
 * deformation (`.proof.`) still hits while `.proof-synthetic` (a DIFFERENT
 * directory — it is where proof_conjure scaffolds the sandbox the model is
 * INSTRUCTED to write into) and `anchor.jsonl` (not `anchor.json`) do not.
 * The START additionally treats `.` and `-` as name characters, so a target
 * segment never matches inside a LONGER name that merely extends it: with
 * the store at `proof`, the string `.proof/evidence.jsonl` (a genuinely
 * different, dotted directory) must NOT hit. Quoting (`"`.proof`"`), `/`-
 * delimiters, string ends and the NUL truncation model all still hit. With
 * the sweep now running over every string value of every call (see
 * {@link sweepToolInputStrings}), that precision is what keeps the plugin's
 * own conjure protocol callable and a differently-named store directory
 * distinct. False positives still cost one denied call with a reason saying
 * why; a false negative costs the chain.
 */
const SEGMENT_INNER_CHAR = /[A-Za-z0-9_-]/
const SEGMENT_HEAD_CHAR = /[A-Za-z0-9_.-]/

export function shellCommandMentionsPath(command: string, targets: readonly string[]): boolean {
  if (typeof command !== 'string' || command.length === 0) return false
  const haystack = command.replace(/\\/g, '/').toLowerCase()
  for (const target of targets) {
    if (typeof target !== 'string' || target.length === 0) continue
    const needle = target.replace(/\\/g, '/').toLowerCase()
    if (needle.length === 0) continue
    let from = 0
    for (;;) {
      const at = haystack.indexOf(needle, from)
      if (at < 0) break
      const before = at > 0 ? haystack.charAt(at - 1) : ''
      const after = at + needle.length < haystack.length ? haystack.charAt(at + needle.length) : ''
      const startsClean = before === '' || !SEGMENT_HEAD_CHAR.test(before)
      const endsClean = after === '' || !SEGMENT_INNER_CHAR.test(after)
      if (startsClean && endsClean) return true
      from = at + 1
    }
  }
  return false
}

/**
 * X-H-13 (v0.23): every string value in a tool call's arguments, collected
 * for the guard's value sweep — the death of the key-name whitelist.
 *
 * The pre-v0.23 command sweep read exactly three keys (`command`/`cmd`/
 * `script`), so `{commandLine: …}`, `{code: …}` and mixed argv vectors
 * carried store-writing commands straight through every gate; before that,
 * the shell TOOL-NAME list was the hole. Names and keys are both attacker
 * spellings — this sweep enumerates NEITHER: it walks the argument object's
 * values (arrays contribute their elements individually; nested objects
 * recurse) and hands back every string it finds, and the guard refuses any
 * call whose ANY string value mentions a protected path.
 *
 * Bounds, so a hostile payload cannot turn the sweep into a cost attack:
 * depth ≤ 3, at most 64 strings, each swept up to its first 8192 characters
 * (a longer string contributes its head — skipping it wholesale would make
 * `command: ' '.repeat(9000) + 'rm .proof'` a length-shaped bypass, while
 * the tail beyond the cap is the same blind spot every bounded sweep has).
 * Cycles are guarded by a visited set. The deliberate false-positive surface:
 * a read-only tool naming the store (`grep {pattern: 'evidence.jsonl'}`, a
 * Read of the log) is denied too — 宁误拦, one denied call with a reason
 * beats one rewritten chain, and the plugin's own proof_* tools read the log
 * through the engine's port, not through host tool calls.
 */
const SWEEP_MAX_DEPTH = 3
const SWEEP_MAX_STRINGS = 64
const SWEEP_MAX_STRING = 8192

export function sweepToolInputStrings(toolInput: unknown): string[] {
  const out: string[] = []
  const visited = new Set<unknown>()
  const full = (): boolean => out.length >= SWEEP_MAX_STRINGS
  const visit = (value: unknown, depth: number): void => {
    if (full()) return
    if (typeof value === 'string') {
      if (value.length > 0) out.push(value.slice(0, SWEEP_MAX_STRING))
      return
    }
    if (value === null || typeof value !== 'object') return
    if (depth > SWEEP_MAX_DEPTH) return
    if (visited.has(value)) return
    visited.add(value)
    for (const item of Array.isArray(value) ? value : Object.values(value as Record<string, unknown>)) {
      visit(item, depth + 1)
      if (full()) return
    }
  }
  visit(toolInput, 0)
  return out
}

export interface DriftReport {
  /** Files whose content changed without a tool call touching them. */
  readonly drifted: readonly string[]
  /** Files the tool stream claims to have touched in this window. */
  readonly touched: readonly string[]
  /** Files the agent read but that are now different. */
  readonly staleReads: readonly string[]
  readonly scanned: number
}

export class WorkspaceWatch {
  private readonly fs: FsPort
  private readonly root: string

  /** path -> sha256 of the content last observed through a tool. */
  private readonly fingerprints = new Map<string, string>()
  /** Paths touched by tool calls in the current window. */
  private readonly touched = new Set<string>()
  /** Paths the agent has ever mutated through a tool, across windows (v0.3). */
  private readonly sessionTouched = new Set<string>()
  /** Paths the agent has read through a tool (so staleness is meaningful). */
  private readonly read = new Set<string>()
  /**
   * Tool names that only read, so their paths are "read" not "touched".
   * Consulted only after `isMutationToolName` says no (see `observe`) — the
   * shared, case-insensitive {@link READ_ONLY_TOOL_NAMES} list (H-01: a
   * camelCase `Read` from a real host used to miss the case-sensitive set,
   * fall to the default mutation charge, and permanently silence drift
   * detection for the files it read).
   */
  private readonly readOnlyTools = READ_ONLY_SET

  constructor(fs: FsPort, root: string) {
    this.fs = fs
    this.root = root
  }

  /**
   * Extract every path named by a tool call's arguments.
   *
   * Only keys name paths: a string counts when it sits under a path key
   * (`path`, `files`, …), and an array's string items count only when the
   * array itself sits under one (H9a) — a bare array anywhere else is argv
   * or content, not a path list. Nested objects still contribute their own
   * path keys.
   *
   * `contentKeys: true` re-admits the `source` key (and its array form) for
   * callers that prefer over-detection to precision — the evidence-store
   * guard in index.ts. A false positive there costs one user approval prompt;
   * a false negative lets a `move {source: '.proof/evidence.jsonl', dest: …}`
   * carry the log out of the guarded directory un-asked. The watcher itself
   * keeps the precise view: its misclassification cost is a wrong attribution,
   * which no prompt can undo.
   */
  static pathsIn(args: unknown, options: { contentKeys?: boolean } = {}): string[] {
    const keys = options.contentKeys === true
      ? new Set([...PATH_KEY_SET, 'source'])
      : PATH_KEY_SET
    const arrayKeys = options.contentKeys === true
      ? new Set([...PATH_ARRAY_KEY_SET, 'sources'])
      : PATH_ARRAY_KEY_SET
    const out = new Set<string>()
    // `underPathKey`: this value sits directly beneath a key that names paths.
    // Only there may an array's bare strings be read as paths (H9a): a bare
    // array under any other key is overwhelmingly argv (`command: ['node',
    // 'scripts/build.ts']`), patch lines, or content — collecting its strings
    // wholesale let content sail around the very key whitelist this extractor
    // exists to enforce (`{source: [...]}` used to leak the snippet as a
    // path). Nested objects still recurse: a legal path key inside an element
    // (`patches: [{file: 'x.ts'}]`) remains reachable, depth-capped as before.
    const visit = (value: unknown, depth: number, underPathKey: boolean): void => {
      if (depth > 4 || value === null || typeof value !== 'object') return
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            if (underPathKey) out.add(item)
          } else {
            visit(item, depth + 1, false)
          }
        }
        return
      }
      for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
        // X-H-14: the key comparison folds case on both sides.
        const isPathKey = keys.has(key.toLowerCase()) || arrayKeys.has(key.toLowerCase())
        if (typeof val === 'string') {
          if (isPathKey) out.add(val)
        } else {
          visit(val, depth + 1, isPathKey)
        }
      }
    }
    visit(args, 0, false)
    // W13-M3 (v0.23): no `looksLikePath` filter on the way out. Every string
    // in `out` already sits under a key that ENDORSES it as a path, and the
    // old heuristics filter rejected exactly the key-endorsed values that
    // carry no separator: a bare `{file: 'Makefile'}` or `{path: 'README'}`
    // never recorded a touch, so the agent's own edit of such a file read as
    // external drift. The key is the path authority; the shape is not.
    return [...out]
  }

  /**
   * True once this session has run any shell-class tool (`SHELL_TOOL_RE`) —
   * a session-level fact, deliberately NOT cleared by `windowStart`: once the
   * agent has had a shell, "file X is not in the touched set" no longer
   * proves "file X was changed outside the agent" — the shell's edits are
   * invisible to path extraction by construction (the command string is not
   * parsed). Consumers (drift attribution, change classification) must use
   * this to demote `external` to `unknown` rather than report a false
   * "edited behind your back". This observer states the fact; it does not
   * guess which paths the shell moved.
   */
  private shellUsed = false

  /** Record one completed tool call. */
  async observe(exec: Readonly<ToolExecution>, _result: Readonly<ToolExecutionResult>): Promise<void> {
    if (isShellToolName(exec.name)) this.shellUsed = true
    const paths = WorkspaceWatch.pathsIn(exec.arguments)
    // Classification precedence, one source of truth (`isMutationToolName`):
    //   1. the name matches a mutation/shell pattern -> mutation
    //   2. the name is on the read-only whitelist -> read
    //   3. anything else -> mutation. Unknown tools default to *mutation* on
    //      purpose: over-recording a path costs the agent an entry drift
    //      detection can walk back, but an unknown write classified as a read
    //      would let a real edit escape attribution entirely. Better to
    //      over-charge the agent than let it escape responsibility.
    const isRead = !isMutationToolName(exec.name) && this.readOnlyTools.has(exec.name.toLowerCase())
    for (const raw of paths) {
      const rel = toWorkspaceRelative(raw, this.root)
      if (rel === undefined) continue
      if (isRead) {
        this.read.add(rel)
      } else {
        this.touched.add(rel)
        this.sessionTouched.add(rel)
      }
      const hash = await this.fingerprint(rel)
      if (hash !== undefined) this.fingerprints.set(rel, hash)
    }
  }

  /** Files touched by tool calls since the last `windowStart`. */
  touchedPaths(): string[] {
    return [...this.touched].sort()
  }

  /**
   * Files the agent has mutated through tools since the watcher was created —
   * the provenance set for change attribution (windows come and go; the
   * session's responsibility does not).
   */
  sessionTouchedPaths(): string[] {
    return [...this.sessionTouched].sort()
  }

  /**
   * Whether any shell-class tool ran this session (H9b). Session-scoped like
   * `sessionTouchedPaths`: windows do not reset it, because the epistemic
   * fact it encodes ("a shell ran; path extraction has a blind spot") does
   * not age out.
   */
  sessionShellUsed(): boolean {
    return this.shellUsed
  }

  /** Clear the touched window (called at turn boundaries). */
  windowStart(): void {
    this.touched.clear()
  }

  /**
   * Compare the filesystem against recorded fingerprints.
   *
   * `drifted` is the interesting set: a file whose bytes moved without any
   * tool call claiming it. `staleReads` is the subset the agent has actually
   * seen, i.e. the ones that will corrupt its reasoning.
   */
  async detectDrift(files?: readonly string[]): Promise<DriftReport> {
    const candidates = files ?? [...this.fingerprints.keys(), ...this.read]
    const drifted: string[] = []
    const staleReads: string[] = []
    let scanned = 0

    for (const rel of [...new Set(candidates)]) {
      scanned++
      const current = await this.fingerprint(rel)
      const recorded = this.fingerprints.get(rel)
      if (current === undefined) {
        // W13-M2 (v0.23): a file the agent itself deleted through a tool is
        // the agent's own work, not drift — the vanished branch used to push
        // it into `drifted` even with `touched` set, accusing the agent of
        // "changes outside your tool calls" for its own `rm`. Only a file
        // that vanished with NO claiming tool call is drift.
        if (recorded !== undefined && !this.touched.has(rel)) {
          drifted.push(rel)
          if (this.read.has(rel)) staleReads.push(rel)
        }
        continue
      }
      if (recorded === undefined) {
        // Never observed through a tool: if it is on disk and not touched, it
        // arrived from outside the agent's tool stream.
        if (!this.touched.has(rel)) drifted.push(rel)
        continue
      }
      if (current !== recorded && !this.touched.has(rel)) {
        drifted.push(rel)
        if (this.read.has(rel)) staleReads.push(rel)
      }
    }

    return {
      drifted: [...new Set(drifted)].sort(),
      touched: [...this.touched].sort(),
      staleReads: [...new Set(staleReads)].sort(),
      scanned,
    }
  }

  /** Fingerprint every listed path without marking it touched. */
  async snapshot(paths: readonly string[]): Promise<void> {
    for (const rel of paths) {
      const hash = await this.fingerprint(rel)
      if (hash !== undefined) this.fingerprints.set(rel, hash)
      else this.fingerprints.delete(rel)
    }
  }

  private async fingerprint(rel: string): Promise<string | undefined> {
    const content = await this.fs.readFile(`${this.root}/${rel}`)
    return content === undefined ? undefined : sha256(content)
  }
}

/**
 * Project any path a tool can name onto the workspace's relative path space:
 * POSIX-absolute, Windows drive-absolute (`C:\ws\…` or `C:/ws/…`), and
 * already-relative forms all describe workspace files. A path that is absolute
 * but outside the root describes a different filesystem neighbourhood and
 * yields undefined — treating it as relative would let external files
 * masquerade as workspace state and agent edits be misattributed as external.
 *
 * Drive-absolute paths compare against the root case-insensitively: the same
 * Windows workspace legitimately arrives as `C:\…` from the host and as
 * `c:/…` from tools and language servers. POSIX stays case-sensitive.
 *
 * W13-L11 (v0.23): the relative branch folds `.`/`..` segments and refuses
 * the ones that ESCAPE. `../outside.txt` used to pass through verbatim and
 * the fingerprinter then read `${root}/../outside.txt` — a file OUTSIDE the
 * workspace, whose later external change reported as workspace drift; and
 * `a/../../b` walked out the same way. A relative path whose folded form
 * still carries a leading `..` names no workspace file and yields undefined,
 * exactly like an absolute path outside the root.
 */
export function toWorkspaceRelative(raw: string, root: string): string | undefined {
  if (raw.length === 0 || raw.length > 4096) return undefined
  if (raw.includes('\0')) return undefined
  const normalized = raw.replace(/\\/g, '/')
  const normalizedRoot = root.replace(/\\/g, '/').replace(/\/+$/, '')
  if (/^[A-Za-z]:\//.test(normalized)) {
    // A drive path can only be inside a drive root; anything else is foreign.
    if (!/^[A-Za-z]:\//.test(normalizedRoot)) return undefined
    const inside = normalized.toLowerCase().startsWith(`${normalizedRoot.toLowerCase()}/`)
    return inside ? normalized.slice(normalizedRoot.length + 1) : undefined
  }
  if (normalized.startsWith('/')) {
    return normalized.startsWith(`${normalizedRoot}/`) ? normalized.slice(normalizedRoot.length + 1) : undefined
  }
  const folded = foldRelativeSegments(normalized.replace(/^\.\//, ''))
  return folded.startsWith('../') || folded === '..' ? undefined : folded
}

/**
 * Collapse `.` and `..` segments in an already-relative path. A leading `..`
 * that would escape the root is KEPT (`..` cannot pop past nothing), so the
 * caller can recognize and refuse the escape; interior detours fold away.
 */
function foldRelativeSegments(rel: string): string {
  const out: string[] = []
  for (const segment of rel.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..' && out.length > 0 && out[out.length - 1] !== '..') out.pop()
    else out.push(segment)
  }
  return out.join('/')
}

/**
 * Render drift as corrective context for the model. Short on purpose.
 *
 * H9②/M2 (v0.23): `shellUsed` says a shell-class tool ran this session. A
 * shell's edits are invisible to path extraction by construction, so with it
 * set, "changed outside your tool calls" would be a false accusation in the
 * plugin's authoritative voice — exactly the statement the session-level
 * shell fact exists to prevent. The headings demote to what is actually
 * known ("outside your file tools; a shell ran — yours or an external
 * editor's, indistinguishable here") while the remedy line stays.
 */
export function driftNarrative(report: DriftReport, options: { shellUsed?: boolean } = {}): string | undefined {
  if (report.drifted.length === 0 && report.staleReads.length === 0) return undefined
  const shell = options.shellUsed === true
  const lines: string[] = []
  if (report.staleReads.length > 0) {
    lines.push(shell
      ? '⚠️ Files you already read have changed outside your file tools — a shell ran this session, so these may be your own shell edits or an external editor\'s (indistinguishable here). Your in-context copies are stale:'
      : '⚠️ Files you already read have changed outside your tool calls. Your in-context copies are stale:')
    for (const f of report.staleReads.slice(0, 10)) lines.push(`  · ${f}`)
  }
  if (report.drifted.length > 0 && report.staleReads.length !== report.drifted.length) {
    lines.push(shell
      ? '⚠️ Workspace changes not made through your file tools (a shell ran this session — shell edits and external edits cannot be told apart here):'
      : '⚠️ Workspace changes not made through your tools:')
    for (const f of report.drifted.filter(f => !report.staleReads.includes(f)).slice(0, 10)) lines.push(`  · ${f}`)
  }
  lines.push('Re-read these before relying on them, then re-run proof_verify.')
  return lines.join('\n')
}
