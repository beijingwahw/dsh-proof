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
const PATH_KEYS = ['path', 'file', 'file_path', 'filePath', 'target', 'filename', 'dest', 'destination']
const PATH_ARRAY_KEYS = ['paths', 'files', 'targets', 'globs', 'patterns']

/**
 * Tool-name classification — the single source both adapter layers consult
 * (the pre-execute gates in index.ts and the read/write split below). It lives
 * here so the watcher cannot drift from the gates again.
 */
/** Tools whose calls constitute a workspace mutation. */
export const MUTATION_TOOL_RE = /(^|[_-])(write|edit|create|patch|delete|remove|move|rename|mkdir|touch|apply|install|update|upsert)([_-]|$)/i
/** Tools that execute arbitrary host commands (which can mutate anything). */
export const SHELL_TOOL_RE = /^(bash|shell|exec|run_code|run_command|terminal|process|task|npm|pnpm|yarn|pip|cargo|go|make)$/i

/** True when a tool call of this name can move workspace state. */
export function isMutationToolName(toolName: string): boolean {
  return MUTATION_TOOL_RE.test(toolName) || SHELL_TOOL_RE.test(toolName)
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
   * Consulted only after `isMutationToolName` says no (see `observe`).
   */
  private readonly readOnlyTools = new Set(['read', 'read_file', 'view', 'cat', 'grep', 'glob', 'ls', 'list', 'search', 'search_files', 'find', 'show', 'head', 'tail'])

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
      ? [...PATH_KEYS, 'source']
      : PATH_KEYS
    const arrayKeys = options.contentKeys === true
      ? [...PATH_ARRAY_KEYS, 'sources']
      : PATH_ARRAY_KEYS
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
        const isPathKey = keys.includes(key) || arrayKeys.includes(key)
        if (typeof val === 'string') {
          if (isPathKey) out.add(val)
        } else {
          visit(val, depth + 1, isPathKey)
        }
      }
    }
    visit(args, 0, false)
    return [...out].filter(p => looksLikePath(p))
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
    if (SHELL_TOOL_RE.test(exec.name)) this.shellUsed = true
    const paths = WorkspaceWatch.pathsIn(exec.arguments)
    // Classification precedence, one source of truth (`isMutationToolName`):
    //   1. the name matches a mutation/shell pattern -> mutation
    //   2. the name is on the read-only whitelist -> read
    //   3. anything else -> mutation. Unknown tools default to *mutation* on
    //      purpose: over-recording a path costs the agent an entry drift
    //      detection can walk back, but an unknown write classified as a read
    //      would let a real edit escape attribution entirely. Better to
    //      over-charge the agent than let it escape responsibility.
    const isRead = !isMutationToolName(exec.name) && this.readOnlyTools.has(exec.name)
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
        if (recorded !== undefined) {
          // File disappeared under us.
          drifted.push(rel)
          if (this.read.has(rel) && !this.touched.has(rel)) staleReads.push(rel)
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
  return normalized.replace(/^\.\//, '')
}

function looksLikePath(value: string): boolean {
  if (value.length === 0 || value.length > 4096) return false
  if (/\s/.test(value) && !/[/.\\]/.test(value)) return false
  return /[/.\\]/.test(value) || /^[A-Za-z0-9_-]+$/.test(value) === false
}

/** Render drift as corrective context for the model. Short on purpose. */
export function driftNarrative(report: DriftReport): string | undefined {
  if (report.drifted.length === 0 && report.staleReads.length === 0) return undefined
  const lines: string[] = []
  if (report.staleReads.length > 0) {
    lines.push('⚠️ Files you already read have changed outside your tool calls. Your in-context copies are stale:')
    for (const f of report.staleReads.slice(0, 10)) lines.push(`  · ${f}`)
  }
  if (report.drifted.length > 0 && report.staleReads.length !== report.drifted.length) {
    lines.push('⚠️ Workspace changes not made through your tools:')
    for (const f of report.drifted.filter(f => !report.staleReads.includes(f)).slice(0, 10)) lines.push(`  · ${f}`)
  }
  lines.push('Re-read these before relying on them, then re-run proof_verify.')
  return lines.join('\n')
}
