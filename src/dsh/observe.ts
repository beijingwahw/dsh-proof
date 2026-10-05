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

/** Tools whose arguments name files this plugin should fingerprint. */
const PATH_KEYS = ['path', 'file', 'file_path', 'filePath', 'target', 'filename', 'dest', 'destination', 'source']
const PATH_ARRAY_KEYS = ['paths', 'files', 'targets', 'globs', 'patterns']

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
  /** Tool names that only read, so their paths are "read" not "touched". */
  private readonly readOnlyTools = new Set(['read', 'read_file', 'view', 'cat', 'grep', 'glob', 'ls', 'list', 'search'])

  constructor(fs: FsPort, root: string) {
    this.fs = fs
    this.root = root
  }

  /** Extract every path named by a tool call's arguments. */
  static pathsIn(args: unknown): string[] {
    const out = new Set<string>()
    const visit = (value: unknown, depth: number): void => {
      if (depth > 4 || value === null || typeof value !== 'object') return
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') out.add(item)
          else visit(item, depth + 1)
        }
        return
      }
      for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
        if (typeof val === 'string' && (PATH_KEYS.includes(key) || PATH_ARRAY_KEYS.includes(key))) {
          out.add(val)
        } else {
          visit(val, depth + 1)
        }
      }
    }
    visit(args, 0)
    return [...out].filter(p => looksLikePath(p))
  }

  /** Record one completed tool call. */
  async observe(exec: Readonly<ToolExecution>, _result: Readonly<ToolExecutionResult>): Promise<void> {
    const paths = WorkspaceWatch.pathsIn(exec.arguments)
    const isRead = this.readOnlyTools.has(exec.name)
    for (const raw of paths) {
      const rel = this.toRelative(raw)
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

  private toRelative(raw: string): string | undefined {
    if (raw.length === 0 || raw.length > 4096) return undefined
    if (raw.includes('\0')) return undefined
    const normalized = raw.replace(/\\/g, '/')
    if (normalized.startsWith('/')) {
      const root = this.root.replace(/\\/g, '/').replace(/\/+$/, '')
      return normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : undefined
    }
    return normalized.replace(/^\.\//, '')
  }
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
