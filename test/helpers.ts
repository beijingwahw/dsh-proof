/**
 * In-memory fakes for the core ports, so the whole engine is testable without a
 * harness, a git repository, or a shell.
 */

import type {
  CheckSpec, Clock, CommandPort, CommandResult, CommandRunOptions,
  FileStat, FsPort, WalkOptions, WalkResult, WorkspacePort,
} from '../src/core/ports.ts'

export class FakeClock implements Clock {
  private t = 1_700_000_000_000
  /** Advances 1ms per read so elapsed-time logic behaves without real waiting. */
  now(): number { this.t += 1; return this.t }
  advance(ms: number): void { this.t += ms }
}

export class MemoryFs implements FsPort {
  files = new Map<string, string>()
  log: string[] = []
  /**
   * V8-L3 (v0.24): directories the fake knows exist WITHOUT any file under
   * them. The production port (`NodeFsPort.readDir`) answers `[]` for an
   * existing-but-empty directory and `undefined` only for a path that is not
   * a directory at all; the fake used to fold BOTH into `undefined`, so
   * "exists, empty" — a shape tests need to pin (e.g. an empty coverage
   * staging dir) — was unexpressible. A directory registers here via
   * `mkdirp`; any path with files under it exists implicitly, exactly as
   * before.
   */
  private readonly dirs = new Set<string>()
  /**
   * Per-path mtime clock (instance-level counter). `stat` used to report a
   * constant `mtimeMs: 0`, which made cache-invalidation-by-mtime untestable:
   * the LSP resolver versions documents as `mtimeMs:size`, so a file rewritten
   * to the same length looked unchanged forever. `mutate` (the test hook for
   * "the file changed behind the engine's back") bumps the counter; every
   * never-mutated path keeps `mtimeMs: 0`, exactly the pre-existing value, so
   * no existing assertion on fresh files can observe the counter.
   */
  private mtimeCounter = 0
  private readonly mtimes = new Map<string, number>()

  static of(entries: Record<string, string>): MemoryFs {
    const fs = new MemoryFs()
    for (const [k, v] of Object.entries(entries)) fs.files.set(normalize(k), v)
    return fs
  }

  async readFile(path: string): Promise<string | undefined> {
    return this.files.get(normalize(path))
  }

  async readDir(path: string): Promise<string[] | undefined> {
    const key = normalize(path)
    const prefix = `${key.replace(/\/+$/, '')}/`
    const names = new Set<string>()
    for (const fileKey of this.files.keys()) {
      if (fileKey.startsWith(prefix)) names.add(fileKey.slice(prefix.length).split('/')[0] as string)
    }
    // V8-L3: exists-but-empty answers [] (production semantics — see the
    // `dirs` field note); only a path that is neither a parent of any file
    // nor a registered directory answers undefined.
    if (names.size > 0) return [...names].sort()
    return this.dirs.has(key) || this.dirs.has(key.replace(/\/+$/, '')) ? [] : undefined
  }

  async stat(path: string): Promise<FileStat | undefined> {
    const content = this.files.get(normalize(path))
    if (content === undefined) return undefined
    return { kind: 'file', size: content.length, mtimeMs: this.mtimes.get(normalize(path)) ?? 0 }
  }

  async walk(root: string, options: WalkOptions = {}): Promise<WalkResult> {
    const prefix = `${normalize(root).replace(/\/+$/, '')}/`
    const ignore = new Set(options.ignoreDirs ?? [])
    const out: string[] = []
    for (const key of this.files.keys()) {
      if (!key.startsWith(prefix)) continue
      const rel = key.slice(prefix.length)
      if (rel.split('/').some(s => ignore.has(s))) continue
      out.push(rel)
    }
    const limit = options.limit ?? 1e9
    const files = out.sort().slice(0, limit)
    // Mirrors NodeFsPort semantics exactly: hitting the cap is truncation —
    // the fake knows the full list, but fidelity with the real port beats
    // cleverness, and tests that pin the real port's conservative answer
    // (`limit` reached ⇒ `truncated`, even when nothing more remained) must
    // see the same answer here.
    return { files, truncated: files.length >= limit }
  }

  async appendLine(path: string, line: string): Promise<void> {
    const key = normalize(path)
    const prev = this.files.get(key)
    this.files.set(key, prev === undefined ? `${line}\n` : `${prev}${line}\n`)
    this.log.push(line)
  }

  async readLines(path: string): Promise<string[]> {
    const raw = this.files.get(normalize(path))
    return raw === undefined ? [] : raw.split('\n').filter(l => l.trim().length > 0)
  }

  async writeFile(path: string, contents: string): Promise<void> {
    this.files.set(normalize(path), contents)
  }

  async mkdirp(path: string): Promise<void> {
    // The memory fs needs no directories for file placement — but registering
    // the path makes "exists, empty" expressible for readDir (V8-L3), which
    // the production port answers with [] rather than undefined.
    this.dirs.add(normalize(path).replace(/\/+$/, ''))
  }

  /**
   * V8-L3 (v0.24): the optional recursive-delete capability, mirroring
   * `NodeFsPort.removeDir` — deletes every file under the prefix (and the
   * registered directories at/under it). Best-effort like the production
   * port: never throws, exactly what a staging cleanup may ask of it.
   */
  async removeDir(path: string): Promise<void> {
    const prefix = `${normalize(path).replace(/\/+$/, '')}/`
    for (const key of [...this.files.keys()]) {
      if (key.startsWith(prefix)) this.files.delete(key)
    }
    for (const dir of [...this.dirs]) {
      if (dir === prefix.slice(0, -1) || dir.startsWith(prefix)) this.dirs.delete(dir)
    }
  }

  /** Test helper: mutate a file behind the engine's back. */
  mutate(path: string, contents: string): void {
    const key = normalize(path)
    this.files.set(key, contents)
    this.mtimes.set(key, ++this.mtimeCounter)
  }
}

/** A command port driven by a table of predicate -> outcome. */
export class FakeCommands implements CommandPort {
  calls: { argv: readonly string[]; cwd: string }[] = []
  private readonly rules: { match: (argv: readonly string[]) => boolean; result: Partial<CommandResult>; delayMs?: number }[] = []

  /** Every command succeeds with empty output unless a rule says otherwise. */
  /** Newest rule wins, so a test can flip an outcome without resetting. */
  on(match: (argv: readonly string[]) => boolean, result: Partial<CommandResult>, options?: { delayMs?: number }): this {
    this.rules.unshift({ match, result, ...(options?.delayMs !== undefined ? { delayMs: options.delayMs } : {}) })
    return this
  }

  onCommand(command: string, result: Partial<CommandResult>, options?: { delayMs?: number }): this {
    return this.on(argv => argv.includes(command), result, options)
  }

  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    this.calls.push({ argv, cwd: options.cwd })
    if (options.signal.aborted) {
      return { exitCode: null, output: '', durationMs: 0, aborted: true }
    }
    for (const rule of this.rules) {
      if (rule.match(argv)) {
        // Optional wall-clock delay, so tests can force commands to settle
        // out of submission order and assert the runner's determinism.
        if (rule.delayMs !== undefined) await new Promise<void>(resolve => { setTimeout(resolve, rule.delayMs) })
        return {
          exitCode: rule.result.exitCode ?? 0,
          output: rule.result.output ?? '',
          durationMs: rule.result.durationMs ?? 5,
          aborted: rule.result.aborted ?? false,
          ...(rule.result.spawnError !== undefined ? { spawnError: rule.result.spawnError } : {}),
        }
      }
    }
    return { exitCode: 0, output: '', durationMs: 5, aborted: false }
  }
}

export class FakeWorkspace implements WorkspacePort {
  dirty: string[] = []
  head: string | null = 'abc123'
  /** Files the fake reports as differing from `head` (tracked). */
  changedSinceFiles: string[] = []
  /** Files the fake reports as untracked. */
  untrackedFiles: string[] = []
  /**
   * What `gitAvailable()` reports (E3). `null` simulates a host that never
   * implemented the capability: the `gitAvailable` property itself becomes
   * `undefined`, exactly like a port object without the optional method —
   * consumers' `gitAvailable?.()` / `!== undefined` checks must see absence,
   * not a throwing method. Defaults to `true` (the port contract treats an
   * absent capability as "git available").
   */
  gitAvailableValue: boolean | null = true
  readonly root: string

  constructor(root: string = '/ws') {
    this.root = root
  }

  /** Optional capability, re-derived from `gitAvailableValue` on every access. */
  get gitAvailable(): (() => Promise<boolean>) | undefined {
    const value = this.gitAvailableValue
    return value === null ? undefined : () => Promise.resolve(value)
  }

  async gitHead(): Promise<string | null> { return this.head }
  async gitDirty(): Promise<string[]> { return [...this.dirty].sort() }
  async changedSince(ref: string): Promise<string[]> { void ref; return [...this.changedSinceFiles].sort() }
  async untracked(): Promise<string[]> { return [...this.untrackedFiles].sort() }
}

export function spec(overrides: Partial<CheckSpec> & { id: string }): CheckSpec {
  return {
    label: overrides.id,
    command: ['npm', 'run', '--silent', 'test'],
    kind: 'test',
    source: 'config',
    paths: ['*'],
    timeoutMs: 10_000,
    ...overrides,
  } as CheckSpec
}

function normalize(path: string): string {
  return path.replace(/\\/g, '/').replace(/\/+/g, '/')
}
