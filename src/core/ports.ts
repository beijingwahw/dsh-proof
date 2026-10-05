/**
 * Ports — the only way the `dsh-proof` core touches the outside world.
 *
 * The core is a pure domain layer: it never imports `@deepseek-ai/*`, never
 * opens a socket, and never reads `process`. Everything it needs arrives
 * through these interfaces. That is the "interface / implementation / consumer"
 * split DSH itself prescribes — the DSH adapter (`src/dsh/`) is just one
 * implementation of these ports, and the test suite is another.
 *
 * @module dsh-proof/core/ports
 */

/** Result of running one external command to completion. */
export interface CommandResult {
  /** Process exit code, or `null` when the process was killed by a signal. */
  readonly exitCode: number | null
  /** Combined stdout+stderr captured for evidence. */
  readonly output: string
  /** Wall-clock duration in milliseconds. */
  readonly durationMs: number
  /** True when the run was aborted through the supplied signal. */
  readonly aborted: boolean
  /** Set when the command could not even be started. */
  readonly spawnError?: string
}

/** Runs an argv vector to completion. Implementations must honour `signal`. */
export interface CommandPort {
  run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult>
}

export interface CommandRunOptions {
  readonly cwd: string
  readonly timeoutMs: number
  readonly signal: AbortSignal
  /** Environment overlay applied on top of the inherited environment. */
  readonly env?: Readonly<Record<string, string>>
  /** Maximum captured output size in characters. */
  readonly maxOutputChars?: number
}

/** The subset of the filesystem the core is allowed to see. */
export interface FsPort {
  /** UTF-8 file contents, or `undefined` when the path does not exist / is not a file. */
  readFile(path: string): Promise<string | undefined>
  /** Directory entries (names only, not paths), or `undefined` when not a directory. */
  readDir(path: string): Promise<string[] | undefined>
  /** POSIX-ish `lstat`: file kind + mtime + size, or `undefined`. */
  stat(path: string): Promise<FileStat | undefined>
  /** Recursively list regular files under `root`, relative to it. */
  walk(root: string, options?: WalkOptions): Promise<string[]>
  /** Append one line to a JSONL log, creating parent directories. */
  appendLine(path: string, line: string): Promise<void>
  /** Read every line of a JSONL log, or `[]` when absent. */
  readLines(path: string): Promise<string[]>
  /** Write a file atomically (write-temp + rename). */
  writeFile(path: string, contents: string): Promise<void>
  mkdirp(path: string): Promise<void>
}

export interface FileStat {
  readonly kind: 'file' | 'dir' | 'other'
  readonly size: number
  readonly mtimeMs: number
}

export interface WalkOptions {
  /** Directory names skipped entirely. */
  readonly ignoreDirs?: readonly string[]
  /** Maximum number of files returned before the walk stops. */
  readonly limit?: number
}

/** Deterministic time source, so evidence ids are reproducible in tests. */
export interface Clock {
  now(): number
}

/**
 * Signs checkpoint payloads with a key held by the *host*, outside the
 * workspace the agent can write to. The model can recompute every hash in
 * the log, but it cannot produce a signature only this key can make — that
 * asymmetry is what separates the prover from the verifier.
 */
export interface SignerPort {
  /** Stable identity of the signing key (digest of the public key). */
  readonly keyId: string
  /** Detached signature over the exact UTF-8 string, base64-encoded. */
  sign(data: string): Promise<string>
  /** True when `signature` was produced by this key over `data`. */
  verify(data: string, signature: string): Promise<boolean>
}

/** Workspace facts the core needs but does not own. */
export interface WorkspacePort {
  /** Absolute root of the project under verification. */
  readonly root: string
  /** `git rev-parse HEAD`, or `null` outside a git work tree. */
  gitHead(): Promise<string | null>
  /** Files differing from `HEAD`, relative to root. */
  gitDirty(): Promise<string[]>
}

/** A check the workspace can objectively answer: run this command, expect success. */
export interface CheckSpec {
  /** Stable identity, derived from `source` + `command`. */
  readonly id: string
  /** Human label shown to the model and to the user. */
  readonly label: string
  /** argv vector. The first element is the executable. */
  readonly command: readonly string[]
  /** What kind of claim this check answers. */
  readonly kind: CheckKind
  /** Where the check was discovered. */
  readonly source: CheckSource
  /**
   * Path prefixes (relative to workspace root) whose modification makes this
   * check's evidence stale. `['*']` means "any change invalidates me".
   */
  readonly paths: readonly string[]
  /** Cooperative budget for one run. */
  readonly timeoutMs: number
}

export type CheckKind = 'test' | 'build' | 'lint' | 'typecheck' | 'other'
export type CheckSource =
  | 'package.json'
  | 'pyproject.toml'
  | 'Makefile'
  | 'Cargo.toml'
  | 'go.mod'
  | 'composer.json'
  | 'config'
