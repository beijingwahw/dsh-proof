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

import type { JuryAttestation } from './attest.ts'

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
  /**
   * Signal name (e.g. 'SIGTERM') when the process was terminated by an
   * external signal — one that did not come from this port's own abort or
   * timeout handling. `exitCode === null` with `aborted === false` alone
   * cannot distinguish an external kill from a timeout; this field can.
   * Since libuv 1.44 a kill issued by THIS process (abort/timeout) does
   * propagate `exit_signal` even on Windows; what stays indistinguishable
   * there is only a third party's TerminateProcess (exit code 1, no signal),
   * and ports leave the field unset rather than inventing a signal for it.
   */
  readonly killedBySignal?: string
  /**
   * True when this port itself killed the process for exceeding its
   * `timeoutMs` budget — "we killed it because it ran too slow", as opposed
   * to the outside world killing it (`killedBySignal`) or the caller
   * cancelling (`aborted`). The three are orthogonal facts: a timeout kill
   * still reports `exitCode: null` and (for consumers predating this field)
   * a `spawnError` of the form `timed out after Nms`, but the honest death
   * cause lives here.
   */
  readonly timedOut?: boolean
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
  /** Recursively list regular files under `root`, relative to it. See `WalkResult`. */
  walk(root: string, options?: WalkOptions): Promise<WalkResult>
  /** Append one line to a JSONL log, creating parent directories. */
  appendLine(path: string, line: string): Promise<void>
  /** Read every line of a JSONL log, or `[]` when absent. */
  readLines(path: string): Promise<string[]>
  /** Write a file atomically (write-temp + rename). */
  writeFile(path: string, contents: string): Promise<void>
  mkdirp(path: string): Promise<void>
  /**
   * τ: recursively delete a directory tree — used to clean up the
   * `NODE_V8_COVERAGE` scratch directory after a run has harvested its
   * `coverage-*.json` files. Optional capability: the Node implementation
   * removes recursively; `MemoryFs` and other in-memory fakes may omit it,
   * and callers must treat its absence as "cleanup not supported", never as
   * an error.
   */
  removeDir?(path: string): Promise<void>
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

/**
 * M8: what a workspace walk saw — and, crucially, whether it stopped early.
 * `truncated` is `true` the moment the walk stopped at its `limit`: the file
 * list is then a PREFIX of the workspace, not a census, and every consumer
 * (the dependency graph, check selection, anything reasoning about "files
 * that do not exist") must treat the result as incomplete — a silently
 * truncated walk presented as complete is how a workspace bigger than the
 * limit produced a graph that never said it was partial, and a "proven"
 * grade over files the walk never saw. Callers that cannot widen the limit
 * must propagate `truncated` so the impact decision degrades to *uncertain*
 * (over-selection), never to a falsely narrow selection.
 */
export interface WalkResult {
  /** Regular files under `root`, relative to it, sorted. */
  readonly files: readonly string[]
  /** True when the walk stopped at `limit` — more files may exist unseen. */
  readonly truncated: boolean
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

/**
 * 陪审端口：宿主若有隔离模型 seam 可实现之；v0.11 适配层用 same-session
 * 工具协议实现。(ι) The host may implement this with a genuinely isolated
 * model seam — which is what `independence: 'isolated-model'` is for — while
 * the default adapter deliberates through the same session's tool protocol
 * and must record itself as 'same-session'. Either way the implementation's
 * duty is to build the prompt with `juryPrompt`, run the juror verbatim, and
 * return the complete deliberation for the chain; it decides, it does not
 * advocate.
 */
export interface JuryPort {
  deliberate(request: { claim: string; context: string }): Promise<JuryAttestation>
}

/**
 * Resolves the workspace file an import site binds to, typically by asking
 * a language server (goToDefinition on the module specifier). Implementations
 * MUST be defensive: any failure resolves to `null`, which the graph builder
 * treats as "unverified" and falls back to the approximate edge — precision
 * degrades visibly, soundness never narrows.
 */
export interface DefinitionResolverPort {
  /**
   * @param file workspace-relative path of the importing file
   * @param line 0-based line of the specifier, UTF-16 code units
   * @param character 0-based column of the specifier start
   * @returns workspace-relative path of the resolved file, or `null`
   */
  resolveDefinition(file: string, line: number, character: number): Promise<string | null>
}

/** Workspace facts the core needs but does not own. */
export interface WorkspacePort {
  /** Absolute root of the project under verification. */
  readonly root: string
  /** `git rev-parse HEAD`, or `null` outside a git work tree. */
  gitHead(): Promise<string | null>
  /**
   * Files differing from `HEAD`, relative to root. FAILURE CONTRACT: a query
   * that fails (git error, lock contention, timeout) must REJECT — a failed
   * query is not an empty answer; throw so callers can degrade loudly. An
   * empty array is reserved for the positive finding "nothing is dirty".
   */
  gitDirty(): Promise<string[]>
  /**
   * Files differing from `ref` (tracked, worktree + index), relative to root.
   * Optional capability: hosts without git history support omit it and the
   * change-set resolution degrades to the dirty-set union. FAILURE CONTRACT:
   * as with `gitDirty` — a failed query must reject, never resolve `[]`.
   */
  changedSince?(ref: string): Promise<string[]>
  /**
   * Untracked files (honouring .gitignore), relative to root. Optional.
   * FAILURE CONTRACT: as with `gitDirty` — a failed query must reject, never
   * resolve `[]`; "no untracked files" is a positive finding, not a default.
   */
  untracked?(): Promise<string[]>
  /**
   * Whether git is usable in this workspace at all (binary present, inside a
   * work tree). Optional capability: hosts that omit it are treated as
   * "git available" so callers keep their current degradation path; hosts
   * without git should implement it returning `false` so callers can skip
   * git-dependent work instead of discovering the failure per command.
   */
  gitAvailable?(): Promise<boolean>
}

/** A check the workspace can objectively answer: run this command, expect success. */
export interface CheckSpec {
  /** Stable identity, derived from `source` + `command`. */
  readonly id: string
  /** Human label shown to the model and to the user. */
  readonly label: string
  /** argv vector. The first element is the executable. */
  readonly command: readonly string[]
  /**
   * What kind of claim this check answers. A `benchmark` kind measures
   * performance: its evidence's `durationMs` is what a perf-budget contract's
   * `within-budget` obligation binds to.
   */
  readonly kind: CheckKind
  /** Where the check was discovered. */
  readonly source: CheckSource
  /**
   * Path prefixes (relative to workspace root) whose modification makes this
   * check's evidence stale. `['*']` means "any change invalidates me".
   */
  readonly paths: readonly string[]
  /**
   * Directory the command runs in, relative to the workspace root. Absent
   * means the root itself — which is every pre-monorepo check. The runner
   * resolves it to `<root>/<cwd>`; discovery uses it so workspace-subpackage
   * checks (same argv, different package) get distinct identities and actually
   * execute inside the subpackage that declares them.
   */
  readonly cwd?: string
  /** Cooperative budget for one run. */
  readonly timeoutMs: number
  /**
   * sha256 (hex) of the script *body* that defines this check — discovery's
   * answer to "the id says `npm run test`, but WHAT did `test` say?". Only the
   * package.json discovery path fills it (the npm script's verbatim text);
   * explicit config entries and the other ecosystems (make/py/go targets)
   * leave it `undefined` because their "script body" is not enumerable from
   * build metadata — a documented limitation, not an oversight. It is
   * deliberately NOT part of the `checkId` material (ids must stay
   * byte-compatible with already-minted baselines) and never enters the
   * evidence payload; it exists so a baseline can record, and the engine can
   * later compare, *which body* answered under a given id — an agent
   * rewriting `"test": "vitest run"` into `"exit 0"` keeps the id but cannot
   * keep the digest.
   */
  readonly scriptDigest?: string
}

// 'benchmark' (ε) is additive: perf-measuring checks get their own kind so a
// perf-budget claim can find their evidence by kind.
export type CheckKind = 'test' | 'build' | 'lint' | 'typecheck' | 'benchmark' | 'other'
export type CheckSource =
  | 'package.json'
  | 'pyproject.toml'
  | 'tox.ini'
  | 'Makefile'
  | 'Cargo.toml'
  | 'go.mod'
  | 'composer.json'
  | 'config'
  // ο: a check the plugin *constructed* for an assertion no discovered check
  // covers (see core/synthetic.ts). It counts — the run is real, screened and
  // content-addressed — but it weighs less than any discovered check, because
  // its author is a party to the claim it tests. The pricing lives in
  // core/bayes.ts (falsePass 0.15 vs 0.02); this value is the marker every
  // consumer (bayes, contract details, reports) keys on, never a record shape.
  | 'synthetic'
