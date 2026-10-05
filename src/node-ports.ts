/**
 * Real Node implementations of the core ports.
 *
 * Kept out of `core/` on purpose: the domain layer must not know it is running
 * on Node, and these adapters are the only place allowed to spawn processes or
 * touch `node:fs`.
 *
 * @module dsh-proof/node-ports
 */

import { spawn } from 'node:child_process'
import { existsSync, promises as fsp, readFileSync, statSync } from 'node:fs'
import * as path from 'node:path'
import { StringDecoder } from 'node:string_decoder'
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto'
import type {
  Clock, CommandPort, CommandResult, CommandRunOptions, FileStat, FsPort,
  SignerPort, WalkOptions, WorkspacePort,
} from './core/ports.ts'

export class SystemClock implements Clock {
  now(): number { return Date.now() }
}

/**
 * Windows: `npm`, `pnpm`, `yarn` & co. ship as `.cmd` shims, which
 * `spawn(shell: false)` cannot execute (ENOENT for a bare name, EINVAL once
 * the name carries its `.cmd` extension). Rather than enabling a shell (an
 * injection surface this port refuses to open), the shims are *parsed*:
 * npm-generated `.cmd` files follow a stable template that ends in exactly
 * one invocation of `node <target> %*` (or `<target.exe> %*`), and that tail
 * can be rewritten into a pure argv vector — no string interpolation, still
 * no shell. The well-known `npm` fast path is kept ahead of the generic
 * parse: it needs no file read at all.
 */
function resolveWindowsArgv(argv: readonly string[], env: NodeJS.ProcessEnv, cwd: string): string[] {
  const command = argv[0]
  if (command === undefined) return [...argv]
  const lower = command.toLowerCase()
  if (lower === 'npm' || lower === 'npm.cmd') {
    const cli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    if (existsSync(cli)) return [process.execPath, cli, ...argv.slice(1)]
  }
  const shimPath = findCmdShim(command, env, cwd)
  if (shimPath !== undefined) {
    const resolution = resolveCmdShim(shimPath)
    if (resolution !== undefined) {
      if ('script' in resolution) return [resolution.node, resolution.script, ...argv.slice(1)]
      return [resolution.exe, ...argv.slice(1)]
    }
  }
  return [...argv]
}

/** What a parsed `.cmd` shim reduces to: a `node <script>` vector, a direct exe, or nothing. */
export type CmdShimResolution =
  | { readonly node: string; readonly script: string }
  | { readonly exe: string }

/**
 * npm-template invocation tails this parser is willing to rewrite. Both
 * template generations forward `%*` after exactly one quoted target relative
 * to the shim's own directory (`%dp0%` / `%~dp0`):
 *   current:  `... || title %COMSPEC% & "%_prog%"  "%dp0%\..\pkg\target" %*`
 *   legacy:   `"%~dp0\node.exe"  "%~dp0\..\pkg\target" %*` / `node  "..." %*`
 */
const SHIM_NODE_TAIL =
  /(?:"%_prog%"|"%~dp0\\node\.exe"|\bnode(?:\.exe)?)\s+"(?:%dp0%|%~dp0)\\([^"%]+)"\s+%\*\s*$/
const SHIM_DIRECT_TAIL = /"(?:%dp0%|%~dp0)\\([^"%]+)"\s+%\*\s*$/

function isRegularFile(p: string): boolean {
  try {
    return statSync(p).isFile()
  } catch {
    return false
  }
}

/**
 * Parses an npm-generated `.cmd` shim into a spawnable argv head — the
 * world's fix for "user configured `pnpm test` and spawn said ENOENT"
 * without ever opening a shell.
 *
 * Conservative by contract: ANY ambiguity — two different targets, an
 * unresolved `%VAR%` inside the target, a directly-invoked script that would
 * itself need a shell or interpreter — returns `undefined`, and the caller
 * lets the raw spawn fail with its clean spawnError instead. Never guess.
 */
export function resolveCmdShim(cmdPath: string): CmdShimResolution | undefined {
  let text: string
  try {
    text = readFileSync(cmdPath, 'utf8').replace(/^\uFEFF/, '')
  } catch {
    return undefined
  }
  const shimDir = path.dirname(cmdPath)
  const scripts = new Set<string>()
  const exes = new Set<string>()
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line.length === 0) continue
    const nodeMatch = SHIM_NODE_TAIL.exec(line)
    if (nodeMatch !== null) {
      const rel = nodeMatch[1]
      // `%` here would mean an unresolved environment variable — refuse.
      if (rel === undefined || rel.includes('%')) return undefined
      scripts.add(path.resolve(shimDir, rel).toLowerCase())
      continue
    }
    const directMatch = SHIM_DIRECT_TAIL.exec(line)
    if (directMatch !== null) {
      const rel = directMatch[1]
      if (rel === undefined || rel.includes('%')) return undefined
      const target = path.resolve(shimDir, rel).toLowerCase()
      // A directly-invoked script (`.js`, `.ps1`, extensionless) would itself
      // need a shell or an interpreter choice we cannot vouch for — refuse.
      if (!/\.(exe|com)$/.test(target)) return undefined
      exes.add(target)
    }
  }
  // Exactly one target, one shape — everything else is ambiguity.
  if (scripts.size > 1 || exes.size > 1 || (scripts.size > 0 && exes.size > 0)) return undefined
  if (scripts.size === 1) {
    const script = [...scripts][0]
    if (script === undefined || !isRegularFile(script)) return undefined
    // The template prefers a node.exe living next to the shim (portable
    // installs); fall back to the running runtime, exactly like `_prog=node`.
    const shimLocalNode = path.join(shimDir, 'node.exe')
    return { node: isRegularFile(shimLocalNode) ? shimLocalNode : process.execPath, script }
  }
  if (exes.size === 1) {
    const exe = [...exes][0]
    return exe !== undefined && isRegularFile(exe) ? { exe } : undefined
  }
  return undefined
}

/**
 * Case-robust PATH lookup — Windows hands the variable over as `Path` as
 * often as `PATH`, and a caller overlay may spell it yet another way. The
 * last definition wins: that is the caller's intent over the inheritance.
 */
function pathEnvValue(env: NodeJS.ProcessEnv): string | undefined {
  let value: string | undefined
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === 'PATH') value = env[key]
  }
  return value
}

/**
 * Locates the `.cmd` shim cmd.exe would run for `command`, mirroring its
 * resolution closely enough to never hijack a directly-spawnable executable:
 * the spawn cwd first, then PATH directories in order; inside a directory
 * `.com`/`.exe`/`.bat` beat `.cmd` (PATHEXT order), and finding one means
 * plain spawn already handles the command — no rewrite, stay out of it.
 */
function findCmdShim(command: string, env: NodeJS.ProcessEnv, cwd: string): string | undefined {
  const isCmdName = command.toLowerCase().endsWith('.cmd')
  if (/[\\/]/.test(command)) {
    if (!isCmdName) return undefined
    const direct = path.resolve(cwd, command)
    return isRegularFile(direct) ? direct : undefined
  }
  const cmdName = isCmdName ? command : `${command}.cmd`
  const rivals = isCmdName ? [] : ['.com', '.exe', '.bat']
  const dirs = [cwd, ...(pathEnvValue(env)?.split(';') ?? [])]
  for (const dir of dirs) {
    if (dir.trim().length === 0) continue
    const base = path.resolve(dir)
    if (rivals.some((ext) => isRegularFile(path.join(base, command + ext)))) return undefined
    const candidate = path.join(base, cmdName)
    if (isRegularFile(candidate)) return candidate
  }
  return undefined
}

/** Spawns argv vectors without a shell — no quoting games, no injection surface. */
export class NodeCommandPort implements CommandPort {
  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    // An already-aborted signal never fires its 'abort' listener, so checking
    // after spawn would let the child run until the timeout killed it.
    if (options.signal?.aborted) {
      return { exitCode: null, output: '', durationMs: 0, aborted: true }
    }
    // Child environment, computed once so the Windows shim resolver sees the
    // same PATH the child will: inherited environment first, deterministic
    // color/CI defaults on top of it, caller overlay last — hosts stay free
    // to override when they must, everything else gets deterministic output.
    const env: NodeJS.ProcessEnv = {
      ...process.env, CI: '1', FORCE_COLOR: '0', NO_COLOR: '1', ...(options.env ?? {}),
    }
    const [command, ...args] = process.platform === 'win32'
      ? resolveWindowsArgv(argv, env, options.cwd)
      : [...argv]
    const started = Date.now()
    return new Promise((resolve) => {
      if (command === undefined) {
        resolve({ exitCode: null, output: '', durationMs: 0, aborted: false, spawnError: 'empty command' })
        return
      }
      const maxChars = options.maxOutputChars ?? 64_000
      let output = ''
      let aborted = false
      let timedOut = false
      let settled = false
      // One decoder per stream: a multi-byte UTF-8 character straddling a
      // chunk boundary must survive the join instead of becoming U+FFFD —
      // captured evidence has to be byte-faithful for digests to be stable.
      const stdoutDecoder = new StringDecoder('utf8')
      const stderrDecoder = new StringDecoder('utf8')

      let child: ReturnType<typeof spawn>
      try {
        child = spawn(command, args, {
          cwd: options.cwd,
          env,
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: false,
        })
      } catch (error) {
        // Some argv heads (an explicit `.cmd`/`.bat` path, a null byte)
        // make spawn() itself throw synchronously — surface that as the
        // same clean spawnError instead of a rejected promise. No timer
        // or listener has been registered yet, so resolve directly.
        resolve({
          exitCode: null,
          output: '',
          durationMs: Date.now() - started,
          aborted: false,
          spawnError: `spawn failed: ${error instanceof Error ? error.message : String(error)}`,
        })
        return
      }

      const finish = (exitCode: number | null, spawnError?: string, killedBySignal?: string) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        options.signal.removeEventListener('abort', onAbort)
        // Flush decoders: a tail partial sequence (killed process) surfaces
        // as replacement characters instead of silently vanishing bytes.
        output += stdoutDecoder.end() + stderrDecoder.end()
        resolve({
          exitCode,
          output: output.slice(0, maxChars),
          durationMs: Date.now() - started,
          aborted,
          ...(spawnError !== undefined ? { spawnError } : {}),
          // Signal deaths NOT caused by this port's own abort/timeout — the
          // fact that separates an external kill from a timeout at the port
          // boundary. Windows never propagates signals; there it stays unset.
          ...(!aborted && killedBySignal !== undefined ? { killedBySignal } : {}),
        })
      }

      const onAbort = () => { aborted = true; killChild(child) }
      options.signal.addEventListener('abort', onAbort, { once: true })

      const timer = setTimeout(() => {
        timedOut = true
        killChild(child)
      }, Math.max(1, options.timeoutMs))

      // Always feed the decoders (their buffered partial bytes must not
      // desync), only stop appending once the capture cap is far exceeded.
      child.stdout?.on('data', (chunk: Buffer) => {
        const text = stdoutDecoder.write(chunk)
        if (output.length < maxChars * 2) output += text
      })
      child.stderr?.on('data', (chunk: Buffer) => {
        const text = stderrDecoder.write(chunk)
        if (output.length < maxChars * 2) output += text
      })
      child.on('error', (error: NodeJS.ErrnoException) => {
        finish(null, `spawn failed: ${error.code ?? error.message}`)
      })
      child.on('close', (code: number | null, signal: string | null) => {
        if (timedOut && code === null) {
          finish(null, `timed out after ${options.timeoutMs}ms`)
          return
        }
        // `signal` is the child's own signalCode at exit time, surfaced
        // verbatim: how the process died is a fact the port must carry.
        finish(code, undefined, signal ?? undefined)
      })
    })
  }
}

function killChild(child: ReturnType<typeof spawn>): void {
  try {
    child.kill('SIGTERM')
    setTimeout(() => { try { child.kill('SIGKILL') } catch { /* already gone */ } }, 2_000).unref()
  } catch { /* already gone */ }
}

/**
 * Distinguishes concurrent temp files inside ONE process: `${pid}` alone let
 * two concurrent writers of the same target path (two verifications
 * refreshing the same anchor) share a temp name and clobber each other's
 * partial write between the write and the rename.
 */
let tempFileCounter = 0

function nextTempName(target: string): string {
  return `${target}.${process.pid}.${tempFileCounter++}.tmp`
}

/**
 * Windows concurrency wart on atomic writes: MoveFileEx replacing an
 * existing destination can fail EPERM/EBUSY/EACCES for the instants another
 * writer (another verification refreshing the same anchor) holds it. Unique
 * temp names removed the write-write collision; this bounded retry closes
 * the rename-rename one. Non-transient codes surface immediately, and the
 * orphan temp file is cleaned up on the way out so failed writes leave no
 * residue next to the target.
 */
async function renameReplacing(from: string, to: string): Promise<void> {
  const transientCodes = new Set(['EPERM', 'EBUSY', 'EACCES'])
  for (let attempt = 0; ; attempt++) {
    try {
      await fsp.rename(from, to)
      return
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (!transientCodes.has(code ?? '') || attempt >= 9) {
        try { await fsp.unlink(from) } catch { /* nothing more to give back */ }
        throw error
      }
      await new Promise((r) => setTimeout(r, 5 * (attempt + 1)))
    }
  }
}

export class NodeFsPort implements FsPort {
  async readFile(filePath: string): Promise<string | undefined> {
    try {
      return await fsp.readFile(filePath, 'utf8')
    } catch {
      return undefined
    }
  }

  async readDir(dirPath: string): Promise<string[] | undefined> {
    try {
      return await fsp.readdir(dirPath)
    } catch {
      return undefined
    }
  }

  async stat(filePath: string): Promise<FileStat | undefined> {
    try {
      const st = await fsp.lstat(filePath)
      return {
        kind: st.isFile() ? 'file' : st.isDirectory() ? 'dir' : 'other',
        size: st.size,
        mtimeMs: st.mtimeMs,
      }
    } catch {
      return undefined
    }
  }

  async walk(root: string, options: WalkOptions = {}): Promise<string[]> {
    const ignore = new Set(options.ignoreDirs ?? [])
    const limit = options.limit ?? 20_000
    const out: string[] = []
    const visit = async (dir: string, prefix: string): Promise<void> => {
      if (out.length >= limit) return
      let entries: import('node:fs').Dirent[]
      try {
        entries = await fsp.readdir(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const entry of entries) {
        if (out.length >= limit) return
        if (entry.name.startsWith('.') && entry.name !== '.') continue
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name
        if (entry.isDirectory()) {
          if (ignore.has(entry.name)) continue
          await visit(path.join(dir, entry.name), rel)
        } else if (entry.isFile()) {
          out.push(rel)
        }
      }
    }
    await visit(root, '')
    return out.sort()
  }

  async appendLine(filePath: string, line: string): Promise<void> {
    await fsp.mkdir(path.dirname(filePath), { recursive: true })
    await fsp.appendFile(filePath, `${line}\n`, 'utf8')
  }

  async readLines(filePath: string): Promise<string[]> {
    try {
      const raw = await fsp.readFile(filePath, 'utf8')
      return raw.split('\n').filter(l => l.trim().length > 0)
    } catch {
      return []
    }
  }

  async writeFile(filePath: string, contents: string): Promise<void> {
    await fsp.mkdir(path.dirname(filePath), { recursive: true })
    const tmp = nextTempName(filePath)
    await fsp.writeFile(tmp, contents, 'utf8')
    await renameReplacing(tmp, filePath)
  }

  async mkdirp(dirPath: string): Promise<void> {
    await fsp.mkdir(dirPath, { recursive: true })
  }
}

/**
 * Ed25519 checkpoint signer whose key lives in a host-side directory the
 * agent's sandboxed tools cannot write to (default DSH_HOME, never the
 * workspace). The private key is created with owner-only permissions on
 * first use and never leaves the directory.
 *
 * The trust asymmetry this buys: the model can recompute every hash in the
 * evidence log, but only this key can produce the checkpoint signatures the
 * audit chain accepts.
 */
export class NodeEd25519Signer implements SignerPort {
  readonly keyId: string
  private readonly privateKeyPem: string
  private readonly publicKeyPem: string

  private constructor(privateKeyPem: string, publicKeyPem: string) {
    this.privateKeyPem = privateKeyPem
    this.publicKeyPem = publicKeyPem
    this.keyId = createHash('sha256').update(publicKeyPem, 'utf8').digest('hex').slice(0, 16)
  }

  /** Load the key from `dir`, creating it on first use. */
  static async load(dir: string): Promise<NodeEd25519Signer> {
    await fsp.mkdir(dir, { recursive: true })
    const privateKeyPath = path.join(dir, 'proof-signing-key.pem')
    const publicKeyPath = path.join(dir, 'proof-signing-key.pub.pem')
    let privatePem: string
    try {
      privatePem = await fsp.readFile(privateKeyPath, 'utf8')
    } catch {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519')
      privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
      const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
      // Write the private half first (atomic temp+rename, owner-only) so a
      // crash never leaves a public half without its private counterpart.
      const privateTmp = nextTempName(privateKeyPath)
      await fsp.writeFile(privateTmp, privatePem, { mode: 0o600 })
      await renameReplacing(privateTmp, privateKeyPath)
      await fsp.writeFile(publicKeyPath, publicPem, { mode: 0o644 })
    }
    let publicPem: string
    try {
      publicPem = await fsp.readFile(publicKeyPath, 'utf8')
    } catch {
      // Key exists but the public half is missing: derive it from the private key.
      publicPem = createPublicKey(createPrivateKey(privatePem)).export({ type: 'spki', format: 'pem' }) as string
      await fsp.writeFile(publicKeyPath, publicPem, { mode: 0o644 })
    }
    return new NodeEd25519Signer(privatePem, publicPem)
  }

  async sign(data: string): Promise<string> {
    const key = createPrivateKey(this.privateKeyPem)
    return edSign(null, Buffer.from(data, 'utf8'), key).toString('base64')
  }

  async verify(data: string, signature: string): Promise<boolean> {
    try {
      const key = createPublicKey(this.publicKeyPem)
      return edVerify(null, Buffer.from(data, 'utf8'), key, Buffer.from(signature, 'base64'))
    } catch {
      return false
    }
  }
}

/**
 * Parses `git status --porcelain -z` output into the set of paths it mentions.
 *
 * The `-z` stream is a sequence of NUL-terminated fields. Each entry begins
 * with a status field `XY <path>` (two status letters, a space, the path);
 * when the status contains `R` (rename) or `C` (copy) the ORIGINAL path
 * follows as a second bare field with no prefix — both halves are workspace
 * facts, so both are collected. Paths are emitted verbatim (`-z` performs no
 * C-quoting, so `sp ace.ts` arrives unquoted).
 *
 * Tolerant by design: a field without a status prefix (truncated or garbage
 * stream) is kept verbatim rather than dropped — dirtiness must never be
 * under-reported.
 */
export function parsePorcelainZ(output: string): string[] {
  const fields = output.split('\0')
  const paths: string[] = []
  for (let i = 0; i < fields.length; i++) {
    const field = fields[i]
    if (field === undefined || field.length === 0) continue
    if (field.length >= 3 && field.charCodeAt(2) === 0x20 /* space */) {
      // Status field: 'XY <new-path>', possibly followed by the old path.
      const newPath = field.slice(3)
      if (newPath.length > 0) paths.push(newPath)
      const status = field.slice(0, 2)
      if (status.includes('R') || status.includes('C')) {
        const oldPath = fields[++i]
        if (oldPath !== undefined && oldPath.length > 0) paths.push(oldPath)
      }
    } else {
      paths.push(field)
    }
  }
  return paths.sort()
}

/** Git-backed workspace facts. Degrades to "unknown" outside a work tree. */
export class GitWorkspace implements WorkspacePort {
  readonly root: string
  private readonly commands: CommandPort
  /** Cached availability probe: git usability does not flip mid-process. */
  private gitAvailablePromise: Promise<boolean> | undefined

  constructor(root: string, commands: CommandPort = new NodeCommandPort(), clock: Clock = new SystemClock()) {
    this.root = root
    this.commands = commands
    void clock
  }

  /**
   * Whether git can answer questions about this workspace at all — the binary
   * is present AND the root sits inside a work tree (E3). Probed once and
   * remembered: availability cannot flip while the process lives, and every
   * re-probe on a git-less host would burn the 5s timeout again.
   *
   * `--is-inside-work-tree` exits non-zero outside any repository, but exits
   * ZERO with "false" inside a bare one — so the output is checked too, not
   * just the exit code, or a bare repo would pass as verifiable.
   */
  gitAvailable(): Promise<boolean> {
    this.gitAvailablePromise ??= this.commands
      .run(['git', 'rev-parse', '--is-inside-work-tree'], {
        cwd: this.root, timeoutMs: 5_000, signal: AbortSignal.timeout(5_000),
      })
      .then(
        result => result.exitCode === 0 && result.output.trim() === 'true',
        () => false, // a probe that cannot even run is not an availability proof
      )
    return this.gitAvailablePromise
  }

  async gitHead(): Promise<string | null> {
    const result = await this.commands.run(['git', 'rev-parse', 'HEAD'], {
      cwd: this.root, timeoutMs: 5_000, signal: AbortSignal.timeout(5_000),
    })
    return result.exitCode === 0 ? result.output.trim() || null : null
  }

  async gitDirty(): Promise<string[]> {
    const result = await this.commands.run(['git', 'status', '--porcelain', '-z'], {
      cwd: this.root, timeoutMs: 10_000, signal: AbortSignal.timeout(10_000),
    })
    if (result.exitCode !== 0) return []
    // Both ends of a rename/copy are workspace facts — see parsePorcelainZ.
    return parsePorcelainZ(result.output)
  }

  /**
   * Files modified since `ref`, relative to root — the session's change set.
   *
   * `git diff --name-only -z` emits a plain NUL-separated path list: every
   * path terminated by NUL, no status prefixes, no rename pairing, no
   * quoting — so `split('\0')` + dropping empty strings is the exact inverse.
   */
  async changedSince(ref: string): Promise<string[]> {
    const result = await this.commands.run(['git', 'diff', '--name-only', '-z', ref], {
      cwd: this.root, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
    })
    if (result.exitCode !== 0) return []
    return result.output.split('\0').filter(Boolean).sort()
  }

  /**
   * Untracked files (honouring .gitignore), relative to root.
   *
   * `git ls-files --others --exclude-standard -z` also emits a plain
   * NUL-separated path list (no prefixes, no quoting), so `split('\0')` +
   * dropping empty strings parses it exactly.
   */
  async untracked(): Promise<string[]> {
    const result = await this.commands.run(['git', 'ls-files', '--others', '--exclude-standard', '-z'], {
      cwd: this.root, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
    })
    if (result.exitCode !== 0) return []
    return result.output.split('\0').filter(Boolean).sort()
  }
}
