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
import { existsSync, promises as fsp } from 'node:fs'
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
 * Windows: `npm` ships as an `.cmd` shim, which `spawn(shell: false)` cannot
 * execute. Rather than enabling a shell (an injection surface this port
 * refuses to open), rewrite well-known shims to `node <cli.js>` — still a
 * pure argv vector, still no string interpolation.
 */
function resolveWindowsArgv(argv: readonly string[]): string[] {
  const command = argv[0]
  if (command === undefined) return [...argv]
  const cli = command.toLowerCase() === 'npm' || command.toLowerCase() === 'npm.cmd'
    ? path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    : undefined
  if (cli !== undefined && existsSync(cli)) return [process.execPath, cli, ...argv.slice(1)]
  return [...argv]
}

/** Spawns argv vectors without a shell — no quoting games, no injection surface. */
export class NodeCommandPort implements CommandPort {
  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    // An already-aborted signal never fires its 'abort' listener, so checking
    // after spawn would let the child run until the timeout killed it.
    if (options.signal?.aborted) {
      return { exitCode: null, output: '', durationMs: 0, aborted: true }
    }
    const [command, ...args] = process.platform === 'win32' ? resolveWindowsArgv(argv) : [...argv]
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

      const child = spawn(command, args, {
        cwd: options.cwd,
        // Inherited environment first, deterministic color/CI defaults on
        // top of it, caller overlay last: hosts stay free to override when
        // they must, everything else gets deterministic output by default.
        env: { ...process.env, CI: '1', FORCE_COLOR: '0', NO_COLOR: '1', ...(options.env ?? {}) },
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      })

      const finish = (exitCode: number | null, spawnError?: string) => {
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
      child.on('close', (code: number | null) => {
        if (timedOut && code === null) {
          finish(null, `timed out after ${options.timeoutMs}ms`)
          return
        }
        finish(code)
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
    const tmp = `${filePath}.${process.pid}.tmp`
    await fsp.writeFile(tmp, contents, 'utf8')
    await fsp.rename(tmp, filePath)
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
      const privateTmp = `${privateKeyPath}.${process.pid}.tmp`
      await fsp.writeFile(privateTmp, privatePem, { mode: 0o600 })
      await fsp.rename(privateTmp, privateKeyPath)
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
