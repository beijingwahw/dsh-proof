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
  run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
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

      const child = spawn(command, args, {
        cwd: options.cwd,
        env: { ...process.env, ...(options.env ?? {}), CI: '1', FORCE_COLOR: '0', NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      })

      const finish = (exitCode: number | null, spawnError?: string) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        options.signal.removeEventListener('abort', onAbort)
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

      child.stdout?.on('data', (chunk: Buffer) => { if (output.length < maxChars * 2) output += chunk.toString('utf8') })
      child.stderr?.on('data', (chunk: Buffer) => { if (output.length < maxChars * 2) output += chunk.toString('utf8') })
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

/** Git-backed workspace facts. Degrades to "unknown" outside a work tree. */
export class GitWorkspace implements WorkspacePort {
  readonly root: string
  private readonly commands: CommandPort

  constructor(root: string, commands: CommandPort = new NodeCommandPort(), clock: Clock = new SystemClock()) {
    this.root = root
    this.commands = commands
    void clock
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
    return result.output
      .split('\0')
      .map(entry => entry.slice(3).trim())
      .filter(Boolean)
      .sort()
  }

  /** Files modified since `ref`, relative to root — the session's change set. */
  async changedSince(ref: string): Promise<string[]> {
    const result = await this.commands.run(['git', 'diff', '--name-only', '-z', ref], {
      cwd: this.root, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
    })
    if (result.exitCode !== 0) return []
    return result.output.split('\0').filter(Boolean).sort()
  }
}
