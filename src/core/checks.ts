/**
 * Objective check discovery.
 *
 * A "check" is a claim the *workspace itself* can answer: run this command and
 * look at the exit code. The agent never gets to define what counts as passing
 * — that is the whole point. Discovery reads the project's own build metadata
 * and turns it into `CheckSpec`s; explicit user configuration always wins.
 *
 * @module dsh-proof/core/checks
 */

import type { CheckKind, CheckSpec, CheckSource, FsPort } from './ports.ts'
import { sha256 } from './hash.ts'

/** Explicit override supplied through plugin configuration. */
export interface CheckConfigEntry {
  /** Human label. Defaults to the command. */
  label?: string
  /** argv vector, or a shell string which is split on whitespace. */
  command: string | readonly string[]
  kind?: CheckKind
  /**
   * Path prefixes this check covers. Defaults to `['*']` (always affected).
   * Use this to make incremental verification cheap and precise.
   */
  paths?: readonly string[]
  timeoutMs?: number
  /** Skip auto-discovery entirely and use only `checks`. */
  exclusive?: boolean
}

export interface DiscoverOptions {
  /** Explicit entries, always merged (and `exclusive` disables auto-discovery). */
  readonly checks?: readonly CheckConfigEntry[]
  /** Per-check timeout default. */
  readonly timeoutMs?: number
  /** Names of package.json scripts considered verifiable. */
  readonly scriptKinds?: Readonly<Record<string, CheckKind>>
}

const DEFAULT_SCRIPT_KINDS: Record<string, CheckKind> = {
  test: 'test',
  'test:unit': 'test',
  'test:int': 'test',
  'test:e2e': 'test',
  'test:ci': 'test',
  check: 'other',
  verify: 'other',
  build: 'build',
  compile: 'build',
  typecheck: 'typecheck',
  'type-check': 'typecheck',
  tsc: 'typecheck',
  lint: 'lint',
  'lint:check': 'lint',
  'lint:ci': 'lint',
  stylelint: 'lint',
  eslint: 'lint',
}

const DEFAULT_IGNORE_DIRS = [
  'node_modules', '.git', 'dist', 'build', 'out', 'target', 'coverage',
  '.next', '.nuxt', '.output', '.cache', '.venv', 'venv', '__pycache__',
  '.pytest_cache', '.mypy_cache', '.ruff_cache', 'vendor', '.turbo', '.proof',
  'tmp', '.openclaw',
]

/** Discover every objective check the workspace declares. */
export async function discoverChecks(fs: FsPort, root: string, options: DiscoverOptions = {}): Promise<CheckSpec[]> {
  const timeoutMs = options.timeoutMs ?? 120_000
  const scriptKinds = { ...DEFAULT_SCRIPT_KINDS, ...(options.scriptKinds ?? {}) }
  const found: CheckSpec[] = []
  const push = (spec: Omit<CheckSpec, 'id' | 'timeoutMs'> & { timeoutMs?: number }) => {
    found.push({
      ...spec,
      id: checkId(spec.source, spec.command, spec.cwd),
      timeoutMs: spec.timeoutMs ?? timeoutMs,
    })
  }

  const explicit = options.checks ?? []
  for (const entry of explicit) {
    const argv = toArray(entry.command)
    push({
      label: entry.label ?? argv.join(' '),
      command: argv,
      kind: entry.kind ?? 'other',
      source: 'config',
      paths: entry.paths ?? ['*'],
      ...(entry.timeoutMs !== undefined ? { timeoutMs: entry.timeoutMs } : {}),
    })
  }
  if (explicit.some(e => e.exclusive)) return dedupe(found)

  // ---- Node / JS / TS -------------------------------------------------
  const pkgRaw = await fs.readFile(join(root, 'package.json'))
  if (pkgRaw !== undefined) {
    const pkg = parseJson(pkgRaw)
    if (pkg) {
      const scripts = (pkg.scripts ?? {}) as Record<string, unknown>
      const workspaces = await expandWorkspacePatterns(fs, root, collectWorkspaceDirs(pkg))
      for (const [name, value] of Object.entries(scripts)) {
        if (typeof value !== 'string') continue
        const kind = scriptKinds[name]
        if (!kind) continue
        // npm folds `pre<script>`/`post<script>` into the run of `<script>`
        // itself — but only when that base script exists. Names that merely
        // *start with* the letters (prettier, postcss, prepare) are ordinary
        // scripts and must survive discovery.
        if (isHookScript(name, scripts)) continue
        const argv = packageScriptArgv(pkg, name, value)
        push({
          label: `npm script "${name}"`,
          command: argv,
          kind,
          source: 'package.json',
          paths: workspacePaths(root, workspaces),
        })
      }
      // Recursive discovery for pnpm/npm workspace members. The argv is
      // deliberately identical to the root's (`npm run` is the one invocation
      // that resolves `node_modules/.bin` under every manager); what separates
      // a subpackage check from the root's is `cwd` — it executes in the
      // member directory, gets its own id, and only expires on its own paths.
      for (const dir of workspaces) {
        const childRaw = await fs.readFile(join(root, dir, 'package.json'))
        const child = childRaw === undefined ? undefined : parseJson(childRaw)
        if (!child) continue
        const childScripts = (child.scripts ?? {}) as Record<string, unknown>
        for (const [name, value] of Object.entries(childScripts)) {
          if (typeof value !== 'string') continue
          const kind = scriptKinds[name]
          if (!kind) continue
          if (isHookScript(name, childScripts)) continue
          push({
            label: `npm script "${name}" (${dir})`,
            command: packageScriptArgv(child, name, value),
            kind,
            source: 'package.json',
            paths: [`${dir}/**`],
            cwd: dir,
          })
        }
      }
    }
  }

  // ---- Python ---------------------------------------------------------
  const pyRaw = await fs.readFile(join(root, 'pyproject.toml'))
  // pytest is discoverable through either file; a bare pytest.ini must not be
  // invisible just because the project never grew a pyproject.toml. The source
  // stays 'pyproject.toml' so already-minted pytest ids keep addressing.
  const hasPytestConfig = (pyRaw !== undefined && /(^|\n)\s*\[tool\.pytest/.test(pyRaw))
    || (await fs.readFile(join(root, 'pytest.ini'))) !== undefined
  if (hasPytestConfig) {
    push({ label: 'pytest', command: pythonRunner(root, ['pytest', '-q']), kind: 'test', source: 'pyproject.toml', paths: ['*'] })
  }
  if (pyRaw !== undefined) {
    if (/(^|\n)\s*\[tool\.mypy/.test(pyRaw)) {
      push({ label: 'mypy', command: pythonRunner(root, ['mypy', '.']), kind: 'typecheck', source: 'pyproject.toml', paths: ['*'] })
    }
    if (/(^|\n)\s*\[tool\.ruff/.test(pyRaw)) {
      push({ label: 'ruff check', command: pythonRunner(root, ['ruff', 'check', '.']), kind: 'lint', source: 'pyproject.toml', paths: ['*'] })
    }
  }
  if ((await fs.readFile(join(root, 'tox.ini'))) !== undefined) {
    push({ label: 'tox', command: pythonRunner(root, ['tox', '-q']), kind: 'test', source: 'tox.ini', paths: ['*'] })
  }

  // ---- Go -------------------------------------------------------------
  if ((await fs.readFile(join(root, 'go.mod'))) !== undefined) {
    push({ label: 'go build', command: ['go', 'build', './...'], kind: 'build', source: 'go.mod', paths: ['*'] })
    push({ label: 'go vet', command: ['go', 'vet', './...'], kind: 'lint', source: 'go.mod', paths: ['*'] })
    push({ label: 'go test', command: ['go', 'test', './...'], kind: 'test', source: 'go.mod', paths: ['*'] })
  }

  // ---- Rust -----------------------------------------------------------
  const cargoRaw = await fs.readFile(join(root, 'Cargo.toml'))
  if (cargoRaw !== undefined) {
    push({ label: 'cargo check', command: ['cargo', 'check', '--all-targets'], kind: 'build', source: 'Cargo.toml', paths: ['*'] })
    push({ label: 'cargo test', command: ['cargo', 'test'], kind: 'test', source: 'Cargo.toml', paths: ['*'] })
    if (/(^|\n)\s*clippy/.test(cargoRaw) || (await fs.readFile(join(root, 'clippy.toml'))) !== undefined) {
      push({ label: 'cargo clippy', command: ['cargo', 'clippy', '--all-targets', '--', '-D', 'warnings'], kind: 'lint', source: 'Cargo.toml', paths: ['*'] })
    }
  }

  // ---- Make -----------------------------------------------------------
  const makeRaw = await fs.readFile(join(root, 'Makefile'))
  if (makeRaw !== undefined) {
    for (const target of parseMakeTargets(makeRaw)) {
      const kind: CheckKind = target === 'test' || target === 'check' ? 'test'
        : target === 'build' || target === 'all' ? 'build'
          : target === 'lint' ? 'lint' : 'other'
      push({ label: `make ${target}`, command: ['make', target], kind, source: 'Makefile', paths: ['*'] })
    }
  }

  // ---- PHP ------------------------------------------------------------
  const composerRaw = await fs.readFile(join(root, 'composer.json'))
  if (composerRaw !== undefined) {
    const composer = parseJson(composerRaw)
    const scripts = (composer?.scripts ?? {}) as Record<string, unknown>
    for (const name of ['test', 'phpunit', 'phpstan', 'psalm']) {
      if (typeof scripts[name] === 'string') {
        push({ label: `composer ${name}`, command: ['composer', name], kind: name === 'test' || name === 'phpunit' ? 'test' : 'typecheck', source: 'composer.json', paths: ['*'] })
      }
    }
  }

  return dedupe(found)
}

/** Stable check identity: the discovery source plus the exact command. */
export function checkId(source: CheckSource, command: readonly string[], cwd?: string): string {
  // `cwd` joins the hash material only when present, so ids minted before the
  // field existed (every root-dir check) stay byte-identical and the baselines
  // addressing them keep verifying. Monorepo siblings share argv but not cwd,
  // which is exactly what separates their identities.
  const material = cwd === undefined ? command.join('\u0000') : `${command.join('\u0000')}\u0000${cwd}`
  return `${source}:${sha256(material).slice(0, 12)}`
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function toArray(command: string | readonly string[]): string[] {
  return typeof command === 'string' ? command.split(/\s+/).filter(Boolean) : [...command]
}

function join(root: string, ...parts: string[]): string {
  return `${root.replace(/\/+$/, '')}/${parts.filter(Boolean).join('/')}`
}

function parseJson(raw: string): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(raw) as unknown
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined
  } catch {
    return undefined
  }
}

/**
 * Workspace member patterns as declared: literals (`apps/web`) and globs
 * (`packages/*`, `packages/**`) alike. Expansion against the real filesystem
 * happens in `expandWorkspacePatterns`; keeping them raw here is what lets
 * single-level globs reach their subpackages at all.
 */
function collectWorkspaceDirs(pkg: Record<string, unknown>): string[] {
  const out = new Set<string>()
  const add = (pattern: unknown) => {
    if (typeof pattern !== 'string') return
    const normalized = pattern.replace(/\/+$/, '')
    if (normalized.length > 0) out.add(normalized)
  }
  if (Array.isArray(pkg.workspaces)) pkg.workspaces.forEach(add)
  else if (pkg.workspaces && typeof pkg.workspaces === 'object') {
    const w = pkg.workspaces as { packages?: unknown }
    if (Array.isArray(w.packages)) w.packages.forEach(add)
  }
  return [...out]
}

/**
 * Resolve workspace patterns to concrete member directories. Single-level
 * globs (`packages/*`, `packages/**`) are expanded by listing the parent
 * directory and keeping every child that owns a package.json — without this,
 * the most common monorepo layout silently discovers nothing. Deeper or
 * unrecognised globs degrade to their literal prefix, which the caller's
 * package.json probe then filters. Missing directories yield nothing: there
 * are no members to lose.
 */
async function expandWorkspacePatterns(fs: FsPort, root: string, patterns: readonly string[]): Promise<string[]> {
  const out = new Set<string>()
  for (const pattern of patterns) {
    if (!/[*?]/.test(pattern)) { out.add(pattern); continue }
    const segments = pattern.split('/')
    const globIndex = segments.findIndex(s => /[*?]/.test(s))
    const deeper = globIndex >= 0 && segments.slice(globIndex + 1).some(s => /[*?]/.test(s))
    if (globIndex < 0 || deeper) {
      out.add(pattern.replace(/\/?\*.*$/, '').replace(/\/+$/, ''))
      continue
    }
    const parent = segments.slice(0, globIndex).join('/')
    const names = await fs.readDir(join(root, parent))
    if (names === undefined) continue
    for (const name of names) {
      const dir = parent === '' ? name : `${parent}/${name}`
      // Only package.json-owning children are workspace members.
      if ((await fs.readFile(join(root, dir, 'package.json'))) !== undefined) out.add(dir)
    }
  }
  return [...out]
}

/**
 * npm hook semantics: `name` is a lifecycle hook only when stripping its
 * `pre`/`post` prefix leaves a script the same package actually declares.
 * A bare `pre`/`post` prefix (prettier, postcss, prepare) is just a name.
 */
function isHookScript(name: string, scripts: Record<string, unknown>): boolean {
  for (const prefix of ['pre', 'post']) {
    if (!name.startsWith(prefix)) continue
    const base = name.slice(prefix.length)
    if (base.length > 0 && typeof scripts[base] === 'string') return true
  }
  return false
}

function workspacePaths(root: string, dirs: string[]): string[] {
  if (dirs.length === 0) return ['*']
  return ['*', ...dirs.map(d => `${d}/**`)]
}

/** How npm runs a script without a `run` prefix, pinned to the local binary. */
function packageScriptArgv(pkg: Record<string, unknown>, name: string, _value: string): string[] {
  const hasPnpmLock = false // argv stays package-manager agnostic on purpose.
  void hasPnpmLock
  void pkg
  void name
  // `npm run <name>` is the only invocation that resolves `node_modules/.bin`
  // consistently across npm/pnpm/yarn, and it is what the project documents.
  return ['npm', 'run', '--silent', name]
}

function pythonRunner(root: string, argv: string[]): string[] {
  void root
  return argv
}

function parseMakeTargets(makefile: string): string[] {
  const targets: string[] = []
  for (const line of makefile.split('\n')) {
    const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)/.exec(line)
    if (!m) continue
    const name = m[1]
    if (name === undefined) continue
    if (name === 'all' || name === 'test' || name === 'check' || name === 'build' || name === 'lint' || name === 'verify') {
      targets.push(name)
    }
  }
  return [...new Set(targets)]
}

function dedupe(specs: CheckSpec[]): CheckSpec[] {
  const seen = new Map<string, CheckSpec>()
  for (const spec of specs) if (!seen.has(spec.id)) seen.set(spec.id, spec)
  return [...seen.values()]
}

export { DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS }
