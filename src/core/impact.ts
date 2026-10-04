/**
 * Change-impact analysis: from "these files changed" to "these checks are now
 * stale" — through a reverse-dependency closure, not a guess.
 *
 * Why this matters: running every check after every edit is how agent sessions
 * burn minutes and money; running no check is how "I fixed it" turns into a
 * broken main branch. The closure gives a *sound* middle ground: a check is
 * re-run whenever something it transitively depends on moved.
 *
 * @module dsh-proof/core/impact
 */

import type { CheckSpec, FsPort } from './ports.ts'

/** A file path relative to the workspace root, using `/` separators. */
export type RelPath = string

/** Adjacency: file -> files it directly depends on. */
export interface DependencyGraph {
  readonly nodes: ReadonlySet<RelPath>
  /** module -> importing modules (reverse edges), for cheap closure walks. */
  readonly dependents: ReadonlyMap<RelPath, ReadonlySet<RelPath>>
  /** How many files were scanned; surfaced in reports so limits are visible. */
  readonly scanned: number
  readonly truncated: boolean
}

export interface BuildGraphOptions {
  readonly limit?: number
  readonly ignoreDirs?: readonly string[]
}

const SOURCE_EXT = /\.(m|c)?(j|t)sx?$|\.py$|\.go$|\.rs$|\.java$|\.kt$|\.rb$|\.php$|\.cs$/

/** Files whose change invalidates every check, regardless of path filters. */
export const GLOBAL_INVALIDATORS: readonly RegExp[] = [
  /(^|\/)package\.json$/,
  /(^|\/)package-lock\.json$/,
  /(^|\/)npm-shrinkwrap\.json$/,
  /(^|\/)pnpm-lock\.ya?ml$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)bun\.lockb?$/,
  /(^|\/)tsconfig(\.[\w.-]+)?\.json$/,
  /(^|\/)pyproject\.toml$/,
  /(^|\/)poetry\.lock$/,
  /(^|\/)requirements[^/]*\.txt$/,
  /(^|\/)Pipfile(\.lock)?$/,
  /(^|\/)Cargo\.(toml|lock)$/,
  /(^|\/)go\.(mod|sum)$/,
  /(^|\/)Makefile$/,
  /(^|\/)CMakeLists\.txt$/,
  /(^|\/)composer\.(json|lock)$/,
  /(^|\/)Gemfile(\.lock)?$/,
  /(^|\/)\.github\/workflows\//,
  /(^|\/)Dockerfile(\..*)?$/,
  /(^|\/)\.eslintrc(\..*)?$/,
  /(^|\/)eslint\.config\.(m|c)?js$/,
  /(^|\/)vitest\.config\.(m|c)?(j|t)s$/,
  /(^|\/)jest\.config\.(m|c)?(j|t)s$/,
]

export function isGlobalInvalidator(path: RelPath): boolean {
  return GLOBAL_INVALIDATORS.some(re => re.test(path))
}

/**
 * Build a reverse-dependency graph from the workspace's source files.
 *
 * Import resolution is deliberately *approximate*: relative specifiers are
 * resolved against the filesystem, bare specifiers are ignored (they are
 * external dependencies, already covered by the lockfile rules). Approximation
 * errs toward over-inclusion, which costs a re-run and never hides a break.
 */
export async function buildDependencyGraph(
  fs: FsPort,
  root: string,
  files: readonly RelPath[],
  options: BuildGraphOptions = {},
): Promise<DependencyGraph> {
  const limit = options.limit ?? 20_000
  const ignore = new Set(options.ignoreDirs ?? [])
  const scannedFiles = files.filter(f => SOURCE_EXT.test(f) && !isIgnored(f, ignore)).slice(0, limit)
  const truncated = files.filter(f => SOURCE_EXT.test(f) && !isIgnored(f, ignore)).length > limit

  const known = new Set(scannedFiles)
  const dependents = new Map<RelPath, Set<RelPath>>()
  const ensure = (node: RelPath) => {
    let set = dependents.get(node)
    if (!set) { set = new Set(); dependents.set(node, set) }
    return set
  }
  for (const f of scannedFiles) ensure(f)

  for (const file of scannedFiles) {
    const content = await fs.readFile(`${root}/${file}`)
    if (content === undefined) continue
    for (const spec of extractImports(content)) {
      const resolved = resolveSpecifier(file, spec, known)
      if (resolved === undefined) continue
      ensure(resolved).add(file)
    }
  }

  return { nodes: new Set(scannedFiles), dependents, scanned: scannedFiles.length, truncated }
}

/**
 * Every file transitively affected by `changed`: the changed set itself, plus
 * all files that (transitively) import something in it.
 */
export function impactClosure(graph: DependencyGraph, changed: readonly RelPath[]): Set<RelPath> {
  const affected = new Set<RelPath>()
  const queue: RelPath[] = []
  for (const file of changed) {
    if (!affected.has(file)) { affected.add(file); queue.push(file) }
  }
  while (queue.length > 0) {
    const current = queue.pop() as RelPath
    for (const dependent of graph.dependents.get(current) ?? []) {
      if (!affected.has(dependent)) { affected.add(dependent); queue.push(dependent) }
    }
  }
  return affected
}

export interface SelectionResult {
  /** Checks whose impact set intersects the change closure. */
  readonly affected: CheckSpec[]
  /** Checks proven untouched by this change set. */
  readonly untouched: CheckSpec[]
  /** True when a global invalidator was present, forcing every check to run. */
  readonly forcedAll: boolean
  /** The closure actually used for the decision (for reporting). */
  readonly closure: readonly RelPath[]
  /** True when the dependency graph could not cover every changed file. */
  readonly uncertain: boolean
}

/**
 * Select the checks a change set makes stale. Conservative by construction:
 * uncertainty (unknown file types, truncated graphs, missing path filters)
 * widens the selection rather than narrowing it.
 */
export function selectAffectedChecks(
  checks: readonly CheckSpec[],
  changed: readonly RelPath[],
  graph?: DependencyGraph,
): SelectionResult {
  const forcedAll = changed.some(isGlobalInvalidator)
  const closure = graph ? [...impactClosure(graph, changed)].sort() : [...new Set(changed)].sort()
  const uncertain = graph === undefined || graph.truncated
    || changed.some(f => graph !== undefined && !graph.nodes.has(f) && SOURCE_EXT.test(f))

  if (forcedAll) {
    return { affected: [...checks], untouched: [], forcedAll, closure, uncertain }
  }

  const affected: CheckSpec[] = []
  const untouched: CheckSpec[] = []
  for (const check of checks) {
    if (check.paths.includes('*') || uncertain) { affected.push(check); continue }
    const hit = closure.some(file => matchesAny(file, check.paths))
    ;(hit ? affected : untouched).push(check)
  }
  return { affected, untouched, forcedAll, closure, uncertain }
}

/**
 * Map each changed file to the checks it invalidates — the attribution table
 * used when a regression needs an owner.
 */
export function attributeChange(
  checks: readonly CheckSpec[],
  changed: readonly RelPath[],
  graph?: DependencyGraph,
): Map<string, string[]> {
  const closure = graph ? impactClosure(graph, changed) : new Set(changed)
  const table = new Map<string, string[]>()
  for (const file of changed) {
    const owners: string[] = []
    const reachable = graph ? transitiveDependents(graph, file) : new Set<RelPath>()
    reachable.add(file)
    for (const check of checks) {
      const hit = check.paths.includes('*')
        || [...reachable].some(p => matchesAny(p, check.paths))
        || closure.has(file) && matchesAny(file, check.paths)
      if (hit) owners.push(check.id)
    }
    table.set(file, owners)
  }
  return table
}

function transitiveDependents(graph: DependencyGraph, file: RelPath): Set<RelPath> {
  const out = new Set<RelPath>()
  const queue = [file]
  while (queue.length > 0) {
    const current = queue.pop() as RelPath
    for (const dep of graph.dependents.get(current) ?? []) {
      if (!out.has(dep)) { out.add(dep); queue.push(dep) }
    }
  }
  return out
}

/** `src/foo/**` and `src/foo` both match `src/foo/bar.ts`. `*` matches everything. */
export function matchesAny(file: RelPath, patterns: readonly string[]): boolean {
  return patterns.some(pattern => matches(file, pattern))
}

export function matches(file: RelPath, pattern: string): boolean {
  if (pattern === '*') return true
  const normalized = pattern.replace(/\/+$/, '')
  if (normalized.endsWith('/**')) {
    const prefix = normalized.slice(0, -3)
    return file === prefix || file.startsWith(`${prefix}/`)
  }
  if (normalized.endsWith('/*')) {
    const prefix = normalized.slice(0, -2)
    return file.startsWith(`${prefix}/`) && !file.slice(prefix.length + 1).includes('/')
  }
  return file === normalized || file.startsWith(`${normalized}/`)
}

function isIgnored(file: RelPath, ignore: ReadonlySet<string>): boolean {
  return file.split('/').some(segment => ignore.has(segment))
}

/**
 * Pull workspace-reachable module specifiers out of source text.
 *
 * Line-based rather than one heroic regex: ESM/CJS `import`/`export ... from`,
 * bare side-effect `import '...'`, `require('...')`, and Python `from x.y import`.
 * Bare package names and `node:` builtins are dropped — those are external
 * dependencies, already covered by the lockfile rules.
 */
export function extractImports(content: string): string[] {
  const out = new Set<string>()
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim()
    if (line.length === 0 || line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue

    // ESM: import ... from 'x' / export ... from 'x'
    const from = /(?:^|[;{}])\s*(?:import|export)\b[\s\S]*?\bfrom\s+['"]([^'"]+)['"]/.exec(line)
    if (from?.[1]) { add(out, from[1]); continue }

    // Side-effect: import 'x'
    const bare = /^import\s+['"]([^'"]+)['"]/.exec(line)
    if (bare?.[1]) { add(out, bare[1]); continue }

    // Python: from x.y import thing
    const py = /^from\s+([.\w][\w.]*)\s+import\b/.exec(line)
    if (py?.[1]) { add(out, py[1]); continue }

    // CJS: require('x') — searched anywhere in the line.
    const req = /require\(\s*['"]([^'"]+)['"]\s*\)/.exec(line)
    if (req?.[1]) add(out, req[1])
  }
  return [...out]
}

function add(into: Set<string>, specifier: string): void {
  const value = specifier.trim()
  if (value.length === 0) return
  // `node:fs`, `fs`, `@scope/pkg`, `lodash/get` are external.
  if (value.startsWith('node:')) return
  if (value.startsWith('.') || value.startsWith('/')) { into.add(value); return }
  // Python-style dotted module path: `pkg.mod` -> pkg/mod
  if (/^[A-Za-z_][\w]*(\.[\w_]+)+$/.test(value)) into.add(value)
}

function resolveSpecifier(from: RelPath, specifier: string, known: ReadonlySet<RelPath>): RelPath | undefined {
  if (specifier.startsWith('.')) {
    const base = dirname(from)
    const joined = normalizePath(`${base}/${specifier}`)
    const candidates = [
      joined,
      `${joined}.ts`, `${joined}.tsx`, `${joined}.js`, `${joined}.jsx`, `${joined}.mjs`, `${joined}.cjs`,
      `${joined}/index.ts`, `${joined}/index.tsx`, `${joined}/index.js`, `${joined}/index.py`,
      `${joined}.py`, `${joined}.go`, `${joined}.rs`,
    ]
    for (const candidate of candidates) if (known.has(candidate)) return candidate
    return undefined
  }
  // Python-style absolute import: `from pkg.mod import x` -> pkg/mod.py or pkg/mod/__init__.py
  if (/^[\w.]+$/.test(specifier)) {
    const rel = specifier.replace(/\./g, '/')
    for (const candidate of [`${rel}.py`, `${rel}/__init__.py`]) if (known.has(candidate)) return candidate
  }
  return undefined
}

function dirname(path: RelPath): string {
  const idx = path.lastIndexOf('/')
  return idx < 0 ? '' : path.slice(0, idx)
}

function normalizePath(path: string): string {
  const segments: string[] = []
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') segments.pop()
    else segments.push(segment)
  }
  return segments.join('/')
}
