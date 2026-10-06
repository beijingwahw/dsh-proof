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

import type { CheckSpec, DefinitionResolverPort, FsPort } from './ports.ts'

/** A file path relative to the workspace root, using `/` separators. */
export type RelPath = string

/** How exact the impact analysis behind a selection is. */
export type SelectionPrecision = 'lsp-verified' | 'approximate' | 'forced'

/** Adjacency: file -> files it directly depends on. */
export interface DependencyGraph {
  readonly nodes: ReadonlySet<RelPath>
  /** module -> importing modules (reverse edges), for cheap closure walks. */
  readonly dependents: ReadonlyMap<RelPath, ReadonlySet<RelPath>>
  /** How many files were scanned; surfaced in reports so limits are visible. */
  readonly scanned: number
  readonly truncated: boolean
  /** Edges confirmed by the resolver, keyed `${dependent}\u0000${dependency}`. */
  readonly lspConfirmed: ReadonlySet<string>
  readonly precision: SelectionPrecision
}

export interface BuildGraphOptions {
  readonly limit?: number
  readonly ignoreDirs?: readonly string[]
  /** Optional LSP-backed resolver for precise, alias-aware edges. */
  readonly resolver?: DefinitionResolverPort
  /** Maximum resolver round-trips for one graph build (degrades beyond). */
  readonly lspQueryBudget?: number
  /**
   * M8: the caller's workspace walk (`FsPort.walk`) reported truncation — the
   * `files` list handed to this builder is a prefix of the workspace, so the
   * graph is incomplete for reasons THIS function cannot detect (its own
   * `limit` may never have fired). Propagated into `DependencyGraph.truncated`
   * so `selectAffectedChecks` degrades the selection to uncertain (all checks
   * run) instead of silently reasoning over a partial node set — a workspace
   * bigger than the walk limit used to produce a complete-looking graph that
   * never said it was partial.
   */
  readonly walkTruncated?: boolean
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
 * Two edge sources, fused conservatively:
 *
 * 1. *Approximate* — regex-extracted relative specifiers resolved against the
 *    filesystem. Always available; errs toward over-inclusion.
 * 2. *LSP-verified* — when a `resolver` is provided, every import site
 *    (relative AND bare/alias) is resolved through the language server's
 *    goToDefinition. This both confirms approximate edges and discovers
 *    workspace-internal edges regex cannot see (tsconfig `paths` aliases,
 *    package-internal imports) — real breakage blind spots in monorepos.
 *
 * Selection semantics never narrow: confirmed and approximate edges are
 * unioned; a failed or budget-exhausted resolver simply leaves the edge
 * approximate. `precision` reports which regime produced the graph.
 */
export async function buildDependencyGraph(
  fs: FsPort,
  root: string,
  files: readonly RelPath[],
  options: BuildGraphOptions = {},
): Promise<DependencyGraph> {
  const limit = options.limit ?? 20_000
  const ignore = new Set(options.ignoreDirs ?? [])
  const eligible = files.filter(f => SOURCE_EXT.test(f) && !isIgnored(f, ignore))
  const scannedFiles = eligible.slice(0, limit)
  // Truncation is the disjunction of BOTH causes: this builder's own scan
  // cap firing, or the caller's walk having stopped at its limit upstream
  // (M8 — the walk knows, the builder does not, so the caller must tell it).
  const truncated = eligible.length > limit || options.walkTruncated === true

  const known = new Set(scannedFiles)
  const dependents = new Map<RelPath, Set<RelPath>>()
  const ensure = (node: RelPath) => {
    let set = dependents.get(node)
    if (!set) { set = new Set(); dependents.set(node, set) }
    return set
  }
  for (const f of scannedFiles) ensure(f)

  const resolver = options.resolver
  const lspBudget = options.lspQueryBudget ?? 400
  let lspQueries = 0
  let lspConfirmedCount = 0
  const lspConfirmed = new Set<string>()

  for (const file of scannedFiles) {
    const content = await fs.readFile(`${root}/${file}`)
    if (content === undefined) continue
    for (const site of extractImportSites(content)) {
      // Approximate edges, by specifier kind:
      // - relative: resolve against the filesystem (the classic case).
      // - bare: only Python dotted modules (`from pkg.mod import x` arrives
      //   here because kindOf only recognises `.`/`/` prefixes) get a
      //   filesystem attempt. A dotted name that happens to collide with a
      //   scanned file can only add a spurious edge — over-selection, which
      //   the soundness constitution allows; a missed edge is what it forbids.
      const resolved = site.kind === 'relative'
        ? resolveSpecifier(file, site.specifier, known)
        : resolveBarePythonModule(site.specifier, known)
      if (resolved !== undefined) ensure(resolved).add(file)
      // Verified edge: ask the language server where this import actually
      // binds. `node:` builtins are external by contract; everything else
      // (bare aliases included) may resolve inside the workspace.
      if (resolver !== undefined && lspQueries < lspBudget && !site.specifier.startsWith('node:')) {
        lspQueries += 1
        const target = await resolver.resolveDefinition(file, site.line, site.character).catch(() => null)
        if (typeof target === 'string' && target.length > 0 && target !== file) {
          const normalized = target.replace(/\\/g, '/')
          ensure(normalized).add(file)
          const key = `${file}\u0000${normalized}`
          if (!lspConfirmed.has(key)) { lspConfirmed.add(key); lspConfirmedCount += 1 }
        }
      }
    }
  }

  return {
    nodes: new Set(scannedFiles),
    dependents,
    scanned: scannedFiles.length,
    truncated,
    lspConfirmed,
    precision: resolver !== undefined && lspConfirmedCount > 0 ? 'lsp-verified' : 'approximate',
  }
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
  /** Which edge regime produced the graph behind this selection. */
  readonly precision: SelectionPrecision
}

/**
 * The forced selection: every check affected, nothing untouched, precision
 * `forced`. Single source of truth for this shape — it is what
 * `selectAffectedChecks` returns on a global invalidator, and what the engine
 * (`verify` with `all`/degraded git facts) and the report (`forceAll`) reach
 * for when impact analysis is deliberately bypassed. Before this constructor
 * existed the same literal lived in three modules and had already begun to
 * drift; one factory keeps them byte-identical.
 *
 * `closure` is NOT an impact closure here — no graph was consulted (or none
 * was allowed to narrow the run). It carries the change set the forced
 * decision was made on, so reports and attribution still name the files that
 * triggered the full sweep. `uncertain` is `false` for the same reason: the
 * selection does not depend on graph coverage, so graph coverage cannot make
 * it uncertain; `precision: 'forced'` states exactly which regime produced it.
 */
export function forcedSelection(
  specs: readonly CheckSpec[],
  changed: readonly RelPath[],
): SelectionResult {
  return {
    affected: [...specs],
    untouched: [],
    forcedAll: true,
    closure: [...changed],
    uncertain: false,
    precision: 'forced',
  }
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
  const precision: SelectionPrecision = graph === undefined ? 'approximate' : graph.precision

  if (forcedAll) {
    return forcedSelection(checks, closure)
  }

  const affected: CheckSpec[] = []
  const untouched: CheckSpec[] = []
  for (const check of checks) {
    if (check.paths.includes('*') || uncertain) { affected.push(check); continue }
    const hit = closure.some(file => matchesAny(file, check.paths))
    ;(hit ? affected : untouched).push(check)
  }
  return { affected, untouched, forcedAll, closure, uncertain, precision }
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
  const table = new Map<string, string[]>()
  for (const file of changed) {
    const owners: string[] = []
    // `reachable` already contains `file` itself, so the per-file path match
    // needs no separate closure membership test.
    const reachable = graph ? transitiveDependents(graph, file) : new Set<RelPath>()
    reachable.add(file)
    for (const check of checks) {
      const hit = check.paths.includes('*')
        || [...reachable].some(p => matchesAny(p, check.paths))
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

// Whether a pattern uses glob metacharacters in a position the five-form
// matcher below does not interpret. The supported canon, exhaustively:
//
//   pattern shape            | matched how
//   -------------------------+----------------------------------------------
//   `*`                      | everything (wildcard-all)
//   `<literal>/**`           | `<literal>` itself and everything under it
//   `<literal>/*`            | direct children of `<literal>` only
//   `<literal>`              | exactly `<literal>` or anything under it
//
// `<literal>` must itself be metacharacter-free. EVERY other metacharacter-
// bearing shape is unsupported — the decision table, spelled per feature:
//
//   `?` anywhere                      e.g. `a?b.ts`            → unsupported
//   `[` or `]` (character class)      e.g. `[abc].ts`          → unsupported
//   `{` or `}` (brace group)          e.g. `{a,b}`             → unsupported
//   `**` NOT as the terminal          e.g. `src/` + `**` + `/*.ts`,
//                                      or a leading `**` prefix          → unsupported
//   `*` glued to other text           e.g. `src/*.ts`, `a*`               → unsupported
//   `*` in a supported terminal form  e.g. `src/**`, `src/*`, `*`         → supported
//   no metacharacter at all           e.g. `src/a.ts` (plain literal)     → supported
function isUnsupportedGlobShape(pattern: string): boolean {
  if (!/[*?[\]{}]/.test(pattern)) return false // plain literal — always supported
  if (pattern === '*') return false // wildcard-all — supported
  const doubleStar = /^(.*)\/\*\*$/.exec(pattern)
  if (doubleStar !== null) return hasGlobMeta(doubleStar[1] ?? '')
  const singleStar = /^(.*)\/\*$/.exec(pattern)
  if (singleStar !== null) return hasGlobMeta(singleStar[1] ?? '')
  return true
}

function hasGlobMeta(literal: string): boolean {
  return /[*?[\]{}]/.test(literal)
}

export function matches(file: RelPath, pattern: string): boolean {
  if (pattern === '*') return true
  const normalized = pattern.replace(/\/+$/, '')
  // M9 conservative fallback: a pattern that LOOKS like a glob but is not one
  // of the five supported shapes matches EVERYTHING. The old matcher silently
  // treated `src/**/*.ts` (or `a?b.ts`, or `{a,b}`) as a literal prefix — a
  // shape that matches no real file, so a check configured that way never ran:
  // a dead check wearing a live one's configuration. For a filter we cannot
  // interpret, over-inclusion (run the check) is the only sound direction;
  // under-inclusion manufactures false "untouched" verdicts.
  if (isUnsupportedGlobShape(normalized)) return true
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
 * One import site: a module specifier plus the 0-based UTF-16 position of its
 * first character — exactly where a language server's goToDefinition resolves
 * the module the statement binds to.
 */
export interface ImportSite {
  readonly specifier: string
  readonly line: number
  readonly character: number
  readonly kind: 'relative' | 'bare'
}

const SITE_ESM_FROM = /(?:^|[;{}])\s*(?:import|export)\b[^\n]*?\bfrom\s+(['"])([^'"]+)\1/d
const SITE_SIDE_EFFECT = /(?:^|[;{}])\s*import\s+(['"])([^'"]+)\1/d
const SITE_PYTHON = /^from\s+([.\w][\w.]*)\s+import\b/d
const SITE_REQUIRE = /require\(\s*(['"])([^'"]+)\1\s*\)/d
// Dynamic `import('...')`: lazy chunks are imports too, and code-split files
// break exactly like statically imported ones.
const SITE_DYNAMIC_IMPORT = /\bimport\s*\(\s*(['"])([^'"]+)\1\s*\)/d
// Multi-line ESM tail: `import {\n ...\n} from './x'` — the `from` lives on a
// line of its own that starts with `}`, invisible to SITE_ESM_FROM.
const SITE_MULTILINE_FROM = /^\s*\}\s*from\s+(['"])([^'"]+)\1/d

/** Pull every import site (specifier + cursor position) out of source text. */
export function extractImportSites(content: string): ImportSite[] {
  const out: ImportSite[] = []
  const lines = content.split('\n')
  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim()
    if (trimmed.length === 0 || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return
    for (const pattern of [SITE_ESM_FROM, SITE_SIDE_EFFECT, SITE_DYNAMIC_IMPORT, SITE_MULTILINE_FROM, SITE_REQUIRE]) {
      const match = pattern.exec(rawLine)
      const groups = match?.indices
      const start = groups?.[2]?.[0]
      const specifier = match?.[2]
      if (start !== undefined && specifier !== undefined) {
        out.push({ specifier, line: index, character: start, kind: kindOf(specifier) })
      }
    }
    const py = SITE_PYTHON.exec(trimmed)
    const pyStart = py?.indices?.[1]?.[0]
    if (pyStart !== undefined && py?.[1] !== undefined) {
      const indent = rawLine.length - rawLine.trimStart().length
      out.push({ specifier: py[1], line: index, character: pyStart + indent, kind: kindOf(py[1]) })
    }
  })
  return out
}

function kindOf(specifier: string): 'relative' | 'bare' {
  return specifier.startsWith('.') || specifier.startsWith('/') ? 'relative' : 'bare'
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
  for (const site of extractImportSites(content)) {
    add(out, site.specifier)
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
  if (!specifier.startsWith('.')) return undefined
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

/**
 * Python-style absolute import: `from pkg.mod import x` -> pkg/mod.py or
 * pkg/mod/__init__.py, but only when that target is genuinely in the scanned
 * set — the edge is added on proof of existence, never on speculation.
 * JS bare specifiers (`@scope/pkg`, `lodash/get`) fail the shape test and
 * stay external, as before.
 */
function resolveBarePythonModule(specifier: string, known: ReadonlySet<RelPath>): RelPath | undefined {
  if (!/^[\w.]+$/.test(specifier)) return undefined
  const rel = specifier.replace(/\./g, '/')
  for (const candidate of [`${rel}.py`, `${rel}/__init__.py`]) if (known.has(candidate)) return candidate
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
