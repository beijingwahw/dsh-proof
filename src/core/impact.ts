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
      // - relative: resolve against the filesystem (the classic case). H-24:
      //   the resolver now counts LEADING DOTS the way Python does (`.mod` is
      //   a sibling in the source file's package, `..x` the parent package),
      //   instead of joining the dots as JS path segments — `pkg/.mod.py`
      //   never existed on any disk. JS relative specifiers resolve through
      //   the same dot arithmetic (their `.`/`..` semantics agree), plus the
      //   Python `__init__.py` candidates for mixed trees. X-H-17(b): a dot
      //   INSIDE the remainder is ambiguous across languages, so both
      //   readings are probed (see resolveSpecifier) and every hit adds its
      //   own edge — over-inclusion is the direction the constitution allows.
      // - bare: only Python dotted modules (`from pkg.mod import x`, bare
      //   `import pkg.mod`, and the name-list sites those mint) get a
      //   filesystem attempt. A dotted name that happens to collide with a
      //   scanned file can only add a spurious edge — over-selection, which
      //   the soundness constitution allows; a missed edge is what it forbids.
      if (site.kind === 'relative') {
        for (const target of resolveSpecifier(file, site.specifier, known)) ensure(target).add(file)
      } else {
        const target = resolveBarePythonModule(site.specifier, known)
        if (target !== undefined) ensure(target).add(file)
      }
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
  // M-26: a RelPath never begins with `./` or `/`, but users write both in
  // config (`paths: ['./src/**']` is the most natural spelling there is).
  // Normalising the PATTERN (not judging it unsupported) keeps the five-form
  // semantics while un-deathing the prefixed spellings — the old matcher
  // literal-compared `./src/` against `src/...` and never matched anything,
  // a dead check wearing a live one's configuration (the exact M9 failure,
  // resurrected through a leading dot). `/**`-under-prefix and `/*` and bare
  // literals all normalise the same way; an empty residue (pattern `./`)
  // matches nothing a user could mean, so it falls back to match-everything
  // like every other shape this matcher refuses to interpret.
  const normalized = pattern
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
  // W14-L9: wildcard-all is judged AFTER normalisation. `./*`, `/*` and `*/`
  // all normalise to `*` but used to fall through to the literal comparison
  // below (`file === '*'`) — dead for every file that exists, while their
  // empty-residue sibling `./` matched everything. Same-family spellings must
  // not be split between a live and a dead reading of the same intent.
  if (normalized.length === 0 || normalized === '*') return true
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

// H-24/M-28: the in-line patterns carry the `g` flag and are consumed through
// `matchAll` only — a direct `.exec` on a global regex would drag shared
// `lastIndex` state across lines and silently skip sites. `matchAll` clones,
// so one line yielding several sites (`import a from './b'; import c from './d'`)
// reports every specifier: the second edge used to be invisible, and a missed
// edge is the one direction the soundness constitution forbids.
const SITE_ESM_FROM = /(?:^|[;{}])\s*(?:import|export)\b[^\n]*?\bfrom\s+(['"])([^'"]+)\1/gd
const SITE_SIDE_EFFECT = /(?:^|[;{}])\s*import\s+(['"])([^'"]+)\1/gd
const SITE_REQUIRE = /require\(\s*(['"])([^'"]+)\1\s*\)/gd
// Dynamic `import('...')`: lazy chunks are imports too, and code-split files
// break exactly like statically imported ones.
const SITE_DYNAMIC_IMPORT = /\bimport\s*\(\s*(['"])([^'"]+)\1\s*\)/gd
// Multi-line ESM tail: `import {\n ...\n} from './x'` — the `from` lives on a
// line of its own that starts with `}`, invisible to SITE_ESM_FROM. Anchored,
// so at most one match per line and no `g` flag is needed.
const SITE_MULTILINE_FROM = /^\s*\}\s*from\s+(['"])([^'"]+)\1/d
// H-24: Python `from <module> import <names>` — module in group 1, the raw
// name list in group 2 (both for the `from pkg import mod` submodule edge,
// where the *name* is the dependency, not the package).
// L (V7-L2): the module group is NON-GREEDY and the separator before the
// `import` keyword is `\s*` (not `\s+`). `from .import x` — legal Python,
// no space after the dot-run — used to fail entirely: the greedy group ate
// `.import`, then required `\s+import` and backtracked into nothing, so the
// whole site (module AND names) was lost. Non-greedy growth stops at the
// first prefix after which the literal `import` follows, which for every
// valid statement is exactly the module's true end (`from .import x` →
// module `.`, `from pkg.mod import x` → module `pkg.mod`); a false early
// stop is only possible on invalid text (`from ximport y`), where the
// resulting spurious edge is the over-inclusion direction the constitution
// allows. Greedy behaviour on all previously matching inputs is unchanged.
const SITE_PYTHON = /^from\s+([.\w][\w.]*?)\s*import\s*([^#\n]*)/d
// H-24: bare Python `import pkg.mod [as m][, pkg2.mod2 as m2 ...]`. No JS
// statement has this shape (`import x from ...` needs `from`, side-effect
// imports quote), so treating it as a Python site can only over-include.
// Each comma segment is its own dependency statement; an `as` alias renames
// the binding, so the dotted head before it is the specifier; a trailing
// `# comment` is tolerated (`#` cannot occur inside a dotted name).
const SITE_PYTHON_BARE = /^import\s+((?:[.\w][\w.]*(?:\s+as\s+[\w.]+)?\s*,\s*)*[.\w][\w.]*(?:\s+as\s+[\w.]+)?)\s*(?:#.*)?$/d

/** Pull every import site (specifier + cursor position) out of source text. */
export function extractImportSites(content: string): ImportSite[] {
  const out: ImportSite[] = []
  const lines = content.split('\n')
  // W14-M5: a `from pkg import (` whose paren the line cannot close — the
  // black/isort formatting of any long name list. Until the paren closes,
  // every identifier on the continuation lines mints the same pkg/<name>.py
  // name edge the single-line form would have; before this state existed the
  // opening line yielded the package edge only and every listed name was
  // silently edgeless (the exact under-inclusion the constitution forbids).
  let pending: { readonly module: string; depth: number } | null = null
  // A continuation segment that is a plain (optionally aliased) name, plus
  // optional trailing comma/closer — anything else cannot mend the list.
  const NAME_TAIL = /^([\w.]+)(?:\s+as\s+[\w.]+)?\s*,?\s*\)*\s*$/
  const CLOSER_TAIL = /^[),\s]*$/
  // X-H-17(a)/Y-H-07: one concatenation for BOTH name-list readers (the
  // single-line capture below and the bracket-continuation reader), so the
  // dot-tail rule can never again be fixed on one path and forgotten on the
  // other — the single-line fix shipped while the continuation reader (added
  // the same version) kept minting `'.' + '.' + 'x'` = '..x', walking every
  // `from . import (\n x,\n)` name to the PARENT package. A module prefix
  // that already ends with the dot contributes no second dot.
  const joinDotted = (module: string, name: string): string =>
    module.endsWith('.') ? `${module}${name}` : `${module}.${name}`
  const parenDepth = (text: string): number => {
    const opens = text.match(/\(/g)?.length ?? 0
    const closes = text.match(/\)/g)?.length ?? 0
    return opens - closes
  }

  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim()
    const indent = rawLine.length - rawLine.trimStart().length
    if (pending !== null) {
      const state = pending
      // Comments are legal inside a parenthesised list; the `#` cut mirrors
      // SITE_PYTHON's name-list capture (`[^#\n]*`), which stops there too.
      const body = trimmed.split('#', 1)[0] ?? ''
      let cursor = 0
      for (const raw of body.split(',')) {
        const segment = raw.trim()
        if (segment.length > 0 && !CLOSER_TAIL.test(segment)) {
          const head = NAME_TAIL.exec(segment)
          if (head?.[1] !== undefined) {
            // Y-H-07: the continuation reader mints its specifier through the
            // SAME conditional join as the single-line path (joinDotted above)
            // — `from . import (\n x,\n)` names the SIBLING pkg/x.py, never
            // the parent package's x.py. Unconditional `'.'+'.'+'x'` here was
            // the exact X-H-17(a) off-by-one resurrected on the one spelling
            // (black/isort long name lists) that most needed the reader.
            const specifier = joinDotted(state.module, head[1])
            out.push({
              specifier,
              line: index,
              character: indent + cursor + (raw.length - raw.trimStart().length),
              kind: kindOf(specifier),
            })
          }
        }
        cursor += raw.length + 1
      }
      state.depth += parenDepth(body)
      if (state.depth <= 0) pending = null
    }
    if (trimmed.length === 0 || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return
    for (const pattern of [SITE_ESM_FROM, SITE_SIDE_EFFECT, SITE_DYNAMIC_IMPORT, SITE_MULTILINE_FROM, SITE_REQUIRE]) {
      // Global patterns report every in-line site; the anchored multi-line
      // tail form yields at most one — matchAll would reject it for lack of /g.
      const matches = pattern.global ? rawLine.matchAll(pattern) : [pattern.exec(rawLine)].filter(m => m !== null)
      for (const match of matches) {
        const start = match.indices?.[2]?.[0]
        const specifier = match[2]
        if (start !== undefined && specifier !== undefined) {
          out.push({ specifier, line: index, character: start, kind: kindOf(specifier) })
        }
      }
    }
    // W14-M4: Python allows `;`-separated simple statements on one line. The
    // anchored forms must judge each statement alone: the whole-line match
    // either rejected `import os; import sys` outright (the `$` anchor fails
    // on the `;` — BOTH module edges lost) or parsed `from x import y;
    // from z import w` as the name list `y; from z import w` (the second
    // statement invisible). Split first, match each segment independently.
    let offset = 0
    for (const rawSegment of trimmed.split(';')) {
      const segment = rawSegment.trimStart()
      const base = offset + (rawSegment.length - segment.length)
      const py = SITE_PYTHON.exec(segment)
      const pyStart = py?.indices?.[1]?.[0]
      if (pyStart !== undefined && py?.[1] !== undefined) {
        const module = py[1]
        out.push({ specifier: module, line: index, character: base + pyStart + indent, kind: kindOf(module) })
        // H-24(c): `from pkg import mod` binds the SUBMODULE pkg/mod.py, and
        // `from . import x` binds pkg/x.py — the name list carries those edges.
        // Only plain identifier names are followed (an `as` alias renames the
        // binding); the resolution itself stays proof-of-existence, so a plain
        // function import (`from pkg import helper` with no pkg/helper.py)
        // adds nothing.
        const listStart = py.indices?.[2]?.[0]
        if (listStart !== undefined) {
          let cursor = listStart
          for (const rawName of (py[2] ?? '').split(',')) {
            const head = /^[\s(]*([\w.]+)/.exec(rawName)
            if (head?.[1] !== undefined) {
              const name = head[1]
              // X-H-17(a): the concatenation must respect a dot the module
              // prefix already ends with. `${'.'}.${'x'}` minted '..x' — one
              // dot too many, which resolveSpecifier walked to the PARENT
              // package: `from . import x` (the highest-frequency Python
              // import form) resolved to the parent's x, never the sibling
              // pkg/x.py the statement actually binds. Y-H-07: the join lives
              // in joinDotted so the continuation reader shares it verbatim.
              const specifier = joinDotted(module, name)
              out.push({
                specifier,
                line: index,
                character: base + cursor + (head.index ?? 0) + (head[0].length - head[1].length) + indent,
                kind: kindOf(specifier),
              })
            }
            cursor += rawName.length + 1
          }
          // W14-M5: an unclosed paren — the name list continues on the next
          // lines; hand the module to the continuation reader above.
          const depth = parenDepth(py[2] ?? '')
          if (depth > 0 && pending === null) pending = { module, depth }
        }
      }
      const bare = SITE_PYTHON_BARE.exec(segment)
      const bareSpan = bare?.indices?.[1]
      if (bare?.[1] !== undefined && bareSpan?.[0] !== undefined) {
        let cursor = bareSpan[0]
        for (const rawName of bare[1].split(',')) {
          const lead = rawName.length - rawName.trimStart().length
          const name = /^([\w.]+)/.exec(rawName.trim())?.[1]
          if (name !== undefined) {
            out.push({ specifier: name, line: index, character: base + cursor + lead + indent, kind: kindOf(name) })
          }
          cursor += rawName.length + 1
        }
      }
      offset += rawSegment.length + 1
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
 * bare side-effect `import '...'`, `require('...')`, Python `from x.y import`
 * (module and imported names) and bare `import x.y`. Bare package names and
 * `node:` builtins are dropped — those are external dependencies, already
 * covered by the lockfile rules.
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

/**
 * Resolve a `.`-prefixed specifier against the scanned file set, returning
 * EVERY candidate that exists (usually zero or one).
 *
 * H-24: the leading-dot run is walked Python-style — `.` keeps the source
 * file's directory, each extra dot climbs one level, the remainder's dots
 * become path separators. This is also correct for JS `./x`/`../y` (their
 * semantics agree at one and two dots), and it replaces the old JS join,
 * which turned Python's `.mod` into the never-existing `pkg/.mod.py` — the
 * reason every relative Python form used to be edgeless.
 *
 * X-H-17(b): H-24's dot-to-slash rewrite of the remainder was applied to
 * every relative specifier, but a dot inside the remainder means different
 * things in the two languages — `pkg.mod` is `pkg/mod` in Python, while
 * `./x.component` / `./mod.js` are FILE NAMES in JS (Angular's component
 * convention; TS NodeNext's mandatory `.js` spelling of a `.ts` source).
 * Both readings are therefore probed and every existing candidate adds its
 * own edge: a spurious edge over-selects a check (the allowed direction), a
 * dropped edge manufactured a false "untouched". The NodeNext `.js`-strip
 * retry below covers the emitted-extension spelling against `.ts` sources.
 */
function resolveSpecifier(from: RelPath, specifier: string, known: ReadonlySet<RelPath>): readonly RelPath[] {
  if (!specifier.startsWith('.')) return []
  const dots = /^\.+/.exec(specifier)?.[0]?.length ?? 0
  const rest = specifier.slice(dots)
  let base = dirname(from)
  for (let i = 1; i < dots; i += 1) base = dirname(base)
  if (rest === '') {
    // A bare dot-run (`from . import x`'s module site) names the enclosing
    // package directory itself — its `__init__.py` (or index) candidates.
    // V7-L1: EVERY existing candidate adds its own edge, per the X-H-17(b)
    // doctrine five lines below ("every hit adds its own edge — the allowed
    // direction is over-inclusion"). firstKnown returned only the first hit,
    // so a mixed tree (`pkg.ts` AND `pkg/__init__.py` both on disk) connected
    // just one of them — a missed edge, the direction the constitution
    // forbids. Probe order is preserved, so single-hit trees are unchanged.
    const pkgDir = normalizePath(base)
    const out: RelPath[] = []
    for (const candidate of candidatePaths(pkgDir)) {
      if (known.has(candidate) && !out.includes(candidate)) out.push(candidate)
    }
    return out
  }
  const dotted = normalizePath(`${base}/${rest}`)
  const slashed = normalizePath(`${base}/${rest.replace(/\./g, '/')}`)
  const out: RelPath[] = []
  for (const form of dotted === slashed ? [dotted] : [dotted, slashed]) {
    for (const candidate of candidatePaths(form)) {
      if (known.has(candidate) && !out.includes(candidate)) out.push(candidate)
    }
  }
  return out
}

/** The filesystem spellings one resolved specifier could denote, in probe order. */
function candidatePaths(joined: string): readonly string[] {
  const candidates = [
    joined,
    `${joined}.ts`, `${joined}.tsx`, `${joined}.js`, `${joined}.jsx`, `${joined}.mjs`, `${joined}.cjs`,
    `${joined}/index.ts`, `${joined}/index.tsx`, `${joined}/index.js`, `${joined}/index.py`,
    // Python candidates: a module is `pkg/mod.py`, a package is
    // `pkg/mod/__init__.py`, and `from . import x` resolves to the enclosing
    // package's `__init__.py` (specifier `.`, rest empty, joined = the dir).
    `${joined}.py`, `${joined}/__init__.py`, `${joined}.go`, `${joined}.rs`,
  ]
  // NodeNext: TS sources import their own compilation output as `./mod.js`
  // while the file on disk is `mod.ts` — strip the emitted extension and
  // retry. Proof of existence only; nothing is invented.
  const stripped = joined.replace(/\.(js|jsx|mjs|cjs)$/, '')
  if (stripped !== joined) {
    candidates.push(`${stripped}.ts`, `${stripped}.tsx`, `${stripped}.js`, `${stripped}.jsx`, `${stripped}.mjs`, `${stripped}.cjs`)
  }
  return candidates
}

// (V7-L1 removed `firstKnown`: the bare dot-run branch now returns every
// existing candidate — the same "all hits" doctrine as the remainder branch
// below — so there is no first-hit-only consumer left to serve.)

/**
 * Python-style dotted import: `from pkg.mod import x` (absolute), bare
 * `import pkg.mod`, and the name-list sites those forms mint (`from pkg
 * import mod` -> pkg/mod.py) — but only when the target is genuinely in the
 * scanned set — the edge is added on proof of existence, never on
 * speculation. JS bare specifiers (`@scope/pkg`, `lodash/get`) fail the shape
 * test and stay external, as before.
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
