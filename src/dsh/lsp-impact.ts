/**
 * LSP-backed impact resolution: turns the host's language servers into a
 * precise, alias-aware DefinitionResolverPort for the dependency graph.
 *
 * The trick that makes the closed four-operation LSP surface sufficient:
 * goToDefinition placed *on the module specifier of an import statement*
 * resolves to the file that specifier binds to — including tsconfig `paths`
 * aliases and package-internal imports that regex extraction cannot see.
 *
 * Cost control: every result is cached per (file, content version, position),
 * a hard query budget degrades the remainder to the approximate graph, and —
 * H-34 — every round-trip is raced against a wall-clock deadline: a language
 * server that never answers degrades its position to a null answer (uncached,
 * retried later), never hangs the whole verify.
 *
 * @module dsh-proof/dsh/lsp-impact
 */

import type { DefinitionResolverPort, FsPort } from '../core/ports.ts'
import type { LspLike, LspLocation, LspQueryResult } from '../vendor/dsh-tools.ts'

export interface LspResolverOptions {
  /** Maximum language-server round-trips (per resolver instance). */
  readonly budget?: number
  /**
   * H-34: wall-clock ceiling for ONE language-server round-trip, in ms. A
   * server that never answers (init deadlock, a zombie language-server
   * process) must degrade that position to a null answer — costing one
   * query's worth of latency — instead of hanging the whole verify: no
   * engine budget covers this await (graph building sits outside the check
   * dispatch loop). Default 5s; injectable so tests can pin the behaviour in
   * real time.
   */
  readonly queryTimeoutMs?: number
}

/** Build a caching, budgeted resolver over the host's LSP seam, if present. */
export function createLspResolver(
  lsp: LspLike | undefined,
  root: string,
  fs: FsPort,
  options: LspResolverOptions = {},
): DefinitionResolverPort | undefined {
  if (lsp === undefined) return undefined
  // W13-L10 (v0.23): `Math.max(1, NaN)` is NaN, and `setTimeout(NaN)` fires
  // immediately — a NaN queryTimeoutMs used to time out every round-trip at
  // 0ms and silently degrade the whole graph to approximate. A NaN budget
  // was worse: `queries >= NaN` is always false, so the cap never held.
  // Non-finite or non-positive overrides fall back to the defaults instead
  // of poisoning the timer/counter that consumes them.
  const finitePositive = (value: number | undefined, fallback: number): number =>
    typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback
  return new CachingLspResolver(
    lsp, root, fs,
    Math.max(1, Math.floor(finitePositive(options.budget, 400))),
    finitePositive(options.queryTimeoutMs, 5_000),
  )
}

class CachingLspResolver implements DefinitionResolverPort {
  /**
   * W13-L12 (v0.23): the cache key carries a per-file GENERATION, bumped
   * every time the file's stat changes from the last-seen stat. The old key
   * (`mtimeMs:size`) was ABA-blind: content A → B → A between two stats (a
   * fast save loop, coarse mtime granularity) reproduced the pair and served
   * the STALE first-A answers as if the file had never moved — silently
   * pinning the graph to old definitions for the rest of the session. The
   * generation makes every observed change a new key: a genuine
   * restore-to-old-bytes costs one re-query, an ABA costs its stale cache.
   */
  private readonly entries = new Map<string, { version: string; results: Map<string, string | null> }>()
  private readonly lastStat = new Map<string, string>()
  private readonly generations = new Map<string, number>()
  private queries = 0
  private readonly lsp: LspLike
  private readonly root: string
  private readonly fs: FsPort
  private readonly budget: number
  private readonly queryTimeoutMs: number

  constructor(lsp: LspLike, root: string, fs: FsPort, budget: number, queryTimeoutMs: number) {
    this.lsp = lsp
    this.root = root
    this.fs = fs
    this.budget = budget
    this.queryTimeoutMs = queryTimeoutMs
  }

  async resolveDefinition(file: string, line: number, character: number): Promise<string | null> {
    const stat = await this.fs.stat(`${this.root}/${file}`).catch(() => undefined)
    const statKey = stat === undefined ? 'none' : `${stat.mtimeMs}:${stat.size}`
    // W13-L12: a stat that differs from the last one seen bumps the file's
    // generation, so the cache key changes even when the stat PAIR repeats
    // (the ABA shape); an unchanged stat reuses the current generation.
    let entry = this.entries.get(file)
    if (entry === undefined || this.lastStat.get(file) !== statKey) {
      const generation = (this.generations.get(file) ?? -1) + 1
      this.generations.set(file, generation)
      this.lastStat.set(file, statKey)
      entry = { version: `${generation}:${statKey}`, results: new Map() }
      this.entries.set(file, entry)
    }
    const positionKey = `${line}:${character}`
    // M-30: a cache hit answers for free. The budget gates NEW round-trips
    // only — this resolver is a plugin-lifetime singleton and the budget a
    // whole-session allowance, so checking the budget first used to blind
    // the graph to answers already paid for the moment the counter flipped.
    const cached = entry.results.get(positionKey)
    if (cached !== undefined) return cached
    if (this.queries >= this.budget) return null

    this.queries += 1
    const outcome = await this.timedQuery(file, line, character)
    if (outcome.transient) {
      // H-34/M-30: a timeout or a rejection is a fact about the SERVER
      // (cold start, hiccup, hang), not about the code — it must not be
      // cached: the old `.catch(() => null)` + set() froze "no definition"
      // at this position until the file changed on disk, silently pinning
      // the graph to approximate precision for the rest of the session.
      // Return null now (soundness never narrows) and let the next query retry.
      return null
    }
    const target = outcome.value !== null && outcome.value.kind === 'locations'
      ? firstWorkspaceRelative(outcome.value.locations, this.root)
      : null
    entry.results.set(positionKey, target)
    return target
  }

  /**
   * One round-trip, raced against the deadline, with the vendor seam's abort
   * signal passed through (it is free to ignore it). Resolves to
   * `{ transient: true }` on timeout or rejection — indistinguishable-from-
   * failure inputs deliberately collapse here so neither can be cached.
   */
  private async timedQuery(
    file: string, line: number, character: number,
  ): Promise<{ transient: true } | { transient: false; value: LspQueryResult | null }> {
    const controller = new AbortController()
    let timeoutHit = false
    let deadlineDone: () => void = () => { /* replaced by the promise executor */ }
    const deadline = new Promise<void>((resolve) => { deadlineDone = resolve })
    const timer = setTimeout(() => {
      timeoutHit = true
      controller.abort()
      deadlineDone()
    }, this.queryTimeoutMs)
    try {
      const winner = await Promise.race([
        this.lsp
          .query(
            'goToDefinition',
            { file: `${this.root}/${file}`.replace(/\\/g, '/'), line, character },
            controller.signal,
          )
          .then(
            (value) => ({ timedOut: false as const, value }),
            () => ({ timedOut: true as const, value: null as LspQueryResult | null }),
          ),
        deadline.then(() => ({ timedOut: true as const, value: null as LspQueryResult | null })),
      ])
      if (winner.timedOut || timeoutHit) return { transient: true }
      return { transient: false, value: winner.value }
    } finally {
      // The timer keeps the event loop alive until cleared; a won race must
      // not leak it. A lost (still-pending) server promise already has its
      // rejection handled by the .then mapping above.
      clearTimeout(timer)
    }
  }
}

function firstWorkspaceRelative(locations: readonly LspLocation[], root: string): string | null {
  for (const location of locations) {
    const rel = uriToRelative(location.uri, root)
    if (rel !== null) return rel
  }
  return null
}

/** Convert a `file://` URI to a workspace-relative path, or null when outside. */
export function uriToRelative(uri: string, root: string): string | null {
  if (!uri.startsWith('file:')) return null
  let path: string
  if (uri.startsWith('file:///')) {
    path = `/${decodeURIComponentSafe(uri.slice('file:///'.length))}`
  } else if (uri.startsWith('file://')) {
    path = decodeURIComponentSafe(uri.slice('file://'.length))
  } else {
    return null
  }
  // Windows drive letters arrive as file:///C:/... — normalize /C:/ back to C:/.
  if (/^\/[A-Za-z]:\//.test(path)) path = path.slice(1)
  path = path.replace(/\\/g, '/')
  const normalizedRoot = root.replace(/\\/g, '/').replace(/\/+$/, '')
  // Windows servers routinely disagree with the host on drive-letter case
  // (`file:///c:/…` vs root `C:/…`), and drive filesystems are themselves
  // case-insensitive — so a drive-form root must compare its prefix that way
  // or every edge it resolves is silently dropped. POSIX roots stay
  // case-sensitive: `/WS` and `/ws` really are different directories there.
  const prefix = `${normalizedRoot}/`
  const inside = /^[A-Za-z]:\//.test(normalizedRoot)
    ? path.toLowerCase().startsWith(prefix.toLowerCase())
    : path.startsWith(prefix)
  if (!inside) return null
  return path.slice(prefix.length)
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
