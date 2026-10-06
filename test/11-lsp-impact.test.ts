/**
 * LSP-BACKED IMPACT — dual-source confidence fusion.
 *
 * The regex graph errs toward over-inclusion; the LSP pass verifies edges and
 * discovers alias imports regex cannot see. Selection never narrows: the two
 * edge sources are unioned, and degradation (no server, budget exhausted) is
 * visible through `precision`.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildDependencyGraph, extractImportSites, impactClosure, selectAffectedChecks,
} from '../src/core/impact.ts'
import type { DefinitionResolverPort } from '../src/core/ports.ts'
import type { LspLike, LspQueryResult } from '../src/vendor/dsh-tools.ts'
import { createLspResolver, uriToRelative } from '../src/dsh/lsp-impact.ts'
import { ProofEngine } from '../src/engine.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs, spec } from './helpers.ts'

class TableResolver implements DefinitionResolverPort {
  calls: { file: string; line: number; character: number }[] = []
  private readonly table: Map<string, string>
  constructor(table: Map<string, string>) {
    this.table = table
  }
  async resolveDefinition(file: string, line: number, character: number): Promise<string | null> {
    this.calls.push({ file, line, character })
    return this.table.get(`${file}:${line}:${character}`) ?? null
  }
}

function filesOf(entries: Record<string, string>): string[] {
  return Object.keys(entries)
}

test('extractImportSites reports 0-based UTF-16 positions of specifier starts', () => {
  const content = [
    "import { b } from './b'", // specifier starts at 19
    'export { y } from "../b"', // 19
    "const z = require('./d')", // 18
    'from pkg.mod import thing', // 5
    "  import side from '@alias/thing'", // indented: 2 + 20 = 22
    '// import { skipped } from "./nope"', // comment — no site
  ].join('\n')
  const sites = extractImportSites(content)
  const summary = sites.map(s => `${s.line}:${s.character}:${s.kind}`)
  assert.ok(summary.includes('0:19:relative'), `got ${summary.join(' ')}`)
  assert.ok(summary.includes('1:19:relative'), `got ${summary.join(' ')}`)
  assert.ok(summary.includes('2:19:relative'), `got ${summary.join(' ')}`)
  assert.ok(summary.includes('3:5:bare'), `got ${summary.join(' ')}`)
  assert.ok(summary.includes('4:20:bare'), `got ${summary.join(' ')}`)
  assert.ok(!sites.some(s => s.specifier === './nope'), 'commented imports are not sites')
})

test('THE BLIND SPOT: LSP discovers an alias edge the regex graph cannot see', async () => {
  const entries = {
    '/ws/src/app.ts': "import { thing } from '@lib/thing'\n",
    '/ws/lib/thing.ts': 'export const thing = 1\n',
  }
  const fs = MemoryFs.of(entries)
  const fileKeys = filesOf(entries)
  const strip = (p: string): string => p.replace(/^\/ws\//, '')

  // Derive the site position from the extractor itself — no hand counting.
  const site = extractImportSites(entries['/ws/src/app.ts'] as string)[0]
  assert.ok(site, 'import site found')
  assert.equal(site.kind, 'bare', 'the alias specifier is bare — invisible to regex')

  const table = new Map([[`src/app.ts:${site.line}:${site.character}`, 'lib/thing.ts']])
  const resolver = new TableResolver(table)

  const lspGraph = await buildDependencyGraph(fs, '/ws', fileKeys.map(strip), { resolver })
  const closure = impactClosure(lspGraph, ['lib/thing.ts'])
  assert.ok(closure.has('src/app.ts'), 'the alias edge exists via LSP')
  assert.equal(lspGraph.precision, 'lsp-verified')
  assert.ok(lspGraph.lspConfirmed.has('src/app.ts\u0000lib/thing.ts'))

  // Control: the regex-only graph does NOT have the edge.
  const regexGraph = await buildDependencyGraph(fs, '/ws', fileKeys.map(strip))
  assert.ok(!impactClosure(regexGraph, ['lib/thing.ts']).has('src/app.ts'))
  assert.equal(regexGraph.precision, 'approximate')
})

test('union semantics: unverified regex edges survive, confirmed edges are kept too', async () => {
  const entries = {
    '/ws/src/a.ts': "import { c } from './c'\nimport { t } from '@lib/t'\n",
    '/ws/src/c.ts': 'export const c = 1\n',
    '/ws/lib/t.ts': 'export const t = 1\n',
  }
  const fs = MemoryFs.of(entries)
  const files = filesOf(entries).map(p => p.replace(/^\/ws\//, ''))
  const sites = extractImportSites(entries['/ws/src/a.ts'] as string)
  const aliasSite = sites.find(s => s.kind === 'bare')
  assert.ok(aliasSite)

  // The server resolves the alias but misses the relative import (server hiccup).
  const table = new Map([[`src/a.ts:${aliasSite.line}:${aliasSite.character}`, 'lib/t.ts']])
  const graph = await buildDependencyGraph(fs, '/ws', files, { resolver: new TableResolver(table) })

  const closure = impactClosure(graph, ['src/c.ts'])
  assert.ok(closure.has('src/a.ts'), 'the UNVERIFIED relative edge still selects — soundness never narrows')
  assert.ok(impactClosure(graph, ['lib/t.ts']).has('src/a.ts'), 'the confirmed alias edge selects too')
})

test('selection carries precision, and budget exhaustion degrades visibly', async () => {
  const entries = {
    '/ws/src/a.ts': "import { c } from './c'\n",
    '/ws/src/c.ts': 'export const c = 1\n',
  }
  const fs = MemoryFs.of(entries)
  const files = filesOf(entries).map(p => p.replace(/^\/ws\//, ''))

  const resolver = new TableResolver(new Map())
  const zeroBudget = await buildDependencyGraph(fs, '/ws', files, { resolver, lspQueryBudget: 0 })
  assert.equal(zeroBudget.precision, 'approximate', 'zero budget means no LSP queries at all')
  assert.equal(resolver.calls.length, 0, 'the resolver was never consulted')

  const checks = [spec({ id: 'x', paths: ['src/**'] })]
  const selection = selectAffectedChecks(checks, ['src/c.ts'], zeroBudget)
  assert.equal(selection.precision, 'approximate')
  assert.deepEqual(selection.affected.map(c => c.id), ['x'])
})

test('uriToRelative handles windows drives, unix roots and foreign roots', () => {
  assert.equal(uriToRelative('file:///C:/ws/x/src/a.ts', 'C:/ws/x'), 'src/a.ts')
  assert.equal(uriToRelative('file:///home/u/ws/y.ts', '/home/u/ws'), 'y.ts')
  assert.equal(uriToRelative('file:///home/u/ws/dir%20name/y.ts', '/home/u/ws'), 'dir name/y.ts')
  assert.equal(uriToRelative('file:///elsewhere/z.ts', '/home/u/ws'), null)
  assert.equal(uriToRelative('untitled:Untitled-1', '/home/u/ws'), null)
})

test('drive-form roots compare case-insensitively so LSP edges are not dropped', () => {
  assert.equal(uriToRelative('file:///c:/ws/x/src/a.ts', 'C:/ws/x'), 'src/a.ts', 'server lowercases the drive, host does not')
  assert.equal(uriToRelative('file:///C:/ws/x/src/a.ts', 'c:\\ws\\x'), 'src/a.ts', 'either slash style, either drive case')
  assert.equal(uriToRelative('file:///D:/ws/x/src/a.ts', 'C:/ws/x'), null, 'a different drive is still outside')
  // POSIX sensitivity is correct behaviour, not an oversight: /WS != /ws.
  assert.equal(uriToRelative('file:///WS/x/src/a.ts', '/ws/x'), null)
})

test('the caching resolver asks the server once per position', async () => {
  const queries: { file: string; line: number; character: number }[] = []
  const lsp: LspLike = {
    async query(operation, args): Promise<LspQueryResult> {
      queries.push({ file: args.file, line: args.line, character: args.character })
      return { kind: 'locations', locations: [{ uri: 'file:///ws/lib/t.ts', range: {} }] }
    },
  }
  const fs = MemoryFs.of({ '/ws/src/a.ts': "import { t } from '@lib/t'\n" })
  const resolver = createLspResolver(lsp, '/ws', fs, { budget: 10 })
  assert.ok(resolver, 'resolver built when the seam is present')

  const first = await resolver.resolveDefinition('src/a.ts', 0, 10)
  const second = await resolver.resolveDefinition('src/a.ts', 0, 10)
  assert.equal(first, 'lib/t.ts')
  assert.equal(second, 'lib/t.ts')
  assert.equal(queries.length, 1, 'cached per (file, version, position)')

  await resolver.resolveDefinition('src/a.ts', 0, 11)
  assert.equal(queries.length, 2, 'a different position is a different query')

  assert.equal(createLspResolver(undefined, '/ws', fs), undefined, 'no seam, no resolver')
})

test('ENGINE: precision surfaces end to end through verify', async () => {
  const entries = {
    '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'vitest run' } }),
    '/ws/src/a.ts': "import { t } from '@lib/t'\nvoid t\n",
    '/ws/lib/t.ts': 'export const t = 1\n',
  }
  const fs = MemoryFs.of(entries)
  const found = extractImportSites(entries['/ws/src/a.ts'] as string)
  const site = found[0]
  assert.ok(site !== undefined, 'import site found')
  const resolver = new TableResolver(new Map([[`src/a.ts:${site.line}:${site.character}`, 'lib/t.ts']]))

  const engine = new ProofEngine({
    root: '/ws', fs, commands: new FakeCommands(), workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(), impactGraphLimit: 1_000, resolver, lspQueryBudget: 50,
  })
  await engine.establishBaseline()
  const graph = await engine.loadGraph(true)
  assert.equal(graph?.precision, 'lsp-verified')

  const outcome = await engine.verify({ changed: ['lib/t.ts'] })
  assert.equal(outcome.selection.precision, 'lsp-verified')
  assert.ok(outcome.selection.affected.length > 0, 'the alias-reachable check is selected')
  assert.equal(outcome.report.grade, 'proven')
})

// -- H-34/M-30: the resolver's own reliability (hang, poison, budget order) --------

test('H-34: a never-settling language server degrades to null within the deadline — and is not cached as fact', async () => {
  // The hang shape this pins: `query()` returns a promise that never settles
  // (init deadlock, a zombie language-server process). Before H-34 the
  // resolver awaited it bare — no engine budget covers graph building — so
  // one hung position hung the WHOLE verify. Now every round-trip races a
  // deadline (injectable: 60ms here, 5s in production).
  let queries = 0
  const signals: (AbortSignal | undefined)[] = []
  const hung: LspLike = {
    query(operation, args, signal): Promise<LspQueryResult> {
      void operation; void args
      queries += 1
      signals.push(signal)
      return new Promise<LspQueryResult>(() => { /* never settles */ })
    },
  }
  const fs = MemoryFs.of({ '/ws/src/a.ts': "import { t } from '@lib/t'\n" })
  const resolver = createLspResolver(hung, '/ws', fs, { budget: 10, queryTimeoutMs: 60 })
  assert.ok(resolver, 'resolver built when the seam is present')

  const startedAt = Date.now()
  const first = await resolver.resolveDefinition('src/a.ts', 0, 10)
  const wallMs = Date.now() - startedAt
  assert.equal(first, null, 'a hung server costs its position precision, never the whole verify')
  assert.ok(wallMs < 2_000, `resolveDefinition took ${wallMs}ms — the deadline must bound it`)
  assert.equal(signals[0] instanceof AbortSignal, true, 'the vendor seam receives the signal parameter')
  assert.equal(signals[0]?.aborted, true, 'the deadline aborts it — servers that honour signals stop early')

  // Cache-poisoning guard: a timeout is a fact about the SERVER, not the
  // code. The same position must be QUERIED again (and time out again),
  // never served from a cached null.
  const second = await resolver.resolveDefinition('src/a.ts', 0, 10)
  assert.equal(second, null)
  assert.equal(queries, 2, 'a timed-out answer must not be frozen as "no definition"')
})

test('M-30: a transient server rejection is retried; a deterministic answer still caches', async () => {
  // Cold-start reject (server not ready) used to be cached as null until the
  // file changed on disk — the graph silently pinned to approximate
  // precision for the whole session exactly when the server was warming up.
  let queries = 0
  const flaky: LspLike = {
    async query(): Promise<LspQueryResult> {
      queries += 1
      if (queries === 1) throw new Error('server not ready (cold start)')
      return { kind: 'locations', locations: [{ uri: 'file:///ws/lib/t.ts', range: {} }] }
    },
  }
  const fs = MemoryFs.of({ '/ws/src/a.ts': "import { t } from '@lib/t'\n" })
  const resolver = createLspResolver(flaky, '/ws', fs, { budget: 10 })
  assert.ok(resolver)

  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 10), null,
    'the rejection answers null now — soundness never narrows')
  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 10), 'lib/t.ts',
    'the retry reaches the now-ready server')
  assert.equal(queries, 2, 'the failed first attempt was not cached as an answer')
  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 10), 'lib/t.ts',
    'deterministic answers cache exactly as before')
  assert.equal(queries, 2)
})

test('M-30: the budget gates NEW round-trips only — cache hits stay free after it runs dry', async () => {
  // The resolver is a plugin-lifetime singleton and the budget a whole-
  // session allowance; the old budget-before-cache order blinded the graph to
  // answers already paid for the moment the counter flipped.
  let queries = 0
  const lsp: LspLike = {
    async query(): Promise<LspQueryResult> {
      queries += 1
      return { kind: 'locations', locations: [{ uri: 'file:///ws/lib/t.ts', range: {} }] }
    },
  }
  const fs = MemoryFs.of({ '/ws/src/a.ts': "import { t } from '@lib/t'\n" })
  const resolver = createLspResolver(lsp, '/ws', fs, { budget: 1 })
  assert.ok(resolver)

  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 10), 'lib/t.ts',
    'the one round-trip the budget allows')
  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 10), 'lib/t.ts',
    'a cache hit answers without consulting the budget')
  assert.equal(queries, 1, 'no new round-trip for a cached position')
  assert.equal(await resolver.resolveDefinition('src/a.ts', 0, 11), null,
    'a NEW position past the budget degrades to null (approximate graph)')
  assert.equal(queries, 1)
})
