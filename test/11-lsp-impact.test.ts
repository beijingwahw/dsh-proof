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
