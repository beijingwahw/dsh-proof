import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  attributeChange, buildDependencyGraph, extractImports, impactClosure,
  isGlobalInvalidator, matches, matchesAny, selectAffectedChecks,
} from '../src/core/impact.ts'
import { MemoryFs, spec } from './helpers.ts'

const TREE = {
  '/ws/src/a.ts': "import { b } from './b'\nexport const a = b\n",
  '/ws/src/b.ts': "import { c } from './c'\nexport const b = c\n",
  '/ws/src/c.ts': 'export const c = 1\n',
  '/ws/src/orphan.ts': 'export const o = 1\n',
  '/ws/test/a.test.ts': "import { a } from '../src/a'\nvoid a\n",
  '/ws/package.json': '{"name":"ws"}',
}

test('extractImports finds relative ESM and CJS specifiers', () => {
  const found = extractImports(`
    import x from './a'
    export { y } from "../b"
    import './c'
    const z = require('./d')
    from pkg.mod import thing
    import fs from 'node:fs'
  `)
  assert.ok(found.includes('./a'))
  assert.ok(found.includes('../b'))
  assert.ok(found.includes('./c'))
  assert.ok(found.includes('./d'))
  assert.ok(found.includes('pkg.mod'))
  assert.ok(!found.includes('node:fs'), 'bare node: specifiers are not workspace deps')
})

test('dynamic import() sites are import sites too', () => {
  const found = extractImports("export function go() {\n  return import('./lazy')\n}\n")
  assert.ok(found.includes('./lazy'), 'a lazily loaded chunk depends on its target like anyone else')
})

test('multi-line ESM imports produce a site on the closing from-line', () => {
  const found = extractImports("import {\n  a,\n  b,\n} from './multi'\n")
  assert.ok(found.includes('./multi'), 'the from on a }-prefixed line must not be invisible')
})

test('dynamic and multi-line imports carry the closure — no silent edge loss', async () => {
  const files = {
    '/ws/src/lazy.ts': "export function go() { return import('./dep') }\n",
    '/ws/src/multi.ts': "import {\n  dep,\n} from './dep'\nexport const m = dep\n",
    '/ws/src/dep.ts': 'export const dep = 1\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  const closure = impactClosure(graph, ['src/dep.ts'])
  assert.ok(closure.has('src/lazy.ts'), 'dynamic import() edges are walkable')
  assert.ok(closure.has('src/multi.ts'), 'multi-line ESM edges are walkable')

  // Selection follows the closure: a check scoped to the importer is chosen
  // when only its (dynamically/multi-line imported) dependency changed.
  const checks = [spec({ id: 'lazy', paths: ['src/lazy.ts'] }), spec({ id: 'orphan', paths: ['docs/**'] })]
  const result = selectAffectedChecks(checks, ['src/dep.ts'], graph)
  assert.deepEqual(result.affected.map(c => c.id), ['lazy'])
  assert.deepEqual(result.untouched.map(c => c.id), ['orphan'])
})

test('python dotted imports resolve inside the scanned set only', async () => {
  const files = {
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/pkg/__init__.py': '',
    '/ws/app.py': 'from pkg.mod import X\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  const closure = impactClosure(graph, ['pkg/mod.py'])
  assert.ok(closure.has('app.py'), 'bare dotted specifier binds to pkg/mod.py')
  // Edges are added only on proof: a dotted name with no scanned target
  // (the __init__ form here) adds nothing, so this stays exact, not guessed.
  assert.deepEqual([...impactClosure(graph, ['pkg/__init__.py'])], ['pkg/__init__.py'])
})

test('impact closure walks reverse dependencies transitively', async () => {
  const fs = MemoryFs.of(TREE)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(TREE).map(stripRoot))
  const affected = impactClosure(graph, ['src/c.ts'])
  assert.deepEqual([...affected].sort(), ['src/a.ts', 'src/b.ts', 'src/c.ts', 'test/a.test.ts'])
  assert.ok(!affected.has('src/orphan.ts'))

  const shallow = impactClosure(graph, ['src/orphan.ts'])
  assert.deepEqual([...shallow], ['src/orphan.ts'])
})

test('global invalidators force every check', () => {
  assert.ok(isGlobalInvalidator('package.json'))
  assert.ok(isGlobalInvalidator('pnpm-lock.yaml'))
  assert.ok(isGlobalInvalidator('.github/workflows/ci.yml'))
  assert.ok(!isGlobalInvalidator('src/a.ts'))

  const checks = [spec({ id: 'a', paths: ['src/**'] }), spec({ id: 'b', paths: ['docs/**'] })]
  const result = selectAffectedChecks(checks, ['package.json'])
  assert.equal(result.forcedAll, true)
  assert.equal(result.affected.length, 2)
})

test('path filters narrow the selection', async () => {
  const fs = MemoryFs.of(TREE)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(TREE).map(stripRoot))
  const checks = [
    spec({ id: 'src-check', paths: ['src/**'] }),
    spec({ id: 'docs-check', paths: ['docs/**'] }),
    spec({ id: 'always', paths: ['*'] }),
  ]
  const result = selectAffectedChecks(checks, ['src/c.ts'], graph)
  assert.deepEqual(result.affected.map(c => c.id).sort(), ['always', 'src-check'])
  assert.deepEqual(result.untouched.map(c => c.id), ['docs-check'])
  assert.equal(result.forcedAll, false)
})

test('uncertainty widens the selection rather than narrowing it', () => {
  const checks = [spec({ id: 'narrow', paths: ['docs/**'] })]
  const result = selectAffectedChecks(checks, ['src/mystery.zzz'], undefined)
  assert.equal(result.uncertain, true)
  assert.equal(result.affected.length, 1, 'unknown file types must not silently skip checks')
})

test('attribution maps changed files to the checks they own', async () => {
  const fs = MemoryFs.of(TREE)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(TREE).map(stripRoot))
  const checks = [spec({ id: 'src-check', paths: ['src/**'] }), spec({ id: 'docs-check', paths: ['docs/**'] })]
  const table = attributeChange(checks, ['src/c.ts'], graph)
  assert.deepEqual(table.get('src/c.ts'), ['src-check'])
})

test('glob matching covers prefix, /**, /* and exact forms', () => {
  assert.ok(matches('src/a/b.ts', 'src/**'))
  assert.ok(matches('src', 'src/**'))
  assert.ok(!matches('srcx/a.ts', 'src/**'))
  assert.ok(matches('src/a.ts', 'src/*'))
  assert.ok(!matches('src/a/b.ts', 'src/*'))
  assert.ok(matches('a/b.ts', 'a'))
  assert.ok(matches('anything', '*'))
  assert.ok(matchesAny('x/y.ts', ['nope', 'x/**']))
})

test('graph reports truncation so callers can widen', async () => {
  const files = {
    '/ws/a.ts': "import './b'",
    '/ws/b.ts': 'export const b = 1',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot), { limit: 1 })
  assert.equal(graph.truncated, true)
  assert.equal(graph.scanned, 1)
})

function stripRoot(path: string): string {
  return path.replace(/^\/ws\/?/, '')
}
