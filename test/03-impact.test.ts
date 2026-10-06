import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  attributeChange, buildDependencyGraph, extractImportSites, extractImports,
  impactClosure, isGlobalInvalidator, matches, matchesAny, selectAffectedChecks,
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

// ---------------------------------------------------------------------------
// H-24 — the Python import forms that used to be edgeless. The absolute
// `from pkg.mod import x` form was the only one with an edge; everything
// below produced NO dependency edge at all, so a narrowly-pathed Python
// check read "untouched" while its imports moved under it.
// ---------------------------------------------------------------------------

test('H-24: bare `import pkg.mod` carries the dependency edge', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/bare.py': 'import pkg.mod\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  const closure = impactClosure(graph, ['pkg/mod.py'])
  assert.ok(closure.has('bare.py'), 'the bare statement binds to pkg/mod.py')
  // The alias and comma-list spellings are dependency statements too.
  const files2 = {
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/other.py': 'Y = 1\n',
    '/ws/bare2.py': 'import os, pkg.mod as m\n',
  }
  const graph2 = await buildDependencyGraph(MemoryFs.of(files2), '/ws', Object.keys(files2).map(stripRoot))
  const closure2 = impactClosure(graph2, ['pkg/mod.py'])
  assert.ok(closure2.has('bare2.py'), 'aliased comma-list bare import binds')
  // os has no scanned target: proof-of-existence, no speculative edge.
  assert.deepEqual([...impactClosure(graph2, ['other.py'])], ['other.py'])
})

test('H-24: relative python imports resolve by leading dots, not JS joins', async () => {
  // `from .mod import x` / `from . import x` / `from ..x import z` /
  // `from .sub.mod import w` — the old resolver joined `.mod` as a JS path
  // segment (`pkg/.mod.py`), which never exists, so all four forms were
  // edgeless. Python semantics: n leading dots = the source file's directory
  // after climbing n−1 levels.
  const files = {
    '/ws/pkg/__init__.py': 'P = 1\n',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/pkg/sub/__init__.py': '',
    '/ws/pkg/sub/mod.py': 'S = 1\n',
    '/ws/pkg/main.py': 'from .mod import X\nfrom . import P\nfrom .sub.mod import S\n',
    '/ws/other.py': 'Z = 1\n',
    '/ws/pkg/deep.py': 'from ..other import Z\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  const closure = (f: string) => impactClosure(graph, [f])
  assert.ok(closure('pkg/mod.py').has('pkg/main.py'), 'from .mod import X -> pkg/mod.py')
  assert.ok(closure('pkg/__init__.py').has('pkg/main.py'), 'from . import P -> pkg/__init__.py')
  assert.ok(closure('pkg/sub/mod.py').has('pkg/main.py'), 'from .sub.mod import S -> pkg/sub/mod.py')
  assert.ok(closure('other.py').has('pkg/deep.py'), 'from ..other import Z climbs out of the package')
})

test('H-24: `from pkg import mod` binds the submodule, not only the package', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/app.py': 'from pkg import mod\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  const closure = impactClosure(graph, ['pkg/mod.py'])
  assert.ok(closure.has('app.py'), 'the imported NAME resolves to pkg/mod.py')
  assert.ok(impactClosure(graph, ['pkg/__init__.py']).has('app.py'), 'the package itself still binds too')
  // A plain function import adds no speculative submodule edge.
  const files2 = { '/ws/pkg/__init__.py': 'def helper(): pass\n', '/ws/app.py': 'from pkg import helper\n' }
  const graph2 = await buildDependencyGraph(MemoryFs.of(files2), '/ws', Object.keys(files2).map(stripRoot))
  assert.ok(impactClosure(graph2, ['pkg/__init__.py']).has('app.py'), 'the package edge exists')
})

// ---------------------------------------------------------------------------
// X-H-17 — the two H-24 regressions. (a) the name-list specifier for
// `from . import x` was concatenated one dot too long ('..' + 'x' = '..x'),
// which the resolver walked to the PARENT package — the highest-frequency
// Python import form resolved to a file that is not the one it binds. (b)
// H-24's `\./g → /` rewrite of every relative specifier's remainder deleted
// every JS edge whose FILE NAME carries a dot. Both are missed edges → false
// "untouched"; the fix direction is dual-candidate probing (both readings
// emit edges, over-inclusion is the allowed direction).
// ---------------------------------------------------------------------------

test('X-H-17(a): `from . import x` binds the sibling pkg/x.py, not the parent package', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/x.py': 'X = 1\n',
    '/ws/pkg/main.py': 'from . import x\n',
    '/ws/x.py': 'PARENT = 1\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  // The sibling edge is the fix; the parent edge is the bug's dead endpoint.
  assert.ok(impactClosure(graph, ['pkg/x.py']).has('pkg/main.py'), 'pkg/x.py is a dependency of pkg/main.py')
  // The parent-package x.py is NOT what the statement binds (it only gained
  // no edge before because the mangled '..x' resolved to the bare root 'x'
  // candidate — which DID exist here, the silent mis-binding this test pins).
  assert.ok(!impactClosure(graph, ['x.py']).has('pkg/main.py'), 'the parent package\'s x.py is not bound by `from . import x`')
  // `from .. import x` climbs exactly one level out of the subpackage.
  const files2 = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/x.py': 'X = 1\n',
    '/ws/pkg/sub/__init__.py': '',
    '/ws/pkg/sub/deep.py': 'from .. import x\n',
  }
  const graph2 = await buildDependencyGraph(MemoryFs.of(files2), '/ws', Object.keys(files2).map(stripRoot))
  assert.ok(impactClosure(graph2, ['pkg/x.py']).has('pkg/sub/deep.py'), 'from .. import x -> pkg/x.py')
  // Site-level KAT of the specifier actually minted (the off-by-one itself).
  const sites = extractImportSites('from . import x\n')
  assert.deepEqual(sites.map(s => s.specifier), ['.', '.x'], 'module site "." + name site ".x" — never "..x"')
})

test('X-H-17(b): JS specifiers whose FILE NAME carries dots keep their edges — both readings probed', async () => {
  // Angular convention: the file is x.component.ts, the specifier './x.component'.
  const angular = {
    '/ws/src/x.component.ts': 'export const c = 1\n',
    '/ws/src/app.ts': "import { c } from './x.component'\n",
  }
  const g1 = await buildDependencyGraph(MemoryFs.of(angular), '/ws', Object.keys(angular).map(stripRoot))
  assert.ok(impactClosure(g1, ['src/x.component.ts']).has('src/app.ts'), "'./x.component' -> src/x.component.ts (was rewritten to src/x/component)")

  // TS NodeNext: the source is mod.ts, the mandatory spelling is './mod.js'.
  const nodeNext = {
    '/ws/src/mod.ts': 'export const m = 1\n',
    '/ws/src/app.ts': "import { m } from './mod.js'\n",
  }
  const g2 = await buildDependencyGraph(MemoryFs.of(nodeNext), '/ws', Object.keys(nodeNext).map(stripRoot))
  assert.ok(impactClosure(g2, ['src/mod.ts']).has('src/app.ts'), "'./mod.js' -> src/mod.ts via the emitted-extension strip (was rewritten to src/mod/js)")

  // The Python reading still works: '.sub.mod' remains pkg/sub/mod.py.
  const dotted = {
    '/ws/pkg/sub/__init__.py': '',
    '/ws/pkg/sub/mod.py': 'S = 1\n',
    '/ws/pkg/main.py': 'from .sub.mod import S\n',
  }
  const g3 = await buildDependencyGraph(MemoryFs.of(dotted), '/ws', Object.keys(dotted).map(stripRoot))
  assert.ok(impactClosure(g3, ['pkg/sub/mod.py']).has('pkg/main.py'), "'from .sub.mod import S' -> pkg/sub/mod.py (the slashed reading survives)")

  // Dual-candidate: when BOTH readings exist on disk, both edges are emitted
  // — the conservative direction is more edges, never fewer.
  const both = {
    '/ws/src/dotdir/mod.py': 'P = 1\n',
    '/ws/src/dotdir/mod.ts': 'T = 1\n',
    '/ws/src/app.ts': "import { p } from './dotdir.mod'\n",
  }
  const g4 = await buildDependencyGraph(MemoryFs.of(both), '/ws', Object.keys(both).map(stripRoot))
  assert.ok(impactClosure(g4, ['src/dotdir/mod.py']).has('src/app.ts'), 'the Python reading keeps its edge')
  assert.ok(impactClosure(g4, ['src/dotdir/mod.ts']).has('src/app.ts'), 'the JS dotted-name reading keeps its edge too')
})

// ---------------------------------------------------------------------------
// W14-M4/M5 — the two Python statement shapes the line reader dropped.
// ---------------------------------------------------------------------------

test('W14-M4: semicolon-separated Python statements each carry their edges', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/pkg/other.py': 'Y = 1\n',
    '/ws/app.py': 'import pkg.mod; import pkg.other\n',
    '/ws/app2.py': 'from pkg.mod import X; from pkg.other import Y\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  assert.ok(impactClosure(graph, ['pkg/mod.py']).has('app.py'), 'first statement of `import a; import b` binds')
  assert.ok(impactClosure(graph, ['pkg/other.py']).has('app.py'), 'SECOND statement of `import a; import b` binds too (both used to be dropped)')
  assert.ok(impactClosure(graph, ['pkg/mod.py']).has('app2.py'), 'from-list head of the first `from x import y; from z import w` binds')
  assert.ok(impactClosure(graph, ['pkg/other.py']).has('app2.py'), 'the SECOND `from z import w` statement binds (used to be eaten as a name)')
  // Site-level: two bare statements mint two module sites.
  const sites = extractImportSites('import pkg.mod; import pkg.other')
  assert.deepEqual(sites.map(s => s.specifier), ['pkg.mod', 'pkg.other'])
})

test('W14-M5: multi-line parenthesised `from pkg import (…)` name lists carry every name edge', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/pkg/helper.py': 'H = 1\n',
    // black/isort formatting: paren opens on the first line, closes on a
    // later one — the name list spans lines.
    '/ws/app.py': 'from pkg import (\n    mod,\n    helper,\n)\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  assert.ok(impactClosure(graph, ['pkg/__init__.py']).has('app.py'), 'the package edge survives as always')
  assert.ok(impactClosure(graph, ['pkg/mod.py']).has('app.py'), 'the first continuation name binds (used to be dropped)')
  assert.ok(impactClosure(graph, ['pkg/helper.py']).has('app.py'), 'the second continuation name binds too')
  // Comments are legal inside the list and mint nothing.
  const commented = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/mod.py': 'X = 1\n',
    '/ws/app.py': 'from pkg import (\n    # mod moved elsewhere\n    mod,  # trailing comment\n)\n',
  }
  const g2 = await buildDependencyGraph(MemoryFs.of(commented), '/ws', Object.keys(commented).map(stripRoot))
  assert.ok(impactClosure(g2, ['pkg/mod.py']).has('app.py'), 'comment lines inside the list do not eat the names')
})

// ---------------------------------------------------------------------------
// Y-H-07 — X-H-17(a) resurrected on the continuation reader. The dot-tail
// conditional join was fixed ONLY on the single-line name-list path; the
// bracket-continuation reader added the same version kept the unconditional
// `'.'+'.'+'x'` join, so `from . import (\n x,\n)` — black/isort's standard
// formatting for a long name list, i.e. the exact spelling the reader exists
// for — minted '..x' and walked every name to the PARENT package.
// ---------------------------------------------------------------------------

test('Y-H-07: `from . import (x, y)` continuation names bind the SIBLINGS, not the parent package', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/main.py': 'from . import (\n    x,\n    y,\n)\n',
    '/ws/pkg/x.py': 'X = 1\n',
    '/ws/pkg/y.py': 'Y = 1\n',
    '/ws/x.py': 'PARENT = 1\n',
    '/ws/y.py': 'PARENT = 1\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  // Both sibling edges survive (the pre-fix reader dropped them all).
  assert.ok(impactClosure(graph, ['pkg/x.py']).has('pkg/main.py'), 'continuation name x binds pkg/x.py, not the parent')
  assert.ok(impactClosure(graph, ['pkg/y.py']).has('pkg/main.py'), 'continuation name y binds pkg/y.py, not the parent')
  // Reverse pin: the parent-package files gain NO edge — the pre-fix '..x'
  // join manufactured exactly these pseudo-edges.
  assert.ok(!impactClosure(graph, ['x.py']).has('pkg/main.py'), 'no parent-package x.py edge from the continuation reader')
  assert.ok(!impactClosure(graph, ['y.py']).has('pkg/main.py'), 'no parent-package y.py edge from the continuation reader')
  // The package's own edge survives as always.
  assert.ok(impactClosure(graph, ['pkg/__init__.py']).has('pkg/main.py'), 'the module site binds the package __init__')
  // Site-level KAT of the specifiers actually minted (the off-by-one itself):
  // each continuation name is '.x'/'.y' — never '..x'/'..y'.
  const sites = extractImportSites('from . import (\n    x,\n    y,\n)\n')
  assert.deepEqual(sites.map(s => s.specifier), ['.', '.x', '.y'], 'module site "." + name sites ".x"/".y" — never "..x"/"..y"')
})

// ---------------------------------------------------------------------------
// V7-L1/L2 — the two Python shapes the X-H-17(b) doctrine and the no-space
// spelling exposed. (L1) a bare dot-run's module site took the FIRST
// candidate only, so a mixed tree (`pkg.ts` AND `pkg/__init__.py`) connected
// one file; the doctrine five lines below it is "every hit adds its own
// edge". (L2) `from .import x` — legal Python, no space after the dot-run —
// lost the whole site to greedy regex backtracking.
// ---------------------------------------------------------------------------

test('V7-L1: a bare dot-run module site connects EVERY existing candidate in a mixed tree', async () => {
  const files = {
    // Both readings exist on disk: the TS module and the Python package.
    '/ws/pkg.ts': 'export const p = 1\n',
    '/ws/pkg/__init__.py': 'P = 1\n',
    '/ws/pkg/main.py': 'from . import x\n',
    '/ws/pkg/x.py': 'X = 1\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  assert.ok(impactClosure(graph, ['pkg/__init__.py']).has('pkg/main.py'), 'the package __init__ keeps its edge (probe order first)')
  assert.ok(impactClosure(graph, ['pkg.ts']).has('pkg/main.py'), 'the mixed-tree pkg.ts keeps its edge too (firstKnown used to drop it)')
  // Single-hit trees are unchanged: still exactly the one candidate.
  const solo = {
    '/ws/solo/__init__.py': '',
    '/ws/solo/main.py': 'from . import x\n',
    '/ws/solo/x.py': 'X = 1\n',
  }
  const g2 = await buildDependencyGraph(MemoryFs.of(solo), '/ws', Object.keys(solo).map(stripRoot))
  assert.ok(impactClosure(g2, ['solo/__init__.py']).has('solo/main.py'), 'single-hit resolution is untouched')
})

test('V7-L2: `from .import x` (no space after the dot-run) carries the same edges as the spaced form', async () => {
  const files = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/main.py': 'from .import x\n',
    '/ws/pkg/x.py': 'X = 1\n',
    '/ws/x.py': 'PARENT = 1\n',
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  assert.ok(impactClosure(graph, ['pkg/x.py']).has('pkg/main.py'), 'the no-space form binds the sibling pkg/x.py')
  assert.ok(impactClosure(graph, ['pkg/__init__.py']).has('pkg/main.py'), 'the module site still binds the package')
  assert.ok(!impactClosure(graph, ['x.py']).has('pkg/main.py'), 'and still never the parent package')
  // Multi-dot no-space form climbs the right number of levels.
  const files2 = {
    '/ws/pkg/__init__.py': '',
    '/ws/pkg/sub/__init__.py': '',
    '/ws/pkg/sub/deep.py': 'from ..import x\n',
    '/ws/pkg/x.py': 'X = 1\n',
  }
  const g2 = await buildDependencyGraph(MemoryFs.of(files2), '/ws', Object.keys(files2).map(stripRoot))
  assert.ok(impactClosure(g2, ['pkg/x.py']).has('pkg/sub/deep.py'), 'from ..import x climbs exactly one level out of the subpackage')
  // Site-level: the specifier is the dot-run, not a mangled module name.
  const sites = extractImportSites('from .import x\n')
  assert.deepEqual(sites.map(s => s.specifier), ['.', '.x'], 'module site "." + name site ".x" — the greedy-eaten site is back')
})

test('H-24/M-28: two imports on one line both carry edges — the second is not invisible', async () => {
  const files = {
    '/ws/a.ts': 'export const a = 1\n',
    '/ws/b.ts': 'export const b = 1\n',
    '/ws/multi.ts': "import { a } from './a'; import { b } from './b'\n",
    '/ws/req.ts': "const x = require('./a'), y = require('./b')\n",
  }
  const fs = MemoryFs.of(files)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(files).map(stripRoot))
  assert.ok(impactClosure(graph, ['a.ts']).has('multi.ts'), 'first in-line import binds')
  assert.ok(impactClosure(graph, ['b.ts']).has('multi.ts'), 'SECOND in-line import binds too (used to be dropped)')
  assert.ok(impactClosure(graph, ['a.ts']).has('req.ts'), 'first in-line require binds')
  assert.ok(impactClosure(graph, ['b.ts']).has('req.ts'), 'SECOND in-line require binds too')
  // And the sites exist for the LSP channel as well (positions verifiable).
  const sites = extractImportSites(files['/ws/multi.ts'] as string)
  assert.deepEqual(sites.map(s => s.specifier), ['./a', './b'])
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

test('M9: unsupported glob shapes match everything — a check scoped like src/**/*.ts is never silently dead', () => {
  // The five supported forms keep their exact semantics:
  assert.ok(matches('src/a/b.ts', 'src/**'), 'terminal dir/** form unchanged')
  assert.ok(!matches('srcx/a.ts', 'src/**'), 'terminal dir/** form unchanged (no prefix bleed)')
  assert.ok(matches('src/a.ts', 'src/*'), 'terminal dir/* form unchanged')
  assert.ok(!matches('src/a/b.ts', 'src/*'), 'terminal dir/* form unchanged (direct children only)')
  assert.ok(matches('anything', '*'), 'bare * still matches everything')
  assert.ok(matches('src/a.ts', 'src/a.ts'), 'pure literal: exact match')
  assert.ok(!matches('src/other.ts', 'src/a.ts'), 'pure literal: no accidental sibling match')

  // Everything else that LOOKS like a glob is over-inclusive: the old matcher
  // compared these as literal prefixes, a shape no real file ever has — so a
  // check configured with src/**/*.ts simply never ran. A dead check wearing
  // a live one's configuration. The conservative direction is to run it.
  assert.ok(matches('src/a/b.ts', 'src/**/*.ts'), 'mid-pattern ** used to silently match nothing')
  assert.ok(matches('docs/readme.md', 'src/**/*.ts'), 'the fallback is TOTAL: a filter we cannot interpret selects everything')
  assert.ok(matches('anything/x.ts', 'a?b.ts'), '? is not interpretable — match')
  assert.ok(matches('anything/x.ts', '{a,b}'), 'brace groups are not interpretable — match')
  assert.ok(matches('anything/x.ts', '[abc].ts'), 'character classes are not interpretable — match')
  assert.ok(matches('anything/x.ts', '**'), 'a bare ** is not the terminal dir/** form — match')
  assert.ok(matches('src/x.ts', 'src/*.ts'), 'a star glued to text is not the dir/* form — match')
})

test('M9: selection runs the previously-dead deep-glob check instead of burying it', async () => {
  const fs = MemoryFs.of(TREE)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(TREE).map(stripRoot))
  const checks = [
    spec({ id: 'deep-glob', paths: ['src/**/*.ts'] }),
    spec({ id: 'docs-check', paths: ['docs/**'] }),
  ]
  const result = selectAffectedChecks(checks, ['src/c.ts'], graph)
  assert.equal(result.uncertain, false, 'the change is fully in-graph — only the glob shape decides')
  assert.deepEqual(result.affected.map(c => c.id), ['deep-glob'], 'the unsupported-glob check is selected, not skipped')
  assert.deepEqual(result.untouched.map(c => c.id), ['docs-check'], 'a supported narrow form still narrows honestly')
})

test('M-26: `./`- and `/`-prefixed patterns are normalised, not silently dead', () => {
  // RelPaths never start with `./` or `/`, but users write both in config —
  // the most natural spelling (`paths: ['./src/**']`) used to literal-compare
  // `./src/` against `src/...` and match NOTHING, forever, without ever
  // falling back to the conservative everything-match: a dead check wearing
  // a live one's configuration (the M9 failure resurrected through a dot).
  assert.ok(matches('src/a/b.ts', './src/**'), './-prefixed /** normalises to the supported form')
  assert.ok(matches('src/a.ts', './src/*'), './-prefixed /* normalises')
  assert.ok(matches('src/a.ts', './src/a.ts'), './-prefixed literal normalises')
  assert.ok(!matches('docs/readme.md', './src/**'), 'a normalised narrow pattern still narrows honestly')
  assert.ok(matches('anything/x.ts', '/src/**/*.ts'), 'a /-prefixed unsupported shape still falls back to everything')
  assert.ok(matches('src/a.ts', '././src/**'), 'repeated ./ segments are all stripped')
  assert.ok(matches('anything', './**'), './** normalises to the bare ** wildcard fallback')
  assert.ok(matches('anything', './'), 'a pattern that normalises to nothing cannot mean a filter — match everything')
  // The unprefixed canon is byte-identical to before.
  assert.ok(matches('src/a/b.ts', 'src/**') && !matches('srcx/a.ts', 'src/**'))
})

test('M-26: selection honours a `./`-prefixed narrow path filter end to end', async () => {
  const fs = MemoryFs.of(TREE)
  const graph = await buildDependencyGraph(fs, '/ws', Object.keys(TREE).map(stripRoot))
  const checks = [
    spec({ id: 'src-check', paths: ['./src/**'] }),
    spec({ id: 'docs-check', paths: ['docs/**'] }),
  ]
  const result = selectAffectedChecks(checks, ['src/c.ts'], graph)
  assert.equal(result.uncertain, false)
  assert.deepEqual(result.affected.map(c => c.id), ['src-check'], 'the ./-prefixed check is selectable, not dead')
  assert.deepEqual(result.untouched.map(c => c.id), ['docs-check'])
})

test('W14-L9: wildcard-all spellings that normalise to `*` are live, not dead', () => {
  // `./*`, `/*` and `*/` all normalise to the bare wildcard, but the
  // wildcard-all judgement used to run on the PRE-normalisation string —
  // these three fell through to the literal comparison (`file === '*'`) and
  // matched nothing, while their empty-residue sibling `./` matched
  // everything. One family of spellings, one reading: wildcard-all.
  for (const pattern of ['*', './*', '/*', '*/', './']) {
    assert.ok(matches('src/a.ts', pattern), `pattern ${JSON.stringify(pattern)} matches everything`)
    assert.ok(matches('docs/readme.md', pattern), `pattern ${JSON.stringify(pattern)} matches everything`)
  }
  // The narrow prefixed forms keep their exact semantics (no bleed).
  assert.ok(!matches('docs/readme.md', './src/**'), 'normalised narrow forms still narrow')
  assert.ok(matches('src/a.ts', './src/*'), 'direct children still match ./src/*')
  // And `./*` itself, once normalised, IS wildcard-all — it cannot mean
  // "root children only" in the five-form canon, and the fallback direction
  // for an uninterpretable intent is over-inclusion (M9), same as `./`.
  assert.ok(matches('src/a/b.ts', './*'), 'deep files match ./* — normalised to wildcard-all, over-inclusive by design')
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

test('M8: walkTruncated ORs into graph.truncated and the selection degrades to uncertain (all checks run)', async () => {
  const fs = MemoryFs.of(TREE)
  const files = Object.keys(TREE).map(stripRoot)
  // Contrast first: same files, no walk truncation — the graph is complete.
  const honest = await buildDependencyGraph(fs, '/ws', files)
  assert.equal(honest.truncated, false, 'no local cap fired and the walk said nothing — complete graph')
  // The builder cannot see the walk's limit itself; the caller must tell it.
  const fromTruncatedWalk = await buildDependencyGraph(fs, '/ws', files, { walkTruncated: true })
  assert.equal(fromTruncatedWalk.truncated, true, 'the walk\'s truncation ORs into the graph flag')
  assert.equal(fromTruncatedWalk.scanned, honest.scanned, 'the builder scanned its whole input — the flag is purely propagated')

  // Pin the widening behaviour: an in-graph change with a narrowly-scoped
  // check still selects EVERYTHING, because the node set is a prefix of the
  // workspace, not a census — a missing node could hide any dependency.
  const checks = [
    spec({ id: 'src-check', paths: ['src/**'] }),
    spec({ id: 'docs-check', paths: ['docs/**'] }),
  ]
  const result = selectAffectedChecks(checks, ['src/c.ts'], fromTruncatedWalk)
  assert.equal(result.uncertain, true, 'a truncated graph makes every selection uncertain')
  assert.deepEqual(result.affected.map(c => c.id).sort(), ['docs-check', 'src-check'], 'uncertainty widens to ALL checks')
  assert.deepEqual(result.untouched, [], 'nothing may be declared untouched over a partial node set')
})

test('M8: MemoryFs walk returns the truncation shape (files + truncated round-trip)', async () => {
  const fs = MemoryFs.of({ '/ws/src/a.ts': 'a', '/ws/src/b.ts': 'b', '/ws/src/sub/c.ts': 'c' })
  const full = await fs.walk('/ws', { ignoreDirs: ['node_modules'] })
  assert.deepEqual([...full.files], ['src/a.ts', 'src/b.ts', 'src/sub/c.ts'])
  assert.equal(full.truncated, false, 'below the limit: complete listing, no truncation')

  const capped = await fs.walk('/ws', { limit: 2 })
  assert.equal(capped.files.length, 2)
  assert.equal(capped.truncated, true, 'the limit was hit — the fake mirrors the real port\'s conservative answer')

  const exact = await fs.walk('/ws', { limit: 3 })
  assert.deepEqual([...exact.files], [...full.files])
  assert.equal(exact.truncated, true, 'hitting the cap exactly is still truncation, as in NodeFsPort')
})

test('MemoryFs.stat mtimeMs: fresh files are 0, mutations bump an instance counter', async () => {
  const fs = MemoryFs.of({ '/ws/src/a.ts': 'export const a = 1\n' })
  assert.equal((await fs.stat('/ws/src/a.ts'))?.mtimeMs, 0, 'never-mutated paths keep the historical 0')
  fs.mutate('/ws/src/a.ts', 'export const a = 2\n')
  const first = (await fs.stat('/ws/src/a.ts'))?.mtimeMs
  assert.ok(first !== undefined && first > 0, 'a mutation is visible in the version clock')
  fs.mutate('/ws/src/a.ts', 'export const a = 3 // same length?\n')
  const second = (await fs.stat('/ws/src/a.ts'))?.mtimeMs
  assert.ok(second !== undefined && second > first, 'mtime advances even when the size could stay equal — the LSP version cache must invalidate')
})

function stripRoot(path: string): string {
  return path.replace(/^\/ws\/?/, '')
}
