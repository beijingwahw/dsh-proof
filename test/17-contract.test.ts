/**
 * CONTRACT (ε) — typed claim contracts bind each ClaimKind to its own evidence
 * obligations. These tests pin the three layers the contract adds:
 *
 * 1. the API-surface extractor (all five export forms, the over-report bias,
 *    multi-line lists, comment skipping, sort+dedupe) and its diff;
 * 2. the docs-path classifier (doc extensions vs code vs the global
 *    invalidators that can hide inside a doc extension);
 * 3. the obligation matrix of `evaluateContract` for every kind — met and
 *    unmet paths, fixed obligation ids and order, the jury cap, and the
 *    determinism the evidence chain demands.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  diffApiSurface, evaluateContract, extractApiSurface, isDocsPath,
  type ClaimContract, type ContractInput, type ContractVerdict,
} from '../src/core/contract.ts'
import { buildBaseline, makeEvidence, snapshotWorkspace, type Evidence } from '../src/core/evidence.ts'
import type { CheckSpec } from '../src/core/ports.ts'
import { FakeClock, spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', [])
const clock = new FakeClock()

function ev(s: CheckSpec, status: 'pass' | 'fail', durationMs = 10): Evidence {
  return makeEvidence(s, { status, exitCode: status === 'pass' ? 0 : 1, durationMs, output: 'ok' }, WS, clock)
}

function contract(kind: ClaimContract['kind'], extra: Partial<ClaimContract> = {}): ClaimContract {
  return { kind, claim: 'did the thing', ...extra }
}

function input(over: Partial<ContractInput> = {}): ContractInput {
  return {
    contract: contract('behavior-preserving'),
    changed: [],
    specs: [],
    records: [],
    baseline: undefined,
    apiSurfaceBefore: undefined,
    apiSurfaceAfter: undefined,
    graph: undefined,
    ...over,
  }
}

function byId(verdict: ContractVerdict, id: string) {
  const found = verdict.obligations.find(o => o.id === id)
  assert.ok(found, `obligation ${id} present in ${verdict.obligations.map(o => o.id).join(', ')}`)
  return found
}

// ---------------------------------------------------------------------------
// extractApiSurface
// ---------------------------------------------------------------------------

test('extractApiSurface: the five export forms, one of each, sorted', () => {
  const surface = extractApiSurface([{ rel: 'src/a.ts', content: [
    'export const x = 1',
    'export let y = 2',
    'export var z = 3',
    'export function f() {}',
    'export async function g() {}',
    'export class C {}',
    'export abstract class D {}',
    'export interface I {}',
    'export type T = number',
    'export enum E { A }',
    'export const enum CE { B }',
    'export function* gen() {}',
    'export { a, b as c }',
    'export default 42',
    "export * from './x'",
    'export = CjsThing',
  ].join('\n') }])
  assert.deepEqual(surface, [
    'src/a.ts#*',
    'src/a.ts#=',
    'src/a.ts#C',
    'src/a.ts#CE',
    'src/a.ts#D',
    'src/a.ts#E',
    'src/a.ts#I',
    'src/a.ts#T',
    'src/a.ts#a',
    'src/a.ts#c',
    'src/a.ts#default',
    'src/a.ts#f',
    'src/a.ts#g',
    'src/a.ts#gen',
    'src/a.ts#x',
    'src/a.ts#y',
    'src/a.ts#z',
  ])
})

test('extractApiSurface: multi-line export lists, aliases and comments inside them', () => {
  const surface = extractApiSurface([{ rel: 'm.ts', content: [
    'export {',
    '  alpha,',
    '  // comment inside the list',
    '  beta as gamma,',
    '  delta,',
    "} from './other'",
  ].join('\n') }])
  // `beta as c` exports the ALIAS — that is the name importers bind.
  assert.deepEqual(surface, ['m.ts#alpha', 'm.ts#delta', 'm.ts#gamma'])
})

test('W15-M4: inline `export { type X }` names the type on the surface — the type face cannot move silently', () => {
  // TS ≥ 4.5 inline type modifiers (the isolatedModules/verbatimModuleSyntax
  // house style). The token `type Foo` failed the IDENTIFIER test wholesale,
  // so both before and after read the same (empty) surface and
  // api-surface-unchanged was vacuously met while the public TYPE face moved.
  const surface = extractApiSurface([{ rel: 't.ts', content: [
    'export { type Foo }',
    'export { type Bar as Baz }',
    "export { type Qux, value } from './dep'",
    'export type Named = number',   // declaration form — already worked
    'export { plain }',
  ].join('\n') }])
  assert.deepEqual(surface, [
    't.ts#Baz',
    't.ts#Foo',
    't.ts#Named',
    't.ts#Qux',
    't.ts#plain',
    't.ts#value',
  ])
  // A binding genuinely NAMED `type` survives (the strip needs whitespace).
  const named = extractApiSurface([{ rel: 'n.ts', content: 'export { type, other }' }])
  assert.deepEqual(named, ['n.ts#other', 'n.ts#type'])
  // And the surface diff actually fires on a type-only move (regression KAT
  // for the vacuous-pass this fix closes).
  const before = extractApiSurface([{ rel: 't.ts', content: 'export { type Foo }\nexport { keep }' }])
  const after = extractApiSurface([{ rel: 't.ts', content: 'export { type Renamed }\nexport { keep }' }])
  const diff = diffApiSurface(before, after)
  assert.deepEqual(diff, { added: ['t.ts#Renamed'], removed: ['t.ts#Foo'] })
})

test('extractApiSurface: comment lines are skipped', () => {
  const surface = extractApiSurface([{ rel: 'c.ts', content: [
    '// export const commented = 1',
    '/* export class Ghost {} */',
    '* export type Star = void',
    'export const real = 1',
  ].join('\n') }])
  assert.deepEqual(surface, ['c.ts#real'])
})

test('extractApiSurface: sorted, deduped across files', () => {
  const surface = extractApiSurface([
    { rel: 'b.ts', content: 'export const same = 1\nexport const same = 2' },
    { rel: 'a.ts', content: 'export const zzz = 1' },
  ])
  assert.deepEqual(surface, ['a.ts#zzz', 'b.ts#same'])
})

test('extractApiSurface: export * as ns records the wildcard face AND the namespace binding', () => {
  const surface = extractApiSurface([{ rel: 's.ts', content: "export * as ns from './x'" }])
  assert.deepEqual(surface, ['s.ts#*', 's.ts#ns'])
})

test('extractApiSurface: export default records #default even when the default is a function', () => {
  const surface = extractApiSurface([{ rel: 'd.ts', content: 'export default function foo() {}' }])
  assert.deepEqual(surface, ['d.ts#default'])
})

test('extractApiSurface: over-report bias — multi-declarator lists report every name', () => {
  const surface = extractApiSurface([{ rel: 'md.ts', content: 'export const p = 1, q = 2' }])
  assert.deepEqual(surface, ['md.ts#p', 'md.ts#q'])
})

test('extractApiSurface: over-report without phantoms — arrow-function commas add nothing', () => {
  const surface = extractApiSurface([{ rel: 'ar.ts', content: 'export const cb = (a, b) => a + b' }])
  assert.deepEqual(surface, ['ar.ts#cb'])
})

test('extractApiSurface: destructuring exports over-report every pattern identifier', () => {
  const surface = extractApiSurface([{ rel: 'de.ts', content: 'export const { a, b: x } = obj' }])
  assert.deepEqual(surface, ['de.ts#a', 'de.ts#b', 'de.ts#x'])
})

test('extractApiSurface: string aliases are kept verbatim', () => {
  const surface = extractApiSurface([{ rel: 'q.ts', content: 'export { a as "weird-name" }' }])
  assert.deepEqual(surface, ['q.ts#weird-name'])
})

// ---------------------------------------------------------------------------
// extractApiSurface — typed exports (H4)
//
// The un-annotated samples above must stay byte-identical forever (they are
// the compat red line); the samples below are the blind spot those left: a
// capture that required `identifier =` silently dropped every annotated
// declarator, so `behavior-preserving` claims over idiomatic TypeScript saw a
// permanently empty surface diff — vacuously met. The phantom side of the same
// coin: a destructuring declaration's TYPE read as a name (`Foo` below).
// ---------------------------------------------------------------------------

test('extractApiSurface: THE TYPED EXPORT — a type annotation must not hide a name', () => {
  const surface = extractApiSurface([{ rel: 'tx.ts', content: [
    'export const x: number = 1',
    'export let y: string = "s"',
    'export declare const d: number',
    'export var flag: boolean',
    'export const bare: number',
  ].join('\n') }])
  assert.deepEqual(surface, ['tx.ts#bare', 'tx.ts#d', 'tx.ts#flag', 'tx.ts#x', 'tx.ts#y'])
})

test('extractApiSurface: THE TYPED DESTRUCTURING — pattern names in, annotation phantom out', () => {
  const surface = extractApiSurface([{ rel: 'ph.ts', content: 'export const { a, b }: Foo = obj' }])
  // `Foo` is the type of the whole pattern, not an export; before the fix it
  // surfaced as a phantom symbol while the real names rode along by accident.
  assert.deepEqual(surface, ['ph.ts#a', 'ph.ts#b'])
  assert.ok(!surface.some(n => n.includes('Foo')))
})

test('extractApiSurface: a typed array pattern keeps its elements and drops its annotation', () => {
  const surface = extractApiSurface([{ rel: 'ta.ts', content: 'export const [p, q]: [number, string] = pair' }])
  // The annotation's own `[number, string]` commas must not shatter the
  // declarator, and `number`/`string` must not surface as names.
  assert.deepEqual(surface, ['ta.ts#p', 'ta.ts#q'])
})

test('extractApiSurface: a mixed declarator list reports annotated and plain names alike', () => {
  const surface = extractApiSurface([{ rel: 'mx.ts', content: 'export const p = 1, q: number = 2' }])
  assert.deepEqual(surface, ['mx.ts#p', 'mx.ts#q'])
})

test('extractApiSurface: typed and untyped destructuring agree on the pattern names', () => {
  const untyped = extractApiSurface([{ rel: 'u.ts', content: 'export const { a, b: x } = obj' }])
  const typed = extractApiSurface([{ rel: 'v.ts', content: 'export const { a, b: x }: Shape = obj' }])
  assert.deepEqual(untyped, ['u.ts#a', 'u.ts#b', 'u.ts#x'])
  assert.deepEqual(typed, ['v.ts#a', 'v.ts#b', 'v.ts#x'])
  assert.ok(!typed.some(n => n.includes('Shape')))
})

test('extractApiSurface: nested patterns report their inner names, annotation aside', () => {
  const surface = extractApiSurface([{ rel: 'n.ts', content: 'export const { a: { b }, c: [d] }: Shape = shape' }])
  assert.deepEqual(surface, ['n.ts#a', 'n.ts#b', 'n.ts#c', 'n.ts#d'])
})

test('extractApiSurface: annotated arrow parameters still stay inside the initializer', () => {
  // The annotation-tolerant capture could have made `b` (a typed parameter)
  // look like a declarator head; segment-level comma splitting keeps it — and
  // every other initializer comma — out of the surface.
  const surface = extractApiSurface([{ rel: 'tp.ts', content: 'export const cb = (a: number, b: string) => a + b' }])
  assert.deepEqual(surface, ['tp.ts#cb'])
})

test('extractApiSurface: an annotated declarator after a plain one in the same list', () => {
  const surface = extractApiSurface([{ rel: 'ml.ts', content: 'export const x: number = 1, y = 2' }])
  assert.deepEqual(surface, ['ml.ts#x', 'ml.ts#y'])
})

// ---------------------------------------------------------------------------
// diffApiSurface
// ---------------------------------------------------------------------------

test('diffApiSurface: both directions, sorted', () => {
  const diff = diffApiSurface(['a.ts#x', 'a.ts#y'], ['a.ts#y', 'b.ts#z', 'a.ts#w'])
  assert.deepEqual(diff, { added: ['a.ts#w', 'b.ts#z'], removed: ['a.ts#x'] })
})

test('diffApiSurface: empty sets and identity', () => {
  assert.deepEqual(diffApiSurface([], []), { added: [], removed: [] })
  const same = ['a.ts#x', 'b.ts#y']
  assert.deepEqual(diffApiSurface(same, [...same]), { added: [], removed: [] })
  assert.deepEqual(diffApiSurface([], ['c#1', 'a#2']), { added: ['a#2', 'c#1'], removed: [] })
})

// ---------------------------------------------------------------------------
// isDocsPath
// ---------------------------------------------------------------------------

test('isDocsPath: documentation assets are docs, code is not', () => {
  assert.equal(isDocsPath('README.md'), true)
  assert.equal(isDocsPath('docs/guide.markdown'), true)
  assert.equal(isDocsPath('docs/img/arch.png'), true)
  assert.equal(isDocsPath('notes.txt'), true)
  assert.equal(isDocsPath('src/a.ts'), false)
  assert.equal(isDocsPath('scripts/run.py'), false)
  assert.equal(isDocsPath('style.css'), false)
})

test('isDocsPath: global invalidators are never docs — even with a docs extension', () => {
  assert.equal(isDocsPath('package-lock.yaml'), false)
  assert.equal(isDocsPath('package.json'), false)
  // The interesting case: requirements-dev.txt carries the .txt docs extension
  // but is exactly the dependency declaration whose change kills every check.
  assert.equal(isDocsPath('requirements-dev.txt'), false)
  assert.equal(isDocsPath('requirements.txt'), false)
})

// ---------------------------------------------------------------------------
// evaluateContract — behavior-preserving
// ---------------------------------------------------------------------------

test('behavior-preserving: identical surface + green run meets both obligations', () => {
  const s = spec({ id: 'c1' })
  const v = evaluateContract(input({
    contract: contract('behavior-preserving'),
    specs: [s],
    baseline: buildBaseline([ev(s, 'pass')], WS, clock),
    records: [ev(s, 'pass')],
    apiSurfaceBefore: ['a.ts#x', 'a.ts#y'],
    apiSurfaceAfter: ['a.ts#x', 'a.ts#y'],
  }))
  assert.equal(v.kind, 'behavior-preserving')
  assert.equal(v.skipChecks, false)
  assert.equal(v.juryCappedConfidence, undefined)
  assert.deepEqual(v.obligations.map(o => o.id), ['zero-regressions', 'api-surface-unchanged'])
  assert.ok(v.obligations.every(o => o.met), v.obligations.map(o => o.detail).join(' | '))
})

test('behavior-preserving: an added export fails api-surface-unchanged and names the symbol', () => {
  const v = evaluateContract(input({
    contract: contract('behavior-preserving'),
    apiSurfaceBefore: ['a.ts#x'],
    apiSurfaceAfter: ['a.ts#x', 'a.ts#y'],
  }))
  const o = byId(v, 'api-surface-unchanged')
  assert.equal(o.met, false)
  assert.match(o.detail, /a\.ts#y/)
})

test('behavior-preserving: a removed export fails too', () => {
  const v = evaluateContract(input({
    contract: contract('behavior-preserving'),
    apiSurfaceBefore: ['a.ts#x', 'a.ts#gone'],
    apiSurfaceAfter: ['a.ts#x'],
  }))
  const o = byId(v, 'api-surface-unchanged')
  assert.equal(o.met, false)
  assert.match(o.detail, /a\.ts#gone/)
})

test('behavior-preserving: a baseline without a captured surface cannot attest preservation', () => {
  const v = evaluateContract(input({
    contract: contract('behavior-preserving'),
    apiSurfaceAfter: ['a.ts#x'],
  }))
  const o = byId(v, 'api-surface-unchanged')
  assert.equal(o.met, false)
  assert.match(o.detail, /proof_baseline/)
})

test('behavior-preserving: a missing current surface is the engine\u2019s failure, said out loud', () => {
  const v = evaluateContract(input({
    contract: contract('behavior-preserving'),
    apiSurfaceBefore: ['a.ts#x'],
    apiSurfaceAfter: undefined,
  }))
  const o = byId(v, 'api-surface-unchanged')
  assert.equal(o.met, false)
  assert.match(o.detail, /apiSurfaceAfter/)
})

// ---------------------------------------------------------------------------
// evaluateContract — behavior-adding
// ---------------------------------------------------------------------------

test('behavior-adding: a passing check covering the new source path meets new-paths-covered', () => {
  const cover = spec({ id: 'cover', paths: ['src/**'] })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    changed: ['src/new.ts', 'README.md'], // README is not source, so it needs no check
    specs: [cover],
    records: [ev(cover, 'pass')],
  }))
  assert.deepEqual(v.obligations.map(o => o.id), ['zero-regressions', 'new-paths-covered'])
  assert.ok(v.obligations.every(o => o.met))
})

test('behavior-adding: a path no check covers is named with the fix hint', () => {
  const cover = spec({ id: 'cover', paths: ['docs/**'] })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    changed: ['src/new.ts'],
    specs: [cover],
    records: [ev(cover, 'pass')],
  }))
  const o = byId(v, 'new-paths-covered')
  assert.equal(o.met, false)
  assert.match(o.detail, /src\/new\.ts/)
  assert.match(o.detail, /add a check/)
})

test('behavior-adding: a covering check that never passed does not count', () => {
  const cover = spec({ id: 'cover', paths: ['src/**'] })
  const stalled = makeEvidence(cover, { status: 'timeout', exitCode: null, durationMs: 0, output: '' }, WS, clock)
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    changed: ['src/new.ts'],
    specs: [cover],
    records: [stalled],
  }))
  assert.equal(byId(v, 'new-paths-covered').met, false)
})

test('behavior-adding: no source paths in the change set trivially meets coverage', () => {
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    changed: ['README.md', 'assets/logo.png'],
  }))
  const o = byId(v, 'new-paths-covered')
  assert.equal(o.met, true)
  assert.match(o.detail, /no source paths/)
})

// ---------------------------------------------------------------------------
// evaluateContract — perf-budget
// ---------------------------------------------------------------------------

test('perf-budget: a passing benchmark within budget meets both obligations', () => {
  const bench = spec({ id: 'bench1', kind: 'benchmark' })
  const v = evaluateContract(input({
    contract: contract('perf-budget', { budgetMs: 200 }),
    specs: [bench],
    records: [ev(bench, 'pass', 120)],
  }))
  assert.deepEqual(v.obligations.map(o => o.id), ['zero-regressions', 'benchmark-evidence', 'within-budget'])
  assert.ok(v.obligations.every(o => o.met))
})

test('perf-budget: over budget fails within-budget, but the measurement still counts as evidence', () => {
  const bench = spec({ id: 'bench1', kind: 'benchmark' })
  const v = evaluateContract(input({
    contract: contract('perf-budget', { budgetMs: 100 }),
    records: [ev(bench, 'fail', 300)],
  }))
  assert.equal(byId(v, 'benchmark-evidence').met, true, 'a decisive fail is still a measurement')
  const w = byId(v, 'within-budget')
  assert.equal(w.met, false)
  assert.match(w.detail, /300ms/)
})

test('perf-budget: no benchmark evidence fails benchmark-evidence with the config hint', () => {
  const t = spec({ id: 't1' })
  const v = evaluateContract(input({
    contract: contract('perf-budget', { budgetMs: 100 }),
    specs: [t],
    records: [ev(t, 'pass', 5)],
  }))
  const o = byId(v, 'benchmark-evidence')
  assert.equal(o.met, false)
  assert.match(o.detail, /kind: benchmark/)
  assert.equal(byId(v, 'within-budget').met, false)
})

test('perf-budget: a missing budgetMs fails within-budget even with green evidence', () => {
  const bench = spec({ id: 'bench1', kind: 'benchmark' })
  const v = evaluateContract(input({
    contract: contract('perf-budget'),
    records: [ev(bench, 'pass', 5)],
  }))
  const o = byId(v, 'within-budget')
  assert.equal(o.met, false)
  assert.match(o.detail, /budgetMs/)
})

test('H-29: a non-finite or non-positive budgetMs is refused — the budget must be able to bind', () => {
  // `1e999` parses to Infinity and used to sail through: `durationMs >
  // Infinity` is always false, so "the benchmark stayed in budget" was
  // vacuously met for ANY duration — a performance claim's budget component
  // was decorative, and the detail even printed "Infinityms". A budget that
  // cannot bind is a misdelivery of the contract: not-met, with the fix.
  const bench = spec({ id: 'bench1', kind: 'benchmark' })
  for (const bad of [
    Number.POSITIVE_INFINITY, // JSON.parse('1e999')
    Number.NaN,
    0,
    -100,
  ]) {
    const v = evaluateContract(input({
      contract: contract('perf-budget', { budgetMs: bad }),
      records: [ev(bench, 'pass', 999_999)],
    }))
    const o = byId(v, 'within-budget')
    assert.equal(o.met, false, `budgetMs ${bad} must not be met`)
    assert.match(o.detail, /finite positive/, `budgetMs ${bad}: ${o.detail}`)
    assert.equal(byId(v, 'benchmark-evidence').met, true, 'the measurement itself still counts')
  }
})

test('H-29: a benchmark record with a NaN duration cannot be "within" any budget', () => {
  // `durationMs > budget` is false for NaN — a broken-clock record slipped
  // through as within-budget. The comparison is now NaN-safe: only a real
  // `<= budget` counts as inside.
  const bench = spec({ id: 'bench1', kind: 'benchmark' })
  const v = evaluateContract(input({
    contract: contract('perf-budget', { budgetMs: 200 }),
    records: [ev(bench, 'pass', Number.NaN)],
  }))
  const o = byId(v, 'within-budget')
  assert.equal(o.met, false, 'a NaN duration is not within anything')
  assert.match(o.detail, /NaN/)
})

// ---------------------------------------------------------------------------
// evaluateContract — docs-only
// ---------------------------------------------------------------------------

test('docs-only: all-docs change + review meets everything and caps confidence at the default', () => {
  const v = evaluateContract(input({
    contract: contract('docs-only', { review: 'checked the wording against the actual flag names' }),
    changed: ['README.md', 'docs/img/arch.png'],
  }))
  assert.equal(v.skipChecks, true)
  assert.deepEqual(v.obligations.map(o => o.id), ['zero-regressions', 'docs-only-changes', 'jury-review'])
  assert.ok(v.obligations.every(o => o.met))
  assert.equal(v.juryCappedConfidence, 0.8)
})

test('docs-only: a custom jury cap is honoured verbatim', () => {
  const v = evaluateContract(input({
    contract: contract('docs-only', { review: 'fine' }),
    changed: ['README.md'],
  }), 0.5)
  assert.equal(v.juryCappedConfidence, 0.5)
})

test('docs-only: a .ts file in the change set fails docs-only-changes and withholds the cap', () => {
  const v = evaluateContract(input({
    contract: contract('docs-only', { review: 'fine' }),
    changed: ['README.md', 'src/a.ts'],
  }))
  const o = byId(v, 'docs-only-changes')
  assert.equal(o.met, false)
  assert.match(o.detail, /src\/a\.ts/)
  assert.equal(v.juryCappedConfidence, undefined)
})

test('docs-only: a blank review fails jury-review and withholds the cap', () => {
  const v = evaluateContract(input({
    contract: contract('docs-only', { review: '   ' }),
    changed: ['README.md'],
  }))
  assert.equal(byId(v, 'jury-review').met, false)
  assert.equal(v.juryCappedConfidence, undefined)
})

test('docs-only: zero-regressions is re-homed onto docs-only-changes when nothing ran', () => {
  const v = evaluateContract(input({
    contract: contract('docs-only', { review: 'fine' }),
    changed: ['README.md'],
  }))
  const o = byId(v, 'zero-regressions')
  assert.equal(o.met, true)
  assert.match(o.detail, /docs-only-changes/)
})

test('skipChecks is true only for docs-only', () => {
  for (const kind of ['behavior-preserving', 'behavior-adding', 'perf-budget'] as const) {
    assert.equal(evaluateContract(input({ contract: contract(kind) })).skipChecks, false, kind)
  }
  assert.equal(evaluateContract(input({ contract: contract('docs-only') })).skipChecks, true)
})

// ---------------------------------------------------------------------------
// evaluateContract — the shared zero-regressions floor
// ---------------------------------------------------------------------------

test('zero-regressions: a pass→fail flip is charged and the check is named', () => {
  const s = spec({ id: 'c1' })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    specs: [s],
    baseline: buildBaseline([ev(s, 'pass')], WS, clock),
    records: [ev(s, 'fail')],
    changed: ['src/a.ts'],
  }))
  const o = byId(v, 'zero-regressions')
  assert.equal(o.met, false)
  assert.match(o.detail, /c1/)
})

test('zero-regressions: a still-green run is met', () => {
  const s = spec({ id: 'c1' })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    specs: [s],
    baseline: buildBaseline([ev(s, 'pass')], WS, clock),
    records: [ev(s, 'pass')],
    changed: ['src/a.ts'],
  }))
  assert.equal(byId(v, 'zero-regressions').met, true)
})

test('zero-regressions: pre-existing red (fail→fail) is not a regression', () => {
  const s = spec({ id: 'c1' })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    specs: [s],
    baseline: buildBaseline([ev(s, 'fail')], WS, clock),
    records: [ev(s, 'fail')],
  }))
  assert.equal(byId(v, 'zero-regressions').met, true)
})

test('zero-regressions: checks with no record this run are outside the comparison', () => {
  const s = spec({ id: 'c1' })
  const v = evaluateContract(input({
    contract: contract('behavior-adding'),
    specs: [s, spec({ id: 'never-ran' })],
    baseline: buildBaseline([ev(s, 'pass')], WS, clock),
    records: [ev(s, 'pass')],
  }))
  assert.equal(byId(v, 'zero-regressions').met, true)
})

// ---------------------------------------------------------------------------
// determinism & tolerance
// ---------------------------------------------------------------------------

test('determinism: identical inputs produce byte-identical verdicts', () => {
  const s = spec({ id: 'c1' })
  const base = input({
    contract: contract('perf-budget', { budgetMs: 100 }),
    specs: [s],
    baseline: buildBaseline([ev(s, 'pass')], WS, clock),
    records: [ev(s, 'pass', 50)],
    changed: ['src/b.ts', 'src/a.ts'],
  })
  assert.deepEqual(evaluateContract(base), evaluateContract(base))
})

test('determinism: record order does not change the verdict', () => {
  const a = spec({ id: 'a' })
  const b = spec({ id: 'b' })
  const ra = ev(a, 'pass')
  const rb = ev(b, 'pass')
  const one = evaluateContract(input({ contract: contract('behavior-adding'), specs: [a, b], records: [ra, rb] }))
  const two = evaluateContract(input({ contract: contract('behavior-adding'), specs: [b, a], records: [rb, ra] }))
  assert.deepEqual(one, two)
})

test('the graph input is tolerated and never consulted', () => {
  const v = evaluateContract(input({ graph: { nodes: new Set(['src/a.ts']) } as never }))
  assert.ok(v.obligations.length > 0)
})
