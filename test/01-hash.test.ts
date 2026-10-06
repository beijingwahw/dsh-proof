import { test } from 'node:test'
import assert from 'node:assert/strict'

import { addressOf, canonicalJson, merkleRoot, normalizeOutput, sha256 } from '../src/core/hash.ts'

test('canonicalJson is key-order independent', () => {
  const a = { b: 1, a: { z: true, y: [3, 2, 1] } }
  const b = { a: { y: [3, 2, 1], z: true }, b: 1 }
  assert.equal(canonicalJson(a), canonicalJson(b))
  assert.equal(addressOf(a), addressOf(b))
})

test('canonicalJson drops undefined and normalises -0', () => {
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}')
  assert.equal(canonicalJson({ n: -0 }), canonicalJson({ n: 0 }))
  assert.equal(canonicalJson([1, undefined, 2]), '[1,null,2]')
})

test('addressOf is stable and collision-resistant across shapes', () => {
  assert.equal(addressOf({ a: 1 }), addressOf({ a: 1 }))
  assert.notEqual(addressOf({ a: 1 }), addressOf({ a: 2 }))
  assert.notEqual(addressOf({ a: 1 }), addressOf([1]))
})

test('merkleRoot is order independent but content sensitive', () => {
  const ids = ['aa', 'bb', 'cc']
  assert.equal(merkleRoot(ids), merkleRoot([...ids].reverse()))
  assert.notEqual(merkleRoot(ids), merkleRoot(['aa', 'bb', 'cd']))
  assert.equal(merkleRoot([]), sha256(''))
})

test('normalizeOutput removes cosmetic churn', () => {
  const raw = 'took 12ms to run\r\ndone   \n\n'
  const normalized = normalizeOutput(raw)
  assert.equal(normalized, 'took <duration> to run\ndone')

  const withPath = normalizeOutput('failed at /home/me/proj/src/a.ts', { root: '/home/me/proj' })
  assert.equal(withPath, 'failed at $WORKSPACE/src/a.ts')

  assert.equal(
    normalizeOutput('at 2026-10-04T12:00:00Z'),
    normalizeOutput('at 2026-10-05T09:30:11Z'),
  )
})

test('H-28: output that already carries a literal placeholder can never impersonate a folded one', () => {
  // The folds are many-to-one by design (every machine's real path becomes
  // `$WORKSPACE`), but an output that PRE-PRINTS the placeholder literal used
  // to be byte-identical to the folded product of a different, real output —
  // same outputDigest for different observables, breaking the
  // content-addressing promise for anyone who can shape a check's stdout.
  // Now such an output is marked with a one-line escape prefix, so the two
  // classes can never collide.
  const folded = normalizeOutput('err in C:/ws/src/a.ts', { root: 'C:/ws' })
  const preprinted = normalizeOutput('err in $WORKSPACE/src/a.ts', { root: 'C:/ws' })
  assert.equal(folded, 'err in $WORKSPACE/src/a.ts', 'the honest fold is unchanged')
  assert.ok(preprinted.startsWith('[raw output contained literal placeholders]\n'), 'the literal-bearing output is marked')
  assert.notEqual(folded, preprinted)
  assert.notEqual(sha256(folded), sha256(preprinted), 'different digests — same digest must imply same observable output')

  // The same holds for the duration/timestamp folds, and for $HOME.
  assert.notEqual(
    sha256(normalizeOutput('done in 12 ms')),
    sha256(normalizeOutput('done in <duration>')),
  )
  assert.notEqual(
    sha256(normalizeOutput('at 2026-10-04T12:00:00Z')),
    sha256(normalizeOutput('at <timestamp>')),
  )
  assert.notEqual(
    sha256(normalizeOutput('read /home/alice/f', { home: '/home/alice' })),
    sha256(normalizeOutput('read $HOME/f', { home: '/home/alice' })),
  )

  // Honest inputs (no literal placeholders anywhere) are byte-for-byte
  // unchanged — the marker only ever appears on the literal-bearing class.
  assert.ok(!normalizeOutput('took 12ms', {}).includes('[raw output'))
  assert.ok(!normalizeOutput('x'.repeat(100), { root: '/r' }).includes('[raw output'))
})

test('W14-M3: an output that PRE-PRINTS the marker line cannot collide with a marked one', () => {
  // The marker text itself carries neither `$WORKSPACE`/`$HOME` nor
  // `<duration>`/`<timestamp>`, so an output whose first line IS the marker
  // used to normalise to exactly `MARKER + folded body` — byte-equal to the
  // marked product of a genuinely literal-bearing output. The marker line is
  // in the detection set now: marker-bearing outputs normalise to
  // `MARKER + k marker lines + folded body` (k preserved in the text), a
  // class no k=0 output can reach.
  const forged = '[raw output contained literal placeholders]\ntook 5ms and 5ms too'
  const real = 'took 5ms and <duration> too'
  const a = normalizeOutput(forged)
  const b = normalizeOutput(real)
  assert.notEqual(a, b, 'the pre-printed marker line must not reopen the cross-class equality')
  assert.notEqual(sha256(a), sha256(b), 'different digests — same digest must imply same observable output')
  assert.equal(a.split('[raw output contained literal placeholders]').length - 1, 2, 'the forged marker line is itself marked (k = 1 visible beyond the prefix)')
  assert.equal(b.split('[raw output contained literal placeholders]').length - 1, 1, 'the literal-bearing honest output carries exactly the one prefix marker')

  // Two marker-line counts stay distinct from each other too (k lives in the bytes).
  assert.notEqual(
    sha256(normalizeOutput('[raw output contained literal placeholders]\nplain output')),
    sha256(normalizeOutput('[raw output contained literal placeholders]\n[raw output contained literal placeholders]\nplain output')),
  )
  // And honest literal-free output remains byte-identical to before this fix.
  assert.equal(normalizeOutput('plain output'), 'plain output')
})

test('normalised output addressing ignores cosmetic differences', () => {
  const a = normalizeOutput('x=1\n', { root: '/r' })
  const b = normalizeOutput('x=1 \r\n', { root: '/r' })
  assert.equal(sha256(a), sha256(b))
})

test('canonicalJson rejects circular structures with a clear error, DAGs stay legal', () => {
  const self: Record<string, unknown> = { name: 'a' }
  self.self = self
  assert.throws(() => canonicalJson(self), TypeError)
  assert.throws(() => canonicalJson(self), /circular structure cannot be canonicalised/)

  const cycle: unknown[] = [1]
  cycle.push(cycle)
  assert.throws(() => canonicalJson(cycle), /circular structure cannot be canonicalised/)
  // The public addressing API reports the same clear error instead of a
  // recursion-depth stack trace.
  assert.throws(() => addressOf(self), /circular structure cannot be canonicalised/)

  // A shared-but-acyclic reference is NOT a cycle: the guard tracks the
  // current path (add on enter, remove on exit), so DAGs canonicalise exactly
  // as they always did.
  const shared = { v: 1 }
  assert.equal(canonicalJson({ a: shared, b: shared }), '{"a":{"v":1},"b":{"v":1}}')
})

test('normalizeOutput folds drive-letter case drift (c:\\ws vs root C:/ws)', () => {
  const out = normalizeOutput('failed at c:\\ws\\src\\a.ts and c:/ws/src/b.ts', { root: 'C:/ws' })
  assert.equal(out, 'failed at $WORKSPACE/src/a.ts and $WORKSPACE/src/b.ts', 'either drive case, either slash style — one address')
  // The new variants stay boundary-anchored: a longer path sharing the prefix
  // is a different location, never this workspace.
  assert.equal(normalizeOutput('built c:/wsx/out.js', { root: 'C:/ws' }), 'built c:/wsx/out.js')
})

test('canonicalJson rejects values with no injective JSON rendering: bigint, symbol, function', () => {
  // Each of these used to fold onto some other value's rendering — 1n onto
  // the string "1", functions/symbols onto null — so distinct payloads
  // minted the SAME address (silent false dedupe). Now they refuse, naming
  // the culprit.
  for (const [label, value] of [
    ['bigint', 1n],
    ['symbol', Symbol('x')],
    ['function', () => 1],
  ] as const) {
    assert.throws(() => canonicalJson(value), TypeError, `${label} must throw`)
    assert.throws(() => canonicalJson(value), new RegExp(`${label} cannot be canonicalised`))
  }
  // Nested inside a legal structure, the exotic leaf still refuses — the
  // address of a container must not silently drop the odd field.
  assert.throws(() => canonicalJson([0, 1n]), /bigint cannot be canonicalised/)
  assert.throws(() => canonicalJson({ list: [/re/] }), /RegExp cannot be canonicalised/)
  // The public addressing API reports the same refusal, not a stack trace.
  assert.throws(() => addressOf({ v: 1n }), /bigint cannot be canonicalised/)
})

test('canonicalJson non-finite numbers fold to null — the documented M17 residual, not a throw', () => {
  // NaN/±Infinity alias null exactly like the rejected kinds, but the
  // checkpoint adjudication paths feed JSON.parse-derived numbers where a
  // forged "count":1e999 parses to Infinity: the fold's signature-verify
  // failure is the correct verdict there, and a throw would crash the audit
  // mid-walk (see the canonicalJson doc comment). This pins the interim
  // behavior so the future flip to a TypeError is a visible change here.
  assert.equal(canonicalJson(Number.NaN), 'null')
  assert.equal(canonicalJson(Number.POSITIVE_INFINITY), 'null')
  assert.equal(canonicalJson(Number.NEGATIVE_INFINITY), 'null')
  assert.equal(canonicalJson({ evidenceId: 'x', n: Number.NaN }), '{"evidenceId":"x","n":null}')
  assert.equal(addressOf({ n: Number.NaN }), addressOf({ n: null }), 'the known collision, pinned open pending the call-site fix')
})

test('canonicalJson rejects non-plain objects — Date, RegExp, Error, boxed, Map, class instances — instead of collapsing them to {}', () => {
  // All of these used to canonicalise as '{}' (or a lossy key subset),
  // aliasing each other AND the genuinely-empty object: new Date() and /re/
  // minted the same evidenceId as {}. Now the constructor is named.
  class Point { x: number; tag: string; constructor(x: number, tag: string) { this.x = x; this.tag = tag } }
  for (const [label, value] of [
    ['Date', new Date(0)],
    ['RegExp', /re/],
    ['Error', new Error('boom')],
    ['Number', new Number(1)],
    ['String', new String('s')],
    ['Boolean', new Boolean(false)],
    ['Map', new Map()],
    ['Set', new Set()],
    ['Point', new Point(1, 'a')],
  ] as const) {
    assert.throws(() => canonicalJson(value), TypeError, `${label} must throw`)
    assert.throws(() => canonicalJson(value), new RegExp(`${label} cannot be canonicalised`))
  }
  // Even an enumerable-keyed class instance refuses: addressing `{x:1}` for a
  // Point whose `tag` the format would drop is a false address — better
  // strict than silently deduplicated against a different value.
  assert.throws(() => addressOf(new Point(1, 'a')), /Point cannot be canonicalised/)
  // And the old collision is truly gone: a Date can never share an address
  // with anything the format does accept.
  assert.throws(() => canonicalJson(new Date(0)), TypeError)
  assert.equal(canonicalJson({}), '{}')
})

test('plain values canonicalise exactly as before — undefined fields, legal numbers, null-prototype objects stay legal', () => {
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}', 'undefined object fields are still dropped')
  assert.equal(canonicalJson([1, undefined, 2]), '[1,null,2]', 'undefined array slots still render as null')
  assert.equal(canonicalJson(undefined), 'null')
  assert.equal(canonicalJson({ n: -0 }), canonicalJson({ n: 0 }), '-0 still folds onto 0')
  assert.equal(canonicalJson({ a: 0.5, b: 1e-7, c: 123456789 }), '{"a":0.5,"b":1e-7,"c":123456789}')
  // Object.create(null) is a plain object by prototype: legal, addressed as usual.
  const nullProto = Object.assign(Object.create(null), { k: 'v', nested: { z: [true, null] } })
  assert.equal(canonicalJson(nullProto), '{"k":"v","nested":{"z":[true,null]}}')
  assert.equal(addressOf(nullProto), addressOf({ nested: { z: [true, null] }, k: 'v' }), 'key order still irrelevant')
  // The full legal shapes still round-trip through the public address.
  assert.equal(addressOf({ s: 'text', n: 3, t: true, x: null, arr: [1, 'two', false] }), addressOf({ arr: [1, 'two', false], x: null, t: true, n: 3, s: 'text' }))
})
