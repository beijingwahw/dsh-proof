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

test('normalised output addressing ignores cosmetic differences', () => {
  const a = normalizeOutput('x=1\n', { root: '/r' })
  const b = normalizeOutput('x=1 \r\n', { root: '/r' })
  assert.equal(sha256(a), sha256(b))
})
