/**
 * CANONICAL EVIDENCE ADDRESSING — location-independent digests.
 *
 * Compiler errors and stack traces almost always carry absolute paths, so
 * digests used to differ per machine and per checkout directory — breaking
 * cross-machine comparison, dedupe, and third-party recomputation, and
 * leaking usernames into records that may be exported for audit. v0.6
 * canonicalises: root -> `$WORKSPACE` (specific first), home -> `$HOME`.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { normalizeOutput, sha256 } from '../src/core/hash.ts'
import { makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { ProofEngine } from '../src/engine.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs, spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', [])

function failAt(root: string): string {
  return `FAIL at ${root}/src/a.ts:1:1\nAssertionError: expected 1 to be 2`
}

test('THE CRACK: the same outcome on different machines addresses identically', () => {
  const a = makeEvidence(spec({ id: 'c1' }), { status: 'fail', exitCode: 1, durationMs: 5, output: failAt('/machine-a/proj') }, WS, new FakeClock(), { budget: 2_000, strategy: 'head' }, { root: '/machine-a/proj' })
  const b = makeEvidence(spec({ id: 'c1' }), { status: 'fail', exitCode: 1, durationMs: 5, output: failAt('/machine-b/proj') }, WS, new FakeClock(), { budget: 2_000, strategy: 'head' }, { root: '/machine-b/proj' })
  assert.equal(a.outputDigest, b.outputDigest, 'digest is a function of what happened, not where')
  assert.equal(a.evidenceId, b.evidenceId, 'evidence dedupes across machines — the transparency-log primitive')
  assert.equal(a.outputHead, 'FAIL at $WORKSPACE/src/a.ts:1:1\nAssertionError: expected 1 to be 2')
})

test('home canonicalisation: usernames never enter the evidence record', () => {
  const output = 'Error: ENOENT /home/alice/secrets.txt\n    at /home/alice/proj/x.ts:1:1'
  const a = makeEvidence(spec({ id: 'c1' }), { status: 'fail', exitCode: 1, durationMs: 5, output }, WS, new FakeClock(), { budget: 2_000, strategy: 'head' }, { root: '/home/alice/proj', home: '/home/alice' })
  assert.ok(!a.outputHead.includes('alice'), 'no username in the excerpt')
  assert.ok(a.outputHead.includes('$HOME/secrets.txt'), 'sibling home paths collapse to $HOME')
  assert.ok(a.outputHead.includes('$WORKSPACE/x.ts'), 'the workspace under home still wins as $WORKSPACE (specific first)')

  const bobOutput = output.replaceAll('/home/alice', '/home/bob')
  const b = makeEvidence(spec({ id: 'c1' }), { status: 'fail', exitCode: 1, durationMs: 5, output: bobOutput }, WS, new FakeClock(), { budget: 2_000, strategy: 'head' }, { root: '/home/bob/proj', home: '/home/bob' })
  assert.equal(a.evidenceId, b.evidenceId, 'two users, same failure, same address')
})

test('windows roots match output in either slash style', () => {
  const normalized = normalizeOutput('fail C:\\Users\\x\\proj\\a.ts and C:/Users/x/proj/b.ts', { root: 'C:\\Users\\x\\proj' })
  assert.equal(normalized, 'fail $WORKSPACE\\a.ts and $WORKSPACE/b.ts')
})

test('root substitution is boundary-anchored: /app must not eat /application', () => {
  const normalized = normalizeOutput('built /application/config.yml from /app/src/a.ts', { root: '/app' })
  assert.equal(normalized, 'built /application/config.yml from $WORKSPACE/src/a.ts', 'a longer path sharing the prefix is a different location, not this workspace')
})

test('root substitution fires at separators, quotes, whitespace and line end — never mid-word', () => {
  const normalized = normalizeOutput('cd "/app"\nsee /app\\src ok in /app and /appdata', { root: '/app' })
  assert.equal(normalized, 'cd "$WORKSPACE"\nsee $WORKSPACE\\src ok in $WORKSPACE and /appdata')
})

test('root substitution fires at glued punctuation (paren, colon, comma, semicolon) — B6-L2', () => {
  // Linters and stack frames render paths as `(/app/x.ts)`, `at /app:3:1`,
  // `/app/a.ts,/app/b.ts` — none of those used to substitute at the bare
  // root, minting cross-machine false DIFFERENCES (same file, different
  // digest per spelling). The boundary now includes the punctuation a path
  // is routinely glued to; the mid-word guard is untouched.
  const out = normalizeOutput('at (/app) and /app:1:1 then /app/a.ts,/app/b.ts; done', { root: '/app' })
  assert.equal(out, 'at ($WORKSPACE) and $WORKSPACE:1:1 then $WORKSPACE/a.ts,$WORKSPACE/b.ts; done')
  // The anchor still refuses to chew into a longer name sharing the prefix.
  assert.equal(normalizeOutput('see /application', { root: '/app' }), 'see /application')
})

test('without canonical roots, legacy behaviour is byte-for-byte unchanged', () => {
  assert.equal(normalizeOutput('plain output\n', {}), 'plain output', 'trailing-empty-line pop is legacy behaviour, unchanged')
  assert.equal(normalizeOutput('fail at /nowhere/here/a.ts\n'), 'fail at /nowhere/here/a.ts', 'no roots given — no substitution, digests stay legacy-stable')
  const digest = sha256(normalizeOutput('took 12ms\n', { root: '/r' }))
  assert.equal(digest, sha256('took <duration>'), 'existing churn rules untouched')
})

test('ENGINE: two engines rooted at different checkouts produce identical evidence', async () => {
  function engineAt(root: string): ProofEngine {
    const commands = new FakeCommands().on(() => true, { exitCode: 0, output: `ok, suite ran from ${root}/src\n` })
    return new ProofEngine({
      root,
      fs: MemoryFs.of({ [`${root}/package.json`]: JSON.stringify({ name: 'demo', scripts: { test: 'vitest run' } }) }),
      commands,
      workspace: new FakeWorkspace(root),
      clock: new FakeClock(),
      impactGraphLimit: 100,
      homeDir: '/home/someone',
    })
  }
  const one = await engineAt('/ws/one').establishBaseline()
  const two = await engineAt('/ws/two').establishBaseline()
  assert.equal(one.records[0]?.evidenceId, two.records[0]?.evidenceId, 'cross-checkout evidence dedupe at engine level')
  assert.equal(one.records[0]?.outputDigest, two.records[0]?.outputDigest)
  assert.ok(one.records[0]?.outputHead.includes('$WORKSPACE/src'))
})
