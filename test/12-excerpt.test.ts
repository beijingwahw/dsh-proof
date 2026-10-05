/**
 * EVIDENCE EXCERPTING — the budget knob works, and it spends the budget
 * where the failure information actually lives.
 *
 * Naive head truncation kept the banner and cut the stack trace. v0.5 makes
 * `headChars` a real budget with two strategies: legacy `head`, and the
 * default `balanced` (head + salient failure lines + tail, markers accounting
 * for every dropped character, deterministic for content addressing).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { excerptOutput, firstInformativeLine, isSalientLine } from '../src/core/excerpt.ts'
import { makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import { ProofEngine } from '../src/engine.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs, spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', [])

function noisyOutput(failureLine: string, fillerLines = 200): string {
  const parts = ['✓ 1 passing', '']
  for (let i = 0; i < fillerLines; i += 1) parts.push(`  filler log line ${i} with some padding to eat budget`)
  parts.push(failureLine)
  parts.push('    at Object.<anonymous> (/ws/test/a.test.ts:42:5)')
  parts.push('[exit code: 1]')
  return parts.join('\n')
}

test('THE CRACK: the budget knob now reaches the evidence record', async () => {
  const output = noisyOutput('AssertionError: expected 1 to be 2')
  const ev = makeEvidence(spec({ id: 'c1' }), { status: 'fail', exitCode: 1, durationMs: 3, output }, WS, new FakeClock(), { budget: 120, strategy: 'head' })
  assert.ok(ev.outputHead.length <= 120, `excerpt ${ev.outputHead.length} exceeds budget`)
  assert.equal(ev.outputTruncated, true)
  assert.equal(ev.outputOmittedChars, output.length - 120)
  // Legacy strategy is the verbatim head slice.
  assert.equal(ev.outputHead, output.slice(0, 120))
})

test('balanced keeps the head, the salient failure, and the tail within budget', () => {
  const failure = 'AssertionError: expected 1 to be 2'
  const output = noisyOutput(failure)
  const excerpt = excerptOutput(output, { budget: 300, strategy: 'balanced' })
  assert.ok(excerpt.text.length <= 300, `excerpt length ${excerpt.text.length} exceeds budget`)
  assert.ok(excerpt.text.includes('✓ 1 passing'), 'head kept')
  assert.ok(excerpt.text.includes(failure), 'the salient failure line survives — the part head truncation cut')
  assert.ok(excerpt.text.includes('at Object.<anonymous>'), 'stack frame at the tail kept')
  assert.ok(excerpt.text.includes('chars omitted'), 'omission is accounted, not silent')
  assert.equal(excerpt.truncated, true)
  assert.ok(excerpt.omittedChars > 0)
})

test('short output passes through untouched with no markers', () => {
  const excerpt = excerptOutput('ok\n', { budget: 2000, strategy: 'balanced' })
  assert.equal(excerpt.text, 'ok\n')
  assert.equal(excerpt.truncated, false)
  assert.equal(excerpt.omittedChars, 0)
})

test('excerpting is deterministic — evidence addressing is stable', () => {
  const output = noisyOutput('Error: boom')
  const a = excerptOutput(output, { budget: 250, strategy: 'balanced' })
  const b = excerptOutput(output, { budget: 250, strategy: 'balanced' })
  assert.equal(a.text, b.text)
  assert.equal(a.omittedChars, b.omittedChars)
  assert.notEqual(excerptOutput(output, { budget: 1000, strategy: 'balanced' }).text, a.text)
})

test('no salient lines in the middle degrades to clean head+tail', () => {
  const output = ['header line', ...Array.from({ length: 100 }, (_, i) => `plain ${i}`), 'footer line'].join('\n')
  const excerpt = excerptOutput(output, { budget: 80, strategy: 'balanced' })
  assert.ok(excerpt.text.includes('header'), 'head kept')
  assert.ok(excerpt.text.includes('footer'), 'tail kept')
  assert.ok(!excerpt.text.includes('plain 50'), 'middle filler dropped')
  assert.ok(excerpt.text.includes('chars omitted'))
})

test('firstInformativeLine prefers salient lines over the first line', () => {
  const text = ['✓ 1 passing', 'AssertionError: expected 1 to be 2', '    at foo (bar.ts:1:1)'].join('\n')
  assert.equal(firstInformativeLine(text), 'AssertionError: expected 1 to be 2')
  assert.equal(firstInformativeLine('all calm\nnothing here'), 'all calm')
  assert.equal(firstInformativeLine(''), '')
  assert.ok(isSalientLine('  3 failing'))
  assert.ok(!isSalientLine('  filler log line 7'))
})

test('ENGINE: engine-level headChars and strategy reach records end to end', async () => {
  const longOutput = noisyOutput('Error: boom')
  const commands = new FakeCommands().on(() => true, { exitCode: 0, output: longOutput })
  const engine = new ProofEngine({
    root: '/ws',
    fs: MemoryFs.of({ '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'x' } }) }),
    commands,
    workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(),
    headChars: 150,
    excerptStrategy: 'balanced',
    impactGraphLimit: 100,
  })
  const { records } = await engine.establishBaseline()
  const record = records[0]
  assert.ok(record !== undefined)
  assert.ok(record.outputHead.length <= 150, `engine-level budget honoured: ${record.outputHead.length}`)
  assert.equal(record.outputTruncated, true)
  assert.ok(record.outputHead.includes('Error: boom'), 'salient failure survives the engine default budget')
})
