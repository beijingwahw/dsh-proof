/**
 * EVIDENCE EXCERPTING — the budget knob works, and it spends the budget
 * where the failure information actually lives.
 *
 * Naive head truncation kept the banner and cut the stack trace. v0.5 makes
 * `headChars` a real budget with two strategies: legacy `head`, and the
 * default `balanced` (head + salient failure lines + tail, markers accounting
 * for every dropped character, deterministic for content addressing).
 *
 * v0.8 (M12) turns the advertised contract into enforced truth, tested here
 * as SPEC cases: the budget bounds the assembled text (marker and joins
 * included, both strategies); the books close exactly
 * (`omittedChars + keptOriginalChars === normalized.length`, and the marker
 * prints that same number); a picked salient line is never cut in half; and
 * for real budgets (>= 64) more budget never keeps fewer original characters.
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

// ---------------------------------------------------------------------------
// v0.8 SPEC — the M12 repair: the excerpt's advertised invariants are now
// enforced truth, so they are pinned as executable specifications.
// ---------------------------------------------------------------------------

const LONG_FAILURE = 'AssertionError: expected 1 to be 2'
const SPEC_OUTPUTS: string[] = [
  noisyOutput(LONG_FAILURE),
  noisyOutput('Error: boom'),
  // no salient middle: head+marker+tail only
  ['header line', ...Array.from({ length: 100 }, (_, i) => `plain ${i}`), 'footer line'].join('\n'),
  // degenerate shape: the whole output is one huge line
  'x'.repeat(5000) + ' FAILED ' + 'y'.repeat(5000),
]

const MARKER_RE = /\[\.\.\. \d+ chars omitted \.\.\.\]/g

test('SPEC (M12): budget bounds the assembled text — marker and joins count against it, both strategies', () => {
  for (const output of SPEC_OUTPUTS) {
    for (const strategy of ['head', 'balanced'] as const) {
      for (let budget = 16; budget <= 600; budget += 7) {
        const e = excerptOutput(output, { budget, strategy })
        assert.ok(e.text.length <= budget, `budget ${budget} (${strategy}): text is ${e.text.length}`)
        assert.equal(e.truncated, true)
      }
    }
  }
  // The head strategy adds no marker, so every character of its text is an
  // original character — zero overhead, byte-locked legacy behaviour.
  const h = excerptOutput(SPEC_OUTPUTS[0]!, { budget: 120, strategy: 'head' })
  assert.equal(h.text, SPEC_OUTPUTS[0]!.slice(0, 120))
  assert.equal(h.keptOriginalChars, h.text.length)
  assert.equal(h.omittedChars, SPEC_OUTPUTS[0]!.length - h.text.length)
})

test('SPEC (M12): the books close exactly — omittedChars + keptOriginalChars === normalized.length', () => {
  for (const output of SPEC_OUTPUTS) {
    for (const strategy of ['head', 'balanced'] as const) {
      for (let budget = 16; budget <= 1200; budget += 13) {
        const e = excerptOutput(output, { budget, strategy })
        assert.equal(
          e.omittedChars + e.keptOriginalChars,
          output.length,
          `books do not close at budget ${budget} (${strategy})`,
        )
        // The marker states the FINAL omission, never a pre-truncation
        // estimate, and there is at most one marker in the text.
        const markers = e.text.match(MARKER_RE) ?? []
        assert.ok(markers.length <= 1, 'at most one omission marker')
        if (markers.length === 1) {
          assert.equal(markers[0], `[... ${e.omittedChars} chars omitted ...]`, `marker lies at budget ${budget}`)
        }
      }
    }
  }
})

test('SPEC (M12): a salient failure line is never cut in half — it appears whole or not at all', () => {
  const output = noisyOutput(LONG_FAILURE)
  for (let budget = 64; budget <= 512; budget += 1) {
    const e = excerptOutput(output, { budget, strategy: 'balanced' })
    if (e.text.includes(LONG_FAILURE)) continue
    // absent is legitimate (the line costs more than half the budget below
    // 68); a visible prefix without the full line is a half-cut and a bug.
    for (let p = 4; p < LONG_FAILURE.length; p += 1) {
      assert.ok(!e.text.includes(LONG_FAILURE.slice(0, p)), `half-cut prefix (${p} chars) at budget ${budget}`)
    }
  }
})

test('SPEC (M12): once the budget can honour it, the failure line survives whole at every budget', () => {
  // 'Error: boom' is 11 chars — pickable at every budget >= 64 — and picked
  // salient lines are never the thing that gets cut, so it must be there.
  const output = noisyOutput('Error: boom')
  for (let budget = 64; budget <= 512; budget += 1) {
    const e = excerptOutput(output, { budget, strategy: 'balanced' })
    assert.ok(e.text.includes('Error: boom'), `salient failure lost at budget ${budget}`)
  }
})

test('SPEC (M12): deterministic output, and more budget never keeps fewer original characters', () => {
  const output = noisyOutput(LONG_FAILURE)
  for (const budget of [64, 150, 217, 218, 500]) {
    const a = excerptOutput(output, { budget, strategy: 'balanced' })
    const b = excerptOutput(output, { budget, strategy: 'balanced' })
    assert.deepEqual(a, b, `determinism broken at budget ${budget}`)
  }
  // Monotonicity is claimed for real budgets (>= 64, the survival floor;
  // real configs default to 2000). Below that the excerpt deliberately
  // trades raw kept characters for salient survival at the fallback
  // boundary, so kept-original-chars is not monotone there by design.
  for (const specOutput of [noisyOutput(LONG_FAILURE), noisyOutput('Error: boom')]) {
    let prev = -1
    for (let budget = 64; budget <= 1024; budget += budget < 512 ? 1 : 16) {
      const e = excerptOutput(specOutput, { budget, strategy: 'balanced' })
      assert.ok(
        e.keptOriginalChars >= prev,
        `kept shrank ${prev} -> ${e.keptOriginalChars} when budget grew to ${budget}`,
      )
      prev = e.keptOriginalChars
    }
  }
})

test('SPEC (M12): pathological tiny budgets degrade to head semantics — honest, truncated, books closed', () => {
  const output = noisyOutput('Error: boom')
  // On this output the omission marker is 29 chars (5-digit count). At
  // budget 40 even marker + 'Error: boom' (29 + 1 + 11) does not fit, so the
  // balanced assembly gives up entirely and the honest head slice remains.
  const e40 = excerptOutput(output, { budget: 40, strategy: 'balanced' })
  assert.equal(e40.text, output.slice(0, 40))
  assert.equal(e40.keptOriginalChars, 40)
  assert.equal(e40.omittedChars, output.length - 40)
  assert.equal(e40.truncated, true)
  // One character of budget more and the salient line wins its place back —
  // the banner is sacrificed (empty head window), never the failure line.
  const e41 = excerptOutput(output, { budget: 41, strategy: 'balanced' })
  assert.equal(e41.text, `[... ${output.length - 11} chars omitted ...]\nError: boom`)
  assert.equal(e41.keptOriginalChars, 11)
  assert.equal(e41.text.length, 41)
  // And an excerpt that would be nothing but a bare marker is not an
  // excerpt — head semantics keeps real evidence instead.
  const longOutput = noisyOutput(LONG_FAILURE)
  const e29 = excerptOutput(longOutput, { budget: 29, strategy: 'balanced' })
  assert.equal(e29.text, longOutput.slice(0, 29))
  assert.equal(e29.keptOriginalChars, 29)
})

test('SPEC (M12): degenerate one-line output — no double-counted head, no lying marker', () => {
  const output = SPEC_OUTPUTS[3]!
  for (let budget = 16; budget <= 300; budget += 7) {
    const e = excerptOutput(output, { budget, strategy: 'balanced' })
    assert.ok(e.text.length <= budget, `one-line output breaks budget at ${budget}`)
    assert.equal(e.omittedChars + e.keptOriginalChars, output.length, `books at budget ${budget}`)
    assert.ok(e.keptOriginalChars > 0, `kept nothing at budget ${budget}`)
  }
})
