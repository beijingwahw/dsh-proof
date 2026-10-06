/**
 * COVERAGE-AWARE PROOF (τ) — the pure domain of "green AND executed".
 *
 * These tests pin the four load-bearing pieces of the τ upgrade:
 *
 * 1. the parser — one V8 `coverage-*.json` becomes two buckets
 *    (executed / loaded-but-never-ran) over workspace-relative paths, with
 *    the exact url normalization this Windows-hosted repository needs
 *    (drive letters, percent-encoding, both `file://` spellings) and the
 *    drop rules (outside-root, `node:` internals, node_modules);
 * 2. the summarizer — the union of every decisive pass's executed set,
 *    sliced against the change set into executed / uncovered / not-applicable,
 *    with the pinned rule that zero executedSets means basis `none`;
 * 3. the gate — observe / require / off arbitration over that summary;
 * 4. the report demotion — `applyCoverageGate` turns proven into unproven
 *    when the change was never executed, never touches a worse grade, and
 *    always attaches the coverage summary; plus makeEvidence's `coverage`
 *    riding into the content address.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  coverageGate, parseV8CoverageReport, summarizeCoverage,
  type CoverageSummary,
} from '../src/core/coverage.ts'
import {
  makeEvidence, snapshotWorkspace,
  type Evidence, type ProofGrade, type RunOutcome,
} from '../src/core/evidence.ts'
import { applyCoverageGate, type GradedProofReport } from '../src/core/report.ts'
import { addressOf, merkleRoot } from '../src/core/hash.ts'
import type { CheckSpec } from '../src/core/ports.ts'
import { spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', [])
/** Frozen clock: evidence-id comparisons must not see the clock tick. */
const FIXED_NOW = 1_700_000_000_000
const fixedClock = { now: () => FIXED_NOW }

const ROOT = 'C:/ws'

/** A V8-shaped report: one entry per url, one function per count. */
function v8Report(entries: ReadonlyArray<{ url: string; counts?: readonly number[] }>): string {
  return JSON.stringify({
    result: entries.map((entry, i) => ({
      ScriptId: String(i + 1),
      url: entry.url,
      functions: (entry.counts ?? []).map((count, j) => ({
        functionName: j === 0 ? '' : `fn${j}`,
        ranges: [{ startOffset: 0, endOffset: 100, count }],
        isBlockCoverage: true,
      })),
    })),
  })
}

// ---------------------------------------------------------------------------
// 1. parseV8CoverageReport
// ---------------------------------------------------------------------------

test('parse: mixed counts sort files into executed vs loaded-not-executed', () => {
  const parsed = parseV8CoverageReport(v8Report([
    { url: 'file:///C:/ws/src/a.ts', counts: [1, 0] },        // top-level ran, helper did not
    { url: 'file:///C:/ws/src/b.ts', counts: [0, 0] },        // loaded, nothing ran
    { url: 'file:///C:/ws/src/inner%20dir/c.ts', counts: [0, 3] }, // only an inner function ran
  ]), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, ['src/a.ts', 'src/inner dir/c.ts'])
  assert.deepEqual(parsed.loadedNotExecuted, ['src/b.ts'])
})

test('parse: outside-root, root-adjacent, node_modules and node: urls are dropped', () => {
  const parsed = parseV8CoverageReport(v8Report([
    { url: 'file:///C:/ws/src/keep.ts', counts: [1] },
    { url: 'file:///D:/elsewhere/d.ts', counts: [5] },                          // other drive
    { url: 'file:///C:/wsx/h.ts', counts: [1] },                                 // prefix-adjacent, not inside
    { url: 'file:///C:/ws/node_modules/pkg/index.js', counts: [7] },             // top-level node_modules
    { url: 'file:///C:/ws/packages/x/node_modules/dep/y.js', counts: [2] },      // nested node_modules
    { url: 'node:internal/bootstrap/webm', counts: [1] },                        // node: internals
  ]), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, ['src/keep.ts'])
  assert.deepEqual(parsed.loadedNotExecuted, [])
})

test('W15-L8: a cache-bust query or fragment on the URL still matches the file it executed', () => {
  // Workspaces that bust V8's script cache get `?v=…` on the coverage URL;
  // matching the query verbatim used to leave the executed file permanently
  // "uncovered" — the gate blocking on exactly the workspaces that
  // instrument. The executed FILE is the path part; the suffix is cut before
  // comparison (a literal `?` in a real path is %3F, so the cut never
  // truncates a genuine path).
  const parsed = parseV8CoverageReport(v8Report([
    { url: 'file:///C:/ws/src/x.mjs?bust=1', counts: [1] },
    { url: 'file:///C:/ws/src/y.mjs#fragment', counts: [0] },
    { url: 'file:///C:/ws/src/q%3Fmark.ts?also-query', counts: [2] },
  ]), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, ['src/q?mark.ts', 'src/x.mjs'], 'query and fragment are stripped, percent-escapes still decode')
  assert.deepEqual(parsed.loadedNotExecuted, ['src/y.mjs'], 'loaded-but-not-executed survives the same cut')
  // End to end: the changed file counts as executed, the gate does not block.
  const summary = summarizeCoverage({ changed: ['src/x.mjs'], executedSets: [parsed.executed] })
  assert.deepEqual(summary.changedExecuted, ['src/x.mjs'])
  assert.deepEqual(summary.changedUncovered, [], 'no false uncovered-change from a cache-bust suffix')
})

test('parse: drive-letter case and backslash root compare case-insensitively', () => {
  const parsed = parseV8CoverageReport(v8Report([
    { url: 'file:///c:/WS/src/low.ts', counts: [1] },
  ]), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, ['src/low.ts'])
})

test('parse: two-slash file:// and POSIX roots work; POSIX stays case-sensitive', () => {
  const two = parseV8CoverageReport(v8Report([
    { url: 'file://C:/ws/src/two.ts', counts: [1] },
  ]), ROOT)
  assert.ok(two)
  assert.deepEqual(two.executed, ['src/two.ts'])

  const posix = parseV8CoverageReport(v8Report([
    { url: 'file:///srv/app/src/p.ts', counts: [1] },
    { url: 'file:///SRV/app/src/q.ts', counts: [1] }, // /SRV ≠ /srv on POSIX
  ]), '/srv/app')
  assert.ok(posix)
  assert.deepEqual(posix.executed, ['src/p.ts'])
})

test('V7-L4: a UNC workspace\'s two-slash coverage URLs resolve — the // prefix is modelled', () => {
  // `file://server/share/…` is UNC; the pre-fix reader emitted the path
  // WITHOUT its leading `//`, so it never matched a `\\server\share\ws` root
  // and every changed file read "uncovered" — observe silently no-op'd (or
  // require blocked everything) for the whole workspace.
  const unc = parseV8CoverageReport(v8Report([
    { url: 'file://build-server/share/ws/src/a.ts', counts: [1] },
    { url: 'file://build-server/share/ws/src/b.ts', counts: [0] },
    { url: 'file://other-server/share/ws/src/c.ts', counts: [1] }, // different host: outside
  ]), '\\\\build-server\\share\\ws')
  assert.ok(unc)
  assert.deepEqual(unc.executed, ['src/a.ts'], 'same-host UNC URLs resolve under the backslashed root')
  assert.deepEqual(unc.loadedNotExecuted, ['src/b.ts'])
  // The forward-slashed UNC root spelling works identically.
  const uncFwd = parseV8CoverageReport(v8Report([
    { url: 'file://build-server/share/ws/src/a.ts', counts: [1] },
  ]), '//build-server/share/ws')
  assert.ok(uncFwd)
  assert.deepEqual(uncFwd.executed, ['src/a.ts'])
  // End to end: the changed file counts as executed, the τ gate does not block.
  const summary = summarizeCoverage({ changed: ['src/a.ts'], executedSets: [unc.executed] })
  assert.deepEqual(summary.changedUncovered, [], 'a UNC workspace no longer reads as fully uncovered')
  // The drive-in-host spelling (`file://C:/ws/…`) is NOT UNC and keeps its
  // pinned legacy reading — pinned above and unchanged by this fix.
})

test('parse: an entry without a functions array counts as loaded-not-executed', () => {
  const parsed = parseV8CoverageReport(JSON.stringify({
    result: [{ ScriptId: '9', url: 'file:///C:/ws/src/nofn.ts' }],
  }), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, [])
  assert.deepEqual(parsed.loadedNotExecuted, ['src/nofn.ts'])
})

test('parse: a url both loaded (count 0) and executed (count>0) resolves to executed', () => {
  const parsed = parseV8CoverageReport(v8Report([
    { url: 'file:///C:/ws/src/dup.ts', counts: [0] },
    { url: 'file:///C:/ws/src/dup.ts', counts: [1] },
  ]), ROOT)
  assert.ok(parsed)
  assert.deepEqual(parsed.executed, ['src/dup.ts'])
  assert.deepEqual(parsed.loadedNotExecuted, [])
})

test('parse: empty result is a valid report with both buckets empty', () => {
  const parsed = parseV8CoverageReport('{"result":[]}', ROOT)
  assert.notEqual(parsed, undefined)
  assert.deepEqual(parsed, { executed: [], loadedNotExecuted: [] })
})

test('parse: garbage JSON and wrong shapes return undefined', () => {
  for (const bad of ['not json {', '', 'null', '42', '{"nope":1}', '{"result":{}}', '{"result":"x"}']) {
    assert.equal(parseV8CoverageReport(bad, ROOT), undefined, `input: ${JSON.stringify(bad)}`)
  }
})

// ---------------------------------------------------------------------------
// 2. summarizeCoverage
// ---------------------------------------------------------------------------

test('summarize: unions executed sets and buckets the change set', () => {
  const summary = summarizeCoverage({
    changed: ['src/b.ts', 'src/a.ts', 'README.md', 'docs/guide.md'],
    executedSets: [['src/a.ts'], ['src/c.ts', 'src/b.ts']],
  })
  assert.deepEqual(summary, {
    basis: 'v8',
    changedExecuted: ['src/a.ts', 'src/b.ts'],
    changedUncovered: [],
    changedNotApplicable: ['README.md', 'docs/guide.md'],
  })
})

test('summarize: changed source no evidence executed lands in uncovered', () => {
  const summary = summarizeCoverage({
    changed: ['src/x.ts', 'src/a.ts', 'NOTE.txt'],
    executedSets: [['src/a.ts']],
  })
  assert.deepEqual(summary, {
    basis: 'v8',
    changedExecuted: ['src/a.ts'],
    changedUncovered: ['src/x.ts'],
    changedNotApplicable: ['NOTE.txt'],
  })
})

test('summarize: empty change set over data is an all-empty v8 summary', () => {
  const summary = summarizeCoverage({ changed: [], executedSets: [['src/a.ts']] })
  assert.deepEqual(summary, {
    basis: 'v8',
    changedExecuted: [],
    changedUncovered: [],
    changedNotApplicable: [],
  })
})

test('summarize: zero executedSets is basis none (pinned), duplicates collapse', () => {
  const summary = summarizeCoverage({
    changed: ['src/a.ts', 'src/a.ts', 'src/x.ts'],
    executedSets: [],
  })
  assert.deepEqual(summary, {
    basis: 'none',
    changedExecuted: [],
    changedUncovered: ['src/a.ts', 'src/x.ts'],
    changedNotApplicable: [],
  })
})

// ---------------------------------------------------------------------------
// 3. coverageGate
// ---------------------------------------------------------------------------

const V8_COVERED: CoverageSummary = { basis: 'v8', changedExecuted: ['src/a.ts'], changedUncovered: [], changedNotApplicable: [] }
const V8_UNCOVERED: CoverageSummary = { basis: 'v8', changedExecuted: ['src/a.ts'], changedUncovered: ['src/x.ts'], changedNotApplicable: [] }
const NO_DATA: CoverageSummary = { basis: 'none', changedExecuted: [], changedUncovered: ['src/x.ts'], changedNotApplicable: [] }

test('gate: observe with no data does not block', () => {
  assert.deepEqual(coverageGate(NO_DATA, 'observe'), { blocked: false, reason: null })
})

test('gate: observe with data and nothing uncovered does not block', () => {
  assert.deepEqual(coverageGate(V8_COVERED, 'observe'), { blocked: false, reason: null })
})

test('gate: observe with an uncovered change blocks on uncovered-change', () => {
  assert.deepEqual(coverageGate(V8_UNCOVERED, 'observe'), { blocked: true, reason: 'uncovered-change' })
})

test('gate: require with no data blocks on no-coverage-data', () => {
  assert.deepEqual(coverageGate(NO_DATA, 'require'), { blocked: true, reason: 'no-coverage-data' })
})

test('gate: require with an uncovered change blocks on uncovered-change too', () => {
  assert.deepEqual(coverageGate(V8_UNCOVERED, 'require'), { blocked: true, reason: 'uncovered-change' })
})

test('gate: off never blocks, whatever the summary says', () => {
  assert.deepEqual(coverageGate(V8_UNCOVERED, 'off'), { blocked: false, reason: null })
  assert.deepEqual(coverageGate(NO_DATA, 'off'), { blocked: false, reason: null })
})

// ---------------------------------------------------------------------------
// 4. applyCoverageGate
// ---------------------------------------------------------------------------

function gradedReport(grade: ProofGrade): GradedProofReport {
  return {
    grade,
    root: merkleRoot(['a', 'b']),
    baselineRoot: 'f'.repeat(64),
    baselineCreatedAt: '2026-01-01T00:00:00.000Z',
    generatedAt: '2026-01-02T00:00:00.000Z',
    workspace: WS,
    checks: [],
    discovered: 2,
    unverified: [],
    summary: { passing: 2, failing: 0, regressions: 0, fixed: 0, preExisting: 0, newChecks: 0, indeterminate: 0 },
    regressions: [],
  }
}

test('apply: proven blocked by an uncovered change becomes unproven with coverage attached', () => {
  const out = applyCoverageGate(gradedReport('proven'), { blocked: true, reason: 'uncovered-change' }, V8_UNCOVERED)
  assert.equal(out.grade, 'unproven')
  assert.deepEqual(out.coverage, { basis: 'v8', uncovered: ['src/x.ts'] })
  // everything else is preserved untouched — the demotion is surgical
  assert.equal(out.root, merkleRoot(['a', 'b']))
  assert.equal(out.summary.passing, 2)
  assert.deepEqual(out.regressions, [])
})

test('apply: proven not blocked keeps its grade and still shows the coverage summary', () => {
  const out = applyCoverageGate(gradedReport('proven'), { blocked: false, reason: null }, V8_COVERED)
  assert.equal(out.grade, 'proven')
  assert.deepEqual(out.coverage, { basis: 'v8', uncovered: [] })
})

test('apply: a none basis attaches honestly without blocking when the gate passed', () => {
  const out = applyCoverageGate(gradedReport('proven'), { blocked: false, reason: null }, NO_DATA)
  assert.equal(out.grade, 'proven')
  assert.deepEqual(out.coverage, { basis: 'none', uncovered: ['src/x.ts'] })
})

test('apply: regressed and stale are never overwritten by the gate', () => {
  const blocked = { blocked: true, reason: 'uncovered-change' as const }
  const regressed = applyCoverageGate(gradedReport('regressed'), blocked, V8_UNCOVERED)
  assert.equal(regressed.grade, 'regressed')
  assert.deepEqual(regressed.coverage, { basis: 'v8', uncovered: ['src/x.ts'] })
  const stale = applyCoverageGate(gradedReport('stale'), blocked, V8_UNCOVERED)
  assert.equal(stale.grade, 'stale')
  assert.deepEqual(stale.coverage, { basis: 'v8', uncovered: ['src/x.ts'] })
})

// ---------------------------------------------------------------------------
// 5. makeEvidence coverage passthrough
// ---------------------------------------------------------------------------

const UNIT: CheckSpec = spec({ id: 'unit' })
const PASS: RunOutcome = { status: 'pass', exitCode: 0, durationMs: 10, output: 'ok' }
const COVMETA: Evidence['coverage'] = { changedExecuted: ['src/a.ts'], changedUncovered: ['src/x.ts'] }

test('evidence: coverage rides into the record and the content address', () => {
  const withCov = makeEvidence(UNIT, PASS, WS, fixedClock, undefined, undefined, undefined, COVMETA)
  const withoutCov = makeEvidence(UNIT, PASS, WS, fixedClock)
  assert.deepEqual(withCov.coverage, COVMETA)
  assert.equal(withoutCov.coverage, undefined)
  // same outcome, different execution footprint → different evidence, and
  // neither can borrow the other's address
  assert.notEqual(withCov.evidenceId, withoutCov.evidenceId)
})

test('evidence: a coverage-carrying record still addresses itself', () => {
  const ev = makeEvidence(UNIT, PASS, WS, fixedClock, undefined, undefined, undefined, COVMETA)
  const { evidenceId, ...rest } = ev
  assert.equal(addressOf(rest), evidenceId)
})

test('evidence: deterministic — same inputs, same record', () => {
  const a = makeEvidence(UNIT, PASS, WS, fixedClock, undefined, undefined, undefined, COVMETA)
  const b = makeEvidence(UNIT, PASS, WS, fixedClock, undefined, undefined, undefined, COVMETA)
  assert.deepEqual(a, b)
})

// ---------------------------------------------------------------------------
// 6. whole-module determinism
// ---------------------------------------------------------------------------

test('determinism: parse, summarize and gate are pure functions of their inputs', () => {
  const content = v8Report([
    { url: 'file:///C:/ws/src/a.ts', counts: [1, 0] },
    { url: 'file:///C:/ws/src/b.ts', counts: [0] },
  ])
  assert.deepEqual(parseV8CoverageReport(content, ROOT), parseV8CoverageReport(content, ROOT))

  const input = { changed: ['src/b.ts', 'src/a.ts', 'README.md'], executedSets: [['src/a.ts'], ['src/b.ts']] }
  assert.deepEqual(summarizeCoverage(input), summarizeCoverage(input))

  for (const mode of ['observe', 'require', 'off'] as const) {
    assert.deepEqual(coverageGate(V8_UNCOVERED, mode), coverageGate(V8_UNCOVERED, mode))
  }
})
