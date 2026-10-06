/**
 * PROTOCOL — the APP/1.4 constants layer, pinned to the wire.
 *
 * The vocabulary arrays in `src/app/protocol.ts` are the dialect two parties
 * agree on before anything else is interpreted, so they are pinned here
 * byte-for-byte — and then cross-checked against what the core actually
 * produces: verdicts against `verdictOf`'s full truth table, grades against
 * five behavioural fixtures, chain modes against `walkChain`, statuses
 * against the decisive/non-decisive split. A drift in either direction —
 * the constants claiming a value core can never emit, or core growing a
 * value the constants never pinned — must fail here, not in the field.
 *
 * v0.18: APP/1.0 → APP/1.1 was the §6 tool-surface expansion (the
 * transparency-log tools joining the MCP contract); v0.19: APP/1.1 → APP/1.2
 * is the SECOND expansion (7 → 10, the responsibility-DAG tools); v0.20:
 * APP/1.2 → APP/1.3 is the THIRD expansion (10 → 11, the training-export
 * tool); v0.21: APP/1.3 → APP/1.4 is the FOURTH expansion (11 → 13, the
 * verification-economics tools `proof_economics` and `proof_sla_quote`). The
 * vocabularies are unchanged every time; the version — which the
 * fingerprint digests — moved, so every APP/1.4 manifest is mutually
 * unintelligible with every APP/1.3 one by construction. The old
 * fingerprints are pinned below as the change detectors — five generations,
 * mutually unintelligible by literal.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  BUNDLE_MEDIA_TYPE, CHAIN_MODES, CHECK_STATUSES, CLAIM_KINDS, GRADE_VALUES,
  PROOF_MEDIA_TYPE, PROTOCOL_NAME, PROTOCOL_VERSION, VERDICT_VALUES,
  appFingerprint, protocolHeader,
} from '../src/app/protocol.ts'
import { canonicalJson, sha256 } from '../src/core/hash.ts'
import {
  type CheckStatus, type CheckVerdict, type ProofGrade,
  buildBaseline, isDecisiveStatus, makeEvidence, snapshotWorkspace, verdictOf,
} from '../src/core/evidence.ts'
import { assembleProof } from '../src/core/report.ts'
import { type ChainMode, GENESIS_PREV, walkChain } from '../src/core/trust.ts'
import type { ClaimKind } from '../src/core/contract.ts'
import { FakeClock, spec } from './helpers.ts'

const WS = snapshotWorkspace('head1', ['src/a.ts'])

test('the five vocabularies are pinned byte-for-byte (the APP/1.4 wire contract)', () => {
  assert.deepEqual(VERDICT_VALUES, [
    'still-passing', 'still-failing', 'regression', 'fixed',
    'new-failure', 'new-check', 'not-run', 'indeterminate',
  ])
  assert.deepEqual(GRADE_VALUES, ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'])
  assert.deepEqual(CHAIN_MODES, ['legacy', 'unsigned', 'signed'])
  assert.deepEqual(CLAIM_KINDS, [
    'behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury',
  ])
  assert.deepEqual(CHECK_STATUSES, ['pass', 'fail', 'error', 'timeout', 'aborted', 'skipped'])

  assert.equal(PROTOCOL_NAME, 'agent-proof-protocol')
  assert.equal(PROTOCOL_VERSION, 'APP/1.4')
  assert.equal(PROOF_MEDIA_TYPE, 'application/vnd.app.proof+json')
  assert.equal(BUNDLE_MEDIA_TYPE, 'application/vnd.app.proof-bundle+json')

  // Compile-time pins: every protocol value IS a core union member. If core
  // renames a value, this stops typechecking; if the array drops one, the
  // deepEquals above stop passing. Both directions of drift are caught.
  const verdictPin: readonly CheckVerdict[] = VERDICT_VALUES
  const gradePin: readonly ProofGrade[] = GRADE_VALUES
  const chainPin: readonly ChainMode[] = CHAIN_MODES
  const claimPin: readonly ClaimKind[] = CLAIM_KINDS
  const statusPin: readonly CheckStatus[] = CHECK_STATUSES
  assert.equal(verdictPin.length + gradePin.length + chainPin.length + claimPin.length + statusPin.length, 27)
})

test('appFingerprint is deterministic and recomputable from the vocabulary alone', () => {
  // Same call, same digest — the fingerprint is a pure function of constants.
  assert.equal(appFingerprint(), appFingerprint())

  // Independent recomputation with the material spelled out in this file, not
  // borrowed from the module: the fingerprint is the canonical digest of the
  // five vocabularies plus one string per load-bearing rule.
  const manual = sha256(canonicalJson({
    name: 'agent-proof-protocol',
    version: 'APP/1.4',
    verdict: ['still-passing', 'still-failing', 'regression', 'fixed', 'new-failure', 'new-check', 'not-run', 'indeterminate'],
    grade: ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'],
    chainModes: ['legacy', 'unsigned', 'signed'],
    claimKinds: ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'],
    checkStatuses: ['pass', 'fail', 'error', 'timeout', 'aborted', 'skipped'],
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }))
  assert.equal(appFingerprint(), manual)
  assert.match(appFingerprint(), /^[0-9a-f]{64}$/, 'a fingerprint is a hex sha256')
})

/**
 * The four prior dialect fingerprints, recomputed from the pinned vocabulary
 * material with only the version rolled back. Each bump MUST move the
 * fingerprint — an APP/1.3 consumer that silently accepted an APP/1.4 bundle
 * (or an APP/1.2 one an APP/1.3 bundle, an APP/1.1 one an APP/1.2 bundle, or
 * an APP/1.0 one an APP/1.1 bundle) would be guessing at a dialect it never
 * agreed to. All old values stay pinned: every past dialect remains
 * refusable by literal, not by reconstruction.
 */
const APP_1_0_FINGERPRINT = '01c9727ea94275365cd29cd193aea1a2b8c8d62efe2ccd60b31d48d717d3deb8'
const APP_1_1_FINGERPRINT = '3464843dd251c2200ad31fb05f3323c7f57771e944117aedecd30a5abde085d2'
const APP_1_2_FINGERPRINT = 'bc46bd21f127709dda7e3edeb9ca624d9cbc1182a854b5c9008858ff3f44d482'
const APP_1_3_FINGERPRINT = '4ac69d28eeddab58f791fd8933df04ac512699d6757ee0ace72ddf286867f7d0'
const APP_1_4_FINGERPRINT = 'ec8ab950a899c7ccbb63588a7513ce4074e32e0088ff5fa1fe27d273be0df5af'

test('the APP/1.4 version bump moved the fingerprint — APP/1.3 dialects are refused, not guessed at', () => {
  // The old material, verbatim from v0.20's implementation: everything
  // identical except the version string. Recomputed here, so the pinned
  // literal below is cross-checked against live primitives, not trusted.
  const app13 = sha256(canonicalJson({
    name: 'agent-proof-protocol',
    version: 'APP/1.3',
    verdict: ['still-passing', 'still-failing', 'regression', 'fixed', 'new-failure', 'new-check', 'not-run', 'indeterminate'],
    grade: ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'],
    chainModes: ['legacy', 'unsigned', 'signed'],
    claimKinds: ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'],
    checkStatuses: ['pass', 'fail', 'error', 'timeout', 'aborted', 'skipped'],
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }))
  assert.equal(app13, APP_1_3_FINGERPRINT, 'the pinned v0.20 fingerprint matches the APP/1.3 material')
  // The live fingerprint is pinned too — the recomputation above proves the
  // pin, the pin proves every future run, so an accidental vocabulary edit
  // fails HERE with the two digests side by side.
  assert.equal(appFingerprint(), APP_1_4_FINGERPRINT, 'the live constants digest to the pinned APP/1.4 fingerprint')
  assert.notEqual(appFingerprint(), APP_1_3_FINGERPRINT,
    'APP/1.4 must not digest to the APP/1.3 fingerprint — the version is fingerprint material')
  assert.notEqual(appFingerprint(), APP_1_2_FINGERPRINT,
    'APP/1.4 must not digest to the APP/1.2 fingerprint — every past dialect stays mutually unintelligible')
  assert.notEqual(appFingerprint(), APP_1_1_FINGERPRINT,
    'APP/1.4 must not digest to the APP/1.1 fingerprint — every past dialect stays mutually unintelligible')
  assert.notEqual(appFingerprint(), APP_1_0_FINGERPRINT,
    'APP/1.4 must not digest to the APP/1.0 fingerprint — every past dialect stays mutually unintelligible')
  // Five generations, five distinct literals: mutual unintelligibility is a
  // property of the PINS, not only of the live digest — no two dialects ever
  // share a fingerprint, in any direction, in any era.
  const generations = [APP_1_0_FINGERPRINT, APP_1_1_FINGERPRINT, APP_1_2_FINGERPRINT, APP_1_3_FINGERPRINT, APP_1_4_FINGERPRINT]
  assert.equal(new Set(generations).size, 5,
    'the five pinned dialect fingerprints are mutually distinct — a shared literal would make two dialects silently interchangeable')
  // And the sensitivity is exactly the version byte, not incidental drift:
  // swapping ONLY the version into the live material reproduces the old
  // digest, so the vocabularies and rules above are byte-identical to v0.20's
  // — the bump is the only change, in both directions.
  const onlyVersionDiffers = sha256(canonicalJson({
    name: PROTOCOL_NAME,
    version: 'APP/1.3',
    verdict: VERDICT_VALUES,
    grade: GRADE_VALUES,
    chainModes: CHAIN_MODES,
    claimKinds: CLAIM_KINDS,
    checkStatuses: CHECK_STATUSES,
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }))
  assert.equal(onlyVersionDiffers, APP_1_3_FINGERPRINT,
    'with the version restored, the live constants digest to the v0.20 fingerprint — the bump is the only change')
})

test('the fingerprint is sensitive to the vocabulary and to the rules it names', () => {
  const material = {
    name: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    verdict: VERDICT_VALUES,
    grade: GRADE_VALUES,
    chainModes: CHAIN_MODES,
    claimKinds: CLAIM_KINDS,
    checkStatuses: CHECK_STATUSES,
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }
  // A vocabulary change (a new verdict sneaks in) must move the digest…
  const extraVerdict = sha256(canonicalJson({ ...material, verdict: [...VERDICT_VALUES, 'mostly-fine'] }))
  assert.notEqual(extraVerdict, appFingerprint())
  // …and so must a rule change (the chaining rule is reworded).
  const otherChainRule = sha256(canonicalJson({ ...material, chain: 'prev=sha256(currentLine)' }))
  assert.notEqual(otherChainRule, appFingerprint())
  assert.notEqual(extraVerdict, otherChainRule)
})

test('protocolHeader stamps the manifest skeleton every bundle starts from', () => {
  const header = protocolHeader('ws-42', '2026-10-06T00:00:00.000Z')
  assert.equal(header.protocol, 'APP/1.4')
  assert.equal(header.protocol, PROTOCOL_VERSION)
  assert.equal(header.appFingerprint, appFingerprint(), 'the skeleton carries the live fingerprint, not a cached one')
  assert.equal(header.workspaceKey, 'ws-42')
  assert.equal(header.createdAt, '2026-10-06T00:00:00.000Z')
  assert.deepEqual(header.files, [], 'a skeleton has packed nothing yet')
  assert.deepEqual(
    Object.keys(header).sort(),
    ['appFingerprint', 'createdAt', 'files', 'protocol', 'workspaceKey'],
  )

  // Each call returns a fresh skeleton: packing one bundle must never leak
  // file entries into the next bundle's manifest.
  const packed = protocolHeader('k2', 't2')
  packed.files.push({ path: 'evidence.jsonl', sha256: '0'.repeat(64), bytes: 1 })
  assert.deepEqual(protocolHeader('k3', 't3').files, [])
})

test('VERDICT_VALUES is exactly the set verdictOf can produce — the full differential, decisive or not', () => {
  const clock = new FakeClock()
  const s = spec({ id: 'c1' })
  const run = (status: CheckStatus) =>
    makeEvidence(s, { status, exitCode: status === 'fail' ? 1 : status === 'pass' ? 0 : null, durationMs: 1, output: status }, WS, clock)
  const pass = run('pass')
  const fail = run('fail')
  const skipped = run('skipped')
  const timeout = run('timeout')
  const error = run('error')
  const aborted = run('aborted')

  // Every baseline × current combination the lattice admits, including
  // "absent" on either side. If core ever grows a ninth verdict, the set
  // equality below fails before it reaches a bundle manifest.
  const sides = [undefined, pass, fail, skipped, timeout, error, aborted]
  const produced = new Set<string>()
  for (const baseline of sides) {
    for (const current of sides) {
      const verdict = verdictOf(baseline, current)
      produced.add(verdict)
      assert.ok(
        (VERDICT_VALUES as readonly string[]).includes(verdict),
        `verdictOf produced "${verdict}", which the pinned vocabulary does not name`,
      )
    }
  }
  assert.deepEqual([...produced].sort(), [...VERDICT_VALUES].sort())

  // And the flagship constructions, named: blame needs a decisive baseline
  // pass; credit needs a decisive baseline fail; unknown is never rounded up.
  assert.equal(verdictOf(pass, pass), 'still-passing')
  assert.equal(verdictOf(fail, fail), 'still-failing')
  assert.equal(verdictOf(pass, fail), 'regression')
  assert.equal(verdictOf(fail, pass), 'fixed')
  assert.equal(verdictOf(undefined, fail), 'new-failure')
  assert.equal(verdictOf(undefined, pass), 'new-check')
  assert.equal(verdictOf(pass, undefined), 'not-run')
  assert.equal(verdictOf(skipped, fail), 'indeterminate')
})

test('GRADE_VALUES is exactly the set a graded run can produce (pessimistic by construction)', () => {
  const clock = new FakeClock()
  const s = spec({ id: 'c1' }) // paths: ['*'] — affected by any change
  const run = (status: CheckStatus) =>
    makeEvidence(s, { status, exitCode: status === 'fail' ? 1 : status === 'pass' ? 0 : null, durationMs: 1, output: status }, WS, clock)
  const pass = run('pass')
  const grades = new Set<string>()

  // no-baseline: the session started with nothing to diff against.
  const noBaseline = assembleProof({ specs: [s], records: [pass], changed: ['src/a.ts'], workspace: WS, clock })
  assert.equal(noBaseline.report.grade, 'no-baseline')
  grades.add(noBaseline.report.grade)

  // regressed: passed at baseline, fails now — charged to this session.
  const regressed = assembleProof({
    specs: [s], baseline: buildBaseline([pass], WS, clock), records: [run('fail')],
    changed: ['src/a.ts'], workspace: WS, clock,
  })
  assert.equal(regressed.report.grade, 'regressed')
  grades.add(regressed.report.grade)

  // stale: an affected check produced no decisive outcome this run.
  const stale = assembleProof({
    specs: [s], baseline: buildBaseline([pass], WS, clock), records: [run('skipped')],
    changed: ['src/a.ts'], workspace: WS, clock,
  })
  assert.equal(stale.report.grade, 'stale')
  grades.add(stale.report.grade)

  // unproven: the workspace declares no checks — nothing objective speaks.
  const unproven = assembleProof({
    specs: [], baseline: buildBaseline([], WS, clock), records: [],
    changed: ['src/a.ts'], workspace: WS, clock,
  })
  assert.equal(unproven.report.grade, 'unproven')
  grades.add(unproven.report.grade)

  // proven: baseline existed, everything affected re-ran decisively green.
  const proven = assembleProof({
    specs: [s], baseline: buildBaseline([pass], WS, clock), records: [run('pass')],
    changed: ['src/a.ts'], workspace: WS, clock,
  })
  assert.equal(proven.report.grade, 'proven')
  grades.add(proven.report.grade)

  assert.deepEqual([...grades].sort(), [...GRADE_VALUES].sort(), 'the grade vocabulary is the lattice, no more, no less')
})

test('CHECK_STATUSES matches the runner vocabulary; only pass and fail are decisive', () => {
  assert.equal(isDecisiveStatus('pass'), true)
  assert.equal(isDecisiveStatus('fail'), true)
  for (const status of CHECK_STATUSES) {
    assert.equal(
      isDecisiveStatus(status),
      status === 'pass' || status === 'fail',
      `"${status}" must be decisive exactly when it settles the check's question`,
    )
  }

  // Every status round-trips through the evidence mint: the record carries
  // the status it was given, so the vocabulary is the runner's, not aspirational.
  const clock = new FakeClock()
  const statuses = CHECK_STATUSES.map((status) =>
    makeEvidence(spec({ id: `c-${status}` }), { status, exitCode: null, durationMs: 0, output: '' }, WS, clock).status)
  assert.deepEqual(statuses, [...CHECK_STATUSES])
})

test('CHAIN_MODES is exactly what the chain walker can report', () => {
  const v1Log = JSON.stringify({ v: 1, kind: 'evidence', at: 't', payload: { evidenceId: 'legacy' } })
  const v2Unsigned = JSON.stringify({ v: 2, kind: 'evidence', at: 't', prev: GENESIS_PREV, payload: { evidenceId: 'x' } })
  const v2Signed = JSON.stringify({
    v: 2, kind: 'checkpoint', at: 't', prev: GENESIS_PREV,
    payload: { count: 1, head: 'h', workspaceKey: null, at: 't' },
    sig: 'sig-over-canonicalJson-payload', keyId: 'host-key',
  })

  assert.equal(walkChain([v1Log]).mode, 'legacy', 'v1-only logs audit as legacy')
  assert.equal(walkChain([v2Unsigned]).mode, 'unsigned', 'a chained log without signatures is unsigned')
  assert.equal(walkChain([v2Signed]).mode, 'signed', 'one signature-bearing checkpoint makes the chain signed')
  assert.deepEqual(['legacy', 'unsigned', 'signed'], [...CHAIN_MODES])
})

test('the protocol layer stays framework-free — core primitives and node: builtins only', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/app/protocol.ts', import.meta.url)), 'utf8')
  // Match real import specifiers, not prose mentions: a doc comment may name
  // the forbidden framework while explaining why the module never imports it.
  const frameworkImport = /(?:from|import\()\s*['"]@deepseek-ai\//
  assert.equal(frameworkImport.test(source), false, 'src/app must never import the harness framework')
  assert.ok(
    source.includes("from '../core/hash.ts'"),
    'the fingerprint is built from core canonicalisation primitives, not re-implemented here',
  )
})
