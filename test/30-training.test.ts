/**
 * TRAINING — the ground-truth flywheel.
 *
 * The evidence log's second life: the same bytes that prove "done" also
 * label it. These tests pin the distillery that turns a chain into a
 * dataset — and, with it, the claim the dataset is allowed to make: every
 * label is a machine-verified differential (or an intra-chain temporal
 * fact), never a self-report.
 *
 * Anchors, in the order they run:
 *
 * 1. **THE GROUND-TRUTH EXHAUST** — one session containing every verdict
 *    class, both flip directions, non-decisive noise, a brand-new check and
 *    a check whose baseline never answered: sample-for-sample,
 *    verdict-for-verdict, reward-for-reward.
 * 2. **Reward law** — the eight-entry table pinned literally, snapshotted
 *    (not referenced) into every manifest.
 * 3. **Flip-pair pairing** — adjacency lives in the decisive subsequence:
 *    non-decisive records neither break a pair nor mint one; a lone
 *    observation flips nothing; same-status neighbours pair nothing; both
 *    temporal directions collapse onto the one DPO direction.
 * 4. **Fidelity tiers** — `private` exports zero output characters (the
 *    sentinel never survives serialization, not even as a key name); `full`
 *    excerpts at exactly 200 characters.
 * 5. **Provenance filter** — one external edit voids the session's
 *    verification labels and keeps its flip-pairs; `all` keeps everything;
 *    externality only counts inside `changedPaths`.
 * 6. **Determinism** — same input twice, byte-identical; a reordered log
 *    (each check's own order intact) distills the same dataset, because the
 *    output sort — not the input order — pins the bytes.
 * 7. **Content addressing** — `sampleHash` is the canonical-JSON digest
 *    truncated to 16 hex characters, the root is the Merkle root over the
 *    leaves, and it moves when one character of one output moves (or when a
 *    label moves).
 * 8. **The empty log is a legal dataset** — zero counts, `sha256('')` root,
 *    honest manifest.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { canonicalJson, merkleRoot, sha256 } from '../src/core/hash.ts'
import type { CheckStatus, CheckVerdict, Evidence } from '../src/core/evidence.ts'
import {
  TRAINING_SCHEMA, VERDICT_REWARD, distillTrainingSet, sampleHash,
  type DistillInput, type FlipPairSample, type TrainingSample, type TrainingSet, type VerificationSample,
} from '../src/core/training.ts'

// ---------------------------------------------------------------------------
// Fixtures — deterministic, every timestamp supplied, nothing random
// ---------------------------------------------------------------------------

const T0 = '2026-10-06T09:00:00.000Z'
const at = (seconds: number): string => new Date(Date.parse(T0) + seconds * 1000).toISOString()

/** Minimal evidence record, digest computed from the output it claims. */
function rec(options: {
  checkId: string
  status: CheckStatus
  at: string
  output?: string
  kind?: Evidence['kind']
  durationMs?: number
}): Evidence {
  const output = options.output ?? `observed output of ${options.checkId} ${options.status} at ${options.at}`
  return {
    evidenceId: `ev:${options.checkId}:${options.status}:${options.at}`,
    checkId: options.checkId,
    label: options.checkId,
    kind: options.kind ?? 'test',
    command: ['npm', 'run', '--silent', 'test'],
    source: 'config',
    status: options.status,
    exitCode: options.status === 'pass' ? 0 : 1,
    durationMs: options.durationMs ?? 42,
    outputDigest: sha256(output),
    outputHead: output,
    recordedAt: options.at,
    workspace: { head: null, dirty: [], dirtDigest: '' },
  }
}

function distill(over: Partial<DistillInput> & { records: readonly Evidence[] }): TrainingSet {
  return distillTrainingSet({
    baselineVerdicts: new Map<string, CheckVerdict>(),
    changedPaths: [],
    workspaceKey: 'ws-tests',
    fidelity: 'full',
    generatedAt: at(99),
    ...over,
  } as DistillInput)
}

function verificationsOf(set: TrainingSet): VerificationSample[] {
  return set.samples.filter((s): s is VerificationSample => s.kind === 'verification')
}

function pairsOf(set: TrainingSet): FlipPairSample[] {
  return set.samples.filter((s): s is FlipPairSample => s.kind === 'flip-pair')
}

// ---------------------------------------------------------------------------
// 1. THE GROUND-TRUTH EXHAUST
// ---------------------------------------------------------------------------

test('THE GROUND-TRUTH EXHAUST: every verdict class, both flip directions, honest exclusions', () => {
  // Baseline side, encoded the way the engine is told to encode it
  // (verdictOf(baseline, baseline) self-comparison):
  const baselineVerdicts = new Map<string, CheckVerdict>([
    ['t/one', 'still-passing'],   // baseline passed
    ['t/two', 'still-failing'],   // baseline failed
    ['t/four', 'indeterminate'],  // baseline timed out — no verdict can be minted
  ])

  const onePass0 = rec({ checkId: 't/one', status: 'pass', at: at(0) })
  const fiveFail0 = rec({ checkId: 't/five', status: 'fail', at: at(0), durationMs: 777 })
  const twoFail1 = rec({ checkId: 't/two', status: 'fail', at: at(1) })
  const oneTimeout2 = rec({ checkId: 't/one', status: 'timeout', at: at(2) })
  // A brand-new check this session, of a different kind, on a pre-ο record
  // (no source field survives) — the source fallback must say so.
  const threePass3: Evidence = {
    ...rec({ checkId: 't/three', status: 'pass', at: at(3), kind: 'typecheck' }),
    source: undefined,
  }
  const oneFail4 = rec({ checkId: 't/one', status: 'fail', at: at(4) })
  const fourPass5 = rec({ checkId: 't/four', status: 'pass', at: at(5) })
  const twoPass6 = rec({ checkId: 't/two', status: 'pass', at: at(6) })
  const onePass7 = rec({ checkId: 't/one', status: 'pass', at: at(7) })
  const oneError8 = rec({ checkId: 't/one', status: 'error', at: at(8) })
  const records = [onePass0, fiveFail0, twoFail1, oneTimeout2, threePass3, oneFail4, fourPass5, twoPass6, onePass7, oneError8]

  const set = distillTrainingSet({
    records,
    baselineVerdicts,
    // Deliberately unsorted: passthrough must be verbatim, not normalized.
    changedPaths: ['src/b.ts', 'src/a.ts'],
    workspaceKey: 'ws-exhaust',
    fidelity: 'full',
    generatedAt: at(60),
  })

  // --- the exhaust ledger: 7 verifications, 3 flip-pairs, exact order ------
  // Order is (recordedAt, checkId, kind); a pair sorts by its chosen side.
  assert.deepEqual(set.manifest.counts, { verification: 7, 'flip-pair': 3 })
  assert.equal(set.samples.length, 10)
  const shape = set.samples.map(s =>
    s.kind === 'verification'
      ? `${s.kind} ${s.checkId} ${s.recordedAt} ${s.verdict} ${s.reward}`
      : `${s.kind} ${s.checkId} chosen@${s.chosen.recordedAt} rejected@${s.rejected.recordedAt}`)
  assert.deepEqual(shape, [
    `verification t/five ${at(0)} new-failure 0`,
    `flip-pair t/one chosen@${at(0)} rejected@${at(4)}`,
    `verification t/one ${at(0)} still-passing 1`,
    `verification t/two ${at(1)} still-failing 0.5`,
    `verification t/three ${at(3)} new-check 0.5`,
    `verification t/one ${at(4)} regression 0`,
    `flip-pair t/two chosen@${at(6)} rejected@${at(1)}`,
    `verification t/two ${at(6)} fixed 1`,
    `flip-pair t/one chosen@${at(7)} rejected@${at(4)}`,
    `verification t/one ${at(7)} still-passing 1`,
  ])

  const verifications = verificationsOf(set)
  const pairs = pairsOf(set)
  const v = (checkId: string, stamp: string) => verifications.find(s => s.checkId === checkId && s.recordedAt === stamp)

  // --- every verdict class, with its reward and its evidence fields -------
  const one0 = v('t/one', at(0))
  assert.ok(one0)
  assert.equal(one0.verdict, 'still-passing')
  assert.equal(one0.reward, 1)
  assert.equal(one0.status, 'pass')
  assert.equal(one0.durationMs, onePass0.durationMs)
  assert.equal(one0.outputDigest, onePass0.outputDigest)
  assert.equal(one0.outputExcerpt, onePass0.outputHead)
  assert.equal(one0.checkKind, 'test')
  assert.equal(one0.source, 'config')

  assert.equal(v('t/one', at(4))?.verdict, 'regression')
  assert.equal(v('t/one', at(4))?.reward, 0)
  assert.equal(v('t/two', at(1))?.verdict, 'still-failing')
  assert.equal(v('t/two', at(1))?.reward, 0.5)
  assert.equal(v('t/two', at(6))?.verdict, 'fixed')
  assert.equal(v('t/two', at(6))?.reward, 1)
  assert.equal(v('t/three', at(3))?.verdict, 'new-check')
  assert.equal(v('t/three', at(3))?.reward, 0.5)
  assert.equal(v('t/three', at(3))?.checkKind, 'typecheck')
  assert.equal(v('t/three', at(3))?.source, 'unknown') // pre-ο record: no source field
  assert.equal(v('t/five', at(0))?.verdict, 'new-failure')
  assert.equal(v('t/five', at(0))?.reward, 0)
  assert.equal(v('t/five', at(0))?.durationMs, 777)

  // --- honest exclusions ---------------------------------------------------
  // Non-decisive records mint nothing...
  assert.equal(v('t/one', at(2)), undefined) // timeout
  assert.equal(v('t/one', at(8)), undefined) // error
  // ...and a decisive run against a baseline that never answered is excluded
  // rather than mislabeled with reward 0.
  assert.equal(v('t/four', at(5)), undefined)
  assert.equal(set.samples.some(s => s.checkId === 't/four'), false)

  // --- reward law consistency + verbatim context passthrough --------------
  for (const s of verifications) {
    assert.equal(s.reward, VERDICT_REWARD[s.verdict])
    assert.deepEqual(s.changedPaths, ['src/b.ts', 'src/a.ts'])
  }

  // --- flip-pairs: direction fixed, digests from the chain, no context bleed
  for (const s of pairs) {
    assert.equal(s.rejected.status, 'fail')
    assert.equal(s.chosen.status, 'pass')
    assert.ok(!('reward' in s))
    assert.ok(!('changedPaths' in s))
    assert.ok(!('verdict' in s))
  }
  const oneFall = pairs.find(s => s.checkId === 't/one' && s.chosen.recordedAt === at(0))
  assert.ok(oneFall)
  assert.equal(oneFall.rejected.outputDigest, oneFail4.outputDigest)
  assert.equal(oneFall.chosen.outputDigest, onePass0.outputDigest)
  assert.equal(oneFall.rejected.outputExcerpt, oneFail4.outputHead)
  assert.equal(oneFall.chosen.outputExcerpt, onePass0.outputHead)
  const twoRise = pairs.find(s => s.checkId === 't/two' && s.chosen.recordedAt === at(6))
  assert.ok(twoRise)
  assert.equal(twoRise.rejected.recordedAt, at(1))

  // --- sample surface is exactly the contract: no evidenceId, no exitCode,
  //     no workspace, no outputHead ever leaves the log ---------------------
  const first = verifications[0] as VerificationSample
  assert.deepEqual(Object.keys(first).sort(), [
    'changedPaths', 'checkId', 'checkKind', 'durationMs', 'kind',
    'outputDigest', 'outputExcerpt', 'recordedAt', 'reward', 'source', 'status', 'verdict',
  ])

  // --- manifest: self-describing, self-addressing --------------------------
  assert.equal(set.manifest.schema, TRAINING_SCHEMA)
  assert.equal(set.manifest.schema, 'dsh-training/1')
  assert.equal(set.manifest.fidelity, 'full')
  assert.equal(set.manifest.workspaceKey, 'ws-exhaust')
  assert.equal(set.manifest.generatedAt, at(60))
  assert.equal(set.manifest.provenanceFilter, 'all') // default, recorded honestly
  assert.equal(set.manifest.root, merkleRoot(set.samples.map(sampleHash)))
})

// ---------------------------------------------------------------------------
// 2. Reward law
// ---------------------------------------------------------------------------

test('the reward table is pinned law, snapshotted into every manifest', () => {
  // The eight values, literally. Neutral 0.5 for pre-existing (not the
  // agent's fault) and for a first-ever pass (nothing to compare against);
  // 0.0 filler only where construction keeps the verdict out of samples.
  assert.deepEqual(VERDICT_REWARD, {
    'still-passing': 1,
    'fixed': 1,
    'regression': 0,
    'new-failure': 0,
    'new-check': 0.5,
    'still-failing': 0.5,
    'not-run': 0,
    'indeterminate': 0,
  })
  assert.equal(Object.keys(VERDICT_REWARD).length, 8) // exhaustive over the verdict lattice

  const set = distill({ records: [rec({ checkId: 't/r', status: 'pass', at: at(0) })] })
  assert.deepEqual(set.manifest.rewardTable, VERDICT_REWARD)
  // Snapshot, not reference: the manifest carries its own copy, and mutating
  // a manifest cannot rewrite the law later datasets will be minted under.
  assert.notEqual(set.manifest.rewardTable, VERDICT_REWARD)
  ;(set.manifest.rewardTable as Record<string, number>).regression = 1
  assert.equal(VERDICT_REWARD.regression, 0)

  // License is opt-in deployer metadata — absent unless stated.
  assert.ok(!('license' in set.manifest))
})

// ---------------------------------------------------------------------------
// 3. Flip-pair pairing semantics
// ---------------------------------------------------------------------------

test('flip pairs pair adjacency inside the decisive subsequence', () => {
  const obs = (status: CheckStatus, i: number) => rec({ checkId: 'flaky', status, at: at(i) })

  // A non-decisive record between two decisive ones is no boundary:
  // pass → timeout → fail is still ONE pair (and only two samples).
  const viaTimeout = distill({ records: [obs('pass', 0), obs('timeout', 1), obs('fail', 2)] })
  assert.deepEqual(viaTimeout.manifest.counts, { verification: 2, 'flip-pair': 1 })
  const pair = pairsOf(viaTimeout)[0]
  assert.ok(pair)
  assert.equal(pair.rejected.recordedAt, at(2))
  assert.equal(pair.chosen.recordedAt, at(0))

  // error is equally non-decisive: pass → error → fail pairs the same way.
  const viaError = distill({ records: [obs('pass', 0), obs('error', 1), obs('fail', 2)] })
  assert.equal(viaError.manifest.counts['flip-pair'], 1)

  // Every adjacent disagreement pairs, not just the first.
  const zigzag = distill({ records: [obs('pass', 0), obs('fail', 1), obs('pass', 2)] })
  assert.deepEqual(zigzag.manifest.counts, { verification: 3, 'flip-pair': 2 })

  // A lone observation flips nothing.
  const lone = distill({ records: [obs('pass', 0)] })
  assert.deepEqual(lone.manifest.counts, { verification: 1, 'flip-pair': 0 })

  // Same-status neighbours pair nothing.
  const sameStatus = distill({ records: [obs('fail', 0), obs('fail', 1), obs('pass', 2)] })
  assert.deepEqual(sameStatus.manifest.counts, { verification: 3, 'flip-pair': 1 })

  // Both temporal directions collapse onto the one DPO direction; the
  // timing is carried by the stamps, never by the pair's shape.
  const fall = pairsOf(distill({ records: [obs('pass', 0), obs('fail', 1)] }))[0]
  const rise = pairsOf(distill({ records: [obs('fail', 0), obs('pass', 1)] }))[0]
  assert.ok(fall && rise)
  assert.equal(fall.chosen.recordedAt, at(0))
  assert.equal(fall.rejected.recordedAt, at(1))
  assert.equal(rise.chosen.recordedAt, at(1))
  assert.equal(rise.rejected.recordedAt, at(0))
  assert.equal(fall.rejected.status, 'fail')
  assert.equal(rise.chosen.status, 'pass')
})

// ---------------------------------------------------------------------------
// 4. Fidelity tiers
// ---------------------------------------------------------------------------

test('fidelity: private exports zero output text; full excerpts at 200 characters', () => {
  const sentinel = 'SECRET-HAWK-EYE-9917 leaked in a stack trace'
  const records = [
    rec({ checkId: 't/hush', status: 'fail', at: at(0), output: sentinel }),
    rec({ checkId: 't/hush', status: 'pass', at: at(1), output: sentinel }),
    rec({ checkId: 't/long', status: 'pass', at: at(2), output: 'Z'.repeat(350) }),
  ]

  // private: no output prose, not even the key that would hold it. Structure,
  // labels and digests still ride out.
  const priv = distillTrainingSet({
    records,
    baselineVerdicts: new Map<string, CheckVerdict>(),
    changedPaths: [],
    workspaceKey: 'ws-priv',
    fidelity: 'private',
    generatedAt: at(9),
  })
  const blob = JSON.stringify(priv.samples) + JSON.stringify(priv.manifest)
  assert.ok(!blob.includes('SECRET-HAWK-EYE-9917'))
  assert.ok(!blob.includes('stack trace'))
  assert.ok(!blob.includes('outputExcerpt'))
  assert.equal(priv.manifest.fidelity, 'private')
  for (const s of priv.samples) {
    if (s.kind === 'verification' && s.checkId === 't/hush') assert.equal(s.outputDigest, sha256(sentinel))
    if (s.kind === 'flip-pair') {
      assert.equal(s.rejected.outputDigest, sha256(sentinel))
      assert.equal(s.chosen.outputDigest, sha256(sentinel))
      assert.deepEqual(Object.keys(s.rejected).sort(), ['outputDigest', 'recordedAt', 'status'])
      assert.deepEqual(Object.keys(s.chosen).sort(), ['outputDigest', 'recordedAt', 'status'])
    }
  }

  // full: the text is there, truncated to exactly 200 characters.
  const full = distill({ records, fidelity: 'full' })
  const hush = verificationsOf(full).find(s => s.checkId === 't/hush')
  assert.ok(hush)
  assert.equal(hush.outputExcerpt, sentinel)
  const long = verificationsOf(full).find(s => s.checkId === 't/long')
  assert.ok(long)
  assert.equal(long.outputExcerpt?.length, 200)
  assert.equal(long.outputExcerpt, 'Z'.repeat(200))
  const pair = pairsOf(full)[0]
  assert.ok(pair)
  assert.equal(pair.rejected.outputExcerpt, sentinel)
  assert.equal(pair.chosen.outputExcerpt, sentinel)
  assert.deepEqual(Object.keys(pair.rejected).sort(), ['outputDigest', 'outputExcerpt', 'recordedAt', 'status'])
})

// ---------------------------------------------------------------------------
// 5. Provenance filter
// ---------------------------------------------------------------------------

test('provenance filter: one external edit voids verification labels, never flips', () => {
  const records = [
    rec({ checkId: 't/alpha', status: 'pass', at: at(0) }),
    rec({ checkId: 't/beta', status: 'fail', at: at(1) }),
    rec({ checkId: 't/beta', status: 'pass', at: at(2) }),
  ]
  const changedPaths = ['src/core/a.ts', 'vendor/gen.ts']
  const base = {
    records,
    baselineVerdicts: new Map<string, CheckVerdict>(),
    changedPaths,
    workspaceKey: 'ws-prov',
    fidelity: 'full' as const,
    generatedAt: at(9),
  }

  // agent-only + one external path: the session's causal claim is void, so
  // every verification label goes — flip-pairs stay (temporal facts), and
  // the manifest says exactly which filter emptied it.
  const agentOnly = distillTrainingSet({
    ...base,
    provenance: new Map([['src/core/a.ts', 'agent'], ['vendor/gen.ts', 'external']]),
    provenanceFilter: 'agent-only',
  })
  assert.deepEqual(agentOnly.manifest.counts, { verification: 0, 'flip-pair': 1 })
  assert.equal(agentOnly.manifest.provenanceFilter, 'agent-only')
  assert.ok(agentOnly.samples.every(s => s.kind === 'flip-pair'))

  // 'all' under the same provenance: nothing is filtered.
  const all = distillTrainingSet({
    ...base,
    provenance: new Map([['src/core/a.ts', 'agent'], ['vendor/gen.ts', 'external']]),
    provenanceFilter: 'all',
  })
  assert.deepEqual(all.manifest.counts, { verification: 3, 'flip-pair': 1 })
  assert.equal(all.manifest.provenanceFilter, 'all')

  // agent-only with a pure change set: the filter is not a blanket drop.
  const pure = distillTrainingSet({
    ...base,
    provenance: new Map([['src/core/a.ts', 'agent'], ['vendor/gen.ts', 'agent']]),
    provenanceFilter: 'agent-only',
  })
  assert.deepEqual(pure.manifest.counts, { verification: 3, 'flip-pair': 1 })

  // Externality only counts inside changedPaths: an external file nobody
  // touched this session voids nothing.
  const offSession = distillTrainingSet({
    ...base,
    provenance: new Map([['docs/README.md', 'external']]),
    provenanceFilter: 'agent-only',
  })
  assert.deepEqual(offSession.manifest.counts, { verification: 3, 'flip-pair': 1 })

  // Omitted filter defaults to 'all' — recorded in the manifest.
  const byDefault = distill({ records, changedPaths, provenance: new Map([['vendor/gen.ts', 'external']]) })
  assert.equal(byDefault.manifest.provenanceFilter, 'all')
  assert.deepEqual(byDefault.manifest.counts, { verification: 3, 'flip-pair': 1 })
})

// ---------------------------------------------------------------------------
// 6. Determinism
// ---------------------------------------------------------------------------

test('determinism: same input twice is byte-identical; a reordered log distills the same dataset', () => {
  const make = () => [
    rec({ checkId: 't/a', status: 'pass', at: at(0) }),
    rec({ checkId: 't/b', status: 'fail', at: at(1) }),
    rec({ checkId: 't/a', status: 'fail', at: at(2) }),
    rec({ checkId: 't/b', status: 'pass', at: at(3) }),
  ]
  const base = {
    baselineVerdicts: new Map<string, CheckVerdict>([['t/a', 'still-passing']]),
    changedPaths: ['src/a.ts'],
    workspaceKey: 'ws-det',
    fidelity: 'full' as const,
    generatedAt: at(9),
  }

  const first = distillTrainingSet({ ...base, records: make() })
  const second = distillTrainingSet({ ...base, records: make() })
  assert.deepEqual(first, second)
  assert.equal(JSON.stringify(first), JSON.stringify(second))

  // Reordered chain — each check's own sequence intact, timestamps untouched:
  // the output sort, not the input order, pins the bytes.
  const fresh = make()
  const reordered = [fresh[1], fresh[0], fresh[3], fresh[2]] as readonly Evidence[]
  const third = distillTrainingSet({ ...base, records: reordered })
  assert.deepEqual(third, first)
})

// ---------------------------------------------------------------------------
// 7. Content addressing
// ---------------------------------------------------------------------------

test('content addressing: sampleHash is the canonical digest cut to 16 hex; the root moves on one character', () => {
  const quiet = distill({ records: [rec({ checkId: 't/x', status: 'pass', at: at(0), output: 'all quiet on the western front' })] })
  const sample = quiet.samples[0] as TrainingSample
  assert.ok(sample)
  assert.match(sampleHash(sample), /^[0-9a-f]{16}$/)
  assert.equal(sampleHash(sample), sha256(canonicalJson(sample)).slice(0, 16))
  // One sample → the root is the Merkle root over that single leaf.
  assert.equal(quiet.manifest.root, merkleRoot([sampleHash(sample)]))

  // One character of one output moves the root (excerpt AND digest both
  // address the sample).
  const quieb = distill({ records: [rec({ checkId: 't/x', status: 'pass', at: at(0), output: 'all quiet on the western fronf' })] })
  assert.notEqual(quiet.manifest.root, quieb.manifest.root)

  // A label moves it too: same record, different baseline encoding → a
  // different verdict, a different reward, a different dataset.
  const record = rec({ checkId: 't/x', status: 'pass', at: at(0), output: 'all quiet on the western front' })
  const asFix = distill({ records: [record], baselineVerdicts: new Map([['t/x', 'still-failing']]) })
  const asNew = distill({ records: [record], baselineVerdicts: new Map<string, CheckVerdict>() })
  assert.equal(verificationsOf(asFix)[0]?.reward, 1) // fixed
  assert.equal(verificationsOf(asNew)[0]?.reward, 0.5) // new-check
  assert.notEqual(asFix.manifest.root, asNew.manifest.root)
})

// ---------------------------------------------------------------------------
// 8. The empty log
// ---------------------------------------------------------------------------

test('the empty log is a legal dataset', () => {
  const set = distillTrainingSet({
    records: [],
    baselineVerdicts: new Map<string, CheckVerdict>(),
    changedPaths: [],
    workspaceKey: 'ws-empty',
    fidelity: 'private',
    generatedAt: at(0),
    license: 'CC-BY-4.0',
  })
  assert.deepEqual(set.samples, [])
  assert.deepEqual(set.manifest.counts, { verification: 0, 'flip-pair': 0 })
  assert.equal(set.manifest.schema, TRAINING_SCHEMA)
  assert.equal(set.manifest.license, 'CC-BY-4.0')
  // merkleRoot over no leaves is sha256('') — the empty dataset still
  // addresses itself.
  assert.equal(set.manifest.root, sha256(''))
})
