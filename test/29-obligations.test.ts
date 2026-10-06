/**
 * OBLIGATIONS — the cross-agent responsibility DAG.
 *
 * Multi-agent delegation used to end at "the child said done". These tests
 * pin the machinery that replaces the handshake with a ledger: obligations
 * are content-addressed contracts, submissions are independently re-verifiable
 * bundles with a claimed grade, and the composition lattice folds a task's
 * whole subtree into one grade — pessimistically, with forgery nailed to the
 * floor and waivers allowed to buy missing work but never broken work.
 *
 * Anchors, in the order they run:
 *
 * 1. **Differential identities** — `obligationIdOf` is pinned byte-for-byte
 *    against a hand-written canonical string hashed with node:crypto directly
 *    (no project code on the expected side); `bundleFingerprint` against a
 *    hand-rolled sorted-digest join, and proven order-free.
 * 2. **THE ACCOUNTABLE DELEGATION** — the flagship narrative: two children,
 *    two verified bundles, one honest parent verdict — and what happens when
 *    one artifact stops verifying.
 * 3. **The composition matrix** — every child state × waiver × own grade,
 *    expectations hand-annotated per row from the lattice.
 * 4. **Forgery** — claimed proven + unverifiable artifact is regressed,
 *    listed, worded exactly, and immune to waivers.
 * 5. **Recursive composition** — three-layer chains, the forged middle, the
 *    unsubmitted organiser, and the diamond whose shared grandchild must
 *    compose once and answer both parents identically.
 * 6. **Cycles** — canonical path strings, deduped whatever order the walk
 *    enters them, and a composer that refuses to fold circular responsibility.
 * 7. **Waiver visibility** — waived work is excused AND shown; forged work is
 *    neither excused nor hidden.
 * 8. **Re-submission memory** (W7-8) — a booked forgery survives a clean
 *    re-submission (`mergeSubmission`); **id re-derivation** (W7-7) — a
 *    recorded obligation id that no longer addresses the record is a named
 *    rewrite. Plus the X-H-07 pin: a never-submitted leaf composes
 *    `unproven`, never a zero-blocker `proven`.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { sha256 } from '../src/core/hash.ts'
import type { ProofGrade } from '../src/core/evidence.ts'
import {
  bundleFingerprint, childrenByParent, composeTaskVerdict, composeVerdict,
  detectCycles, mergeSubmission, obligationIdOf, obligationRewriteProblem,
  type DagNode, type DelegationSubmission, type ObligationWaiver, type TaskObligation,
} from '../src/core/obligations.ts'

// ---------------------------------------------------------------------------
// Fixtures — deterministic, every timestamp supplied, nothing random
// ---------------------------------------------------------------------------

const T0 = '2026-10-06T09:00:00.000Z'

function obligation(n: number, over: Partial<TaskObligation> = {}): TaskObligation {
  return {
    v: 1,
    taskId: `task-${n}`,
    claim: `workspace proves claim-${n} end to end`,
    issuedAt: T0,
    issuedByWorkspace: 'ws-parent',
    ...over,
  }
}

function submission(over: Partial<DelegationSubmission> = {}): DelegationSubmission {
  return {
    childWorkspace: 'ws-child',
    bundleRoot: sha256('bundle-root'),
    claimedGrade: 'proven',
    artifactVerified: true,
    submittedAt: T0,
    ...over,
  }
}

function waiver(over: Partial<ObligationWaiver> = {}): ObligationWaiver {
  return { by: 'ops-lead', reason: 'scope accepted as-is', at: T0, ...over }
}

function node(n: number, over: Partial<DagNode> = {}): DagNode {
  return { obligation: obligation(n), ...over }
}

/** The seven child states the lattice distinguishes, as single-child nodes. */
type ChildState = 'proven' | 'stale' | 'unproven' | 'no-baseline' | 'regressed' | 'unsubmitted' | 'forged'

function childNode(state: ChildState, n = 7): DagNode {
  switch (state) {
    case 'proven':
      return node(n, { submission: submission({ transparencyVerified: true }) })
    case 'stale':
      return node(n, { submission: submission({ claimedGrade: 'stale' }) })
    case 'unproven':
      return node(n, { submission: submission({ claimedGrade: 'unproven' }) })
    case 'no-baseline':
      return node(n, { submission: submission({ claimedGrade: 'no-baseline' }) })
    case 'regressed':
      return node(n, { submission: submission({ claimedGrade: 'regressed' }) })
    case 'unsubmitted':
      return node(n)
    case 'forged':
      // The lie: proven claim, artifact that does not verify, and a problem
      // note from the verifier that must be passed through verbatim.
      return node(n, {
        submission: submission({
          claimedGrade: 'proven',
          artifactVerified: false,
          problems: ['manifest digests do not match file contents'],
        }),
      })
  }
}

function gradeMap(entries: readonly (readonly [string, ProofGrade])[]): ReadonlyMap<string, ProofGrade> {
  return new Map(entries)
}

// ---------------------------------------------------------------------------
// 1. Differential identities
// ---------------------------------------------------------------------------

test('obligationIdOf is exactly the first 16 hex of sha256(canonical bytes) — hand-computed', () => {
  const o = obligation(2, {
    parentTaskId: 'task-1',
    claim: 'the hash module passes all property tests',
    acceptance: 'npm test exits 0',
  })
  // canonicalJson sorts keys and drops absent optionals; written out by hand
  // so the expected side shares no code with the implementation:
  const canonical =
    '{"acceptance":"npm test exits 0","claim":"the hash module passes all property tests",'
    + '"issuedAt":"2026-10-06T09:00:00.000Z","issuedByWorkspace":"ws-parent",'
    + '"parentTaskId":"task-1","taskId":"task-2","v":1}'
  const manual = createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16)
  assert.equal(obligationIdOf(o), manual)
  assert.match(obligationIdOf(o), /^[0-9a-f]{16}$/)
})

test('obligationIdOf is stable, key-order-free, and moves on a one-character claim edit', () => {
  const o = obligation(3, { parentTaskId: 'task-1', acceptance: 'no new dependencies' })
  // Same id on every call, forever.
  assert.equal(obligationIdOf(o), obligationIdOf(o))
  // Key insertion order is not part of the identity (canonical bytes are).
  const shuffled: TaskObligation = {
    issuedByWorkspace: o.issuedByWorkspace,
    acceptance: o.acceptance,
    v: 1,
    issuedAt: o.issuedAt,
    claim: o.claim,
    taskId: o.taskId,
    parentTaskId: o.parentTaskId,
  }
  assert.equal(obligationIdOf(shuffled), obligationIdOf(o))
  // An explicitly-undefined optional is the same record as an absent one.
  assert.equal(obligationIdOf({ ...o, acceptance: undefined, parentTaskId: undefined }), obligationIdOf(obligation(3)))
  // One character of claim is a different contract.
  assert.notEqual(obligationIdOf({ ...o, claim: `${o.claim}!` }), obligationIdOf(o))
  // And so is every other bound field.
  assert.notEqual(obligationIdOf({ ...o, taskId: 'task-4' }), obligationIdOf(o))
  assert.notEqual(obligationIdOf({ ...o, issuedByWorkspace: 'ws-impostor' }), obligationIdOf(o))
  assert.notEqual(obligationIdOf({ ...o, issuedAt: '2026-10-06T10:00:00.000Z' }), obligationIdOf(o))
})

test('bundleFingerprint is sha256 over the sorted digest column — hand-computed and order-free', () => {
  const files = [
    { path: 'evidence.jsonl', sha256: sha256('evidence') },
    { path: 'baseline.json', sha256: sha256('baseline') },
    { path: 'anchor.json', sha256: sha256('anchor') },
  ]
  const manual = createHash('sha256')
    .update(files.map(f => f.sha256).sort().join('\n'), 'utf8')
    .digest('hex')
  assert.equal(bundleFingerprint(files), manual)
  // Any permutation of the manifest addresses the same bundle.
  assert.equal(bundleFingerprint([files[2]!, files[0]!, files[1]!]), manual)
  assert.equal(bundleFingerprint([...files].reverse()), manual)
  // Different content, different fingerprint; duplicates count.
  assert.notEqual(
    bundleFingerprint([...files, { path: 'extra.txt', sha256: sha256('extra') }]),
    manual,
  )
  assert.notEqual(bundleFingerprint([files[0]!, files[0]!]), bundleFingerprint([files[0]!]))
  // The empty manifest has the empty-string root, matching merkleRoot([]).
  assert.equal(bundleFingerprint([]), createHash('sha256').digest('hex'))
})

// ---------------------------------------------------------------------------
// 2. THE ACCOUNTABLE DELEGATION (flagship)
// ---------------------------------------------------------------------------

test('THE ACCOUNTABLE DELEGATION: two verified bundles compose one honest proven verdict', () => {
  // ws-parent mints two obligations under task-1, each with its claim bound
  // by content address at delegation time.
  const port = obligation(2, { parentTaskId: 'task-1', claim: 'the port keeps every hash test green' })
  const cli = obligation(3, { parentTaskId: 'task-1', claim: 'the CLI reports grades without a workspace' })
  const mintedIds = new Set([obligationIdOf(port), obligationIdOf(cli)])

  // Both children run in their own workspaces and turn in bundles; the engine
  // verified each artifact and anchored it by the fingerprint of its manifest.
  const portManifest = [
    { path: 'evidence.jsonl', sha256: sha256('port-evidence') },
    { path: 'baseline.json', sha256: sha256('port-baseline') },
  ]
  const cliManifest = [
    { path: 'evidence.jsonl', sha256: sha256('cli-evidence') },
    { path: 'anchor.json', sha256: sha256('cli-anchor') },
  ]
  const portRoot = bundleFingerprint(portManifest)
  const cliRoot = bundleFingerprint(cliManifest)

  const root = node(1, {})
  const tree: readonly DagNode[] = [
    root,
    node(2, {
      obligation: port,
      submission: submission({ childWorkspace: 'ws-port', bundleRoot: portRoot, transparencyVerified: true }),
    }),
    node(3, {
      obligation: cli,
      submission: submission({ childWorkspace: 'ws-cli', bundleRoot: cliRoot }),
    }),
  ]

  // The parent did none of the work itself — pure delegation.
  const verdict = composeTaskVerdict('task-1', tree, gradeMap([]))
  assert.deepEqual(
    { grade: verdict.grade, own: verdict.own },
    { grade: 'proven', own: true },
    'both children proven + pure-delegation parent → proven',
  )
  assert.deepEqual(verdict.forgedChildren, [])
  assert.deepEqual(verdict.regressedChildren, [])
  assert.deepEqual(verdict.unprovenChildren, [])
  assert.deepEqual(verdict.waived, [])
  assert.deepEqual(verdict.blockers, [])

  // The anchors are re-derivable by any third party from the manifests alone,
  // in any order — the audit that makes "verified" mean something later.
  assert.equal(bundleFingerprint([...portManifest].reverse()), portRoot)
  assert.equal(bundleFingerprint([...cliManifest].reverse()), cliRoot)
  // And the obligation identities still address what was minted.
  assert.equal(obligationIdOf(tree[1]!.obligation), [...mintedIds][0])
  assert.equal(obligationIdOf(tree[2]!.obligation), [...mintedIds][1])

  // --- the twist: the CLI bundle later fails independent re-verification ---
  // Same proven claim, artifact now unverifiable — and a transparency record
  // changes nothing, because the artifact is what the claim stands on.
  const brokenCli = node(3, {
    obligation: cli,
    submission: submission({
      childWorkspace: 'ws-cli',
      bundleRoot: cliRoot,
      claimedGrade: 'proven',
      artifactVerified: false,
      transparencyVerified: true,
      problems: ['chain walk diverges at line 41'],
    }),
  })
  const after = composeTaskVerdict('task-1', [root, tree[1]!, brokenCli], gradeMap([]))
  assert.equal(after.grade, 'regressed', 'a child that claims proven on an unverifiable artifact is forgery, not noise')
  assert.deepEqual(after.forgedChildren, ['task-3'])
  assert.deepEqual(after.blockers, [
    'task-3 claimed proven but its artifact does not verify',
    'task-3: chain walk diverges at line 41',
  ])
})

// ---------------------------------------------------------------------------
// 3. The composition matrix — child state × waiver × own grade
// ---------------------------------------------------------------------------

test('the composition matrix: every child state, waived and not, over every own grade', () => {
  type Row = {
    name: string
    child: ChildState
    waived: boolean
    own: ProofGrade | undefined
    grade: ProofGrade
    ownFlag: boolean
    forged?: readonly string[]
    regressed?: readonly string[]
    unproven?: readonly string[]
    waivedList?: readonly string[]
    has?: readonly string[]
    absent?: readonly string[]
  }
  // Expectations hand-annotated from the lattice, one child (task-7) per row:
  //   broken work (forged/regressed — child OR own) → regressed, waiver
  //   powerless; missing work (stale/unproven/no-baseline/unsubmitted) →
  //   stale unless waived; all children fine → the parent's own grade, with
  //   undefined (pure delegation) reading as proven. X-H-18 pins the cross
  //   product the old priority ordering laundered: own regressed × missing
  //   child is REGRESSED, not a waivable stale — more bad news must never
  //   make the verdict easier to waive.
  const rows: readonly Row[] = [
    // -- one PROVEN child: the verdict is the parent's own story --
    { name: 'proven child / pure delegation', child: 'proven', waived: false, own: undefined, grade: 'proven', ownFlag: true, absent: ['task-7'] },
    { name: 'proven child / own proven', child: 'proven', waived: false, own: 'proven', grade: 'proven', ownFlag: true },
    { name: 'proven child / own stale → degrades as-is', child: 'proven', waived: false, own: 'stale', grade: 'stale', ownFlag: false, has: ['own workspace evidence is stale'] },
    { name: 'proven child / own regressed', child: 'proven', waived: false, own: 'regressed', grade: 'regressed', ownFlag: false, has: ['own workspace evidence is regressed'] },
    // -- missing work blocks proven, but a waiver excuses exactly this --
    { name: 'stale child', child: 'stale', waived: false, own: 'proven', grade: 'stale', ownFlag: true, unproven: ['task-7'], has: ['task-7 is not proven (stale)'] },
    { name: 'stale child waived → excused, waiver visible', child: 'stale', waived: true, own: undefined, grade: 'proven', ownFlag: true, waivedList: ['task-7'], has: ['task-7 waived by ops-lead'], absent: ['not proven'] },
    { name: 'unproven child', child: 'unproven', waived: false, own: 'proven', grade: 'stale', ownFlag: true, unproven: ['task-7'], has: ['task-7 is not proven (unproven)'] },
    { name: 'unproven child waived', child: 'unproven', waived: true, own: undefined, grade: 'proven', ownFlag: true, waivedList: ['task-7'], absent: ['not proven'] },
    { name: 'no-baseline child', child: 'no-baseline', waived: false, own: 'proven', grade: 'stale', ownFlag: true, unproven: ['task-7'], has: ['task-7 is not proven (no-baseline)'] },
    { name: 'no-baseline child waived', child: 'no-baseline', waived: true, own: undefined, grade: 'proven', ownFlag: true, waivedList: ['task-7'], absent: ['not proven'] },
    { name: 'unsubmitted child', child: 'unsubmitted', waived: false, own: 'proven', grade: 'stale', ownFlag: true, unproven: ['task-7'], has: ['task-7 has no submission on record'] },
    { name: 'unsubmitted child waived', child: 'unsubmitted', waived: true, own: undefined, grade: 'proven', ownFlag: true, waivedList: ['task-7'], has: ['task-7 waived by ops-lead'], absent: ['no submission'] },
    // -- broken work: regressed, and a waiver buys nothing --
    { name: 'regressed child', child: 'regressed', waived: false, own: 'proven', grade: 'regressed', ownFlag: true, regressed: ['task-7'], has: ['task-7 is regressed'] },
    { name: 'regressed child WITH waiver → still regressed', child: 'regressed', waived: true, own: 'proven', grade: 'regressed', ownFlag: true, regressed: ['task-7'], waivedList: ['task-7'], has: ['task-7 is regressed', 'task-7 waived by ops-lead'] },
    // -- forged work: the loudest fact, immune to everything --
    { name: 'forged child', child: 'forged', waived: false, own: 'proven', grade: 'regressed', ownFlag: true, forged: ['task-7'], has: ['task-7 claimed proven but its artifact does not verify', 'task-7: manifest digests do not match file contents'] },
    { name: 'forged child WITH waiver → waiver is decoration', child: 'forged', waived: true, own: 'proven', grade: 'regressed', ownFlag: true, forged: ['task-7'], waivedList: ['task-7'], has: ['claimed proven but its artifact does not verify', 'waived by ops-lead'] },
    // -- X-H-18: own broken work × missing child — the degradation is NOT
    //    laundered into a waivable stale by the child's absence --
    { name: 'own regressed + unsubmitted child → regressed (X-H-18)', child: 'unsubmitted', waived: false, own: 'regressed', grade: 'regressed', ownFlag: false, unproven: ['task-7'], has: ['task-7 has no submission on record', 'own workspace evidence is regressed'] },
    { name: 'own regressed + stale child → regressed (X-H-18)', child: 'stale', waived: false, own: 'regressed', grade: 'regressed', ownFlag: false, unproven: ['task-7'], has: ['task-7 is not proven (stale)', 'own workspace evidence is regressed'] },
    { name: 'own regressed + WAIVED unsubmitted child → still regressed (X-H-18: the waiver excuses the child, never the own work)', child: 'unsubmitted', waived: true, own: 'regressed', grade: 'regressed', ownFlag: false, waivedList: ['task-7'], has: ['own workspace evidence is regressed'], absent: ['has no submission'] },
    { name: 'own stale + unsubmitted child → stale (missing work does not upgrade a mere process gap)', child: 'unsubmitted', waived: false, own: 'stale', grade: 'stale', ownFlag: false, unproven: ['task-7'], has: ['task-7 has no submission on record', 'own workspace evidence is stale'] },
  ]

  for (const r of rows) {
    const n = childNode(r.child)
    const dag: DagNode = r.waived ? { ...n, waiver: waiver() } : n
    const v = composeVerdict([dag], r.own)
    assert.equal(v.grade, r.grade, `grade: ${r.name}`)
    assert.equal(v.own, r.ownFlag, `own: ${r.name}`)
    assert.deepEqual(v.forgedChildren, [...(r.forged ?? [])], `forgedChildren: ${r.name}`)
    assert.deepEqual(v.regressedChildren, [...(r.regressed ?? [])], `regressedChildren: ${r.name}`)
    assert.deepEqual(v.unprovenChildren, [...(r.unproven ?? [])], `unprovenChildren: ${r.name}`)
    assert.deepEqual(v.waived, [...(r.waivedList ?? [])], `waived: ${r.name}`)
    for (const needle of r.has ?? []) {
      assert.ok(v.blockers.some(b => b.includes(needle)), `${r.name}: blocker containing "${needle}" — got ${JSON.stringify(v.blockers)}`)
    }
    for (const banned of r.absent ?? []) {
      assert.ok(!v.blockers.some(b => b.includes(banned)), `${r.name}: no blocker containing "${banned}" — got ${JSON.stringify(v.blockers)}`)
    }
  }
})

test('priority order: regressed beats missing work beats own grade — and the lists stay honest', () => {
  // One parent, three children: forged task-2, stale task-3, unsubmitted
  // task-4, own proven. The grade is the WORST fact; the lists record ALL of
  // them — lists are descriptive, the grade is priority.
  const v = composeVerdict(
    [childNode('forged', 2), childNode('stale', 3), childNode('unsubmitted', 4)],
    'proven',
  )
  assert.equal(v.grade, 'regressed')
  assert.equal(v.own, true)
  assert.deepEqual(v.forgedChildren, ['task-2'])
  assert.deepEqual(v.regressedChildren, [])
  assert.deepEqual(v.unprovenChildren, ['task-3', 'task-4'])
  assert.deepEqual(v.blockers, [
    'task-2 claimed proven but its artifact does not verify',
    'task-4 has no submission on record',
    'task-3 is not proven (stale)',
    'task-2: manifest digests do not match file contents',
  ])

  // Drop the forged child: missing work takes over — stale, not regressed.
  const missing = composeVerdict([childNode('stale', 3), childNode('unsubmitted', 4)], 'proven')
  assert.equal(missing.grade, 'stale')
  assert.deepEqual(missing.unprovenChildren, ['task-3', 'task-4'])

  // Waive the unsubmitted one and only the stale child still blocks.
  const partlyWaived = composeVerdict(
    [childNode('stale', 3), { ...childNode('unsubmitted', 4), waiver: waiver() }],
    'proven',
  )
  assert.equal(partlyWaived.grade, 'stale')
  assert.deepEqual(partlyWaived.unprovenChildren, ['task-3'])
  assert.deepEqual(partlyWaived.waived, ['task-4'])
})

test('a childless task is its own evidence: own grade as-is, undefined reads as proven', () => {
  assert.deepEqual(composeVerdict([], undefined), {
    grade: 'proven', own: true, forgedChildren: [], regressedChildren: [],
    unprovenChildren: [], waived: [], blockers: [],
  })
  assert.deepEqual(composeVerdict([], 'stale'), {
    grade: 'stale', own: false, forgedChildren: [], regressedChildren: [],
    unprovenChildren: [], waived: [], blockers: ['own workspace evidence is stale'],
  })
  assert.equal(composeVerdict([], 'regressed').grade, 'regressed')
  // A leaf task composed recursively behaves the same way (rule 4).
  const leaf = composeTaskVerdict('task-9', [node(9)], gradeMap([['task-9', 'no-baseline']]))
  assert.equal(leaf.grade, 'no-baseline')
  assert.deepEqual(leaf.blockers, ['own workspace evidence is no-baseline'])
})

test('X-H-07: a never-submitted leaf composes unproven — absence is not discharge', () => {
  // No children, no submission, no engine measurement: the OLD ownLevelOf
  // answered undefined ("pure delegation") and the lattice's fallback minted
  // a zero-blocker proven out of pure absence. Nobody proved the claim, so
  // the honest verdict is unproven.
  const v = composeTaskVerdict('task-9', [node(9)], gradeMap([]))
  assert.equal(v.grade, 'unproven')
  assert.equal(v.own, false)
  assert.deepEqual(v.forgedChildren, [])
  assert.deepEqual(v.regressedChildren, [])
  assert.deepEqual(v.unprovenChildren, [])
  assert.deepEqual(v.blockers, ['own workspace evidence is unproven'])

  // The default only fills pure absence — a measurement or a submission
  // still speaks first.
  assert.equal(composeTaskVerdict('task-9', [node(9)], gradeMap([['task-9', 'stale']])).grade, 'stale')
  assert.equal(
    composeTaskVerdict('task-9', [node(9, { submission: submission({ claimedGrade: 'stale' }) })], gradeMap([])).grade,
    'stale',
  )
  // A pure delegator WITH children keeps the pure-delegation reading: the
  // undefined own-grade means "delegated everything", and the children
  // carry the verdict (see the flagship test).
  const org = composeTaskVerdict(
    'task-1',
    [node(1), node(2, { obligation: obligation(2, { parentTaskId: 'task-1' }), submission: submission() })],
    gradeMap([]),
  )
  assert.equal(org.grade, 'proven')
})

test('X-H-18 recursion: own-regressed middle + unsubmitted grandchild regresses the root', () => {
  // The middle child honestly reports its own workspace regressed; its own
  // subcontractor never submitted. The old priority folded the middle to a
  // waivable 'stale' at the root — buying out the degradation with someone
  // else's missing work. The own regression must survive the fold.
  const tree = chain(
    { submission: submission({ claimedGrade: 'regressed', artifactVerified: true }) },
    childNode('unsubmitted', 3),
  )
  const root = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'regressed')
  assert.deepEqual(root.regressedChildren, ['task-2'], 'the middle carries its own regression up, not a laundered stale')

  // Waiving the missing grandchild excuses the missing work — and ONLY the
  // missing work: the middle's own degradation still holds the root.
  const waivered = chain(
    { submission: submission({ claimedGrade: 'regressed', artifactVerified: true }) },
    { ...childNode('unsubmitted', 3), waiver: waiver() },
  )
  const waivedRoot = composeTaskVerdict('task-1', waivered, gradeMap([['task-1', 'proven']]))
  assert.equal(waivedRoot.grade, 'regressed', 'waiver excuses missing work, never broken work')
  assert.deepEqual(waivedRoot.regressedChildren, ['task-2'])
})

// ---------------------------------------------------------------------------
// 4. Forgery, nailed down
// ---------------------------------------------------------------------------

test('FORGERY: claimed proven + unverifiable artifact is regressed, worded exactly, and no waiver saves it', () => {
  const v = composeVerdict([childNode('forged', 5)], undefined)
  assert.equal(v.grade, 'regressed')
  assert.deepEqual(v.forgedChildren, ['task-5'])
  // The wording is the cross-agent contract — pinned character for character.
  assert.deepEqual(v.blockers, [
    'task-5 claimed proven but its artifact does not verify',
    'task-5: manifest digests do not match file contents',
  ])

  // The waiver attempt: the waiver is RECORDED (a human tried to accept it)
  // and CHANGES NOTHING — a waiver excuses missing work, never a lie.
  const w = composeVerdict([{ ...childNode('forged', 5), waiver: waiver({ by: 'cto', reason: 'ship it anyway' }) }], 'proven')
  assert.equal(w.grade, 'regressed', 'a waiver cannot buy out forgery')
  assert.deepEqual(w.forgedChildren, ['task-5'])
  assert.deepEqual(w.waived, ['task-5'], 'the futile waiver stays visible on the record')
  assert.deepEqual(w.blockers, [
    'task-5 claimed proven but its artifact does not verify',
    'task-5 waived by cto: ship it anyway',
    'task-5: manifest digests do not match file contents',
  ])

  // Honesty next to the lie, for contrast: a child claiming regressed on a
  // VERIFIED artifact is honest bad news — regressed, but never "forged".
  const honest = composeVerdict([childNode('regressed', 6)], undefined)
  assert.equal(honest.grade, 'regressed')
  assert.deepEqual(honest.forgedChildren, [])
  assert.deepEqual(honest.regressedChildren, ['task-6'])
})

// ---------------------------------------------------------------------------
// 5. Recursive composition
// ---------------------------------------------------------------------------

/** task-1 → task-2 → task-3, with the grandchild and middle configurable. */
function chain(middle: Partial<DagNode>, grandchild: DagNode): readonly DagNode[] {
  return [
    node(1),
    node(2, { obligation: obligation(2, { parentTaskId: 'task-1' }), ...middle }),
    // The grandchild's own facts (submission/waiver) with its parent set to
    // the middle task — the spread order matters, or the link is lost.
    { ...grandchild, obligation: obligation(3, { ...grandchild.obligation, parentTaskId: 'task-2' }) },
  ]
}

test('recursion: a regressed grandchild regresses the child, which regresses the parent', () => {
  const tree = chain(
    { submission: submission() }, // middle claims proven, artifact verified
    childNode('regressed', 3),    // grandchild honestly reports regression
  )
  // Rule 2 applied recursively: the child's effective grade is composed from
  // its own child, and the regressed grandchild wins over the middle's claim.
  const mid = composeTaskVerdict('task-2', tree, gradeMap([]))
  assert.equal(mid.grade, 'regressed')
  assert.deepEqual(mid.regressedChildren, ['task-3'])
  assert.deepEqual(mid.blockers, ['task-3 is regressed'])

  const root = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'regressed')
  assert.deepEqual(root.regressedChildren, ['task-2'], 'the middle child carries its subtree verdict up')
  assert.deepEqual(root.blockers, ['task-2 is regressed'])
})

test('recursion: an unsubmitted grandchild makes the child stale, the parent stale', () => {
  const tree = chain(
    { submission: submission() },
    childNode('unsubmitted', 3),
  )
  const root = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'stale', 'missing work one level down is still missing work')
  assert.deepEqual(root.unprovenChildren, ['task-2'])
  assert.deepEqual(root.blockers, ['task-2 is not proven (stale)'])

  // Waiving the GRANDCHILD unblocks the whole chain from the top.
  const waivered = chain(
    { submission: submission() },
    { ...childNode('unsubmitted', 3), waiver: waiver() },
  )
  const waivedRoot = composeTaskVerdict('task-1', waivered, gradeMap([['task-1', 'proven']]))
  assert.equal(waivedRoot.grade, 'proven')
  assert.deepEqual(waivedRoot.waived, [], 'the parent sees its DIRECT children: the waiver lives a level down')
})

test('recursion: a forged MIDDLE child surfaces as forgery at the top, whatever its subtree says', () => {
  // The middle child delegated successfully (grandchild proven) but its own
  // submission claims proven on an artifact that does not verify. The forgery
  // is about the child's own claim and must reach the parent's forgedChildren.
  const tree = chain(
    { submission: submission({ claimedGrade: 'proven', artifactVerified: false, problems: ['root digest mismatch'] }) },
    childNode('proven', 3),
  )
  const root = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'regressed')
  assert.deepEqual(root.forgedChildren, ['task-2'])
  assert.deepEqual(root.blockers, [
    'task-2 claimed proven but its artifact does not verify',
    'task-2: root digest mismatch',
  ])
})

test('recursion: a pure organiser that never submitted is unsubmitted, even over a green subtree', () => {
  // Documented lattice rule: the middle child ran its own delegation (the
  // grandchild is proven and verified) but never turned in a bundle for ITS
  // obligation. Nobody proved the middle claim — cross-agent proof travels in
  // bundles, so the parent sees unsubmitted, not a free pass.
  const tree = chain({}, childNode('proven', 3))
  const root = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'stale')
  assert.deepEqual(root.unprovenChildren, ['task-2'])
  assert.deepEqual(root.blockers, ['task-2 has no submission on record'])

  // But if the engine MEASURED that workspace itself (ownGrades), the
  // measurement is its own-grade input and a green subtree carries it.
  const measured = composeTaskVerdict('task-1', tree, gradeMap([['task-1', 'proven'], ['task-2', 'proven']]))
  assert.equal(measured.grade, 'proven')
})

test('the diamond: a grandchild shared by two parents composes once and answers both identically', () => {
  // task-1 → {task-2, task-3}; both task-2 and task-3 parent task-4 (the
  // same taskId registered under two parents — the shared-grandchild shape
  // the memo exists for). task-4 honestly reports regression.
  const shared4 = childNode('regressed', 4)
  const shared = (parent: string): DagNode => ({
    ...shared4,
    obligation: obligation(4, { ...shared4.obligation, parentTaskId: parent }),
  })
  const diamond: readonly DagNode[] = [
    node(1),
    node(2, { obligation: obligation(2, { parentTaskId: 'task-1' }), submission: submission() }),
    node(3, { obligation: obligation(3, { parentTaskId: 'task-1' }), submission: submission() }),
    shared('task-2'),
    shared('task-3'),
  ]
  const root = composeTaskVerdict('task-1', diamond, gradeMap([['task-1', 'proven']]))
  assert.equal(root.grade, 'regressed')
  assert.deepEqual(root.regressedChildren, ['task-2', 'task-3'], 'both parents carry the shared verdict up, identically')

  // Composed from either parent alone, the shared grandchild answers the same.
  assert.equal(composeTaskVerdict('task-2', diamond, gradeMap([])).grade, 'regressed')
  assert.equal(composeTaskVerdict('task-3', diamond, gradeMap([])).grade, 'regressed')

  // Green version of the same diamond: both paths proven. Each task-4 record
  // keeps its own obligation (and therefore its own parent link); only the
  // submission is swapped for an honest, verified one.
  const greenDiamond: readonly DagNode[] = diamond.map(n =>
    n.obligation.taskId === 'task-4' ? { ...n, submission: submission() } : n,
  )
  assert.equal(composeTaskVerdict('task-1', greenDiamond, gradeMap([['task-1', 'proven']])).grade, 'proven')

  // The memo must not leak between calls: same DAG, different own grades —
  // each invocation consults its own inputs from scratch.
  const first = composeTaskVerdict('task-1', greenDiamond, gradeMap([['task-1', 'proven']]))
  const second = composeTaskVerdict('task-1', greenDiamond, gradeMap([['task-1', 'stale']]))
  assert.equal(first.grade, 'proven')
  assert.equal(second.grade, 'stale', 'a cached "proven" from the first call must not survive into the second')
  assert.deepEqual(second.blockers, ['own workspace evidence is stale'])
  assert.equal(composeTaskVerdict('task-1', greenDiamond, gradeMap([['task-1', 'proven']])).grade, 'proven')
})

// ---------------------------------------------------------------------------
// 6. Cycles
// ---------------------------------------------------------------------------

/** a → b → c → a in delegation direction: each child's parent is the previous. */
function cycleObligations(): readonly TaskObligation[] {
  return [
    obligation(1, { taskId: 'a', parentTaskId: 'c' }),
    obligation(1, { taskId: 'b', parentTaskId: 'a' }),
    obligation(1, { taskId: 'c', parentTaskId: 'b' }),
  ]
}

test('detectCycles returns the canonical delegation-direction path, once, in any input order', () => {
  assert.deepEqual(detectCycles(cycleObligations()), ['a -> b -> c -> a'])

  // Entering the walk from another member, or shuffling the input, still
  // finds the same cycle exactly once (canonical rotation dedupes).
  for (const perm of [
    ['b', 'c', 'a'],
    ['c', 'a', 'b'],
    ['c', 'b', 'a'],
  ] as const) {
    const byId = new Map(cycleObligations().map(o => [o.taskId, o]))
    const shuffled = perm.map(id => byId.get(id) as TaskObligation)
    assert.deepEqual(detectCycles(shuffled), ['a -> b -> c -> a'])
  }

  // A tail hanging into the cycle (d delegated into a) is not part of it.
  const withTail = [...cycleObligations(), obligation(1, { taskId: 'd', parentTaskId: 'a' })]
  assert.deepEqual(detectCycles(withTail), ['a -> b -> c -> a'])
})

test('detectCycles: self-loops, disjoint cycles, dangling parents, and clean forests', () => {
  // Self-delegation is the shortest possible lie.
  assert.deepEqual(detectCycles([obligation(1, { taskId: 'x', parentTaskId: 'x' })]), ['x -> x'])
  // A two-step loop.
  assert.deepEqual(detectCycles([
    obligation(1, { taskId: 'p', parentTaskId: 'q' }),
    obligation(1, { taskId: 'q', parentTaskId: 'p' }),
  ]), ['p -> q -> p'])
  // Disjoint cycles: all reported, sorted, none hidden.
  const two = [
    obligation(1, { taskId: 'c', parentTaskId: 'c' }),
    obligation(1, { taskId: 'a', parentTaskId: 'b' }),
    obligation(1, { taskId: 'b', parentTaskId: 'a' }),
  ]
  assert.deepEqual(detectCycles(two), ['a -> b -> a', 'c -> c'])
  // A parent that was never minted ends the walk: a minting bug, not a cycle.
  assert.deepEqual(detectCycles([obligation(1, { parentTaskId: 'ghost' })]), [])
  // Forests, deep chains, shared roots: no cycles to find.
  assert.deepEqual(detectCycles([
    obligation(1), obligation(2, { parentTaskId: 'task-1' }),
    obligation(3, { parentTaskId: 'task-2' }), obligation(4),
  ]), [])
  assert.deepEqual(detectCycles([]), [])
})

test('V7-M4: a 50k-deep adversarial parent chain gets a verdict, not a RangeError', () => {
  // Obligations come from chain markers an adversary can shape; a cycle-free
  // but DEEP chain used to blow the JS call stack twice — once in
  // detectCycles's recursive DFS, once in the composition fold's mutual
  // effectiveOf/factsOf recursion (when the query sat at the chain's deep
  // end) — before any graceful refusal or verdict could be delivered. Both
  // walks are iterative now; this pins the depth they must survive.
  const depth = 50_000
  const chain: TaskObligation[] = Array.from({ length: depth }, (_, i) =>
    obligation(i + 1, { parentTaskId: `task-${i + 2}` }))
  assert.deepEqual(detectCycles(chain), [], 'deep and acyclic: no cycle, no crash')
  // Query from EITHER end: the leaf side (subtree = itself)…
  const leaf = composeTaskVerdict('task-1', chain.map(o => ({ obligation: o })), new Map())
  assert.equal(leaf.grade, 'unproven', 'an unsubmitted leaf-side task composes, not crashes')
  // …and the deep root (the fold traverses all 50k levels).
  const root = composeTaskVerdict(`task-${depth}`, chain.map(o => ({ obligation: o })), new Map())
  assert.notEqual(root.grade, undefined, 'the deep-root fold returns a verdict, not a stack overflow')
  // And cycle behaviour at depth is unchanged: a self-loop 50k tasks down is
  // still detected and still refuses the whole composition.
  const selfLoop = [...chain.slice(0, depth - 1), obligation(depth, { taskId: `task-${depth}`, parentTaskId: `task-${depth}` })]
  assert.deepEqual(detectCycles(selfLoop), [`task-${depth} -> task-${depth}`])
  const refused = composeTaskVerdict('task-1', selfLoop.map(o => ({ obligation: o })), new Map())
  assert.equal(refused.grade, 'unproven')
  assert.equal(refused.blockers[0], 'responsibility cycle detected')
})

test('W7-5: a duplicate taskId whose later copy self-parents is a detected cycle, not an unbounded fold', () => {
  // task-2 was minted under task-1, then a second record re-registered
  // task-2 under ITSELF. The old first-wins walk saw only the first record's
  // parent edge, found no cycle — and the recursive fold grouped children by
  // every record, chased task-2's children through its own duplicate, and
  // blew the stack. Every recorded edge is walked now.
  const duplicated: readonly TaskObligation[] = [
    obligation(1),
    obligation(2, { parentTaskId: 'task-1' }),
    obligation(2, { parentTaskId: 'task-2' }),
  ]
  assert.deepEqual(detectCycles(duplicated), ['task-2 -> task-2'])
  // The composer refuses with the cycle verdict instead of crashing.
  const v = composeTaskVerdict('task-1', duplicated.map(o => ({ obligation: o })), gradeMap([]))
  assert.equal(v.grade, 'unproven')
  assert.equal(v.blockers[0], 'responsibility cycle detected')
  assert.deepEqual(v.blockers.slice(1), ['cycle: task-2 -> task-2'])

  // A duplicate that closes no cycle (same parent twice) is still no cycle:
  // duplicated registration is a minting error the fold tolerates, exactly
  // as before.
  const benign: readonly TaskObligation[] = [
    obligation(1),
    obligation(2, { parentTaskId: 'task-1' }),
    obligation(2, { parentTaskId: 'task-1' }),
  ]
  assert.deepEqual(detectCycles(benign), [])
})

test('composeTaskVerdict adjudicates the queried task OWN submission: self-forgery is named and capped', () => {
  // A delegated task composed over its own node: its submission is the one
  // fact in scope (the engine's submitDelegation → composeTaskVerdict path).
  // Honest leaf: the own submission's claim is the own-grade input.
  const honest = composeTaskVerdict(
    'task-4',
    [node(4, { submission: submission({ claimedGrade: 'stale' }) })],
    gradeMap([]),
  )
  assert.equal(honest.grade, 'stale')
  assert.deepEqual(honest.blockers, ['own workspace evidence is stale'])

  // Forged leaf: the task names ITSELF in forgedChildren, the pinned blocker
  // fires for its own id, and the grade caps at regressed.
  const forged = composeTaskVerdict(
    'task-4',
    [node(4, {
      submission: submission({
        claimedGrade: 'proven',
        artifactVerified: false,
        problems: ['digest mismatch at evidence.jsonl'],
      }),
    })],
    gradeMap([]),
  )
  assert.equal(forged.grade, 'regressed')
  assert.deepEqual(forged.forgedChildren, ['task-4'])
  assert.deepEqual(forged.blockers, [
    'task-4 claimed proven but its artifact does not verify',
    'task-4: digest mismatch at evidence.jsonl',
  ])

  // The cap outranks a measured ownGrade: even an engine-measured 'proven'
  // cannot co-sign a bundle that fails verification.
  const measured = composeTaskVerdict(
    'task-4',
    [node(4, { submission: submission({ claimedGrade: 'proven', artifactVerified: false }) })],
    gradeMap([['task-4', 'proven']]),
  )
  assert.equal(measured.grade, 'regressed')
  assert.deepEqual(measured.forgedChildren, ['task-4'])
})

test('composeTaskVerdict refuses to fold circular responsibility: unproven, named blocker', () => {
  const cyclic: readonly DagNode[] = cycleObligations().map((o, i) => ({
    obligation: o,
    submission: submission({ childWorkspace: `ws-${i}` }),
  }))
  // Everyone claims proven and everything verifies — the cycle still proves
  // nothing, and the composer says so before attempting any fold.
  const v = composeTaskVerdict('a', cyclic, gradeMap([['a', 'proven']]))
  assert.equal(v.grade, 'unproven')
  assert.equal(v.own, false)
  assert.deepEqual(v.forgedChildren, [])
  assert.deepEqual(v.regressedChildren, [])
  assert.deepEqual(v.unprovenChildren, [])
  assert.deepEqual(v.waived, [])
  assert.equal(v.blockers[0], 'responsibility cycle detected')
  assert.deepEqual(v.blockers.slice(1), ['cycle: a -> b -> c -> a'])
})

test('composeTaskVerdict on an unminted task id reports it instead of throwing', () => {
  const v = composeTaskVerdict('task-99', [node(1)], gradeMap([]))
  assert.deepEqual(
    { grade: v.grade, own: v.own, blockers: v.blockers },
    { grade: 'unproven', own: false, blockers: ['no obligation on record for task-99'] },
  )
})

// ---------------------------------------------------------------------------
// 7. Waiver visibility — excused AND shown, never a loophole
// ---------------------------------------------------------------------------

test('waiver visibility: the excused child disappears from the blockers, the forged sibling does not', () => {
  // task-4 never submitted and was waived; task-5 claimed proven on a bundle
  // that does not verify and was ALSO waived. The verdict must show: the
  // waiver list carries both (a human taking responsibility is a fact), the
  // unsubmitted child is excused (no missing-work blocker), and the forged
  // child is neither excused nor hidden.
  const v = composeVerdict(
    [
      { ...childNode('unsubmitted', 4), waiver: waiver({ by: 'eng-lead', reason: 'descoped for v1' }) },
      { ...childNode('forged', 5), waiver: waiver({ by: 'eng-lead', reason: 'descoped for v1' }) },
    ],
    'proven',
  )
  assert.equal(v.grade, 'regressed')
  assert.deepEqual(v.waived, ['task-4', 'task-5'])
  assert.deepEqual(v.unprovenChildren, [], 'the waived unsubmitted child is not missing work the parent must chase')
  assert.deepEqual(v.forgedChildren, ['task-5'], 'the forged child stays exactly where it was')
  assert.deepEqual(v.blockers, [
    'task-5 claimed proven but its artifact does not verify',
    'task-4 waived by eng-lead: descoped for v1',
    'task-5 waived by eng-lead: descoped for v1',
    'task-5: manifest digests do not match file contents',
  ])

  // Remove the forged sibling and the waiver actually resolves the verdict.
  const clean = composeVerdict(
    [{ ...childNode('unsubmitted', 4), waiver: waiver({ by: 'eng-lead', reason: 'descoped for v1' }) }],
    'proven',
  )
  assert.equal(clean.grade, 'proven')
  assert.deepEqual(clean.unprovenChildren, [])
  // The waiver line is still on the record: excused is not erased.
  assert.deepEqual(clean.blockers, ['task-4 waived by eng-lead: descoped for v1'])
})

// ---------------------------------------------------------------------------
// Topology grouping
// ---------------------------------------------------------------------------

test('childrenByParent groups by parent, keeps roots under undefined, preserves input order', () => {
  const o1 = obligation(1)
  const o2 = obligation(2, { parentTaskId: 'task-1' })
  const o3 = obligation(3, { parentTaskId: 'task-1' })
  const o4 = obligation(4, { parentTaskId: 'task-2' })
  const map = childrenByParent([o1, o2, o3, o4])
  assert.deepEqual(map.get(undefined), [o1])
  assert.deepEqual(map.get('task-1'), [o2, o3])
  assert.deepEqual(map.get('task-2'), [o4])
  assert.equal(map.get('task-3'), undefined, 'no key for childless tasks')
  assert.equal(map.size, 3)
})

// ---------------------------------------------------------------------------
// 8. Re-submission memory (W7-8) and id re-derivation (W7-7)
// ---------------------------------------------------------------------------

test('W7-8: a re-submission cannot launder a booked forgery — mergeSubmission keeps the flag sticky', () => {
  const forged = submission({
    claimedGrade: 'proven',
    artifactVerified: false,
    problems: ['digest mismatch'],
  })
  const clean = submission({ bundleRoot: sha256('clean-bundle') })

  // Verdict fields are last-wins; the forgery flag rides on top of them.
  const merged = mergeSubmission(forged, clean)
  assert.equal(merged.priorForgery, true)
  assert.equal(merged.claimedGrade, clean.claimedGrade)
  assert.equal(merged.artifactVerified, clean.artifactVerified)
  assert.equal(merged.bundleRoot, clean.bundleRoot)

  // The composer reads the merged submission as forged: waiver-immune
  // regressed, the task named in forgedChildren.
  const v = composeTaskVerdict('task-5', [node(5, { submission: merged })], gradeMap([]))
  assert.equal(v.grade, 'regressed')
  assert.deepEqual(v.forgedChildren, ['task-5'])
  const asChild = composeVerdict([node(5, { submission: merged })], 'proven')
  assert.equal(asChild.grade, 'regressed')
  assert.deepEqual(asChild.forgedChildren, ['task-5'])
  const waived = composeVerdict(
    [node(5, { submission: merged, waiver: waiver({ by: 'cto', reason: 'clean now, honest' }) })],
    'proven',
  )
  assert.equal(waived.grade, 'regressed', 'a waiver cannot buy out a booked forgery')

  // The clean-first order stays clean: no flag where no forgery was booked.
  assert.equal(mergeSubmission(undefined, clean).priorForgery, undefined)
  assert.equal(mergeSubmission(clean, clean).priorForgery, undefined)
  assert.equal(mergeSubmission(undefined, forged).priorForgery, undefined, 'a LIVE forgery needs no flag — it is its own fact')
  // Sticky across many re-submissions: forged → clean → clean still forged.
  assert.equal(mergeSubmission(merged, clean).priorForgery, true)
})

test('W7-7: obligationRewriteProblem names a re-derived id that disagrees with the recorded one', () => {
  const o = obligation(2, { parentTaskId: 'task-1' })
  // No recorded id, or one that still matches → nothing to book.
  assert.equal(obligationRewriteProblem(undefined, o), undefined)
  assert.equal(obligationRewriteProblem(obligationIdOf(o), o), undefined)
  // A recorded id addressing DIFFERENT bytes is a detectable rewrite.
  const imposter = obligationIdOf({ ...o, claim: `${o.claim}!` })
  const line = obligationRewriteProblem(imposter, o)
  assert.match(line ?? '', /^recorded obligation id [0-9a-f]{16} does not match the re-derived [0-9a-f]{16} — the obligation was rewritten$/)
})

// ---------------------------------------------------------------------------
// v0.25 (K1b) — the delegation DAG behind the vouched floor. This file's
// domain, one engine fixture deep: out-of-band delegation markers that are
// CORRECTLY CHAINED (prev and headRef both the digest of the physical
// predecessor, so the suspect position test passes them) but ride ABOVE the
// last checkpoint the host key verified. Pattern 5, the shape-legal append:
// the DAG must not consume them, the taskId must not exist, and the withheld
// count must be visible on the verdict.
// ---------------------------------------------------------------------------

import { ProofEngine } from '../src/engine.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs } from './helpers.ts'
import { lineDigest } from '../src/core/trust.ts'
import type { SignerPort } from '../src/core/ports.ts'

/** The signed-engine shape the floor needs: a host key that actually vouches. */
class K1Key implements SignerPort {
  readonly keyId: string
  constructor(keyId: string) { this.keyId = keyId }
  async sign(data: string): Promise<string> { return `sig:${this.keyId}:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> {
    return signature === `sig:${this.keyId}:${sha256(data)}`
  }
}

const K1_ROOT = '/ws-k1'

test('v0.25 (K1b): out-of-band delegation markers above the vouched floor never enter the DAG', async () => {
  const fs = MemoryFs.of({
    [`${K1_ROOT}/package.json`]: JSON.stringify({ name: 'demo', scripts: { test: 'vitest run' } }),
    [`${K1_ROOT}/src/a.ts`]: 'export const a = 1\n',
  })
  const engine = new ProofEngine({
    root: K1_ROOT,
    fs,
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(K1_ROOT),
    clock: new FakeClock(),
    workspaceKey: 'ws',
    signer: () => Promise.resolve(new K1Key('ws-key')),
  })
  await engine.establishBaseline()
  const { taskId } = await engine.delegateTask({ claim: 'port the parser to WASM' })
  assert.equal(taskId, 'task-1', 'fixture: one honest, checkpointed obligation exists below the floor')

  // The out-of-band tail: a created-twin for task-2 and a verdict-twin over
  // task-1, both correctly chained (headRef = prev = the digest of the line
  // they follow — every structural check green).
  const logPath = `${K1_ROOT}/.proof/evidence.jsonl`
  const appendChained = async (payload: Record<string, unknown>): Promise<void> => {
    const lines = ((await fs.readFile(logPath)) ?? '').split('\n').filter(l => l.trim().length > 0)
    const prev = lineDigest(lines[lines.length - 1] as string)
    await fs.appendLine(logPath, JSON.stringify({
      v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
      payload: { ...payload, headRef: prev },
    }))
  }
  await appendChained({
    label: 'delegation/created', v: 1, taskId: 'task-2',
    claim: 'forged obligation above the floor', issuedAt: '2026-10-06T00:00:00.000Z',
    issuedByWorkspace: 'attacker',
  })
  await appendChained({
    label: 'delegation/verdict', taskId: 'task-1',
    submission: {
      childWorkspace: 'impostor-ws', bundleRoot: 'not-a-real-bundle', claimedGrade: 'proven',
      artifactVerified: true, submittedAt: '2026-10-06T00:00:00.000Z',
    },
  })

  // The DAG: one node, no submission, no task-2 — the twins priced nothing.
  const verdict = await engine.taskVerdict({ taskId })
  assert.equal(verdict.nodes.length, 1, 'the forged task-2 never entered the DAG')
  const node = verdict.nodes.find(n => n.obligation.taskId === taskId)
  assert.ok(node !== undefined, 'fixture: the honest obligation is there')
  assert.equal(node?.submission, undefined, 'the above-floor verdict-twin mutated no node')
  assert.equal(node?.waiver, undefined)
  assert.equal(verdict.composed.grade, 'unproven',
    'a leaf with no admissible submission composes unproven, whatever the append claimed')
  assert.equal(verdict.aboveFloorMarkers, 2, 'both withheld markers are counted, visible on the result')

  // The taskId itself: the twin mints no obligation a verdict can name.
  await assert.rejects(
    () => engine.taskVerdict({ taskId: 'task-2' }),
    /task-2 does not exist on this chain/,
    'an appended created-marker above the floor opens no task',
  )

  // Allocation is deliberately UNbounded (V3-M3/X-H-06 discipline): the
  // twin's number is burned — the next honest delegation is task-3, never a
  // re-minted task-2 alias.
  const next = await engine.delegateTask({ claim: 'the honest successor' })
  assert.equal(next.taskId, 'task-3', 'the burned number is never re-minted, floor or no floor')
})
