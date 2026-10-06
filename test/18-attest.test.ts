/**
 * ATTEST (ι) — Classes B and C re-enter the proof system as first-class,
 * replayable evidence. These tests pin five layers:
 *
 * 1. the rubric: it exists, it orders structured output, and its version
 *    constant is wired (a prompt without a versioned rubric is not evidence);
 * 2. prompt assembly and identity: `juryPrompt` is byte-stable and sectioned,
 *    `claimIdOf` is a stable 16-hex identity of the claim text;
 * 3. the trust arithmetic of `attestationFactor`: p^w semantics, the
 *    abstain/zero-weight neutralities, and the [p,1] property that makes
 *    testimony a discount, never an amplifier;
 * 4. the reliability mixture of `fuseConfidence`: (1−w)·current + w·p for a
 *    decisive jury verdict, the neutralities (abstain, unusable probability,
 *    unusable current), and the Class C seam — endorse is risk acceptance
 *    (the number stands), reject multiplies through `attestationFactor`,
 *    never the mixture;
 * 5. the chain-reading discipline of `activeAttestations` (defensive parse —
 *    including the jury probability's closed [0,1] domain — appeal resolution
 *    by gen, deterministic (claimId, kind) order) and the llm-jury obligation
 *    matrix of `evaluateContract`.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  DEFAULT_TRUST_WEIGHTS, JURY_RUBRIC, RUBRIC_V1, activeAttestations,
  attestationFactor, attestationsFor, claimIdOf, fuseConfidence, juryPrompt,
  type Attestation, type HumanAttestation, type JuryAttestation, type TrustWeights,
} from '../src/core/attest.ts'
import { evaluateContract, type ContractInput } from '../src/core/contract.ts'

const CLAIM = 'the retry loop no longer swallows lock timeouts'
const CONTEXT = 'diff: src/retry.ts lines 40-58; test log: 312 passed, 0 failed'
const AT = 1_700_000_000_000

function jury(over: Partial<JuryAttestation> = {}): JuryAttestation {
  return {
    kind: 'attest/jury',
    claimId: claimIdOf(CLAIM),
    gen: 0,
    prompt: juryPrompt(CLAIM, CONTEXT),
    rubricVersion: RUBRIC_V1,
    model: 'test-juror/v1',
    independence: 'fresh-context',
    verdict: 'uphold',
    probability: 0.9,
    output: '{"verdict":"uphold","probability":0.9,"reasoning":"the diff and the log agree"}',
    at: AT,
    ...over,
  }
}

function human(over: Partial<HumanAttestation> = {}): HumanAttestation {
  return {
    kind: 'attest/human',
    claimId: claimIdOf(CLAIM),
    gen: 0,
    approver: 'r.reviewer@example.org',
    approvedAt: AT + 1,
    scope: { claim: CLAIM, evidenceRoot: null },
    decision: 'endorse',
    ...over,
  }
}

function weights(over: Partial<TrustWeights> = {}): TrustWeights {
  return { ...DEFAULT_TRUST_WEIGHTS, ...over }
}

function cInput(over: Partial<ContractInput> = {}): ContractInput {
  return {
    contract: { kind: 'llm-jury', claim: CLAIM },
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

function byId(obligations: readonly { id: string; met: boolean; detail: string }[], id: string) {
  const found = obligations.find(o => o.id === id)
  assert.ok(found, `obligation ${id} present in ${obligations.map(o => o.id).join(', ')}`)
  return found
}

// ---------------------------------------------------------------------------
// the rubric
// ---------------------------------------------------------------------------

test('JURY_RUBRIC exists, orders structured JSON output, and names every verdict', () => {
  assert.ok(JURY_RUBRIC.trim().length > 0)
  // The structured-output instruction: one JSON object, three named fields.
  assert.match(JURY_RUBRIC, /JSON/)
  assert.match(JURY_RUBRIC, /"verdict"/)
  assert.match(JURY_RUBRIC, /"probability"/)
  assert.match(JURY_RUBRIC, /"reasoning"/)
  for (const verdict of ['uphold', 'reject', 'abstain']) assert.ok(JURY_RUBRIC.includes(verdict))
  // The honesty rules the factor semantics rest on: materials-only judgement,
  // subjective probability, abstain on insufficient evidence, and the
  // permanence warning that makes replay-auditability a stated condition.
  assert.match(JURY_RUBRIC, /subjective probability/i)
  assert.match(JURY_RUBRIC, /abstain/i)
  assert.match(JURY_RUBRIC, /only from the given materials|only.*given materials/i)
  assert.match(JURY_RUBRIC, /Class B evidence/)
  assert.match(JURY_RUBRIC, /re-run|replay/i)
})

test('RUBRIC_V1 is the pinned version tag', () => {
  assert.equal(RUBRIC_V1, 'jury-rubric/v1')
})

// ---------------------------------------------------------------------------
// juryPrompt
// ---------------------------------------------------------------------------

test('juryPrompt is byte-identical across calls and injects claim and context verbatim', () => {
  const a = juryPrompt(CLAIM, CONTEXT)
  const b = juryPrompt(CLAIM, CONTEXT)
  assert.equal(a, b)
  assert.ok(a.includes(CLAIM))
  assert.ok(a.includes(CONTEXT))
})

test('juryPrompt has the fixed section structure, in order, rubric version included', () => {
  const p = juryPrompt(CLAIM, CONTEXT)
  const header = p.indexOf('=== CLASS B JURY DELIBERATION ===')
  const rubric = p.indexOf(`--- RUBRIC ${RUBRIC_V1} ---`)
  const claim = p.indexOf('=== CLAIM ===')
  const context = p.indexOf('=== CONTEXT ===')
  const output = p.indexOf('=== OUTPUT ===')
  for (const [name, at] of [['header', header], ['rubric', rubric], ['claim', claim], ['context', context], ['output', output]] as const) {
    assert.ok(at >= 0, `section ${name} present`)
  }
  assert.ok(header < rubric && rubric < claim && claim < context && context < output, 'sections in order')
  // The rubric text itself rides along, so the prompt is self-contained
  // evidence — the replay needs nothing outside the record.
  assert.ok(p.includes(JURY_RUBRIC))
  // The output instruction demands exactly one JSON object.
  assert.match(p.slice(output), /exactly one JSON object/)
})

test('juryPrompt honours explicit rubric and version overrides', () => {
  const p = juryPrompt(CLAIM, CONTEXT, 'BE BRIEF.', 'jury-rubric/v9')
  assert.ok(p.includes('BE BRIEF.'))
  assert.ok(p.includes('--- RUBRIC jury-rubric/v9 ---'))
  assert.ok(!p.includes(JURY_RUBRIC), 'the override replaces, not appends')
})

// ---------------------------------------------------------------------------
// claimIdOf
// ---------------------------------------------------------------------------

test('claimIdOf is a stable 16-hex identity: same text same id, rewording is a new claim', () => {
  const a = claimIdOf(CLAIM)
  const b = claimIdOf(CLAIM)
  assert.equal(a, b)
  assert.match(a, /^[0-9a-f]{16}$/)
  assert.notEqual(a, claimIdOf(`${CLAIM} `), 'whitespace changes the claim text, so the id')
  assert.notEqual(a, claimIdOf('a different claim'))
})

// ---------------------------------------------------------------------------
// attestationFactor — Class B
// ---------------------------------------------------------------------------

test('Class B uphold: factor is probability^classB (0.9 at default weight 0.7)', () => {
  const f = attestationFactor(jury({ verdict: 'uphold', probability: 0.9 }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(f - 0.9 ** 0.7) < 1e-9, `expected 0.9^0.7, got ${f}`)
  assert.ok(f > 0.9 && f < 1, 'partial trust lands strictly between full weight and no effect')
})

test('Class B abstain is exactly neutral: factor 1, no penalty', () => {
  assert.equal(attestationFactor(jury({ verdict: 'abstain', probability: 0.5 }), DEFAULT_TRUST_WEIGHTS), 1)
})

test('Class B reject rides its own low probability — no direction special-case', () => {
  const f = attestationFactor(jury({ verdict: 'reject', probability: 0.1 }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(f - 0.1 ** 0.7) < 1e-9, `expected 0.1^0.7, got ${f}`)
  assert.ok(f < 0.2, 'a rejection at 0.1 is a heavy discount')
})

test('zero trust is zero evidence: w=0 gives factor 1 — even at p=0', () => {
  assert.equal(attestationFactor(jury({ probability: 0.01 }), weights({ classB: 0 })), 1)
  assert.equal(attestationFactor(jury({ probability: 0 }), weights({ classB: 0 })), 1, '0^0 = 1: no trust, no evidence')
})

test('full trust is the raw testimony: w=1 gives exactly p', () => {
  assert.equal(attestationFactor(jury({ probability: 0.42 }), weights({ classB: 1 })), 0.42)
})

test('the [p,1] property: for w in 0..1 and p in [0,1], factor never leaves [p,1]', () => {
  // A property scan, not a few points: the invariant "a witness can only
  // weaken, never amplify" is the safety property of the whole trust model,
  // so it is checked over a grid instead of trusted from the formula.
  for (let i = 1; i <= 19; i++) {
    const p = i * 0.05
    for (let j = 0; j <= 10; j++) {
      const w = j / 10
      const f = attestationFactor(jury({ probability: p }), weights({ classB: w }))
      assert.ok(f >= p - 1e-12, `factor ${f} < p ${p} at w=${w}`)
      assert.ok(f <= 1 + 1e-12, `factor ${f} > 1 at w=${w}`)
    }
  }
})

test('a jury probability unreadable as a probability degrades to abstain, never NaN', () => {
  assert.equal(attestationFactor(jury({ probability: Number.NaN }), DEFAULT_TRUST_WEIGHTS), 1)
  // > 1 would AMPLIFY the claim — the one thing the exponent semantics
  // exist to forbid — so it must fall back to neutral too.
  assert.equal(attestationFactor(jury({ probability: 1.5 }), DEFAULT_TRUST_WEIGHTS), 1)
  assert.equal(attestationFactor(jury({ probability: -0.2 }), DEFAULT_TRUST_WEIGHTS), 1)
})

// ---------------------------------------------------------------------------
// attestationFactor — Class C
// ---------------------------------------------------------------------------

test('Class C endorse at default trust: humanProbability^classC = 0.95^0.9', () => {
  const f = attestationFactor(human({ decision: 'endorse' }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(f - 0.95 ** 0.9) < 1e-9, `expected 0.95^0.9, got ${f}`)
})

test('Class C reject is a heavy discount: (1-0.95)^0.9', () => {
  const f = attestationFactor(human({ decision: 'reject' }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(f - 0.05 ** 0.9) < 1e-9, `expected 0.05^0.9, got ${f}`)
  assert.ok(f < 0.1, 'a trusted human rejecting must hurt more than a jury abstaining')
})

// ---------------------------------------------------------------------------
// fuseConfidence — the reliability mixture (and the Class C seam)
// ---------------------------------------------------------------------------

test('fuseConfidence: a decisive jury verdict pulls the number toward its probability — (1-w)*current + w*p in closed form', () => {
  // current 0.94, jury asserting 0.99 at the default classB weight 0.7:
  // fused = 0.3*0.94 + 0.7*0.99 = 0.975 — the mixture form, exactly.
  const fused = fuseConfidence(0.94, jury({ verdict: 'uphold', probability: 0.99 }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(fused - ((1 - 0.7) * 0.94 + 0.7 * 0.99)) < 1e-12, `expected 0.3*0.94+0.7*0.99, got ${fused}`)
  assert.ok(Math.abs(fused - 0.975) < 1e-12, 'and that value is 0.975')

  // Both mixture endpoints are p and current: the fused value can never
  // overshoot the witness's own assertion, in either direction.
  assert.ok(fused > 0.94 && fused < 0.99, 'strictly between the machine number and the assertion')
  // Direction lives in p: the same weights at p=0.1 crash the number.
  const crashed = fuseConfidence(0.94, jury({ verdict: 'reject', probability: 0.1 }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(crashed - (0.3 * 0.94 + 0.7 * 0.1)) < 1e-12, `expected 0.3*0.94+0.7*0.1 = 0.352, got ${crashed}`)
  assert.ok(crashed < 0.36, 'a rejecting jury pulls the number most of the way down to its assertion')

  // Pull strength is exactly w: at w=0 the number stands, at w=1 it is replaced.
  assert.equal(fuseConfidence(0.94, jury({ probability: 0.99 }), weights({ classB: 0 })), 0.94)
  assert.equal(fuseConfidence(0.94, jury({ probability: 0.99 }), weights({ classB: 1 })), 0.99)
})

test('fuseConfidence: an abstaining jury leaves the machine number untouched', () => {
  // "I cannot tell" carries no asserted probability to pull toward.
  assert.equal(fuseConfidence(0.94, jury({ verdict: 'abstain', probability: 0.5 }), DEFAULT_TRUST_WEIGHTS), 0.94)
  assert.equal(fuseConfidence(0.12, jury({ verdict: 'abstain', probability: 0.9 }), weights({ classB: 1 })), 0.12)
})

test('fuseConfidence: a jury probability unreadable as a probability leaves the number untouched', () => {
  // Broken delivery is not evidence: the mixture would amplify (>1) or
  // NaN-poison — the guard returns current instead.
  for (const bad of [Number.NaN, 1.5, -0.2, Number.POSITIVE_INFINITY]) {
    assert.equal(fuseConfidence(0.94, jury({ verdict: 'uphold', probability: bad }), DEFAULT_TRUST_WEIGHTS), 0.94)
  }
})

test('fuseConfidence: an unusable current is returned verbatim, whatever the witness says', () => {
  // The first guard fires before any witness arithmetic: a NaN current
  // must not be "rescued" into a number by an upholding jury, and an
  // out-of-range current is passed through as the caller's problem.
  assert.ok(Number.isNaN(fuseConfidence(Number.NaN, jury({ verdict: 'uphold', probability: 0.99 }), DEFAULT_TRUST_WEIGHTS)))
  assert.equal(fuseConfidence(5, jury({ verdict: 'uphold', probability: 0.99 }), DEFAULT_TRUST_WEIGHTS), 5)
  assert.equal(fuseConfidence(-0.2, jury({ verdict: 'reject', probability: 0.1 }), DEFAULT_TRUST_WEIGHTS), -0.2)
  assert.ok(Number.isNaN(fuseConfidence(Number.NaN, human({ decision: 'reject' }), DEFAULT_TRUST_WEIGHTS)))
})

test('fuseConfidence: a human endorsement is risk acceptance — the number stands, at every classC weight', () => {
  // The approval seam carries no probability, so there is nothing to
  // mixture: the human accepted the residual risk and the machine
  // certification stays exactly what machines measured. The unlock happens
  // at the grade level, not in this number.
  for (const w of [0, 0.5, 0.9, 1]) {
    assert.equal(fuseConfidence(0.94, human({ decision: 'endorse' }), weights({ classC: w })), 0.94)
  }
  // The semantic boundary, pinned from both sides: the SAME endorsement is a
  // discount in the claim product (attestationFactor: hp^w < 1) and a no-op
  // in the confidence mixture — by design, not by oversight.
  assert.ok(attestationFactor(human({ decision: 'endorse' }), DEFAULT_TRUST_WEIGHTS) < 1)
  assert.equal(fuseConfidence(0.94, human({ decision: 'endorse' }), DEFAULT_TRUST_WEIGHTS), 0.94)
})

test('fuseConfidence: a human rejection multiplies through attestationFactor — the collapse is multiplicative, never a mixture', () => {
  // Class C has no asserted p to pull toward, so reject does NOT take the
  // (1-w)*current + w*p form: it books the heavy discount of a trusted
  // human contradicting the claim, multiplicatively.
  const fused = fuseConfidence(0.9, human({ decision: 'reject' }), DEFAULT_TRUST_WEIGHTS)
  assert.ok(Math.abs(fused - 0.9 * 0.05 ** 0.9) < 1e-12, `expected 0.9 * (1-0.95)^0.9, got ${fused}`)
  assert.ok(fused < 0.11, 'a rejection collapses the number hard')

  // The composition is pinned across the weight grid: fuseConfidence(reject)
  // is exactly current * attestationFactor(reject), the same factor the
  // claim product would apply.
  for (const classC of [0, 0.3, 0.6, 0.9, 1]) {
    const w = weights({ classC })
    const factor = attestationFactor(human({ decision: 'reject' }), w)
    assert.equal(fuseConfidence(0.77, human({ decision: 'reject' }), w), 0.77 * factor, `classC=${classC}`)
  }
})

// ---------------------------------------------------------------------------
// activeAttestations / attestationsFor
// ---------------------------------------------------------------------------

test('activeAttestations skips garbage payloads without throwing', () => {
  const good = jury({ verdict: 'reject', probability: 0.2 })
  const payloads: unknown[] = [
    null, undefined, 42, 'attest/jury', [], {},
    { kind: 'not-an-attestation' },
    { kind: 'attest/jury', claimId: 'x' },                                  // truncated jury
    { ...jury(), probability: 'high' },                                      // probability not a number
    { ...jury(), gen: -1 },                                                  // negative gen
    { ...jury(), verdict: 'maybe' },                                         // unknown verdict
    { ...jury(), independence: 'telepathic' },                               // unknown independence
    { kind: 'attest/human', claimId: 'x', decision: 'endorse' },             // truncated human
    { ...human(), scope: { claim: CLAIM } },                                 // evidenceRoot missing
    { ...human(), decision: 'shrug' },                                       // unknown decision
    good,
  ]
  const active = activeAttestations(payloads)
  assert.equal(active.length, 1)
  const only = active[0] as JuryAttestation
  assert.equal(only.kind, 'attest/jury')
  assert.equal(only.verdict, 'reject')
})

test('parseJury: a probability outside [0,1] makes the whole record unusable — not an abstain, not evidence', () => {
  // The read path used to accept any finite number, so `uphold @ 5` entered
  // the active set and the two layers read it opposite ways: jury-upholds
  // thresholds the number (5 ≥ 0.5 → met) while attestationFactor treated it
  // as an abstain. Out-of-domain means broken delivery; the record is
  // skipped like any other malformed payload.
  const outOfRange: Attestation[] = [
    jury({ verdict: 'uphold', probability: 5 }),
    jury({ verdict: 'uphold', probability: -0.2 }),
    jury({ verdict: 'uphold', probability: Number.NaN }),
    jury({ verdict: 'uphold', probability: Number.POSITIVE_INFINITY }),
  ]
  assert.equal(activeAttestations(outOfRange).length, 0, 'no out-of-domain probability may enter the active set')

  // With the record unusable, the obligation layer reads the same absence —
  // the two verdicts can no longer disagree about one payload.
  const v = evaluateContract(cInput({ attestations: outOfRange }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, false, 'an uphold at probability 5 is not a delivered verdict')
  assert.equal(byId(v.obligations, 'jury-upholds').met, false)

  // The closed interval [0,1] is the legal domain and parses exactly as
  // before, boundaries included.
  const zero = jury({ claimId: claimIdOf('claim at zero'), verdict: 'reject', probability: 0 })
  const one = jury({ claimId: claimIdOf('claim at one'), verdict: 'uphold', probability: 1 })
  const active = activeAttestations([zero, one, ...outOfRange])
  assert.equal(active.length, 2, 'the legal records survive alongside the skipped ones')
  assert.equal((active[0] as JuryAttestation).probability, 0)
  assert.equal((active[1] as JuryAttestation).probability, 1)
})

test('an appeal at higher gen supersedes the original deliberation', () => {
  const gen0 = jury({ gen: 0, verdict: 'uphold', probability: 0.9 })
  const gen1 = jury({ gen: 1, verdict: 'reject', probability: 0.15 })
  const active = activeAttestations([gen0, gen1])
  assert.equal(active.length, 1)
  const winner = active[0] as JuryAttestation
  assert.equal(winner.gen, 1)
  assert.equal(winner.verdict, 'reject')
  // Chain order is irrelevant to the outcome: the appeal wins by gen, not position.
  assert.deepEqual(activeAttestations([gen1, gen0]), active)
})

test('equal gen resolves to the later chain line', () => {
  const first = jury({ gen: 0, verdict: 'uphold', probability: 0.9 })
  const second = jury({ gen: 0, verdict: 'abstain', probability: 0.5 })
  const active = activeAttestations([first, second])
  assert.equal(active.length, 1)
  assert.equal((active[0] as JuryAttestation).verdict, 'abstain')
})

test('Class B and Class C of the same claim stay independent — and sort human before jury', () => {
  const b = jury({ gen: 5 })
  const c = human({ gen: 0 })
  const active = activeAttestations([b, c])
  assert.equal(active.length, 2, 'one verdict per channel, both alive')
  // Sorted by (claimId, kind): identical claimIds, 'attest/human' < 'attest/jury'.
  assert.deepEqual(active.map(a => a.kind), ['attest/human', 'attest/jury'])
  // A high-gen jury appeal must not erase a human endorsement.
  const appealed = activeAttestations([b, c, jury({ gen: 6, verdict: 'reject', probability: 0.1 })])
  assert.equal(appealed.length, 2)
  assert.deepEqual(appealed.map(a => a.kind), ['attest/human', 'attest/jury'])
  assert.equal((appealed[1] as JuryAttestation).verdict, 'reject')
})

test('output is sorted by (claimId, kind), independent of chain arrival order', () => {
  const other = 'an unrelated claim entirely'
  const payloads: unknown[] = [
    jury({ claimId: claimIdOf(other), gen: 0 }),
    jury({ gen: 0 }),                                     // claimIdOf(CLAIM)
    human({ claimId: claimIdOf(other), gen: 0 }),
    human({ gen: 0 }),
  ]
  const forward = activeAttestations(payloads)
  const scrambled = activeAttestations([payloads[1], payloads[3], payloads[0], payloads[2]])
  assert.deepEqual(forward, scrambled)
  // Sortedness via the composite key: the identity resolution is keyed on.
  const keys = forward.map(a => `${a.claimId}\u0000${a.kind}`)
  assert.deepEqual([...keys].sort(), keys)
})

test('attestationsFor narrows to one claimId and keeps the deterministic order', () => {
  const other = 'an unrelated claim entirely'
  const payloads: unknown[] = [jury(), human(), human({ claimId: claimIdOf(other) })]
  const mine = attestationsFor(payloads, claimIdOf(CLAIM))
  assert.equal(mine.length, 2)
  assert.ok(mine.every(a => a.claimId === claimIdOf(CLAIM)))
  assert.deepEqual(attestationsFor(payloads, claimIdOf(other)).map(a => a.kind), ['attest/human'])
  assert.deepEqual(attestationsFor(payloads, '0000000000000000'), [])
})

// ---------------------------------------------------------------------------
// evaluateContract — llm-jury
// ---------------------------------------------------------------------------

test('llm-jury: an upholding verdict at >= 0.5 meets both obligations and skips machine checks', () => {
  const v = evaluateContract(cInput({ attestations: [jury({ verdict: 'uphold', probability: 0.9 })] }))
  assert.equal(v.kind, 'llm-jury')
  assert.equal(v.skipChecks, true)
  assert.equal(v.juryCappedConfidence, undefined, 'the cap is a docs-only instrument')
  assert.deepEqual(v.obligations.map(o => o.id), ['zero-regressions', 'jury-delivered', 'jury-upholds'])
  assert.ok(v.obligations.every(o => o.met), v.obligations.map(o => o.detail).join(' | '))
})

test('llm-jury: zero-regressions is vacuously met with no machine records, and says so', () => {
  const v = evaluateContract(cInput({ attestations: [jury()] }))
  const o = byId(v.obligations, 'zero-regressions')
  assert.equal(o.met, true)
  assert.match(o.detail, /jury/)
})

test('llm-jury: a rejection delivers but does not uphold — the detail carries verdict and probability', () => {
  const v = evaluateContract(cInput({ attestations: [jury({ verdict: 'reject', probability: 0.12 })] }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, true, 'a rejection is still a delivered verdict')
  const o = byId(v.obligations, 'jury-upholds')
  assert.equal(o.met, false)
  assert.match(o.detail, /reject/)
  assert.match(o.detail, /0\.12/)
})

test('llm-jury: an abstention is delivered evidence but never an upholding', () => {
  const v = evaluateContract(cInput({ attestations: [jury({ verdict: 'abstain', probability: 0.5 })] }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, true)
  const o = byId(v.obligations, 'jury-upholds')
  assert.equal(o.met, false)
  assert.match(o.detail, /abstain/)
  assert.match(o.detail, /0\.5/)
})

test('llm-jury: uphold below the 0.5 threshold is not an upholding — probability in the detail', () => {
  const v = evaluateContract(cInput({ attestations: [jury({ verdict: 'uphold', probability: 0.3 })] }))
  const o = byId(v.obligations, 'jury-upholds')
  assert.equal(o.met, false)
  assert.match(o.detail, /0\.3/)
})

test('llm-jury: no attestation fails jury-delivered with the tooling hint', () => {
  const v = evaluateContract(cInput())
  assert.equal(byId(v.obligations, 'jury-delivered').met, false)
  assert.match(byId(v.obligations, 'jury-delivered').detail, /proof_jury/)
  assert.match(byId(v.obligations, 'jury-delivered').detail, /proof_jury_submit/)
  assert.equal(byId(v.obligations, 'jury-upholds').met, false)
})

test('llm-jury: an explicit empty attestation list behaves like an absent one (backward-compatible field)', () => {
  assert.deepEqual(evaluateContract(cInput({ attestations: [] })).obligations, evaluateContract(cInput()).obligations)
})

test('llm-jury: testimony about a different claim does not transfer', () => {
  const foreign = jury({ claimId: claimIdOf('some other claim'), verdict: 'uphold', probability: 0.99 })
  const v = evaluateContract(cInput({ attestations: [foreign] }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, false)
})

test('llm-jury: a Class C endorsement cannot satisfy the Class B obligations', () => {
  const v = evaluateContract(cInput({ attestations: [human({ decision: 'endorse' })] }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, false, 'humans endorse; they do not deliberate for the jury')
})

test('llm-jury: a re-deliberated rejection supersedes an earlier upholding', () => {
  const v = evaluateContract(cInput({
    attestations: [jury({ gen: 0, verdict: 'uphold', probability: 0.9 }), jury({ gen: 1, verdict: 'reject', probability: 0.1 })],
  }))
  assert.equal(byId(v.obligations, 'jury-delivered').met, true)
  assert.equal(byId(v.obligations, 'jury-upholds').met, false)
})

// ---------------------------------------------------------------------------
// module determinism
// ---------------------------------------------------------------------------

test('determinism: identical inputs produce deep-equal outputs across every entry point', () => {
  const payloads: unknown[] = [jury(), human(), jury({ claimId: claimIdOf('other'), gen: 3 }), { junk: true }]
  assert.equal(juryPrompt(CLAIM, CONTEXT), juryPrompt(CLAIM, CONTEXT))
  assert.deepEqual(activeAttestations(payloads), activeAttestations([...payloads]))
  const att: Attestation = jury({ probability: 0.7 })
  assert.equal(attestationFactor(att, DEFAULT_TRUST_WEIGHTS), attestationFactor(att, DEFAULT_TRUST_WEIGHTS))
  assert.deepEqual(evaluateContract(cInput({ attestations: [jury()] })), evaluateContract(cInput({ attestations: [jury()] })))
})
