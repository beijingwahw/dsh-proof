/**
 * ECONOMICS — the unit cost of trust (v0.21).
 *
 * `core/economics.ts` turns the measurements the engine already takes —
 * milliseconds per record, human review items, prior→posterior moves — into
 * a priced statement, and turns a *proven* grade into an insurance-style
 * offer. These tests pin every number the module rests on:
 *
 * - the flagship ledger: every field hand-calculated against the same inputs
 *   (cost arithmetic, the confidence delta, the entropy-difference sum, both
 *   per-dollar divisions);
 * - the honesty guards: zero cost never yields Infinity, an unmeasured prior
 *   never pretends a purchase, factors absent yields exactly 0 nats;
 * - the signed information ledger: paying to learn the claim *broke* is a
 *   negative entropy delta and is reported as one;
 * - the SLA matrix: proven×{0.97, 0.5, endpoints 0/1} exact premiums,
 *   minPremium floors, deductible pass-through, regressed denial, the three
 *   manual-underwriting grades with pinned reasons, absent and out-of-range
 *   confidence;
 * - the five exclusions, pinned verbatim;
 * - the content-addressed quoteId: determinism, and sensitivity to one cent
 *   of coverage;
 * - the parameter defenses (negative/NaN rates, non-positive coverage).
 *
 * Expected floats are computed here with an independently transcribed entropy
 * oracle (the H(p) formula straight from the spec) — never by calling the
 * module under test with itself.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  SLA_EXCLUSIONS, priceSla, summarizeRunLedger,
  type RateCard,
} from '../src/core/economics.ts'
import type { CheckStatus, Evidence } from '../src/core/evidence.ts'

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Minimal evidence record — the ledger reads only status and durationMs. */
function evidence(checkId: string, status: CheckStatus, durationMs: number): Evidence {
  return {
    evidenceId: `${checkId}:${status}:${durationMs}`,
    checkId,
    label: checkId,
    kind: 'test',
    command: ['npm', 'run', '--silent', 'test'],
    status,
    exitCode: status === 'pass' ? 0 : 1,
    durationMs,
    outputDigest: '0'.repeat(64),
    outputHead: '',
    recordedAt: '2026-01-01T00:00:00.000Z',
    workspace: { head: null, dirty: [], dirtDigest: '' },
  }
}

/**
 * Binary entropy in nats, transcribed straight from the spec
 * (H(p) = −p·ln p − (1−p)·ln(1−p), 0 at the endpoints) — an independent
 * oracle for whatever the module does internally.
 */
function entropy(p: number): number {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log(p) - (1 - p) * Math.log(1 - p)
}

/** The rate card used throughout: $0.0001/ms compute, $15 per review item. */
const USD: RateCard = { currency: 'USD', computePerMs: 0.0001, humanReviewPerItem: 15 }

/**
 * Float equality at the suite's tolerance (|actual − expected| < 1e-12), the
 * same discipline as the bayes tests. `null`/`undefined` fail loudly — a
 * ratio that was promised as a number must arrive as one.
 */
function near(actual: number | null | undefined, expected: number, message = ''): void {
  const value = typeof actual === 'number' ? actual : Number.NaN
  assert.ok(
    Math.abs(value - expected) < 1e-12,
    `${message} expected ≈${expected}, got ${actual}`,
  )
}

// ---------------------------------------------------------------------------
// THE UNIT COST OF TRUST — the flagship ledger
// ---------------------------------------------------------------------------

test('THE UNIT COST OF TRUST — a run ledger states compute, assertions, confidence and information, each priced per dollar', () => {
  // Five records: three decisive answers (pass/pass/fail — a decisive fail is
  // still an answered assertion), two that ran without answering (timeout,
  // skipped). All five spent milliseconds; only three bought an assertion.
  const ledger = summarizeRunLedger({
    records: [
      evidence('unit/test', 'pass', 1200),
      evidence('unit/build', 'pass', 800),
      evidence('unit/lint', 'fail', 300),
      evidence('unit/e2e', 'timeout', 5000),
      evidence('unit/slow', 'skipped', 100),
    ],
    priorProbability: 0.4,
    posteriorProbability: 0.97,
    factors: [
      { prior: 0.4, posterior: 0.95 },
      { prior: 0.6, posterior: 0.98 },
    ],
    humanReviewItems: 2,
    rate: USD,
  })

  // Compute: 1200+800+300+5000+100 = 7400ms — the timeout's 5 seconds are
  // spent money too, and the ledger counts them.
  assert.equal(ledger.computeMs, 7400)
  assert.equal(ledger.humanReviewItems, 2)

  // Cost, hand-calculated: 7400ms × $0.0001/ms = $0.74, plus 2 review items
  // × $15 = $30, total $30.74 — exactly, at the 6-decimal money spec.
  assert.equal(ledger.cost, 30.74)

  // Assertions are decisive answers; a decisive fail counts (it verified the
  // assertion is false — that is knowledge, priced the same as a pass).
  assert.equal(ledger.assertions, 3)
  assert.equal(ledger.decisiveCount, 3)
  assert.equal(ledger.skippedCount, 2)

  // $30.74 / 3 assertions = $10.246666… → $10.246667 at the money spec.
  assert.equal(ledger.costPerAssertion, 10.246667)

  // Confidence purchased: 0.97 − 0.4 = 0.57, and per dollar 0.57/30.74.
  assert.equal(ledger.confidencePurchased, 0.57)
  near(ledger.confidencePerDollar, 0.57 / 30.74, "confidencePerDollar = 0.57/30.74")

  // Information purchased: Σ[H(prior) − H(posterior)] over the two factors,
  // computed against the independent entropy oracle.
  const expectedNats = (entropy(0.4) - entropy(0.95)) + (entropy(0.6) - entropy(0.98))
  assert.ok(expectedNats > 0) // the oracle itself is sanity-checked
  near(ledger.infoNats, expectedNats, "infoNats = Σ[H(prior)−H(posterior)]")
  near(ledger.natsPerDollar, expectedNats / 30.74, "natsPerDollar")
})

// ---------------------------------------------------------------------------
// Honesty guards — never Infinity, never an invented purchase
// ---------------------------------------------------------------------------

test('zero cost buys nothing per dollar — both per-dollar ratios are null, never Infinity', () => {
  const ledger = summarizeRunLedger({
    records: [evidence('unit/test', 'pass', 250)],
    priorProbability: 0.5,
    posteriorProbability: 0.9,
    factors: [{ prior: 0.5, posterior: 0.9 }],
    rate: { currency: 'USD', computePerMs: 0 }, // free compute is a legal card
  })
  assert.equal(ledger.cost, 0)
  assert.equal(ledger.costPerAssertion, 0)
  // The run DID purchase confidence and information — those are stated. What
  // it did not purchase is anything *per dollar*: division by zero is not an
  // answer a financial statement may carry.
  assert.equal(ledger.confidencePurchased, 0.4)
  assert.equal(ledger.confidencePerDollar, null)
  near(ledger.infoNats, entropy(0.5) - entropy(0.9), "infoNats")
  assert.equal(ledger.natsPerDollar, null)
})

test('an unmeasured prior purchases nothing — confidencePurchased null, factors absent yields exactly 0 nats', () => {
  const ledger = summarizeRunLedger({
    records: [evidence('unit/test', 'pass', 250)],
    // no priorProbability, no posteriorProbability, no factors
    rate: USD,
  })
  assert.equal(ledger.cost, 0.025) // 250ms × $0.0001 — cost exists…
  assert.equal(ledger.confidencePurchased, null) // …but no purchase is claimed
  assert.equal(ledger.confidencePerDollar, null)
  assert.equal(ledger.infoNats, 0) // no factors, no information claimed
  // Zero information per dollar was bought — that is a statement, not null:
  // the cost was real and the information was really zero.
  assert.equal(ledger.natsPerDollar, 0)
})

// ---------------------------------------------------------------------------
// Signed information — bad news is still information
// ---------------------------------------------------------------------------

test('infoNats is signed — paying to learn the claim broke still bought information (negative entropy delta)', () => {
  const ledger = summarizeRunLedger({
    records: [evidence('unit/test', 'fail', 400)],
    factors: [{ prior: 0.9, posterior: 0.2 }],
    rate: USD,
  })
  // The factor folded toward failure: entropy rose from H(0.9) to H(0.2),
  // so the "gain" is negative — reported as-is, not clamped, not abs().
  const expected = entropy(0.9) - entropy(0.2)
  assert.ok(expected < 0)
  near(ledger.infoNats, expected, "signed infoNats")
  assert.ok(ledger.infoNats < 0)
})

test('degenerate endpoints carry zero entropy — H(0) and H(1) are 0; a factor settled to certainty yields ln 2', () => {
  const settled = summarizeRunLedger({
    records: [],
    factors: [{ prior: 0, posterior: 1 }], // both endpoints: 0 − 0
    rate: USD,
  })
  assert.equal(settled.infoNats, 0)

  const fromEvenOdds = summarizeRunLedger({
    records: [],
    factors: [{ prior: 0.5, posterior: 1 }], // ln 2 − 0
    rate: USD,
  })
  near(fromEvenOdds.infoNats, Math.log(2), "0.5→1 buys ln 2")

  const alreadyCertain = summarizeRunLedger({
    records: [],
    factors: [{ prior: 1, posterior: 1 }],
    rate: USD,
  })
  assert.equal(alreadyCertain.infoNats, 0)
})

// ---------------------------------------------------------------------------
// Sunk-cost visibility
// ---------------------------------------------------------------------------

test('skippedCount keeps the sunk cost visible — non-decisive time is spent money that bought no assertion', () => {
  const ledger = summarizeRunLedger({
    records: [
      evidence('unit/timeout', 'timeout', 1000),
      evidence('unit/error', 'error', 1000),
      evidence('unit/aborted', 'aborted', 1000),
      evidence('unit/skipped', 'skipped', 1000),
    ],
    rate: { currency: 'USD', computePerMs: 0.001 },
  })
  assert.equal(ledger.computeMs, 4000) // every millisecond was spent…
  assert.equal(ledger.assertions, 0) // …and none of them bought an answer
  assert.equal(ledger.decisiveCount, 0)
  assert.equal(ledger.skippedCount, 4)
  // With zero assertions the divisor floors at 1: the whole cost is stated
  // as the price of the first assertion nobody got.
  assert.equal(ledger.cost, 4)
  assert.equal(ledger.costPerAssertion, 4)
})

test('money carries at most six decimals — float dust never reaches a statement', () => {
  const ledger = summarizeRunLedger({
    records: [evidence('unit/test', 'pass', 1000)],
    rate: { currency: 'USD', computePerMs: 1 / 3 }, // 1000/3 = 333.3333333…
    humanReviewItems: 0,
  })
  assert.equal(ledger.cost, 333.333333) // not 333.3333333333333
})

// ---------------------------------------------------------------------------
// SLA matrix — grade × confidence
// ---------------------------------------------------------------------------

test('proven prices an offer — premium = coverage × (1 − confidence), exactly', () => {
  const quote = priceSla({
    grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate: USD,
  })
  assert.equal(quote.decision.class, 'offer')
  const offer = quote.decision as { class: 'offer'; premium: number; pUndetected: number; deductible: number; coverageAmount: number }
  near(offer.pUndetected, 0.03, "pUndetected = 1−0.97")
  // 10,000 × 0.03 = 300 — the raw product is 300.0000000000003 in doubles;
  // the money spec rounds it to the $300 the arithmetic says it is.
  assert.equal(offer.premium, 300)
  assert.equal(offer.deductible, 0) // absent deductible passes through as 0
  assert.equal(offer.coverageAmount, 10_000)
  // The quote surface carries its identity fields.
  assert.equal(quote.vehicle, 'dsh-proof/SLA-1')
  assert.equal(quote.termsVersion, 'SLA-1')
  assert.equal(quote.currency, 'USD')
  assert.equal(quote.grade, 'proven')
  assert.equal(quote.confidenceAtIssue, 0.97)

  const half = priceSla({ grade: 'proven', confidence: 0.5, coverageAmount: 10_000, rate: USD })
  assert.equal((half.decision as { premium: number }).premium, 5000)
})

test('confidence endpoints are degenerate but legal — P=0 prices full coverage, P=1 prices the floor', () => {
  const certainFail = priceSla({ grade: 'proven', confidence: 0, coverageAmount: 10_000, rate: USD })
  const of0 = certainFail.decision as { class: 'offer'; premium: number; pUndetected: number }
  assert.equal(of0.class, 'offer')
  assert.equal(of0.pUndetected, 1)
  assert.equal(of0.premium, 10_000) // everything undetected: premium = coverage

  const certainPass = priceSla({ grade: 'proven', confidence: 1, coverageAmount: 10_000, rate: USD })
  const of1 = certainPass.decision as { class: 'offer'; premium: number; pUndetected: number }
  assert.equal(of1.class, 'offer')
  assert.equal(of1.pUndetected, 0)
  assert.equal(of1.premium, 0) // nothing undetected: no minPremium given, floor 0
})

test('minPremium lifts the floor — a computed premium below the bookkeeping minimum is raised to it', () => {
  // P=1 computes premium 0; the card's minimum prevails.
  const floor = priceSla({
    grade: 'proven', confidence: 1, coverageAmount: 10_000,
    rate: USD, minPremium: 500,
  })
  assert.equal((floor.decision as { premium: number }).premium, 500)

  // A tiny real premium (1000 × 0.01 = $10) is lifted to a $25 minimum.
  const lifted = priceSla({
    grade: 'proven', confidence: 0.99, coverageAmount: 1000,
    rate: USD, minPremium: 25,
  })
  assert.equal((lifted.decision as { premium: number }).premium, 25)
})

test('deductible passes through — the claim-time excess never enters the premium', () => {
  const bare = priceSla({ grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate: USD })
  const withDeductible = priceSla({
    grade: 'proven', confidence: 0.97, coverageAmount: 10_000, rate: USD, deductible: 500,
  })
  const bareOffer = bare.decision as { premium: number; deductible: number }
  const dedOffer = withDeductible.decision as { premium: number; deductible: number }
  assert.equal(dedOffer.deductible, 500)
  assert.equal(dedOffer.premium, 300) // identical premium: +deductible never sneaks in
  assert.equal(bareOffer.premium, dedOffer.premium)
  assert.equal(bareOffer.deductible, 0)
})

test('regressed is denied in one honest sentence', () => {
  const quote = priceSla({ grade: 'regressed', confidence: 0.9, coverageAmount: 10_000, rate: USD })
  assert.deepEqual(quote.decision, {
    class: 'denied',
    reason: 'the delivery failed verification — the claim already broke',
  })
  // The confidence that was measured is still attested on the quote.
  assert.equal(quote.confidenceAtIssue, 0.9)
})

test('stale routes to manual underwriting — the priced state is not the delivered state', () => {
  const quote = priceSla({ grade: 'stale', confidence: 0.9, coverageAmount: 10_000, rate: USD })
  assert.deepEqual(quote.decision, {
    class: 'manual-underwriting',
    reason: 'the proof is stale — the workspace moved after the evidence was taken, so the priced state is not the delivered state',
  })
})

test('unproven routes to manual underwriting — nothing verified to underwrite', () => {
  const quote = priceSla({ grade: 'unproven', confidence: 0.9, coverageAmount: 10_000, rate: USD })
  assert.deepEqual(quote.decision, {
    class: 'manual-underwriting',
    reason: 'the delivery was never proven — no decisive evidence backs the claim, so there is nothing verified to underwrite',
  })
})

test('no-baseline routes to manual underwriting — no prior state to insure', () => {
  const quote = priceSla({ grade: 'no-baseline', confidence: 0.9, coverageAmount: 10_000, rate: USD })
  assert.deepEqual(quote.decision, {
    class: 'manual-underwriting',
    reason: 'no baseline exists to diff against — without a prior state there is no regression to insure',
  })
})

test('proven without confidence routes to manual underwriting — an unknown posterior has no price', () => {
  const quote = priceSla({ grade: 'proven', coverageAmount: 10_000, rate: USD })
  assert.deepEqual(quote.decision, {
    class: 'manual-underwriting',
    reason: 'no confidence was measured for this proof — an unknown posterior cannot be priced into a premium',
  })
  assert.equal(quote.confidenceAtIssue, null)
})

test('confidence outside [0,1] routes to manual underwriting — NaN included', () => {
  for (const bad of [1.5, -0.1, Number.NaN]) {
    const quote = priceSla({ grade: 'proven', confidence: bad, coverageAmount: 10_000, rate: USD })
    assert.deepEqual(quote.decision, {
      class: 'manual-underwriting',
      reason: 'confidence is outside [0,1] — not a probability this policy can convert into a premium',
    }, `confidence ${bad}`)
    // A non-finite confidence is attested as absent, never as NaN.
    if (Number.isNaN(bad)) assert.equal(quote.confidenceAtIssue, null)
    else assert.equal(quote.confidenceAtIssue, bad)
  }
})

// ---------------------------------------------------------------------------
// Exclusions — the honest edges, pinned verbatim
// ---------------------------------------------------------------------------

test('the exclusions are the policy\'s honest edges — five clauses, pinned verbatim, carried into every quote', () => {
  assert.deepEqual(SLA_EXCLUSIONS, [
    'attribution keys on command strings — the same defect hidden behind a rewritten command line is not covered',
    "the transparency log witnesses one operator's view — a divergent fork view held by another operator is not covered",
    'evidence appended after the last signed checkpoint carries chain cover only — the tail window is not covered',
    'human endorsements price accepted risk, not verified fact — the accepted-risk portion of an endorsement is not covered',
    'non-decisive outcomes (timeout, error, aborted, skipped) verified nothing — the surface they never answered is not covered',
  ])

  // Every quote — offer, denial, manual — carries the same clauses.
  for (const grade of ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'] as const) {
    const quote = priceSla({
      grade, confidence: 0.9, coverageAmount: 10_000, rate: USD,
    })
    assert.deepEqual(quote.exclusions, SLA_EXCLUSIONS)
  }
})

// ---------------------------------------------------------------------------
// Content addressing — the quote addresses its own pricing content
// ---------------------------------------------------------------------------

test('quoteId addresses the quote — same inputs mint the same bytes; one cent of coverage is a different quote', () => {
  const base = { grade: 'proven' as const, confidence: 0.97, coverageAmount: 10_000, rate: USD }
  const a = priceSla(base)
  const b = priceSla(base)
  assert.deepEqual(a, b) // determinism, whole quote
  assert.match(a.quoteId, /^[0-9a-f]{16}$/) // 16 hex chars

  // One cent of coverage changes the price, so it must change the address.
  const penny = priceSla({ ...base, coverageAmount: 10_000.01 })
  assert.notEqual(penny.quoteId, a.quoteId)

  // A different confidence reprices the premium, so the address moves.
  const repriced = priceSla({ ...base, confidence: 0.98 })
  assert.notEqual(repriced.quoteId, a.quoteId)

  // A different decision class is a different quote, address included.
  const denied = priceSla({ ...base, grade: 'regressed' })
  assert.notEqual(denied.quoteId, a.quoteId)
})

test('the rate card is not part of the address — repricing the deployment leaves the quote bytes alone', () => {
  // The quoteId material is exactly {vehicle, grade, confidenceAtIssue,
  // decision, exclusions, termsVersion}: the premium is a function of the
  // *proof*, not of the deployer's cost card.
  const cheap = priceSla({
    grade: 'proven', confidence: 0.97, coverageAmount: 10_000,
    rate: { currency: 'USD', computePerMs: 0.000001, humanReviewPerItem: 0.5 },
  })
  const dear = priceSla({
    grade: 'proven', confidence: 0.97, coverageAmount: 10_000,
    rate: { currency: 'USD', computePerMs: 5, humanReviewPerItem: 250 },
  })
  assert.deepEqual(cheap, dear)
})

// ---------------------------------------------------------------------------
// Defenses — a bad price is refused, never computed
// ---------------------------------------------------------------------------

test('defense: coverage must be finite and strictly positive', () => {
  const base = { grade: 'proven' as const, confidence: 0.97, rate: USD }
  for (const coverageAmount of [0, -10_000, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => priceSla({ ...base, coverageAmount }),
      TypeError,
      `coverageAmount ${coverageAmount}`,
    )
  }
  // The defense precedes grading: even a regressed claim cannot be priced
  // against nonsense coverage.
  assert.throws(() => priceSla({ ...base, grade: 'regressed', coverageAmount: 0 }), TypeError)
})

test('defense: the rate card must be finite, non-negative USD', () => {
  const base = { grade: 'proven' as const, confidence: 0.97, coverageAmount: 10_000 }
  for (const rate of [
    { currency: 'USD', computePerMs: -0.0001 },
    { currency: 'USD', computePerMs: Number.NaN },
    { currency: 'USD', computePerMs: 0.0001, humanReviewPerItem: -1 },
    { currency: 'EUR', computePerMs: 0.0001 },
  ] as RateCard[]) {
    assert.throws(() => priceSla({ ...base, rate }), TypeError)
  }
})

test('defense: optional money fields must be finite and non-negative', () => {
  const base = { grade: 'proven' as const, confidence: 0.97, coverageAmount: 10_000, rate: USD }
  assert.throws(() => priceSla({ ...base, deductible: -1 }), TypeError)
  assert.throws(() => priceSla({ ...base, deductible: Number.NaN }), TypeError)
  assert.throws(() => priceSla({ ...base, minPremium: -5 }), TypeError)
})

test('the ledger defends its rate card too — a corrupt card corrupts every statement downstream', () => {
  const records = [evidence('unit/test', 'pass', 1000)]
  assert.throws(() => summarizeRunLedger({
    records, rate: { currency: 'USD', computePerMs: -1 },
  }), TypeError)
  assert.throws(() => summarizeRunLedger({
    records, rate: { currency: 'USD', computePerMs: Number.NaN },
  }), TypeError)
  assert.throws(() => summarizeRunLedger({
    records, rate: { currency: 'USD', computePerMs: 0.0001, humanReviewPerItem: -15 },
  }), TypeError)
  assert.throws(() => summarizeRunLedger({
    records, humanReviewItems: -2, rate: USD,
  }), TypeError)
})
