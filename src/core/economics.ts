/**
 * The economics of verification — what a run cost, what the money bought,
 * and what a proven claim is worth insuring. (v0.21)
 *
 * Every earlier layer of this project made trust *recomputable*; this module
 * gives it a unit cost. The evidence log already carries the two things money
 * can honestly be charged against — measured wall-clock (`durationMs` on
 * every record) and consumed human review (B/C attestations, counted
 * upstream) — and the v0.9 scheduler already ranked checks by certainty per
 * millisecond. The ledger below is that same data, restated as a statement:
 * compute spent, assertions verified, confidence purchased, information
 * gained, each per dollar. The SLA pricer turns a *proven* grade into an
 * insurance-style offer: premium = coverage × P(undetected defect).
 *
 * Two disciplines govern every number here:
 *
 * 1. **Only the measurable is measured.** Durations and counts come off
 *    records the engine already produced — no estimates, no self-reported
 *    effort. What was not measured is not invented: with no prior,
 *    `confidencePurchased` is `null` (never zero — do not pretend a purchase
 *    nobody priced), and with zero cost both per-dollar ratios are `null`
 *    (never Infinity — a free run did not buy anything *per dollar*). What
 *    was measured WRONG is not folded into the arithmetic either: a record
 *    whose `durationMs` is negative or non-finite books as unknown (counted,
 *    never summed), an out-of-domain factor is refused outright, and every
 *    priced input sits under the money ceiling (1e15) so no input, however
 *    finite, can overflow the money spec's rounding into an Infinity.
 * 2. **Prices are injected, never embedded.** This module contains no price.
 *    The deployer supplies a `RateCard`; swap the card and the same evidence
 *    reprices. A hardcoded rate would be a lie with a decimal point.
 *
 * Determinism: every monetary amount is rounded to six decimal places (the
 * money spec — floating-point dust never reaches a statement), and every
 * quote is content-addressed over its own pricing content, so identical
 * inputs mint identical bytes and a one-cent change is a different quote.
 *
 * Like `core/bayes.ts`, this module is pure: no clocks, no randomness, no
 * environment — only arithmetic over records and a rate card, so the same
 * inputs always produce the deeply identical outputs that audited money
 * demands.
 *
 * @module dsh-proof/core/economics
 */

import { canonicalJson, sha256 } from './hash.ts'
import { isDecisiveStatus } from './evidence.ts'
import type { Evidence, ProofGrade } from './evidence.ts'

// ---------------------------------------------------------------------------
// Money discipline
// ---------------------------------------------------------------------------

/** Every amount this module emits carries at most this many decimal places. */
const MONEY_DECIMALS = 6

/**
 * H-15: the magnitude ceiling every priced input shares. An amount at or
 * below 1e15 survives the ×10^6 money rounding without overflow AND still
 * has all six of its decimals representable in a double (float-53 integer
 * dust begins near 9e15). The v0.21 audit's overflow PoC came through
 * exactly this door: `coverageAmount = 1e308` is finite, passed every
 * finite-check, then `roundMoney`'s `×10^6` rounded it to Infinity — an
 * Infinity that landed in the decision AND, via canonical JSON's non-finite
 * fold, made three DIFFERENT coverages mint one identical quoteId. What the
 * money spec cannot round, this module never prices.
 */
const MONEY_CEILING = 1e15

/**
 * Round an amount to the money spec: six decimal places, half up. Applied to
 * every monetary field the module emits (ledger cost, cost-per-assertion,
 * premium, deductible, coverage) so float dust can never appear on a
 * statement — `7400ms × 0.0001` must read `0.74`, not `0.7400000000000001`.
 *
 * H-15: the exit is guarded — an amount whose rounding overflows the double
 * range throws instead of returning Infinity. "Infinity on a financial
 * statement is never an answer" is enforced at the last arithmetic exit as
 * well as at every input gate, so no combination of individually-legal
 * inputs (huge Σduration × a huge-but-legal rate) can smuggle one through.
 */
function roundMoney(amount: number): number {
  const rounded = Math.round(amount * 10 ** MONEY_DECIMALS) / 10 ** MONEY_DECIMALS
  if (!Number.isFinite(rounded)) {
    throw new TypeError(`amount ${amount} overflows the money spec — Infinity on a financial statement is never an answer`)
  }
  return rounded
}

/**
 * Finite, non-negative and inside the money ceiling — the shared shape of
 * every legal rate/amount field (H-15's input gate; see `MONEY_CEILING`).
 */
function isPricedField(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MONEY_CEILING
}

/** A probability this module will fold into information arithmetic: finite and in [0,1]. */
function isProbability(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1
}

// ---------------------------------------------------------------------------
// The rate card — prices come from the deployer, not from this file
// ---------------------------------------------------------------------------

/**
 * The deployer's price list. `computePerMs` converts measured milliseconds
 * into dollars; `humanReviewPerItem` prices one human review item (a B/C
 * attestation consumed by the run), defaulting to 0 when the deployment has
 * no paid review step. No field of this card has a default *value* other
 * than zero-for-absent: this module must never embed an opinion about what
 * compute or people cost.
 */
export interface RateCard {
  readonly currency: 'USD'
  readonly computePerMs: number
  readonly humanReviewPerItem?: number
}

function rateFieldError(field: string): TypeError {
  return new TypeError(`rate.${field} must be a finite non-negative number`)
}

/**
 * One validation, two consumers (ledger and pricer share the card): a rate
 * that is not a finite, non-negative USD card inside the money ceiling is
 * rejected loudly, because a negative or NaN price silently corrupts every
 * downstream statement — the ledger would report negative cost, the pricer
 * would mint nonsense quotes.
 */
function validateRate(rate: RateCard): void {
  if (typeof rate !== 'object' || rate === null) {
    throw new TypeError('rate must be a RateCard')
  }
  if (rate.currency !== 'USD') {
    throw new TypeError("rate.currency must be 'USD' — this ledger prices exactly one currency")
  }
  if (!isPricedField(rate.computePerMs)) throw rateFieldError('computePerMs')
  if (rate.humanReviewPerItem !== undefined && !isPricedField(rate.humanReviewPerItem)) {
    throw rateFieldError('humanReviewPerItem')
  }
}

// ---------------------------------------------------------------------------
// Information units
// ---------------------------------------------------------------------------

/**
 * Binary entropy in nats: H(p) = −p·ln(p) − (1−p)·ln(1−p), with 0·ln 0 ≡ 0 at
 * both degenerate endpoints (p ≤ 0 or p ≥ 1 → 0).
 *
 * The same formula as the module-private `binaryEntropy` in `core/bayes.ts`,
 * transcribed rather than imported: bayes.ts does not export it (its public
 * surface is deliberately only the scheduling API), and widening that surface
 * for one three-line function would couple two modules whose release
 * boundaries differ. If either copy ever changes, the other must follow —
 * the nats in a `RunLedger` and the VOI in a schedule are the same unit, and
 * two different nats in one codebase would be two different truths.
 */
function binaryEntropy(p: number): number {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log(p) - (1 - p) * Math.log(1 - p)
}

// ---------------------------------------------------------------------------
// The run ledger
// ---------------------------------------------------------------------------

/**
 * Everything one verification run consumed and produced, priced by a rate
 * card.
 *
 * - `records` — the run's evidence log entries; `durationMs` on each is the
 *   measured compute cost, decisive or not.
 * - `priorProbability`/`posteriorProbability` — the claim's probability
 *   before/after the run (v0.9's claim model). Either may be absent: a run
 *   without a measured prior bought an *unmeasured* amount of confidence,
 *   and the ledger says `null` instead of guessing.
 * - `factors` — per-check prior→posterior pairs, for the information sum.
 *   The run-level probabilities alone cannot reconstruct Σ[H(prior)−H(posterior)]
 *   (entropy does not distribute over products), so the per-check moves are
 *   supplied directly by whoever folded them. Each side must be a finite
 *   probability in [0,1]; anything else is a `TypeError` (M23), never a
 *   silently entropy-folded endpoint.
 * - `humanReviewItems` — human review items (B/C attestations) the run
 *   consumed; priced only when the card prices them. Counted in whole items:
 *   a non-integer (or non-finite, negative, >1e15) count is a `TypeError`.
 */
export interface RunLedgerInput {
  readonly records: readonly Evidence[]
  readonly priorProbability?: number
  readonly posteriorProbability?: number
  readonly factors?: ReadonlyArray<{ prior: number; posterior: number }>
  readonly humanReviewItems?: number
  readonly rate: RateCard
}

/** One run, restated as a statement of cost and what the cost bought. */
export interface RunLedger {
  /** Σ durationMs over *all* records — non-decisive time was spent too. */
  readonly computeMs: number
  readonly humanReviewItems: number
  /** computeMs×computePerMs + humanReviewItems×humanReviewPerItem (absent ⇒ 0), at the 6-decimal money spec. */
  readonly cost: number
  /**
   * Decisive records: each decisive check answer is one verified assertion.
   * @deprecated one number under two names — always equal to
   * `decisiveCount`; read `decisiveCount` (kept so existing consumers keep
   * compiling while they migrate).
   */
  readonly assertions: number
  readonly decisiveCount: number
  /** Non-decisive records — sunk cost made visible, not hidden. */
  readonly skippedCount: number
  /**
   * Records whose `durationMs` was not a finite non-negative number: the
   * time is booked as unknown — it contributes NOTHING to `computeMs`/`cost`
   * (never a negative or NaN on a statement) — and this count is the
   * narrative that says so, instead of the milliseconds silently vanishing.
   */
  readonly rejectedDurationRecords: number
  /**
   * cost / decisiveCount: what one verified assertion cost. `null` when
   * nothing was verified — a "per X" with no X is not the total cost
   * wearing a divisor's clothes (same three-state law as the per-dollar
   * ratios: zero assertions ≠ one assertion).
   */
  readonly costPerAssertion: number | null
  /** posterior − prior; `null` when either side was never measured. */
  readonly confidencePurchased: number | null
  /** confidencePurchased / cost; `null` when cost ≤ 0 or nothing was purchased — never Infinity. */
  readonly confidencePerDollar: number | null
  /** Σ[H(prior)−H(posterior)] in nats, signed — paying to learn bad news is still information. Absent factors ⇒ 0. */
  readonly infoNats: number
  /** infoNats / cost; `null` when cost ≤ 0 — never Infinity. */
  readonly natsPerDollar: number | null
}

/**
 * Price one run.
 *
 * Field semantics (pinned by test/31):
 *
 * - `computeMs` sums `durationMs` over **every** record whose duration is a
 *   finite non-negative number. A timed-out check burned the milliseconds
 *   all the same; `skippedCount` exists so the statement shows that spend
 *   bought no assertion rather than hiding it. A record whose `durationMs`
 *   is negative, NaN or ±Infinity contributes NOTHING to computeMs — the
 *   time is booked as unknown and `rejectedDurationRecords` says how many
 *   were (M22: an unmeasured duration never reaches a statement as a
 *   number, and decisiveness is judged on `status`, which the bad duration
 *   cannot poison).
 * - `assertions === decisiveCount`: `isDecisiveStatus` decides (pass/fail
 *   settle the check's question; error/timeout/aborted/skipped never did).
 * - `cost`, `costPerAssertion` and every other amount are rounded to six
 *   decimals — the money spec shared by everything this module emits.
 * - `costPerAssertion` is `null` when `decisiveCount === 0`: a per-unit
 *   price with no units is not the total cost (M24 — the same three-state
 *   law as the per-dollar ratios).
 * - `confidencePurchased` is exactly `posterior − prior` and only when both
 *   sides were measured; a negative value is reported as-is (a run that
 *   *lost* confidence is a real outcome, not a rounding problem).
 * - `infoNats` is the signed entropy drop per factor, summed in array order
 *   (deterministic for a given input). A factor folding toward failure
 *   (posterior < prior, entropy rising) contributes negatively — honest
 *   bookkeeping counts information gained, not news enjoyed. Every factor
 *   must be a finite probability in [0,1] — an out-of-domain prior is
 *   REFUSED (M23), never entropy-folded into a plausible-looking negative
 *   information gain.
 * - Both per-dollar ratios are `null` whenever `cost ≤ 0`: a free run bought
 *   confidence, but it bought nothing *per dollar*, and `Infinity` on a
 *   financial statement is never an answer.
 */
export function summarizeRunLedger(input: RunLedgerInput): RunLedger {
  validateRate(input.rate)
  if (input.humanReviewItems !== undefined
    && (!isPricedField(input.humanReviewItems) || !Number.isInteger(input.humanReviewItems))) {
    throw new TypeError('humanReviewItems must be a finite non-negative integer no greater than 1e15 when provided — review items are counted, not weighed')
  }

  let computeMs = 0
  let decisive = 0
  let rejectedDurationRecords = 0
  for (const record of input.records) {
    if (Number.isFinite(record.durationMs) && record.durationMs >= 0) {
      computeMs += record.durationMs
    } else {
      // M22: unmeasured time is booked as unknown (null accounting), never
      // summed into the statement — the count below is the narrative.
      rejectedDurationRecords += 1
    }
    if (isDecisiveStatus(record.status)) decisive += 1
  }
  const humanReviewItems = input.humanReviewItems ?? 0
  const cost = roundMoney(
    computeMs * input.rate.computePerMs + humanReviewItems * (input.rate.humanReviewPerItem ?? 0),
  )

  const purchased = input.priorProbability !== undefined && input.posteriorProbability !== undefined
    ? input.posteriorProbability - input.priorProbability
    : null

  let infoNats = 0
  for (const factor of input.factors ?? []) {
    if (!isProbability(factor.prior) || !isProbability(factor.posterior)) {
      throw new TypeError('factors must carry finite probabilities in [0,1] — an out-of-domain factor is refused, never folded into the information sum')
    }
    infoNats += binaryEntropy(factor.prior) - binaryEntropy(factor.posterior)
  }

  return {
    computeMs,
    humanReviewItems,
    cost,
    assertions: decisive,
    decisiveCount: decisive,
    skippedCount: input.records.length - decisive,
    rejectedDurationRecords,
    costPerAssertion: decisive > 0 ? roundMoney(cost / decisive) : null,
    confidencePurchased: purchased,
    confidencePerDollar: purchased !== null && cost > 0 ? purchased / cost : null,
    infoNats,
    natsPerDollar: cost > 0 ? infoNats / cost : null,
  }
}

// ---------------------------------------------------------------------------
// SLA pricing — insurance-style offers over proven grades
// ---------------------------------------------------------------------------

/**
 * The policy's exclusions: the honest edges of what dsh-proof can verify,
 * restated as the things this policy does not cover. Pinned verbatim by the
 * tests — an exclusion nobody can quote is a promise nobody made.
 */
export const SLA_EXCLUSIONS: readonly string[] = [
  'attribution keys on command strings — the same defect hidden behind a rewritten command line is not covered',
  "the transparency log witnesses one operator's view — a divergent fork view held by another operator is not covered",
  'evidence appended after the last signed checkpoint carries chain cover only — the tail window is not covered',
  'human endorsements price accepted risk, not verified fact — the accepted-risk portion of an endorsement is not covered',
  'non-decisive outcomes (timeout, error, aborted, skipped) verified nothing — the surface they never answered is not covered',
]

/** The quoting vehicle: one versioned set of terms, addressed into every quote. */
const VEHICLE = 'dsh-proof/SLA-1'
const TERMS_VERSION = 'SLA-1'

const REASON_REGRESSED = 'the delivery failed verification — the claim already broke'
const REASON_STALE =
  'the proof is stale — the workspace moved after the evidence was taken, so the priced state is not the delivered state'
const REASON_UNPROVEN =
  'the delivery was never proven — no decisive evidence backs the claim, so there is nothing verified to underwrite'
const REASON_NO_BASELINE =
  'no baseline exists to diff against — without a prior state there is no regression to insure'
const REASON_NO_CONFIDENCE =
  'no confidence was measured for this proof — an unknown posterior cannot be priced into a premium'
const REASON_CONFIDENCE_OUT_OF_RANGE =
  'confidence is outside [0,1] — not a probability this policy can convert into a premium'
const REASON_FOREIGN_GRADE =
  'the grade is not one of the five proof grades this policy prices — a word the formula cannot read never reaches the proven branch, a human underwriter reads it instead'

/**
 * H-15: the `ProofGrade` vocabulary as a runtime set — a grade this policy
 * prices is admitted BY VALUE. The engine boundary already refuses foreign
 * grades outright; this core-level gate makes the same refusal total, because
 * before it, anything that failed the four known-grade checks fell into the
 * `proven` branch — `'Proven'`, `'nonsense'` and the empty string all minted
 * full offers, the most privileged path a typo could buy.
 */
const SLA_GRADES: ReadonlySet<string> = new Set(['proven', 'regressed', 'stale', 'unproven', 'no-baseline'])

/**
 * The underwriting decision. Three outcomes, no fourth:
 *
 * - `offer` — a priced policy: premium now, deductible at claim time.
 * - `denied` — the claim already failed verification; insuring it would be
 *   selling coverage for a known loss.
 * - `manual-underwriting` — evidence exists but this formula honestly cannot
 *   price it (stale, unproven, no baseline, unmeasured or invalid
 *   confidence); a human underwriter takes over rather than a number being
 *   invented.
 */
export type SlaDecision =
  | { class: 'offer'; premium: number; pUndetected: number; deductible: number; coverageAmount: number }
  | { class: 'denied'; reason: string }
  | { class: 'manual-underwriting'; reason: string }

/** What the pricer needs: a graded proof, the coverage sought, and the rate card. */
export interface SlaQuoteInput {
  /**
   * The grade being priced. Runtime values outside the `ProofGrade`
   * vocabulary (foreign callers, JSON round-trips) route to manual
   * underwriting — refused BY VALUE, never fallen through to `proven`.
   */
  readonly grade: ProofGrade
  /** Posterior claim probability at issue time; absent or outside [0,1] routes to manual underwriting. */
  readonly confidence?: number
  readonly coverageAmount: number
  readonly rate: RateCard
  /** Claim-time excess, passed through untouched — never added into the premium. */
  readonly deductible?: number
  /** Floor for the premium (bookkeeping minimum); defaults to 0. */
  readonly minPremium?: number
}

/**
 * A content-addressed quote. `quoteId` is the first 16 hex chars of
 * `sha256(canonicalJson({vehicle, grade, confidenceAtIssue, decision, exclusions, termsVersion}))`
 * — the quote addresses its own pricing content, so the same inputs always
 * mint the same quote bytes and changing the coverage by one cent mints a
 * different id. The `decision` in that address is the *pricing* content
 * (class + the numbers); the human-readable `reason` strings are prose and
 * are deliberately excluded, so rewording a denial never re-prices the book.
 */
export interface SlaQuote {
  readonly quoteId: string
  readonly vehicle: 'dsh-proof/SLA-1'
  readonly grade: ProofGrade
  readonly confidenceAtIssue: number | null
  readonly decision: SlaDecision
  readonly exclusions: readonly string[]
  readonly currency: 'USD'
  readonly termsVersion: 'SLA-1'
}

/**
 * Price an SLA over a graded proof.
 *
 * Grading:
 *
 * - Any grade outside the five-value vocabulary (`proven`, `regressed`,
 *   `stale`, `unproven`, `no-baseline`) → manual underwriting (H-15): a
 *   foreign string never reaches the proven branch, whatever confidence it
 *   brought with it.
 * - `proven` + a confidence in **[0,1]** (endpoints included — P=0 and P=1
 *   are degenerate but mathematically legal, and priced at their face) → an
 *   offer. Confidence absent, non-finite, or outside [0,1] → manual
 *   underwriting: an unmeasured posterior has no price, and this module does
 *   not invent one.
 * - `regressed` → denied, verbatim: the delivery failed verification — the
 *   claim already broke.
 * - `stale` / `unproven` / `no-baseline` → manual underwriting, each with its
 *   one-sentence reason: evidence exists (or provably does not), but not in
 *   a shape this formula can underwrite.
 *
 * The offer's math:
 *
 *     pUndetected = 1 − confidence
 *     premium     = max(minPremium ?? 0, coverageAmount × pUndetected)
 *     deductible  = passthrough (claim-time excess; NEVER added into premium)
 *
 * **No second β.** The confidence supplied here already absorbed every
 * false-pass discount the scheduler applied on its way in — the organic
 * β = 0.02 of `BAYES_CONSTANTS.falsePass` (v0.9) and the synthetic-check
 * 0.15 of v0.12 (see `core/bayes.ts`, `PriorInput.syntheticFalsePass`).
 * `1 − confidence` therefore *is* the comprehensive probability that a
 * defect went undetected, synthetic checks included. Multiplying another β
 * in here would discount the discount and quietly under-price the book —
 * the one way this formula is forbidden from being clever.
 *
 * Defense: `coverageAmount` must be finite, strictly positive and no greater
 * than the money ceiling (1e15 — H-15: an amount whose `×10^6` rounding
 * would overflow is refused at the gate, so no Infinity can reach a decision
 * or, through canonical JSON's non-finite fold, collapse three different
 * coverages onto one `quoteId`); the rate card must pass `validateRate`;
 * optional money fields must be finite, non-negative and inside the ceiling.
 * A grade outside the five-value vocabulary routes to manual underwriting —
 * refused, never priced. Anything else throws a `TypeError` — a bad price is
 * never computed, it is refused.
 */
export function priceSla(input: SlaQuoteInput): SlaQuote {
  validateRate(input.rate)
  if (!Number.isFinite(input.coverageAmount) || input.coverageAmount <= 0 || input.coverageAmount > MONEY_CEILING) {
    throw new TypeError('coverageAmount must be a finite positive USD amount no greater than 1e15 — an amount the money spec cannot round is never priced')
  }
  if (input.deductible !== undefined && !isPricedField(input.deductible)) {
    throw new TypeError('deductible must be a finite non-negative number no greater than 1e15 when provided')
  }
  if (input.minPremium !== undefined && !isPricedField(input.minPremium)) {
    throw new TypeError('minPremium must be a finite non-negative number no greater than 1e15 when provided')
  }

  // A non-finite confidence cannot be attested on a quote (and must never
  // reach the content address, where canonical JSON would fold it to null
  // and collide with an honestly-absent one).
  const confidenceAtIssue = typeof input.confidence === 'number' && Number.isFinite(input.confidence)
    ? input.confidence
    : null

  const decision = decide(input)
  return {
    quoteId: sha256(canonicalJson({
      vehicle: VEHICLE,
      grade: input.grade,
      confidenceAtIssue,
      decision: decisionMaterial(decision),
      exclusions: SLA_EXCLUSIONS,
      termsVersion: TERMS_VERSION,
    })).slice(0, 16),
    vehicle: VEHICLE,
    grade: input.grade,
    confidenceAtIssue,
    decision,
    exclusions: SLA_EXCLUSIONS,
    currency: 'USD',
    termsVersion: TERMS_VERSION,
  }
}

function decide(input: SlaQuoteInput): SlaDecision {
  // H-15: vocabulary first. Before this gate, everything that was not one of
  // the four known non-proven grades fell through to the proven branch —
  // 'Proven', 'nonsense' and '' all minted offers. A foreign grade is a word
  // this formula cannot read: manual underwriting (the refusal door for
  // "evidence exists but this formula honestly cannot price it"), aligned
  // with the engine boundary, which refuses the same values by value.
  if (!SLA_GRADES.has(input.grade)) {
    return { class: 'manual-underwriting', reason: REASON_FOREIGN_GRADE }
  }
  if (input.grade === 'regressed') return { class: 'denied', reason: REASON_REGRESSED }
  if (input.grade === 'stale') return { class: 'manual-underwriting', reason: REASON_STALE }
  if (input.grade === 'unproven') return { class: 'manual-underwriting', reason: REASON_UNPROVEN }
  if (input.grade === 'no-baseline') return { class: 'manual-underwriting', reason: REASON_NO_BASELINE }

  // grade === 'proven': an offer needs a measured, legal probability.
  const confidence = input.confidence
  if (confidence === undefined) {
    return { class: 'manual-underwriting', reason: REASON_NO_CONFIDENCE }
  }
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return { class: 'manual-underwriting', reason: REASON_CONFIDENCE_OUT_OF_RANGE }
  }

  // pUndetected = 1 − confidence, already comprehensive — see "No second β"
  // in the pricer's doc comment. Endpoints are legal: P=1 prices the premium
  // down to the minPremium floor, P=0 prices it up to full coverage.
  const pUndetected = 1 - confidence
  return {
    class: 'offer',
    premium: roundMoney(Math.max(input.minPremium ?? 0, input.coverageAmount * pUndetected)),
    pUndetected,
    deductible: roundMoney(input.deductible ?? 0),
    coverageAmount: roundMoney(input.coverageAmount),
  }
}

/** The decision as addressable pricing content: class plus the numbers, never the prose. */
function decisionMaterial(decision: SlaDecision): { class: string; premium?: number; pUndetected?: number; deductible?: number; coverageAmount?: number } {
  if (decision.class !== 'offer') return { class: decision.class }
  return {
    class: decision.class,
    premium: decision.premium,
    pUndetected: decision.pUndetected,
    deductible: decision.deductible,
    coverageAmount: decision.coverageAmount,
  }
}
