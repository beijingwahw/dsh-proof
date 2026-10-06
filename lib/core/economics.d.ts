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
import type { Evidence, ProofGrade } from './evidence.ts';
/**
 * The deployer's price list. `computePerMs` converts measured milliseconds
 * into dollars; `humanReviewPerItem` prices one human review item (a B/C
 * attestation consumed by the run), defaulting to 0 when the deployment has
 * no paid review step. No field of this card has a default *value* other
 * than zero-for-absent: this module must never embed an opinion about what
 * compute or people cost.
 */
export interface RateCard {
    readonly currency: 'USD';
    readonly computePerMs: number;
    readonly humanReviewPerItem?: number;
}
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
    readonly records: readonly Evidence[];
    readonly priorProbability?: number;
    readonly posteriorProbability?: number;
    readonly factors?: ReadonlyArray<{
        prior: number;
        posterior: number;
    }>;
    readonly humanReviewItems?: number;
    readonly rate: RateCard;
}
/** One run, restated as a statement of cost and what the cost bought. */
export interface RunLedger {
    /** Σ durationMs over *all* records — non-decisive time was spent too. */
    readonly computeMs: number;
    readonly humanReviewItems: number;
    /** computeMs×computePerMs + humanReviewItems×humanReviewPerItem (absent ⇒ 0), at the 6-decimal money spec. */
    readonly cost: number;
    /**
     * Decisive records: each decisive check answer is one verified assertion.
     * @deprecated one number under two names — always equal to
     * `decisiveCount`; read `decisiveCount` (kept so existing consumers keep
     * compiling while they migrate).
     */
    readonly assertions: number;
    readonly decisiveCount: number;
    /** Non-decisive records — sunk cost made visible, not hidden. */
    readonly skippedCount: number;
    /**
     * Records whose `durationMs` was not a finite non-negative number: the
     * time is booked as unknown — it contributes NOTHING to `computeMs`/`cost`
     * (never a negative or NaN on a statement) — and this count is the
     * narrative that says so, instead of the milliseconds silently vanishing.
     */
    readonly rejectedDurationRecords: number;
    /**
     * cost / decisiveCount: what one verified assertion cost. `null` when
     * nothing was verified — a "per X" with no X is not the total cost
     * wearing a divisor's clothes (same three-state law as the per-dollar
     * ratios: zero assertions ≠ one assertion).
     */
    readonly costPerAssertion: number | null;
    /** posterior − prior; `null` when either side was never measured. */
    readonly confidencePurchased: number | null;
    /** confidencePurchased / cost; `null` when cost ≤ 0 or nothing was purchased — never Infinity. */
    readonly confidencePerDollar: number | null;
    /** Σ[H(prior)−H(posterior)] in nats, signed — paying to learn bad news is still information. Absent factors ⇒ 0. */
    readonly infoNats: number;
    /** infoNats / cost; `null` when cost ≤ 0 — never Infinity. */
    readonly natsPerDollar: number | null;
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
export declare function summarizeRunLedger(input: RunLedgerInput): RunLedger;
/**
 * The policy's exclusions: the honest edges of what dsh-proof can verify,
 * restated as the things this policy does not cover. Pinned verbatim by the
 * tests — an exclusion nobody can quote is a promise nobody made.
 */
export declare const SLA_EXCLUSIONS: readonly string[];
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
export type SlaDecision = {
    class: 'offer';
    premium: number;
    pUndetected: number;
    deductible: number;
    coverageAmount: number;
} | {
    class: 'denied';
    reason: string;
} | {
    class: 'manual-underwriting';
    reason: string;
};
/** What the pricer needs: a graded proof, the coverage sought, and the rate card. */
export interface SlaQuoteInput {
    /**
     * The grade being priced. Runtime values outside the `ProofGrade`
     * vocabulary (foreign callers, JSON round-trips) route to manual
     * underwriting — refused BY VALUE, never fallen through to `proven`.
     */
    readonly grade: ProofGrade;
    /** Posterior claim probability at issue time; absent or outside [0,1] routes to manual underwriting. */
    readonly confidence?: number;
    readonly coverageAmount: number;
    readonly rate: RateCard;
    /** Claim-time excess, passed through untouched — never added into the premium. */
    readonly deductible?: number;
    /** Floor for the premium (bookkeeping minimum); defaults to 0. */
    readonly minPremium?: number;
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
    readonly quoteId: string;
    readonly vehicle: 'dsh-proof/SLA-1';
    readonly grade: ProofGrade;
    readonly confidenceAtIssue: number | null;
    readonly decision: SlaDecision;
    readonly exclusions: readonly string[];
    readonly currency: 'USD';
    readonly termsVersion: 'SLA-1';
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
export declare function priceSla(input: SlaQuoteInput): SlaQuote;
//# sourceMappingURL=economics.d.ts.map