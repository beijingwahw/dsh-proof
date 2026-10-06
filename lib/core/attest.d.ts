/**
 * Attestation evidence (ι): Classes B and C re-enter the proof system.
 *
 * Class A evidence is the machine's own measurement — a check ran, its exit
 * code and normalised output were captured, and any third party can re-run
 * the command and compare digests. Classes B and C are *testimony*, not
 * measurement, and each gets the strongest honesty mechanism testimony admits:
 *
 * - Class B — an LLM jury deliberates on a claim. The juror is not
 *   deterministic, so the evidence is not the verdict alone but the whole
 *   reproducibility bundle: the exact prompt (rubric included), the declared
 *   model identity, the declared independence mode, and the complete verbatim
 *   output. That bundle does not make a deliberation reproducible the way a
 *   hash is; it makes it *auditable* — any third party can replay the frozen
 *   prompt against the declared model and check the recorded output is what
 *   that model actually tends to say. A verdict that will not replay is
 *   detectable, which is the ceiling of integrity a non-deterministic witness
 *   can offer, and it is enough to support disputes.
 * - Class C — a named human endorses or rejects a claim against a recorded
 *   scope (the claim text and, when one exists, the evidence root they
 *   reviewed). The seam is binary by design: elicited self-confidence from
 *   the endorsing party is not evidence, so human confidence is modelled as
 *   a constant (see `TrustWeights.humanProbability`).
 *
 * Appeals: the evidence chain is append-only, so a re-deliberation cannot
 * overwrite the record it disputes. Instead it is appended at `gen + 1`, and
 * readers resolve to the highest `gen` (`activeAttestations`) — the old
 * record stays on the chain as the appeal's foil, superseded but visible.
 *
 * Determinism: everything here is a pure function of its inputs. No clock
 * (timestamps are *supplied* by the caller and recorded, never generated), no
 * randomness, no `node:*` imports — `sha256` comes from `./hash.ts`, keeping
 * this module inside the content-addressing discipline: outputs enter the
 * evidence chain, so the same input must produce byte-identical output
 * forever.
 *
 * @module dsh-proof/core/attest
 */
/**
 * The three evidence classes. 'A' is machine measurement (evidence records,
 * this module's caller), 'B' is LLM jury testimony (`JuryAttestation`), 'C'
 * is human endorsement (`HumanAttestation`). The class is a *trust policy
 * dimension*, not a quality ranking: an A record is recomputable, a B record
 * is auditable, a C record is accountable to a named person.
 */
export type EvidenceClass = 'A' | 'B' | 'C';
/** Version tag of the default jury rubric; recorded on every attestation that used it. */
export declare const RUBRIC_V1: "jury-rubric/v1";
/**
 * The default jury rubric — the deliberation contract every Class B prompt
 * carries (see `juryPrompt`). Frozen verbatim in the source so a rubric edit
 * is a code change, visible in review and impossible to make silently mid-chain;
 * `RUBRIC_V1` tags which text a given attestation deliberated under.
 *
 * The rubric states the three obligations a juror owes the record: judge only
 * from the given materials, report `probability` as a subjective
 * probability-that-the-claim-is-true (a judgment, not a measurement), abstain
 * when the evidence is insufficient — and the provenance warning that the
 * output lands on a tamper-evident chain and will be replayed by third
 * parties. A juror told it is being recorded is a juror that can be held to
 * what it said.
 */
export declare const JURY_RUBRIC: string;
/** A Class B attestation: one complete, replayable jury deliberation. */
export interface JuryAttestation {
    readonly kind: 'attest/jury';
    /** Identity of the claim deliberated: `claimIdOf(claim)`. */
    readonly claimId: string;
    /**
     * Deliberation generation, 0-based. An appeal re-deliberates at `gen + 1`;
     * readers resolve to the highest gen per (claimId, kind), so on-chain
     * history is preserved while the *active* verdict always reflects the last
     * undisputed (or last-word) deliberation.
     */
    readonly gen: number;
    /** The prompt the juror saw, byte for byte — rubric, claim, and context. The thing a third party replays. */
    readonly prompt: string;
    /** Which rubric text the prompt embedded (e.g. `RUBRIC_V1`). */
    readonly rubricVersion: string;
    /**
     * The model identity the *submitter* declares for the juror. This module
     * cannot verify it — an LLM's self-report is not a signature — so it is
     * recorded as a claim, and a replay that disagrees is the audit that
     * catches it.
     */
    readonly model: string;
    /**
     * How independent the juror's context was declared to be:
     * - 'same-session' — deliberated inside the authoring agent's own context
     *   (cheapest, most contamination-prone);
     * - 'fresh-context' — a fresh conversation with the same model family;
     * - 'isolated-model' — a different model instance entirely.
     * Trust policy may weigh these differently; honesty demands they be named.
     */
    readonly independence: 'same-session' | 'fresh-context' | 'isolated-model';
    /** The ruling. 'abstain' means "evidence insufficient" and carries factor 1. */
    readonly verdict: 'uphold' | 'reject' | 'abstain';
    /** The juror's subjective probability that the claim is true. */
    readonly probability: number;
    /** The juror's complete verbatim output, reasoning included. */
    readonly output: string;
    /** Submit-time epoch millis, supplied by the caller (this module never reads a clock). */
    readonly at: number;
}
/** A Class C attestation: a named human's endorsement or rejection. */
export interface HumanAttestation {
    readonly kind: 'attest/human';
    readonly claimId: string;
    /** Endorsement generation, 0-based; a retraction-and-reendorse supersedes via `activeAttestations`. */
    readonly gen: number;
    /** Identity of the endorsing human, as declared. Named accountability is the whole of Class C. */
    readonly approver: string;
    /** Endorse-time epoch millis, supplied by the caller. */
    readonly approvedAt: number;
    /** Exactly what the approver took responsibility for. */
    readonly scope: {
        readonly claim: string;
        readonly evidenceRoot: string | null;
    };
    readonly decision: 'endorse' | 'reject';
}
export type Attestation = JuryAttestation | HumanAttestation;
/**
 * Stable 16-hex identity of a claim text: the first 16 characters of its
 * sha256. Sixteen hex chars (64 bits) is collision-safe for any realistic
 * number of claims on one chain, while staying readable in reports and marker
 * payloads. Attestations bind to the *exact* claim text — rewording a claim
 * is a new claim and needs new testimony.
 */
export declare function claimIdOf(claim: string): string;
/**
 * Assemble the Class B deliberation prompt deterministically: header, the
 * rubric (annotated with its version — a replay must know which rubric text
 * it owes fidelity to), the claim, the context, and the output-format
 * instruction. Pure string concatenation, no templating engine, because the
 * prompt itself is evidence: the same (claim, context, rubric, version)
 * must produce the byte-identical prompt every time, forever, or "replay
 * this prompt" stops meaning anything.
 */
export declare function juryPrompt(claim: string, context: string, rubric?: string, rubricVersion?: string): string;
/**
 * The operator's explicit trust policy for testimony, in the currency of
 * `attestationFactor`. Weights are declared, never learned: there is no
 * labelled dataset of "this witness was right" to fit them on, and a tuned
 * constant nobody re-tunes is worse than an honest declared one.
 */
export interface TrustWeights {
    /** Exponent for Class B (LLM jury) probability. Default 0.7 — a juror is trusted less than a human, more than nothing. */
    readonly classB: number;
    /** Exponent for Class C (human endorsement) probability. Default 0.9. */
    readonly classC: number;
    /**
     * Probability that an endorsing human is right, default 0.95. A modelling
     * choice, not a measurement: Class C's seam is binary, and this constant
     * stands in for the confidence the seam declines to elicit. It is 0.95,
     * not 1 — an endorsement that could never be wrong would make every
     * endorsed claim unfalsifiable. Domain: finite [0,1] (assertTrustWeights
     * refuses the outside loudly — V7-M2); the endpoints are defined, not
     * nonsense: 0 prices humans as always wrong, 1 as infallible.
     */
    readonly humanProbability: number;
}
export declare const DEFAULT_TRUST_WEIGHTS: TrustWeights;
/**
 * The claim-probability factor an attestation contributes — the same currency
 * `claimProbability` (core/bayes.ts) multiplies together over machine checks.
 *
 * **Why an exponent.** `claimProbability` is a product of factors, so an
 * attestation's effect on the log of the claim probability is log(factor).
 * Defining factor = p^w makes log(factor) = w·log(p): the trust weight is a
 * *linear discount of the evidence's log-odds contribution*. w = 0 → factor
 * is 1 (no trust, no evidence — even p = 0 cannot move the claim, since
 * 0^0 = 1); w = 1 → factor is p (the witness testifies at full weight);
 * values in between interpolate smoothly and monotonically. Exponentiation
 * is the unique family that does this while keeping every factor in [0, 1].
 *
 * **Why a weak witness can only weaken.** For w ∈ [0, 1] and p ∈ [0, 1],
 * p^w ∈ [p, 1] (because w·ln p lies between ln p and 0). So every testimony
 * factor is ≤ 1: evidence enters the claim product as a discount, never a
 * multiplier. A claim cannot be argued *above* what its priors and machine
 * evidence support by stacking witnesses — the most a witness can do for a
 * claim is abstain (factor 1). Testimony can only make a claim harder to
 * believe, which is the correct direction of skepticism for self-interested
 * proof systems.
 *
 * Direction needs no special case IN THE FACTOR: a 'reject' verdict arrives
 * with a low probability-that-the-claim-is-true, and p^w is low exactly then.
 * The probability carries the direction; the weight carries only the belief.
 * (The *fusion* layer does consume the verdict — see `fuseConfidence` —
 * because there a rejection raising the machine's confidence must be
 * structurally impossible, number field notwithstanding.)
 */
export declare function attestationFactor(att: Attestation, weights: TrustWeights): number;
/**
 * Fuse one witness into a confidence the machine run already earned — the
 * *reliability mixture*, not the discount above.
 *
 * `attestationFactor` (p^w) is the right algebra when the witness is one more
 * independent component of a claim product: there it can only add residual
 * doubt. But when a machine certification already exists and a witness
 * speaks about THE WHOLE CLAIM, the honest model is different: with
 * probability w the witness is reliable, in which case the confidence should
 * become what they assert; with probability 1 − w they are noise and the
 * machine number stands. The expectation of that is the linear mixture
 *
 *     fused = (1 − w) · current + w · p
 *
 * which pulls the number TOWARD the witness's asserted probability with pull
 * strength exactly w. A jury asserting 0.99 at w = 0.7 can carry a 0.94
 * machine certification across a 0.97 target (0.3·0.94 + 0.7·0.99 ≈ 0.98) —
 * the rescue the product exists to sell — while the same jury asserting 0.1
 * crashes it to ≈ 0.34. Direction lives in p, strength in w, and the fused
 * value can never overshoot the witness's own assertion (both mixture
 * endpoints are p and current).
 *
 * H-30 — a REJECTING verdict never mixtures. The mixture's premise is that
 * the witness asserts a probability for the WHOLE claim; a juror whose
 * verdict is 'reject' testifies *against* it, and testimony against enters
 * as the discount (`attestationFactor`, multiplicatively — the same seam a
 * Class C rejection takes), never as an asserted high confidence. Before
 * this, `fuseConfidence(0.94, reject@0.99)` returned 0.975 — a sworn
 * rejection CARRYING the number across a 0.97 certify target — because the
 * algebra read only the probability field and treated the verdict as display
 * text. (`parseJury` now refuses such self-contradictory records at the
 * chain-read boundary; this branch is the second lock, for
 * directly-constructed records, so the guarantee does not depend on which
 * door the record came through.)
 *
 * Class C is binary (the approval seam carries no number), so it does not
 * mixture: an endorsement is *risk acceptance*, not certainty transfer — it
 * leaves the confidence untouched (the human accepted the residual; the
 * number stays what machines measured) and unlocks the grade at the engine
 * level. A rejection multiplies in the heavy discount via `attestationFactor`.
 */
export declare function fuseConfidence(current: number, att: Attestation, weights: TrustWeights): number;
/**
 * Marker payloads as read off the chain, in log order — the shape the tools
 * layer hands to `activeAttestations` after collecting every attestation
 * marker from the evidence log.
 */
export interface AttestationMarkerPayloads {
    readonly payloads: readonly unknown[];
}
/**
 * Parse raw chain payloads into the *active* attestation set.
 *
 * Parsing is defensive because the input is chain data — bytes a writer may
 * have gotten wrong or an adversary may have shaped: payloads that are not
 * objects, do not carry an attestation `kind`, or fail the shape of that
 * kind are skipped, never thrown on. One corrupt marker must not render
 * every attestation unreadable.
 *
 * Appeal resolution: within one (claimId, kind), the highest `gen` wins, and
 * an equal gen is won by the later chain line — matching the log's own
 * "later wins" reading discipline (`EvidenceStore.latest`). The chain is
 * append-only, so an appeal re-deliberates at gen+1 and resolution does the
 * superseding; the disputed record stays visible as the appeal's foil.
 *
 * B and C are resolved *independently* even for the same claimId: an
 * appealed jury verdict must not erase a human endorsement, nor a
 * re-endorsement a jury record — they are different evidence channels with
 * different appeal processes, and the (claimId, kind) key keeps both.
 *
 * Output is sorted by (claimId, kind) so the result is a deterministic
 * function of the payload set, whatever order the chain received them in.
 */
export declare function activeAttestations(payloads: readonly unknown[]): Attestation[];
/** The active attestation set narrowed to one claim, in the same deterministic order. */
export declare function attestationsFor(payloads: readonly unknown[], claimId: string): Attestation[];
//# sourceMappingURL=attest.d.ts.map