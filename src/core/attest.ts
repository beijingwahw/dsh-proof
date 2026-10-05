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

import { sha256 } from './hash.ts'

/**
 * The three evidence classes. 'A' is machine measurement (evidence records,
 * this module's caller), 'B' is LLM jury testimony (`JuryAttestation`), 'C'
 * is human endorsement (`HumanAttestation`). The class is a *trust policy
 * dimension*, not a quality ranking: an A record is recomputable, a B record
 * is auditable, a C record is accountable to a named person.
 */
export type EvidenceClass = 'A' | 'B' | 'C'

/** Version tag of the default jury rubric; recorded on every attestation that used it. */
export const RUBRIC_V1 = 'jury-rubric/v1' as const

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
export const JURY_RUBRIC: string = [
  'You are an independent juror in a machine-verifiable proof system. Deliberate',
  'on the single CLAIM below, judged solely against the materials given in',
  'CONTEXT.',
  '',
  'Rules of deliberation:',
  '',
  '1. Decide only from the given materials. Do not use outside knowledge about',
  '   the claim\'s subject, and do not assume access to tools, files, or',
  '   sessions beyond what CONTEXT provides.',
  '2. "verdict" is your ruling on the claim: "uphold" when the materials',
  '   support it, "reject" when the materials contradict it, "abstain" when',
  '   the materials are insufficient to decide either way.',
  '3. "probability" is your subjective probability, in [0, 1], that the claim',
  '   is true. It is a calibrated judgment, not a measurement — report the',
  '   number your own reasoning actually supports.',
  '4. When the evidence before you is insufficient, abstain. An honest',
  '   abstention is worth more to the record than a confident guess.',
  '5. "reasoning" states, in your own words, which parts of the context',
  '   support or undermine the claim, and why your probability is what it is.',
  '',
  'Output format: respond with exactly one JSON object of the form',
  '{"verdict": "uphold" | "reject" | "abstain", "probability": <number in [0,1]>,',
  '"reasoning": "<string>"} — and nothing else before or after it.',
  '',
  'Provenance warning: your entire output, this prompt, and the declared model',
  'identity will be recorded verbatim as Class B evidence on a tamper-evident',
  'chain. Any third party may re-run this exact prompt against the same or a',
  'different model and compare outputs. Deliberate as if your answer were a',
  'permanent, public, reproducible artifact — because it is.',
].join('\n')

/** A Class B attestation: one complete, replayable jury deliberation. */
export interface JuryAttestation {
  readonly kind: 'attest/jury'
  /** Identity of the claim deliberated: `claimIdOf(claim)`. */
  readonly claimId: string
  /**
   * Deliberation generation, 0-based. An appeal re-deliberates at `gen + 1`;
   * readers resolve to the highest gen per (claimId, kind), so on-chain
   * history is preserved while the *active* verdict always reflects the last
   * undisputed (or last-word) deliberation.
   */
  readonly gen: number
  /** The prompt the juror saw, byte for byte — rubric, claim, and context. The thing a third party replays. */
  readonly prompt: string
  /** Which rubric text the prompt embedded (e.g. `RUBRIC_V1`). */
  readonly rubricVersion: string
  /**
   * The model identity the *submitter* declares for the juror. This module
   * cannot verify it — an LLM's self-report is not a signature — so it is
   * recorded as a claim, and a replay that disagrees is the audit that
   * catches it.
   */
  readonly model: string
  /**
   * How independent the juror's context was declared to be:
   * - 'same-session' — deliberated inside the authoring agent's own context
   *   (cheapest, most contamination-prone);
   * - 'fresh-context' — a fresh conversation with the same model family;
   * - 'isolated-model' — a different model instance entirely.
   * Trust policy may weigh these differently; honesty demands they be named.
   */
  readonly independence: 'same-session' | 'fresh-context' | 'isolated-model'
  /** The ruling. 'abstain' means "evidence insufficient" and carries factor 1. */
  readonly verdict: 'uphold' | 'reject' | 'abstain'
  /** The juror's subjective probability that the claim is true. */
  readonly probability: number
  /** The juror's complete verbatim output, reasoning included. */
  readonly output: string
  /** Submit-time epoch millis, supplied by the caller (this module never reads a clock). */
  readonly at: number
}

/** A Class C attestation: a named human's endorsement or rejection. */
export interface HumanAttestation {
  readonly kind: 'attest/human'
  readonly claimId: string
  /** Endorsement generation, 0-based; a retraction-and-reendorse supersedes via `activeAttestations`. */
  readonly gen: number
  /** Identity of the endorsing human, as declared. Named accountability is the whole of Class C. */
  readonly approver: string
  /** Endorse-time epoch millis, supplied by the caller. */
  readonly approvedAt: number
  /** Exactly what the approver took responsibility for. */
  readonly scope: { readonly claim: string; readonly evidenceRoot: string | null }
  readonly decision: 'endorse' | 'reject'
}

export type Attestation = JuryAttestation | HumanAttestation

/**
 * Stable 16-hex identity of a claim text: the first 16 characters of its
 * sha256. Sixteen hex chars (64 bits) is collision-safe for any realistic
 * number of claims on one chain, while staying readable in reports and marker
 * payloads. Attestations bind to the *exact* claim text — rewording a claim
 * is a new claim and needs new testimony.
 */
export function claimIdOf(claim: string): string {
  return sha256(claim).slice(0, 16)
}

/**
 * Assemble the Class B deliberation prompt deterministically: header, the
 * rubric (annotated with its version — a replay must know which rubric text
 * it owes fidelity to), the claim, the context, and the output-format
 * instruction. Pure string concatenation, no templating engine, because the
 * prompt itself is evidence: the same (claim, context, rubric, version)
 * must produce the byte-identical prompt every time, forever, or "replay
 * this prompt" stops meaning anything.
 */
export function juryPrompt(
  claim: string,
  context: string,
  rubric: string = JURY_RUBRIC,
  rubricVersion: string = RUBRIC_V1,
): string {
  return [
    '=== CLASS B JURY DELIBERATION ===',
    '',
    `--- RUBRIC ${rubricVersion} ---`,
    rubric,
    '',
    '=== CLAIM ===',
    claim,
    '',
    '=== CONTEXT ===',
    context,
    '',
    '=== OUTPUT ===',
    'Respond with exactly one JSON object — {"verdict": "uphold"|"reject"|"abstain", "probability": <number 0..1>, "reasoning": "<text>"} — and nothing else.',
  ].join('\n')
}

/**
 * The operator's explicit trust policy for testimony, in the currency of
 * `attestationFactor`. Weights are declared, never learned: there is no
 * labelled dataset of "this witness was right" to fit them on, and a tuned
 * constant nobody re-tunes is worse than an honest declared one.
 */
export interface TrustWeights {
  /** Exponent for Class B (LLM jury) probability. Default 0.7 — a juror is trusted less than a human, more than nothing. */
  readonly classB: number
  /** Exponent for Class C (human endorsement) probability. Default 0.9. */
  readonly classC: number
  /**
   * Probability that an endorsing human is right, default 0.95. A modelling
   * choice, not a measurement: Class C's seam is binary, and this constant
   * stands in for the confidence the seam declines to elicit. It is 0.95,
   * not 1 — an endorsement that could never be wrong would make every
   * endorsed claim unfalsifiable.
   */
  readonly humanProbability: number
}

export const DEFAULT_TRUST_WEIGHTS: TrustWeights = { classB: 0.7, classC: 0.9, humanProbability: 0.95 }

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
 * Direction needs no special case: a 'reject' verdict arrives with a low
 * probability-that-the-claim-is-true, and p^w is low exactly then. The
 * probability carries the direction; the weight carries only the belief.
 */
export function attestationFactor(att: Attestation, weights: TrustWeights): number {
  if (att.kind === 'attest/jury') {
    // Abstention is deliberately factor 1, not a penalty: "I cannot tell" is
    // the absence of evidence, and absence of evidence must not be booked as
    // evidence of absence.
    if (att.verdict === 'abstain') return 1
    // The probability came out of an LLM's JSON. A value unreadable as a
    // probability (NaN — which would turn the whole claim product into NaN —
    // or anything outside [0,1], where > 1 would AMPLIFY the claim) is a
    // broken delivery, not evidence; treat it as abstain.
    if (!isUsableProbability(att.probability)) return 1
    return Math.pow(att.probability, weights.classB)
  }
  // Class C: endorse testifies "true" with probability humanProbability;
  // reject testifies "true" only with the human's error probability
  // 1 − humanProbability — a trusted human's rejection is a heavy discount,
  // which is the entire point of registering a human at Class C.
  if (!isUsableProbability(weights.humanProbability)) return 1
  const p = att.decision === 'endorse' ? weights.humanProbability : 1 - weights.humanProbability
  return Math.pow(p, weights.classC)
}

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
 * Class C is binary (the approval seam carries no number), so it does not
 * mixture: an endorsement is *risk acceptance*, not certainty transfer — it
 * leaves the confidence untouched (the human accepted the residual; the
 * number stays what machines measured) and unlocks the grade at the engine
 * level. A rejection multiplies in the heavy discount via `attestationFactor`.
 */
export function fuseConfidence(current: number, att: Attestation, weights: TrustWeights): number {
  if (!isUsableProbability(current)) return current
  if (att.kind === 'attest/human') {
    // Endorse: the number stands (risk acceptance, grade-level unlock).
    // Reject: a trusted human's rejection is a heavy discount.
    return att.decision === 'endorse'
      ? current
      : current * attestationFactor(att, weights)
  }
  if (att.verdict === 'abstain') return current
  if (!isUsableProbability(att.probability)) return current
  const w = weights.classB
  return (1 - w) * current + w * att.probability
}

/** A probability this module is willing to fold into a claim product: finite and in [0, 1]. */
function isUsableProbability(p: number): boolean {
  return Number.isFinite(p) && p >= 0 && p <= 1
}

/**
 * Marker payloads as read off the chain, in log order — the shape the tools
 * layer hands to `activeAttestations` after collecting every attestation
 * marker from the evidence log.
 */
export interface AttestationMarkerPayloads { readonly payloads: readonly unknown[] }

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
export function activeAttestations(payloads: readonly unknown[]): Attestation[] {
  const active = new Map<string, Attestation>()
  for (const payload of payloads) {
    const att = parseAttestation(payload)
    if (att === undefined) continue
    const key = `${att.claimId}\u0000${att.kind}`
    const incumbent = active.get(key)
    // `>=`, not `>`: at equal gen the later chain line wins.
    if (incumbent === undefined || att.gen >= incumbent.gen) active.set(key, att)
  }
  return [...active.values()].sort(
    (a, b) => compareStrings(a.claimId, b.claimId) || compareStrings(a.kind, b.kind),
  )
}

/** The active attestation set narrowed to one claim, in the same deterministic order. */
export function attestationsFor(payloads: readonly unknown[], claimId: string): Attestation[] {
  return activeAttestations(payloads).filter(att => att.claimId === claimId)
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

// ---------------------------------------------------------------------------
// Defensive payload parsing (chain bytes → typed attestations)
// ---------------------------------------------------------------------------

function parseAttestation(payload: unknown): Attestation | undefined {
  if (typeof payload !== 'object' || payload === null) return undefined
  const p = payload as Record<string, unknown>
  if (p.kind === 'attest/jury') return parseJury(p)
  if (p.kind === 'attest/human') return parseHuman(p)
  return undefined
}

const INDEPENDENCE: ReadonlySet<string> = new Set(['same-session', 'fresh-context', 'isolated-model'])
const VERDICTS: ReadonlySet<string> = new Set(['uphold', 'reject', 'abstain'])
const DECISIONS: ReadonlySet<string> = new Set(['endorse', 'reject'])

function isString(v: unknown): v is string {
  return typeof v === 'string'
}

/** A generation counter: a non-negative integer. Anything else is a malformed record. */
function isGen(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

function parseJury(p: Record<string, unknown>): JuryAttestation | undefined {
  if (
    !isString(p.claimId) || !isGen(p.gen) || !isString(p.prompt) || !isString(p.rubricVersion)
    || !isString(p.model) || typeof p.independence !== 'string' || !INDEPENDENCE.has(p.independence)
    || typeof p.verdict !== 'string' || !VERDICTS.has(p.verdict)
    || !isFiniteNumber(p.probability) || !isString(p.output) || !isFiniteNumber(p.at)
  ) return undefined
  return {
    kind: 'attest/jury',
    claimId: p.claimId,
    gen: p.gen,
    prompt: p.prompt,
    rubricVersion: p.rubricVersion,
    model: p.model,
    independence: p.independence as JuryAttestation['independence'],
    verdict: p.verdict as JuryAttestation['verdict'],
    probability: p.probability,
    output: p.output,
    at: p.at,
  }
}

function parseHuman(p: Record<string, unknown>): HumanAttestation | undefined {
  const scope = p.scope
  if (
    !isString(p.claimId) || !isGen(p.gen) || !isString(p.approver) || !isFiniteNumber(p.approvedAt)
    || typeof scope !== 'object' || scope === null
    || !isString((scope as Record<string, unknown>).claim)
    || !isEvidenceRoot((scope as Record<string, unknown>).evidenceRoot)
    || typeof p.decision !== 'string' || !DECISIONS.has(p.decision)
  ) return undefined
  return {
    kind: 'attest/human',
    claimId: p.claimId,
    gen: p.gen,
    approver: p.approver,
    approvedAt: p.approvedAt,
    scope: {
      claim: (scope as Record<string, unknown>).claim as string,
      evidenceRoot: (scope as Record<string, unknown>).evidenceRoot as string | null,
    },
    decision: p.decision as HumanAttestation['decision'],
  }
}

function isEvidenceRoot(v: unknown): v is string | null {
  return v === null || typeof v === 'string'
}
