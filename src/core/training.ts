/**
 * The training-data flywheel — the evidence log distilled into labeled data.
 *
 * Every other module in this core exists so that "done" can be proven. This
 * one exists so that proving it teaches the next model something. The
 * evidence log is, among other things, a chronicle of agent behaviour with
 * machine-verified outcomes attached: every record says what ran, what it
 * printed, how long it took, and — read against the baseline — what that run
 * *meant* (`still-passing`, `regression`, `fixed`, ...). Those labels are not
 * the model's opinion of itself; they are differential facts under
 * hash-chain protection. Distilled into a dataset they become RL/DPO
 * training pairs whose labels no annotator graded and no model self-reported
 * — the ground truth an agent-behaviour dataset normally spends a human
 * label budget to approximate, available here as a by-product of doing the
 * work honestly.
 *
 * Two sample kinds ride in one schema:
 *
 * - `verification` — one per decisive observation: the context (check,
 *   changed paths) and the scalar `reward` its verdict earns under
 *   `VERDICT_REWARD`. RL-shaped.
 * - `flip-pair` — one per adjacent disagreement in a check's decisive
 *   subsequence: `{rejected: fail, chosen: pass}` in DPO's fixed direction.
 *   Which way the flip ran in time is not lost — it lives in the two
 *   `recordedAt` stamps — but the preference statement itself never points
 *   anywhere but away from red.
 *
 * Honesty rules this module will not trade away:
 *
 * - **Unknown is not zero.** A decisive run whose baseline produced no
 *   decisive answer mints an `indeterminate` verdict; such records are
 *   EXCLUDED from the dataset rather than labeled reward 0 — a real pass
 *   punished like a regression is worse data than no data. (The table still
 *   carries `indeterminate: 0` so `Record<CheckVerdict, number>` is
 *   exhaustive and a manifest snapshot never meets a missing key.)
 * - **Causal purity is session-level.** Under `provenanceFilter:
 *   'agent-only'`, a single changed path attributed `external` voids the
 *   whole session's verification labels: reward 1.0 asserts "the agent's
 *   edit kept the suite green", and that sentence is false when a human was
 *   also editing the workspace. Flip-pairs survive the void — pass-then-fail
 *   within one chain is a temporal fact about the check whatever hand moved
 *   the files. Better an empty dataset than a mislabeled one.
 * - **`private` fidelity leaks no text.** Output prose can carry secrets;
 *   digests cannot (they are one-way content addresses). A `private` export
 *   carries zero output characters — structure, labels and digests only —
 *   so a dataset can leave the machine before anyone has read every line of
 *   it. Any fidelity value other than `full` degrades the same way: the
 *   failure direction is silence, never leakage.
 *
 * The dataset is self-describing and self-addressing: the manifest snapshots
 * the reward table it was minted under (a number without its minting law is
 * unlabeled data), and `root` is the order-independent Merkle root over the
 * samples' content addresses — the same discipline as a baseline's root, so
 * two exports can be compared without trusting either exporter.
 *
 * Determinism: no clocks (`generatedAt` arrives as input), no randomness,
 * output sorted by `(recordedAt, checkId, kind)` with total tiebreakers, and
 * every hash runs over `canonicalJson`. Same input, same bytes, every time.
 *
 * This module is pure domain: `node:crypto` only via `core/hash.ts`, types
 * only from `core/evidence.ts`. It never re-derives a baseline differential —
 * the caller passes baseline verdicts computed with `core/evidence`'s own
 * `verdictOf` (see `DistillInput.baselineVerdicts`); this module only
 * re-expresses the decisive arm of that lattice over the caller's encodings.
 *
 * @module dsh-proof/core/training
 */

import type { CheckVerdict, Evidence } from './evidence.ts'
import { canonicalJson, merkleRoot, sha256 } from './hash.ts'

// ---------------------------------------------------------------------------
// Schema, reward law, sample shapes
// ---------------------------------------------------------------------------

export const TRAINING_SCHEMA = 'dsh-training/1' as const

/**
 * Privacy tier of an export. `full` carries (truncated) output text;
 * `private` carries zero output characters — only structure, labels and
 * digests.
 */
export type SampleFidelity = 'full' | 'private'

/**
 * The reward law — what each verdict is worth as an RL label.
 *
 * - Credit (`still-passing`, `fixed`): 1.0 — the session's work left the
 *   assertion holding, from a baseline that could certify either direction.
 * - Blame (`regression`, `new-failure`): 0.0 — the session broke what held,
 *   or shipped a check that never held.
 * - Neutral (`new-check`, `still-failing`): 0.5 — a pass with no baseline to
 *   compare against, or a failure that predates the session (pre-existing is
 *   not the agent's fault; charging it 0 would be as dishonest as crediting
 *   it 1).
 * - `not-run` / `indeterminate`: 0.0 — unreachable in samples by
 *   construction (no record ran / the record is excluded, see the module
 *   doc); present only so the table is exhaustive law.
 *
 * Pinned by tests, snapshotted into every manifest, and deliberately NOT a
 * knob: a reward table that varies per export is a dataset whose labels
 * cannot be compared.
 */
export const VERDICT_REWARD: Readonly<Record<CheckVerdict, number>> = {
  'still-passing': 1,
  'fixed': 1,
  'regression': 0,
  'new-failure': 0,
  'new-check': 0.5,
  'still-failing': 0.5,
  'not-run': 0,
  'indeterminate': 0,
}

/** Excerpt budget for `full`-fidelity output text: 200 characters. */
const EXCERPT_CHARS = 200

/** One decisive observation as an RL-shaped sample: context + verdict + reward. */
export interface VerificationSample {
  readonly kind: 'verification'
  readonly checkId: string
  readonly checkKind: string
  /** Which discovery source minted the check; `'unknown'` on pre-ο records that carry none. */
  readonly source: string
  /** The session's change set, passed through verbatim (order preserved). */
  readonly changedPaths: readonly string[]
  readonly verdict: CheckVerdict
  /** The record's own status — always `'pass' | 'fail'` here (decisive-only filter). */
  readonly status: string
  readonly durationMs: number
  readonly reward: number
  /** Present only under `full` fidelity: the record's excerpt, truncated to 200 characters. */
  readonly outputExcerpt?: string
  readonly outputDigest: string
  readonly recordedAt: string
}

/** The rejected half of a flip-pair — the failing observation. Always `fail`. */
export interface RejectedSide {
  readonly status: 'fail'
  readonly outputExcerpt?: string
  readonly outputDigest: string
  readonly recordedAt: string
}

/** The chosen half of a flip-pair — the passing observation. Always `pass`. */
export interface ChosenSide {
  readonly status: 'pass'
  readonly outputExcerpt?: string
  readonly outputDigest: string
  readonly recordedAt: string
}

/**
 * One adjacent pass↔fail disagreement in a check's decisive subsequence, in
 * DPO's fixed direction: `rejected` is always the fail, `chosen` always the
 * pass. Which side came first in time is carried by the two `recordedAt`
 * stamps, never by the pair's direction.
 */
export interface FlipPairSample {
  readonly kind: 'flip-pair'
  readonly checkId: string
  readonly checkKind: string
  readonly rejected: RejectedSide
  readonly chosen: ChosenSide
  /** Always absent: a preference pair carries no scalar — the DPO loss is the signal. */
  readonly reward?: undefined
}

export type TrainingSample = VerificationSample | FlipPairSample

/**
 * The dataset's self-description. `rewardTable` is a *snapshot* of
 * `VERDICT_REWARD` (not a reference), so a dataset always states the law its
 * numbers were minted under even if the law later changes; `root` is
 * `merkleRoot(sampleHashes)` — order-independent, recomputable by anyone
 * holding the samples.
 */
export interface TrainingManifest {
  readonly schema: typeof TRAINING_SCHEMA
  readonly fidelity: SampleFidelity
  readonly workspaceKey: string
  readonly generatedAt: string
  readonly counts: { readonly verification: number; readonly 'flip-pair': number }
  readonly rewardTable: typeof VERDICT_REWARD
  /** The deployer's terms for the exported dataset, stated on the dataset itself. */
  readonly license?: string
  /** Which filter was applied — recorded honestly even (especially) when it emptied the dataset. */
  readonly provenanceFilter: ProvenanceFilter
  readonly root: string
}

// ---------------------------------------------------------------------------
// Distillation input
// ---------------------------------------------------------------------------

/** Path attribution labels — the same vocabulary as `core/changeset`'s `ChangeProvenance`. */
export type ProvenanceLabel = 'agent' | 'external' | 'explicit' | 'unknown'

export type ProvenanceFilter = 'agent-only' | 'all'

export interface DistillInput {
  /** Evidence records in chain order; adjacency for flip-pairs follows this order per check. */
  readonly records: readonly Evidence[]
  /**
   * Baseline-side verdicts per checkId, computed by the CALLER with
   * `core/evidence`'s own `verdictOf` — this module never re-derives a
   * differential from Evidence pairs. The intended construction is a
   * self-comparison, `verdictOf(baselineRecord, baselineRecord)`, which
   * encodes exactly the three facts the decisive arm needs:
   *
   * - `'still-passing'`   ⇔ the baseline check passed,
   * - `'still-failing'`   ⇔ the baseline check failed,
   * - `'indeterminate'`   ⇔ the baseline ran but produced no decisive answer,
   *
   * and an absent entry ⇔ no baseline record for the check. Any other value
   * is treated as "no usable baseline" — the defensive default, never an
   * invented comparison.
   */
  readonly baselineVerdicts: ReadonlyMap<string, CheckVerdict>
  /** The session's change set; passed through verbatim onto verification samples. */
  readonly changedPaths: readonly string[]
  readonly workspaceKey: string
  readonly fidelity: SampleFidelity
  /** Path → attribution; consulted only under `provenanceFilter: 'agent-only'`. */
  readonly provenance?: ReadonlyMap<string, ProvenanceLabel>
  /** Default `'all'`. Under `'agent-only'`, an `external` path in `changedPaths` voids all verification labels. */
  readonly provenanceFilter?: ProvenanceFilter
  readonly generatedAt: string
  readonly license?: string
}

export interface TrainingSet {
  readonly manifest: TrainingManifest
  readonly samples: readonly TrainingSample[]
}

// ---------------------------------------------------------------------------
// Content addressing
// ---------------------------------------------------------------------------

/**
 * Content address of one sample: `sha256(canonicalJson(sample))[:16]` — the
 * leaves of `manifest.root`'s Merkle tree. 64 bits per leaf is collision-safe
 * at dataset scale (the root commits to the whole multiset), and keeps the
 * exported per-sample ids short enough to eyeball.
 */
export function sampleHash(sample: TrainingSample): string {
  return sha256(canonicalJson(sample)).slice(0, 16)
}

// ---------------------------------------------------------------------------
// The decisive arm of the verdict lattice, over caller-supplied encodings
// ---------------------------------------------------------------------------

/**
 * What `baselineVerdicts.get(checkId)` says about the baseline side, decoded.
 * Only the three self-comparison verdicts carry a usable answer; everything
 * else (including an absent entry) means "no baseline this record can be
 * diffed against".
 */
const BASELINE_ANSWER_OF: Readonly<Record<CheckVerdict, 'pass' | 'fail' | 'no-answer' | 'none'>> = {
  'still-passing': 'pass',
  'still-failing': 'fail',
  indeterminate: 'no-answer',
  regression: 'none',
  fixed: 'none',
  'new-failure': 'none',
  'new-check': 'none',
  'not-run': 'none',
}

/**
 * Verdict of one decisive observation against the caller's baseline encoding.
 * This is the decisive arm of `core/evidence`'s `verdictOf` lattice — same
 * truth table, re-keyed off `CheckVerdict` inputs because the caller already
 * paid for the differential. `status` is always decisive here; the
 * non-decisive arms of `verdictOf` are structurally unreachable and the
 * `no-answer` arm yields `indeterminate`, which the sample filter excludes.
 */
function verdictFor(baseline: CheckVerdict | undefined, status: 'pass' | 'fail'): CheckVerdict {
  switch (BASELINE_ANSWER_OF[baseline ?? 'new-check']) {
    case 'pass': return status === 'pass' ? 'still-passing' : 'regression'
    case 'fail': return status === 'pass' ? 'fixed' : 'still-failing'
    case 'no-answer': return 'indeterminate'
    default: return status === 'pass' ? 'new-check' : 'new-failure'
  }
}

/** A record whose status settles the check's question; only these become samples. */
type DecisiveObservation = Evidence & { readonly status: 'pass' | 'fail' }

function asDecisive(record: Evidence): DecisiveObservation | undefined {
  return record.status === 'pass' || record.status === 'fail'
    ? (record as DecisiveObservation)
    : undefined
}

// ---------------------------------------------------------------------------
// Distillation
// ---------------------------------------------------------------------------

function excerptOf(head: string): string {
  return head.length > EXCERPT_CHARS ? head.slice(0, EXCERPT_CHARS) : head
}

function rejectedSide(record: DecisiveObservation, fidelity: SampleFidelity): RejectedSide {
  return {
    status: 'fail',
    outputDigest: record.outputDigest,
    recordedAt: record.recordedAt,
    ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
  }
}

function chosenSide(record: DecisiveObservation, fidelity: SampleFidelity): ChosenSide {
  return {
    status: 'pass',
    outputDigest: record.outputDigest,
    recordedAt: record.recordedAt,
    ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
  }
}

/**
 * Total order over samples: `(recordedAt, checkId, kind)`, then kind-specific
 * tiebreakers (status/digest/duration for verifications; the rejected side's
 * stamp and digests for pairs) so the order is total, not merely stable —
 * the same multiset of samples serialises to the same bytes whatever order
 * the log handed them over in. A flip-pair sorts by its *chosen* side's
 * stamp: the moment the pair's good outcome was observed.
 */
function compareSamples(a: TrainingSample, b: TrainingSample): number {
  const ka = sortKeyOf(a)
  const kb = sortKeyOf(b)
  for (let i = 0; i < ka.length; i += 1) {
    const x = ka[i] as string
    const y = kb[i] as string
    if (x < y) return -1
    if (x > y) return 1
  }
  return 0
}

function sortKeyOf(sample: TrainingSample): readonly string[] {
  return sample.kind === 'verification'
    ? [sample.recordedAt, sample.checkId, sample.kind, sample.status, sample.outputDigest, String(sample.durationMs)]
    : [sample.chosen.recordedAt, sample.checkId, sample.kind, sample.rejected.recordedAt, sample.rejected.outputDigest, sample.chosen.outputDigest]
}

/**
 * Distill one session's evidence into a labeled, content-addressed dataset.
 *
 * - One `verification` sample per decisive record whose verdict is not
 *   `indeterminate` (decisive run, undecided baseline → excluded, not
 *   mislabeled — see the module doc), unless the provenance filter voided
 *   the session.
 * - One `flip-pair` per adjacent disagreement in each check's decisive
 *   subsequence (bayes.ts pairing semantics: `error`/`timeout`/`aborted`/
 *   `skipped` records neither break adjacency nor mint a pair).
 * - Empty input is a legal dataset: zero counts and `root = sha256('')`.
 */
export function distillTrainingSet(input: DistillInput): TrainingSet {
  const fidelity = input.fidelity
  const provenanceFilter: ProvenanceFilter = input.provenanceFilter ?? 'all'
  // Session-level causal purity. Under 'agent-only', ONE externally-attributed
  // path in the change set voids EVERY verification label this session could
  // mint — "the agent kept the suite green" is a causal claim about the
  // agent's edits alone. Flip-pairs are temporal facts about the check and
  // are voided by nothing here.
  const causallyPure = provenanceFilter !== 'agent-only'
    || !input.changedPaths.some(path => input.provenance?.get(path) === 'external')

  const changedPaths = [...input.changedPaths]
  const verifications: TrainingSample[] = []

  if (causallyPure) {
    for (const record of input.records) {
      const decisive = asDecisive(record)
      if (decisive === undefined) continue // ran, but no conclusion — not sample material
      const verdict = verdictFor(input.baselineVerdicts.get(record.checkId), decisive.status)
      if (verdict === 'indeterminate') continue // honest unknown — excluded, never labeled 0
      verifications.push({
        kind: 'verification',
        checkId: record.checkId,
        checkKind: record.kind,
        source: record.source ?? 'unknown',
        changedPaths,
        verdict,
        status: decisive.status,
        durationMs: record.durationMs,
        reward: VERDICT_REWARD[verdict],
        ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
        outputDigest: record.outputDigest,
        recordedAt: record.recordedAt,
      })
    }
  }

  // Per-check decisive subsequences, in chain order (the given order), for
  // flip pairing. The kind is the check's first-seen record's kind — records
  // of one checkId agree on it in every real log.
  const groups = new Map<string, { kind: Evidence['kind']; decisive: DecisiveObservation[] }>()
  for (const record of input.records) {
    let group = groups.get(record.checkId)
    if (group === undefined) {
      group = { kind: record.kind, decisive: [] }
      groups.set(record.checkId, group)
    }
    const decisive = asDecisive(record)
    if (decisive !== undefined) group.decisive.push(decisive)
  }

  const flipPairs: TrainingSample[] = []
  for (const checkId of [...groups.keys()].sort()) {
    const group = groups.get(checkId)
    if (group === undefined) continue
    for (let i = 1; i < group.decisive.length; i += 1) {
      const previous = group.decisive[i - 1] as DecisiveObservation
      const current = group.decisive[i] as DecisiveObservation
      if (previous.status === current.status) continue
      const failSide = previous.status === 'fail' ? previous : current
      const passSide = previous.status === 'fail' ? current : previous
      flipPairs.push({
        kind: 'flip-pair',
        checkId,
        checkKind: group.kind,
        rejected: rejectedSide(failSide, fidelity),
        chosen: chosenSide(passSide, fidelity),
      })
    }
  }

  const samples: TrainingSample[] = [...verifications, ...flipPairs].sort(compareSamples)
  const manifest: TrainingManifest = {
    schema: TRAINING_SCHEMA,
    fidelity,
    workspaceKey: input.workspaceKey,
    generatedAt: input.generatedAt,
    counts: { verification: verifications.length, 'flip-pair': flipPairs.length },
    // Snapshot, not reference: the manifest states the law as it stood when
    // the dataset was minted, and mutating a manifest cannot rewrite it.
    rewardTable: { ...VERDICT_REWARD },
    ...(input.license !== undefined ? { license: input.license } : {}),
    // Recorded honestly even when the filter emptied the dataset: an honest
    // zero is part of the data, not an embarrassment to hide.
    provenanceFilter,
    root: merkleRoot(samples.map(sampleHash)),
  }
  return { manifest, samples }
}
