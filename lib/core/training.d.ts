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
 * - **Causal purity is session-level — and never silent.** Under
 *   `provenanceFilter: 'agent-only'`, a single changed path attributed
 *   `external` voids the whole session's verification labels: reward 1.0
 *   asserts "the agent's edit kept the suite green", and that sentence is
 *   false when a human was also editing the workspace. Flip-pairs survive
 *   the void — pass-then-fail within one chain is a temporal fact about the
 *   check whatever hand moved the files. Better an empty dataset than a
 *   mislabeled one.
 *   The filter can only fire on attribution it can SEE (H-13): when a
 *   changed path's attribution cannot be decided — no provenance map, a path
 *   missing from it, or an `unknown` label (uncertain, not external) — the
 *   session is NOT silently kept as if the filter had held. Verification
 *   samples still ride out (information preserved), each carrying
 *   `provenanceDegraded: true`, while the manifest declares
 *   `provenanceUnresolved` and counts `unknownAttributed`. A manifest that
 *   says `agent-only` now means the filter *executed*, or says why it could
 *   not. An empty change set is pure by vacuity: no edits, no hidden hand.
 * - **Repeats are not supervision.** A green workspace can re-run `verify`
 *   forever; each re-run used to mint a fresh reward-1.0 sample with a fresh
 *   timestamp (H-14). Distillation now folds homomorphic re-runs: a second
 *   record with the same `(checkId, status, outputDigest)` mints nothing
 *   (the first observation stands) and the manifest counts
 *   `dedupedCount`. The flywheel's "ground truth nobody labeled" must not
 *   be self-dilutable by a shell loop.
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
import type { CheckVerdict, Evidence } from './evidence.ts';
export declare const TRAINING_SCHEMA: "dsh-training/1";
/**
 * Privacy tier of an export. `full` carries (truncated) output text;
 * `private` carries zero output characters — only structure, labels and
 * digests.
 */
export type SampleFidelity = 'full' | 'private';
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
export declare const VERDICT_REWARD: Readonly<Record<CheckVerdict, number>>;
/** One decisive observation as an RL-shaped sample: context + verdict + reward. */
export interface VerificationSample {
    readonly kind: 'verification';
    readonly checkId: string;
    readonly checkKind: string;
    /** Which discovery source minted the check; `'unknown'` on pre-ο records that carry none. */
    readonly source: string;
    /** The session's change set, passed through verbatim (order preserved). */
    readonly changedPaths: readonly string[];
    readonly verdict: CheckVerdict;
    /** The record's own status — always `'pass' | 'fail'` here (decisive-only filter). */
    readonly status: string;
    /**
     * The record's measured duration; `null` when the record's `durationMs`
     * was not a finite number (a forged `1e999` off the chain, a corrupt
     * ledger read) — unmeasured, and folded to the SAME canonical null the
     * content address would have folded Infinity into anyway (H-28's fold
     * meets its new consumer one layer early, so the sample says what it
     * means instead of two different-looking inputs sharing one address).
     */
    readonly durationMs: number | null;
    readonly reward: number;
    /** Present only under `full` fidelity: the record's excerpt, truncated to 200 characters. */
    readonly outputExcerpt?: string;
    readonly outputDigest: string;
    readonly recordedAt: string;
    /**
     * Present only when `agent-only` was requested but the change set's
     * attribution could not be decided (H-13): the reward still rides out —
     * with the causal claim it stands on visibly downgraded, never silently
     * kept as if the filter had held. A dataset consumer discounts (or drops)
     * flagged samples; the flywheel does not get to pretend it filtered.
     */
    readonly provenanceDegraded?: true;
}
/** The rejected half of a flip-pair — the failing observation. Always `fail`. */
export interface RejectedSide {
    readonly status: 'fail';
    readonly outputExcerpt?: string;
    readonly outputDigest: string;
    readonly recordedAt: string;
}
/** The chosen half of a flip-pair — the passing observation. Always `pass`. */
export interface ChosenSide {
    readonly status: 'pass';
    readonly outputExcerpt?: string;
    readonly outputDigest: string;
    readonly recordedAt: string;
}
/**
 * One adjacent pass↔fail disagreement in a check's decisive subsequence, in
 * DPO's fixed direction: `rejected` is always the fail, `chosen` always the
 * pass. Which side came first in time is carried by the two `recordedAt`
 * stamps, never by the pair's direction.
 */
export interface FlipPairSample {
    readonly kind: 'flip-pair';
    readonly checkId: string;
    readonly checkKind: string;
    readonly rejected: RejectedSide;
    readonly chosen: ChosenSide;
    /** Always absent: a preference pair carries no scalar — the DPO loss is the signal. */
    readonly reward?: undefined;
}
export type TrainingSample = VerificationSample | FlipPairSample;
/**
 * The dataset's self-description. `rewardTable` is a *snapshot* of
 * `VERDICT_REWARD` (not a reference), so a dataset always states the law its
 * numbers were minted under even if the law later changes; `root` is
 * `merkleRoot(sampleHashes)` — order-independent, recomputable by anyone
 * holding the samples.
 */
export interface TrainingManifest {
    readonly schema: typeof TRAINING_SCHEMA;
    readonly fidelity: SampleFidelity;
    readonly workspaceKey: string;
    readonly generatedAt: string;
    readonly counts: {
        readonly verification: number;
        readonly 'flip-pair': number;
    };
    readonly rewardTable: typeof VERDICT_REWARD;
    /** The deployer's terms for the exported dataset, stated on the dataset itself. */
    readonly license?: string;
    /** Which filter was applied — recorded honestly even (especially) when it emptied the dataset. */
    readonly provenanceFilter: ProvenanceFilter;
    /**
     * H-13: present exactly when `agent-only` was requested but the change
     * set's attribution could not be decided (no provenance map, or changed
     * paths missing from it). Verification samples were still minted — each
     * flagged `provenanceDegraded` — instead of silently kept as if the
     * filter had held. Absent means the requested filter either executed or
     * had nothing to decide.
     */
    readonly provenanceUnresolved?: true;
    /**
     * H-13: changed paths whose recorded attribution is `unknown` (the
     * attributor could not tell agent from external) under `agent-only`. Not
     * voided like `external` — the label IS uncertainty, not an external
     * verdict — and not silently passed either: every verification sample
     * carries the degraded flag and this count says why. Absent when zero.
     */
    readonly unknownAttributed?: number;
    /**
     * H-14: homomorphic re-runs folded away — verification records repeating
     * an already-sampled `(checkId, status, outputDigest)` (and byte-identical
     * flip-pairs) minted nothing; the first observation stands. Always
     * present: `0` is the statement "nothing folded", not "nobody counted".
     */
    readonly dedupedCount: number;
    /**
     * M3: decisive records EXCLUDED because their `baselineVerdicts` entry was
     * not a self-comparison encoding (`still-passing` / `still-failing` /
     * `indeterminate`) — an undecodable differential is excluded and counted,
     * never decoded into a weaker label. Always present.
     */
    readonly excludedUnverifiable: number;
    /**
     * checkIds whose records disagree on `kind` (the check was reconfigured
     * mid-log): pairs still carry the first-seen kind, and this counter makes
     * the drift visible instead of assuming one kind per checkId. Always
     * present.
     */
    readonly checkKindDrift: number;
    /**
     * Decisive records whose `durationMs` was not finite: the sample carries
     * `durationMs: null` (unmeasured) — one canonical null, never an Infinity
     * the content address would fold to that same null anyway. Always present.
     */
    readonly unmeasuredDuration: number;
    readonly root: string;
}
/** Path attribution labels — the same vocabulary as `core/changeset`'s `ChangeProvenance`. */
export type ProvenanceLabel = 'agent' | 'external' | 'explicit' | 'unknown';
export type ProvenanceFilter = 'agent-only' | 'all';
export interface DistillInput {
    /** Evidence records in chain order; adjacency for flip-pairs follows this order per check. */
    readonly records: readonly Evidence[];
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
     * (`fixed`, `regression`, `new-failure`, `new-check`, `not-run`) means the
     * caller encoded a DIFFERENTIAL instead of the self-comparison the
     * contract specifies: such records are EXCLUDED from the dataset and
     * counted in `excludedUnverifiable` (M3) — the defensive direction is
     * "exclude, never relabel", not "decode into a weaker label".
     */
    readonly baselineVerdicts: ReadonlyMap<string, CheckVerdict>;
    /** The session's change set; passed through verbatim onto verification samples. */
    readonly changedPaths: readonly string[];
    readonly workspaceKey: string;
    readonly fidelity: SampleFidelity;
    /**
     * Path → attribution; consulted only under `provenanceFilter:
     * 'agent-only'`. `external` voids the session's verification labels;
     * `unknown` and paths with NO entry (or no map at all) degrade them — see
     * `provenanceUnresolved` / `unknownAttributed` on the manifest. An absent
     * map under a non-empty change set is the deployed engine's default shape
     * today (its markers record the attribution method, not a per-path map),
     * which is exactly why the degradation is declared rather than assumed
     * pure.
     */
    readonly provenance?: ReadonlyMap<string, ProvenanceLabel>;
    /** Default `'all'`. Under `'agent-only'`, an `external` path in `changedPaths` voids all verification labels. */
    readonly provenanceFilter?: ProvenanceFilter;
    readonly generatedAt: string;
    readonly license?: string;
}
export interface TrainingSet {
    readonly manifest: TrainingManifest;
    readonly samples: readonly TrainingSample[];
}
/**
 * Content address of one sample: `sha256(canonicalJson(sample))[:16]` — the
 * leaves of `manifest.root`'s Merkle tree. 64 bits per leaf is collision-safe
 * at dataset scale (the root commits to the whole multiset), and keeps the
 * exported per-sample ids short enough to eyeball.
 */
export declare function sampleHash(sample: TrainingSample): string;
/**
 * Distill one session's evidence into a labeled, content-addressed dataset.
 *
 * - One `verification` sample per decisive record whose verdict is not
 *   `indeterminate` (decisive run, undecided baseline → excluded, not
 *   mislabeled — see the module doc), unless the provenance filter voided
 *   the session. A baselineVerdicts entry that is not a self-comparison
 *   encoding excludes its records too (counted, never relabeled — M3).
 * - One `flip-pair` per adjacent disagreement in each check's decisive
 *   subsequence (bayes.ts pairing semantics: `error`/`timeout`/`aborted`/
 *   `skipped` records neither break adjacency nor mint a pair).
 * - Homomorphic re-runs fold (H-14): a verification record repeating an
 *   already-sampled `(checkId, status, outputDigest)` mints nothing, and
 *   `dedupedCount` on the manifest says how many folded.
 * - Empty input is a legal dataset: zero counts and `root = sha256('')`.
 */
export declare function distillTrainingSet(input: DistillInput): TrainingSet;
//# sourceMappingURL=training.d.ts.map