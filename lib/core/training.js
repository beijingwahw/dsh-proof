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
import { canonicalJson, merkleRoot, sha256 } from "./hash.js";
// ---------------------------------------------------------------------------
// Schema, reward law, sample shapes
// ---------------------------------------------------------------------------
export const TRAINING_SCHEMA = 'dsh-training/1';
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
export const VERDICT_REWARD = {
    'still-passing': 1,
    'fixed': 1,
    'regression': 0,
    'new-failure': 0,
    'new-check': 0.5,
    'still-failing': 0.5,
    'not-run': 0,
    'indeterminate': 0,
};
/** Excerpt budget for `full`-fidelity output text: 200 characters. */
const EXCERPT_CHARS = 200;
// ---------------------------------------------------------------------------
// Content addressing
// ---------------------------------------------------------------------------
/**
 * Content address of one sample: `sha256(canonicalJson(sample))[:16]` — the
 * leaves of `manifest.root`'s Merkle tree. 64 bits per leaf is collision-safe
 * at dataset scale (the root commits to the whole multiset), and keeps the
 * exported per-sample ids short enough to eyeball.
 */
export function sampleHash(sample) {
    return sha256(canonicalJson(sample)).slice(0, 16);
}
// ---------------------------------------------------------------------------
// The decisive arm of the verdict lattice, over caller-supplied encodings
// ---------------------------------------------------------------------------
/**
 * What `baselineVerdicts.get(checkId)` says about the baseline side, decoded.
 * Only the three self-comparison verdicts carry a usable answer;
 * `regression`/`fixed`/`new-failure`/`new-check`/`not-run` mean the caller
 * encoded a DIFFERENTIAL instead of the specified self-comparison — the
 * distillery EXCLUDES those records and counts them (`excludedUnverifiable`,
 * M3) before `verdictFor` ever runs. An absent entry is a different fact —
 * no baseline record exists — and honestly mints `new-check`/`new-failure`.
 */
const BASELINE_ANSWER_OF = {
    'still-passing': 'pass',
    'still-failing': 'fail',
    indeterminate: 'no-answer',
    regression: 'none',
    fixed: 'none',
    'new-failure': 'none',
    'new-check': 'none',
    'not-run': 'none',
};
/**
 * Verdict of one decisive observation against the caller's baseline encoding.
 * This is the decisive arm of `core/evidence`'s `verdictOf` lattice — same
 * truth table, re-keyed off `CheckVerdict` inputs because the caller already
 * paid for the differential. `status` is always decisive here; the
 * non-decisive arms of `verdictOf` are structurally unreachable and the
 * `no-answer` arm yields `indeterminate`, which the sample filter excludes.
 * The `none` arm is reachable only for an ABSENT entry (a brand-new check) —
 * non-self-comparison values are excluded by the distillery before this
 * function runs (M3), so no mis-encoded differential is ever decoded.
 */
function verdictFor(baseline, status) {
    switch (BASELINE_ANSWER_OF[baseline ?? 'new-check']) {
        case 'pass': return status === 'pass' ? 'still-passing' : 'regression';
        case 'fail': return status === 'pass' ? 'fixed' : 'still-failing';
        case 'no-answer': return 'indeterminate';
        default: return status === 'pass' ? 'new-check' : 'new-failure';
    }
}
function asDecisive(record) {
    return record.status === 'pass' || record.status === 'fail'
        ? record
        : undefined;
}
// ---------------------------------------------------------------------------
// Distillation
// ---------------------------------------------------------------------------
/**
 * Absolute-path roots this module redacts from `full` excerpts (A4-L3): the
 * evidence layer folds the two roots it knows (`$WORKSPACE`, `$HOME`) before
 * the record is ever addressed, but `full` excerpts still carried every
 * OTHER absolute root verbatim — another drive, another user's home,
 * `/etc`, a UNC share. Here such a root is replaced by the `$ABSPATH`
 * placeholder; the basename survives (it is usually the diagnostic), the
 * location does not. Relative paths ride out untouched — they ARE the
 * workspace context the sample exists to carry.
 *
 * Shape: a Windows drive root (`C:\` / `C:/`), a UNC double backslash, or a
 * POSIX leading slash — each only at a token boundary (not glued to a word,
 * digit, slash or colon, so `t/one`, timestamps and `https://` URLs do not
 * match), consuming to the first whitespace, quote or common prose
 * delimiter.
 */
const ABSOLUTE_ROOT = /(?<![A-Za-z0-9_$@.\\\/:])(?:[A-Za-z]:[\\/]|\\{2}|\/)[^\s'"`;,()<>]*/g;
/** Replace one matched absolute root with its placeholder form. */
function redactAbsoluteRoot(token) {
    const cut = Math.max(token.lastIndexOf('/'), token.lastIndexOf('\\'));
    const base = cut >= 0 ? token.slice(cut + 1) : token;
    return base.length > 0 ? `$ABSPATH/${base}` : '$ABSPATH';
}
function excerptOf(head) {
    const redacted = head.replace(ABSOLUTE_ROOT, redactAbsoluteRoot);
    return redacted.length > EXCERPT_CHARS ? redacted.slice(0, EXCERPT_CHARS) : redacted;
}
function rejectedSide(record, fidelity) {
    return {
        status: 'fail',
        outputDigest: record.outputDigest,
        recordedAt: record.recordedAt,
        ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
    };
}
function chosenSide(record, fidelity) {
    return {
        status: 'pass',
        outputDigest: record.outputDigest,
        recordedAt: record.recordedAt,
        ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
    };
}
/**
 * Total order over samples: `(recordedAt, checkId, kind)`, then kind-specific
 * tiebreakers (status/digest/duration for verifications; the rejected side's
 * stamp and digests for pairs) so the order is total, not merely stable —
 * the same multiset of samples serialises to the same bytes whatever order
 * the log handed them over in. A flip-pair sorts by its *chosen* side's
 * stamp: the moment the pair's good outcome was observed.
 */
function compareSamples(a, b) {
    const ka = sortKeyOf(a);
    const kb = sortKeyOf(b);
    for (let i = 0; i < ka.length; i += 1) {
        const x = ka[i];
        const y = kb[i];
        if (x < y)
            return -1;
        if (x > y)
            return 1;
    }
    return 0;
}
function sortKeyOf(sample) {
    return sample.kind === 'verification'
        ? [sample.recordedAt, sample.checkId, sample.kind, sample.status, sample.outputDigest, String(sample.durationMs)]
        : [sample.chosen.recordedAt, sample.checkId, sample.kind, sample.rejected.recordedAt, sample.rejected.outputDigest, sample.chosen.outputDigest];
}
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
export function distillTrainingSet(input) {
    const fidelity = input.fidelity;
    const provenanceFilter = input.provenanceFilter ?? 'all';
    // Session-level causal purity — with the H-13 honesty gates. Under
    // 'agent-only', ONE externally-attributed path in the change set voids
    // EVERY verification label this session could mint ("the agent kept the
    // suite green" is a causal claim about the agent's edits alone;
    // flip-pairs are temporal facts about the check and are voided by nothing
    // here). But the filter can only fire on attribution it can SEE:
    //
    // - `external`          → resolved: the session voids;
    // - `agent` / `explicit`→ resolved: pure ('explicit' is the caller-harness's
    //                        own declared change set — declared authorship,
    //                        not an external hand);
    // - `unknown`           → degraded: uncertainty is NOT an external verdict,
    //                        but it is not agent purity either — samples ride
    //                        out flagged, and `unknownAttributed` counts them;
    // - no map / no entry   → degraded: undecidable, samples ride out flagged,
    //                        the manifest declares `provenanceUnresolved`.
    //
    // An empty change set is pure by vacuity (no edits, no hidden hand) — the
    // deployed engine's own default, which cannot invent attributions, lands
    // there rather than degrading every export it makes.
    let externalPresent = false;
    let provenanceUnresolved = false;
    let unknownAttributed = 0;
    if (provenanceFilter === 'agent-only') {
        for (const path of input.changedPaths) {
            const label = input.provenance?.get(path);
            if (label === 'external')
                externalPresent = true;
            else if (label === 'unknown')
                unknownAttributed += 1;
            else if (label !== 'agent' && label !== 'explicit')
                provenanceUnresolved = true;
        }
    }
    const causallyPure = !externalPresent;
    const provenanceDegraded = !externalPresent && (provenanceUnresolved || unknownAttributed > 0);
    const changedPaths = [...input.changedPaths];
    const verifications = [];
    let excludedUnverifiable = 0;
    let unmeasuredDuration = 0;
    if (causallyPure) {
        for (const record of input.records) {
            const decisive = asDecisive(record);
            if (decisive === undefined)
                continue; // ran, but no conclusion — not sample material
            // M3: a baselineVerdicts entry that is not a self-comparison encoding
            // carries a differential this module never paid for — exclude and
            // count, never decode it into a weaker label.
            const baseline = input.baselineVerdicts.get(record.checkId);
            if (baseline !== undefined && BASELINE_ANSWER_OF[baseline] === 'none') {
                excludedUnverifiable += 1;
                continue;
            }
            const verdict = verdictFor(baseline, decisive.status);
            if (verdict === 'indeterminate')
                continue; // honest unknown — excluded, never labeled 0
            // H-28 fold met one layer early: a non-finite duration becomes the
            // canonical null it would have addressed to anyway — the sample then
            // SAYS unmeasured instead of pretending two different inputs differ.
            const durationMs = Number.isFinite(record.durationMs) ? record.durationMs : null;
            if (durationMs === null)
                unmeasuredDuration += 1;
            verifications.push({
                kind: 'verification',
                checkId: record.checkId,
                checkKind: record.kind,
                source: record.source ?? 'unknown',
                changedPaths,
                verdict,
                status: decisive.status,
                durationMs,
                reward: VERDICT_REWARD[verdict],
                ...(fidelity === 'full' ? { outputExcerpt: excerptOf(record.outputHead) } : {}),
                outputDigest: record.outputDigest,
                recordedAt: record.recordedAt,
                ...(provenanceDegraded ? { provenanceDegraded: true } : {}),
            });
        }
    }
    // H-14: homomorphic re-runs fold. A green workspace can mint unlimited
    // reward-1.0 samples by re-running verify — every repeat carries a fresh
    // recordedAt, so full-sample addressing saw each as new supervision. The
    // outcome identity is (checkId, status, outputDigest): one check, one
    // verdict, one output. Repeats mint nothing; the FIRST observation stands
    // (chain order), and `dedupedCount` makes the folding auditable.
    const seenOutcome = new Set();
    const keptVerifications = [];
    let dedupedCount = 0;
    for (const sample of verifications) {
        if (sample.kind !== 'verification')
            continue; // structurally unreachable; keeps the narrowing honest
        const key = `${sample.checkId}\u0000${sample.status}\u0000${sample.outputDigest}`;
        if (seenOutcome.has(key)) {
            dedupedCount += 1;
            continue;
        }
        seenOutcome.add(key);
        keptVerifications.push(sample);
    }
    // Per-check decisive subsequences, in chain order (the given order), for
    // flip pairing. The kind is the check's first-seen record's kind; a checkId
    // whose records disagree on it is no longer assumed away — `checkKindDrift`
    // counts the drift (first-seen kind still rides the pairs).
    const groups = new Map();
    for (const record of input.records) {
        let group = groups.get(record.checkId);
        if (group === undefined) {
            group = { kind: record.kind, kindDrifted: false, decisive: [] };
            groups.set(record.checkId, group);
        }
        else if (record.kind !== group.kind) {
            group.kindDrifted = true;
        }
        const decisive = asDecisive(record);
        if (decisive !== undefined)
            group.decisive.push(decisive);
    }
    let checkKindDrift = 0;
    for (const group of groups.values()) {
        if (group.kindDrifted)
            checkKindDrift += 1;
    }
    const flipPairs = [];
    for (const checkId of [...groups.keys()].sort()) {
        const group = groups.get(checkId);
        if (group === undefined)
            continue;
        for (let i = 1; i < group.decisive.length; i += 1) {
            const previous = group.decisive[i - 1];
            const current = group.decisive[i];
            if (previous.status === current.status)
                continue;
            const failSide = previous.status === 'fail' ? previous : current;
            const passSide = previous.status === 'fail' ? current : previous;
            flipPairs.push({
                kind: 'flip-pair',
                checkId,
                checkKind: group.kind,
                rejected: rejectedSide(failSide, fidelity),
                chosen: chosenSide(passSide, fidelity),
            });
        }
    }
    // Byte-identical pairs (a duplicated adjacent record, not a genuinely new
    // temporal observation — different stamps mean different facts and fold
    // nothing) collapse by their full content address.
    const seenPairAddress = new Set();
    const keptPairs = [];
    for (const pair of flipPairs) {
        const address = sampleHash(pair);
        if (seenPairAddress.has(address)) {
            dedupedCount += 1;
            continue;
        }
        seenPairAddress.add(address);
        keptPairs.push(pair);
    }
    const samples = [...keptVerifications, ...keptPairs].sort(compareSamples);
    const manifest = {
        schema: TRAINING_SCHEMA,
        fidelity,
        workspaceKey: input.workspaceKey,
        generatedAt: input.generatedAt,
        counts: { verification: keptVerifications.length, 'flip-pair': keptPairs.length },
        // Snapshot, not reference: the manifest states the law as it stood when
        // the dataset was minted, and mutating a manifest cannot rewrite it.
        rewardTable: { ...VERDICT_REWARD },
        ...(input.license !== undefined ? { license: input.license } : {}),
        // Recorded honestly even when the filter emptied the dataset: an honest
        // zero is part of the data, not an embarrassment to hide.
        provenanceFilter,
        // ...and so is a filter that could not execute: the degradation flags
        // ride the manifest only when verification samples actually rode out
        // under a downgraded causal claim (a voided session executed its filter
        // — there is nothing left to degrade).
        ...(provenanceDegraded && provenanceUnresolved ? { provenanceUnresolved: true } : {}),
        ...(provenanceDegraded && unknownAttributed > 0 ? { unknownAttributed } : {}),
        dedupedCount,
        excludedUnverifiable,
        checkKindDrift,
        unmeasuredDuration,
        root: merkleRoot(samples.map(sampleHash)),
    };
    return { manifest, samples };
}
//# sourceMappingURL=training.js.map