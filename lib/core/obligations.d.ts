/**
 * Proof obligations — the cross-agent responsibility DAG.
 *
 * Delegation in a multi-agent system is a handshake with no memory: a parent
 * task sends work down, a child agent reports "done", and the parent's proof
 * silently inherits a claim nobody verified. This module gives that handshake
 * a topology and a law:
 *
 * - A `TaskObligation` is minted by the delegating engine at the moment of
 *   delegation: WHAT the child must prove (the claim), for whom, when, under
 *   which parent. Its identity is the content address of the whole record
 *   (`obligationIdOf`), so rewording a claim is a new obligation, never a
 *   silent edit of an old one.
 * - A `DelegationSubmission` is what comes back: a claimed grade PLUS the
 *   artifact the parent independently re-verified (a v0.14 proof bundle,
 *   anchored by `bundleFingerprint`). Claim and artifact are kept separate
 *   on purpose: a child claiming `proven` whose artifact does not verify is
 *   not weak evidence — it is FORGERY. Forgery is booked as `regressed`
 *   (broken work, the loudest fact in the lattice) and no waiver can buy it
 *   out, the same symmetry as v0.11's endorsement rule that a backer cannot
 *   endorse broken work.
 * - `composeVerdict` / `composeTaskVerdict` fold a task's children (its whole
 *   subtree, for the recursive form) into one grade on the five-grade lattice,
 *   pessimistically: anything undecidable slides away from `proven`.
 *
 * The composition lattice, in strict priority order:
 *
 * 1. Any forged or regressed child, OR the queried task's own evidence being
 *    `regressed` → `regressed` (X-H-18). Broken work outranks everything —
 *    including missing work — and a waiver excuses missing work, never
 *    broken or forged work, in whomever's hands it sits: a task whose OWN
 *    workspace evidence regressed cannot launder that fact into a waivable
 *    `stale` by also having a child that never submitted. Monotonicity is
 *    the law being enforced: one MORE piece of bad news (a missing child)
 *    must never make the composed verdict easier to waive.
 * 2. Else any unwaived child that is MISSING work — never submitted, or
 *    submitted `stale` / `unproven` / `no-baseline` — → parent `stale`.
 *    Missing work is a process gap, not a defect: it blocks `proven` without
 *    claiming anything was broken.
 * 3. Else every child is proven or waived → the parent's grade is its OWN
 *    evidence (`ownGrade`), reported as-is even when it degrades.
 *    `ownGrade === undefined` means pure delegation — the parent did none of
 *    the work itself, so there is nothing of its own to fail → `proven`.
 * 4. No children at all → the leaf speaks through its own evidence:
 *    submission claim, engine measurement, or — with neither (X-H-07) —
 *    `unproven`. A leaf nobody proved is NOT `proven`; the old
 *    `ownGrade ?? 'proven'` fallback minted a zero-blocker `proven` out of
 *    pure absence, and absence is not discharge.
 *
 * A child that itself has children (an interior node) is composed from below:
 * its effective grade is the lattice over its own subtree, with its own
 * submission's claim as its own-grade input. A child that was issued an
 * obligation but submitted nothing is *unsubmitted* at its parent's level —
 * even with a green subtree — because the obligation's claim was never
 * proven by anyone. An obligation is discharged by a submitted bundle, by
 * the engine's own measurement of that workspace (`ownGrades`), or by a
 * waiver — never by a green subtree alone. Cross-agent proof travels in
 * bundles, not opinions.
 *
 * Determinism: same discipline as the rest of `src/core` — pure functions of
 * their arguments, no clock (timestamps are supplied by callers and hashed as
 * data), no randomness, no `node:*` imports (`sha256`/`canonicalJson` come
 * from `./hash.ts`). Composition output enters reports and markers, so the
 * same DAG must compose to the same verdict forever.
 *
 * @module dsh-proof/core/obligations
 */
import type { ProofGrade } from './evidence.ts';
/**
 * One delegated task's proof obligation, minted by the delegating engine at
 * delegation time. The record is the contract: `claim` is the proposition the
 * child workspace must prove (its bundle is the proof), `acceptance` adds
 * verifiable acceptance criteria, and `issuedByWorkspace` names the party on
 * the hook for verifying what comes back.
 */
export interface TaskObligation {
    v: 1;
    /** 'task-<n>', minted by the engine; unique within the delegation tree. */
    taskId: string;
    /** The delegating task. Absent on top-level tasks (they have no parent). */
    parentTaskId?: string;
    /** The proposition the child must prove. Rewording it mints a new id. */
    claim: string;
    /** Optional acceptance criteria supplementing the claim. */
    acceptance?: string;
    issuedAt: string;
    /** workspaceKey of the delegating party. */
    issuedByWorkspace: string;
}
/**
 * Stable 16-hex identity of an obligation: the first 16 characters of the
 * sha256 of its canonical JSON — the same shape and the same reasoning as
 * `claimIdOf` (core/attest.ts): 64 bits is collision-safe for any realistic
 * task tree while staying readable in reports. The id addresses the WHOLE
 * record, so every field — claim text, parent, timestamps, issuing workspace
 * — is bound: editing any of them is a different obligation, and a
 * re-derived id that disagrees with a recorded one is a detectable rewrite.
 */
export declare function obligationIdOf(o: TaskObligation): string;
/**
 * The engine-side anchoring identifier for a submitted bundle:
 * `sha256(manifest.files.map(f => f.sha256).sort().join('\n'))` — the merkle
 * root of the manifest's content-digest column, order-free (the same
 * construction as `merkleRoot` in core/hash.ts). The engine computes it after
 * it verifies the bundle and hands it to the `DelegationSubmission` as
 * `bundleRoot`, so the submission names the exact bytes it stands behind.
 * Exported because G2/G3 re-derive it on both sides of the delegation seam.
 */
export declare function bundleFingerprint(files: readonly {
    path: string;
    sha256: string;
}[]): string;
/**
 * What a child workspace turns in for its obligation. The two-grade structure
 * is the whole point: `claimedGrade` is testimony, `artifactVerified` is the
 * parent's own measurement of the bundle. `proven` is only accepted when the
 * artifact verified; `proven` without verification is forgery (see the
 * module lattice). Non-proven claims (`stale`, `regressed`, …) are honest
 * self-reports and are booked as missing/broken work respectively.
 */
export interface DelegationSubmission {
    childWorkspace: string;
    /**
     * The bundle's anchoring identifier: `bundleFingerprint(manifest.files)`,
     * computed by the engine after it verified the bundle. Null when the
     * submission carries no bundle at all.
     */
    bundleRoot: string | null;
    /** The grade the child asserts for its own task — a claim, not a fact. */
    claimedGrade: ProofGrade;
    /** The parent-side `verifyBundle` result (structure + chain integrity). */
    artifactVerified: boolean;
    /** When a transparency-log record accompanies the bundle and verified. */
    transparencyVerified?: boolean;
    /** Verification problems, passed through to the composed blockers verbatim. */
    problems?: readonly string[];
    /**
     * W7-8: sticky forgery memory. Set when an EARLIER submission for this
     * obligation claimed `proven` on an artifact that did not verify and a
     * re-submission arrived afterwards: the re-submission may update every
     * verdict field (last-wins, as ever), but it cannot erase the forgery from
     * the record — once `isForged` was true for this obligation it stays true,
     * the grade stays waiver-immune `regressed`, and only an explicit appeal
     * discipline (none is minted here) could ever lift it. The engine's
     * `delegationGraph` sets this while folding `delegation/verdict`
     * re-submissions via `mergeSubmission`; a first submission never carries
     * it, so every historical record composes exactly as before.
     */
    priorForgery?: true;
    submittedAt: string;
}
/** A recorded waiver: a named human accepting that work will stay missing. */
export interface ObligationWaiver {
    by: string;
    reason: string;
    at: string;
}
/** One node of the responsibility DAG: an obligation plus what came back for it. */
export interface DagNode {
    obligation: TaskObligation;
    submission?: DelegationSubmission;
    /** Waives missing work only — never forgery, never regression. */
    waiver?: ObligationWaiver;
}
/**
 * One task's grade folded from its children and its own evidence, with the
 * facts a reader needs to audit the fold. The lists are DESCRIPTIVE (what is
 * on record for each direct child); `grade` applies the lattice priority to
 * them. `blockers` are human-readable, one line per fact, in a fixed order:
 * forged, regressed, unsubmitted, below-proven, waivers, passthrough
 * problems, then the parent's own-evidence line — so two readers always see
 * the same story in the same order.
 */
export interface ComposedVerdict {
    grade: ProofGrade;
    /**
     * Whether the parent's own evidence does not degrade the verdict: true when
     * `ownGrade` was `proven`, or when the parent is a pure delegator
     * (`ownGrade === undefined` — nothing of its own to fail). False when the
     * parent's own work is below proven, whatever the children said.
     */
    own: boolean;
    /**
     * Tasks that claimed proven but whose artifact did not verify. For
     * `composeVerdict` these are the passed children; `composeTaskVerdict`
     * also adjudicates the QUERIED task's own submission, so a forged task
     * names itself here when its own verdict is composed.
     */
    forgedChildren: string[];
    /** Children whose effective grade is regressed (claimed, or composed from below). */
    regressedChildren: string[];
    /** Unwaived children missing work: unsubmitted, or stale/unproven/no-baseline. */
    unprovenChildren: string[];
    /** Every child carrying a waiver, honoured or not — waivers are visible. */
    waived: string[];
    blockers: string[];
}
/**
 * W7-8: fold a re-submission onto its predecessor — the merge the engine's
 * `delegationGraph` applies when a task's `delegation/verdict` marker
 * appears more than once. The verdict fields are last-wins (a re-submission
 * is a fresh, honest or otherwise, statement of the child's claim), but the
 * forgery flag is STICKY: once a submission for this obligation was forged,
 * every later submission composes as forged too, so submitting a clean
 * bundle over a caught forgery cannot launder the `regressed` it booked.
 * Nothing but this function mints `priorForgery`.
 */
export declare function mergeSubmission(previous: DelegationSubmission | undefined, next: DelegationSubmission): DelegationSubmission;
/**
 * W7-7 (read-side re-derivation): when a caller holds an obligation id that
 * was RECORDED alongside the obligation (the `delegation/created` /
 * `agent-team/delegated` markers can carry `obligationIdOf`'s answer), a
 * re-derived id that disagrees with it is a detectable rewrite of the
 * contract. Returns the problem line to book, or `undefined` when the
 * recorded id matches (or none was recorded).
 */
export declare function obligationRewriteProblem(recordedId: string | undefined, obligation: TaskObligation): string | undefined;
/**
 * Compose ONE level: the caller hands the direct children as `DagNode`s plus
 * the parent's own grade, and each child is adjudicated by its submission
 * alone (no recursion — use `composeTaskVerdict` when children have children
 * of their own). The obligations' `parentTaskId` fields are not consulted
 * here; the caller frames which nodes are the children.
 */
export declare function composeVerdict(nodes: readonly DagNode[], ownGrade: ProofGrade | undefined): ComposedVerdict;
/**
 * Group obligations by `parentTaskId`. Top-level tasks (no parent) share the
 * `undefined` key; the key is absent when no such children exist. Buckets
 * preserve input order, so downstream composition is a deterministic
 * function of the input array.
 */
export declare function childrenByParent(obligations: readonly TaskObligation[]): Map<string | undefined, TaskObligation[]>;
/**
 * Every cycle in the parent graph, as delegation-direction path strings
 * ('a -> b -> c -> a' means a delegated to b, b to c, c back to a). Each
 * distinct cycle is reported exactly once, rotated to start from its
 * lexicographically smallest member, whatever order the walk entered it or
 * the obligations arrived in; multiple cycles sort lexicographically. A
 * parent pointing at a task that does not exist ends the walk (no cycle) —
 * dangling references are a minting problem, not a topology lie. Returns []
 * for any acyclic forest.
 *
 * W7-5: every RECORD contributes its parent edge, not just the first record
 * per taskId. A duplicated taskId is a minting error, but the edge its later
 * copy carries (worst case `parentTaskId` naming itself) is still a fact in
 * the input, and a cycle visible only through that copy must not slip past
 * detection — the fold downstream (`composeTaskVerdict`) groups children by
 * every record too, so an undetected duplicate-edge cycle is an unbounded
 * recursive fold, not a cosmetic miss. With unique ids the edge set is
 * exactly the old first-wins set and every historical output is unchanged;
 * a task genuinely shared by two parents (the diamond) contributes two
 * parent edges and is, as ever, no cycle.
 */
export declare function detectCycles(obligations: readonly TaskObligation[]): string[];
/**
 * Recursively compose one task's verdict from its whole subtree.
 *
 * - Direct children that are leaves contribute their submission/waiver facts
 *   exactly as `composeVerdict` would read them.
 * - The queried task's OWN submission is adjudicated too (it is in this
 *   verdict's scope the way children's submissions are in their parents'):
 *   a forged own submission names the task itself in `forgedChildren` and
 *   caps the grade at `regressed` — over any `ownGrades` entry — while an
 *   honest own submission's grade feeds the verdict as its own-grade input.
 * - A child with children of its own contributes its RECURSIVELY composed
 *   grade: the lattice over its subtree, with its own submission claim as
 *   its own-grade input. Results are memoised per call (a grandchild shared
 *   by two parents is composed once and answered identically to both), and
 *   the memo lives inside this invocation only — no state survives the call.
 * - `ownGrades` is authoritative for the QUERIED task (the one party that
 *   can measure its own workspace), falling back to that task's own
 *   submission claim; for CHILDREN it is only a fallback when they submitted
 *   nothing — children are adjudicated by what they turned in, because
 *   cross-agent proof travels in bundles.
 * - A cycle anywhere in `all` is refused before composition: grade
 *   `unproven`, first blocker exactly 'responsibility cycle detected', then
 *   one 'cycle: <path>' line per detected cycle. A circular responsibility
 *   chain proves nothing and must not be folded as if it did.
 * - An unknown `taskId` composes to `unproven` with a naming blocker —
 *   asking about a task that was never minted is a caller bug, reported
 *   rather than thrown so batch composers can continue past it.
 *
 * Duplicate taskIds in `all` are a minting error; the FIRST node wins for
 * submission/waiver lookups, while every obligation record still groups
 * under its own parent (so one task can genuinely be shared by two parents,
 * the diamond the memo exists for). A duplicate whose later copy closes a
 * cycle the first copy hides (a self-parenting re-registration, say) is now
 * caught by `detectCycles`' all-edges walk (W7-5) and refused with the
 * cycle verdict — it used to escape detection and recurse the fold unboundedly.
 */
export declare function composeTaskVerdict(taskId: string, all: readonly DagNode[], ownGrades: ReadonlyMap<string, ProofGrade>): ComposedVerdict;
//# sourceMappingURL=obligations.d.ts.map