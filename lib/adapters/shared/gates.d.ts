/**
 * The three decisions every host adapter needs, as host-agnostic functions.
 *
 * A pre-tool gate ("may this call run?"), a baseline probe ("is there
 * anything to attribute regressions against?") and a turn-end evaluation
 * ("must this turn be stopped and corrected?"). Claude Code and OpenCode
 * differ in how they surface these — permission prompts, stop hooks, message
 * injection — but not in what they mean; the semantics live here, mirroring
 * src/index.ts (the DSH adapter): the workspace evidence-store guard, the
 * requireBaseline off/warn/ask ladder, and drift-then-correction turn
 * stopping. Where this file deviates from index.ts it is deliberate and the
 * comment says why (case-insensitive guard via paths.ts; a deny where the
 * DSH host could only ask; one-time notices tracked in the session file
 * because no adapter process lives long enough to remember them).
 *
 * @module dsh-proof/adapters/shared/gates
 */
import type { ProofPaths } from './paths.ts';
import type { AdapterSession, DriftResult } from './session.ts';
export type { AdapterSession, DriftResult };
/** What a host configures for the two pre-tool gates. */
export interface GateOptions {
    readonly evidenceStore: 'host' | 'workspace';
    readonly evidenceDir: string;
    readonly requireBaseline: 'off' | 'warn' | 'ask';
    /**
     * The host trust root, when the caller knows it — names the trust-side
     * artifacts (anchors, host-mode store, adapter sessions, signing keys) a
     * shell command must not touch either. Optional for callers that only
     * reproduce the historical workspace-store contract — but see the
     * unarmed-host-store warning below: host mode without it disarms BOTH
     * store sweeps.
     */
    readonly trustRoot?: string;
}
/**
 * The three ways a pre-tool call can go. The DSH host only had `ask`;
 * adapters get a real `deny` too — a host with a hard permission seam should
 * not have to fake certainty with a question.
 */
export type GateDecision = {
    readonly action: 'allow';
} | {
    readonly action: 'ask';
    readonly reason: string;
} | {
    readonly action: 'deny';
    readonly reason: string;
};
/**
 * Every spelling of the store and trust artifacts a shell command must not
 * name — the ONE target-set constructor both guard faces consume since
 * v0.24: paths.ts `guardedTargets` (Y-H-10/V5-M1/Y-H-11). It lists the
 * workspace store segment and its artifacts (folded through `foldHostPath`,
 * the ONE fold — a configured `evidenceDir` like `a/..` collapses to the
 * degenerate root case in the TEXTUAL sweep exactly like it already did in
 * the structural one), the trust-side store DIRECTORY and files under both
 * identity keys, the anchors, the adapter session ledgers, the `keys`
 * directory and the bare signing-key file names, and — for the default
 * trust root — the `~`/`$DSH_HOME`/`$HOME` spellings `rm -rf ~/.dsh/proof`
 * walks in through. Pre-v0.24 this list was hand-rolled here and in
 * src/index.ts and the two forks disagreed in exactly the places the audit
 * drove commands through; `shellCommandMentionsPath` folds case and
 * separators on both sides, so one spelling per target is enough
 * (`.proof/evidence.jsonl` also catches `.PROOF\EVIDENCE.JSONL`).
 * Substring semantics are the conservative direction on purpose —
 * `cd .proof && …`, `> .proof/evidence.jsonl` and `rm -rf <trust>/anchors/<key>`
 * must all land; the price is an occasional over-denied call whose reason
 * says exactly why.
 */
/**
 * Decide one tool call before the host executes it.
 *
 * Priority (first match wins):
 * 1. DENY — workspace mode + a mutation tool naming any path inside the
 *    evidence store. The log is the thing auditing the agent; letting the
 *    audited party edit the audit is the one compromise this plugin cannot
 *    survive. Only mutation tools: reading the log back is legitimate (the
 *    model-facing proof tools do exactly that), it is writes the guard
 *    exists for — index.ts's semantics, kept here. The path view is the
 *    over-detecting one (`contentKeys: true`): a `move {source:
 *    '.proof/evidence.jsonl'}` must not slip the log out through a key the
 *    observer treats as content noise. A false positive costs one denied
 *    call; a false negative costs the chain.
 *    Since H-01 the mutation classification is an anchored name list with an
 *    unknown-name default of MUTATION — `MultiEdit` and `NotebookEdit` (real
 *    host mutators the old word-regex could not see) take this path like
 *    every other mutator, and `notebook_path` extracts like every path key.
 * 1a. DENY — a mutation tool naming, by absolute path, any trust-side
 *    artifact directory (host-mode store, anchors, adapter session ledgers —
 *    H-26 plus W11-M3) in EITHER store mode: the trust root is where the
 *    process being audited keeps its commitments, and no agent tool call is
 *    ever a legitimate writer there. The absolute candidates fold through
 *    `foldHostPath` (X-H-12: `\\?\`-prefixed and drive-relative spellings of
 *    the same directory compare the same).
 * 1b. DENY — ANY call (mutator or not) one of whose input strings names the
 *    evidence store or the trust artifacts (X-H-13): the sweep reads VALUES,
 *    not key names — `{commandLine: …}`, `{code: …}`, mixed argv and nested
 *    command objects are all just strings now. The read-only roster exempts
 *    ONLY the structured path check above (reading the store is legitimate);
 *    it no longer exempts the textual sweep: a read-named tool CARRYING a
 *    command string is an execution signal (`grep {command: 'echo x >
 *    .proof/evidence.jsonl'}` was the audit's PoC #4). Accepted over-deny
 *    (宁误拦): a string that legitimately mentions the store — including a
 *    read tool's own file_path — is denied once with a reason saying why;
 *    the proof MCP tools remain the sanctioned read route.
 * 2. ASK — a mutation with provably no baseline under requireBaseline 'ask'.
 *    `hasBaseline === undefined` means "unknown" and never blocks (mirrors
 *    index.ts, where a baseline probe that throws passes the call through).
 * 3. ALLOW.
 *
 * requireBaseline 'warn' is invisible here by design: warn passes the call
 * and owes the model a corrective notice instead — that is `evaluateStop`'s
 * rule 2, at turn end, where the model can still act on it.
 */
export declare function decidePreToolUse(toolName: string, toolInput: unknown, root: string, options: GateOptions, hasBaseline: boolean | undefined): GateDecision;
/**
 * Does a REAL baseline exist at the adapter-derived path?
 *
 * H-20 (v0.23): shape is not enough. The old check accepted any parsable
 * JSON with a string `baselineId` — and in workspace mode the baseline file
 * sits in the agent-writable area, so a 20-byte `{"baselineId":"forged"}`
 * permanently dismissed the baseline gate (ask ladder released, notices
 * silenced). True requires the file to address ITSELF: the check evidence
 * addresses must merkle to the recorded root, and the recorded id must equal
 * the address of exactly that material — the same identity `buildBaseline`
 * computes.
 *
 * W11-M4: self-address alone was five lines away with the package's own
 * exports (`addressOf` and `merkleRoot` are public) — an EMPTY self-consistent
 * baseline released the ladder as surely as a forged one. Two closures:
 * - `chainDigest` (optional): when the caller can see the evidence chain, the
 *   digest the chain's non-suspect `baseline`/`saved` marker recorded for the
 *   baseline FILE BYTES — a matching digest is the engine-side authority
 *   (H-23's rule mirrored here); any mismatch (including a hand-recomputed
 *   self-consistent forgery) is false.
 * - Without a chain to bind to, the floor rises instead: at least one check
 *   and a parseable `createdAt` are required. The price is honest over-deny:
 *   a genuine zero-check baseline (a project with no discovered checks) reads
 *   as "no baseline" and keeps the ladder armed — one ask per mutation,
 *   versus a five-line forgery the old check accepted as history.
 */
export declare function hasBaselineOnDisk(paths: ProofPaths, readFile: (abs: string) => Promise<string | undefined>, chainDigest?: string): Promise<boolean>;
/** The facts a turn-end evaluation needs, gathered by the host adapter. */
export interface StopFacts {
    /** This turn's drift computation, when drift detection is on. */
    readonly drift: DriftResult | undefined;
    /** How many files this window's tool calls touched. */
    readonly touchedCount: number;
    readonly hasBaseline: boolean;
    readonly requireBaseline: 'off' | 'warn' | 'ask';
    readonly enforceOnTurnEnd: boolean;
    readonly driftDetection: boolean;
}
/**
 * Decide whether a turn may stop, and what to tell the model if not.
 *
 * Returns `{ block, fire }`: `block` is the message the host must surface
 * (and keep the turn alive for); `fire` is the one-time notice id the CALLER
 * must write back into the session's `firedNotices` — evaluateStop never
 * mutates the session (pure function, session-as-value discipline), it only
 * names what its caller owes the ledger.
 *
 * Priority (first match wins):
 * 1. Drift blocks, EVERY time — "the workspace moved outside your tool
 *    calls" is a fact about the present disk, not a nag; by next turn it can
 *    be a different file. Not a one-time notice, so no `fire`. The text is
 *    `driftNarrative`'s, exactly: staleReads first (the corruption that
 *    poisons the model's in-context copies), then the rest of the drift,
 *    then the remedy — re-read, then proof_verify. When the session has used
 *    a shell this session, the narrative says so instead of accusing (a
 *    shell's edits are invisible to path attribution — the accusation would
 *    be false in the plugin's authoritative voice).
 * 2. One-time 'baseline': mutations happened, no baseline exists, the ladder
 *    is not 'off' (both 'warn' and 'ask' end a turn here — 'ask' already
 *    gated each call, but an unknown tool can still have slipped a mutation
 *    through, and the turn end is the last honest checkpoint). ONE-TIME per
 *    session: the missing-baseline state does not change turn to turn.
 * 3. 'verify': mutations happened, a baseline exists, turn-end enforcement
 *    is on — the work was never re-verified against it. Re-arms EVERY turn
 *    (v0.23, M-45): the DSH host's turn-end rule fires every turn that
 *    mutated without a proven claim, and a notice the audited party can
 *    burn once (ignore it, let it fire, stay silent forever after) is not
 *    enforcement — each mutating turn owes its own verification. `fire` is
 *    still returned (the ledger keeps the fact) but no longer suppresses.
 * 4. Nothing to say: the turn may stop.
 */
export declare function evaluateStop(facts: StopFacts, session: AdapterSession): {
    block?: string;
    fire?: string;
};
//# sourceMappingURL=gates.d.ts.map