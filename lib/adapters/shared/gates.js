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
import { WorkspaceWatch, driftNarrative, isMutationToolName, shellCommandMentionsPath, sweepToolInputStrings, } from "../../dsh/observe.js";
import { absoluteInside, deriveProofPaths, foldHostPath, guardedTargets, touchesEvidencePath, workspaceKeyPair, } from "./paths.js";
import { addressOf, merkleRoot, sha256 } from "../../core/hash.js";
/**
 * V5-L5: host mode with NO trustRoot disarms both store sweeps at once (the
 * structural branch has no store to compare against; the textual branch has
 * no targets to mention). The real host adapters always pass a trust root —
 * a library caller that does not must at least be TOLD the guard is off,
 * once per process, instead of sailing silently. Never throws: a diagnostics
 * gap must not become a denial.
 */
let warnedUnarmedHostStore = false;
function warnUnarmedHostStore() {
    if (warnedUnarmedHostStore)
        return;
    warnedUnarmedHostStore = true;
    try {
        process.stderr.write('dsh-proof: GateOptions.evidenceStore=\'host\' without a trustRoot disarms BOTH evidence-store sweeps '
            + '(structural and textual) — no guard is running for the host-side store. Pass trustRoot (the host '
            + 'adapters always do); this is the historical no-trust contract, announced rather than silent.\n');
    }
    catch {
        /* a closed stderr cannot stop the gate either */
    }
}
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
export function decidePreToolUse(toolName, toolInput, root, options, hasBaseline) {
    // V5-L5: announce the disarmed combination instead of running silent —
    // host mode without a trustRoot has no store to guard and no targets to
    // mention; the historical contract, but a loud one.
    if (options.evidenceStore === 'host'
        && (options.trustRoot === undefined || options.trustRoot.length === 0)) {
        warnUnarmedHostStore();
    }
    const mutation = isMutationToolName(toolName);
    const targets = guardedTargets(root, options);
    if (mutation && (options.evidenceStore === 'workspace' || options.trustRoot !== undefined)) {
        const candidates = WorkspaceWatch.pathsIn(toolInput, { contentKeys: true });
        let verdict;
        if (options.evidenceStore === 'workspace') {
            // pure derivation: this sweep only consumes root/evidenceDir/evidenceStore
            // (the key is never read here), so the identity probe is skipped.
            const paths = deriveProofPaths({
                root,
                evidenceStore: options.evidenceStore,
                evidenceDir: options.evidenceDir,
            }, { pure: true });
            if (candidates.some(candidate => touchesEvidencePath(candidate, paths)))
                verdict = 'store';
        }
        if (verdict === undefined && options.trustRoot !== undefined && options.trustRoot.length > 0) {
            // H-26 structured half + W11-M3, unified across store modes: the
            // host-mode store, the anchors and the adapter session ledgers all live
            // under the trust root — an ABSOLUTE path into any of them is the write
            // this guard exists to refuse, in workspace mode just as much as in
            // host mode (only the store's location differs). Both identity
            // spellings are swept (a migrated deployment may still hold its state
            // under the legacy key), the same pair the shell rule lists; Y-H-11
            // adds the `keys` directory — the Ed25519 pair the checkpoint chain's
            // signatures live and die by, a file-level addition rather than the
            // whole trust root (over-deny stops where nothing sensitive lives).
            const trust = foldHostPath(options.trustRoot);
            const pair = workspaceKeyPair(root);
            const keys = pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy];
            const guardedDirs = keys.flatMap(key => [
                `${trust}/workspaces/${key}`,
                `${trust}/anchors/${key}`,
                `${trust}/adapter-sessions/${key}`,
                `${trust}/keys`,
            ]);
            if (candidates.some(candidate => guardedDirs.some(dir => absoluteInside(candidate, dir))))
                verdict = 'trust';
        }
        if (verdict !== undefined) {
            return verdict === 'store'
                ? {
                    action: 'deny',
                    reason: 'dsh-proof: this call writes into the verification evidence store, which must not be '
                        + 'modified by the agent it is meant to audit. Evidence changes go through host mode '
                        + '(store outside the workspace) or a human — never through your own tools.',
                }
                : {
                    action: 'deny',
                    reason: 'dsh-proof: this call writes into the trust-side verification artifacts (evidence store, '
                        + 'anchors, session ledgers) by absolute path — they live outside the workspace precisely so the '
                        + 'agent they audit cannot edit them. Evidence changes go through a human, never through your own tools.',
                };
        }
    }
    // X-H-13: the textual sweep runs for EVERY tool name — the capability gate
    // moved from "is this name a mutator" (a list, walked around by read-named
    // tools carrying commands) to "does this call carry a string that names the
    // store" (a property of the input). Empty targets (no workspace store, no
    // trust root — the historical GateOptions contract) disarm it as before.
    if (targets.length > 0) {
        for (const value of sweepToolInputStrings(toolInput)) {
            if (shellCommandMentionsPath(value, targets)) {
                return {
                    action: 'deny',
                    reason: 'dsh-proof: this command names the verification evidence store or its trust files, '
                        + 'which must not be modified by the agent they are meant to audit. Command strings cannot be '
                        + 'path-checked structurally, so any mention of the store is refused — run the command without '
                        + 'the evidence paths, or route evidence changes through a human.',
                };
            }
        }
    }
    if (mutation && hasBaseline === false && options.requireBaseline === 'ask') {
        return {
            action: 'ask',
            reason: `dsh-proof: no verification baseline exists yet, and \`${toolName}\` mutates the workspace. `
                + 'Establish one first with the proof_baseline MCP tool so later failures can be attributed correctly.',
        };
    }
    return { action: 'allow' };
}
/**
 * Recompute the baseline's self-address from its own contents, exactly the
 * way `buildBaseline` minted it (evidence.ts): the merkle root over the
 * check evidence addresses, then `addressOf` over {createdAt, workspace,
 * checkIds, root}. This mirrors the engine-side recompute interface (F2's
 * baselineId work); if that formula ever moves, this mirror must move with
 * it — a gate that validates against a stale formula is worse than none.
 */
function baselineSelfAddress(parsed) {
    if (typeof parsed.createdAt !== 'string'
        || parsed.workspace === null || typeof parsed.workspace !== 'object' || Array.isArray(parsed.workspace)) {
        return undefined;
    }
    if (!Array.isArray(parsed.checks) || typeof parsed.root !== 'string')
        return undefined;
    const checks = parsed.checks;
    if (!checks.every(c => c !== null && typeof c === 'object' && !Array.isArray(c)
        && typeof c.checkId === 'string' && typeof c.evidenceId === 'string')) {
        return undefined;
    }
    // The recorded merkle root must BE the root of the recorded evidence —
    // buildBaseline never writes a mismatched pair, so a mismatch is damage.
    const root = merkleRoot(checks.map(c => c.evidenceId));
    if (root !== parsed.root)
        return undefined;
    const material = {
        createdAt: parsed.createdAt,
        workspace: parsed.workspace,
        checkIds: checks.map(c => c.checkId),
        root,
    };
    try {
        return addressOf(material);
    }
    catch {
        // A workspace snapshot that cannot canonicalise (exotic prototype) is
        // not a baseline any engine wrote; "no baseline" is the honest verdict.
        return undefined;
    }
}
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
export async function hasBaselineOnDisk(paths, readFile, chainDigest) {
    const raw = await readFile(paths.baselinePath);
    if (raw === undefined)
        return false;
    // Chain binding first: bytes the engine never saved are not a baseline,
    // whatever they say about themselves.
    if (chainDigest !== undefined && sha256(raw) !== chainDigest)
        return false;
    try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
            return false;
        if (typeof parsed.baselineId !== 'string')
            return false;
        if (chainDigest === undefined) {
            // The no-chain floor (W11-M4): without bytes to bind to, an empty
            // self-consistent baseline is trivially mintable — see the doc above.
            if (!Array.isArray(parsed.checks) || parsed.checks.length === 0)
                return false;
            if (typeof parsed.createdAt !== 'string' || Number.isNaN(Date.parse(parsed.createdAt)))
                return false;
        }
        return baselineSelfAddress(parsed) === parsed.baselineId;
    }
    catch {
        return false;
    }
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
export function evaluateStop(facts, session) {
    if (facts.driftDetection && facts.drift !== undefined
        && (facts.drift.drifted.length > 0 || facts.drift.staleReads.length > 0)) {
        const narrative = driftNarrative({
            drifted: [...facts.drift.drifted],
            touched: [...session.touched],
            staleReads: [...facts.drift.staleReads],
            // DriftResult does not carry the scan count; the narrative never reads
            // it, and what it would describe (how many files were compared) is not
            // a fact this gate decides on.
            scanned: facts.drift.drifted.length + facts.drift.staleReads.length,
        }, { shellUsed: session.shellUsed === true });
        if (narrative !== undefined)
            return { block: narrative };
    }
    if (facts.touchedCount > 0 && !facts.hasBaseline && facts.requireBaseline !== 'off'
        && !session.firedNotices.includes('baseline')) {
        return {
            block: '⚠️ dsh-proof: this turn mutated the workspace, but it has no completion-proof baseline. '
                + 'Call the proof_baseline MCP tool to establish one so later failures can be attributed to your changes.',
            fire: 'baseline',
        };
    }
    if (facts.touchedCount > 0 && facts.hasBaseline && facts.enforceOnTurnEnd) {
        return {
            block: '⚠️ dsh-proof: this turn mutated the workspace, but the changes have not been verified against the '
                + 'baseline. Call the proof_verify MCP tool before reporting completion — a prose assertion is not evidence.',
            fire: 'verify',
        };
    }
    return {};
}
//# sourceMappingURL=gates.js.map