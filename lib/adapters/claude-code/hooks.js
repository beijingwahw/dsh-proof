/**
 * Claude Code host adapter — hook handlers.
 *
 * What this adds on top of the MCP tool surface (src/app/mcp-server.ts, which
 * Claude Code consumes through `claude mcp add proof -- dsh-proof-mcp`): the
 * three things a tool server structurally cannot do.
 *
 *   PreToolUse    the gates as permission decisions — the evidence-store guard
 *                 (workspace mode: the log must not be agent-writable) and the
 *                 baseline gate (no baseline, no unreviewed mutation)
 *   PostToolUse   provenance observation — which files the agent actually
 *                 moved, fingerprinted at observation time
 *   Stop          drift detection (files that changed outside tool calls) as a
 *                 stop block, plus the one-shot no-baseline reminder; the stop
 *                 is also the turn boundary, so the observation window advances
 *   SessionStart  policy context injection (the `proof:policy` section plus the
 *                 MCP tool names on this host)
 *
 * Host protocol shapes live in this layer and nowhere else, so tests can pin
 * them (Claude Code feeds one JSON object on stdin; the command answers with a
 * single line of JSON on stdout and exit 0 — exit 0 with no output means "no
 * action"):
 *
 *   PreToolUse    {"hookSpecificOutput":{"hookEventName":"PreToolUse",
 *                    "permissionDecision":"allow"|"ask"|"deny",
 *                    "permissionDecisionReason":"..."}}
 *   Stop          {"decision":"block","reason":"..."}   // reason is fed back
 *                 to the model as why the turn may not end
 *   SessionStart  {"hookSpecificOutput":{"hookEventName":"SessionStart",
 *                    "additionalContext":"..."}}
 *
 * Tool surface: settings matchers do the coarse filtering (see
 * examples/claude-code.settings.json), but every handler here stays total for
 * ANY tool name — a hook configured with a broader matcher must never crash.
 * Write/Edit/MultiEdit/NotebookEdit mutate via `tool_input.file_path`
 * (NotebookEdit via `notebook_path`); Read reads via `file_path`; Bash
 * executes `tool_input.command`. Since H-02 the Bash command string is swept
 * for evidence/trust paths at the gate; what it still cannot do is attribute
 * the files a command changed (a Bash-written file contributes no
 * fingerprint — the documented observation blind spot, stated in the example
 * settings and the SessionStart context).
 *
 * State is per Claude Code session (session_id), persisted under the shared
 * adapter paths (src/adapters/shared/paths.ts) so independent hook processes —
 * one process per event — read and write the same observation window. The
 * ledger is workspace-keyed and self-checking (H-19): a snapshot that does not
 * address itself resets loudly instead of being trusted.
 *
 * Environment (mirrors the DSH plugin's config defaults; parsed ONCE in
 * paths.ts `resolveAdapterEnv`, the contract app/mcp-entry.ts shares):
 *   DSH_PROOF_ROOT             workspace root (default: the hook's cwd)
 *   DSH_PROOF_TRUST_DIR        trust root (default: deriveProofPaths' own)
 *   DSH_PROOF_EVIDENCE_STORE   'host' (default) | 'workspace'
 *   DSH_PROOF_EVIDENCE_DIR     workspace-relative evidence dir (default '.proof')
 *   DSH_PROOF_REQUIRE_BASELINE 'off' | 'warn' (default) | 'ask'
 *   DSH_PROOF_DRIFT            '0'|'false'|'no'|'off' disables drift (default: on)
 *   DSH_PROOF_ENFORCE_TURN_END '0'|'false'|'no'|'off' disables the turn-end
 *                              reminder (default: on)
 *
 * @module dsh-proof/adapters/claude-code/hooks
 */
import { promises as fsp } from 'node:fs';
import { deriveProofPaths, resolveAdapterEnv } from "../shared/paths.js";
import { applyObservation, computeDrift, emptySession, loadSession, saveSession, windowStart } from "../shared/session.js";
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from "../shared/gates.js";
// v0.25.1 (U4-H1): `readChainMarkers` is the one public read carrying the
// H-32 position verdict, reserved for engine-less faces (this process holds
// no store); the `_readMarkers` escape hatch is retired (test/32 claim 1b).
import { readChainMarkers } from "../../core/evidence.js";
import { buildPolicySection } from "../../dsh/prompt.js";
import { MCP_TOOLS } from "../../app/mcp-server.js";
/** Best-effort stderr default; a closed stream must never break a handler. */
function defaultStderr(line) {
    try {
        process.stderr.write(`${line}\n`);
    }
    catch {
        /* nothing further to do */
    }
}
async function nodeReadFile(abs) {
    try {
        return await fsp.readFile(abs, 'utf8');
    }
    catch {
        return undefined;
    }
}
/**
 * Assemble the adapter environment. `cwd` is the hook process's working
 * directory (Claude Code sets it to the project dir); DSH_PROOF_ROOT wins.
 * The env contract itself is parsed by the shared `resolveAdapterEnv` — one
 * parser for every face (H-21: a variable only this file reads is a forked
 * deployment, not a configuration).
 */
export function ccAdapterEnv(env, cwd) {
    const values = resolveAdapterEnv(env);
    const root = values.root ?? cwd;
    // The trust-root default is left to deriveProofPaths (the DSH_HOME rule the
    // plugin and the MCP entry both apply), so all three faces derive the same one.
    const paths = deriveProofPaths({
        root,
        ...(values.trustRoot !== undefined ? { trustRoot: values.trustRoot } : {}),
        ...(values.evidenceStore !== undefined ? { evidenceStore: values.evidenceStore } : {}),
        ...(values.evidenceDir !== undefined ? { evidenceDir: values.evidenceDir } : {}),
    });
    // GateOptions mirrors the plugin config's semantics: `evidenceDir` is the
    // workspace-relative dir ('.proof' by default), only meaningful in
    // workspace mode — host mode keeps the store outside the sandbox. The
    // trust root rides along so the shell-command sweep can guard the
    // trust-side artifacts too (H-02).
    const gate = {
        evidenceStore: paths.evidenceStore,
        evidenceDir: values.evidenceDir ?? '.proof',
        requireBaseline: values.requireBaseline ?? 'warn',
        trustRoot: paths.trustRoot,
    };
    return {
        paths,
        gate,
        driftDetection: values.driftDetection ?? true,
        enforceOnTurnEnd: values.enforceTurnEnd ?? true,
        now: () => new Date().toISOString(),
        readFile: nodeReadFile,
        stderr: defaultStderr,
    };
}
function sessionIdOf(payload) {
    const value = payload.session_id;
    return typeof value === 'string' && value.length > 0 ? value : undefined;
}
/** The PreToolUse answer for one permission decision ('allow' renders as no output at all). */
function preToolUseResponse(decision, reason) {
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: decision,
            // W12-M1: reasons embed data (tool names in the ask ladder's text);
            // whatever a reason carries is flattened before the host feeds it back
            // to the model.
            permissionDecisionReason: sanitizeBlockForModel(reason),
        },
    };
}
/**
 * Host-render sanitization for any model-facing decision/block text (W12-M1).
 *
 * Drift narratives embed workspace FILE NAMES — attacker-controllable data —
 * and a POSIX file name may legally contain newlines, so a crafted name used
 * to arrive inside a Stop block reason (or a permission reason) as its own
 * forged instruction line. At this render point the text is one flat string,
 * so the honest fix is structural: every original newline becomes a visible
 * ' | ' separator (a forged "instruction line" can no longer occupy a line of
 * its own), other C0 control characters and DEL are dropped, and any single
 * over-long segment (a padded payload) is capped. The producing side
 * (observe.ts's driftNarrative) is the classifier owner's domain; this is the
 * host's defense-in-depth render rule. Mirrored in
 * adapters/opencode/plugin.ts — keep the two in lockstep.
 */
const HOST_RENDER_SEGMENT_CAP = 200;
export function sanitizeBlockForModel(text) {
    return text
        .split(/\r?\n/)
        .map(segment => {
        const clean = segment.replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '').trim();
        return clean.length > HOST_RENDER_SEGMENT_CAP ? `${clean.slice(0, HOST_RENDER_SEGMENT_CAP)}…` : clean;
    })
        .filter(segment => segment.length > 0)
        .join(' | ');
}
/**
 * Y-H-13 (v0.24): the digest the evidence chain remembers for the baseline
 * FILE BYTES — the binding argument `hasBaselineOnDisk`'s W11-M4 contract
 * shipped in v0.23 and then never received: every adapter call site invoked
 * the probe two-argument, so the chain floor never engaged and a five-line
 * self-consistent baseline minted with the package's own public
 * `addressOf`/`merkleRoot` walked the ask ladder exactly like a genuine one
 * (the audit's PoC). This read is that third argument.
 *
 * The rule is the ENGINE's, mirrored verbatim — core/evidence.ts's private
 * `lastBaselineDigest`, the same selection `loadBaseline()` and `audit()`
 * bind by: last-wins among `baseline/saved` markers whose `headRef` can vouch
 * for their physical position; when EVERY such marker is suspect (a log
 * written before the headRef witness existed), the last one still speaks, so
 * an upgraded deployment keeps exactly the detection it had, never less. No
 * marker the chain remembers means `undefined`, and `hasBaselineOnDisk` then
 * falls to its own no-chain floor instead of to an accusation — the same
 * degradation `loadBaseline` grants a baseline placed by a flow that never
 * recorded a save.
 *
 * Line discipline: the store's `readLines` (node-ports) splits on '\n' and
 * drops blank lines; the suspect test hashes each marker's PHYSICAL
 * predecessor, so this split must produce the same snapshot the engine's own
 * walk sees, or the two faces would disagree about who is suspect.
 *
 * Cost (deliberately uncached): a gate evaluation now reads TWO files
 * (baseline + log) where it read one. On this host that is one extra bounded
 * read per hook PROCESS (Claude Code spawns a process per event), and an
 * mtime-keyed digest cache was considered and rejected anyway: it would open
 * a staleness window exactly where freshness IS the security property (a
 * swapped baseline must fail the very next gate call, not the first call
 * after the log's mtime moves), and it would need a stat seam the
 * readFile-only env contract does not carry.
 *
 * Mirrored in adapters/opencode/plugin.ts — keep the two in lockstep (the
 * sanitizeBlockForModel rule).
 */
async function savedBaselineDigest(logPath, readFile) {
    const raw = await readFile(logPath);
    if (raw === undefined)
        return undefined;
    const lines = raw.split('\n').filter(line => line.trim().length > 0);
    // v0.25.1 (U4-H1): the read goes through `readChainMarkers` — the one
    // PUBLIC read that carries the H-32 position verdict, imported by exactly
    // the two engine-less adapter faces (test/32 claim 1b pins the importer
    // set). Same single-pass core the store's `markersWith` and the verified
    // view derive from; the underscore `_readMarkers` escape hatch is retired.
    const markers = readChainMarkers(lines, { label: 'baseline/saved' })
        .filter(marker => typeof marker.payload.digest === 'string');
    const trusted = markers.filter(marker => !marker.suspect);
    const pool = trusted.length > 0 ? trusted : markers;
    const last = pool[pool.length - 1];
    return last === undefined ? undefined : last.payload.digest;
}
/**
 * The chained baseline probe every handler here uses: `hasBaselineOnDisk`
 * bound to the digest the chain remembers, so the Y-H-13 binding runs at
 * every call site this file owns instead of at none of them.
 */
async function chainedHasBaselineOnDisk(env) {
    return hasBaselineOnDisk(env.paths, env.readFile, await savedBaselineDigest(env.paths.logPath, env.readFile));
}
/**
 * PreToolUse — evidence-store guard + baseline gate as a permission decision.
 *
 * `allow` is returned as undefined: Claude Code treats exit 0 with no output as
 * "no action", which is exactly what an allow is. `ask`/`deny` ride the
 * hookSpecificOutput shape so the host routes the call accordingly.
 */
export async function handlePreToolUse(payload, env) {
    const toolName = typeof payload.tool_name === 'string' ? payload.tool_name : '';
    const hasBaseline = await chainedHasBaselineOnDisk(env);
    const decision = decidePreToolUse(toolName, payload.tool_input ?? {}, env.paths.root, env.gate, hasBaseline);
    if (decision.action === 'allow')
        return undefined;
    return preToolUseResponse(decision.action, decision.reason);
}
/**
 * PostToolUse — provenance observation. Loads the session (seeding an empty
 * one on first sight), folds the observation in, persists. A tool result must
 * never be delayed by bookkeeping failures, so an observation error is
 * swallowed — but SAID on stderr since v0.23 (M-43: a silent observation
 * loss reads to the operator like working drift detection).
 * A payload without session_id is a no-op — there is nowhere to persist.
 */
export async function handlePostToolUse(payload, env) {
    const sessionId = sessionIdOf(payload);
    if (sessionId === undefined)
        return undefined;
    try {
        let session = await loadSession(env.paths.sessionDir, sessionId) ?? emptySession(env.now());
        if (typeof payload.tool_name === 'string') {
            session = await applyObservation(session, payload.tool_name, payload.tool_input, env.paths.root, env.readFile);
        }
        await saveSession(env.paths.sessionDir, sessionId, session);
    }
    catch (error) {
        // Observation is best-effort by design; drift detection at Stop re-reads
        // the filesystem anyway, so a lost observation degrades, never breaks.
        env.stderr(`dsh-proof: post-tool observation failed (${error instanceof Error ? error.message : String(error)}); `
            + 'drift attribution may lag one turn');
    }
}
/**
 * Stop — drift detection, the one-shot baseline reminder, and the window turn.
 *
 * Claude Code's Stop is the turn boundary, which is DSH's turn-stopping /
 * windowStart seam: whatever this handler decides, the observation window
 * advances and the session persists. A block hands the reason back to the
 * model instead of letting the turn end; the baseline reminder (`fire`) is
 * one-shot per session through `firedNotices`, a drift block re-arms every
 * stop, and the verify reminder re-arms every TURN (v0.23: one blockable
 * fact per mutating turn — a notice that can be burned once is not
 * enforcement).
 *
 * Ordering (M-43, v0.23): the DECISION is computed first and returned even
 * when persistence fails; the save runs last in its own best-effort try. A
 * chmod'd read-only session directory used to swallow every drift block this
 * handler had already computed — the exact failure the block exists for.
 * A payload without session_id is a no-op — there is nothing to observe.
 */
export async function handleStop(payload, env) {
    const sessionId = sessionIdOf(payload);
    if (sessionId === undefined)
        return undefined;
    let outcome;
    try {
        const session = await loadSession(env.paths.sessionDir, sessionId) ?? emptySession(env.now());
        const drift = env.driftDetection
            ? await computeDrift(session, env.paths.root, env.readFile)
            : undefined;
        const facts = {
            drift,
            touchedCount: session.touched.length,
            hasBaseline: await chainedHasBaselineOnDisk(env),
            requireBaseline: env.gate.requireBaseline,
            enforceOnTurnEnd: env.enforceOnTurnEnd,
            driftDetection: env.driftDetection,
        };
        const decision = evaluateStop(facts, session);
        // Drift is the louder signal: when both a block and a one-shot notice are
        // due, the drift reason is what the model needs to act on first.
        const reason = decision.block !== undefined ? decision.block : decision.fire;
        const fired = decision.fire !== undefined && !session.firedNotices.includes(decision.fire)
            ? [...session.firedNotices, decision.fire]
            : session.firedNotices;
        outcome = { reason, next: windowStart({ ...session, firedNotices: fired }, env.now()) };
    }
    catch (error) {
        // A failing Stop evaluation must never wedge the turn's wind-down — but
        // it is said, not silenced.
        env.stderr(`dsh-proof: stop evaluation failed (${error instanceof Error ? error.message : String(error)}); the turn proceeds unblocked`);
        return undefined;
    }
    try {
        await saveSession(env.paths.sessionDir, sessionId, outcome.next);
    }
    catch (error) {
        env.stderr(`dsh-proof: session persistence failed (${error instanceof Error ? error.message : String(error)}); `
            + `the observation window did not advance — one-time notices may repeat`);
    }
    if (outcome.reason === undefined)
        return undefined;
    // W12-M1: the reason is fed back to the model as why the turn may not end —
    // the plugin's authoritative voice. Whatever data the block carries (drift
    // narratives embed workspace file names, and POSIX names may contain
    // newlines) is flattened here, at the render point.
    return { decision: 'block', reason: sanitizeBlockForModel(outcome.reason) };
}
/**
 * The concrete spelling of "the evidence store" for the DETECTED self-check,
 * derived from the adapter's own paths (W12-M2) — never hardcoded: with
 * DSH_PROOF_EVIDENCE_DIR='.evi' a hardcoded `.proof/evidence.jsonl` told the
 * model to probe a file whose un-denied write is CORRECT behavior, and the
 * self-check would misreport the guard as absent (or teach the model the
 * check ignores what it writes). Workspace mode names the relative file the
 * model can attempt; host mode (the default) names the absolute store under
 * the trust root — exactly the absolute-path write the H-26 arm denies.
 */
function evidenceSelfCheckPath(paths) {
    if (paths.evidenceStore === 'workspace') {
        return paths.evidenceDir === '' ? 'evidence.jsonl in the workspace root' : `${paths.evidenceDir}/evidence.jsonl`;
    }
    return paths.logPath;
}
/**
 * The MCP line appended to the SessionStart context: the tool names on THIS
 * host, plus the wiring self-check (H-22): the policy section describes what
 * the hooks DO when they are wired, and this adapter cannot verify its own
 * wiring — a project-scope settings file can silently drop the PreToolUse
 * hook. The context therefore states the detection, not a guarantee, and
 * hands the model the one check that falsifies it — spelled from the derived
 * paths, so the check tests the store that is actually guarded.
 */
function mcpToolsLine(paths) {
    return `On this host the proof surface is ${MCP_TOOLS.length} MCP tools (APP/1.4 frozen contract; registered with `
        + '`claude mcp add proof -- dsh-proof-mcp`): '
        + `${MCP_TOOLS.join(', ')}. Call proof_verify after any significant change, before claiming the work done. `
        + 'Note: files changed only through Bash are not path-attributed — prefer Write/Edit so drift attribution can see them.\n\n'
        + 'Enforcement wiring: the gates above run through host hooks (.claude/settings.json), and they cover exactly '
        + 'the tool names the configured PreToolUse matcher routes to them — a tool the matcher does not list never '
        + 'reaches this gate (the shipped example lists only the known mutators). This context cannot verify they are '
        + 'wired — a project-level settings file can omit or remove them, narrow the matcher, and hook wiring supplied by '
        + 'the repository travels with the repository. Treat enforcement as DETECTED, not guaranteed: if a write into '
        + `the evidence store (${evidenceSelfCheckPath(paths)}) is not denied, report that the guard is absent instead of assuming oversight.`;
}
/**
 * SessionStart — inject the policy context and seed the session file.
 *
 * The checks list is empty on purpose: discovery belongs to the proof engine,
 * which on this host lives behind the MCP tools (proof_status reports the
 * discovered checks); the policy section plus the MCP line below carry that.
 * Seeding happens only when no session file exists yet — a resume must not
 * wipe the observation window of the session being resumed.
 */
export async function handleSessionStart(payload, env) {
    const sessionId = sessionIdOf(payload);
    if (sessionId !== undefined) {
        try {
            const existing = await loadSession(env.paths.sessionDir, sessionId);
            if (existing === undefined) {
                await saveSession(env.paths.sessionDir, sessionId, emptySession(env.now()));
            }
        }
        catch {
            // Seeding is an optimisation for first-observation latency, not a
            // precondition — PostToolUse seeds too when the file is missing.
        }
    }
    const hasBaseline = await chainedHasBaselineOnDisk(env);
    const additionalContext = `${buildPolicySection({
        discovered: [],
        hasBaseline,
        requireBaseline: env.gate.requireBaseline,
    })}\n\n`
        // W12-M15: the policy section says "no objective checks are discovered in
        // this workspace" — true of what THIS ADAPTER can see (nothing: discovery
        // is the engine's, behind the MCP tools). Without this qualifier a model
        // in a repo full of check scripts would take the line as a workspace fact.
        + 'Check discovery does not run in this host adapter — the line above is the adapter\'s view, not the '
        + 'workspace\'s. Ask `proof_status` for the live discovered set before concluding the workspace declares no checks.'
        + `\n\n${mcpToolsLine(env.paths)}`;
    return {
        hookSpecificOutput: {
            hookEventName: 'SessionStart',
            additionalContext,
        },
    };
}
//# sourceMappingURL=hooks.js.map