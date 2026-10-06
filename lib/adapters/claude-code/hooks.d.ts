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
import type { ProofPaths } from '../shared/paths.ts';
import type { GateOptions } from '../shared/gates.ts';
/** One Claude Code hook event, as it arrives on stdin (unknown fields tolerated). */
export interface CcHookPayload {
    session_id?: string;
    hook_event_name?: string;
    tool_name?: string;
    tool_input?: unknown;
    /** PostToolUse also carries tool_response; observation only needs the input. */
    tool_response?: unknown;
    cwd?: string;
    [k: string]: unknown;
}
/** Everything a handler needs, assembled once per process from the environment. */
export interface CcAdapterEnv {
    paths: ProofPaths;
    gate: GateOptions;
    driftDetection: boolean;
    enforceOnTurnEnd: boolean;
    now: () => string;
    readFile: (abs: string) => Promise<string | undefined>;
    /** Diagnostics sink, one line per call (persistence failures are said, not swallowed). */
    stderr: (line: string) => void;
}
/**
 * Assemble the adapter environment. `cwd` is the hook process's working
 * directory (Claude Code sets it to the project dir); DSH_PROOF_ROOT wins.
 * The env contract itself is parsed by the shared `resolveAdapterEnv` — one
 * parser for every face (H-21: a variable only this file reads is a forked
 * deployment, not a configuration).
 */
export declare function ccAdapterEnv(env: NodeJS.ProcessEnv, cwd: string): CcAdapterEnv;
export declare function sanitizeBlockForModel(text: string): string;
/**
 * PreToolUse — evidence-store guard + baseline gate as a permission decision.
 *
 * `allow` is returned as undefined: Claude Code treats exit 0 with no output as
 * "no action", which is exactly what an allow is. `ask`/`deny` ride the
 * hookSpecificOutput shape so the host routes the call accordingly.
 */
export declare function handlePreToolUse(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined>;
/**
 * PostToolUse — provenance observation. Loads the session (seeding an empty
 * one on first sight), folds the observation in, persists. A tool result must
 * never be delayed by bookkeeping failures, so an observation error is
 * swallowed — but SAID on stderr since v0.23 (M-43: a silent observation
 * loss reads to the operator like working drift detection).
 * A payload without session_id is a no-op — there is nowhere to persist.
 */
export declare function handlePostToolUse(payload: CcHookPayload, env: CcAdapterEnv): Promise<undefined>;
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
export declare function handleStop(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined>;
/**
 * SessionStart — inject the policy context and seed the session file.
 *
 * The checks list is empty on purpose: discovery belongs to the proof engine,
 * which on this host lives behind the MCP tools (proof_status reports the
 * discovered checks); the policy section plus the MCP line below carry that.
 * Seeding happens only when no session file exists yet — a resume must not
 * wipe the observation window of the session being resumed.
 */
export declare function handleSessionStart(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined>;
//# sourceMappingURL=hooks.d.ts.map