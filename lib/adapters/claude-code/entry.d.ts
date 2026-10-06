#!/usr/bin/env node
/**
 * Claude Code hook entry — the command Claude Code runs per event.
 *
 * Usage: dsh-proof-cc <pre-tool-use|post-tool-use|stop|session-start>
 *
 * Claude Code feeds one JSON object (the hook payload) on stdin and reads a
 * single line of JSON from stdout; exit 0 always, exit 0 with no output means
 * "no action". Wiring lives in examples/claude-code.settings.json; the tool
 * surface itself — the thirteen frozen MCP names of the APP/1.4 contract
 * (proof_status/proof_baseline/proof_verify/proof_claim/proof_bundle and
 * eight more; the single source is MCP_TOOLS in src/app/mcp-server.ts) —
 * rides MCP: `claude mcp add proof -- dsh-proof-mcp`.
 *
 * Failure posture, per event:
 *   - a payload that does not parse: PreToolUse answers `ask` (a gate that
 *     cannot read its input must not wave the mutation through); every other
 *     event stays silent — an unparseable observation is no observation.
 *   - an internal error: PreToolUse answers `ask` (the conservative
 *     direction for a gate); every other event logs to stderr and stays
 *     silent, because a broken Stop/PostToolUse must never wedge the turn.
 *   - an unrecognized event name: silent exit 0 — forward compatibility with
 *     events this version does not know yet.
 *
 * @module dsh-proof/adapters/claude-code/entry
 */
export {};
//# sourceMappingURL=entry.d.ts.map