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
import { ccAdapterEnv, handlePostToolUse, handlePreToolUse, handleSessionStart, handleStop } from "./hooks.js";
const EVENTS = ['pre-tool-use', 'post-tool-use', 'stop', 'session-start'];
/** A one-line PreToolUse `ask` — the conservative answer a gate gives when it cannot decide. */
function preAsk(reason) {
    return `${JSON.stringify({
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'ask',
            permissionDecisionReason: reason,
        },
    })}\n`;
}
/**
 * Read stdin with a size cap and a deadline (B3-L2). Claude Code writes one
 * JSON object and closes the pipe; a host that never ends (or an upstream
 * pipe fault that floods) must not hang the hook until the host's own
 * timeout or grow the buffer without bound. On either limit we take what
 * arrived: a truncated payload fails JSON.parse downstream, and for
 * pre-tool-use that honestly answers `ask` — a gate that cannot read its
 * input must not wave the mutation through.
 *
 * The cap counts real BYTES (W12-L10): the pre-v0.24 check compared
 * `buffer.length` against a constant named *_BYTES, but a JS string's length
 * counts UTF-16 code units — a CJK-heavy payload could buffer ~8 million
 * bytes before tripping a "4 MB" cap. The limit and the fail-closed posture
 * were never wrong; only the label was.
 */
const STDIN_LIMIT_BYTES = 4 * 1024 * 1024;
const STDIN_DEADLINE_MS = 10_000;
function readStdin() {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        if (stdin.readableEnded) {
            resolve('');
            return;
        }
        stdin.setEncoding('utf8');
        let buffer = '';
        let receivedBytes = 0;
        let settled = false;
        const settle = () => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            try {
                stdin.destroy();
            }
            catch {
                /* already gone */
            }
            resolve(buffer);
        };
        const timer = setTimeout(settle, STDIN_DEADLINE_MS);
        stdin.on('data', (chunk) => {
            if (settled)
                return;
            buffer += chunk;
            receivedBytes += Buffer.byteLength(chunk, 'utf8');
            if (receivedBytes > STDIN_LIMIT_BYTES)
                settle();
        });
        stdin.on('end', settle);
        stdin.on('error', settle);
    });
}
async function main() {
    // Read stdin first, whatever the event: an early exit that leaves the host's
    // pipe unread is noise on the spawning side, silence on ours.
    const raw = await readStdin();
    const arg = process.argv[2];
    if (!EVENTS.includes(arg))
        return; // unknown event: silent, forward-compatible
    let payload;
    try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
            throw new Error('payload is not a JSON object');
        payload = parsed;
    }
    catch {
        if (arg === 'pre-tool-use')
            writeOut(preAsk('dsh-proof: gate could not parse the hook payload'));
        return;
    }
    // Claude Code sets the hook process's cwd to the project directory, and the
    // payload repeats it; trust the payload, fall back to the process.
    const cwd = typeof payload.cwd === 'string' && payload.cwd.length > 0 ? payload.cwd : process.cwd();
    const env = ccAdapterEnv(process.env, cwd);
    let result;
    switch (arg) {
        case 'pre-tool-use':
            result = await handlePreToolUse(payload, env);
            break;
        case 'post-tool-use':
            await handlePostToolUse(payload, env);
            result = undefined;
            break;
        case 'stop':
            result = await handleStop(payload, env);
            break;
        case 'session-start':
            result = await handleSessionStart(payload, env);
            break;
    }
    if (result !== undefined)
        writeOut(`${JSON.stringify(result)}\n`);
}
// A closed stdout (EPIPE when the host has already gone away) turns
// process.stdout.write into an 'error' event that, unhandled, exits non-zero
// — breaking the "exit 0 always" contract for nothing the host can use.
// The answer is best-effort; silence is already the protocol's no-action.
process.stdout.on('error', () => { });
// W12-L11: the same holds for stderr — console.error and process.stderr.write
// after the host closed the pipe raise the same unhandled 'error' event, and
// a diagnostics sink must never be the thing that breaks exit-0-always.
process.stderr.on('error', () => { });
function writeOut(line) {
    try {
        process.stdout.write(line);
    }
    catch {
        /* EPIPE after the host left — exit 0 regardless */
    }
}
main().catch((error) => {
    // Exit 0 regardless: the protocol speaks through stdout, and a dead hook
    // must not look like a denied tool call. Only the gate answers, with `ask`.
    if (process.argv[2] === 'pre-tool-use') {
        writeOut(preAsk('dsh-proof: gate internal error'));
        return;
    }
    console.error(`[dsh-proof-cc] ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
});
//# sourceMappingURL=entry.js.map