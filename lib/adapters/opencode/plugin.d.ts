/**
 * OpenCode host adapter — the three things the MCP tool face cannot do alone.
 *
 * OpenCode consumes dsh-proof's verification tools — the thirteen frozen MCP
 * names of the APP/1.4 contract (`MCP_TOOLS` in src/app/mcp-server.ts; the
 * five-name APP/1.0 roster of proof_status/baseline/verify/claim/bundle grew
 * eight more since) — through the MCP server configured in `opencode.json`
 * (see `examples/opencode.json`). What MCP cannot give it is host-side
 * enforcement, so this plugin hooks the OpenCode plugin API for exactly three
 * jobs:
 *
 *   1. `tool.execute.before` — the front door: evidence-store guard + baseline
 *      gate (the same two gates the DSH adapter installs on `tools/pre-execute`).
 *   2. `tool.execute.after`  — post-observation: which files tool calls actually
 *      moved, fingerprinted for drift detection (provenance).
 *   3. `chat.params`         — policy injection: the `proof:policy` section plus
 *      the MCP tool names, appended to the assembled chat parameters.
 *
 * The OpenCode plugin API is explicitly still evolving (upstream warns about
 * breaking changes), so the core design principle here is **runtime
 * duck-typing + graceful degradation**: every surface is probed with
 * `typeof`/shape checks (`vendor.ts` narrowers), every registered handler and
 * every registration call is wrapped in try/catch, and a surface that does
 * not match simply stays idle with one stderr line. The adapter NEVER throws
 * into the host — the MCP tools keep working regardless of what this plugin
 * could or could not hook.
 *
 * Semantic differences vs the Claude Code adapter (deliberate, documented):
 *
 *   - Drift anchor: Claude Code has a Stop hook, so drift is checked when the
 *     turn tries to end. OpenCode has none, so `ocBeforeHandler` opportunistically
 *     runs the drift check ahead of EVERY tool call ("the next tool call is the
 *     anchor"): the first call after external changes is held with the drift
 *     narrative, the model re-reads the stale files (the read observation
 *     refreshes the fingerprint), and subsequent calls pass. Each distinct
 *     drift set is surfaced at most once per plugin lifetime to avoid holding
 *     every call forever when the message is ignored. The one-time baseline/verify
 *     notices (the shared layer's turn-end rules) surface at the same anchor, once
 *     per session — a held call is the only channel a before hook gives this
 *     adapter for reaching the model.
 *   - Interception shape: Claude Code hooks block via exit code 2 + stderr.
 *     OpenCode's before hook has no stable interception contract, so a held
 *     call returns `{ error: { message } }` (the most commonly documented
 *     form) AND explains itself on stderr — whichever one the running OpenCode
 *     version honors, the model sees the reason.
 *   - `ask` semantics: the shared gate's `ask` decision (route through user
 *     approval) cannot be expressed in OpenCode's before hook, so `ask` and
 *     `deny` both hold the call; `deny` additionally marks the reason as a
 *     refusal. There is no approval round-trip on this host — a held call is
 *     held, and the reason tells the model what to do instead. The one carve-
 *     out is the trusted MCP face: `proof_*` tool names never enter the
 *     baseline ladder (see {@link isProofMcpToolName}), because holding the
 *     only tool that can establish a baseline is a deadlock, not a gate.
 *
 * @module dsh-proof/adapters/opencode/plugin
 */
import type { ProofPaths } from '../shared/paths.ts';
import type { GateOptions } from '../shared/gates.ts';
export interface OcAdapterOptions {
    /** Workspace root to verify. Default: `$DSH_PROOF_ROOT`, then the ctx directory, then cwd. */
    root?: string;
    /** Host trust root (keys/anchors/sessions). Default: `$DSH_PROOF_TRUST_DIR`, then the shared layer's default. */
    trustRoot?: string;
    /** `'workspace'` puts the evidence store inside the project (guarded); `'host'` (default) keeps it outside. */
    evidenceStore?: string;
    /** Evidence directory relative to the root (workspace mode only; default `.proof`). */
    evidenceDir?: string;
    /** Baseline gate mode. Default `warn` (same as the DSH/config default). */
    requireBaseline?: 'off' | 'warn' | 'ask';
    /** Opportunistic drift checks at the next tool call. Default `true`. */
    driftDetection?: boolean;
    /** Turn-end enforcement facts (used by `ocTurnEndHandler`; not registered in v1). Default `true`. */
    enforceOnTurnEnd?: boolean;
    /** Clock for session window stamps (ISO strings). Default: real time. */
    now?: () => string;
    /** File reader (returns undefined for missing files). Default: real fs, utf8. */
    readFile?: (abs: string) => Promise<string | undefined>;
    /** Diagnostics sink, one line per call. Default: `process.stderr`. */
    stderr?: (line: string) => void;
}
/**
 * Everything the handlers need — the η-shared pieces plus this adapter's own
 * knobs. `hasBaseline` is a cache (refreshed before every gate decision and
 * after any `proof_*` tool call, so the injected prompt stays truthful without
 * an fs read per prompt render); `surfacedDrift` dedupes before-time drift
 * holds (and re-arms when the disk comes back clean — M-42). Structurally the
 * same record the Claude Code adapter builds, defined here so this layer
 * imports nothing from the claude-code directory.
 */
export interface OcAdapterEnv {
    readonly paths: ProofPaths;
    readonly gate: GateOptions;
    readonly driftDetection: boolean;
    readonly enforceTurnEnd: boolean;
    readonly now: () => string;
    readonly readFile: (abs: string) => Promise<string | undefined>;
    readonly stderr: (line: string) => void;
    /** Cached `baseline.json exists on disk` flag — see interface comment above. */
    hasBaseline: boolean;
    /**
     * Drift CONTENT fingerprints already held once at before-time. A drift set
     * is held once per plugin lifetime WHILE IT PERSISTS; once computeDrift
     * comes back clean (every member resolved), the set clears and the same
     * drift shape blocks again on recurrence — ignoring a hold is never a
     * permanent exemption.
     */
    readonly surfacedDrift: Set<string>;
    /**
     * W12-M4: has the "before payload shape not recognized" stderr line been
     * spent for this plugin lifetime? The same unrecognized shape repeats on
     * every call; the contract is ONE line, not one per call. Mutable state on
     * an otherwise readonly record — same licence as `hasBaseline`.
     */
    shapeDriftWarned?: boolean;
}
/**
 * Assemble the adapter environment. Environment variables honor the SAME
 * names and semantics as the Claude Code hooks and the MCP entry — parsed by
 * the shared `resolveAdapterEnv` (H-21/M-44): pre-v0.23 this adapter read
 * only ROOT/TRUST_DIR/EVIDENCE_STORE/REQUIRE_BASELINE from the host process
 * environment while the README promised one shared set, so `DSH_PROOF_DRIFT`,
 * `DSH_PROOF_ENFORCE_TURN_END` and `DSH_PROOF_EVIDENCE_DIR` silently did
 * nothing here. Options (opencode.json plugin options) still beat the
 * environment, which beats the code default.
 */
export declare function ocAdapterEnv(options: OcAdapterOptions, cwd: string): OcAdapterEnv;
export interface GuessedToolCall {
    readonly tool: string | undefined;
    readonly args: unknown;
    readonly sessionId: string | undefined;
}
/**
 * Guess `{ tool, args, sessionId }` from a hook payload:
 *   - tool name: `tool` / `name` / `toolName` as strings, then a nested
 *     `tool.name` when `tool` is an object;
 *   - args: `arguments` / `args` / `input`, first one present;
 *   - session: `sessionID` / `session_id`.
 */
export declare function guessToolCall(input: unknown): GuessedToolCall;
/**
 * Trusted-MCP-face test (W20-H4 / W12-F3): is this tool name one of dsh-proof's
 * own `proof_*` MCP tools?
 *
 * CONTRACT with the observe classifier (G5's domain, src/dsh/observe.ts):
 * `isMutationToolName` is being taught that `proof_`-prefixed names are NOT
 * mutations — the MCP tools write through the server process, never through
 * host tool arguments, so the mutation charge buys nothing there. Until (and
 * after — this arm is the defense-in-depth) that lands, THIS consumer exempts
 * them from the baseline ladder itself: `decidePreToolUse` is handed
 * `hasBaseline: undefined` ("unknown") for a proof_* call, and the ask rule
 * (rule 2) never fires on "unknown". The DENY arms (evidence-store guard,
 * shell sweep) stay fully armed — the exemption opens the rescue hatch, not
 * the door.
 *
 * Why the exemption must exist at all: on OpenCode the before hook sees EVERY
 * tool call (no matcher), and `ask`/`deny` both HOLD. Under
 * `requireBaseline:'ask'` with no baseline, `proof_baseline` itself was held
 * by a gate whose hold reason said "Establish one first with the proof_baseline
 * MCP tool" — the remedy held itself, and the agent could never self-rescue
 * (only a human writing a baseline file outside the tools would release it,
 * and in workspace mode even that route is command-swept). Claude Code does
 * not deadlock this way (`ask` there is a real approval round-trip, and the
 * example matchers keep MCP names out of the hook), which is why this fix is
 * OpenCode-side only.
 *
 * Name matching: OpenCode spells MCP tools by their server-declared name
 * (`proof_baseline`); a host that namespaces imported tools (Claude Code's
 * `mcp__proof__proof_baseline`) carries the server-declared name as the last
 * `__`-separated segment, so both spellings are honored.
 */
export declare function isProofMcpToolName(name: string): boolean;
export declare function sanitizeBlockForModel(text: string): string;
/**
 * The front door. Returns `{ block }` to hold the call (mapped by the plugin
 * wrapper into OpenCode's `{ error: { message } }` form), or `undefined` to
 * let it through.
 *
 * Order of business:
 *   1. the shared turn-end evaluation runs opportunistically (OpenCode's only
 *      reliable anchor is the next tool call — see the module comment): each
 *      distinct drift set is held once per plugin lifetime, the one-time
 *      baseline/verify notices once per session, and fire ids are paid into
 *      the session ledger before anything is surfaced;
 *   2. the evidence-store guard + baseline gate via the shared `decidePreToolUse`
 *      (`ask` and `deny` both hold here — no approval round-trip on this host;
 *      a `deny` is marked as a refusal in the text).
 */
export declare function ocBeforeHandler(env: OcAdapterEnv, input: unknown): Promise<{
    block?: string;
} | undefined>;
/**
 * Post-observation: apply the shared observation (touched/read split +
 * fingerprints) to the session and persist it. A payload without a guessable
 * session id is a no-op — there is nowhere durable to put the observation.
 * Never blocks, never throws.
 */
export declare function ocAfterHandler(env: OcAdapterEnv, input: unknown): Promise<undefined>;
/**
 * Turn-end evaluation: full drift + enforcement facts, `windowStart` to roll
 * the observation window. NOT registered in v1 — OpenCode exposes no Stop
 * hook and its event bus shape is not stable enough to guess. Exported so a
 * future version (or an e2e harness that can simulate turn ends) gets the
 * same semantics the Claude Code adapter's Stop hook has; until then drift
 * enforcement rides `ocBeforeHandler`'s next-call anchor instead.
 */
export declare function ocTurnEndHandler(env: OcAdapterEnv, sessionId: string | undefined): Promise<{
    block?: string;
} | undefined>;
/**
 * The system-prompt addition: the canonical `proof:policy` section plus the
 * host-specific note that the proof tools ride an MCP server here.
 * Injected through `chat.params` when that seam exists; exported regardless
 * so an e2e harness can assert what WOULD be injected.
 */
export declare function buildSystemPromptAddition(env: OcAdapterEnv): string;
/**
 * Build the plugin initializer. Probe a context, register on every surface
 * that duck-types into a known shape, and never let the host see an
 * exception. Returns `(ctx) => Promise<{ dispose }>`; `dispose` revokes what
 * it can (a registrar that handed back an unregister function gets it called).
 */
export declare function createOpencodePlugin(options?: OcAdapterOptions): (ctx: unknown) => Promise<{
    dispose: () => void;
}>;
declare const _default: (ctx: unknown) => Promise<{
    dispose: () => void;
}>;
export default _default;
//# sourceMappingURL=plugin.d.ts.map