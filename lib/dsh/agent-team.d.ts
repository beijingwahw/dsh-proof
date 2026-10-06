/**
 * DSH-side bridge for the host's EXPERIMENTAL agent-team surface (v0.19).
 *
 * The responsibility DAG (delegateTask / submitDelegation / taskVerdict /
 * waiveDelegation) is engine-side and settled; what is NOT settled is the
 * host's event vocabulary for "an agent just delegated a subtask to another
 * agent" — no released `@deepseek-ai/*` type declares it yet. The v0.15
 * OpenCode precedent is therefore applied wholesale here: **runtime
 * duck-typing + graceful degradation**.
 *
 *   - Every host event is narrowed from `unknown` (`normalizeTeamEvent`) —
 *     the same defensive discipline as `adapters/opencode/vendor.ts`: failure
 *     is `undefined`, never a throw, and a shape that cannot prove itself is
 *     skipped, not guessed at.
 *   - The bridge probes a short list of plausible event seams
 *     (`TEAM_EVENT_SEAMS`), each subscription wrapped in its own try/catch —
 *     cordis's behaviour for an undeclared event name is unknown, and one
 *     refusing registration must not take the others down with it.
 *   - A seam hit means the delegation is mirrored onto the chain as a signed
 *     obligation (deps.delegate → engine delegateTask) and the worker's
 *     handoff instruction is written back into the event's payload object
 *     where the host can ship it to the child. No mutable payload channel →
 *     one stderr line naming taskId + obligationId for manual wiring.
 *   - NOTHING here ever throws into the host: a bridge failure degrades to a
 *     stderr line, and the plugin's own tools (proof_delegate & friends) keep
 *     working as the first-class path.
 *
 * The whole feature is opt-in (`agentTeamBridge`, default false) — an
 * experimental seam must not surprise deployments that never asked for it.
 *
 * @module dsh-proof/dsh/agent-team
 */
/**
 * What a host delegation event narrows down to. Every field except `kind` is
 * optional and untyped on purpose: the host vocabulary is unknown, so the
 * bridge records what it could prove (a text field, id fields, a mutable
 * payload object) and narrows again at the point of use — never inventing a
 * value the event did not carry.
 */
export interface TeamBridgeEvent {
    kind: 'delegated';
    /** The new (child) task's identity, as the host spelled it. */
    taskId?: unknown;
    /** The delegation's parent task, when the host named one. */
    parentTaskId?: unknown;
    /** The obligation text, when found under a `claim` key. */
    claim?: unknown;
    /** The child's instructions, when found under `prompt`/`task`/`description`. */
    prompt?: unknown;
    /** The event's mutable payload object — the write-back channel, when present. */
    payload?: Record<string, unknown>;
}
/**
 * Narrow an untrusted host event into a {@link TeamBridgeEvent}.
 *
 * The walk descends through nested plain objects (any key — `toolInput`,
 * `event`, `payload`, whatever the host's dialect calls the envelope) within
 * a depth/object budget, collecting:
 *
 *   - the first string found under each of `claim` / `prompt` / `task` /
 *     `description` — later resolved by precedence (claim wins; the rest ride
 *     the `prompt` channel, which is what they are: the child's instructions);
 *   - the first `taskId` / `parentTaskId` values, kept verbatim as `unknown`;
 *   - the first plain object found under a `payload` key — the write-back
 *     channel for the handoff instruction.
 *
 * An event with no locatable text is not a recognizable delegation:
 * `undefined`, silently. Same for non-objects, null, primitives, cycles (a
 * visited set guards them) — failure is always `undefined`, never a throw.
 */
export declare function normalizeTeamEvent(raw: unknown): TeamBridgeEvent | undefined;
/**
 * What the bridge needs from its host. `delegate` is the engine's
 * `delegateTask` (or a test double); `instructionOf` renders the worker's
 * handoff text (index.ts's template, worded after the MCP `proof_delegate`
 * face); `stderr` receives the degradation lines, one at a time. `mark`
 * (wired by index.ts to the engine's store) lands the bridge's own
 * observation markers on the tamper-evident chain — the parent-edge losses
 * and id mappings below are chain facts, not stderr ephemera.
 */
export interface TeamBridgeDeps {
    delegate: (input: {
        claim: string;
        parentTaskId?: string;
        acceptance?: string;
    }) => Promise<{
        taskId: string;
        obligationId: string;
        obligation: unknown;
    }>;
    instructionOf: (taskId: string, obligationId: string, claim: string) => string;
    stderr?: (line: string) => void;
    /** Best-effort observation marker onto the chain; absent = no chain access. */
    mark?: (label: string, payload: Record<string, unknown>) => Promise<void>;
    /**
     * W7-M9 (v0.23): the bridge's own persisted id mappings, read back from the
     * chain — the `agent-team/delegated` markers as (hostTaskId, engineTaskId)
     * pairs. Consulted lazily, once, before the first parent-edge lookup: the
     * mapping used to live only in bridge-private memory, so a restarted
     * process (host reload, crash recovery) forgot every edge its predecessor
     * minted and re-minted the affected delegations as roots — the mapping was
     * persisted precisely so this read-back could happen. Absent = no chain
     * read seam and the bridge keeps the historical amnesia.
     */
    mappings?: () => Promise<ReadonlyArray<{
        readonly hostTaskId: string;
        readonly engineTaskId: string;
    }>>;
}
/**
 * The event names this bridge recognizes as "the host delegated a subtask" —
 * the plausible spellings of a still-unreleased agent-team API. Probed in
 * order; the first one the host accepts is enough.
 */
export declare const TEAM_EVENT_SEAMS: readonly ["agent/team:delegated", "agent/delegation", "team/task-created", "agent/subtask"];
/**
 * Build the bridge: `onEvent` accepts a raw host event (unnormalized), and
 * `seams` carries the event names it expects to be fed from.
 *
 * H-12 (v0.23): the host's task vocabulary and the engine's `task-N` ids are
 * DIFFERENT namespaces, and the bridge no longer pretends otherwise. A host
 * `parentTaskId` is translated through the hostId→engineId map the bridge
 * maintains (every delegation it mints records the mapping, on-chain when a
 * `mark` channel exists); an unmapped parent — including one that merely
 * LOOKS like `task-N`, which could coincide with an engine id minted for an
 * unrelated task — is never cast into the engine namespace. The obligation is
 * still minted, as a root, and the lost parent edge is recorded loudly
 * (stderr + observation marker) with the host's own id spelled out for
 * manual re-linking. Silent wrong edges and silent lost obligations were the
 * two failure modes; both are now visible.
 *
 * `onEvent` never throws and never rejects: an unrecognizable event returns
 * silently, a delegation failure degrades to a stderr line, and a frozen or
 * absent payload channel degrades to a stderr handoff (taskId + obligationId)
 * for manual wiring. The same event object delivered twice — a host fanning
 * one delegation out to several subscribed seams — is deduped by identity, so
 * one delegation is one obligation on the chain.
 */
export declare function createTeamBridge(deps: TeamBridgeDeps): {
    onEvent: (raw: unknown) => Promise<void>;
    seams: string[];
};
/**
 * Subscribe the bridge to every seam the host will accept. Each registration
 * is wrapped in its own try/catch — cordis's behaviour for an undeclared
 * event name is unknown, and a single refusing registration must leave the
 * others untouched. Returns true when at least one seam subscribed; false
 * (with one stderr line, when a sink is given) otherwise. A `ctx` without a
 * callable `on` is the same clean false.
 */
export declare function attachTeamBridge(ctx: unknown, bridge: {
    onEvent: (raw: unknown) => Promise<void>;
    seams: string[];
}, stderr?: (line: string) => void): boolean;
//# sourceMappingURL=agent-team.d.ts.map