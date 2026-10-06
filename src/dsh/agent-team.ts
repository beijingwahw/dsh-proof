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

// ---------------------------------------------------------------------------
// The normalized event
// ---------------------------------------------------------------------------

/**
 * What a host delegation event narrows down to. Every field except `kind` is
 * optional and untyped on purpose: the host vocabulary is unknown, so the
 * bridge records what it could prove (a text field, id fields, a mutable
 * payload object) and narrows again at the point of use — never inventing a
 * value the event did not carry.
 */
export interface TeamBridgeEvent {
  kind: 'delegated'
  /** The new (child) task's identity, as the host spelled it. */
  taskId?: unknown
  /** The delegation's parent task, when the host named one. */
  parentTaskId?: unknown
  /** The obligation text, when found under a `claim` key. */
  claim?: unknown
  /** The child's instructions, when found under `prompt`/`task`/`description`. */
  prompt?: unknown
  /** The event's mutable payload object — the write-back channel, when present. */
  payload?: Record<string, unknown>
}

/** Keys whose string values can name the delegated work, in preference order. */
const TEXT_KEYS = ['claim', 'prompt', 'task', 'description'] as const

/** How deep into nested `toolInput`/`event`/`payload`/… objects to search. */
const MAX_DEPTH = 4
/** Hard cap on objects visited per event — a hostile payload cannot stall the walk. */
const MAX_OBJECTS = 64

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** A non-empty (whitespace-trimmed) string, or nothing. Blank text is no text. */
function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined
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
export function normalizeTeamEvent(raw: unknown): TeamBridgeEvent | undefined {
  if (!isPlainObject(raw)) return undefined
  const texts = new Map<string, string>()
  let taskId: unknown
  let parentTaskId: unknown
  let payload: Record<string, unknown> | undefined
  const visited = new Set<unknown>()
  let level: Record<string, unknown>[] = [raw]
  for (let depth = 0; depth <= MAX_DEPTH && level.length > 0; depth += 1) {
    const next: Record<string, unknown>[] = []
    for (const obj of level) {
      if (visited.has(obj)) continue
      visited.add(obj)
      if (visited.size > MAX_OBJECTS) break
      for (const key of TEXT_KEYS) {
        if (texts.has(key)) continue
        const text = nonEmptyString(obj[key])
        if (text !== undefined) texts.set(key, text)
      }
      if (taskId === undefined) {
        const found = obj.taskId
        if (found !== undefined) taskId = found
      }
      if (parentTaskId === undefined) {
        const found = obj.parentTaskId
        if (found !== undefined) parentTaskId = found
      }
      if (payload === undefined && isPlainObject(obj.payload)) payload = obj.payload
      for (const value of Object.values(obj)) {
        if (isPlainObject(value) && !visited.has(value)) next.push(value)
      }
    }
    level = next
  }
  const claim = texts.get('claim')
  const prompt = texts.get('prompt') ?? texts.get('task') ?? texts.get('description')
  if (claim === undefined && prompt === undefined) return undefined
  return {
    kind: 'delegated',
    ...(taskId !== undefined ? { taskId } : {}),
    ...(parentTaskId !== undefined ? { parentTaskId } : {}),
    ...(claim !== undefined ? { claim } : {}),
    ...(prompt !== undefined ? { prompt } : {}),
    ...(payload !== undefined ? { payload } : {}),
  }
}

// ---------------------------------------------------------------------------
// The bridge
// ---------------------------------------------------------------------------

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
  delegate: (input: { claim: string; parentTaskId?: string; acceptance?: string }) => Promise<{
    taskId: string
    obligationId: string
    obligation: unknown
  }>
  instructionOf: (taskId: string, obligationId: string, claim: string) => string
  stderr?: (line: string) => void
  /** Best-effort observation marker onto the chain; absent = no chain access. */
  mark?: (label: string, payload: Record<string, unknown>) => Promise<void>
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
  mappings?: () => Promise<ReadonlyArray<{ readonly hostTaskId: string; readonly engineTaskId: string }>>
}

/**
 * The event names this bridge recognizes as "the host delegated a subtask" —
 * the plausible spellings of a still-unreleased agent-team API. Probed in
 * order; the first one the host accepts is enough.
 */
export const TEAM_EVENT_SEAMS = [
  'agent/team:delegated', 'agent/delegation', 'team/task-created', 'agent/subtask',
] as const

/** A delegation claim is capped at 500 characters — an event prompt is not a spec. */
const CLAIM_LIMIT = 500

/**
 * The claim text an event yields: its `claim` field, else its `prompt`
 * (which is what a `task`/`description` field narrows to). Trimmed, and
 * truncated to 500 characters so a whole child prompt cannot become the
 * obligation's content address input.
 *
 * V6-L13 (v0.24): the truncation is LOUD — the cut text carries a baked-in
 * flag naming the original length, the same discipline as the DSH tools'
 * `capToolString`. A silent slice made an obligation's claim LOOK complete on
 * the chain while the host event had said more; the flag is a chain fact the
 * reader can see without the event.
 */
function claimOf(event: TeamBridgeEvent): string | undefined {
  const raw = typeof event.claim === 'string'
    ? event.claim
    : typeof event.prompt === 'string' ? event.prompt : undefined
  if (raw === undefined) return undefined
  const text = raw.trim()
  if (text.length === 0) return undefined
  return text.length > CLAIM_LIMIT
    ? `${text.slice(0, CLAIM_LIMIT)}…[claim truncated from ${text.length} chars]`
    : text
}

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
export function createTeamBridge(deps: TeamBridgeDeps): {
  onEvent: (raw: unknown) => Promise<void>
  seams: string[]
} {
  const seen = new WeakSet<object>()
  /** Host task id → engine task id, for every obligation this bridge minted. */
  const hostToEngine = new Map<string, string>()
  /**
   * W7-M9: one-shot rehydration of the persisted mappings. The chain list is
   * in append order (oldest first), and V6-L13 (v0.24) makes rehydration
   * apply it with NEWEST-WINS — an unconditional `set` — so a host that
   * REUSES a hostTaskId gets the same answer fresh and restarted: the mapping
   * this process would overwrite in flight (line: `hostToEngine.set(...)`
   * after every mint) is the same one the chain's LAST marker for that id
   * supplies on rehydrate. The pre-fix `set`-if-absent let the OLDEST marker
   * win offline while the NEWEST won in-process — a restarted bridge quietly
   * re-linked a reused id's children to the superseded obligation. A failed
   * read rehydrates nothing and never throws — the bridge then behaves
   * exactly as it did before the chain grew a memory.
   */
  let rehydrated: Promise<void> | undefined
  const ensureMappings = (): Promise<void> => {
    if (rehydrated === undefined) {
      rehydrated = (async () => {
        if (deps.mappings === undefined) return
        try {
          for (const pair of await deps.mappings()) {
            hostToEngine.set(pair.hostTaskId, pair.engineTaskId)
          }
        } catch {
          /* an unreadable chain rehydrates nothing; see above */
        }
      })()
    }
    return rehydrated
  }
  /**
   * W7-M10: a `mark` that rejects must not take the delegation down with it.
   * Both marker writes used to sit inside the outer try — a rejecting chain
   * write was swallowed by the blanket catch and the obligation lived on
   * with NO chain fact and NO stderr line: a silent orphan. Degrade loudly
   * instead; the delegation itself stands either way.
   */
  const markBestEffort = async (label: string, payload: Record<string, unknown>): Promise<void> => {
    if (deps.mark === undefined) return
    try {
      await deps.mark(label, payload)
    } catch (error) {
      deps.stderr?.(
        `dsh-proof: agent-team bridge could not record the ${label} observation marker `
        + `(${error instanceof Error ? error.message : String(error)}) — the delegation stands, `
        + 'but its chain fact is missing; re-check the obligation on the chain manually',
      )
    }
  }
  return {
    seams: [...TEAM_EVENT_SEAMS],
    onEvent: async (raw: unknown): Promise<void> => {
      try {
        if (typeof raw === 'object' && raw !== null) {
          if (seen.has(raw)) return
          seen.add(raw)
        }
        const event = normalizeTeamEvent(raw)
        if (event === undefined) return
        const claim = claimOf(event)
        if (claim === undefined) return
        await ensureMappings()
        const hostParentTaskId = typeof event.parentTaskId === 'string' && event.parentTaskId.length > 0
          ? event.parentTaskId
          : undefined
        const hostTaskId = typeof event.taskId === 'string' && event.taskId.length > 0
          ? event.taskId
          : undefined
        // H-12: translate the parent edge through the mapping — never trust
        // shape coincidence between the two id namespaces.
        let parentTaskId: string | undefined
        let lostParent: { hostParentTaskId: string; reason: string } | undefined
        if (hostParentTaskId !== undefined) {
          const mapped = hostToEngine.get(hostParentTaskId)
          if (mapped !== undefined) {
            parentTaskId = mapped
          } else {
            // Unmapped. If it coincides with an engine id this bridge minted
            // for a different host task, say so — that is the collision that
            // used to mint a wrong signed parent edge.
            let coincidence: string | undefined
            for (const [host, engine] of hostToEngine) {
              if (engine === hostParentTaskId && host !== hostParentTaskId) {
                coincidence = `coincides with the engine id minted for host task ${JSON.stringify(host)}`
                break
              }
            }
            lostParent = {
              hostParentTaskId,
              reason: coincidence ?? 'no host task with this id was delegated through this bridge',
            }
          }
        }
        if (lostParent !== undefined) {
          deps.stderr?.(
            `dsh-proof: agent-team bridge could not translate parentTaskId `
            + `${JSON.stringify(lostParent.hostParentTaskId)} (${lostParent.reason}) — the obligation below is `
            + `minted as a ROOT; re-link it manually if the parent edge matters`,
          )
        await markBestEffort('agent-team/parent-unmapped', {
          hostParentTaskId: lostParent.hostParentTaskId,
          reason: lostParent.reason,
          claim: claim.slice(0, 200),
        })
        }
        let minted: { taskId: string; obligationId: string; obligation: unknown }
        try {
          minted = await deps.delegate({ claim, ...(parentTaskId !== undefined ? { parentTaskId } : {}) })
        } catch (error) {
          deps.stderr?.(
            `dsh-proof: agent-team bridge could not record the delegation "${claim.slice(0, 80)}" — `
            + `${error instanceof Error ? error.message : String(error)}`,
          )
          return
        }
        // Record the namespace mapping so later host events (a grandchild, a
        // verdict) can find this obligation — and so the mapping itself is a
        // chain fact, not bridge-private memory (W7-M9: a successor process
        // reads exactly this marker back to re-adopt the edge).
        if (hostTaskId !== undefined) {
          hostToEngine.set(hostTaskId, minted.taskId)
          await markBestEffort('agent-team/delegated', {
            hostTaskId,
            engineTaskId: minted.taskId,
            obligationId: minted.obligationId,
          })
        }
        const instruction = deps.instructionOf(minted.taskId, minted.obligationId, claim)
        const payload = event.payload
        if (isPlainObject(payload)) {
          try {
            payload.proofObligation = instruction
            if (typeof payload.instructions === 'string') payload.instructions = instruction
            return
          } catch {
            // Frozen/sealed payload — fall through to the stderr handoff; the
            // obligation exists on the chain and must not be silently orphaned.
          }
        }
        deps.stderr?.(
          `dsh-proof: agent-team delegation recorded as ${minted.taskId} `
          + `(obligation ${minted.obligationId}) — the host event carried no mutable payload; `
          + 'paste the proof_delegate instruction into the subtask manually',
        )
      } catch {
        // Defense in depth: nothing the host handed us may ever throw out of here.
      }
    },
  }
}

// ---------------------------------------------------------------------------
// The seam probe
// ---------------------------------------------------------------------------

/** The one-line degradation notice when no seam could be subscribed. */
const NO_SEAM_MESSAGE = 'dsh-proof: no agent-team delegation seam found (experimental API) '
  + '— use proof_delegate via MCP/engine directly'

/**
 * Subscribe the bridge to every seam the host will accept. Each registration
 * is wrapped in its own try/catch — cordis's behaviour for an undeclared
 * event name is unknown, and a single refusing registration must leave the
 * others untouched. Returns true when at least one seam subscribed; false
 * (with one stderr line, when a sink is given) otherwise. A `ctx` without a
 * callable `on` is the same clean false.
 */
export function attachTeamBridge(
  ctx: unknown,
  bridge: { onEvent: (raw: unknown) => Promise<void>; seams: string[] },
  stderr?: (line: string) => void,
): boolean {
  const candidate = (typeof ctx === 'object' || typeof ctx === 'function') && ctx !== null
    ? (ctx as { on?: unknown })
    : undefined
  const on = candidate?.on
  if (typeof on !== 'function') {
    stderr?.(NO_SEAM_MESSAGE)
    return false
  }
  const registrar = on as (event: string, handler: (raw: unknown) => unknown) => unknown
  let attached = false
  for (const seam of bridge.seams) {
    try {
      // The handler returns the bridge's promise (which never rejects); a
      // host that ignores returned promises is equally fine — the delegation
      // ride-along must never gate the host's own event dispatch.
      registrar.call(ctx, seam, (raw: unknown) => bridge.onEvent(raw))
      attached = true
    } catch {
      // This seam is not spoken here — try the next.
    }
  }
  if (!attached) {
    stderr?.(NO_SEAM_MESSAGE)
    return false
  }
  return true
}
