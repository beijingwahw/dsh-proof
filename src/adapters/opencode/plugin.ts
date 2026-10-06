/**
 * OpenCode host adapter — the three things the MCP tool face cannot do alone.
 *
 * OpenCode consumes dsh-proof's five verification tools (`proof_status`,
 * `proof_baseline`, `proof_verify`, `proof_claim`, `proof_bundle`) through the
 * MCP server configured in `opencode.json` (see `examples/opencode.json`).
 * What MCP cannot give it is host-side enforcement, so this plugin hooks the
 * OpenCode plugin API for exactly three jobs:
 *
 *   1. `tool.execute.before` — the front door: evidence-store guard + baseline
 *      gate (the same two gates the DSH adapter installs on `tools/pre-execute`).
 *   2. `tool.execute.after`  — post-observation: which files tool calls actually
 *      moved, fingerprinted for drift detection (provenance).
 *   3. `chat.params`         — policy injection: the `proof:policy` section plus
 *      the five MCP tool names, appended to the assembled chat parameters.
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
 *     held, and the reason tells the model what to do instead.
 *
 * @module dsh-proof/adapters/opencode/plugin
 */

import { promises as fsp } from 'node:fs'

import { buildPolicySection } from '../../dsh/prompt.ts'
import { MCP_TOOLS } from '../../app/mcp-server.ts'
import { asAfter, asBefore, asPluginContext, directoryOf } from './vendor.ts'
import { deriveProofPaths } from '../shared/paths.ts'
import type { ProofPaths } from '../shared/paths.ts'
import { applyObservation, computeDrift, emptySession, loadSession, saveSession, windowStart } from '../shared/session.ts'
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from '../shared/gates.ts'
import type { GateOptions, StopFacts } from '../shared/gates.ts'

// ---------------------------------------------------------------------------
// Options and the adapter environment
// ---------------------------------------------------------------------------

export interface OcAdapterOptions {
  /** Workspace root to verify. Default: `$DSH_PROOF_ROOT`, then the ctx directory, then cwd. */
  root?: string
  /** Host trust root (keys/anchors/sessions). Default: `$DSH_PROOF_TRUST_DIR`, then the shared layer's default. */
  trustRoot?: string
  /** `'workspace'` puts the evidence store inside the project (guarded); `'host'` (default) keeps it outside. */
  evidenceStore?: string
  /** Evidence directory relative to the root (workspace mode only; default `.proof`). */
  evidenceDir?: string
  /** Baseline gate mode. Default `warn` (same as the DSH/config default). */
  requireBaseline?: 'off' | 'warn' | 'ask'
  /** Opportunistic drift checks at the next tool call. Default `true`. */
  driftDetection?: boolean
  /** Turn-end enforcement facts (used by `ocTurnEndHandler`; not registered in v1). Default `true`. */
  enforceOnTurnEnd?: boolean
  /** Clock for session window stamps (ISO strings). Default: real time. */
  now?: () => string
  /** File reader (returns undefined for missing files). Default: real fs, utf8. */
  readFile?: (abs: string) => Promise<string | undefined>
  /** Diagnostics sink, one line per call. Default: `process.stderr`. */
  stderr?: (line: string) => void
}

/**
 * Everything the handlers need — the η-shared pieces plus this adapter's own
 * knobs. `hasBaseline` is a cache (refreshed before every gate decision and
 * after any `proof_*` tool call, so the injected prompt stays truthful without
 * an fs read per prompt render); `surfacedDrift` dedupes before-time drift
 * holds. Structurally the same record the Claude Code adapter builds, defined
 * here so this layer imports nothing from the claude-code directory.
 */
export interface OcAdapterEnv {
  readonly paths: ProofPaths
  readonly gate: GateOptions
  readonly driftDetection: boolean
  readonly enforceTurnEnd: boolean
  readonly now: () => string
  readonly readFile: (abs: string) => Promise<string | undefined>
  readonly stderr: (line: string) => void
  /** Cached `baseline.json exists on disk` flag — see interface comment above. */
  hasBaseline: boolean
  /** Drift sets already held once at before-time, per plugin lifetime. */
  readonly surfacedDrift: Set<string>
}

function envString(name: string): string | undefined {
  const value = process.env[name]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function normalizeStore(value: string | undefined): 'host' | 'workspace' {
  return value === 'workspace' ? 'workspace' : 'host'
}

function normalizeRequireBaseline(value: string | undefined): 'off' | 'warn' | 'ask' {
  return value === 'off' || value === 'ask' ? value : 'warn'
}

const defaultNow = (): string => new Date().toISOString()

const defaultReadFile = async (abs: string): Promise<string | undefined> => {
  try {
    return await fsp.readFile(abs, 'utf8')
  } catch {
    return undefined
  }
}

const defaultStderr = (line: string): void => {
  process.stderr.write(`${line}\n`)
}

/**
 * Assemble the adapter environment. Environment variables honor the SAME
 * precedence the MCP entry (`src/app/mcp-entry.ts`) applies, so the plugin's
 * gates and the MCP server's tools always agree on where evidence lives —
 * a guard pointing at a different `.proof` than the server reads would be
 * decorative.
 */
export function ocAdapterEnv(options: OcAdapterOptions, cwd: string): OcAdapterEnv {
  const root = options.root ?? envString('DSH_PROOF_ROOT') ?? cwd
  const evidenceStore = normalizeStore(options.evidenceStore ?? envString('DSH_PROOF_EVIDENCE_STORE'))
  const paths = deriveProofPaths({
    root,
    trustRoot: options.trustRoot ?? envString('DSH_PROOF_TRUST_DIR'),
    evidenceStore,
    evidenceDir: options.evidenceDir,
  })
  return {
    paths,
    gate: {
      evidenceStore: paths.evidenceStore,
      evidenceDir: paths.evidenceDir,
      requireBaseline: normalizeRequireBaseline(
        options.requireBaseline ?? envString('DSH_PROOF_REQUIRE_BASELINE'),
      ),
    },
    driftDetection: options.driftDetection ?? true,
    enforceTurnEnd: options.enforceOnTurnEnd ?? true,
    now: options.now ?? defaultNow,
    readFile: options.readFile ?? defaultReadFile,
    stderr: options.stderr ?? defaultStderr,
    hasBaseline: false,
    surfacedDrift: new Set<string>(),
  }
}

// ---------------------------------------------------------------------------
// Input guessing — OpenCode's before/after hook payload shape is not pinned,
// so the tool name, arguments and session id are coaxed out of whichever keys
// are present. Never throws; missing pieces are simply undefined.
// ---------------------------------------------------------------------------

export interface GuessedToolCall {
  readonly tool: string | undefined
  readonly args: unknown
  readonly sessionId: string | undefined
}

function firstString(...values: readonly unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

/**
 * Guess `{ tool, args, sessionId }` from a hook payload:
 *   - tool name: `tool` / `name` / `toolName` as strings, then a nested
 *     `tool.name` when `tool` is an object;
 *   - args: `arguments` / `args` / `input`, first one present;
 *   - session: `sessionID` / `session_id`.
 */
export function guessToolCall(input: unknown): GuessedToolCall {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { tool: undefined, args: undefined, sessionId: undefined }
  }
  const record = input as Record<string, unknown>
  let tool = firstString(record.tool, record.name, record.toolName)
  if (tool === undefined && typeof record.tool === 'object' && record.tool !== null && !Array.isArray(record.tool)) {
    const nested = record.tool as Record<string, unknown>
    tool = firstString(nested.name, nested.toolName)
  }
  const args = record.arguments !== undefined ? record.arguments : record.args !== undefined ? record.args : record.input
  return {
    tool,
    args,
    sessionId: firstString(record.sessionID, record.session_id),
  }
}

// ---------------------------------------------------------------------------
// Handlers — separated from registration so each is directly testable
// ---------------------------------------------------------------------------

function driftKey(drift: { readonly drifted: readonly string[] }): string {
  return drift.drifted.join(' ')
}

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
export async function ocBeforeHandler(env: OcAdapterEnv, input: unknown): Promise<{ block?: string } | undefined> {
  const call = guessToolCall(input)
  if (call.tool === undefined && call.sessionId === undefined) return undefined

  // (1) drift + one-time notices, ahead of the gate — advisory: a broken
  //     check must never wedge the door.
  let heldNotice: string | undefined
  if (call.sessionId !== undefined) {
    try {
      const session = await loadSession(env.paths.sessionDir, call.sessionId)
      if (session !== undefined) {
        const drift = env.driftDetection
          ? await computeDrift(session, env.paths.root, env.readFile)
          : undefined
        const facts: StopFacts = {
          drift,
          touchedCount: session.touched.length,
          hasBaseline: env.hasBaseline,
          requireBaseline: env.gate.requireBaseline,
          // The turn has NOT ended here — the turn-end-only enforcement rule
          // stays off until OpenCode grows a stop seam (ocTurnEndHandler).
          enforceOnTurnEnd: false,
          driftDetection: env.driftDetection,
        }
        const verdict = evaluateStop(facts, session)
        // evaluateStop is pure: a fire id is this caller's ledger debt, paid
        // BEFORE the block is surfaced (a crash in between must not re-fire
        // the notice on the next call).
        if (verdict.fire !== undefined) {
          await saveSession(env.paths.sessionDir, call.sessionId, {
            ...session,
            firedNotices: [...session.firedNotices, verdict.fire],
          })
        }
        if (verdict.block !== undefined) {
          const drifted = drift !== undefined
            && (drift.drifted.length > 0 || drift.staleReads.length > 0)
          if (drifted) {
            // The shared gate blocks on drift EVERY time; on a host whose
            // only anchor is the next tool call that holds every subsequent
            // call hostage once the message is ignored. Each distinct drift
            // set is held exactly once per plugin lifetime. (The Claude Code
            // Stop hook needs no such cap — it fires once per real turn
            // boundary.)
            if (!env.surfacedDrift.has(driftKey(drift))) {
              heldNotice = verdict.block
              env.surfacedDrift.add(driftKey(drift))
            }
          } else {
            heldNotice = verdict.block
          }
        }
      }
    } catch {
      /* no drift opinion is better than a thrown one */
    }
  }

  // (2) the gate.
  let gateBlock: string | undefined
  if (call.tool !== undefined) {
    try {
      env.hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
    } catch {
      /* keep the cached flag; a failed stat is not a policy input */
    }
    const decision = decidePreToolUse(call.tool, call.args, env.paths.root, env.gate, env.hasBaseline)
    if (decision.action === 'deny') gateBlock = `denied — ${decision.reason}`
    else if (decision.action === 'ask') gateBlock = decision.reason
  }

  if (heldNotice === undefined && gateBlock === undefined) return undefined
  const parts = [gateBlock, heldNotice].filter((part): part is string => part !== undefined)
  return { block: parts.join('\n\n') }
}

/**
 * Post-observation: apply the shared observation (touched/read split +
 * fingerprints) to the session and persist it. A payload without a guessable
 * session id is a no-op — there is nowhere durable to put the observation.
 * Never blocks, never throws.
 */
export async function ocAfterHandler(env: OcAdapterEnv, input: unknown): Promise<undefined> {
  const call = guessToolCall(input)
  if (call.sessionId === undefined || call.tool === undefined) return undefined
  try {
    const session = (await loadSession(env.paths.sessionDir, call.sessionId)) ?? emptySession(env.now())
    const observed = await applyObservation(session, call.tool, call.args, env.paths.root, env.readFile)
    await saveSession(env.paths.sessionDir, call.sessionId, observed)
  } catch (error) {
    env.stderr(`dsh-proof: post-tool observation failed (${errorMessage(error)}); drift detection may lag`)
  }
  // A proof_* call may have just established a baseline on disk (the MCP
  // server writes it); refresh the cache so the next prompt render is honest.
  if (call.tool.startsWith('proof_')) {
    try {
      env.hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
    } catch {
      /* keep the cached flag */
    }
  }
  return undefined
}

/**
 * Turn-end evaluation: full drift + enforcement facts, `windowStart` to roll
 * the observation window. NOT registered in v1 — OpenCode exposes no Stop
 * hook and its event bus shape is not stable enough to guess. Exported so a
 * future version (or an e2e harness that can simulate turn ends) gets the
 * same semantics the Claude Code adapter's Stop hook has; until then drift
 * enforcement rides `ocBeforeHandler`'s next-call anchor instead.
 */
export async function ocTurnEndHandler(env: OcAdapterEnv, sessionId: string | undefined): Promise<{ block?: string } | undefined> {
  try {
    const session = (sessionId !== undefined
      ? await loadSession(env.paths.sessionDir, sessionId)
      : undefined) ?? emptySession(env.now())
    const drift = env.driftDetection
      ? await computeDrift(session, env.paths.root, env.readFile)
      : undefined
    try {
      env.hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
    } catch {
      /* keep the cached flag */
    }
    const facts: StopFacts = {
      drift,
      touchedCount: session.touched.length,
      hasBaseline: env.hasBaseline,
      requireBaseline: env.gate.requireBaseline,
      enforceOnTurnEnd: env.enforceTurnEnd,
      driftDetection: env.driftDetection,
    }
    const verdict = evaluateStop(facts, session)
    if (sessionId !== undefined) {
      // Fire ids are this caller's ledger debt (evaluateStop is pure — it
      // never mutates the session); pay them, then roll the window.
      const ledgered = verdict.fire !== undefined
        ? { ...session, firedNotices: [...session.firedNotices, verdict.fire] }
        : session
      await saveSession(env.paths.sessionDir, sessionId, windowStart(ledgered, env.now()))
    }
    return verdict.block !== undefined ? { block: verdict.block } : undefined
  } catch (error) {
    env.stderr(`dsh-proof: turn-end evaluation failed (${errorMessage(error)}); turn proceeds`)
    return undefined
  }
}

// ---------------------------------------------------------------------------
// Prompt injection
// ---------------------------------------------------------------------------

/** One-line blurbs for the five frozen MCP tool names (APP/1.0 contract). */
const TOOL_BLURB: Record<string, string> = {
  proof_status: 'read the current proof state — baseline? discovered checks? chain intact?',
  proof_baseline: 'establish or refresh the verification baseline, before the first edit',
  proof_verify: 're-run the objective checks this change set made stale; a check that passed at baseline and now fails is YOUR regression',
  proof_claim: 'state the exact completion claim and prove it in one call; proven only when nothing regressed',
  proof_bundle: 'export the tamper-evident evidence bundle for audit or hand-off',
}

/**
 * The system-prompt addition: the canonical `proof:policy` section plus the
 * host-specific note that the five proof tools ride an MCP server here.
 * Injected through `chat.params` when that seam exists; exported regardless
 * so an e2e harness can assert what WOULD be injected.
 */
export function buildSystemPromptAddition(env: OcAdapterEnv): string {
  const policy = buildPolicySection({
    // Check discovery is the MCP server's job on this host; the adapter has
    // no engine. The section honestly says "no checks discovered here" — the
    // tools themselves know better once the server reports for duty.
    discovered: [],
    hasBaseline: env.hasBaseline,
    requireBaseline: env.gate.requireBaseline,
  })
  const lines: string[] = [
    policy,
    '',
    '## Proof tools on this host (OpenCode + MCP)',
    '',
    'This workspace runs the dsh-proof MCP server. Five tools, frozen contract:',
    ...MCP_TOOLS.map(name => `- \`${name}\` — ${TOOL_BLURB[name] ?? name}`),
    '',
    'Before editing: `proof_baseline`. Before saying work is done: `proof_claim` — a prose assertion is not evidence.',
    'If a tool call is held with a dsh-proof reason, act on the reason instead of retrying the same call.',
  ]
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// The plugin — probe, register, degrade gracefully
// ---------------------------------------------------------------------------

const NO_SURFACE_LINE = 'dsh-proof: no compatible OpenCode plugin surface found; enforcement idle (MCP tools still work)'

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function firstLine(text: string): string {
  return text.split('\n')[0] ?? text
}

/**
 * Build the plugin initializer. Probe a context, register on every surface
 * that duck-types into a known shape, and never let the host see an
 * exception. Returns `(ctx) => Promise<{ dispose }>`; `dispose` revokes what
 * it can (a registrar that handed back an unregister function gets it called).
 */
export function createOpencodePlugin(options: OcAdapterOptions = {}): (ctx: unknown) => Promise<{ dispose: () => void }> {
  return async function init(ctx: unknown): Promise<{ dispose: () => void }> {
    const stderr = options.stderr ?? defaultStderr
    const context = asPluginContext(ctx)
    if (context === undefined) {
      stderr(NO_SURFACE_LINE)
      return { dispose: () => undefined }
    }
    const directory = directoryOf(context) ?? process.cwd()
    const env = ocAdapterEnv(options, directory)
    // Pre-warm the baseline flag so the first prompt render tells the truth
    // about a workspace that already has one.
    try {
      env.hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
    } catch {
      /* cache stays false; first gate decision retries */
    }

    const disposers: Array<() => void> = []
    const registered: string[] = []

    /** One registration attempt: a throwing registrar degrades to a stderr line. */
    const register = (label: string, attempt: () => unknown): void => {
      try {
        const undo = attempt()
        if (typeof undo === 'function') {
          disposers.push(() => {
            try {
              undo()
            } catch (error) {
              stderr(`dsh-proof: ${label} dispose failed (${errorMessage(error)})`)
            }
          })
        }
        registered.push(label)
      } catch (error) {
        stderr(`dsh-proof: OpenCode ${label} registration failed (${errorMessage(error)}); that seam stays idle`)
      }
    }

    // -- tool.execute.before: the front door --------------------------------
    const wrappedBefore = async (input: unknown, _output: unknown): Promise<unknown> => {
      try {
        const decision = await ocBeforeHandler(env, input)
        if (decision !== undefined && decision.block !== undefined) {
          stderr(`dsh-proof: holding a tool call via tool.execute.before — ${firstLine(decision.block)}`)
          // OpenCode's before-hook interception shape is not stable across
          // releases; `{ error: { message } }` is the most commonly documented
          // form. The stderr line above covers hosts that report differently.
          return { error: { message: decision.block } }
        }
        return undefined
      } catch (error) {
        stderr(`dsh-proof: before hook failed (${errorMessage(error)}); allowing the call`)
        return undefined
      }
    }

    // -- tool.execute.after: observation ------------------------------------
    const wrappedAfter = async (input: unknown, _output: unknown): Promise<undefined> => {
      try {
        await ocAfterHandler(env, input)
      } catch (error) {
        stderr(`dsh-proof: after hook failed (${errorMessage(error)})`)
      }
      return undefined
    }

    // -- chat.params: policy injection ---------------------------------------
    // The seam is guessed as `(handler) => unknown` with the handler receiving
    // the assembled chat parameters as its second argument; a `system` member
    // (string or string array) gets the policy addition appended. Anything
    // unexpected inside the handler is swallowed — a broken prompt append must
    // never break chat assembly.
    const wrappedParams = (input: unknown, output: unknown): unknown => {
      try {
        if (typeof output !== 'object' || output === null || Array.isArray(output)) return undefined
        const record = output as { system?: unknown }
        const addition = buildSystemPromptAddition(env)
        if (typeof record.system === 'string') {
          record.system = record.system.length > 0 ? `${record.system}\n\n${addition}` : addition
        } else if (Array.isArray(record.system)) {
          record.system = [...record.system, addition]
        }
        // No recognizable `system` member: leave the parameters untouched
        // rather than inventing a key the host might not read.
        return undefined
      } catch (error) {
        stderr(`dsh-proof: prompt injection failed (${errorMessage(error)})`)
        return undefined
      }
    }

    const execute = context.tool?.execute
    const before = asBefore(execute?.before)
    if (before !== undefined) register('tool.execute.before', () => before(wrappedBefore))
    const after = asAfter(execute?.after)
    if (after !== undefined) register('tool.execute.after', () => after(wrappedAfter))
    const params = context.chat?.params
    if (typeof params === 'function') {
      const registrar = params as (handler: (input: unknown, output: unknown) => unknown) => unknown
      register('chat.params', () => registrar(wrappedParams))
    }

    if (registered.length === 0) {
      stderr(NO_SURFACE_LINE)
    } else {
      stderr(`dsh-proof: OpenCode adapter active [${registered.join(', ')}] root=${env.paths.root} `
        + `requireBaseline=${env.gate.requireBaseline} evidenceStore=${env.paths.evidenceStore}`)
    }

    return {
      dispose: () => {
        for (const disposer of disposers) disposer()
      },
    }
  }
}

export default createOpencodePlugin()
