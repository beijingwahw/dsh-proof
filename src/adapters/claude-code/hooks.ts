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
 * Write/Edit/MultiEdit/NotebookEdit mutate via `tool_input.file_path`; Read
 * reads via `file_path`; Bash executes `tool_input.command`, a shell command
 * that names no path — a deliberate path blind spot (documented in the example
 * settings and the SessionStart context): a Bash-written file contributes no
 * fingerprint, so only its gate classification (mutation-capable) applies.
 *
 * State is per Claude Code session (session_id), persisted under the shared
 * adapter paths (src/adapters/shared/paths.ts) so independent hook processes —
 * one process per event — read and write the same observation window.
 *
 * Environment (mirrors the DSH plugin's config defaults; see src/config.ts):
 *   DSH_PROOF_ROOT             workspace root (default: the hook's cwd)
 *   DSH_PROOF_TRUST_DIR        trust root (default: deriveProofPaths' own)
 *   DSH_PROOF_EVIDENCE_STORE   'host' (default) | 'workspace'
 *   DSH_PROOF_EVIDENCE_DIR     workspace-relative evidence dir (default '.proof')
 *   DSH_PROOF_REQUIRE_BASELINE 'off' | 'warn' (default) | 'ask'
 *   DSH_PROOF_DRIFT            '0' disables drift detection (default: on)
 *   DSH_PROOF_ENFORCE_TURN_END '0' disables the turn-end reminder (default: on)
 *
 * @module dsh-proof/adapters/claude-code/hooks
 */

import { promises as fsp } from 'node:fs'

import type { ProofPaths } from '../shared/paths.ts'
import { deriveProofPaths } from '../shared/paths.ts'
import type { AdapterSession } from '../shared/session.ts'
import { applyObservation, computeDrift, emptySession, loadSession, saveSession, windowStart } from '../shared/session.ts'
import type { DriftResult, GateOptions, StopFacts } from '../shared/gates.ts'
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from '../shared/gates.ts'
import { buildPolicySection } from '../../dsh/prompt.ts'

/** One Claude Code hook event, as it arrives on stdin (unknown fields tolerated). */
export interface CcHookPayload {
  session_id?: string
  hook_event_name?: string
  tool_name?: string
  tool_input?: unknown
  /** PostToolUse also carries tool_response; observation only needs the input. */
  tool_response?: unknown
  cwd?: string
  [k: string]: unknown
}

/** Everything a handler needs, assembled once per process from the environment. */
export interface CcAdapterEnv {
  paths: ProofPaths
  gate: GateOptions
  driftDetection: boolean
  enforceOnTurnEnd: boolean
  now: () => string
  readFile: (abs: string) => Promise<string | undefined>
}

function envString(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/** DSH_PROOF_REQUIRE_BASELINE parsing — anything invalid falls back to config.ts's 'warn'. */
function parseRequireBaseline(value: string | undefined): 'off' | 'warn' | 'ask' {
  return value === 'off' || value === 'ask' ? value : 'warn'
}

/** DSH_PROOF_DRIFT / DSH_PROOF_ENFORCE_TURN_END parsing — only '0' turns a default-on flag off. */
function parseFlag(value: string | undefined): boolean {
  return value !== '0'
}

async function nodeReadFile(abs: string): Promise<string | undefined> {
  try {
    return await fsp.readFile(abs, 'utf8')
  } catch {
    return undefined
  }
}

/**
 * Assemble the adapter environment. `cwd` is the hook process's working
 * directory (Claude Code sets it to the project dir); DSH_PROOF_ROOT wins.
 */
export function ccAdapterEnv(env: NodeJS.ProcessEnv, cwd: string): CcAdapterEnv {
  const root = envString(env, 'DSH_PROOF_ROOT') ?? cwd
  const trustRoot = envString(env, 'DSH_PROOF_TRUST_DIR')
  const evidenceStore = envString(env, 'DSH_PROOF_EVIDENCE_STORE')
  const evidenceDir = envString(env, 'DSH_PROOF_EVIDENCE_DIR')
  // The trust-root default is left to deriveProofPaths (the DSH_HOME rule the
  // plugin and the MCP entry both apply), so all three faces derive the same one.
  const paths = deriveProofPaths({
    root,
    ...(trustRoot !== undefined ? { trustRoot } : {}),
    ...(evidenceStore !== undefined ? { evidenceStore } : {}),
    ...(evidenceDir !== undefined ? { evidenceDir } : {}),
  })
  // GateOptions mirrors the plugin config's semantics: `evidenceDir` is the
  // workspace-relative dir ('.proof' by default), only meaningful in
  // workspace mode — host mode keeps the store outside the sandbox.
  const gate: GateOptions = {
    evidenceStore: paths.evidenceStore,
    evidenceDir: evidenceDir ?? '.proof',
    requireBaseline: parseRequireBaseline(env.DSH_PROOF_REQUIRE_BASELINE),
  }
  return {
    paths,
    gate,
    driftDetection: parseFlag(env.DSH_PROOF_DRIFT),
    enforceOnTurnEnd: parseFlag(env.DSH_PROOF_ENFORCE_TURN_END),
    now: () => new Date().toISOString(),
    readFile: nodeReadFile,
  }
}

function sessionIdOf(payload: CcHookPayload): string | undefined {
  const value = payload.session_id
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/** The PreToolUse answer for one permission decision ('allow' renders as no output at all). */
function preToolUseResponse(decision: 'ask' | 'deny', reason: string): Record<string, unknown> {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  }
}

/**
 * PreToolUse — evidence-store guard + baseline gate as a permission decision.
 *
 * `allow` is returned as undefined: Claude Code treats exit 0 with no output as
 * "no action", which is exactly what an allow is. `ask`/`deny` ride the
 * hookSpecificOutput shape so the host routes the call accordingly.
 */
export async function handlePreToolUse(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined> {
  const toolName = typeof payload.tool_name === 'string' ? payload.tool_name : ''
  const hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
  const decision = decidePreToolUse(toolName, payload.tool_input ?? {}, env.paths.root, env.gate, hasBaseline)
  if (decision.action === 'allow') return undefined
  return preToolUseResponse(decision.action, decision.reason)
}

/**
 * PostToolUse — provenance observation. Loads the session (seeding an empty
 * one on first sight), folds the observation in, persists. A tool result must
 * never be delayed by bookkeeping failures, so an observation error is
 * swallowed: the handler answers undefined and the turn continues.
 * A payload without session_id is a no-op — there is nowhere to persist.
 */
export async function handlePostToolUse(payload: CcHookPayload, env: CcAdapterEnv): Promise<undefined> {
  const sessionId = sessionIdOf(payload)
  if (sessionId === undefined) return undefined
  try {
    let session: AdapterSession = await loadSession(env.paths.sessionDir, sessionId) ?? emptySession(env.now())
    if (typeof payload.tool_name === 'string') {
      session = await applyObservation(session, payload.tool_name, payload.tool_input, env.paths.root, env.readFile)
    }
    await saveSession(env.paths.sessionDir, sessionId, session)
  } catch {
    // Observation is best-effort by design; drift detection at Stop re-reads
    // the filesystem anyway, so a lost observation degrades, never breaks.
  }
}

/**
 * Stop — drift detection, the one-shot baseline reminder, and the window turn.
 *
 * Claude Code's Stop is the turn boundary, which is DSH's turn-stopping /
 * windowStart seam: whatever this handler decides, the observation window
 * advances and the session persists. A block hands the reason back to the
 * model instead of letting the turn end; the baseline reminder (`fire`) is
 * one-shot per session through `firedNotices`, while a drift block re-arms
 * every stop until the drift is resolved.
 * A payload without session_id is a no-op — there is nothing to observe.
 */
export async function handleStop(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined> {
  const sessionId = sessionIdOf(payload)
  if (sessionId === undefined) return undefined
  try {
    const session = await loadSession(env.paths.sessionDir, sessionId) ?? emptySession(env.now())
    const drift: DriftResult | undefined = env.driftDetection
      ? await computeDrift(session, env.paths.root, env.readFile)
      : undefined
    const facts: StopFacts = {
      drift,
      touchedCount: session.touched.length,
      hasBaseline: await hasBaselineOnDisk(env.paths, env.readFile),
      requireBaseline: env.gate.requireBaseline,
      enforceOnTurnEnd: env.enforceOnTurnEnd,
      driftDetection: env.driftDetection,
    }
    const decision = evaluateStop(facts, session)
    if (decision.fire !== undefined && !session.firedNotices.includes(decision.fire)) {
      session.firedNotices.push(decision.fire)
    }
    // Drift is the louder signal: when both a block and a one-shot notice are
    // due, the drift reason is what the model needs to act on first.
    const reason = decision.block !== undefined ? decision.block : decision.fire
    await saveSession(env.paths.sessionDir, sessionId, windowStart(session, env.now()))
    if (reason === undefined) return undefined
    return { decision: 'block', reason }
  } catch {
    // A failing Stop hook must never wedge the turn's wind-down.
    return undefined
  }
}

/** The MCP line appended to the SessionStart context: the tool names on THIS host. */
function mcpToolsLine(): string {
  return 'On this host the proof verbs are MCP tools: proof_status, proof_baseline, proof_verify, proof_claim, proof_bundle '
    + '(registered with `claude mcp add proof -- dsh-proof-mcp`). Call proof_verify after any significant change, before claiming the work done. '
    + 'Note: files changed only through Bash are not path-attributed — prefer Write/Edit so drift attribution can see them.'
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
export async function handleSessionStart(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined> {
  const sessionId = sessionIdOf(payload)
  if (sessionId !== undefined) {
    try {
      const existing = await loadSession(env.paths.sessionDir, sessionId)
      if (existing === undefined) {
        await saveSession(env.paths.sessionDir, sessionId, emptySession(env.now()))
      }
    } catch {
      // Seeding is an optimisation for first-observation latency, not a
      // precondition — PostToolUse seeds too when the file is missing.
    }
  }
  const hasBaseline = await hasBaselineOnDisk(env.paths, env.readFile)
  const additionalContext = `${buildPolicySection({
    discovered: [],
    hasBaseline,
    requireBaseline: env.gate.requireBaseline,
  })}\n\n${mcpToolsLine()}`
  return {
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext,
    },
  }
}
