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

import { promises as fsp } from 'node:fs'

import type { ProofPaths } from '../shared/paths.ts'
import { deriveProofPaths, resolveAdapterEnv } from '../shared/paths.ts'
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
  /** Diagnostics sink, one line per call (persistence failures are said, not swallowed). */
  stderr: (line: string) => void
}

/** Best-effort stderr default; a closed stream must never break a handler. */
function defaultStderr(line: string): void {
  try {
    process.stderr.write(`${line}\n`)
  } catch {
    /* nothing further to do */
  }
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
 * The env contract itself is parsed by the shared `resolveAdapterEnv` — one
 * parser for every face (H-21: a variable only this file reads is a forked
 * deployment, not a configuration).
 */
export function ccAdapterEnv(env: NodeJS.ProcessEnv, cwd: string): CcAdapterEnv {
  const values = resolveAdapterEnv(env)
  const root = values.root ?? cwd
  // The trust-root default is left to deriveProofPaths (the DSH_HOME rule the
  // plugin and the MCP entry both apply), so all three faces derive the same one.
  const paths = deriveProofPaths({
    root,
    ...(values.trustRoot !== undefined ? { trustRoot: values.trustRoot } : {}),
    ...(values.evidenceStore !== undefined ? { evidenceStore: values.evidenceStore } : {}),
    ...(values.evidenceDir !== undefined ? { evidenceDir: values.evidenceDir } : {}),
  })
  // GateOptions mirrors the plugin config's semantics: `evidenceDir` is the
  // workspace-relative dir ('.proof' by default), only meaningful in
  // workspace mode — host mode keeps the store outside the sandbox. The
  // trust root rides along so the shell-command sweep can guard the
  // trust-side artifacts too (H-02).
  const gate: GateOptions = {
    evidenceStore: paths.evidenceStore,
    evidenceDir: values.evidenceDir ?? '.proof',
    requireBaseline: values.requireBaseline ?? 'warn',
    trustRoot: paths.trustRoot,
  }
  return {
    paths,
    gate,
    driftDetection: values.driftDetection ?? true,
    enforceOnTurnEnd: values.enforceTurnEnd ?? true,
    now: () => new Date().toISOString(),
    readFile: nodeReadFile,
    stderr: defaultStderr,
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
 * swallowed — but SAID on stderr since v0.23 (M-43: a silent observation
 * loss reads to the operator like working drift detection).
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
  } catch (error) {
    // Observation is best-effort by design; drift detection at Stop re-reads
    // the filesystem anyway, so a lost observation degrades, never breaks.
    env.stderr(`dsh-proof: post-tool observation failed (${error instanceof Error ? error.message : String(error)}); `
      + 'drift attribution may lag one turn')
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
export async function handleStop(payload: CcHookPayload, env: CcAdapterEnv): Promise<Record<string, unknown> | undefined> {
  const sessionId = sessionIdOf(payload)
  if (sessionId === undefined) return undefined
  let outcome: { reason: string | undefined; next: AdapterSession }
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
    // Drift is the louder signal: when both a block and a one-shot notice are
    // due, the drift reason is what the model needs to act on first.
    const reason = decision.block !== undefined ? decision.block : decision.fire
    const fired = decision.fire !== undefined && !session.firedNotices.includes(decision.fire)
      ? [...session.firedNotices, decision.fire]
      : session.firedNotices
    outcome = { reason, next: windowStart({ ...session, firedNotices: fired }, env.now()) }
  } catch (error) {
    // A failing Stop evaluation must never wedge the turn's wind-down — but
    // it is said, not silenced.
    env.stderr(`dsh-proof: stop evaluation failed (${error instanceof Error ? error.message : String(error)}); the turn proceeds unblocked`)
    return undefined
  }
  try {
    await saveSession(env.paths.sessionDir, sessionId, outcome.next)
  } catch (error) {
    env.stderr(`dsh-proof: session persistence failed (${error instanceof Error ? error.message : String(error)}); `
      + `the observation window did not advance — one-time notices may repeat`)
  }
  if (outcome.reason === undefined) return undefined
  return { decision: 'block', reason: outcome.reason }
}

/**
 * The MCP line appended to the SessionStart context: the tool names on THIS
 * host, plus the wiring self-check (H-22): the policy section describes what
 * the hooks DO when they are wired, and this adapter cannot verify its own
 * wiring — a project-scope settings file can silently drop the PreToolUse
 * hook. The context therefore states the detection, not a guarantee, and
 * hands the model the one check that falsifies it.
 */
function mcpToolsLine(): string {
  return 'On this host the proof verbs are MCP tools: proof_status, proof_baseline, proof_verify, proof_claim, proof_bundle '
    + '(registered with `claude mcp add proof -- dsh-proof-mcp`). Call proof_verify after any significant change, before claiming the work done. '
    + 'Note: files changed only through Bash are not path-attributed — prefer Write/Edit so drift attribution can see them.\n\n'
    + 'Enforcement wiring: the gates above run through host hooks (.claude/settings.json). This context cannot '
    + 'verify they are wired — a project-level settings file can omit or remove them, and hook wiring supplied by '
    + 'the repository travels with the repository. Treat enforcement as DETECTED, not guaranteed: if a write into '
    + 'the evidence store (.proof/evidence.jsonl) is not denied, report that the guard is absent instead of assuming oversight.'
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
