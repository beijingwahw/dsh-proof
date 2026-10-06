#!/usr/bin/env node
/**
 * Claude Code hook entry — the command Claude Code runs per event.
 *
 * Usage: dsh-proof-cc <pre-tool-use|post-tool-use|stop|session-start>
 *
 * Claude Code feeds one JSON object (the hook payload) on stdin and reads a
 * single line of JSON from stdout; exit 0 always, exit 0 with no output means
 * "no action". Wiring lives in examples/claude-code.settings.json; the tool
 * surface itself (proof_status/proof_baseline/proof_verify/proof_claim/
 * proof_bundle) rides MCP: `claude mcp add proof -- dsh-proof-mcp`.
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

import type { CcHookPayload } from './hooks.ts'
import { ccAdapterEnv, handlePostToolUse, handlePreToolUse, handleSessionStart, handleStop } from './hooks.ts'

type CcEvent = 'pre-tool-use' | 'post-tool-use' | 'stop' | 'session-start'

const EVENTS: readonly CcEvent[] = ['pre-tool-use', 'post-tool-use', 'stop', 'session-start']

/** A one-line PreToolUse `ask` — the conservative answer a gate gives when it cannot decide. */
function preAsk(reason: string): string {
  return `${JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: reason,
    },
  })}\n`
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin
    if (stdin.readableEnded) {
      resolve('')
      return
    }
    stdin.setEncoding('utf8')
    let buffer = ''
    stdin.on('data', (chunk: string) => { buffer += chunk })
    stdin.on('end', () => { resolve(buffer) })
    stdin.on('error', () => { resolve(buffer) })
  })
}

async function main(): Promise<void> {
  // Read stdin first, whatever the event: an early exit that leaves the host's
  // pipe unread is noise on the spawning side, silence on ours.
  const raw = await readStdin()
  const arg = process.argv[2]
  if (!EVENTS.includes(arg as CcEvent)) return // unknown event: silent, forward-compatible

  let payload: CcHookPayload
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('payload is not a JSON object')
    payload = parsed as CcHookPayload
  } catch {
    if (arg === 'pre-tool-use') process.stdout.write(preAsk('dsh-proof: gate could not parse the hook payload'))
    return
  }

  // Claude Code sets the hook process's cwd to the project directory, and the
  // payload repeats it; trust the payload, fall back to the process.
  const cwd = typeof payload.cwd === 'string' && payload.cwd.length > 0 ? payload.cwd : process.cwd()
  const env = ccAdapterEnv(process.env, cwd)

  let result: Record<string, unknown> | undefined
  switch (arg) {
    case 'pre-tool-use':
      result = await handlePreToolUse(payload, env)
      break
    case 'post-tool-use':
      await handlePostToolUse(payload, env)
      result = undefined
      break
    case 'stop':
      result = await handleStop(payload, env)
      break
    case 'session-start':
      result = await handleSessionStart(payload, env)
      break
  }
  if (result !== undefined) process.stdout.write(`${JSON.stringify(result)}\n`)
}

main().catch((error: unknown) => {
  // Exit 0 regardless: the protocol speaks through stdout, and a dead hook
  // must not look like a denied tool call. Only the gate answers, with `ask`.
  if (process.argv[2] === 'pre-tool-use') {
    process.stdout.write(preAsk('dsh-proof: gate internal error'))
    return
  }
  console.error(`[dsh-proof-cc] ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
})
