/**
 * CLAUDE CODE ADAPTER — hook handlers over real directories, and the real
 * host protocol over real subprocesses.
 *
 * Three layers:
 *   1. handler units — ccAdapterEnv/handlePreToolUse/handlePostToolUse/
 *      handleStop/handleSessionStart called directly, against real files in
 *      the task's designated temp area (C:\mimoclaw_workspace\.openclaw\tmp\
 *      cc-it-<pid>): the gates as permission decisions, observation into the
 *      persisted session, drift + the one-shot baseline reminder at Stop, and
 *      the SessionStart context + seeding.
 *   2. the entry subprocess — `node --experimental-strip-types entry.ts
 *      <event>` fed JSON on stdin (exactly what Claude Code does), asserting
 *      the single-line JSON answer, and a post→mutate→stop round-trip where
 *      every step is an independent process sharing only the session file.
 *   3. bad input — unparseable stdin on PreToolUse answers `ask`; an unknown
 *      event name is silent exit 0 (forward compatibility).
 *
 * Plus examples/claude-code.settings.json, kept honest: it must parse as pure
 * JSON and carry the documented matcher shape.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { ccAdapterEnv, handlePostToolUse, handlePreToolUse, handleSessionStart, handleStop } from '../src/adapters/claude-code/hooks.ts'
import type { CcAdapterEnv, CcHookPayload } from '../src/adapters/claude-code/hooks.ts'
import { loadSession } from '../src/adapters/shared/session.ts'

const ENTRY = fileURLToPath(new URL('../src/adapters/claude-code/entry.ts', import.meta.url))
// The task's designated temp area, one scratch tree per test run.
const TMP = fileURLToPath(new URL('../../.openclaw/tmp/', import.meta.url))
const WORKSPACE = join(TMP, `cc-it-${process.pid}`)

// Isolated roots per family, so one family's baseline file never satisfies
// another family's "no baseline" premise. All run in workspace evidence mode
// (the only mode where the evidence-store guard has a decision to make).
const ROOT_GATES = join(WORKSPACE, 'gates')
const ROOT_DRIFT = join(WORKSPACE, 'drift')
const ROOT_NOTICE = join(WORKSPACE, 'notice')
const ROOT_START = join(WORKSPACE, 'start')
const ROOT_E2E = join(WORKSPACE, 'e2e')
const TRUST = join(WORKSPACE, 'trust')

const PROOF_TOOLS = ['proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle'] as const

/** A hermetic adapter env: only what the test sets, nothing inherited. */
function unitEnv(root: string, extra: Record<string, string> = {}): CcAdapterEnv {
  return ccAdapterEnv({
    DSH_PROOF_ROOT: root,
    DSH_PROOF_TRUST_DIR: TRUST,
    DSH_PROOF_EVIDENCE_STORE: 'workspace',
    ...extra,
  }, root)
}

const gatesEnv = unitEnv(ROOT_GATES)
const driftEnv = unitEnv(ROOT_DRIFT)
const noticeEnv = unitEnv(ROOT_NOTICE)
const startEnv = unitEnv(ROOT_START)

async function writeFile(root: string, rel: string, contents: string): Promise<void> {
  const abs = join(root, rel)
  await fsp.mkdir(dirname(abs), { recursive: true })
  await fsp.writeFile(abs, contents)
}

before(async () => {
  await fsp.rm(WORKSPACE, { recursive: true, force: true })
  for (const root of [ROOT_GATES, ROOT_DRIFT, ROOT_NOTICE, ROOT_START, ROOT_E2E]) {
    await fsp.mkdir(join(root, 'src'), { recursive: true })
  }
  // The drift family isolates drift from the baseline reminder: a baseline on
  // disk (the minimal shape a baseline.json parse-check accepts) means Stop
  // can only be blocking on drift there.
  await fsp.mkdir(dirname(driftEnv.paths.baselinePath), { recursive: true })
  await fsp.writeFile(driftEnv.paths.baselinePath, JSON.stringify({ baselineId: 'cc-it', checks: [] }))
})

after(async () => {
  await fsp.rm(WORKSPACE, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// PreToolUse — the gates as Claude Code permission decisions
// ---------------------------------------------------------------------------

test('ccAdapterEnv parses the env contract and defaults to config.ts semantics', () => {
  assert.equal(gatesEnv.paths.root, ROOT_GATES.replace(/\\/g, '/'), 'the root is derived (POSIX-normalised)')
  assert.equal(gatesEnv.gate.evidenceStore, 'workspace')
  assert.equal(gatesEnv.gate.evidenceDir, '.proof')
  assert.equal(gatesEnv.gate.requireBaseline, 'warn', 'DSH_PROOF_REQUIRE_BASELINE unset means warn, the plugin default')
  assert.equal(gatesEnv.driftDetection, true)
  assert.equal(gatesEnv.enforceOnTurnEnd, true)

  const tuned = unitEnv(ROOT_GATES, {
    DSH_PROOF_REQUIRE_BASELINE: 'ask',
    DSH_PROOF_DRIFT: '0',
    DSH_PROOF_ENFORCE_TURN_END: '0',
    DSH_PROOF_EVIDENCE_DIR: '.evi',
  })
  assert.equal(tuned.gate.requireBaseline, 'ask')
  assert.equal(tuned.gate.evidenceDir, '.evi')
  assert.equal(tuned.driftDetection, false)
  assert.equal(tuned.enforceOnTurnEnd, false)

  const bogus = unitEnv(ROOT_GATES, { DSH_PROOF_REQUIRE_BASELINE: 'nonsense' })
  assert.equal(bogus.gate.requireBaseline, 'warn', 'an invalid value falls back to the default, never to a crash')
})

test('PreToolUse: Write into the evidence log is denied (workspace mode)', async () => {
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Write',
    tool_input: { file_path: '.proof/evidence.jsonl', content: 'tamper' }, cwd: ROOT_GATES,
  }, gatesEnv)
  assert.ok(out !== undefined, 'an evidence-store write must produce a decision, not silence')
  const hso = out.hookSpecificOutput as { hookEventName?: string; permissionDecision?: string; permissionDecisionReason?: string }
  assert.equal(hso.hookEventName, 'PreToolUse')
  assert.equal(hso.permissionDecision, 'deny')
  assert.ok(typeof hso.permissionDecisionReason === 'string' && hso.permissionDecisionReason.length > 0)
})

test('PreToolUse: the evidence guard cannot be walked around with an absolute path', async () => {
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Edit',
    tool_input: { file_path: join(ROOT_GATES, '.proof', 'evidence.jsonl'), old_string: 'a', new_string: 'b' }, cwd: ROOT_GATES,
  }, gatesEnv)
  assert.equal((out?.hookSpecificOutput as { permissionDecision?: string })?.permissionDecision, 'deny')
})

test('PreToolUse: no baseline + requireBaseline=ask routes an Edit through approval', async () => {
  const askEnv = unitEnv(ROOT_GATES, { DSH_PROOF_REQUIRE_BASELINE: 'ask' })
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Edit',
    tool_input: { file_path: 'src/a.ts', old_string: 'a', new_string: 'b' }, cwd: ROOT_GATES,
  }, askEnv)
  assert.ok(out !== undefined)
  const hso = out.hookSpecificOutput as { hookEventName?: string; permissionDecision?: string; permissionDecisionReason?: string }
  assert.equal(hso.hookEventName, 'PreToolUse')
  assert.equal(hso.permissionDecision, 'ask')
  assert.ok(typeof hso.permissionDecisionReason === 'string' && hso.permissionDecisionReason.length > 0)
})

test('PreToolUse: default warn passes an Edit through as no output (allow)', async () => {
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Edit',
    tool_input: { file_path: 'src/a.ts', old_string: 'a', new_string: 'b' }, cwd: ROOT_GATES,
  }, gatesEnv)
  assert.equal(out, undefined, 'allow renders as exit 0 with no stdout — the no-action shape')
})

test('PreToolUse: Bash is allowed under default warn (and never crashes the handler)', async () => {
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash',
    tool_input: { command: 'npm test', description: 'run tests' }, cwd: ROOT_GATES,
  }, gatesEnv)
  assert.equal(out, undefined)
})

// ---------------------------------------------------------------------------
// PostToolUse — provenance observation into the persisted session
// ---------------------------------------------------------------------------

test('PostToolUse: a Write lands in the session as touched with a content fingerprint', async () => {
  await writeFile(ROOT_DRIFT, 'src/a.ts', 'alpha')
  const out = await handlePostToolUse({
    session_id: 'post-write', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/a.ts', content: 'alpha' }, cwd: ROOT_DRIFT,
  }, driftEnv)
  assert.equal(out, undefined, 'PostToolUse never answers')
  const session = await loadSession(driftEnv.paths.sessionDir, 'post-write')
  assert.ok(session !== undefined, 'the observation persisted across handler calls')
  assert.ok(session.touched.includes('src/a.ts'))
  assert.match(session.fingerprints['src/a.ts'] ?? '', /^[0-9a-f]{64}$/, 'the fingerprint is the sha256 of the observed content')
})

test('PostToolUse: a Read lands in the read set, not in touched', async () => {
  await writeFile(ROOT_DRIFT, 'src/b.ts', 'beta')
  await handlePostToolUse({
    session_id: 'post-read', hook_event_name: 'PostToolUse', tool_name: 'Read',
    tool_input: { file_path: 'src/b.ts' }, cwd: ROOT_DRIFT,
  }, driftEnv)
  const session = await loadSession(driftEnv.paths.sessionDir, 'post-read')
  assert.ok(session !== undefined)
  assert.ok(session.read.includes('src/b.ts'))
  assert.ok(!session.touched.includes('src/b.ts'), 'reads are provenance context, not mutations')
})

test('PostToolUse: a payload without session_id is a no-op', async () => {
  const out = await handlePostToolUse({
    hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/orphan.ts', content: 'x' }, cwd: ROOT_DRIFT,
  }, driftEnv)
  assert.equal(out, undefined)
})

// ---------------------------------------------------------------------------
// Stop — drift blocks, the window advances, the baseline reminder fires once
// ---------------------------------------------------------------------------

test('Stop: external drift on a file the agent read blocks with the file name and proof_verify guidance', async () => {
  await writeFile(ROOT_DRIFT, 'src/d.ts', 'v1')
  await handlePostToolUse({
    session_id: 'stop-drift', hook_event_name: 'PostToolUse', tool_name: 'Read',
    tool_input: { file_path: 'src/d.ts' }, cwd: ROOT_DRIFT,
  }, driftEnv)
  // The change the agent never made through a tool — after the read, its
  // in-context copy is now stale, which is the corruption drift exists for.
  await writeFile(ROOT_DRIFT, 'src/d.ts', 'v2 — outside every tool call')

  const out = await handleStop({ session_id: 'stop-drift', hook_event_name: 'Stop', cwd: ROOT_DRIFT }, driftEnv)
  assert.ok(out !== undefined, 'drift must block the turn, not pass silently')
  assert.equal((out as { decision?: string }).decision, 'block')
  const reason = (out as { reason?: string }).reason ?? ''
  assert.ok(reason.includes('src/d.ts'), `the reason names the drifted file, got: ${reason}`)
  assert.ok(reason.includes('proof_verify'), `the reason points at proof_verify, got: ${reason}`)
})

test('Stop: the same session with the drift resolved no longer blocks', async () => {
  await writeFile(ROOT_DRIFT, 'src/d.ts', 'v1') // restored to the observed bytes
  const out = await handleStop({ session_id: 'stop-drift', hook_event_name: 'Stop', cwd: ROOT_DRIFT }, driftEnv)
  assert.equal(out, undefined, 'no drift, no unmet gate — the turn may end')
})

test('Stop: mutations with a baseline but no verification block once (verify notice)', async () => {
  await writeFile(ROOT_DRIFT, 'src/v.ts', 'v1')
  await handlePostToolUse({
    session_id: 'verify-notice', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/v.ts', content: 'v1' }, cwd: ROOT_DRIFT,
  }, driftEnv)

  const first = await handleStop({ session_id: 'verify-notice', hook_event_name: 'Stop', cwd: ROOT_DRIFT }, driftEnv)
  assert.ok(first !== undefined, 'unverified mutations against a baseline block the turn end')
  assert.equal((first as { decision?: string }).decision, 'block')
  assert.match((first as { reason?: string }).reason ?? '', /proof_verify/i)
  const after = await loadSession(driftEnv.paths.sessionDir, 'verify-notice')
  assert.deepEqual(after?.firedNotices, ['verify'], 'the one-time notice was recorded')

  // The turn continues, mutates again, stops again: the reminder must not repeat.
  await handlePostToolUse({
    session_id: 'verify-notice', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/v.ts', content: 'v1' }, cwd: ROOT_DRIFT,
  }, driftEnv)
  const second = await handleStop({ session_id: 'verify-notice', hook_event_name: 'Stop', cwd: ROOT_DRIFT }, driftEnv)
  assert.equal(second, undefined, 'firedNotices makes the verify reminder one-shot per session')
})

test('Stop: touched>0 without a baseline blocks once, and firedNotices dedupes it', async () => {
  await writeFile(ROOT_NOTICE, 'src/n.ts', 'x')
  await handlePostToolUse({
    session_id: 'notice', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/n.ts', content: 'x' }, cwd: ROOT_NOTICE,
  }, noticeEnv)

  const first = await handleStop({ session_id: 'notice', hook_event_name: 'Stop', cwd: ROOT_NOTICE }, noticeEnv)
  assert.ok(first !== undefined, 'warn mode defers its baseline notice to the turn boundary — and blocks there')
  assert.equal((first as { decision?: string }).decision, 'block')
  assert.match((first as { reason?: string }).reason ?? '', /baseline/i)

  const after = await loadSession(noticeEnv.paths.sessionDir, 'notice')
  assert.ok(after !== undefined)
  assert.equal(after.touched.length, 0, 'the stop advanced the observation window')
  assert.equal(after.firedNotices.length, 1, 'the fired notice was recorded for dedup')

  // The turn continues, mutates again, stops again: the reminder must not repeat.
  await handlePostToolUse({
    session_id: 'notice', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/n.ts', content: 'x' }, cwd: ROOT_NOTICE,
  }, noticeEnv)
  const second = await handleStop({ session_id: 'notice', hook_event_name: 'Stop', cwd: ROOT_NOTICE }, noticeEnv)
  assert.equal(second, undefined, 'firedNotices makes the baseline reminder one-shot per session')
})

// ---------------------------------------------------------------------------
// SessionStart — policy context injection + session seeding
// ---------------------------------------------------------------------------

test('SessionStart: additionalContext carries the policy section and the five MCP tool names', async () => {
  const out = await handleSessionStart({ session_id: 'fresh', hook_event_name: 'SessionStart', cwd: ROOT_START }, startEnv)
  assert.ok(out !== undefined)
  const hso = out.hookSpecificOutput as { hookEventName?: string; additionalContext?: string }
  assert.equal(hso.hookEventName, 'SessionStart')
  const context = hso.additionalContext ?? ''
  assert.match(context, /Completion proof/, 'the proof:policy section leads the context')
  assert.match(context, /No baseline is established/, 'the no-baseline state is stated honestly')
  for (const tool of PROOF_TOOLS) {
    assert.ok(context.includes(tool), `the context names ${tool}`)
  }
  assert.ok(context.includes('proof_verify'), 'the context tells the model when to verify')
})

test('SessionStart: seeds the session file, and never wipes an existing one', async () => {
  const seeded = await loadSession(startEnv.paths.sessionDir, 'fresh')
  assert.ok(seeded !== undefined, 'the session file exists after SessionStart')
  assert.deepEqual(seeded.touched, [])

  // A resume fires SessionStart again mid-session — observations must survive.
  await writeFile(ROOT_START, 'src/s.ts', 's')
  await handlePostToolUse({
    session_id: 'fresh', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/s.ts', content: 's' }, cwd: ROOT_START,
  }, startEnv)
  await handleSessionStart({ session_id: 'fresh', hook_event_name: 'SessionStart', cwd: ROOT_START }, startEnv)
  const after = await loadSession(startEnv.paths.sessionDir, 'fresh')
  assert.ok(after !== undefined)
  assert.ok(after.touched.includes('src/s.ts'), 're-seeding only happens when no session file exists')
})

// ---------------------------------------------------------------------------
// The entry subprocess — the exact contract Claude Code drives
// ---------------------------------------------------------------------------

interface RunResult { code: number | null; stdout: string; stderr: string }

function runHook(event: string, stdinText: string, root: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', ENTRY, event], {
      cwd: root,
      env: {
        ...process.env,
        DSH_PROOF_ROOT: root,
        DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust-e2e'),
        DSH_PROOF_EVIDENCE_STORE: 'workspace',
        DSH_PROOF_REQUIRE_BASELINE: '', // the default (warn) — cleared of the ambient environment
        DSH_PROOF_DRIFT: '',
        DSH_PROOF_ENFORCE_TURN_END: '',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => {
      child.kill()
    }, 30_000)
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => { stdout += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => { stderr += chunk })
    child.on('error', (error) => { clearTimeout(timer); settled = true; reject(error) })
    child.on('exit', (code) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
    child.stdin.on('error', () => { /* the child exiting early closes the pipe; the exit event settles us */ })
    child.stdin.write(stdinText)
    child.stdin.end()
  })
}

function singleLineJson(stdout: string): Record<string, unknown> {
  const lines = stdout.split('\n').filter(line => line.trim().length > 0)
  assert.equal(lines.length, 1, `expected exactly one stdout line, got ${JSON.stringify(stdout)}`)
  return JSON.parse(lines[0]!) as Record<string, unknown>
}

test('e2e pre-tool-use: the deny answer is a single-line PreToolUse hookSpecificOutput', async () => {
  const { code, stdout } = await runHook('pre-tool-use', JSON.stringify({
    session_id: 'e2e', hook_event_name: 'PreToolUse', tool_name: 'Write',
    tool_input: { file_path: '.proof/evidence.jsonl', content: 'tamper' }, cwd: ROOT_E2E,
  }), ROOT_E2E)
  assert.equal(code, 0)
  const hso = (singleLineJson(stdout).hookSpecificOutput ?? {}) as {
    hookEventName?: string; permissionDecision?: string; permissionDecisionReason?: string
  }
  assert.equal(hso.hookEventName, 'PreToolUse')
  assert.equal(hso.permissionDecision, 'deny')
  assert.ok(typeof hso.permissionDecisionReason === 'string' && hso.permissionDecisionReason.length > 0)
})

test('e2e pre-tool-use: an allowed call is exit 0 with empty stdout', async () => {
  const { code, stdout } = await runHook('pre-tool-use', JSON.stringify({
    session_id: 'e2e', hook_event_name: 'PreToolUse', tool_name: 'Edit',
    tool_input: { file_path: 'src/e.ts', old_string: 'a', new_string: 'b' }, cwd: ROOT_E2E,
  }), ROOT_E2E)
  assert.equal(code, 0)
  assert.equal(stdout, '', 'allow = no action = no output')
})

test('e2e round-trip: post → external mutation → stop blocks, across independent processes', async () => {
  // One process observes the write…
  await writeFile(ROOT_E2E, 'src/rt.ts', 'one')
  const post = await runHook('post-tool-use', JSON.stringify({
    session_id: 'rt', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: 'src/rt.ts', content: 'one' }, cwd: ROOT_E2E,
  }), ROOT_E2E)
  assert.equal(post.code, 0)
  assert.equal(post.stdout, '')

  // …a second process stops: touched>0, no baseline → the deferred reminder
  // blocks, the notice is recorded, and the observation window advances.
  const stop1 = await runHook('stop', JSON.stringify({ session_id: 'rt', hook_event_name: 'Stop', cwd: ROOT_E2E }), ROOT_E2E)
  assert.equal(stop1.code, 0)
  const blocked1 = singleLineJson(stop1.stdout)
  assert.equal(blocked1.decision, 'block')
  assert.match(String(blocked1.reason), /baseline/i)

  // …the turn ends; between turns the file mutates behind every tool's back
  // (drift is judged against the fingerprint, and the closed window's touch
  // no longer masks an outside change)…
  await writeFile(ROOT_E2E, 'src/rt.ts', 'two — outside every tool call')

  // …and a third process stops: drift, named, with the proof_verify guidance.
  const stop2 = await runHook('stop', JSON.stringify({ session_id: 'rt', hook_event_name: 'Stop', cwd: ROOT_E2E }), ROOT_E2E)
  assert.equal(stop2.code, 0)
  const blocked2 = singleLineJson(stop2.stdout)
  assert.equal(blocked2.decision, 'block')
  assert.ok(String(blocked2.reason).includes('src/rt.ts'), `the drift reason names the file, got: ${String(blocked2.reason)}`)
  assert.ok(String(blocked2.reason).includes('proof_verify'), `the drift reason points at proof_verify, got: ${String(blocked2.reason)}`)

  // Resolved drift and a spent reminder: the turn may end in silence.
  await writeFile(ROOT_E2E, 'src/rt.ts', 'one')
  const stop3 = await runHook('stop', JSON.stringify({ session_id: 'rt', hook_event_name: 'Stop', cwd: ROOT_E2E }), ROOT_E2E)
  assert.equal(stop3.code, 0)
  assert.equal(stop3.stdout, '')
})

test('e2e session-start: answers the context and seeds the session file', async () => {
  const { code, stdout } = await runHook('session-start', JSON.stringify({
    session_id: 'e2e-start', hook_event_name: 'SessionStart', cwd: ROOT_E2E,
  }), ROOT_E2E)
  assert.equal(code, 0)
  const hso = (singleLineJson(stdout).hookSpecificOutput ?? {}) as { hookEventName?: string; additionalContext?: string }
  assert.equal(hso.hookEventName, 'SessionStart')
  const context = hso.additionalContext ?? ''
  assert.match(context, /proof:policy/)
  for (const tool of PROOF_TOOLS) assert.ok(context.includes(tool))
})

// ---------------------------------------------------------------------------
// bad input
// ---------------------------------------------------------------------------

test('e2e bad input: unparseable stdin on pre-tool-use answers ask, not silence', async () => {
  const { code, stdout } = await runHook('pre-tool-use', '{ this is not json', ROOT_E2E)
  assert.equal(code, 0)
  const hso = (singleLineJson(stdout).hookSpecificOutput ?? {}) as {
    hookEventName?: string; permissionDecision?: string; permissionDecisionReason?: string
  }
  assert.equal(hso.hookEventName, 'PreToolUse')
  assert.equal(hso.permissionDecision, 'ask', 'a gate that cannot read its payload must not wave the mutation through')
  assert.match(hso.permissionDecisionReason ?? '', /parse/i)
})

test('e2e bad input: an unknown event name is silent exit 0 (forward compatibility)', async () => {
  const { code, stdout } = await runHook('Notification', JSON.stringify({ session_id: 'x', cwd: ROOT_E2E }), ROOT_E2E)
  assert.equal(code, 0)
  assert.equal(stdout, '', 'unknown events cost nothing and break nothing')
})

// ---------------------------------------------------------------------------
// examples/claude-code.settings.json
// ---------------------------------------------------------------------------

test('the example settings file is pure JSON with the documented hook wiring', async () => {
  const raw = await fsp.readFile(fileURLToPath(new URL('../examples/claude-code.settings.json', import.meta.url)), 'utf8')
  const settings = JSON.parse(raw) as {
    $schema?: unknown
    _comment?: unknown
    hooks: Record<string, { matcher?: string | string[]; hooks: { type?: string; command?: string }[] }[]>
  }
  assert.equal(typeof settings.$schema, 'string', 'the file declares its schema')
  assert.ok(Array.isArray(settings._comment), 'guidance lives in the harmless _comment key, not in comment syntax')

  const pre = settings.hooks.PreToolUse?.[0]
  assert.ok(pre !== undefined)
  assert.deepEqual([...(pre.matcher as string[])].sort(), ['Bash', 'Edit', 'MultiEdit', 'NotebookEdit', 'Write'])
  assert.equal(pre.hooks[0]?.command, 'dsh-proof-cc pre-tool-use')
  assert.equal(pre.hooks[0]?.type, 'command')

  const post = settings.hooks.PostToolUse?.[0]
  assert.ok(post !== undefined)
  assert.deepEqual([...(post.matcher as string[])].sort(), ['Bash', 'Edit', 'MultiEdit', 'NotebookEdit', 'Read', 'Write'])

  assert.equal(settings.hooks.Stop?.[0]?.hooks?.[0]?.command, 'dsh-proof-cc stop')
  assert.equal(settings.hooks.SessionStart?.[0]?.hooks?.[0]?.command, 'dsh-proof-cc session-start')

  // The MCP registration rides the comment block: one file, one purpose.
  const comment = Array.isArray(settings._comment) ? settings._comment.join('\n') : String(settings._comment)
  assert.ok(comment.includes('claude mcp add proof'), 'the comment explains how the tool surface is registered')
})

test('handler payloads stay total for tool names the matchers never list', async () => {
  // A misconfigured matcher (or a future tool) must hit total handlers, never a crash.
  const out = await handlePreToolUse({
    session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'SomeBrandNewTool',
    tool_input: { file_path: 'src/a.ts' }, cwd: ROOT_GATES,
  }, gatesEnv)
  assert.equal(out, undefined, 'unknown tool, no gate opinion: allow-shaped silence')
  await handlePostToolUse({
    session_id: 'post-unknown', hook_event_name: 'PostToolUse', tool_name: 'SomeBrandNewTool',
    tool_input: { file_path: 'src/a.ts' }, cwd: ROOT_GATES,
  }, gatesEnv)
  const payload: CcHookPayload = { session_id: 'post-unknown', tool_name: 'SomeBrandNewTool' }
  await handleStop(payload, gatesEnv)
  assert.ok(true, 'no handler threw on an arbitrary tool name')
})
