/**
 * OPENCODE ADAPTER — duck-typed plugin surface, contract-first shared layer,
 * graceful degradation.
 *
 * The OpenCode plugin API is still evolving, so the adapter's whole posture is
 * "probe at runtime, never throw into the host". These tests pin:
 *
 *   1. vendor.ts narrowing matrix (null / number / function / object / array);
 *   2. ocBeforeHandler — evidence-store guard, ask-mode baseline gate, warn
 *      default passing, and the DRIFT ANCHOR: OpenCode has no Stop hook, so
 *      drift observed by an after hook is held at the NEXT tool call, with the
 *      drifted file named in the reason;
 *   3. ocAfterHandler — observation persisted (touched + fingerprints) across
 *      three real-world payload shapes ({tool,args}, {name,input},
 *      {tool:{name},arguments});
 *   4. createOpencodePlugin — registration on a synthetic context, end-to-end
 *      hold through the registered before handler (OpenCode `{error:{message}}`
 *      shape), chat.params prompt injection, and the surface-less no-op;
 *   5. hostile contexts — registrars that throw or return junk, payloads that
 *      are null/numbers — the plugin survives all of it.
 *
 * Real temp workspaces under .openclaw/tmp/oc-it-<pid>; real filesystem, real
 * sha256 fingerprints, no harness.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { asAfter, asBefore, asPluginContext, directoryOf } from '../src/adapters/opencode/vendor.ts'
import {
  buildSystemPromptAddition, createOpencodePlugin, guessToolCall,
  ocAdapterEnv, ocAfterHandler, ocBeforeHandler, ocTurnEndHandler,
  type OcAdapterOptions,
} from '../src/adapters/opencode/plugin.ts'
import opencodePluginDefault from '../src/adapters/opencode/plugin.ts'
import { loadSession } from '../src/adapters/shared/session.ts'
import { addressOf, merkleRoot } from '../src/core/hash.ts'

/** A self-addressing baseline.json — the only shape hasBaselineOnDisk accepts (H-20). */
function realBaselineJson(): string {
  const checks = [{ checkId: 'package.json:test', evidenceId: 'e1', status: 'pass' }]
  const workspace = { head: null, dirty: [], dirtDigest: merkleRoot([]) }
  const createdAt = '2026-10-06T10:00:00.000Z'
  const root = merkleRoot(checks.map(c => c.evidenceId))
  return JSON.stringify({
    baselineId: addressOf({ createdAt, workspace, checkIds: checks.map(c => c.checkId), root }),
    createdAt,
    workspace,
    checks,
    root,
  })
}

// The workspace root one level above the repo — the designated scratch area.
const WORKSPACE = fileURLToPath(new URL('../../', import.meta.url))
const SCRATCH = join(WORKSPACE, '.openclaw', 'tmp')
const ROOT = join(SCRATCH, `oc-it-${process.pid}`)

before(async () => {
  await fsp.mkdir(ROOT, { recursive: true })
})

after(async () => {
  await fsp.rm(ROOT, { recursive: true, force: true })
})

/** A fresh per-test workspace with a src/ directory. */
let counter = 0
async function freshWorkspace(): Promise<string> {
  const root = join(ROOT, `ws-${++counter}`)
  await fsp.mkdir(join(root, 'src'), { recursive: true })
  return root
}

/** Adapter env bound to the fresh workspace, with a stderr collector. */
function makeEnv(root: string, options: Partial<OcAdapterOptions> = {}): { env: ReturnType<typeof ocAdapterEnv>; stderrLines: string[] } {
  const stderrLines: string[] = []
  const env = ocAdapterEnv({
    trustRoot: join(root, 'trust'),
    stderr: line => stderrLines.push(line),
    ...options,
  }, root)
  return { env, stderrLines }
}

async function write(root: string, rel: string, contents: string): Promise<void> {
  await fsp.writeFile(join(root, ...rel.split('/')), contents)
}

// ---------------------------------------------------------------------------
// 1. vendor narrowing matrix
// ---------------------------------------------------------------------------

test('vendor: asPluginContext accepts plain objects only', () => {
  assert.equal(asPluginContext(null), undefined)
  assert.equal(asPluginContext(undefined), undefined)
  assert.equal(asPluginContext(42), undefined)
  assert.equal(asPluginContext('ctx'), undefined)
  assert.equal(asPluginContext(() => undefined), undefined)
  assert.equal(asPluginContext([]), undefined)
  const ctx = asPluginContext({ tool: { execute: {} }, directory: '/w' })
  assert.ok(ctx !== undefined)
  assert.equal(ctx.directory, '/w')
})

test('vendor: asBefore/asAfter narrow to functions and pass the same reference through', () => {
  const registrar = (handler: unknown) => handler
  assert.equal(asBefore(undefined), undefined)
  assert.equal(asBefore(null), undefined)
  assert.equal(asBefore(42), undefined)
  assert.equal(asBefore({}), undefined)
  assert.equal(asBefore('x'), undefined)
  assert.equal(asBefore(registrar), registrar)
  assert.equal(asAfter(registrar), registrar)
  assert.equal(asAfter(null), undefined)
  assert.equal(asAfter([]), undefined)
})

test('vendor: directoryOf prefers project.directory, falls back to directory, else undefined', () => {
  const of = (value: unknown): string | undefined => {
    const ctx = asPluginContext(value)
    return ctx === undefined ? undefined : directoryOf(ctx)
  }
  assert.equal(of({ project: { directory: '/w/a' } }), '/w/a')
  assert.equal(of({ directory: '/w/b' }), '/w/b')
  assert.equal(of({ project: { directory: '/first' }, directory: '/second' }), '/first')
  assert.equal(of({ project: { directory: '' } }), undefined)
  assert.equal(of({ project: { directory: 42 } }), undefined)
  assert.equal(of({ project: {} }), undefined)
  assert.equal(of({}), undefined)
})

// ---------------------------------------------------------------------------
// payload guessing (shared by the before/after handlers)
// ---------------------------------------------------------------------------

test('guessToolCall: three payload shapes and defensive garbage', () => {
  assert.deepEqual(
    guessToolCall({ tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' }),
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionId: 's1' },
  )
  const edited = guessToolCall({ name: 'Edit', input: { file_path: 'src/b.ts' }, session_id: 's2' })
  assert.equal(edited.tool, 'Edit')
  assert.deepEqual(edited.args, { file_path: 'src/b.ts' })
  assert.equal(edited.sessionId, 's2')
  const nested = guessToolCall({ tool: { name: 'write' }, arguments: { file_path: 'src/c.ts' }, sessionID: 's3' })
  assert.equal(nested.tool, 'write')
  assert.deepEqual(nested.args, { file_path: 'src/c.ts' })
  assert.deepEqual(
    guessToolCall(null),
    { tool: undefined, args: undefined, sessionId: undefined },
  )
  assert.equal(guessToolCall(42).tool, undefined)
  assert.equal(guessToolCall({ tool: '', name: 'Edit' }).tool, 'Edit')
})

// ---------------------------------------------------------------------------
// 2. ocBeforeHandler — the front door
// ---------------------------------------------------------------------------

test('before: workspace-mode write into the evidence store is held', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { evidenceStore: 'workspace' })
  const decision = await ocBeforeHandler(
    env,
    { tool: 'write', args: { file_path: '.proof/evidence.jsonl' }, sessionID: 's1' },
  )
  assert.ok(decision !== undefined && decision.block !== undefined, `expected a hold, got ${JSON.stringify(decision)}`)
  assert.match(decision.block, /evidence/i)
})

test('before: ask mode without a baseline holds mutation tools', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { requireBaseline: 'ask' })
  const decision = await ocBeforeHandler(
    env,
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' },
  )
  assert.ok(decision !== undefined && decision.block !== undefined)
  assert.match(decision.block, /baseline/i)
})

test('before: default warn mode lets a baseline-less mutation through', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root)
  const decision = await ocBeforeHandler(
    env,
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' },
  )
  assert.equal(decision, undefined)
})

test('before: ask mode with a real baseline on disk lets mutation tools through', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { requireBaseline: 'ask' })
  await fsp.mkdir(env.paths.logDir, { recursive: true })
  // A REAL baseline (self-addressing — H-20: a bare {"baselineId":"x"} is a
  // forgery and must NOT release the ask gate on this host either).
  await fsp.writeFile(env.paths.baselinePath, realBaselineJson())
  const decision = await ocBeforeHandler(
    env,
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' },
  )
  assert.equal(decision, undefined)
})

test('before: a forged 20-byte baseline does NOT release the ask gate (H-20)', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { requireBaseline: 'ask' })
  await fsp.mkdir(env.paths.logDir, { recursive: true })
  await fsp.writeFile(env.paths.baselinePath, JSON.stringify({ baselineId: 'forged' }))
  const decision = await ocBeforeHandler(
    env,
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' },
  )
  assert.ok(decision !== undefined && decision.block !== undefined, 'the gate stays armed against a shape-only forgery')
  assert.match(decision.block, /baseline/i)
})

test('before: MultiEdit and Bash-redirect into the store are held (H-01/H-02 on this host)', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { evidenceStore: 'workspace' })
  const multi = await ocBeforeHandler(
    env,
    { tool: 'MultiEdit', args: { file_path: '.proof/evidence.jsonl', edits: [] }, sessionID: 's1' },
  )
  assert.ok(multi !== undefined && multi.block !== undefined, 'the camelCase mutator is held')
  assert.match(multi.block, /evidence/i)

  const bash = await ocBeforeHandler(
    env,
    { tool: 'bash', args: { command: 'cp evil.jsonl .proof/evidence.jsonl' }, sessionID: 's1' },
  )
  assert.ok(bash !== undefined && bash.block !== undefined, 'the shell redirect channel is held')
  assert.match(bash.block, /command names the verification evidence store/i)

  const honest = await ocBeforeHandler(
    env,
    { tool: 'bash', args: { command: 'npm test' }, sessionID: 's1' },
  )
  assert.equal(honest, undefined, 'an honest shell command still passes')
})

test('before: a gate evaluation that THROWS holds the call — fail-closed, never decorative (M-40)', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { evidenceStore: 'workspace' })
  // Poison one gate input so the evaluation itself throws (a number where a
  // string segment is expected — the kind of thing a future refactor or a
  // hostile host option can produce). The gate section must convert the
  // throw into a HOLD; pre-v0.23 the wrapper caught everything and said
  // "allowing the call" — the exact inverse of the Claude Code adapter's
  // ask-on-error posture.
  const poisoned = { ...env, gate: { ...env.gate, evidenceDir: 42 as unknown as string } }
  const decision = await ocBeforeHandler(
    poisoned,
    { tool: 'bash', args: { command: 'npm test' }, sessionID: 's1' },
  )
  assert.ok(decision !== undefined && decision.block !== undefined, 'a broken gate holds the call, never allows it')
  assert.match(decision.block, /denied — dsh-proof: gate internal error/)
  assert.match(decision.block, /held rather than waved through/)
})

test('surfacedDrift: an ignored hold is not a permanent exemption — a resolved-then-recurred drift blocks again (M-42)', async () => {
  const root = await freshWorkspace()
  await write(root, 'src/a.ts', 'const a = 1\n')
  const { env } = makeEnv(root)
  await ocAfterHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 're-arm' })
  await write(root, 'src/a.ts', 'const a = 2\n')
  const first = await ocBeforeHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 're-arm' })
  assert.ok(first !== undefined && first.block !== undefined, 'the drift is held once')
  // The model ignores the hold and calls again — still suppressed (a host
  // whose only anchor is the next call must not hold every call hostage).
  const ignored = await ocBeforeHandler(env, { tool: 'read', args: { file_path: 'src/b.ts' }, sessionID: 're-arm' })
  assert.equal(ignored, undefined, 'the SAME persisting drift set stays spent')
  // Recovery: the file is re-read through the tool, the disk comes back clean.
  await ocAfterHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 're-arm' })
  assert.equal(await ocBeforeHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 're-arm' }), undefined)
  // Recurrence: the SAME shape drifts again — the hold re-arms.
  await write(root, 'src/a.ts', 'const a = 3\n')
  const again = await ocBeforeHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 're-arm' })
  assert.ok(again !== undefined && again.block !== undefined,
    'the same drift shape recurring after resolution holds again — ignoring a hold buys nothing permanent')
})

test('ocAdapterEnv: the DSH_PROOF_* knobs work on this host too — one contract, two faces (H-21/M-44)', async () => {
  const root = await freshWorkspace()
  const names = ['DSH_PROOF_ROOT', 'DSH_PROOF_TRUST_DIR', 'DSH_PROOF_EVIDENCE_STORE',
    'DSH_PROOF_EVIDENCE_DIR', 'DSH_PROOF_REQUIRE_BASELINE', 'DSH_PROOF_DRIFT', 'DSH_PROOF_ENFORCE_TURN_END'] as const
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]))
  try {
    process.env.DSH_PROOF_ROOT = root
    process.env.DSH_PROOF_EVIDENCE_STORE = 'workspace'
    process.env.DSH_PROOF_EVIDENCE_DIR = '.evi'
    process.env.DSH_PROOF_REQUIRE_BASELINE = 'ask'
    process.env.DSH_PROOF_DRIFT = '0'
    process.env.DSH_PROOF_ENFORCE_TURN_END = '0'
    const env = ocAdapterEnv({}, '/nowhere')
    assert.equal(env.paths.root, root.replace(/\\/g, '/').replace(/\/+$/, ''))
    assert.equal(env.paths.evidenceStore, 'workspace')
    assert.equal(env.gate.evidenceDir, '.evi')
    assert.equal(env.paths.logDir, `${env.paths.root}/.evi`, 'README\'s shared-variable promise is now true')
    assert.equal(env.gate.requireBaseline, 'ask')
    assert.equal(env.driftDetection, false, 'DSH_PROOF_DRIFT=0 turns drift off on OpenCode as documented')
    assert.equal(env.enforceTurnEnd, false, 'DSH_PROOF_ENFORCE_TURN_END=0 works here too')
    // Options still beat the environment.
    const overridden = ocAdapterEnv({ driftDetection: true }, '/nowhere')
    assert.equal(overridden.driftDetection, true)
  } finally {
    for (const n of names) {
      const v = saved[n]
      if (v === undefined) delete process.env[n]
      else process.env[n] = v
    }
  }
})

test('before: garbage payloads pass through untouched', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root)
  assert.equal(await ocBeforeHandler(env, null), undefined)
  assert.equal(await ocBeforeHandler(env, 42), undefined)
  assert.equal(await ocBeforeHandler(env, {}), undefined)
  assert.equal(await ocBeforeHandler(env, { args: { file_path: 'x' } }), undefined)
  assert.equal(await ocBeforeHandler(env, 'read'), undefined)
})

test('before: drift is anchored at the next tool call — read, external edit, next call held with the file named', async () => {
  const root = await freshWorkspace()
  await write(root, 'src/a.ts', 'const a = 1\n')
  const { env } = makeEnv(root)
  // after hook observes a read of src/a.ts (read set + fingerprint recorded)
  assert.equal(
    await ocAfterHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 'drift' }),
    undefined,
  )
  // the file changes behind the tool stream (IDE, formatter, human, ...)
  await write(root, 'src/a.ts', 'const a = 2\n')
  // the NEXT tool call is the drift anchor on this host: held, file named
  const held = await ocBeforeHandler(
    env,
    { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 'drift' },
  )
  assert.ok(held !== undefined && held.block !== undefined, `expected a drift hold, got ${JSON.stringify(held)}`)
  assert.match(held.block, /src\/a\.ts/)
  // recovery loop: re-reading through the tool refreshes the fingerprint;
  // the following call passes again
  assert.equal(
    await ocAfterHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 'drift' }),
    undefined,
  )
  assert.equal(
    await ocBeforeHandler(env, { tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 'drift' }),
    undefined,
  )
})

// ---------------------------------------------------------------------------
// 3. ocAfterHandler — observation + persistence
// ---------------------------------------------------------------------------

test('after: write tools persist touched paths and fingerprints across payload shapes', async () => {
  const root = await freshWorkspace()
  await write(root, 'src/a.ts', 'A\n')
  await write(root, 'src/b.ts', 'B\n')
  await write(root, 'src/c.ts', 'C\n')
  const { env } = makeEnv(root)
  const shapes = [
    { tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' },
    { name: 'Edit', input: { file_path: 'src/b.ts' }, session_id: 's1' },
    { tool: { name: 'write' }, arguments: { file_path: 'src/c.ts' }, sessionID: 's1' },
  ]
  for (const shape of shapes) assert.equal(await ocAfterHandler(env, shape), undefined)
  const session = await loadSession(env.paths.sessionDir, 's1')
  assert.ok(session !== undefined, 'session must persist when the payload carries a session id')
  assert.deepEqual([...session.touched].sort(), ['src/a.ts', 'src/b.ts', 'src/c.ts'])
  assert.equal(Object.keys(session.fingerprints).length, 3)
})

test('after: payloads without a guessable session id are a no-op', async () => {
  const root = await freshWorkspace()
  await write(root, 'src/a.ts', 'A\n')
  const { env, stderrLines } = makeEnv(root)
  assert.equal(await ocAfterHandler(env, { tool: 'write', args: { file_path: 'src/a.ts' } }), undefined)
  assert.equal(await loadSession(env.paths.sessionDir, 'anon'), undefined)
  assert.equal(stderrLines.length, 0)
})

// ---------------------------------------------------------------------------
// turn-end handler (exported for the future stop seam; v1 leaves it unregistered)
// ---------------------------------------------------------------------------

test('turn-end: inert configuration produces no verdict and does not throw', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root, { requireBaseline: 'off', driftDetection: false, enforceOnTurnEnd: false })
  assert.equal(await ocTurnEndHandler(env, 's-none'), undefined)
  assert.equal(await ocTurnEndHandler(env, undefined), undefined)
})

// ---------------------------------------------------------------------------
// prompt injection
// ---------------------------------------------------------------------------

test('prompt addition carries the policy section and all five MCP tool names', async () => {
  const root = await freshWorkspace()
  const { env } = makeEnv(root)
  const text = buildSystemPromptAddition(env)
  assert.match(text, /proof:policy/)
  for (const name of ['proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle']) {
    assert.match(text, new RegExp(name))
  }
  assert.match(text, /YOUR regression/)
})

// ---------------------------------------------------------------------------
// 4. createOpencodePlugin — probing, registration, end-to-end
// ---------------------------------------------------------------------------

type Hook = (input: unknown, output: unknown) => unknown

function syntheticContext(root: string, sinks: { before: Hook[]; after: Hook[]; params: Hook[] }): Record<string, unknown> {
  return {
    tool: {
      execute: {
        before: (h: Hook) => { sinks.before.push(h); return () => undefined },
        after: (h: Hook) => { sinks.after.push(h) },
      },
    },
    chat: { params: (h: Hook) => { sinks.params.push(h) } },
    project: { directory: root },
  }
}

test('plugin: registers on a duck-typed context, holds evidence-store writes end to end, injects the prompt', async () => {
  const root = await freshWorkspace()
  await write(root, 'src/a.ts', 'A\n')
  const stderrLines: string[] = []
  const sinks = { before: [] as Hook[], after: [] as Hook[], params: [] as Hook[] }
  const init = createOpencodePlugin({
    trustRoot: join(root, 'trust'),
    evidenceStore: 'workspace',
    stderr: line => stderrLines.push(line),
  })
  const handle = await init(syntheticContext(root, sinks))

  // registration happened on every probed surface
  assert.equal(sinks.before.length, 1)
  assert.equal(sinks.after.length, 1)
  assert.equal(sinks.params.length, 1)
  assert.ok(stderrLines.some(l => l.includes('dsh-proof: OpenCode adapter active')))
  assert.ok(stderrLines.some(l => l.includes('tool.execute.before')))

  // end to end: the host invokes the registered before handler; a held call
  // comes back as OpenCode's `{ error: { message } }` interception shape
  const held = await sinks.before[0]!(
    { tool: 'write', args: { file_path: '.proof/evidence.jsonl' }, sessionID: 's1' },
    {},
  )
  assert.ok(typeof held === 'object' && held !== null, `expected an interception object, got ${String(held)}`)
  const message = (held as { error?: { message?: unknown } }).error?.message
  assert.ok(typeof message === 'string')
  assert.match(message, /evidence/i)
  assert.ok(stderrLines.some(l => l.includes('holding a tool call')))

  // a passing call resolves undefined
  assert.equal(
    await sinks.before[0]!({ tool: 'read', args: { file_path: 'src/a.ts' }, sessionID: 's1' }, {}),
    undefined,
  )

  // the registered after handler observes and persists
  assert.equal(
    await sinks.after[0]!({ tool: 'write', args: { file_path: 'src/a.ts' }, sessionID: 's1' }, {}),
    undefined,
  )
  const session = await loadSession(ocAdapterEnv({ trustRoot: join(root, 'trust') }, root).paths.sessionDir, 's1')
  assert.ok(session !== undefined)
  assert.ok(session.touched.includes('src/a.ts'))

  // prompt injection: the host invokes the registered params handler with the
  // assembled chat parameters; a string `system` gets the addition appended
  const stringParams: { system?: unknown } = { system: 'You are a coding agent.' }
  sinks.params[0]!({}, stringParams)
  assert.ok(typeof stringParams.system === 'string')
  assert.match(stringParams.system as string, /You are a coding agent\./)
  assert.match(stringParams.system as string, /proof:policy/)
  // an array-of-parts `system` gets the addition appended as a new part
  const arrayParams: { system?: unknown } = { system: ['Be brief.'] }
  sinks.params[0]!({}, arrayParams)
  assert.ok(Array.isArray(arrayParams.system))
  assert.ok((arrayParams.system as unknown[]).some(part => typeof part === 'string' && part.includes('proof:policy')))

  handle.dispose()
})

test('plugin: a surface-less context degrades to a no-op with one stderr line', async () => {
  const root = await freshWorkspace()
  const stderrLines: string[] = []
  const init = createOpencodePlugin({ trustRoot: join(root, 'trust'), stderr: line => { stderrLines.push(line) } })
  const handle = await init({})
  assert.ok(stderrLines.some(l => l.includes('no compatible OpenCode plugin surface found')))
  assert.ok(stderrLines.some(l => l.includes('MCP tools still work')))
  handle.dispose()
  // a non-object context behaves identically
  const again = await init(42)
  again.dispose()
  assert.equal(stderrLines.length, 2)
})

// ---------------------------------------------------------------------------
// 5. hostile contexts — the adapter never throws into the host
// ---------------------------------------------------------------------------

test('plugin: registrars that throw degrade to stderr lines, never exceptions', async () => {
  const root = await freshWorkspace()
  const stderrLines: string[] = []
  const accepted: Hook[] = []
  const hostile = {
    tool: {
      execute: {
        // accepts the handler, then explodes anyway — our bookkeeping must
        // treat the seam as failed while the wrapped handler stays callable
        before: (h: Hook) => { accepted.push(h); throw new Error('boom-before') },
        after: () => { throw new Error('boom-after') },
      },
    },
    chat: { params: () => { throw new Error('boom-params') } },
    project: { directory: root },
  }
  const init = createOpencodePlugin({ trustRoot: join(root, 'trust'), stderr: line => stderrLines.push(line) })
  const handle = await init(hostile) // must not throw
  assert.ok(stderrLines.some(l => l.includes('registration failed')))
  handle.dispose()

  // the wrapped handler invoked with hostile payloads returns undefined
  assert.equal(await accepted[0]!(null, undefined), undefined)
  assert.equal(await accepted[0]!(42, 'x'), undefined)
  assert.equal(await accepted[0]!({ tool: 'write' }, undefined), undefined)
})

test('plugin: a registrar returning junk registers fine and disposes without a fight', async () => {
  const root = await freshWorkspace()
  const stderrLines: string[] = []
  const init = createOpencodePlugin({ trustRoot: join(root, 'trust'), stderr: line => stderrLines.push(line) })
  const handle = await init({ tool: { execute: { before: () => ({ weird: true }) } }, directory: root })
  assert.ok(stderrLines.some(l => l.includes('OpenCode adapter active')))
  handle.dispose()
})

test('plugin: the default export is the bare initializer (what OpenCode loads)', () => {
  // createOpencodePlugin() with no options — an `(ctx) => Promise<{dispose}>`
  // initializer. Not invoked here: its defaults point at the real stderr and
  // trust root, and pinning the shape is what matters.
  assert.equal(typeof opencodePluginDefault, 'function')
  assert.equal(opencodePluginDefault.length, 1)
})
