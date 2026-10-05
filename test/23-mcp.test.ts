/**
 * MCP SERVER INTEGRATION — the real protocol over a real subprocess.
 *
 * Spawns `node --experimental-strip-types src/app/mcp-entry.ts` against a
 * minimal real npm project and drives it over newline-delimited JSON-RPC 2.0
 * on stdio: the handshake, the five-tool contract, a real baseline → verify →
 * status → bundle chain (real `npm test`, real evidence, real Ed25519 chain),
 * and the error paths (unknown tool, bogus claim kind, malformed JSON line).
 * Nothing is stubbed — this is the test that proves any foreign harness can
 * drive the proof protocol end to end.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

// The repo (for the entry script) and the scratch workspace per the task's
// designated temp area: C:\mimoclaw_workspace\.openclaw\tmp\mcp-it-<pid>.
const ENTRY = fileURLToPath(new URL('../src/app/mcp-entry.ts', import.meta.url))
const WORKSPACE = join(fileURLToPath(new URL('../../../.openclaw/tmp', import.meta.url)), `mcp-it-${process.pid}`)

const MCP_TOOLS = ['proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle'] as const

const CHECK_SCRIPT = [
  "import assert from 'node:assert/strict'",
  'assert.equal(1 + 1, 2)',
  "console.log('PASS 1 test')",
  '',
].join('\n')

const REQUEST_TIMEOUT_MS = 30_000

// ---------------------------------------------------------------------------
// A minimal newline-delimited JSON-RPC client: writes one request per line,
// resolves when the line carrying the same id comes back. Also keeps every
// received line countable (to prove notifications get no reply) and offers
// nextLine() for responses that carry no id (protocol errors).
// ---------------------------------------------------------------------------

class LineRpc {
  private nextId = 1
  private readonly pending = new Map<number, { resolve: (m: Record<string, unknown>) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>()
  private lineWaiter: ((line: string) => void) | undefined
  private buffer = ''
  private exited = false
  receivedLines = 0
  stderrText = ''

  private readonly child: ChildProcess

  constructor(child: ChildProcess) {
    this.child = child
    child.stdout!.setEncoding('utf8')
    child.stdout!.on('data', (chunk: string) => {
      this.buffer += chunk
      let index = this.buffer.indexOf('\n')
      while (index >= 0) {
        const line = this.buffer.slice(0, index)
        this.buffer = this.buffer.slice(index + 1)
        if (line.trim().length > 0) this.onLine(line)
        index = this.buffer.indexOf('\n')
      }
    })
    child.stderr!.setEncoding('utf8')
    child.stderr!.on('data', (chunk: string) => { this.stderrText += chunk })
    child.on('exit', () => {
      this.exited = true
      for (const [, entry] of this.pending) {
        clearTimeout(entry.timer)
        entry.reject(new Error(`server exited before answering (stderr: ${this.stderrText.slice(0, 2000)})`))
      }
      this.pending.clear()
    })
  }

  private onLine(line: string): void {
    this.receivedLines += 1
    const waiter = this.lineWaiter
    if (waiter !== undefined) {
      this.lineWaiter = undefined
      waiter(line)
      return
    }
    let message: { id?: unknown }
    try {
      message = JSON.parse(line) as { id?: unknown }
    } catch {
      return // a non-JSON line from the server is a protocol bug; requests will time out
    }
    if (typeof message.id !== 'number') return
    const entry = this.pending.get(message.id)
    if (entry === undefined) return
    this.pending.delete(message.id)
    clearTimeout(entry.timer)
    entry.resolve(message)
  }

  /** The next stdout line, whatever it carries (used for id-less error responses). */
  nextLine(timeoutMs = REQUEST_TIMEOUT_MS): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout waiting for a line (stderr: ${this.stderrText.slice(0, 2000)})`)), timeoutMs)
      this.lineWaiter = (line) => { clearTimeout(timer); resolve(line) }
    })
  }

  request(method: string, params?: unknown, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Record<string, unknown>> {
    const id = this.nextId++
    const payload = new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`timeout waiting for ${method} (id=${id}; stderr: ${this.stderrText.slice(0, 2000)})`))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
    })
    this.child.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) })}\n`)
    if (this.exited) throw new Error('server already exited')
    return payload
  }

  /** Send a raw line (malformed JSON tests) or a notification (no id, no reply). */
  send(line: string): void {
    this.child.stdin!.write(`${line}\n`)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}

// ---------------------------------------------------------------------------
// fixture + server lifecycle
// ---------------------------------------------------------------------------

let child: ChildProcess
let client: LineRpc

before(async () => {
  await fsp.rm(WORKSPACE, { recursive: true, force: true })
  await fsp.mkdir(WORKSPACE, { recursive: true })
  await fsp.writeFile(join(WORKSPACE, 'package.json'), JSON.stringify({
    name: 'mcp-it-fixture',
    version: '1.0.0',
    private: true,
    scripts: { test: 'node check.mjs' },
  }, null, 2))
  await fsp.writeFile(join(WORKSPACE, 'check.mjs'), CHECK_SCRIPT)

  child = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  client = new LineRpc(child)
})

after(async () => {
  child.kill()
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, 5_000)
    child.once('exit', () => { clearTimeout(timer); resolve() })
  })
  await fsp.rm(WORKSPACE, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// protocol lifecycle
// ---------------------------------------------------------------------------

test('initialize handshake answers with the server identity and a supported protocol version', async () => {
  const response = await client.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'dsh-proof-test', version: '0.0.0' },
  })
  assert.equal(response.error, undefined, `initialize must not fail: ${JSON.stringify(response.error)}`)
  const result = response.result as {
    protocolVersion: string
    capabilities: { tools: { listChanged: boolean } }
    serverInfo: { name: string; version: string }
  }
  assert.equal(result.serverInfo.name, 'agent-proof-protocol')
  assert.equal(result.serverInfo.version, '0.14.0')
  assert.equal(result.protocolVersion, '2025-06-18', 'a requested supported version is echoed back')
  assert.equal(result.capabilities.tools.listChanged, false)
})

test('an unsupported requested protocol version is answered with the newest supported one', async () => {
  const response = await client.request('initialize', {
    protocolVersion: '1999-01-01',
    capabilities: {},
    clientInfo: { name: 'dsh-proof-test', version: '0.0.0' },
  })
  const result = response.result as { protocolVersion: string }
  assert.equal(result.protocolVersion, '2025-06-18')
})

test('notifications/initialized produces no reply and ping answers an empty result', async () => {
  const before = client.receivedLines
  client.send(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }))
  await sleep(250)
  assert.equal(client.receivedLines, before, 'a notification must never be answered')

  const pong = await client.request('ping')
  assert.equal(pong.error, undefined)
  assert.deepEqual(pong.result, {})
})

test('tools/list exposes exactly the five APP/1.0 contract tools', async () => {
  const response = await client.request('tools/list', {})
  assert.equal(response.error, undefined)
  const tools = (response.result as {
    tools: { name: string; description: string; inputSchema: Record<string, unknown> }[]
  }).tools
  assert.deepEqual(
    tools.map(t => t.name).sort(),
    [...MCP_TOOLS].sort(),
    'the cross-agent contract is exactly five tools',
  )
  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, 'object', `${tool.name} inputSchema must be an object schema`)
    assert.ok(typeof tool.description === 'string' && tool.description.length > 0, `${tool.name} carries a description`)
  }
  const claim = tools.find(t => t.name === 'proof_claim')!
  assert.deepEqual((claim.inputSchema as { required?: string[] }).required, ['claim'])
  const kind = (claim.inputSchema as { properties?: Record<string, { enum?: string[] }> }).properties?.kind?.enum
  assert.deepEqual(kind, ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'])
})

test('an unknown method is a JSON-RPC -32601 error', async () => {
  const response = await client.request('resources/list', {})
  const error = response.error as { code: number; message: string } | undefined
  assert.ok(error !== undefined, 'unknown methods answer with a JSON-RPC error')
  assert.equal(error.code, -32601)
})

// ---------------------------------------------------------------------------
// end to end: a real baseline, a real verification, real chain state
// ---------------------------------------------------------------------------

interface ToolCallResponse {
  isError?: true
  content: { type: string; text: string }[]
  structuredContent: Record<string, unknown>
}

async function callTool(name: string, args: Record<string, unknown>, timeoutMs = REQUEST_TIMEOUT_MS): Promise<ToolCallResponse> {
  const response = await client.request('tools/call', { name, arguments: args }, timeoutMs)
  assert.equal(response.error, undefined, `tools/call ${name} must not fail at the RPC layer: ${JSON.stringify(response.error)}`)
  const result = response.result as ToolCallResponse
  assert.equal(result.content[0]?.type, 'text', 'MCP tool results carry text content')
  assert.deepEqual(JSON.parse(result.content[0]!.text), result.structuredContent, 'content text is the JSON of structuredContent')
  return result
}

test('proof_baseline really runs the workspace npm test and anchors a baseline', async () => {
  const result = await callTool('proof_baseline', {}, 60_000)
  assert.equal(result.isError, undefined, `baseline errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as { ok: boolean; ran: number; passing: number; failing: number }
  assert.equal(value.ok, true)
  assert.ok(value.ran >= 1, 'the real check was discovered and ran')
  assert.equal(value.passing, value.ran)
  assert.equal(value.failing, 0)
})

test('proof_verify against an unchanged file grades still-passing work proven', async () => {
  const result = await callTool('proof_verify', { changed: ['check.mjs'] }, 60_000)
  assert.equal(result.isError, undefined, `verify errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    grade: string; failing: number; regressions: unknown[]; changed: string[]
  }
  assert.equal(value.grade, 'proven')
  assert.equal(value.failing, 0)
  assert.deepEqual(value.regressions, [])
  assert.deepEqual(value.changed, ['check.mjs'])
})

test('proof_status reports the baseline, the checks and an intact chain', async () => {
  const result = await callTool('proof_status', {})
  assert.equal(result.isError, undefined)
  const value = result.structuredContent as {
    hasBaseline: boolean; chainIntact: boolean; evidenceLogIntact: boolean
    checks: { label: string; lastStatus: string | null }[]; evidenceRecords: number
  }
  assert.equal(value.hasBaseline, true)
  assert.equal(value.chainIntact, true)
  assert.equal(value.evidenceLogIntact, true)
  assert.ok(value.checks.length >= 1)
  assert.equal(value.checks[0]?.lastStatus, 'pass')
  assert.ok(value.evidenceRecords >= 1, 'real evidence landed on the chain')
})

test('proof_bundle exports a manifest that digests the evidence log', async () => {
  const result = await callTool('proof_bundle', {}, 60_000)
  assert.equal(result.isError, undefined, `bundle errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    bundle: {
      manifest: { protocol: string; files: { path: string; sha256: string; bytes: number }[] }
      files: Record<string, string>
    }
  }
  assert.ok(value.bundle !== undefined, 'a small bundle rides the response in full')
  assert.equal(value.bundle.manifest.protocol, 'APP/1.0')
  const entry = value.bundle.manifest.files.find(f => f.path === 'evidence.jsonl')
  assert.ok(entry !== undefined, 'the manifest digests evidence.jsonl')
  assert.match(entry.sha256, /^[0-9a-f]{64}$/)
  assert.ok(typeof value.bundle.files['evidence.jsonl'] === 'string')
})

// ---------------------------------------------------------------------------
// error paths
// ---------------------------------------------------------------------------

test('an unknown tool is a normal result with isError: true, not an RPC error', async () => {
  const result = await callTool('proof_nope', {})
  assert.equal(result.isError, true, 'unknown tools answer with MCP tool-error semantics')
  assert.match(result.content[0]!.text, /unknown tool/, 'the text names the problem')
})

test('proof_claim with a bogus kind errors loudly instead of silently downgrading', async () => {
  const result = await callTool('proof_claim', { claim: 'changed nothing at all', kind: 'bogus' }, 60_000)
  assert.equal(result.isError, true, 'a foreign agent must be told its contract kind is not one of the five')
  const text = result.content[0]!.text
  assert.match(text, /kind/, 'the error names the offending argument')
  assert.match(text, /bogus/, 'the error echoes the offending value')
  assert.ok(!text.includes('"proven"'), 'the answer must not read like a verification verdict')
})

test('a malformed JSON line gets a -32700 JSON-RPC error response', async () => {
  client.send('{ this is not json')
  const line = await client.nextLine()
  const message = JSON.parse(line) as { id: unknown; error: { code: number; message: string } }
  assert.equal(message.error.code, -32700)
  assert.equal(message.id, null, 'a parse error answers with id null — the line carried none')
})
