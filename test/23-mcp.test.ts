/**
 * MCP SERVER INTEGRATION — the real protocol over a real subprocess.
 *
 * Spawns `node --experimental-strip-types src/app/mcp-entry.ts` against a
 * minimal real npm project and drives it over newline-delimited JSON-RPC 2.0
 * on stdio: the handshake, the thirteen-tool APP/1.4 contract, a real baseline →
 * verify → status → bundle → publish → log-verify chain, then the v0.19
 * responsibility DAG end to end (delegate → task overview/detail → honest
 * bundle submit → forged bundle refusal), then the v0.20 training-export
 * valve (private default with no samples on the wire, full + path writing the
 * JSONL dataset to disk, the loud enum refusal), then the v0.21
 * verification-economics pair (the SLA quote's offer/denied doors over the
 * real engine, and proof_economics' honest absence until a rate-carrying
 * verification lands a ledger on the chain) — real `npm test`, real
 * evidence, real Ed25519 chain, real transparency log — and the error paths
 * (unknown tool, bogus claim kind, malformed JSON line). Nothing is stubbed —
 * this is the test that proves any foreign harness can drive the proof
 * protocol end to end.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { sha256 } from '../src/core/hash.ts'
// v0.19: the worker's half of the delegation protocol is simulated in-process
// by minting a real APP bundle from the fixture's evidence artifacts — the
// same builder the proof_bundle tool itself calls.
import { buildBundle } from '../src/app/bundle.ts'

// The repo (for the entry script) and the scratch workspace per the task's
// designated temp area: C:\mimoclaw_workspace\.openclaw\tmp\mcp-it-<pid>.
const ENTRY = fileURLToPath(new URL('../src/app/mcp-entry.ts', import.meta.url))
const WORKSPACE = join(fileURLToPath(new URL('../../../.openclaw/tmp', import.meta.url)), `mcp-it-${process.pid}`)

// v0.18 (APP/1.1): the transparency-log tools joined the frozen contract;
// v0.19 (APP/1.2): the responsibility-DAG tools took it to ten; v0.20
// (APP/1.3): the training-export tool took it to eleven; v0.21 (APP/1.4):
// the verification-economics tools take it to thirteen — appended in order
// so every earlier dialect's prefix is unchanged.
const MCP_TOOLS = [
  'proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle',
  'proof_publish', 'proof_log_verify',
  'proof_delegate', 'proof_delegate_submit', 'proof_task',
  'proof_training_export',
  'proof_economics', 'proof_sla_quote',
] as const

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
  assert.equal(result.serverInfo.version, '0.21.0')
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

test('tools/list exposes exactly the thirteen APP/1.4 contract tools', async () => {
  const response = await client.request('tools/list', {})
  assert.equal(response.error, undefined)
  const tools = (response.result as {
    tools: { name: string; description: string; inputSchema: Record<string, unknown> }[]
  }).tools
  assert.deepEqual(
    tools.map(t => t.name).sort(),
    [...MCP_TOOLS].sort(),
    'the cross-agent contract is exactly thirteen tools',
  )
  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, 'object', `${tool.name} inputSchema must be an object schema`)
    assert.ok(typeof tool.description === 'string' && tool.description.length > 0, `${tool.name} carries a description`)
  }
  const claim = tools.find(t => t.name === 'proof_claim')!
  assert.deepEqual((claim.inputSchema as { required?: string[] }).required, ['claim'])
  const kind = (claim.inputSchema as { properties?: Record<string, { enum?: string[] }> }).properties?.kind?.enum
  assert.deepEqual(kind, ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'])
  // v0.19: the delegation tools' parameter faces — the orchestrator's
  // delegate needs a claim, the worker's submit needs a task and a bundle,
  // and the task inspector's optional ownGrade speaks the five-grade scale.
  const delegate = tools.find(t => t.name === 'proof_delegate')!
  assert.deepEqual((delegate.inputSchema as { required?: string[] }).required, ['claim'])
  const submit = tools.find(t => t.name === 'proof_delegate_submit')!
  assert.deepEqual(
    ((submit.inputSchema as { required?: string[] }).required ?? []).slice().sort(),
    ['bundle', 'taskId'],
  )
  const task = tools.find(t => t.name === 'proof_task')!
  assert.equal((task.inputSchema as { required?: string[] }).required, undefined, 'proof_task takes no required argument')
  const ownGrade = (task.inputSchema as { properties?: Record<string, { enum?: string[] }> }).properties?.ownGrade?.enum
  assert.deepEqual(ownGrade, ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'])
  // v0.20: the training-export tool's parameter face — the two-tier fidelity
  // scale with its private DEFAULT pinned in the schema, the provenance
  // filter's two scopes, and no required argument (privacy is the default,
  // not something a caller must remember to ask for).
  const training = tools.find(t => t.name === 'proof_training_export')!
  assert.equal(
    (training.inputSchema as { required?: string[] }).required,
    undefined,
    'proof_training_export takes no required argument — private is the default tier',
  )
  const trainingProps = (training.inputSchema as {
    properties?: Record<string, { enum?: string[]; default?: string }>
  }).properties
  assert.deepEqual(trainingProps?.fidelity?.enum, ['full', 'private'])
  assert.equal(trainingProps?.fidelity?.default, 'private', 'the privacy default is pinned in the schema itself')
  assert.deepEqual(trainingProps?.provenanceFilter?.enum, ['agent-only', 'all'])
  // v0.21: the verification-economics pair's parameter faces — the economics
  // query demands a real rate card (computePerMs required), and the quote
  // speaks the five-grade scale with a USD-only currency enum and no required
  // pricing knobs beyond the grade and the coverage.
  const economics = tools.find(t => t.name === 'proof_economics')!
  assert.deepEqual(
    (economics.inputSchema as { required?: string[] }).required,
    ['computePerMs'],
    'the rate card\'s compute price is the one required argument',
  )
  const economicsProps = (economics.inputSchema as {
    properties?: Record<string, { type?: string; exclusiveMinimum?: number }>
  }).properties
  assert.equal(economicsProps?.computePerMs?.type, 'number')
  assert.equal(economicsProps?.computePerMs?.exclusiveMinimum, 0, 'a zero-or-negative rate is refused by the schema itself')
  assert.equal(economicsProps?.humanReviewPerItem?.type, 'number')
  const sla = tools.find(t => t.name === 'proof_sla_quote')!
  assert.deepEqual(
    ((sla.inputSchema as { required?: string[] }).required ?? []).slice().sort(),
    ['coverageAmount', 'grade'],
  )
  const slaProps = (sla.inputSchema as {
    properties?: Record<string, { type?: string; enum?: string[]; minimum?: number; maximum?: number; exclusiveMinimum?: number }>
  }).properties
  assert.deepEqual(slaProps?.grade?.enum, ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'])
  assert.equal(slaProps?.coverageAmount?.type, 'number')
  assert.equal(slaProps?.coverageAmount?.exclusiveMinimum, 0)
  assert.equal(slaProps?.confidence?.type, 'number')
  assert.equal(slaProps?.confidence?.minimum, 0)
  assert.equal(slaProps?.confidence?.maximum, 1)
  assert.deepEqual(slaProps?.currency?.enum, ['USD'], 'only USD is priced — a singleton enum, not a free string')
  assert.equal(slaProps?.deductible?.type, 'number')
  assert.equal(slaProps?.minPremium?.type, 'number')
  // And the economics description does its one navigational job: it tells a
  // caller with no ledger on the chain exactly how to mint one — v0.21 closed
  // the seam: proof_verify itself accepts the rate card on this MCP face.
  assert.ok(
    economics.description.includes('economics: {computePerMs, humanReviewPerItem?}'),
    'the description names the rate-carrying verify entry point that mints a ledger',
  )
  // The seam it names must actually exist: proof_verify's schema carries the
  // economics rate card with computePerMs required.
  const verify = tools.find(t => t.name === 'proof_verify')!
  const verifyEconomics = (verify.inputSchema as {
    properties?: Record<string, { type?: string; required?: string[] }>
  }).properties?.economics
  assert.equal(verifyEconomics?.type, 'object', 'proof_verify prices the run when asked')
  assert.deepEqual(verifyEconomics?.required, ['computePerMs'])
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
  assert.equal(value.bundle.manifest.protocol, 'APP/1.4')
  const entry = value.bundle.manifest.files.find(f => f.path === 'evidence.jsonl')
  assert.ok(entry !== undefined, 'the manifest digests evidence.jsonl')
  assert.match(entry.sha256, /^[0-9a-f]{64}$/)
  assert.ok(typeof value.bundle.files['evidence.jsonl'] === 'string')
})

// ---------------------------------------------------------------------------
// v0.18: the transparency-log tools over the real subprocess (real Ed25519
// operator key bootstrapped under <trustRoot>/ptl, real Merkle tree on disk)
// ---------------------------------------------------------------------------

// A type alias (not an interface): anonymous object types carry the implicit
// index signature that lets `structuredContent as PublishValue` typecheck.
type PublishValue = {
  sequence: number
  duplicate: boolean
  leafHash: string
  treeSize: number
  root: string
  logId: string
  at: string
  inclusionProof: string[]
  sth: { logId: string; treeSize: number; root: string; at: string; sig: string }
}

let firstPublish: PublishValue | undefined

test('proof_publish mirrors the latest signed checkpoint and detects the duplicate republish', async () => {
  const result = await callTool('proof_publish', {}, 60_000)
  assert.equal(result.isError, undefined, `publish errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as PublishValue
  firstPublish = value
  assert.equal(value.duplicate, false, 'the first publish mints a new leaf')
  assert.equal(value.sequence, 0)
  assert.equal(value.treeSize, 1)
  assert.match(value.leafHash, /^[0-9a-f]{64}$/, 'the entry addresses to a hex sha256 leaf')
  assert.match(value.root, /^[0-9a-f]{64}$/, 'the tree commits to a hex sha256 root')
  assert.equal(value.sth.treeSize, 1)
  assert.equal(value.sth.root, value.root, 'the signed tree head covers the recomputed root')
  assert.match(value.sth.sig, /^[A-Za-z0-9+/]+={0,2}$/, 'the STH carries a base64 Ed25519 signature')
  assert.ok(Array.isArray(value.inclusionProof))

  // Republishing without new signed work changes nothing: duplicate detected,
  // the tree does not grow (re-publishing cannot pad the public log).
  const again = await callTool('proof_publish', {}, 60_000)
  assert.equal(again.isError, undefined, `republish errored: ${again.content[0]?.text}`)
  const dup = again.structuredContent as PublishValue
  assert.equal(dup.duplicate, true)
  assert.equal(dup.treeSize, 1, 'the tree is unchanged by a duplicate publish')
  assert.equal(dup.sequence, 0)
  assert.equal(dup.leafHash, value.leafHash)
})

test('proof_log_verify audits the log: self-check, inclusion, consistency — and refuses forgery', async () => {
  assert.ok(firstPublish !== undefined, 'the publish test ran first (state chains, like baseline → verify)')

  // More signed work on the chain: a fresh verification appends evidence and
  // a NEW signed checkpoint, so the next publish grows the tree to 2.
  const verify = await callTool('proof_verify', { changed: ['check.mjs'] }, 60_000)
  assert.equal((verify.structuredContent as { grade: string }).grade, 'proven')
  const second = await callTool('proof_publish', {}, 60_000)
  assert.equal(second.isError, undefined, `second publish errored: ${second.content[0]?.text}`)
  const secondValue = second.structuredContent as PublishValue
  assert.equal(secondValue.duplicate, false)
  assert.equal(secondValue.sequence, 1, 'the second checkpoint lands as the second leaf')
  assert.equal(secondValue.treeSize, 2)

  // Self-check (no arguments): the root is recomputed from the log's own
  // bytes and the tree head's signature is adjudicated under the operator
  // key the publish bootstrapped.
  const self = await callTool('proof_log_verify', {})
  assert.equal(self.isError, undefined, `self-check errored: ${self.content[0]?.text}`)
  const selfValue = self.structuredContent as {
    ok: boolean
    treeSize: number
    root: string
    treeHead: { logId: string; treeSize: number; root: string; sizeMatches: boolean; rootMatches: boolean; signature: string }
  }
  assert.equal(selfValue.ok, true, JSON.stringify(selfValue))
  assert.equal(selfValue.treeHead.logId, secondValue.logId, 'the head names the operator key that signed it')
  assert.equal(selfValue.treeSize, 2)
  assert.equal(selfValue.root, secondValue.root)
  assert.equal(selfValue.treeHead.signature, 'verified', 'the operator key is present — the STH must genuinely verify')
  assert.equal(selfValue.treeHead.rootMatches, true)
  assert.equal(selfValue.treeHead.sizeMatches, true)

  // Full arguments: inclusion of the FIRST leaf (against the grown tree) and
  // consistency from the first published tree to the current one.
  const full = await callTool('proof_log_verify', {
    sequence: firstPublish.sequence,
    leafHash: firstPublish.leafHash,
    publishedTreeSize: firstPublish.treeSize,
    publishedRoot: firstPublish.root,
  }, 60_000)
  assert.equal(full.isError, undefined, `full verify errored: ${full.content[0]?.text}`)
  const fullValue = full.structuredContent as {
    ok: boolean
    inclusion: { sequence: number; leafHash: string; verified: boolean }
    consistency: { fromTreeSize: number; toTreeSize: number; verified: boolean }
  }
  assert.equal(fullValue.ok, true, JSON.stringify(fullValue))
  assert.equal(fullValue.inclusion.sequence, 0)
  assert.equal(fullValue.inclusion.verified, true, 'the first leaf is committed by the current root')
  assert.equal(fullValue.consistency.fromTreeSize, 1)
  assert.equal(fullValue.consistency.toTreeSize, 2)
  assert.equal(fullValue.consistency.verified, true, 'the current tree provably extends the first published tree')

  // The hostile direction: a root that was never published fails the audit
  // loudly — the tool recomputes everything, so a forged "published past" is
  // a finding (ok: false), never a guess.
  const hostile = await callTool('proof_log_verify', {
    publishedTreeSize: firstPublish.treeSize,
    publishedRoot: sha256('a root that was never published'),
  }, 60_000)
  assert.equal(hostile.isError, undefined)
  const hostileValue = hostile.structuredContent as { ok: boolean; problems: string[] }
  assert.equal(hostileValue.ok, false, 'a fabricated published root must fail the audit')
  assert.ok(
    hostileValue.problems.some(p => p.toLowerCase().includes('consistency')),
    `the problems name the consistency failure: ${JSON.stringify(hostileValue.problems)}`,
  )
})

// ---------------------------------------------------------------------------
// v0.19: the responsibility DAG over the real subprocess — real delegation
// markers on the real chain, a worker bundle minted from the fixture's own
// artifacts (the cross-process story in miniature), and the engine's
// adjudication of an honest vs a forged submission.
// ---------------------------------------------------------------------------

// The obligation the orchestrator delegates across the tests below.
const DELEGATED_CLAIM = 'deliver the audit-report section with evidence citations'
const DELEGATED_ACCEPTANCE = 'the section exists, cites at least three evidence records, and npm test passes'

/**
 * Mint the bundle a worker agent would export from ITS completed workspace.
 * The fixture's store already holds a green baseline + verify chain by this
 * point in the file (state chains, like the publish tests above), so this is
 * the honest export: same builder, same artifacts, as proof_bundle itself.
 */
async function mintWorkerBundle(): Promise<{ manifest: { protocol: string }; files: Record<string, string> }> {
  // mcp-entry's derivation, mirrored: workspaceKey = sha256(root)[:16], host
  // mode stores evidence at <trustRoot>/workspaces/<key>.
  const workspaceKey = sha256(WORKSPACE).slice(0, 16)
  const storeDir = join(WORKSPACE, 'trust', 'workspaces', workspaceKey)
  const evidenceLog = await fsp.readFile(join(storeDir, 'evidence.jsonl'), 'utf8')
  const input: { evidenceLog: string; baselineJson?: string; anchorJson?: string } = { evidenceLog }
  await fsp.readFile(join(storeDir, 'baseline.json'), 'utf8').then(
    (baselineJson) => { input.baselineJson = baselineJson },
    () => { /* absent — the bundle simply omits it */ },
  )
  await fsp.readFile(join(WORKSPACE, 'trust', 'anchors', workspaceKey, 'anchor.json'), 'utf8').then(
    (anchorJson) => { input.anchorJson = anchorJson },
    () => { /* absent — the bundle simply omits it */ },
  )
  const bundle = buildBundle(input, workspaceKey, new Date().toISOString())
  return { manifest: bundle.manifest, files: { ...bundle.files } }
}

test('proof_delegate records the obligation and returns the worker handoff instruction', async () => {
  const result = await callTool('proof_delegate', {
    claim: DELEGATED_CLAIM,
    acceptance: DELEGATED_ACCEPTANCE,
  })
  assert.equal(result.isError, undefined, `delegate errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    taskId: string
    obligationId: string
    obligation: { claim?: unknown; acceptance?: unknown }
    instruction: string
  }
  assert.equal(value.taskId, 'task-1', 'the first delegation on a fresh chain numbers task-1')
  assert.equal(typeof value.obligationId, 'string')
  assert.ok(value.obligationId.length > 0, 'the obligation carries its own chain identity')
  assert.equal(value.obligation.claim, DELEGATED_CLAIM, 'the obligation records the claim verbatim')
  assert.equal(value.obligation.acceptance, DELEGATED_ACCEPTANCE, 'the obligation records the acceptance verbatim')
  // The instruction is the wiring point: everything the worker must know has
  // to ride in it, because the orchestrator will not be watching its prompt.
  assert.ok(value.instruction.includes(DELEGATED_CLAIM), 'the instruction restates the claim')
  assert.ok(value.instruction.includes(DELEGATED_ACCEPTANCE), 'the instruction restates the acceptance')
  assert.ok(value.instruction.includes('task-1'), 'the instruction names the taskId to submit against')
  assert.ok(value.instruction.includes('proof_baseline'), '…points the worker at proof_baseline first')
  assert.ok(value.instruction.includes('proof_verify'), '…tells the worker to prove before submitting')
  assert.ok(value.instruction.includes('proof_bundle'), '…tells the worker to export an APP bundle')
  assert.ok(value.instruction.includes('proof_delegate_submit'), '…tells the worker how to submit it back')
  assert.ok(value.instruction.includes('precondition'),
    '…states it plainly: the worker\'s proven is the precondition of the parent\'s')
})

test('proof_task before any submission: the overview lists the DAG, the parent composes stale', async () => {
  // The orchestrator nests the worker's obligation under its own: task-1 is
  // the parent (from the test above), task-2 the child that must discharge it.
  const child = await callTool('proof_delegate', {
    claim: 'write the audit-report section to spec',
    parentTaskId: 'task-1',
  })
  assert.equal(child.isError, undefined, `child delegate errored: ${child.content[0]?.text}`)
  assert.equal((child.structuredContent as { taskId: string }).taskId, 'task-2',
    'the second delegation numbers task-2')

  const overview = await callTool('proof_task', {})
  assert.equal(overview.isError, undefined, `overview errored: ${overview.content[0]?.text}`)
  const tasks = (overview.structuredContent as {
    tasks: { taskId: string; parentTaskId: string | null; claim: string; submitted: boolean }[]
  }).tasks
  const parent = tasks.find(t => t.taskId === 'task-1')
  const worker = tasks.find(t => t.taskId === 'task-2')
  assert.ok(parent !== undefined && worker !== undefined, 'the whole-graph overview lists both tasks')
  assert.equal(parent.parentTaskId, null, 'task-1 is a root obligation')
  assert.equal(worker.parentTaskId, 'task-1', 'the overview shows the nesting edge')
  assert.equal(worker.claim, 'write the audit-report section to spec')
  assert.ok(worker.claim.length <= 80, 'the overview summary is capped at 80 characters')
  assert.equal(parent.submitted, false, 'nothing has been submitted yet')
  assert.equal(worker.submitted, false, 'nothing has been submitted yet')

  // The parent's composed verdict while its obligation is unmet: stale, with
  // the unsubmitted child named — the orchestrator's honest stop-light.
  const detail = await callTool('proof_task', { taskId: 'task-1' })
  assert.equal(detail.isError, undefined, `detail errored: ${detail.content[0]?.text}`)
  const detailValue = detail.structuredContent as {
    taskId: string
    composed: { grade?: string; unprovenChildren?: string[] }
    nodes: unknown[]
    cycles: string[]
  }
  assert.equal(detailValue.taskId, 'task-1')
  assert.equal(detailValue.composed.grade, 'stale', 'an unmet obligation keeps the composed verdict stale')
  assert.ok(detailValue.composed.unprovenChildren?.includes('task-2'),
    'the unsubmitted child is named, not just counted')
  assert.equal(detailValue.nodes.length, 2, 'the full verdict carries the whole node set')
  assert.deepEqual(detailValue.cycles, [], 'an honest chain has no cycles')
})

test('proof_delegate_submit with an honestly minted worker bundle composes the obligation proven', async () => {
  const bundle = await mintWorkerBundle()
  assert.equal(bundle.manifest.protocol, 'APP/1.4', 'the worker exports the current dialect')

  // The child submits: a green baseline+verify chain minted into a bundle,
  // with no grade claimed — the derivation must earn 'proven' on its own.
  const result = await callTool('proof_delegate_submit', { taskId: 'task-2', bundle: { ...bundle, files: { ...bundle.files } } })
  assert.equal(result.isError, undefined, `submit errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    submission: { claimedGrade?: string; artifactVerified?: boolean }
    composed: { grade?: string; forgedChildren?: string[] }
  }
  assert.equal(value.submission.claimedGrade, 'proven',
    'an omitted claim over a green bundle with a baseline derives proven — the default is earned, not assumed')
  assert.equal(value.submission.artifactVerified, true, 'the untampered artifact verifies')
  assert.equal(value.composed.grade, 'proven', 'an honest bundle composes the submitting task proven')
  assert.deepEqual(value.composed.forgedChildren, [], 'an honest bundle forges nothing')

  // And the PARENT flips with it: the child's proven is the parent's
  // precondition, so the parent's composed verdict is no longer stale.
  const parent = await callTool('proof_task', { taskId: 'task-1' })
  assert.equal(parent.isError, undefined, `parent detail errored: ${parent.content[0]?.text}`)
  const parentValue = parent.structuredContent as {
    composed: { grade?: string; unprovenChildren?: string[] }
  }
  assert.equal(parentValue.composed.grade, 'proven', 'the parent is proven exactly when its obligation is discharged')
  assert.deepEqual(parentValue.composed.unprovenChildren, [])

  // The overview the orchestrator polls sees the submission land.
  const overview = await callTool('proof_task', {})
  const tasks = (overview.structuredContent as { tasks: { taskId: string; submitted: boolean }[] }).tasks
  assert.equal(tasks.find(t => t.taskId === 'task-2')?.submitted, true, 'the overview sees the submission land')
  assert.equal(tasks.find(t => t.taskId === 'task-1')?.submitted, false, 'the parent obligation itself never submitted')
})

test('a forged worker bundle is attributed, not absorbed — composed regressed with forgedChildren', async () => {
  // A second worker under the same parent, and this one lies: it CLAIMS
  // proven while shipping a bundle whose evidence log was rewritten after
  // the manifest was packed (one appended space) — the content no longer
  // digests to what the manifest claims.
  const second = await callTool('proof_delegate', { claim: 'deliver the performance-budget section', parentTaskId: 'task-1' })
  assert.equal(second.isError, undefined, `delegate errored: ${second.content[0]?.text}`)
  const secondTaskId = (second.structuredContent as { taskId: string }).taskId
  assert.equal(secondTaskId, 'task-3', 'the third delegation numbers task-3')

  const honest = await mintWorkerBundle()
  const forgedFiles: Record<string, string> = { ...honest.files }
  forgedFiles['evidence.jsonl'] = `${forgedFiles['evidence.jsonl'] ?? ''} `
  const forged = { manifest: honest.manifest, files: forgedFiles }

  const result = await callTool('proof_delegate_submit', { taskId: secondTaskId, bundle: forged, claimedGrade: 'proven' })
  assert.equal(result.isError, undefined, `submit errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    submission: { claimedGrade?: string; artifactVerified?: boolean }
    composed: { grade?: string }
  }
  assert.equal(value.submission.claimedGrade, 'proven', 'the lie is recorded verbatim — the claim the worker made')
  assert.equal(value.submission.artifactVerified, false, 'the recomputed digests catch the rewrite')
  assert.equal(value.composed.grade, 'regressed', 'a proven claim the artifact cannot back composes regressed')

  // And the parent's composed verdict attributes the forgery by taskId —
  // visible in forgedChildren, never silently absorbed into a lesser grade.
  const parent = await callTool('proof_task', { taskId: 'task-1' })
  assert.equal(parent.isError, undefined, `parent detail errored: ${parent.content[0]?.text}`)
  const parentValue = parent.structuredContent as {
    composed: { grade?: string; forgedChildren?: string[]; unprovenChildren?: string[] }
  }
  assert.equal(parentValue.composed.grade, 'regressed', 'one forged child regresses the parent')
  assert.ok(parentValue.composed.forgedChildren?.includes(secondTaskId),
    `forgedChildren attributes the forgery to ${secondTaskId}`)
  assert.ok(!parentValue.composed.forgedChildren?.includes('task-2'),
    'the honest sibling is not smeared by the forged one')
})

// ---------------------------------------------------------------------------
// v0.20 (APP/1.3): the training-export valve over the real subprocess — the
// chain's recorded agent behavior (a real baseline + verifications by this
// point in the file) distilled into a labeled dataset: the private default
// with zero samples on the wire, the full tier writing the JSONL dataset to
// disk via `path`, and the loud enum refusal.
// ---------------------------------------------------------------------------

test('proof_training_export defaults to the private tier and never ships samples on the wire', async () => {
  // No arguments at all: fidelity defaults to private, the whole response is
  // manifest + anchor + sampleCount — the samples themselves never ride it.
  const result = await callTool('proof_training_export', {}, 60_000)
  assert.equal(result.isError, undefined, `training export errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    manifest: {
      schema: string
      fidelity: string
      provenanceFilter: string
      counts: Record<string, number> | number
    }
    anchor: { count: number; head: unknown }
    sampleCount: number
  }
  assert.equal(value.manifest.schema, 'dsh-training/1', 'the dataset names its own schema version')
  assert.equal(value.manifest.fidelity, 'private', 'an omitted fidelity exports the private tier — zero output text')
  // The baseline + verifications that ran earlier in this file ARE the
  // dataset: the manifest must count at least one distilled sample.
  const counts = value.manifest.counts
  const total = typeof counts === 'number'
    ? counts
    : Object.values(counts ?? {}).reduce((sum, entry) => sum + (typeof entry === 'number' ? entry : 0), 0)
  assert.ok(total >= 1, `the manifest counts the distilled samples: ${JSON.stringify(counts)}`)
  assert.ok(value.anchor.count > 0, 'the anchor commits to a non-empty chain prefix — the dataset is auditable against the chain')
  assert.equal(typeof value.anchor.head, 'string', 'the anchor names the chain head it was distilled at')
  assert.ok((value.anchor.head as string).length > 0)
  assert.ok(typeof value.sampleCount === 'number' && value.sampleCount >= 1, 'sampleCount is reported even though the samples are not shipped')
  assert.equal(
    Object.keys(value).includes('samples'),
    false,
    'the samples never ride the response — manifest, anchor and count only; use path or the engine API for the dataset',
  )
  assert.equal('writtenTo' in value, false, 'no path was given — nothing was written to disk')
})

test('proof_training_export fidelity full with path writes the JSONL dataset to disk', async () => {
  const target = join(WORKSPACE, 'training-full.jsonl')
  const result = await callTool('proof_training_export', { fidelity: 'full', path: target }, 60_000)
  assert.equal(result.isError, undefined, `training export errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    manifest: { schema: string; fidelity: string }
    sampleCount: number
    writtenTo?: string
  }
  assert.equal(value.manifest.schema, 'dsh-training/1')
  assert.equal(value.manifest.fidelity, 'full', 'the explicit full tier is honored, not second-guessed')
  assert.ok(value.sampleCount >= 1)
  assert.equal(value.writtenTo, target, 'the response names where the engine wrote the dataset')
  // The disk is the channel for the samples: exactly sampleCount JSONL lines,
  // every one of them a JSON object (JSONL discipline).
  const onDisk = await fsp.readFile(value.writtenTo!, 'utf8')
  const lines = onDisk.split('\n').filter(line => line.trim().length > 0)
  assert.equal(lines.length, value.sampleCount, 'the JSONL on disk carries exactly sampleCount samples')
  for (const line of lines) {
    const parsed: unknown = JSON.parse(line)
    assert.equal(typeof parsed, 'object', 'each JSONL line is a JSON object — one sample per line')
    assert.ok(parsed !== null && !Array.isArray(parsed))
  }
  assert.equal(
    Object.keys(value).includes('samples'),
    false,
    'even the full tier with a path ships no samples on the wire — the file is the payload',
  )
})

test('proof_training_export refuses an unintelligible fidelity loudly, never silently defaulting', async () => {
  const result = await callTool('proof_training_export', { fidelity: 'loud' })
  assert.equal(result.isError, true, 'a fidelity the two-tier scale does not name is a tool error')
  const text = result.content[0]!.text
  assert.match(text, /fidelity/, 'the error names the offending argument')
  assert.match(text, /loud/, 'the error echoes the offending value')
  assert.ok(text.includes('full') && text.includes('private'), 'the error names the two legal tiers')
})

// ---------------------------------------------------------------------------
// v0.21 (APP/1.4): the verification-economics pair over the real subprocess.
// proof_sla_quote prices what a grade leaves undetected through the engine's
// own underwriting verb (offer / denied / manual-underwriting, exclusions, a
// chain-addressed quoteId); proof_economics reads ledgers back off the chain
// — and this MCP face deliberately never runs a rate-carrying verification
// (proof_verify's parameter surface stays minimal), so the honest answer
// until one lands is the pinned no-ledger error.
// ---------------------------------------------------------------------------

test('proof_sla_quote prices a proven grade: coverage 10000 at confidence 0.97 costs exactly 300', async () => {
  const result = await callTool('proof_sla_quote', { grade: 'proven', confidence: 0.97, coverageAmount: 10000 })
  assert.equal(result.isError, undefined, `quote errored: ${result.content[0]?.text}`)
  const quote = result.structuredContent as {
    quoteId?: string
    vehicle?: string
    grade?: string
    confidenceAtIssue?: number | null
    decision?: { class?: string; premium?: number; pUndetected?: number; deductible?: number; coverageAmount?: number; reason?: unknown }
    exclusions?: unknown[]
    currency?: string
    marker?: boolean
  }
  // The pure risk-pricing identity, pinned to the money spec: premium is
  // exactly coverageAmount × (1 − confidence) — not the float-noise
  // 300.0000000000003 a naive implementation would emit, and not a penny
  // more or less.
  const decision = quote.decision
  assert.equal(decision?.class, 'offer', `a proven grade earns an offer: ${JSON.stringify(quote.decision)}`)
  assert.equal(decision?.premium, 300, 'premium = 10000 × (1 − 0.97), rounded to the money spec — exactly 300')
  assert.equal(typeof decision?.pUndetected, 'number', 'the offer names the residual risk it priced')
  assert.ok(Math.abs(decision!.pUndetected! - 0.03) < 1e-9, 'pUndetected is the 1 − confidence residual (≈ 0.03)')
  assert.equal(typeof decision?.deductible, 'number', 'the offer carries the deductible it was written with')
  assert.equal(decision?.coverageAmount, 10000, 'the offer carries the coverage verbatim')
  assert.equal(quote.confidenceAtIssue, 0.97, 'the quote records the confidence it was priced at')
  assert.equal(quote.grade, 'proven')
  assert.equal(quote.currency, 'USD', 'the only priced currency, stamped on the quote itself')
  // The policy's fine print is a first-class part of the quote: the known
  // blind spots ride out as an exclusions list, never as prose.
  assert.ok(Array.isArray(quote.exclusions), 'exclusions is an array — the blind spots, itemized')
  assert.ok((quote.exclusions ?? []).length > 0, 'a real quote always excludes something — an empty list would claim omniscience')
  for (const exclusion of quote.exclusions ?? []) {
    assert.equal(typeof exclusion, 'string', 'each exclusion is quotable text')
  }
  // And the quote is chain-addressable: quoteId is the 16-hex short form of a
  // sha256 over the quote's own pricing content (the same shape workspaceKey
  // uses), and the marker tag says it landed on the evidence chain.
  assert.match(quote.quoteId ?? '', /^[0-9a-f]{16}$/, 'quoteId is a 16-hex short digest')
  assert.equal(quote.marker, true, 'the quote is on-chain — a price that cannot be audited is a number, not a quote')
})

test('proof_sla_quote refuses a regressed grade honestly — denied, with the reason on the record', async () => {
  const result = await callTool('proof_sla_quote', { grade: 'regressed', confidence: 0.9, coverageAmount: 5000 })
  assert.equal(result.isError, undefined, `a refusal is a QUOTE (denied), not a tool error: ${result.content[0]?.text}`)
  const quote = result.structuredContent as {
    decision?: { class?: string; premium?: unknown; reason?: unknown }
  }
  const decision = quote.decision
  assert.equal(decision?.class, 'denied', `a regressed grade is refused: ${JSON.stringify(quote.decision)}`)
  assert.ok(typeof decision?.reason === 'string' && (decision!.reason as string).length > 0,
    'the denial carries a reason — an insurer that refuses silently is indistinguishable from one that crashed')
  assert.equal(decision?.premium, undefined, 'a denied grade is never quietly priced as an offer')

  // And the third door, named for completeness: a stale grade is neither
  // priced nor refused — the evidence is not decisive enough to price
  // mechanically, so a human underwriter takes over.
  const stale = await callTool('proof_sla_quote', { grade: 'stale', coverageAmount: 1000 })
  assert.equal(stale.isError, undefined)
  const staleDecision = (stale.structuredContent as { decision?: { class?: string; reason?: unknown } }).decision
  assert.equal(staleDecision?.class, 'manual-underwriting', 'a stale grade goes to a human, never to a formula')
  assert.ok(typeof staleDecision?.reason === 'string' && (staleDecision!.reason as string).length > 0)
})

test('proof_sla_quote refuses malformed usage loudly — grade, coverage, currency', async () => {
  // A grade the five-value scale does not name is refused, never guessed at.
  const bogusGrade = await callTool('proof_sla_quote', { grade: 'over-the-moon', coverageAmount: 100 })
  assert.equal(bogusGrade.isError, true)
  const gradeText = bogusGrade.content[0]!.text
  assert.match(gradeText, /grade/, 'the error names the offending argument')
  assert.match(gradeText, /over-the-moon/, 'the error echoes the offending value')
  assert.ok(!gradeText.includes('"proven"'), 'the answer must not read like a quote')

  // A non-positive coverage amount prices nothing honestly.
  const negative = await callTool('proof_sla_quote', { grade: 'proven', coverageAmount: -5 })
  assert.equal(negative.isError, true)
  assert.match(negative.content[0]!.text, /coverageAmount/, 'the error names the offending argument')

  // Only USD is priced: a foreign currency is refused, never converted at a
  // rate nobody agreed to.
  const foreign = await callTool('proof_sla_quote', { grade: 'proven', coverageAmount: 100, currency: 'EUR' })
  assert.equal(foreign.isError, true)
  const currencyText = foreign.content[0]!.text
  assert.match(currencyText, /currency/, 'the error names the offending argument')
  assert.match(currencyText, /EUR/, 'the error echoes the offending value')
  assert.ok(currencyText.includes('USD'), 'the error names the only priced currency')
})

test('proof_economics honestly reports the absent ledger — with the exact remedy pinned', async () => {
  // This MCP face never runs a rate-carrying verification (proof_verify's
  // parameter surface stays minimal by design), and no earlier test minted a
  // ledger, so the chain holds no economics: the honest answer is the pinned
  // absence — never a fabricated ledger, never a recomputation.
  const result = await callTool('proof_economics', { computePerMs: 0.001 })
  assert.equal(result.isError, true, 'no ledger on the chain is a tool error, not an empty quote')
  const text = result.content[0]!.text
  assert.ok(
    text.includes('no economics on the last run — pass economics:{rate} to proof_verify/proof_claim first'),
    `the absence is pinned verbatim, remedy included: ${text}`,
  )

  // The rate card guard is this face's own, priced against nothing: a missing
  // or non-positive compute price is refused now, not on the next run.
  const noRate = await callTool('proof_economics', {})
  assert.equal(noRate.isError, true, 'computePerMs is required — the card you ask under must be a card')
  assert.match(noRate.content[0]!.text, /computePerMs/, 'the error names the offending argument')
  const zeroRate = await callTool('proof_economics', { computePerMs: 0 })
  assert.equal(zeroRate.isError, true, 'a zero rate prices time backwards — refused loudly')
  assert.match(zeroRate.content[0]!.text, /computePerMs/)
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

test('the delegation tools refuse malformed usage loudly, never silently', async () => {
  // A delegation without a claim is not a delegation.
  const noClaim = await callTool('proof_delegate', {})
  assert.equal(noClaim.isError, true)
  assert.match(noClaim.content[0]!.text, /claim/, 'the missing claim is named')

  // A submission without a bundle has nothing to adjudicate.
  const noBundle = await callTool('proof_delegate_submit', { taskId: 'task-1' })
  assert.equal(noBundle.isError, true)
  assert.match(noBundle.content[0]!.text, /bundle/, 'the missing bundle is named')

  // A grade the scale does not name is refused, not rounded into place —
  // same loud-argument discipline as proof_claim's kind guard.
  const bogusGrade = await callTool('proof_task', { taskId: 'task-1', ownGrade: 'over-the-moon' })
  assert.equal(bogusGrade.isError, true)
  const text = bogusGrade.content[0]!.text
  assert.match(text, /ownGrade/, 'the error names the offending argument')
  assert.match(text, /over-the-moon/, 'the error echoes the offending value')
  assert.ok(!text.includes('"proven"'), 'the answer must not read like a verdict')
})

test('a malformed JSON line gets a -32700 JSON-RPC error response', async () => {
  client.send('{ this is not json')
  const line = await client.nextLine()
  const message = JSON.parse(line) as { id: unknown; error: { code: number; message: string } }
  assert.equal(message.error.code, -32700)
  assert.equal(message.id, null, 'a parse error answers with id null — the line carried none')
})

test('a priced verify mints a ledger proof_economics replays verbatim off the chain', async () => {
  // v0.21 seam closure: proof_verify accepts the rate card directly on this
  // MCP face, the ledger rides the boundary marker, and proof_economics
  // replays those bytes — pricing is a chain fact, not a caller's word.
  const priced = await callTool('proof_verify', {
    changed: ['check.mjs'],
    economics: { computePerMs: 0.001 },
  }, 60_000)
  assert.equal(priced.isError, undefined, 'a priced verify succeeds')

  const replay = await callTool('proof_economics', { computePerMs: 0.001 }, 60_000)
  assert.equal(replay.isError, undefined, 'the ledger is on the chain and replays')
  const replayed = (replay.structuredContent ?? {}) as {
    economics?: { ledger?: { computeMs?: number; cost?: number; assertions?: number } }
  }
  const ledger = replayed.economics?.ledger
  assert.ok(typeof ledger?.computeMs === 'number' && ledger.computeMs >= 0)
  // 0.001 USD per ms: cost must equal computeMs × rate at the 6-decimal spec.
  assert.ok(ledger!.cost !== undefined)
  assert.ok(Math.abs(ledger!.cost! - ledger!.computeMs! * 0.001) < 1e-6,
    'the replayed price is exactly the measured compute at the stated rate')
  assert.ok(typeof ledger!.assertions === 'number' && ledger!.assertions >= 1,
    'a decisive run priced its assertions')
})
