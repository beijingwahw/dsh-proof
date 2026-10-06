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
 *
 * v0.24 batch (V4/V6/V9): the verified-view marker reader (blank-line domain
 * + generational fallback, unit-pinned beside the twin-exclusion pin), the
 * budgetMs ceiling (0/1e308 refused, 1e12 the boundary), SERVER_NOT_INITIALIZED
 * (-32002) and its strip in runMcpServer, input-queue backpressure, the
 * confined `..` rule, the blank-claim warning, uncertain=fail for an
 * unadjudicable tree head, the PTL-inside-workspace startup warning, the
 * confidence-anchored SLA copy, and MCP_DEFAULT_VERSION tracking the package.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { Buffer } from 'node:buffer'

import { sha256 } from '../src/core/hash.ts'
import { deriveProofPaths } from '../src/adapters/shared/paths.ts'
// v0.19: the worker's half of the delegation protocol is simulated in-process
// by minting a real APP bundle from the fixture's evidence artifacts — the
// same builder the proof_bundle tool itself calls.
import { buildBundle } from '../src/app/bundle.ts'
// v0.23 (W8): the transport layer and the suspect-filtering marker reader are
// pinned at the unit level too — a chunk boundary inside a code point and an
// out-of-band marker twin are both invisible through the happy-path RPCs.
// v0.24 (V6-M1/M2): the reader goes through the engine's verified view, so
// the fake engine below carries a storeView over the same MemoryFs.
import { markerPayloads, readCappedLines, runMcpServer } from '../src/app/mcp-server.ts'
import type { McpEngineDeps } from '../src/app/mcp-server.ts'
import { EvidenceStore } from '../src/core/evidence.ts'
import type { ProofEngine } from '../src/engine.ts'
import { lineDigest } from '../src/core/trust.ts'
import { MemoryFs } from './helpers.ts'

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
  // V6-L10 (v0.24): MCP_DEFAULT_VERSION tracks the package version — a
  // v0.23 build answering "0.22.0" misjudged every version-negotiating
  // client. DSH_PROOF_SERVER_VERSION still overrides on purpose.
  assert.equal(result.serverInfo.version, '0.25.0')
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

test('V4-M6: an unadjudicable tree head fails the audit — not-checked is a finding, not a pass (uncertain=fail)', async () => {
  assert.ok(firstPublish !== undefined, 'the publish test ran first (state chains)')
  // A copy of the published log WITHOUT any operator key anywhere near it:
  // the tree itself is intact (the root recomputes, the head matches it),
  // but nobody can adjudicate the head's signature. The CLI faces fail this
  // state (self-verify exits 1; bundle-verify door 5 requires === true);
  // this MCP face used to answer ok: true beside a 'not-checked' signature —
  // a pass in disguise for any consumer keying on ok alone.
  const keylessDir = join(WORKSPACE, 'dsh-home', 'ptl-keyless')
  await fsp.mkdir(keylessDir, { recursive: true })
  await fsp.copyFile(join(WORKSPACE, 'trust', 'ptl', 'ptl-entries.jsonl'), join(keylessDir, 'ptl-entries.jsonl'))
  await fsp.copyFile(join(WORKSPACE, 'trust', 'ptl', 'sth.json'), join(keylessDir, 'sth.json'))
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      // A trust root with NO operator key material: the keyless copy of the
      // log is the only PTL in sight.
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust-empty-v4m6'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
      DSH_PROOF_PTL_DIR: keylessDir,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  try {
    const gate = new LineRpc(ephemeral)
    const init = await gate.request('initialize', { protocolVersion: '2025-06-18' })
    assert.equal(init.error, undefined, `initialize failed: ${JSON.stringify(init.error)}`)
    const verified = await gate.request('tools/call', { name: 'proof_log_verify', arguments: {} }, 60_000)
    assert.equal(verified.error, undefined, `log verify failed at the RPC layer: ${JSON.stringify(verified.error)}`)
    const result = verified.result as ToolCallResponse
    assert.equal(result.isError, undefined, 'an audit with findings is a normal result, not a tool error')
    const value = result.structuredContent as {
      ok: boolean
      treeSize: number
      treeHead?: { signature?: string; rootMatches?: boolean }
      problems?: string[]
    }
    assert.equal(value.treeSize, 2, 'the copied log itself is intact')
    assert.equal(value.treeHead?.rootMatches, true, 'the head still matches the recomputed root')
    assert.equal(value.treeHead?.signature, 'not-checked (operator key absent)', 'the three-state still says WHY')
    assert.equal(value.ok, false, 'uncertain FAILS the audit — the CLI faces\' rule, now this face\'s too')
    assert.ok(
      (value.problems ?? []).some(p => p.includes('NOT adjudicated')),
      `the unchecked head rides problems: ${JSON.stringify(value.problems)}`,
    )
  } finally {
    ephemeral.kill()
  }
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
  // mcp-entry's derivation, mirrored: the ONE shared derivation
  // (deriveProofPaths — normalized root spelling, legacy-key probe), host
  // mode stores evidence at <trustRoot>/workspaces/<key>.
  const workspaceKey = deriveProofPaths(
    { root: WORKSPACE, trustRoot: join(WORKSPACE, 'trust'), evidenceStore: 'host' },
  ).workspaceKey
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

test('proof_training_export fidelity full with path writes the JSONL dataset to disk (workspace-relative path)', async () => {
  // v0.22 (H-16): `path` is workspace-RELATIVE on this face — the confinement
  // test at the end of this file pins the refusals; this one pins that a
  // relative destination writes inside the workspace and reports the
  // workspace-absolute writtenTo.
  const result = await callTool('proof_training_export', { fidelity: 'full', path: 'training-full.jsonl' }, 60_000)
  assert.equal(result.isError, undefined, `training export errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as {
    manifest: { schema: string; fidelity: string }
    sampleCount: number
    writtenTo?: string
  }
  assert.equal(value.manifest.schema, 'dsh-training/1')
  assert.equal(value.manifest.fidelity, 'full', 'the explicit full tier is honored, not second-guessed')
  assert.ok(value.sampleCount >= 1)
  const expected = `${WORKSPACE.replaceAll('\\', '/')}/training-full.jsonl`
  assert.equal(
    (value.writtenTo ?? '').replaceAll('\\', '/'),
    expected,
    'writtenTo is the confined workspace-absolute destination the engine wrote',
  )
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
// — no earlier test in this file mints one, so the honest answer until the
// priced-verify test below lands a ledger is the pinned no-ledger error.
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
  // v0.22 (engine M-03 closure): a quote prices evidence the chain REACHED —
  // the grade must appear on a proof/verified marker, or the engine refuses
  // (a caller-asserted grade was a free quote forgery). So the doors are
  // exercised the honest way: actually regress the fixture check and verify
  // (minting a real 'regressed' marker), then ask for the quote.
  await fsp.writeFile(join(WORKSPACE, 'check.mjs'), [
    "import assert from 'node:assert/strict'",
    'assert.equal(1 + 1, 3)',
    "console.log('FAIL loudly')",
    '',
  ].join('\n'))
  const regression = await callTool('proof_verify', { changed: ['check.mjs'] }, 60_000)
  assert.equal((regression.structuredContent as { grade: string }).grade, 'regressed', 'the fixture check really broke')
  // Restore the green fixture for every later test in this file.
  await fsp.writeFile(join(WORKSPACE, 'check.mjs'), CHECK_SCRIPT)

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

  // The third door (stale → manual-underwriting) needs a chain that honestly
  // reached 'stale' — an affected check that never re-ran — which this green
  // fixture cannot mint cheaply, and the door's pricing itself is pinned
  // engine-side (test/31: manual-underwriting with pinned reasons). What THIS
  // face pins instead is the anchoring seam twice over: a grade the chain
  // never reached is refused loudly by the engine, and the MCP face passes
  // that refusal through as a tool error — never minting a quote from
  // nothing, never silently downgrading to an offer.
  const unanchored = await callTool('proof_sla_quote', { grade: 'no-baseline', coverageAmount: 100 })
  assert.equal(unanchored.isError, true, 'a grade with no chain evidence prices nothing')
  assert.match(unanchored.content[0]!.text, /no proof\/verified marker/, 'the refusal names the anchoring rule')
  const unanchoredStale = await callTool('proof_sla_quote', { grade: 'stale', coverageAmount: 100 })
  assert.equal(unanchoredStale.isError, true, 'the stale door also demands honestly-stale evidence first')
  assert.match(unanchoredStale.content[0]!.text, /no proof\/verified marker/)
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

test('proof_economics honestly reports the absent ledger — with the exact on-face remedy pinned', async () => {
  // No earlier test in this file minted a ledger, so the chain holds no
  // economics: the honest answer is the pinned absence — never a fabricated
  // ledger, never a recomputation. The remedy (v0.22 flip) names the shape
  // THIS face actually accepts, not the engine-side {rate} wrapper the old
  // text taught — following the old text failed by construction.
  const result = await callTool('proof_economics', { computePerMs: 0.001 })
  assert.equal(result.isError, true, 'no ledger on the chain is a tool error, not an empty quote')
  const text = result.content[0]!.text
  assert.ok(
    text.includes('no economics on the last run') && text.includes('economics: {computePerMs'),
    `the absence is pinned verbatim, with the on-face remedy: ${text}`,
  )
  assert.ok(
    !text.includes('keeps proof_verify') && !text.includes('{rate}'),
    'the fabricated "minimal parameters" tail and the engine-only {rate} shape are gone',
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
    chainAudit?: { checked?: boolean; ok?: boolean }
  }
  const ledger = replayed.economics?.ledger
  assert.ok(typeof ledger?.computeMs === 'number' && ledger.computeMs >= 0)
  // 0.001 USD per ms: cost must equal computeMs × rate at the 6-decimal spec.
  assert.ok(ledger!.cost !== undefined)
  assert.ok(Math.abs(ledger!.cost! - ledger!.computeMs! * 0.001) < 1e-6,
    'the replayed price is exactly the measured compute at the stated rate')
  assert.ok(typeof ledger!.assertions === 'number' && ledger!.assertions >= 1,
    'a decisive run priced its assertions')
  // v0.22 (M-51): the replay carries its own chain audit verdict — the hash
  // chain detects rewrites, it does not prevent the write, so a replay
  // without an audit verdict vouched for bytes it never checked.
  assert.deepEqual(replayed.chainAudit, { checked: true, ok: true },
    'the replay reports that the chain audit ran and passed')
})

// ---------------------------------------------------------------------------
// v0.22 fix batch: the MCP face's own pins — confinement (H-16), claim
// forwarding (M-50), the finite-budget gate (H-29 face half), loud array
// narrowing (M-54), INVALID_PARAMS for malformed arguments, the protocol
// edges (initialize gate, JSON-RPC batch, transport cap), loud startup on a
// misspelled evidence store, and the double-counted bundle trim.
// ---------------------------------------------------------------------------

/** The fixture store dir (mcp-entry's host-mode derivation, mirrored — the one shared derivation). */
function fixtureStoreDir(): string {
  const workspaceKey = deriveProofPaths(
    { root: WORKSPACE, trustRoot: join(WORKSPACE, 'trust'), evidenceStore: 'host' },
  ).workspaceKey
  return join(WORKSPACE, 'trust', 'workspaces', workspaceKey)
}

test('proof_claim on a green workspace proves the claim — the success path is pinned', async () => {
  // C3-H3 closure: the MCP face's proof_claim success promise (CLAIM_DESCRIPTION)
  // had zero coverage — only the bogus-kind error was ever exercised.
  const result = await callTool('proof_claim', { claim: 'the workspace still passes its own check', changed: ['check.mjs'] }, 60_000)
  assert.equal(result.isError, undefined, `claim errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as { claim: string; grade: string; proven: boolean; blockers?: string[] }
  assert.equal(value.claim, 'the workspace still passes its own check', 'the claim rides the card verbatim')
  assert.equal(value.grade, 'proven')
  assert.equal(value.proven, true, 'a passing workspace proves the claim — the core promise of the card')
  assert.deepEqual(value.blockers ?? [], [], 'nothing to fix')
})

test('proof_verify forwards the claim text onto the chain (M-50/D3 parity with the DSH face)', async () => {
  const claimText = 'fixed the login redirect and added a regression test'
  const result = await callTool('proof_verify', { changed: ['check.mjs'], claim: claimText }, 60_000)
  assert.equal(result.isError, undefined, `verify errored: ${result.content[0]?.text}`)
  // The chain is where the record belongs: read the log back and pin that the
  // LAST proof/verified marker carries the claim text — the MCP face must not
  // diverge from what session logs record.
  const log = await fsp.readFile(join(fixtureStoreDir(), 'evidence.jsonl'), 'utf8')
  const markers = log.split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as { kind?: unknown; payload?: { label?: unknown; claim?: unknown } })
    .filter(entry => entry.kind === 'marker' && entry.payload?.label === 'proof/verified')
  const last = markers[markers.length - 1]
  assert.ok(last !== undefined, 'a proof/verified marker landed')
  assert.equal(typeof last.payload?.claim, 'string', 'the marker carries the claim')
  assert.ok(
    (last.payload?.claim as string).includes('login redirect'),
    `the claim text is recorded on the boundary marker: ${JSON.stringify(last.payload?.claim)}`,
  )

  // A non-string claim is refused loudly, never silently dropped.
  const bogus = await callTool('proof_verify', { claim: 42 }, 60_000)
  assert.equal(bogus.isError, true)
  assert.match(bogus.content[0]!.text, /claim must be a string/)
})

test('proof_claim refuses a non-finite budgetMs — 1e999 is not a budget (H-29 face half)', async () => {
  // JSON cannot spell Infinity, but JSON.parse('1e999') produces it — so the
  // raw line is sent directly, letting the attack vector through exactly as
  // a hostile client would (JSON.stringify would null it first).
  client.send('{"jsonrpc":"2.0","id":910001,"method":"tools/call","params":{"name":"proof_claim",'
    + '"arguments":{"claim":"fast enough","kind":"perf-budget","budgetMs":1e999}}}')
  const line = await client.nextLine()
  const response = JSON.parse(line) as { id: number; result?: ToolCallResponse }
  assert.equal(response.id, 910001)
  assert.equal(response.result?.isError, true, 'an infinite budget is a tool error')
  const text = response.result?.content?.[0]?.text ?? ''
  assert.match(text, /budgetMs/, 'the error names the offending argument')
  assert.match(text, /finite/, 'the error says exactly what was wrong: not a finite number')
})

test('V6-M3: budgetMs 0 and 1e308 are refused — the 1e12 ceiling is face-wide, not DSH-only', async () => {
  // W13-M6 put the ceiling on the DSH face only; the MCP face is the one an
  // UNTRUSTED foreign agent types at, so `budgetMs: 1e308` (finite, positive,
  // vacuously satisfiable by any benchmark) must not pass here either, and
  // `budgetMs: 0` (the old face text said ">= 0") must stop being a budget.
  for (const budgetMs of [0, 1e308, 1e12 + 1]) {
    const result = await callTool('proof_claim', {
      claim: 'fast enough', kind: 'perf-budget', budgetMs,
    }, 60_000)
    assert.equal(result.isError, true, `budgetMs ${budgetMs} must be refused (V6-M3)`)
    const text = result.content[0]!.text
    assert.match(text, /budgetMs/, 'the error names the offending argument')
    assert.match(text, /1e12/, 'the error names the ceiling the DSH face already had')
  }
  // 1e12 itself is the boundary, not beyond it: a legal (if absurd) budget
  // passes the face gate — the ceiling is a ceiling, not a lower bar.
  const legal = await callTool('proof_claim', {
    claim: 'a very slow benchmark', kind: 'perf-budget', budgetMs: 1e12,
  }, 60_000)
  assert.notEqual(legal.isError, true, `1e12 is inside the bound: ${legal.content[0]?.text}`)

  // And the schema says the same thing the gate enforces (tool-description
  // changes ride with their pins): the bound is documented, not folklore.
  const response = await client.request('tools/list', {})
  const tools = (response.result as { tools: { name: string; inputSchema: { properties?: Record<string, { description?: string }> } }[] }).tools
  const budgetDescription = tools.find(t => t.name === 'proof_claim')!.inputSchema.properties?.budgetMs?.description ?? ''
  assert.match(budgetDescription, /1e12/, 'the budgetMs description names the ceiling')
})

test('proof_verify counts dropped non-string changed entries instead of narrowing silently', async () => {
  const result = await callTool('proof_verify', { changed: ['check.mjs', 42, null] }, 60_000)
  assert.equal(result.isError, undefined, `verify errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as { changed: string[]; warning?: string }
  assert.deepEqual(value.changed, ['check.mjs'], 'only the string entry reached the engine')
  assert.match(
    value.warning ?? '',
    /dropped 2 non-string entries from changed/,
    'the drop is counted and named in a warning field (M-54)',
  )
})

test('tools/call with a non-object arguments member is a JSON-RPC -32602 error', async () => {
  const response = await client.request('tools/call', { name: 'proof_status', arguments: 42 })
  const error = response.error as { code: number; message: string } | undefined
  assert.ok(error !== undefined, 'a malformed arguments member is a protocol-level error, not a tool run')
  assert.equal(error.code, -32602)
  assert.match(error.message, /arguments must be an object/)
})

test('a JSON-RPC batch is answered element by element with an array', async () => {
  const before = client.receivedLines
  client.send(JSON.stringify([{ jsonrpc: '2.0', method: 'notifications/initialized' }]))
  await sleep(250)
  assert.equal(client.receivedLines, before, 'a batch of only notifications produces no output at all')

  client.send(JSON.stringify([
    { jsonrpc: '2.0', id: 920001, method: 'ping' },
    { jsonrpc: '2.0', id: 920002, method: 'ping' },
  ]))
  const line = await client.nextLine()
  const parsed = JSON.parse(line) as { id: number; result: unknown }[]
  assert.ok(Array.isArray(parsed), 'the batch answer is an array')
  assert.deepEqual(parsed.map(entry => entry.id), [920001, 920002], 'responses come back in request order')

  client.send(JSON.stringify([]))
  const empty = JSON.parse(await client.nextLine()) as { error: { code: number } }
  assert.equal(empty.error.code, -32600, 'an empty batch is an invalid request')
})

test('a line over the transport cap is refused without being buffered or parsed', async () => {
  client.send(`{"pad":"${'x'.repeat(5 * 1024 * 1024)}"}`)
  const line = await client.nextLine()
  const message = JSON.parse(line) as { id: unknown; error: { code: number; message: string } }
  assert.equal(message.error.code, -32700)
  assert.match(message.error.message, /transport limit/, 'the refusal names the cap')
  // The server is still alive and serving normal traffic afterwards.
  const pong = await client.request('ping')
  assert.equal(pong.error, undefined)
})

test('tools are refused before initialize — the handshake is mandatory (protocol edge)', async () => {
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  try {
    const gate = new LineRpc(ephemeral)
    const refused = await gate.request('tools/list', {})
    const error = refused.error as { code: number; message: string }
    assert.ok(error !== undefined, 'a pre-handshake tools request is refused')
    // V6-L/F9 (v0.24): the code is SERVER_NOT_INITIALIZED (-32002, the
    // JSON-RPC server-error band), not INVALID_REQUEST — the request itself
    // was well-formed JSON-RPC; the session state refused it.
    assert.equal(error.code, -32002)
    assert.match(error.message, /initialize/, 'the refusal names the missing handshake')
    const init = await gate.request('initialize', { protocolVersion: '2025-06-18' })
    assert.equal(init.error, undefined)
    const listed = await gate.request('tools/list', {})
    assert.equal(listed.error, undefined, 'after the handshake the surface answers')
  } finally {
    ephemeral.kill()
  }
})

test('a misspelled DSH_PROOF_EVIDENCE_STORE fails startup loudly, never silently meaning host', async () => {
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
      DSH_PROOF_EVIDENCE_STORE: 'Workspace',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const { code, stderr } = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
    let text = ''
    ephemeral.stderr!.setEncoding('utf8')
    ephemeral.stderr!.on('data', (chunk: string) => { text += chunk })
    ephemeral.on('exit', (exitCode: number | null) => resolve({ code: exitCode, stderr: text }))
  })
  assert.notEqual(code, 0, 'the server must die rather than guess where evidence lives')
  assert.match(stderr, /DSH_PROOF_EVIDENCE_STORE/)
  assert.match(stderr, /'host' or 'workspace'/)
})

test('H-21 env parity: DSH_PROOF_EVIDENCE_DIR steers the server\'s store like it steers the hooks', async () => {
  // The exact H-21 scenario: an operator sets EVIDENCE_STORE=workspace with a
  // custom EVIDENCE_DIR — the adapter hooks guard <root>/.evi, and the server
  // this face spawns must write THE SAME directory, not the old hardcoded
  // .proof (which left the guard watching a phantom store).
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
      DSH_PROOF_EVIDENCE_STORE: 'workspace',
      DSH_PROOF_EVIDENCE_DIR: '.evi',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  try {
    const parity = new LineRpc(ephemeral)
    const init = await parity.request('initialize', { protocolVersion: '2025-06-18' })
    assert.equal(init.error, undefined, `initialize failed: ${JSON.stringify(init.error)}`)
    const baseline = await parity.request('tools/call', {
      name: 'proof_baseline',
      arguments: {},
    }, 60_000)
    assert.equal(baseline.error, undefined, 'baseline over the env-configured store succeeds')
    const logUri = await fsp.stat(join(WORKSPACE, '.evi', 'evidence.jsonl')).then(() => true, () => false)
    assert.equal(logUri, true, 'the evidence log landed in the EVIDENCE_DIR the hooks would guard')
    const phantom = await fsp.stat(join(WORKSPACE, '.proof', 'evidence.jsonl')).then(() => true, () => false)
    assert.equal(phantom, false, 'the old hardcoded .proof store is not written')
  } finally {
    ephemeral.kill()
  }
})

test('SIGTERM ends the server gracefully where signals are real (loop stops, process exits on its own)', async () => {
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const graceful = new LineRpc(ephemeral)
  const init = await graceful.request('initialize', { protocolVersion: '2025-06-18' })
  assert.equal(init.error, undefined)
  ephemeral.kill('SIGTERM')
  const { code, signal } = await new Promise<{ code: number | null; signal: string | null }>((resolve) => {
    const timer = setTimeout(() => resolve({ code: null, signal: 'timeout' }), 5_000)
    ephemeral.once('exit', (exitCode: number | null, exitSignal: string | null) => {
      clearTimeout(timer)
      resolve({ code: exitCode, signal: exitSignal })
    })
  })
  assert.notEqual(signal, 'timeout', 'the server must die promptly on SIGTERM, never hang')
  if (process.platform === 'win32') {
    // Windows cannot deliver SIGTERM to another process: child.kill
    // degenerates to an unconditional TerminateProcess, and no in-process
    // handler can interpose. The graceful path (handler ends the read loop,
    // the in-flight message finishes, the process exits with code 0 and no
    // signal) is POSIX semantics — pinned on the POSIX side of the matrix.
    assert.equal(signal, 'SIGTERM')
    return
  }
  assert.equal(signal, null, 'the process exited on its own (loop end), not killed by the default handler')
  assert.equal(code, 0)
})

test('proof_training_export confines `path` to the workspace — absolute, UNC and .. escapes refused loudly (H-16)', async () => {
  const absolute = await callTool('proof_training_export', { path: join(WORKSPACE, '..', 'escape.jsonl') })
  assert.equal(absolute.isError, true, 'an absolute path is refused on this face')
  const absoluteText = absolute.content[0]!.text
  assert.match(absoluteText, /workspace-RELATIVE/, 'the error names the rule')
  assert.match(absoluteText, /absolute/, 'the error names what was refused')

  const unc = await callTool('proof_training_export', { path: '\\\\server\\share\\proof\\out.jsonl' })
  assert.equal(unc.isError, true, 'a UNC path is refused')
  assert.match(unc.content[0]!.text, /UNC/)

  const escape = await callTool('proof_training_export', { path: 'deep/../../outside.jsonl' })
  assert.equal(escape.isError, true, 'a path that normalizes outside the root is refused')
  // V6-L/F7 (v0.24): the refusal is on the ".." SEGMENT now — same rule as
  // the engine's exportRelPath — not on where the pop-normalisation landed.
  assert.match(escape.content[0]!.text, /segments are refused outright/, 'the error names the segment rule')

  // And the engine-identical half: a dotdot that RE-ENTERS the workspace
  // ('a/../b' normalizes to 'b', inside the root) is refused too — at this
  // trust boundary the two shapes are indistinguishable, and the face gate
  // now refuses exactly the set the engine's own gate refuses.
  const reenter = await callTool('proof_training_export', { path: 'a/../reenter.jsonl' })
  assert.equal(reenter.isError, true, 'a re-entering dotdot is refused — the face and the engine share one rule')
  assert.match(reenter.content[0]!.text, /segments are refused outright/)

  // And none of the refused calls wrote anything outside the workspace.
  assert.equal(
    await fsp.stat(join(WORKSPACE, '..', 'escape.jsonl')).then(() => true, () => false),
    false,
    'the refused absolute destination must not exist',
  )
  assert.equal(
    await fsp.stat(join(WORKSPACE, 'reenter.jsonl')).then(() => true, () => false),
    false,
    'the refused re-entering destination must not exist either (pop-normalisation is gone)',
  )
})

// ---------------------------------------------------------------------------
// v0.23 fix batch (W8 + entry hardening) — loud argument discipline for
// all/changed/entryPoints, the 200-char claim bound made visible, the
// byte-level transport line splitter, the suspect-filtering marker reader,
// proof_economics fail-closed on a failing chain audit, the anchored SLA
// quote description, and the relative-trust-path startup refusals.
// ---------------------------------------------------------------------------

/** Spawn the entry and resolve on exit with the collected stderr. */
function spawnEntry(env: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
      ...env,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  return new Promise((resolve) => {
    let text = ''
    ephemeral.stderr!.setEncoding('utf8')
    ephemeral.stderr!.on('data', (chunk: string) => { text += chunk })
    ephemeral.on('exit', exitCode => resolve({ code: exitCode, stderr: text }))
  })
}

test('W8-M2: a truthy non-boolean all is a tool error, never a silently narrower run', async () => {
  const result = await callTool('proof_verify', { all: 'true', changed: ['check.mjs'] }, 60_000)
  assert.equal(result.isError, true, 'all: "true" is refused — it once meant "run the impact analysis anyway"')
  const text = result.content[0]!.text
  assert.match(text, /all must be a boolean/)
  assert.ok(text.includes('true'), 'the error echoes the offending value')

  const numeric = await callTool('proof_verify', { all: 1 }, 60_000)
  assert.equal(numeric.isError, true, 'all: 1 is the same refusal')
  assert.match(numeric.content[0]!.text, /all must be a boolean/)
})

test('W8-M2: a non-array changed is a tool error on both faces that take it', async () => {
  const verify = await callTool('proof_verify', { changed: 'check.mjs' }, 60_000)
  assert.equal(verify.isError, true, 'a bare string is not a change list')
  assert.match(verify.content[0]!.text, /changed must be an array/)
  assert.match(verify.content[0]!.text, /falling back to the derived change set/, 'the error names the divergence it refused')

  const claim = await callTool('proof_claim', { claim: 'did the thing', changed: 'src/a.ts' }, 60_000)
  assert.equal(claim.isError, true)
  assert.match(claim.content[0]!.text, /changed must be an array/)

  const entryPoints = await callTool('proof_claim', { claim: 'did the thing', entryPoints: 'src/index.ts' }, 60_000)
  assert.equal(entryPoints.isError, true)
  assert.match(entryPoints.content[0]!.text, /entryPoints must be an array/)
})

test('W8-L7: a claim past the 200-character marker bound carries a truncation warning', async () => {
  const longClaim = `fixed the login redirect (${'and also '.repeat(30)}) and added a regression test`
  assert.ok(longClaim.trim().length > 200, 'fixture: the claim exceeds the marker bound')
  const verify = await callTool('proof_verify', { changed: ['check.mjs'], claim: longClaim }, 60_000)
  assert.equal(verify.isError, undefined, `verify errored: ${verify.content[0]?.text}`)
  const verifyValue = verify.structuredContent as { warning?: string }
  assert.match(
    verifyValue.warning ?? '',
    /truncated to its first 200 characters/,
    'the response says the chain record is shorter than the caller\'s words',
  )

  const claim = await callTool('proof_claim', { claim: longClaim }, 60_000)
  assert.equal(claim.isError, undefined, `claim errored: ${claim.content[0]?.text}`)
  const claimValue = claim.structuredContent as { warnings?: string[] }
  assert.ok(
    (claimValue.warnings ?? []).some(w => w.includes('truncated to its first 200 characters')),
    `the claim card warns too: ${JSON.stringify(claimValue.warnings)}`,
  )
})

test('V6-L: a whitespace-only claim on proof_verify records nothing — and says so', async () => {
  // proof_claim REFUSES a blank claim outright; proof_verify used to accept
  // the string and then silently forward nothing (the `trim() !== ''` guard
  // dropped it without a word) — a face-internal inconsistency the loud
  // boundary discipline closes: record nothing, but say it.
  const result = await callTool('proof_verify', { changed: ['check.mjs'], claim: '   \t ' }, 60_000)
  assert.equal(result.isError, undefined, `verify errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as { warning?: string }
  assert.match(
    value.warning ?? '',
    /blank/,
    'the response says nothing was recorded for a whitespace-only claim',
  )
  // And the chain agrees: the LAST proof/verified marker carries no claim.
  const log = await fsp.readFile(join(fixtureStoreDir(), 'evidence.jsonl'), 'utf8')
  const markers = log.split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as { kind?: unknown; payload?: { label?: unknown; claim?: unknown } })
    .filter(entry => entry.kind === 'marker' && entry.payload?.label === 'proof/verified')
  assert.equal(markers[markers.length - 1]?.payload?.claim, undefined, 'the boundary marker carries no claim text')
})

test('the SLA quote description states the anchoring gate the engine actually enforces (W8-M1)', async () => {
  const response = await client.request('tools/list', {})
  assert.equal(response.error, undefined)
  const tools = (response.result as { tools: { name: string; description: string }[] }).tools
  const sla = tools.find(t => t.name === 'proof_sla_quote')!
  assert.ok(
    sla.description.includes('proof/verified marker'),
    'the description names the on-chain evidence a quote is anchored to',
  )
  assert.ok(
    sla.description.includes('grade the chain has actually REACHED') || sla.description.includes('reached'),
    'the description says only reached grades are priced',
  )
  assert.ok(
    sla.description.includes('ERROR') || sla.description.includes('refused'),
    'the description says an unanchored grade is refused, not priced',
  )
  // V6-M4 (v0.24): the engine's SECOND anchor (v0.23) is in the copy too —
  // the description used to promise free-form confidence while the engine
  // already refused a proven quote above the best reached marker.
  assert.ok(
    sla.description.includes('no lower than the confidence you quote'),
    'the description states the confidence anchor: the chain must cover the quoted confidence',
  )
  assert.ok(
    sla.description.includes('quoting below is priced honestly'),
    'the description says the honest direction too: a lower quote prices at the lower number',
  )
  // V6-M4 (v0.24): the confidence PARAMETER documents its anchor too — the
  // caller reads the parameter description, not only the tool preamble.
  const slaWithSchema = tools.find(t => t.name === 'proof_sla_quote') as unknown as {
    inputSchema: { properties?: Record<string, { description?: string }> }
  }
  assert.match(
    String(slaWithSchema.inputSchema.properties?.confidence?.description ?? ''),
    /ANCHORED/,
    'the confidence parameter says its value is anchored to the chain\'s reached markers',
  )
  // V6-M4 sibling: proof_log_verify's description now states uncertain=fail
  // (a missing operator key fails the audit, matching the CLI faces).
  assert.ok(
    (tools.find(t => t.name === 'proof_log_verify')!.description).includes('uncertain-counts-as-failed'),
    'the log-verify description says an unadjudicated head fails the audit',
  )
  // V6-L/F7 sibling: the training-export path parameter documents the ".."-
  // segment rule the face gate now enforces (engine-identical).
  const trainingWithSchema = tools.find(t => t.name === 'proof_training_export') as unknown as {
    inputSchema: { properties?: Record<string, { description?: string }> }
  }
  assert.match(
    String(trainingWithSchema.inputSchema.properties?.path?.description ?? ''),
    /"\.\." segment|\.\.&#34; segment|dotdot/,
    'the path parameter names the dotdot rule',
  )
})

test('W8-L12: a failing chain audit makes proof_economics an isError response stamped untrusted', async () => {
  // The ledger exists by this point (the priced-verify test minted one); the
  // chain it rides on is broken by one appended garbage line — corrupt-lines
  // fails audit.ok, and the replay must fail CLOSED (isError), not ride out
  // as a success with a soft warning.
  const logPath = join(fixtureStoreDir(), 'evidence.jsonl')
  const original = await fsp.readFile(logPath, 'utf8')
  try {
    await fsp.appendFile(logPath, 'corrupt line that breaks the chain audit\n', 'utf8')
    const result = await callTool('proof_economics', { computePerMs: 0.001 }, 60_000)
    assert.equal(result.isError, true, 'a replay over a broken chain is an error, never a soft warning')
    const value = result.structuredContent as {
      untrusted?: boolean
      chainAudit?: { ok?: boolean }
      warning?: string
      economics?: unknown
    }
    assert.equal(value.untrusted, true, 'the pseudo-ledger is stamped untrusted at the top level')
    assert.equal(value.chainAudit?.ok, false, 'the audit verdict rides the response')
    assert.ok(value.economics !== undefined, 'the ledger still rides for the auditor who wants to look')
    assert.match(value.warning ?? '', /chain audit FAILED/)
  } finally {
    await fsp.writeFile(logPath, original, 'utf8')
  }
})

test('W8-F3: readCappedLines survives a chunk boundary inside a multi-byte character', async () => {
  const lines = [
    '{"msg":"你好世界🎉","id":1}',
    '{"msg":"café ñan 高橋 🚀","id":2}',
  ]
  const tick = async (): Promise<void> => new Promise(resolve => setImmediate(resolve))
  for (const line of lines) {
    const bytes = Buffer.from(`${line}\n`, 'utf8')
    // Split at EVERY byte boundary: each prefix/suffix pair is a two-chunk
    // delivery whose boundary may fall inside a code point — the exact shape
    // that used to decode to two U+FFFD halves and answer "not valid JSON".
    for (let split = 1; split < bytes.length - 1; split += 1) {
      const pt = new PassThrough()
      const iterator = readCappedLines(pt, 4096)[Symbol.asyncIterator]()
      pt.write(bytes.subarray(0, split))
      await tick()
      pt.write(bytes.subarray(split))
      await tick()
      pt.end()
      const first = await iterator.next()
      assert.equal(first.done, false)
      const value = first.value as { text?: string; oversized?: true }
      assert.equal(value.oversized, undefined, `split ${split}: a small line is never over-cap`)
      assert.equal(value.text, line, `split ${split}: the line round-trips byte-identically`)
      assert.equal((await iterator.next()).done, true)
    }
  }
})

test('W8-F3: the transport cap is exact byte semantics — cap and cap+1 adjudicate cleanly', async () => {
  const tick = async (): Promise<void> => new Promise(resolve => setImmediate(resolve))
  const cap = 16
  // One byte over cap: oversized; exactly at cap: legal.
  for (const [payload, expectOversized] of [['12345678901234567', true], ['1234567890123456', false]] as const) {
    const pt = new PassThrough()
    const iterator = readCappedLines(pt, cap)[Symbol.asyncIterator]()
    pt.write(Buffer.from(`${payload}\n`, 'utf8'))
    await tick()
    pt.end()
    const first = await iterator.next()
    const value = first.value as { text?: string; oversized?: true }
    assert.equal(value.oversized !== undefined, expectOversized, `payload ${JSON.stringify(payload)} at cap ${cap}`)
    if (!expectOversized) assert.equal(value.text, payload)
  }
})

test('V6-F5: readCappedLines pauses its input at the queue high-water mark and resumes on drain', async () => {
  const tick = async (): Promise<void> => new Promise(resolve => setImmediate(resolve))
  let pauses = 0
  let resumes = 0
  // A PassThrough that RECORDS the transport signals: the queue bound is
  // observable only through the pause/resume it triggers on the input.
  class RecordingStream extends PassThrough {
    override pause(): this {
      pauses += 1
      return super.pause()
    }

    override resume(): this {
      resumes += 1
      return super.resume()
    }
  }
  const pt = new RecordingStream()
  const iterator = readCappedLines(pt, 4096)[Symbol.asyncIterator]()
  const total = 3000
  // A client that keeps writing while nothing consumes: under the old shape
  // the parsed-line queue grew without bound for as long as the client
  // cared to write (the 4 MiB cap bounded each ENTRY, not the depth).
  for (let i = 0; i < total; i += 1) {
    pt.write(`{"n":${i}}\n`)
    if (i % 97 === 0) await tick()
  }
  pt.end()
  await tick()
  assert.ok(pauses >= 1, `the queue high-water mark paused the transport (pauses: ${pauses})`)

  // Then the consumer catches up: every line arrives, in order, and the
  // transport is resumed as the queue drains below the low-water mark.
  const seen: number[] = []
  for (;;) {
    const next = await iterator.next()
    if (next.done) break
    seen.push(JSON.parse((next.value as { text: string }).text).n)
  }
  assert.deepEqual(seen, Array.from({ length: total }, (_, i) => i), 'nothing is dropped or reordered by the pause/resume cycle')
  assert.ok(resumes >= 1, 'draining the queue resumed the transport')
})

test('V6-L/F9: runMcpServer strips allowUninitializedTools — the stdio handshake is mandatory', async () => {
  // A stray `allowUninitializedTools: true` in an embedding used to silently
  // open the un-handshaked door over the stdio transport; the loop now
  // strips the flag before building the handler (embedders that really want
  // the gate gone drive createMcpHandler directly).
  const input = new PassThrough()
  const output = new PassThrough()
  const readOneLine = async (): Promise<string> => new Promise<string>((resolve) => {
    let buffer = ''
    const onData = (chunk: string): void => {
      buffer += chunk
      const index = buffer.indexOf('\n')
      if (index >= 0) {
        output.removeListener('data', onData)
        resolve(buffer.slice(0, index))
      }
    }
    output.setEncoding('utf8')
    output.on('data', onData)
  })
  const server = runMcpServer({
    engine: {} as unknown as ProofEngine,
    evidenceLogPath: '/store/evidence.jsonl',
    baselinePath: '/store/baseline.json',
    anchorPath: '/trust/anchors/k/anchor.json',
    workspaceKey: 'k',
    serverVersion: 'test',
    allowUninitializedTools: true, // the stray flag that must change nothing
    input,
    output,
  })
  try {
    input.write('{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n')
    const refusal = JSON.parse(await readOneLine()) as { id: number; error?: { code: number } }
    assert.equal(refusal.id, 1)
    assert.equal(refusal.error?.code, -32002, 'the un-handshaked request is refused DESPITE the flag')

    // And the gate still opens the honest way: initialize, then serve.
    input.write('{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n')
    const ready = JSON.parse(await readOneLine()) as { id: number; result?: unknown; error?: unknown }
    assert.equal(ready.id, 2)
    assert.equal(ready.error, undefined)
    input.write('{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}\n')
    const listed = JSON.parse(await readOneLine()) as { id: number; error?: unknown }
    assert.equal(listed.id, 3)
    assert.equal(listed.error, undefined, 'after the handshake the surface answers')
  } finally {
    input.end()
    await server
  }
})

test('W8/G2: markerPayloads excludes suspect lines — an out-of-band marker twin is not chain fact', async () => {
  const evidence0 = JSON.stringify({ v: 1, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', payload: { evidenceId: 'e0' } })
  const marker = (label: string, extra: Record<string, unknown>, prev: string, headRef: string) => JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
    payload: { label, ...extra, headRef },
  })
  const honestCreated = marker('delegation/created', { taskId: 'task-1', claim: 'honest obligation' }, 'prev-0', lineDigest(evidence0))
  const honestVerdict = marker('delegation/verdict', { taskId: 'task-1' }, lineDigest(evidence0), lineDigest(honestCreated))
  // The attacker replays the created marker at the tail: its headRef names a
  // line that is NOT its physical predecessor — the position witness fails.
  const replayedTwin = marker('delegation/created', { taskId: 'task-2', claim: 'injected obligation' }, 'prev-x', lineDigest(evidence0))
  const log = [evidence0, honestCreated, honestVerdict, replayedTwin].join('\n') + '\n'
  const deps = fakeMarkerDeps(log)

  const records = await markerPayloads(deps, new Set(['delegation/created', 'delegation/verdict']))
  assert.equal(records.length, 2, 'the honest pair survives; the replayed twin does not')
  assert.deepEqual(records.map(r => (r.payload as { taskId: string }).taskId), ['task-1', 'task-1'])
  assert.equal(records[0]?.at, '2026-10-06T00:00:00.000Z', 'the envelope timestamp rides along')
  // V6-M2: a trusted-pool read carries NO degraded flag — the generational
  // fallback never fired (honest markers exist, the twin is simply absent).
  assert.equal(records.every(r => r.degraded === undefined), true, 'a trusted read is not degraded')

  // Prefix matching (the economics replay's shape) with the same exclusion:
  // an honest proof/verified boundary carrier exists, the appended twin
  // (headRef naming a line that is not its predecessor) does not ride.
  const honestVerified = marker('proof/verified', { grade: 'proven', economics: { cost: 1 } }, 'prev-z', lineDigest(honestCreated))
  const injectedVerified = marker('proof/verified', { grade: 'proven', economics: { cost: 999 } }, 'prev-y', lineDigest(evidence0))
  const deps2 = fakeMarkerDeps([evidence0, honestCreated, honestVerified, injectedVerified].join('\n') + '\n')
  const economics = await markerPayloads(deps2, new Set(), { labelPrefixes: ['proof/', 'claim/'] })
  assert.equal(economics.length, 1, 'only the honest boundary marker rides the prefix read')
  assert.equal((economics[0]?.payload as { economics?: { cost: number } }).economics?.cost, 1, 'the forged carrier never became the run')
})

test('V6-M1: a blank line no longer exiles honest markers — the witness domain is readLines', async () => {
  const evidence0 = JSON.stringify({ v: 1, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', payload: { evidenceId: 'e0' } })
  const marker = (label: string, extra: Record<string, unknown>, prev: string, headRef: string) => JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
    payload: { label, ...extra, headRef },
  })
  const honestCreated = marker('delegation/created', { taskId: 'task-1', claim: 'honest obligation' }, 'prev-0', lineDigest(evidence0))
  const honestVerdict = marker('delegation/verdict', { taskId: 'task-1' }, lineDigest(evidence0), lineDigest(honestCreated))
  // One stray blank line (`echo >> evidence.jsonl` — no attacker required)
  // between the honest records. The old raw split judged the post-blank
  // marker's headRef against the BLANK line's digest and silently dropped
  // every honest marker after it on this face, while the writer (and every
  // readLines-domain reader — DSH face, engine, audit) chained to the
  // previous NON-BLANK line and read them fine.
  const log = [evidence0, '', honestCreated, '', honestVerdict].join('\n') + '\n'
  const records = await markerPayloads(fakeMarkerDeps(log), new Set(['delegation/created', 'delegation/verdict']))
  assert.equal(records.length, 2, 'honest markers survive blank lines on this face now (V6-M1)')
  assert.deepEqual(records.map(r => (r.payload as { taskId: string }).taskId), ['task-1', 'task-1'])
  assert.equal(records[0]?.at, '2026-10-06T00:00:00.000Z', 'the timestamp re-read indexes the blank-filtered domain')
})

test('V6-M1: the blank-line forgery carrier (headRef = digest of the empty line) is refused, not replayed', async () => {
  const evidence0 = JSON.stringify({ v: 1, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', payload: { evidenceId: 'e0' } })
  const marker = (label: string, extra: Record<string, unknown>, prev: string, headRef: string) => JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev,
    payload: { label, ...extra, headRef },
  })
  const honestCreated = marker('delegation/created', { taskId: 'task-1', claim: 'honest obligation' }, 'prev-0', lineDigest(evidence0))
  const honestVerified = marker('proof/verified', { grade: 'proven', economics: { cost: 1 } }, 'prev-z', lineDigest(honestCreated))
  // The PoC's first segment: a forged carrier whose headRef is the digest of
  // the EMPTY line, preceded by a blank line — in the raw view its physical
  // predecessor WAS the blank, so the forged witness PASSED and the forged
  // ledger replayed as a normal success on this face. In the readLines
  // domain the blank is not a line: the carrier chains to the honest
  // boundary before it and reads suspect, and the trusted pool (honest
  // markers present) never consults it.
  const forged = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev: 'prev-forged',
    payload: { label: 'proof/verified', grade: 'proven', economics: { cost: 999999 }, headRef: lineDigest('') },
  })
  const log = [evidence0, honestCreated, honestVerified, '', forged].join('\n') + '\n'
  const economics = await markerPayloads(fakeMarkerDeps(log), new Set(), { labelPrefixes: ['proof/'] })
  assert.equal(economics.length, 1, 'only the honest boundary marker rides')
  assert.equal((economics[0]?.payload as { economics?: { cost: number } }).economics?.cost, 1, 'the FORGED ledger is not the run this face replays')
})

test('V6-M2: a pre-witness legacy label reads degraded, not empty — engine parity (X-H-06)', async () => {
  const evidence0 = JSON.stringify({ v: 1, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', payload: { evidenceId: 'e0' } })
  // Every marker of the label predates the headRef witness: the whole
  // population is suspect, and the ENGINE's generational fallback reads it
  // degraded instead of evaporating (an upgraded deployment keeps exactly
  // the history it had). The MCP face used to read the same chain as an
  // empty DAG ("no delegations recorded on this chain yet") while the
  // engine still composed verdicts from it — the two faces now agree.
  const legacy = JSON.stringify({
    v: 2, kind: 'marker', at: '2025-01-01T00:00:00.000Z', prev: 'legacy-prev',
    payload: { label: 'delegation/created', taskId: 'task-old', claim: 'pre-witness obligation' },
  })
  const log = [evidence0, legacy].join('\n') + '\n'
  const records = await markerPayloads(fakeMarkerDeps(log), new Set(['delegation/created', 'delegation/verdict']))
  assert.equal(records.length, 1, 'the legacy marker is read, not evaporated (V6-M2)')
  assert.equal(records[0]?.degraded, true, 'and it is flagged degraded — the read says what it trusted')
  assert.equal((records[0]?.payload as { taskId?: string }).taskId, 'task-old')
})

/**
 * v0.24 (V6-M1/M2): the fake engine `markerPayloads` needs — the reader goes
 * through the verified view over the engine's store, so the fixture carries
 * a real `EvidenceStore` (reads only; no signer, no clock use) beside the
 * MemoryFs the raw-path checks already used.
 */
function fakeMarkerDeps(log: string): McpEngineDeps {
  const fs = MemoryFs.of({ '/store/evidence.jsonl': log })
  return {
    engine: {
      fsView: fs,
      storeView: new EvidenceStore(fs, '/store/evidence.jsonl', '/store/baseline.json', { now: () => 0 }),
    },
    evidenceLogPath: '/store/evidence.jsonl',
  } as unknown as McpEngineDeps
}

test('W8/G2 end to end: an injected delegation twin appended to the live log never reaches the task overview', async () => {
  const logPath = join(fixtureStoreDir(), 'evidence.jsonl')
  const original = await fsp.readFile(logPath, 'utf8')
  const lines = original.split('\n').filter(l => l.trim().length > 0)
  const lastLine = lines[lines.length - 1] as string
  // Out-of-band append: a created marker whose headRef names a line that is
  // not its physical predecessor (the writer's position witness fails).
  const injected = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev: lineDigest(lastLine),
    payload: { label: 'delegation/created', taskId: 'task-evil', claim: 'obligation nobody delegated', headRef: lineDigest(lines[0] as string) },
  })
  try {
    await fsp.writeFile(logPath, `${[...lines, injected].join('\n')}\n`, 'utf8')
    const overview = await callTool('proof_task', {})
    assert.equal(overview.isError, undefined, `overview errored: ${overview.content[0]?.text}`)
    const tasks = (overview.structuredContent as { tasks: { taskId: string }[] }).tasks
    assert.ok(
      !tasks.some(t => t.taskId === 'task-evil'),
      `the injected twin is excluded from the overview: ${JSON.stringify(tasks.map(t => t.taskId))}`,
    )
    assert.ok(tasks.some(t => t.taskId === 'task-1'), 'the honest delegations still list')
  } finally {
    await fsp.writeFile(logPath, original, 'utf8')
  }
})

test('a relative DSH_PROOF_TRUST_DIR fails startup loudly, never lands in the CWD (X-H-15)', async () => {
  const { code, stderr } = await spawnEntry({ DSH_PROOF_TRUST_DIR: 'relative-trust' })
  assert.notEqual(code, 0, 'the server must die rather than resolve a trust root against the launcher CWD')
  assert.match(stderr, /DSH_PROOF_TRUST_DIR/)
  assert.match(stderr, /ABSOLUTE/)
})

test('a relative DSH_HOME fails startup loudly (X-H-15: it poisons every derived default)', async () => {
  const { code, stderr } = await spawnEntry({ DSH_HOME: 'rel-home' })
  assert.notEqual(code, 0)
  assert.match(stderr, /DSH_HOME/)
  assert.match(stderr, /ABSOLUTE/)
})

test('a relative DSH_PROOF_PTL_DIR fails startup loudly (W10-M2)', async () => {
  const { code, stderr } = await spawnEntry({ DSH_PROOF_PTL_DIR: 'rel-ptl' })
  assert.notEqual(code, 0)
  assert.match(stderr, /DSH_PROOF_PTL_DIR/)
  assert.match(stderr, /ABSOLUTE/)
})

test('V4-M7: a PTL dir inside the workspace warns at startup — never a silent self-reference', async () => {
  // The absoluteness gate (above) passes an ABSOLUTE path pointing INTO the
  // workspace — which reopens exactly the self-reference it exists to close:
  // the operator-key candidates (<ptlDir>/ptl-operator-key, legacy
  // <ptlDir>/operator-key) land in the agent-writable area. M-47's rule
  // (warn + narrative, never silent), now applied to the PTL directory.
  const ephemeral = spawn(process.execPath, ['--experimental-strip-types', ENTRY], {
    cwd: WORKSPACE,
    env: {
      ...process.env,
      DSH_PROOF_ROOT: WORKSPACE,
      DSH_PROOF_TRUST_DIR: join(WORKSPACE, 'trust'),
      DSH_HOME: join(WORKSPACE, 'dsh-home'),
      DSH_PROOF_PTL_DIR: join(WORKSPACE, 'ptl-inside'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  try {
    const warning = await new Promise<string>((resolve, reject) => {
      let text = ''
      const timer = setTimeout(() => reject(new Error(`no containment warning arrived (stderr so far: ${text})`)), 15_000)
      ephemeral.stderr!.setEncoding('utf8')
      ephemeral.stderr!.on('data', (chunk: string) => {
        text += chunk
        if (text.includes('INSIDE the workspace')) {
          clearTimeout(timer)
          resolve(text)
        }
      })
      ephemeral.on('exit', () => {
        clearTimeout(timer)
        reject(new Error(`server exited before warning (stderr: ${text})`))
      })
    })
    assert.match(warning, /ptl-inside/, 'the warning names the offending directory')
    assert.match(warning, /operator/, 'the warning says WHY: the notarising key lands beside the log')
  } finally {
    ephemeral.kill()
  }
})

test('a bundle past half the response limit is trimmed to manifest + file names (both wire copies counted)', async () => {
  // Must run LAST in this file: it pads the evidence log with junk bytes,
  // which the chain audit would (correctly) flag for every later reader.
  const logPath = join(fixtureStoreDir(), 'evidence.jsonl')
  await fsp.appendFile(logPath, `${'x'.repeat(200_000)}\n`, 'utf8')
  const result = await callTool('proof_bundle', {}, 60_000)
  assert.equal(result.isError, undefined, `bundle errored: ${result.content[0]?.text}`)
  const value = result.structuredContent as { bundle: { manifest: unknown; files: string[] | Record<string, string>; note: string } }
  assert.ok(Array.isArray(value.bundle.files), 'files is the name list, not the contents')
  assert.ok((value.bundle.files as string[]).includes('evidence.jsonl'))
  assert.match(value.bundle.note, /only the manifest and the file-name list/, 'the note says what rides the wire')
  assert.match(value.bundle.note, /both wire copies/, 'the note is honest that the limit prices two copies')
})
