/**
 * MCP (Model Context Protocol) server — any harness, any agent.
 *
 * Exposes dsh-proof's verification face over stdio JSON-RPC 2.0 so agents that
 * are NOT running inside DeepSeek Harness can still baseline, verify and claim
 * against the same tamper-evident evidence chain. This module is deliberately
 * framework-free: `createMcpHandler` is a pure per-message dispatcher (no I/O,
 * directly unit-testable) and `runMcpServer` is the thin newline-delimited
 * stdio loop around it.
 *
 * APP/1.0 cross-agent contract: exactly five tools —
 * `MCP_TOOLS` below is the frozen list every consumer agrees on.
 *
 * Transport note: MCP stdio is newline-delimited JSON (one JSON-RPC 2.0
 * message per line), NOT LSP-style Content-Length framing. Protocol-level
 * problems (unknown method, unparseable line, malformed request) answer as
 * JSON-RPC errors; a tool that ran but failed answers as a normal result with
 * `isError: true` — MCP tool-error semantics, never mapped onto the RPC layer.
 *
 * @module dsh-proof/app/mcp-server
 */

import { createInterface } from 'node:readline'

import type { ProofEngine } from '../engine.ts'
import { SystemClock } from '../node-ports.ts'
import {
  toBaselineValue, toClaimValue, toStatusValue, toVerifyValue,
} from '../dsh/tools.ts'
import type { ClaimContract, ClaimKind } from '../core/contract.ts'
import { buildBundle } from './bundle.ts'

// ---------------------------------------------------------------------------
// The APP/1.0 contract — frozen with the other agents. Exactly five tools.
// ---------------------------------------------------------------------------

export const MCP_TOOLS = ['proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle'] as const

/** ζ: the five contract kinds `proof_claim` accepts — mirrors dsh/tools.ts's private list. */
const CLAIM_KINDS: readonly string[] = ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury']

function isClaimKind(value: unknown): value is ClaimKind {
  return typeof value === 'string' && CLAIM_KINDS.includes(value)
}

/**
 * Dependencies the server needs beyond the engine itself. Every path is
 * derived by the entry with the same rules the engine applied to its own
 * private copies (the engine exports neither its log path nor its derivation),
 * so the caller and this module never disagree about where evidence lives.
 */
export interface McpEngineDeps {
  engine: ProofEngine
  /** Physical evidence-log location (`<storeDir>/evidence.jsonl`). */
  evidenceLogPath: string
  /** Physical baseline location (`<storeDir>/baseline.json`). */
  baselinePath: string
  /** Physical anchor location (`<trustDir>/anchors/<workspaceKey>/anchor.json`). */
  anchorPath: string
  /** Stable workspace identity the bundle manifest is keyed by. */
  workspaceKey: string
  /** Reported as serverInfo.version (entry injects from env or the constant). */
  serverVersion: string
}

export interface McpServerOptions extends McpEngineDeps {
  /** Defaults to process.stdin; overridable for tests. */
  input?: NodeJS.ReadableStream
  /** Defaults to process.stdout; overridable for tests. */
  output?: NodeJS.WritableStream
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

export const MCP_SERVER_NAME = 'agent-proof-protocol'
export const MCP_DEFAULT_VERSION = '0.14.0'

/**
 * Protocol versions this server speaks, newest first. A client asking for a
 * version in the list gets it echoed back; anything else (older, newer, or
 * garbage) is answered with the newest version we support.
 */
const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'] as const
const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0] as string

/** Protocol-level JSON-RPC error codes (the only ones this server emits). */
const PARSE_ERROR = -32700
const INVALID_REQUEST = -32600
const METHOD_NOT_FOUND = -32601

/** A serialized bundle at or above this size is trimmed to manifest + names. */
const BUNDLE_INLINE_LIMIT_BYTES = 256 * 1024

/**
 * The clock the entry injects into the engine is private to the engine, so the
 * server holds its own instance of the identical SystemClock implementation —
 * bundle `createdAt` stamps therefore come from the same time source class the
 * engine's own records use.
 */
const clock = new SystemClock()

interface JsonRpcSuccess {
  jsonrpc: '2.0'
  id: string | number | null
  result: unknown
}

interface JsonRpcFailure {
  jsonrpc: '2.0'
  id: string | number | null
  error: { code: number; message: string }
}

function rpcResult(id: string | number | null, result: unknown): JsonRpcSuccess {
  return { jsonrpc: '2.0', id, result }
}

function rpcError(id: string | number | null, code: number, message: string): JsonRpcFailure {
  return { jsonrpc: '2.0', id, error: { code, message } }
}

function isValidId(value: unknown): value is string | number | null {
  return typeof value === 'string' || typeof value === 'number' || value === null
}

// ---------------------------------------------------------------------------
// tools/list descriptors — hand-written JSON Schema (no schema library: zero
// new npm dependencies is a hard constraint of this batch)
// ---------------------------------------------------------------------------

interface ToolDescriptor {
  name: string
  description: string
  inputSchema: Record<string, unknown>
}

const STATUS_DESCRIPTION =
  'Report the current proof state: whether a baseline exists, which objective checks the workspace declares, '
  + 'the latest evidence for each, and whether the tamper-evident chain is intact. Read-only. Call this before '
  + 'claiming anything is done.'

const BASELINE_DESCRIPTION =
  'Establish (or refresh) the verification baseline: run every objective check the workspace declares and record '
  + 'the outcomes as evidence. This is the anchor every later claim is diffed against. Do this once at the start '
  + 'of work, before making changes.'

const VERIFY_DESCRIPTION =
  'Re-run the objective checks this change set made stale and grade the outcome against the baseline. Uses '
  + 'change-impact analysis to run only what is affected unless `all` is set. A check that passed at baseline and '
  + 'now fails is a REGRESSION charged to this work.'

const CLAIM_DESCRIPTION =
  'State a completion claim AND prove it in one call. Runs the affected objective checks against the baseline and '
  + 'returns `proven: true` only when nothing regressed and full coverage was achieved. If it returns '
  + '`proven: false`, the blockers tell you exactly what to fix before the claim can stand.'

const BUNDLE_DESCRIPTION =
  'Export the tamper-evident evidence bundle (evidence log, baseline, anchor) with a digest manifest, for '
  + 'third-party audit or hand-off to another machine. Requires a baseline to exist (run proof_baseline first).'

const MCP_TOOL_LIST: ToolDescriptor[] = [
  {
    name: 'proof_status',
    description: STATUS_DESCRIPTION,
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'proof_baseline',
    description: BASELINE_DESCRIPTION,
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'proof_verify',
    description: VERIFY_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        changed: {
          type: 'array',
          items: { type: 'string' },
          description: 'Files this session changed, relative to the workspace root. Omit to use the derived change set.',
        },
        all: { type: 'boolean', description: 'Ignore impact analysis and re-run every discovered check.' },
        claim: { type: 'string', description: 'The claim being verified, for the record.' },
      },
    },
  },
  {
    name: 'proof_claim',
    description: CLAIM_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        claim: {
          type: 'string',
          description: 'The exact completion claim, e.g. "fixed the login redirect bug and added a regression test".',
        },
        kind: {
          type: 'string',
          enum: ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'],
          description: 'Optional typed contract for the claim: refactor/optimization → behavior-preserving; '
            + 'new feature → behavior-adding; performance → perf-budget (with budgetMs); documentation → docs-only '
            + '(with review); a subjective claim machines cannot measure → llm-jury. Omit to verify without a '
            + 'contract.',
        },
        budgetMs: { type: 'number', description: 'perf-budget only: benchmark checks must stay within this many milliseconds.' },
        review: {
          type: 'string',
          description: 'docs-only only: the self-review that jury evidence carries — what a human reviewer should double-check.',
        },
        entryPoints: {
          type: 'array',
          items: { type: 'string' },
          description: 'API-face entry points (workspace-relative files) the surface check covers; omit to let the '
            + 'engine derive them from package.json. Advanced usage.',
        },
        changed: {
          type: 'array',
          items: { type: 'string' },
          description: 'Files this session changed, relative to the workspace root.',
        },
      },
      required: ['claim'],
    },
  },
  {
    name: 'proof_bundle',
    description: BUNDLE_DESCRIPTION,
    inputSchema: { type: 'object', properties: {} },
  },
]

// ---------------------------------------------------------------------------
// Tool results — MCP semantics: a tool that ran and failed is a normal result
// carrying isError: true, never a JSON-RPC error.
// ---------------------------------------------------------------------------

interface McpToolResult {
  content: { type: 'text'; text: string }[]
  structuredContent: unknown
  isError?: true
}

function toolResult(value: unknown): McpToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  }
}

function toolError(value: unknown): McpToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
    isError: true,
  }
}

/** A never-aborted signal: MCP carries no cancellation in this face (yet). */
function freshSignal(): AbortSignal {
  return new AbortController().signal
}

/** Narrow an untrusted `arguments` object; non-objects degrade to no arguments. */
function callArguments(params: unknown): Record<string, unknown> {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return {}
  const args = (params as { arguments?: unknown }).arguments
  if (typeof args !== 'object' || args === null || Array.isArray(args)) return {}
  return args as Record<string, unknown>
}

/** Keep only the string entries of an untrusted array-valued argument. */
function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  return value.filter((entry): entry is string => typeof entry === 'string')
}

async function callStatusTool(deps: McpEngineDeps): Promise<McpToolResult> {
  // Same projection the DSH tool face uses (dsh/tools.ts createStatusTool) —
  // the MCP face must not diverge from what session logs already record.
  const specs = await deps.engine.loadChecks()
  const baseline = await deps.engine.baseline()
  const latest = await deps.engine.latestEvidence()
  const audit = await deps.engine.audit()
  const snapshot = await deps.engine.workspaceSnapshot()
  return toolResult(toStatusValue({ specs, baseline, latest, audit, snapshot }))
}

async function callBaselineTool(deps: McpEngineDeps): Promise<McpToolResult> {
  const { records, baseline } = await deps.engine.establishBaseline({ signal: freshSignal() })
  return toolResult(toBaselineValue(baseline, records))
}

async function callVerifyTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  // `claim` is accepted for the record (schema parity with the DSH face); the
  // engine's verify() takes no claim text, exactly like dsh/tools.ts.
  void args.claim
  const changed = stringArray(args.changed)
  const outcome = await deps.engine.verify({
    ...(changed !== undefined ? { changed } : {}),
    ...(args.all === true ? { all: true } : {}),
    signal: freshSignal(),
  })
  return toolResult(toVerifyValue(
    outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
    outcome.schedule, outcome.coverage,
  ))
}

async function callClaimTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  const claim = args.claim
  if (typeof claim !== 'string' || claim.trim().length === 0) {
    return toolError({ error: 'proof_claim: claim is required — the exact completion claim being made' })
  }
  // DELIBERATE DIVERGENCE from the DSH tool face: an unknown `kind` is an
  // ERROR here, never a silent fallback to the untyped path. The DSH face can
  // afford graceful degradation because its caller is the harness that owns
  // the schema; an MCP caller is a foreign agent whose every argument is
  // untrusted input — "you asked for a contract you cannot name" must come
  // back loudly or the fallback reads as an honest untyped verification.
  if (args.kind !== undefined && !isClaimKind(args.kind)) {
    return toolError({
      error: `proof_claim: kind must be one of ${CLAIM_KINDS.join(' | ')} `
        + `(got ${typeof args.kind === 'string' ? JSON.stringify(args.kind) : 'a non-string value'}); `
        + 'omitted kind verifies without a contract — a wrong kind is never silently downgraded',
    })
  }
  const changed = stringArray(args.changed)
  if (isClaimKind(args.kind)) {
    const contract: ClaimContract = {
      kind: args.kind,
      claim,
      ...(typeof args.budgetMs === 'number' ? { budgetMs: args.budgetMs } : {}),
      ...(typeof args.review === 'string' ? { review: args.review } : {}),
      ...(stringArray(args.entryPoints) !== undefined ? { entryPoints: stringArray(args.entryPoints) } : {}),
    }
    const outcome = await deps.engine.verifyContract({
      contract,
      ...(changed !== undefined ? { changed } : {}),
      signal: freshSignal(),
    })
    const verified = toVerifyValue(
      outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
      outcome.schedule, outcome.coverage,
    )
    return toolResult(toClaimValue(claim, outcome.report, verified, outcome.contract))
  }
  const outcome = await deps.engine.verify({
    ...(changed !== undefined ? { changed } : {}),
    signal: freshSignal(),
  })
  const verified = toVerifyValue(
    outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
    outcome.schedule, outcome.coverage,
  )
  return toolResult(toClaimValue(claim, outcome.report, verified))
}

/**
 * β's bundle builder owns the manifest shape; this face only decides HOW MUCH
 * of the built bundle rides the wire: under 256KB the whole thing, above it
 * the manifest plus the file-name list plus an explicit note — an MCP result
 * is not the channel for shipping megabytes of evidence log.
 */
function bundleFileNames(files: unknown): string[] {
  if (Array.isArray(files)) {
    const names: string[] = []
    for (const entry of files) {
      if (typeof entry === 'string') names.push(entry)
      else if (typeof entry === 'object' && entry !== null) {
        const record = entry as { name?: unknown; path?: unknown; rel?: unknown }
        const name = [record.name, record.path, record.rel].find(v => typeof v === 'string')
        if (name !== undefined) names.push(name as string)
      }
    }
    return names
  }
  if (typeof files === 'object' && files !== null) return Object.keys(files as Record<string, unknown>)
  return []
}

async function callBundleTool(deps: McpEngineDeps): Promise<McpToolResult> {
  // Read the engine's own evidence artifacts through its fs port, laid out at
  // the paths the entry derived with the engine's own rules. A missing
  // baseline/anchor is not an error — the bundle simply omits them; a missing
  // evidence log means there is nothing to bundle yet.
  const fs = deps.engine.fsView
  const evidenceLog = await fs.readFile(deps.evidenceLogPath)
  if (evidenceLog === undefined) {
    return toolError({
      error: `proof_bundle: no evidence log at ${deps.evidenceLogPath} — establish a baseline with proof_baseline first`,
    })
  }
  const baselineJson = await fs.readFile(deps.baselinePath)
  const anchorJson = await fs.readFile(deps.anchorPath)
  const bundle = buildBundle(
    {
      evidenceLog,
      ...(baselineJson !== undefined ? { baselineJson } : {}),
      ...(anchorJson !== undefined ? { anchorJson } : {}),
    },
    deps.workspaceKey,
    new Date(clock.now()).toISOString(),
  )
  const serialized = JSON.stringify(bundle)
  const size = new TextEncoder().encode(serialized).length
  if (size < BUNDLE_INLINE_LIMIT_BYTES) {
    return toolResult({ bundle })
  }
  return toolResult({
    bundle: {
      manifest: bundle.manifest,
      files: bundleFileNames(bundle.files),
      note: `bundle serialized to ${size} bytes (>= ${BUNDLE_INLINE_LIMIT_BYTES}); only the manifest and the `
        + 'file-name list ride this response — re-export on the host for full contents',
    },
  })
}

async function callTool(deps: McpEngineDeps, params: unknown): Promise<McpToolResult> {
  const name = typeof params === 'object' && params !== null
    ? (params as { name?: unknown }).name
    : undefined
  const args = callArguments(params)
  try {
    switch (name) {
      case 'proof_status': return await callStatusTool(deps)
      case 'proof_baseline': return await callBaselineTool(deps)
      case 'proof_verify': return await callVerifyTool(deps, args)
      case 'proof_claim': return await callClaimTool(deps, args)
      case 'proof_bundle': return await callBundleTool(deps)
      default:
        // Unknown tool: MCP tool-error semantics (isError result), with the
        // name spelled out so a foreign agent can self-correct.
        return toolError({
          error: `unknown tool: ${typeof name === 'string' ? name : String(name)} `
            + `— this server exposes exactly ${MCP_TOOLS.join(', ')}`,
        })
    }
  } catch (error) {
    // The tool ran and failed: same-shaped result with isError (MCP spec —
    // internal tool errors are NOT protocol-level JSON-RPC errors).
    const message = error instanceof Error ? error.message : String(error)
    return toolError({ error: `proof_${String(name)} failed: ${message}` })
  }
}

// ---------------------------------------------------------------------------
// The dispatcher — pure: one parsed message in, {response} or nothing out.
// Never touches stdio; notifications (no id) never produce a response.
// ---------------------------------------------------------------------------

export function createMcpHandler(
  deps: McpEngineDeps,
): (message: unknown) => Promise<{ response?: unknown }> {
  return async function handleMessage(message: unknown): Promise<{ response?: unknown }> {
    if (typeof message !== 'object' || message === null || Array.isArray(message)) {
      // Not even an object: cannot be a notification, so the invalid-request
      // reply is safe (id null — the message carried none we could read).
      return { response: rpcError(null, INVALID_REQUEST, 'invalid request: expected a JSON-RPC 2.0 object') }
    }
    const record = message as { id?: unknown; method?: unknown; params?: unknown }
    const hasId = 'id' in record
    if (hasId && !isValidId(record.id)) {
      return { response: rpcError(null, INVALID_REQUEST, 'invalid request: id must be a string, a number or null') }
    }
    const id = hasId ? (record.id as string | number | null) : null
    const method = record.method
    if (typeof method !== 'string' || method.length === 0) {
      // Notifications stay mute whatever their shape; a request without a
      // method is an invalid request.
      return hasId
        ? { response: rpcError(id, INVALID_REQUEST, 'invalid request: missing or non-string method') }
        : {}
    }
    // A notification (no id member) is never answered — not even to say the
    // method is unknown. This includes `notifications/initialized`, which
    // this server simply accepts as the handshake's second half.
    if (!hasId) return {}

    const params = record.params
    switch (method) {
      case 'initialize': {
        const requested = typeof params === 'object' && params !== null
          ? (params as { protocolVersion?: unknown }).protocolVersion
          : undefined
        const protocolVersion = typeof requested === 'string'
          && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
          ? requested
          : LATEST_PROTOCOL_VERSION
        return {
          response: rpcResult(id, {
            protocolVersion,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: MCP_SERVER_NAME, version: deps.serverVersion },
          }),
        }
      }
      case 'ping':
        return { response: rpcResult(id, {}) }
      case 'tools/list':
        return { response: rpcResult(id, { tools: MCP_TOOL_LIST }) }
      case 'tools/call':
        return { response: rpcResult(id, await callTool(deps, params)) }
      default:
        return { response: rpcError(id, METHOD_NOT_FOUND, `method not found: ${method}`) }
    }
  }
}

// ---------------------------------------------------------------------------
// The stdio loop — newline-delimited JSON both ways.
// ---------------------------------------------------------------------------

/**
 * Run the MCP server over newline-delimited JSON-RPC 2.0: one message per
 * line on stdin, one response per line on stdout. Resolves when the input
 * stream ends. Protocol-level failures (an unparseable line) are emitted as
 * JSON-RPC error responses with id null, because the offending line carried
 * no readable id to echo.
 */
export async function runMcpServer(options: McpServerOptions): Promise<void> {
  const input = options.input ?? process.stdin
  const output = options.output ?? process.stdout
  const handleMessage = createMcpHandler(options)
  const lines = createInterface({ input, crlfDelay: Infinity })
  for await (const line of lines) {
    const text = line.trim()
    if (text.length === 0) continue
    let parsed: unknown
    let parseFailed = false
    try {
      parsed = JSON.parse(text)
    } catch {
      parseFailed = true
    }
    let response: unknown
    if (parseFailed) {
      response = rpcError(null, PARSE_ERROR, `parse error: line is not valid JSON: ${text.slice(0, 80)}`)
    } else {
      const handled = await handleMessage(parsed)
      response = handled.response
    }
    if (response !== undefined) output.write(`${JSON.stringify(response)}\n`)
  }
}
