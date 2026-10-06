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
 * APP/1.2 cross-agent contract: exactly ten tools — `MCP_TOOLS` below is
 * the frozen list every consumer agrees on. (APP/1.0 spoke five; the §6
 * transparency-log expansion took it to seven with `proof_publish` and
 * `proof_log_verify`; the v0.19 responsibility-DAG expansion took it to ten
 * with `proof_delegate`, `proof_delegate_submit` and `proof_task`. Each bump
 * is what lets an older consumer refuse the wider dialect instead of
 * guessing at it.)
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
import { NodeEd25519Signer, SystemClock } from '../node-ports.ts'
import type { FsPort, SignerPort } from '../core/ports.ts'
// v0.18 (§6): the transparency-log domain — leaf hashing, Merkle proofs and
// tree-head verification, all recomputed from the log's own bytes.
import { loadPtl, ptlLeafHash, verifyConsistency, verifyInclusion, verifyTreeHead } from '../core/transparency.ts'
import type { PtlEntry } from '../core/transparency.ts'
import {
  toBaselineValue, toClaimValue, toStatusValue, toVerifyValue,
} from '../dsh/tools.ts'
import type { ClaimContract, ClaimKind } from '../core/contract.ts'
import { buildBundle } from './bundle.ts'
// v0.19: the grade vocabulary backs `proof_task`'s ownGrade validation — the
// five values a composed verdict can be asked to fold in.
import { GRADE_VALUES } from './protocol.ts'

// ---------------------------------------------------------------------------
// The APP/1.2 contract — frozen with the other agents. Exactly ten tools.
// ---------------------------------------------------------------------------

export const MCP_TOOLS = [
  'proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle',
  'proof_publish', 'proof_log_verify',
  // v0.19: the responsibility DAG — delegation, child submission, composed
  // task verdicts. Appended in order so an APP/1.1 consumer reading a list
  // positionally still finds its seven tools where it left them.
  'proof_delegate', 'proof_delegate_submit', 'proof_task',
] as const

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
  /**
   * v0.18: directory of the public transparency log (`proof_publish` /
   * `proof_log_verify`). Absent = both tools answer a clean configuration
   * error. The entry derives it from the environment (DSH_PROOF_PTL_DIR,
   * default `<trustRoot>/ptl`) — the same dir the engine publishes to.
   */
  ptlDir?: string
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
export const MCP_DEFAULT_VERSION = '0.19.0'

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

const PUBLISH_DESCRIPTION =
  'Publish the latest SIGNED checkpoint of this workspace\'s evidence chain to the public transparency log, and '
  + 'mint an operator-signed tree head (STH) over the resulting Merkle tree. The published entry carries the '
  + 'checkpoint\'s own signature, key and {count, head} — publishing mirrors proof, it never re-derives it. Any '
  + 'third party can then prove with proof_log_verify that this checkpoint was published and not silently '
  + 'rewritten afterwards. Requires a signed checkpoint on the chain (run proof_baseline or proof_verify first). '
  + 'Re-publishing the same checkpoint returns duplicate: true and leaves the tree unchanged.'

const LOG_VERIFY_DESCRIPTION =
  'Audit the public transparency log — every verdict is recomputed from the log\'s own bytes, nothing the caller '
  + 'asserts is trusted. With no arguments: recompute the Merkle root from the published entries and check the '
  + 'latest signed tree head against it (its signature is adjudicated when the operator key is present; a missing '
  + 'key is reported as not-checked, never as valid). With {sequence, leafHash}: re-derive the entry\'s leaf hash '
  + 'from the log and verify its inclusion proof against the recomputed root. With {publishedTreeSize, '
  + 'publishedRoot} (they go together): verify the current tree CONSISTENTLY EXTENDS that previously published '
  + 'tree — proof the history between the two sizes was not rewritten. Arguments combine; any failed check '
  + 'returns ok: false with the problems named.'

const DELEGATE_DESCRIPTION =
  'ORCHESTRATOR TOOL. Delegate a unit of work to a worker agent as a signed obligation on this workspace\'s '
  + 'responsibility DAG: the claim that must become true, optional acceptance criteria the result will be judged '
  + 'by, and optionally a parentTaskId to nest under an existing task. Returns the {taskId, obligationId, '
  + 'obligation} AND a ready-to-paste `instruction` — the handoff text for the worker agent\'s initial prompt. '
  + 'The worker proves the obligation in ITS OWN workspace (proof_baseline → work → proof_verify / proof_claim → '
  + 'proof_bundle) and submits the exported APP bundle back with proof_delegate_submit. The delegation is a '
  + 'precondition edge: until the worker\'s bundle verifies, the composed verdict of everything above it stays '
  + 'exactly as stale as the unproven obligation.'

const DELEGATE_SUBMIT_DESCRIPTION =
  'WORKER TOOL. Submit your completed work for a delegated obligation: the APP bundle you exported with '
  + 'proof_bundle in your own workspace, addressed to the taskId the orchestrator\'s proof_delegate returned. '
  + 'The bundle is adjudicated from its own bytes — manifest digests recomputed, chain walked, nothing you assert '
  + 'is trusted; `claimedGrade` (optional, one of the five grades) is what YOU claim and is checked against what '
  + 'the artifacts actually support. Returns the recorded submission and the `composed` verdict the submission '
  + 'produced: a forged or regressed bundle is attributed by taskId, never silently absorbed.'

const TASK_DESCRIPTION =
  'ORCHESTRATOR TOOL. Inspect the responsibility DAG. Without a taskId: the whole-task overview — every delegated '
  + 'task with its parent, an 80-character claim summary and whether a submission has landed. With a taskId: the '
  + 'full composed verdict for that task\'s subtree ({composed, nodes, cycles}) — own grade, forged/regressed/'
  + 'unproven children, waived obligations and blockers. `ownGrade` (optional, one of the five grades) folds this '
  + 'workspace\'s own local verdict into the composition. Roles in one line: the orchestrator speaks '
  + 'proof_delegate and proof_task; the worker speaks proof_verify, proof_bundle and proof_delegate_submit; a '
  + 'third-party auditor verifies the published log with proof_log_verify.'

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
  {
    name: 'proof_publish',
    description: PUBLISH_DESCRIPTION,
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'proof_log_verify',
    description: LOG_VERIFY_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        sequence: {
          type: 'number',
          description: 'Verify the inclusion of the entry at this 0-based leaf index. The leaf hash is recomputed '
            + 'from the log\'s entry — never taken from the caller.',
        },
        leafHash: {
          type: 'string',
          description: 'A 64-character hex sha256 leaf hash. With `sequence`: compared against the recomputed hash '
            + 'of that entry. Alone: the entry is located by hash, then inclusion-verified.',
        },
        publishedTreeSize: {
          type: 'number',
          description: 'A tree size you previously saw published (e.g. from an earlier proof_publish). Must be '
            + 'paired with publishedRoot; the tool then proves the current tree consistently extends it.',
        },
        publishedRoot: {
          type: 'string',
          description: 'The 64-character hex Merkle root you previously saw published at that size.',
        },
      },
    },
  },
  {
    name: 'proof_delegate',
    description: DELEGATE_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        claim: {
          type: 'string',
          description: 'The obligation as a completion claim — what must be TRUE when the worker is done, e.g. '
            + '"add the audit-report section with evidence citations".',
        },
        parentTaskId: {
          type: 'string',
          description: 'Nest this delegation under an existing task (from an earlier proof_delegate) to build the '
            + 'responsibility DAG. Omit for a root obligation.',
        },
        acceptance: {
          type: 'string',
          description: 'The acceptance criteria the submission will be judged by — shipped to the worker verbatim '
            + 'in its handoff instruction and recorded on the obligation.',
        },
      },
      required: ['claim'],
    },
  },
  {
    name: 'proof_delegate_submit',
    description: DELEGATE_SUBMIT_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        taskId: {
          type: 'string',
          description: 'The task the orchestrator\'s proof_delegate returned — the submission is addressed to it.',
        },
        bundle: {
          type: 'object',
          description: 'The APP bundle your proof_bundle export produced in YOUR workspace (manifest + files), '
            + 'passed through unmodified.',
        },
        claimedGrade: {
          type: 'string',
          enum: ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'],
          description: 'Optional: the grade you claim for your own work. Checked against what the bundle\'s '
            + 'artifacts actually support — claiming above the evidence is refused, not rounded down silently.',
        },
        byWorkspace: {
          type: 'string',
          description: 'Optional: your workspace\'s stable identity (e.g. its workspaceKey), recorded on the '
            + 'submission for attribution.',
        },
      },
      required: ['taskId', 'bundle'],
    },
  },
  {
    name: 'proof_task',
    description: TASK_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        taskId: {
          type: 'string',
          description: 'A specific delegated task (from proof_delegate). Omit to list the whole task graph.',
        },
        ownGrade: {
          type: 'string',
          enum: ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'],
          description: 'Optional: fold this workspace\'s own local grade into the composed verdict. One of the '
            + 'five grades — anything else is refused loudly, never silently dropped.',
        },
      },
    },
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

// ---------------------------------------------------------------------------
// v0.18 (§6): the transparency-log tools
// ---------------------------------------------------------------------------

async function callPublishTool(deps: McpEngineDeps): Promise<McpToolResult> {
  // Preconditions (ptlDir configured, a signed checkpoint on the chain, the
  // operator key resolvable) are the ENGINE's to enforce — each failure throws
  // a clean error that the dispatcher below answers as an isError result, so
  // a foreign agent gets the exact precondition it must fix, never a
  // half-published tree.
  const outcome = await deps.engine.publishCheckpoint()
  return toolResult({
    sequence: outcome.sequence,
    duplicate: outcome.duplicate,
    leafHash: outcome.leafHash,
    treeSize: outcome.treeSize,
    root: outcome.root,
    logId: outcome.logId,
    at: outcome.at,
    inclusionProof: [...outcome.inclusionProof],
    sth: outcome.sth,
  })
}

/**
 * The operator key for tree-head adjudication, loaded ONLY when it already
 * exists on disk. `NodeEd25519Signer.load` bootstraps a missing key — exactly
 * right for publishing, exactly wrong for a verify tool: minting a key as a
 * side effect of auditing would write to the very tree under audit and
 * "verify" against a key that never signed anything.
 */
async function operatorSignerFor(fs: FsPort, ptlDir: string): Promise<SignerPort | undefined> {
  const dir = `${ptlDir.replace(/[\/]+$/, '')}/operator-key`
  try {
    const names = await fs.readDir(dir)
    if (names === undefined || !names.some(name => name.endsWith('proof-signing-key.pem'))) return undefined
    return await NodeEd25519Signer.load(dir)
  } catch {
    // A key directory we cannot even probe is a missing capability, not an
    // accusation — reported as not-checked by the caller.
    return undefined
  }
}

/** 64-character lowercase hex (a sha256 digest on the wire). */
function isHexDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

async function callLogVerifyTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  if (deps.ptlDir === undefined) {
    return toolError({
      error: 'proof_log_verify: transparency log not configured (ptlDir) — start the server with DSH_PROOF_PTL_DIR set',
    })
  }
  // Argument adjudication: usage errors (wrong types, unpairable parameters)
  // are tool errors; findings about the LOG are audit results (ok: false).
  // Nothing the caller asserts is trusted — sequence/leafHash are recomputed
  // from the log's own entries, and only then compared.
  const sequenceArg = args.sequence
  if (sequenceArg !== undefined
    && (typeof sequenceArg !== 'number' || !Number.isInteger(sequenceArg) || sequenceArg < 0)) {
    return toolError({ error: `proof_log_verify: sequence must be a non-negative integer (got ${JSON.stringify(sequenceArg)})` })
  }
  const leafHashArg = args.leafHash
  if (leafHashArg !== undefined && !isHexDigest(leafHashArg)) {
    return toolError({ error: `proof_log_verify: leafHash must be a 64-character hex sha256 digest (got ${JSON.stringify(leafHashArg)})` })
  }
  const sizeArg = args.publishedTreeSize
  if (sizeArg !== undefined && (typeof sizeArg !== 'number' || !Number.isInteger(sizeArg) || sizeArg < 1)) {
    return toolError({ error: `proof_log_verify: publishedTreeSize must be a positive integer (got ${JSON.stringify(sizeArg)})` })
  }
  const rootArg = args.publishedRoot
  if (rootArg !== undefined && !isHexDigest(rootArg)) {
    return toolError({ error: `proof_log_verify: publishedRoot must be a 64-character hex sha256 digest (got ${JSON.stringify(rootArg)})` })
  }
  if ((sizeArg !== undefined) !== (rootArg !== undefined)) {
    return toolError({
      error: 'proof_log_verify: publishedTreeSize and publishedRoot must be supplied together — a consistency '
        + 'proof binds a tree size to its root; one without the other proves nothing',
    })
  }

  const fs = deps.engine.fsView
  const { log, sth: head, badLines } = await loadPtl(fs, deps.ptlDir)
  if (log.size === 0) {
    return toolError({
      error: `proof_log_verify: the transparency log at ${deps.ptlDir} holds no entries — publish with proof_publish first`,
    })
  }
  const problems: string[] = []
  if (badLines > 0) {
    problems.push(`${badLines} malformed entry line(s) skipped while loading ${deps.ptlDir} — the readable prefix was audited, but the log is not sound`)
  }
  const treeSize = log.size
  // The root is recomputed from the published leaves before anything else is
  // said: every later check compares against THIS number, never against a
  // root the head file or the caller handed over.
  const root = log.merkleRoot()

  // -- the signed tree head: present, honest about the tree, genuinely signed --
  let treeHead: Record<string, unknown> | undefined
  if (head === undefined) {
    problems.push(`no signed tree head in ${deps.ptlDir} — the published tree carries no operator commitment`)
  } else {
    const sizeMatches = head.treeSize === treeSize
    const rootMatches = head.root === root
    if (!sizeMatches) {
      problems.push(`tree head speaks treeSize ${head.treeSize} but the log holds ${treeSize} entries — entries were appended after the last head, or the head was rewritten`)
    }
    if (!rootMatches) {
      problems.push(`tree head root ${head.root} does not match the root recomputed from the log (${root})`)
    }
    const operator = await operatorSignerFor(fs, deps.ptlDir)
    let signature: 'verified' | 'invalid' | 'not-checked (operator key absent)'
    if (operator === undefined) {
      signature = 'not-checked (operator key absent)'
    } else {
      signature = await verifyTreeHead(head, (data, sig) => operator.verify(data, sig))
        ? 'verified'
        : 'invalid'
      if (signature === 'invalid') {
        problems.push('tree head signature does not verify under the operator key — the head file was rewritten, or signed by a different key')
      }
    }
    treeHead = {
      logId: head.logId,
      treeSize: head.treeSize,
      root: head.root,
      at: head.at,
      sizeMatches,
      rootMatches,
      signature,
    }
  }

  // -- inclusion: the entry at `sequence` (or by leafHash) is committed by the root --
  let inclusion: Record<string, unknown> | undefined
  if (sequenceArg !== undefined || leafHashArg !== undefined) {
    let sequence: number | undefined
    let entry: PtlEntry | undefined
    let leaf: string | undefined
    if (sequenceArg !== undefined) {
      if (sequenceArg >= treeSize) {
        return toolError({
          error: `proof_log_verify: sequence ${sequenceArg} is outside the log (treeSize ${treeSize}) — the log never shrinks`,
        })
      }
      sequence = sequenceArg
      entry = log.entries[sequence]
      // Recomputed from the log's own entry: the caller's leafHash (when
      // given) is compared against THIS, never the other way round.
      leaf = entry !== undefined ? ptlLeafHash(entry) : undefined
    } else {
      const found = log.entries.findIndex(candidate => ptlLeafHash(candidate) === leafHashArg)
      if (found < 0) {
        problems.push(`no entry in the log hashes to ${leafHashArg}`)
      } else {
        sequence = found
        entry = log.entries[found]
        leaf = leafHashArg
      }
    }
    if (sequence !== undefined && leaf !== undefined && leafHashArg !== undefined && leafHashArg !== leaf) {
      problems.push(`the entry at sequence ${sequence} hashes to ${leaf}, not the asserted ${leafHashArg}`)
    }
    if (sequence !== undefined && entry !== undefined && leaf !== undefined) {
      const proof = log.inclusionProof(sequence)
      const verified = verifyInclusion(entry, sequence, treeSize, proof, root)
      if (!verified) {
        problems.push(`inclusion proof for sequence ${sequence} does not verify against the recomputed root`)
      }
      inclusion = { sequence, leafHash: leaf, verified }
    }
  }

  // -- consistency: the current tree extends the previously published one --
  let consistency: Record<string, unknown> | undefined
  if (sizeArg !== undefined && rootArg !== undefined) {
    if (sizeArg > treeSize) {
      return toolError({
        error: `proof_log_verify: publishedTreeSize ${sizeArg} exceeds the current tree size ${treeSize} — the log never shrinks, so no consistency proof to a larger "past" can exist`,
      })
    }
    // Equal sizes are the identity case T1's verifyConsistency adjudicates
    // itself (empty proof, roots must be equal).
    const verified = verifyConsistency(sizeArg, rootArg, treeSize, root, log.consistencyProof(sizeArg, treeSize))
    if (!verified) {
      problems.push(`consistency proof from tree size ${sizeArg} to ${treeSize} does not verify — the current tree is not an extension of the published one (history was rewritten)`)
    }
    consistency = { fromTreeSize: sizeArg, fromRoot: rootArg, toTreeSize: treeSize, verified }
  }

  return toolResult({
    ok: problems.length === 0,
    treeSize,
    root,
    ...(treeHead !== undefined ? { treeHead } : {}),
    ...(inclusion !== undefined ? { inclusion } : {}),
    ...(consistency !== undefined ? { consistency } : {}),
    ...(problems.length > 0 ? { problems } : {}),
  })
}

// ---------------------------------------------------------------------------
// v0.19: the responsibility-DAG tools (APP/1.2's 7 → 10 expansion)
//
// The verbs themselves live in the engine (delegateTask / submitDelegation /
// taskVerdict; waiveDelegation stays engine-side for now). This face only
// adjudicates untrusted ARGUMENTS, narrates the three-party protocol
// (orchestrator delegates and inspects, worker proves and submits), and
// passes engine value objects through verbatim — the composition semantics
// are the engine's, so the MCP layer must never re-derive a grade.
// ---------------------------------------------------------------------------

/**
 * The engine-side delegation contract, as frozen with the engine workstream.
 * Declared HERE (not imported) because the engine grows into it in parallel;
 * `delegationVerbs` narrows the live engine against it at runtime, so this
 * server degrades to a clean capability error — never a crash — on a build
 * whose engine has not landed the responsibility DAG yet.
 */
interface DelegationVerbs {
  delegateTask(input: { claim: string; parentTaskId?: string; acceptance?: string }): Promise<{
    taskId: string
    obligationId: string
    obligation: Record<string, unknown>
  }>
  submitDelegation(input: {
    taskId: string
    bundle: unknown
    byWorkspace?: string
    claimedGrade?: string
  }): Promise<{ submission: Record<string, unknown>; composed: Record<string, unknown> }>
  taskVerdict(input: { taskId: string; ownGrade?: string }): Promise<{
    composed: Record<string, unknown>
    nodes: unknown
    cycles: unknown
  }>
}

/**
 * The live engine's delegation verbs, or undefined when this build's engine
 * does not implement the responsibility DAG. Existence is checked per call —
 * the seam is deliberately the only place the engine's newer surface is
 * reached through a cast.
 */
function delegationVerbs(engine: ProofEngine): DelegationVerbs | undefined {
  const candidate = engine as unknown as Partial<Record<keyof DelegationVerbs, unknown>>
  return typeof candidate.delegateTask === 'function'
    && typeof candidate.submitDelegation === 'function'
    && typeof candidate.taskVerdict === 'function'
    ? (candidate as DelegationVerbs)
    : undefined
}

function delegationUnavailable(tool: string): McpToolResult {
  return toolError({
    error: `${tool}: this engine build does not implement the responsibility-DAG verbs `
      + '(delegateTask / submitDelegation / taskVerdict) — the delegation tools cannot run',
  })
}

/** ζ: the five grades `proof_task`/`proof_delegate_submit` accept — protocol.ts's scale. */
const GRADES: readonly string[] = GRADE_VALUES

function isGradeValue(value: unknown): value is string {
  return typeof value === 'string' && GRADES.includes(value)
}

/**
 * The handoff text for the worker agent, ready to paste into its initial
 * prompt. It carries the obligation verbatim (claim + acceptance), the
 * worker's half of the protocol (prove in YOUR workspace, then submit the
 * exported bundle back), and the precondition sentence that makes the DAG
 * legible: the parent's proven is built out of the child's.
 */
function handoffInstruction(task: {
  taskId: string
  claim: string
  acceptance?: string
  parentTaskId?: string
}): string {
  return [
    `DELEGATED OBLIGATION ${task.taskId}`,
    '',
    'You are the worker agent for a delegated obligation on the agent-proof-protocol',
    `responsibility DAG${task.parentTaskId !== undefined ? ` (nested under parent task ${task.parentTaskId})` : ''}.`,
    'Make the claim below true IN YOUR OWN WORKSPACE, then prove it and submit the',
    'proof back to the orchestrator that delegated it.',
    '',
    'CLAIM (what must become true):',
    `  ${task.claim}`,
    '',
    'ACCEPTANCE (how your submission will be judged):',
    `  ${task.acceptance ?? 'none recorded — the claim text above is the whole contract'}`,
    '',
    'YOUR PART OF THE PROTOCOL, in order:',
    "  1. proof_baseline  — anchor your workspace's starting state before you change anything.",
    '  2. Do the work that makes the claim true.',
    '  3. proof_verify (or proof_claim carrying the claim text) — the affected checks must',
    '     re-run, and your session must grade "proven" with zero regressions before you',
    '     may submit.',
    '  4. proof_bundle    — export the tamper-evident APP bundle of your evidence chain.',
    `  5. Submit it back with proof_delegate_submit { taskId: ${JSON.stringify(task.taskId)}, bundle: <the bundle proof_bundle returned> }.`,
    '',
    'Your "proven" is the precondition of the parent task\'s "proven": until your bundle',
    'verifies, everything above you in the task graph stays stale — and a forged or',
    'regressed submission is attributed to you by taskId, never silently absorbed.',
  ].join('\n')
}

async function callDelegateTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  const claim = args.claim
  if (typeof claim !== 'string' || claim.trim().length === 0) {
    return toolError({ error: 'proof_delegate: claim is required — the obligation, phrased as a completion claim' })
  }
  // Same loud-argument discipline as proof_claim's kind guard: an optional
  // parameter that arrived with the wrong TYPE is an error, never dropped.
  if (args.parentTaskId !== undefined && typeof args.parentTaskId !== 'string') {
    return toolError({ error: `proof_delegate: parentTaskId must be a string (got ${JSON.stringify(args.parentTaskId)})` })
  }
  if (args.acceptance !== undefined && typeof args.acceptance !== 'string') {
    return toolError({ error: `proof_delegate: acceptance must be a string (got ${JSON.stringify(args.acceptance)})` })
  }
  const verbs = delegationVerbs(deps.engine)
  if (verbs === undefined) return delegationUnavailable('proof_delegate')
  const parentTaskId = args.parentTaskId as string | undefined
  const acceptance = args.acceptance as string | undefined
  // Semantic preconditions (unknown parentTaskId, a cyclic nest, …) are the
  // ENGINE's to enforce; a clean throw rides the dispatcher's isError path.
  const outcome = await verbs.delegateTask({
    claim,
    ...(parentTaskId !== undefined ? { parentTaskId } : {}),
    ...(acceptance !== undefined ? { acceptance } : {}),
  })
  return toolResult({
    taskId: outcome.taskId,
    obligationId: outcome.obligationId,
    obligation: outcome.obligation,
    instruction: handoffInstruction({
      taskId: outcome.taskId,
      claim,
      ...(parentTaskId !== undefined ? { parentTaskId } : {}),
      ...(acceptance !== undefined ? { acceptance } : {}),
    }),
  })
}

async function callDelegateSubmitTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  const taskId = args.taskId
  if (typeof taskId !== 'string' || taskId.length === 0) {
    return toolError({ error: 'proof_delegate_submit: taskId is required — the delegation being submitted for' })
  }
  const bundle = args.bundle
  if (typeof bundle !== 'object' || bundle === null || Array.isArray(bundle)) {
    return toolError({
      error: 'proof_delegate_submit: bundle is required — the APP bundle object your proof_bundle export returned',
    })
  }
  // A grade the scale does not name is refused loudly (a worker claiming an
  // unintelligible grade must be told, not silently downgraded), mirroring
  // proof_claim's kind guard.
  if (args.claimedGrade !== undefined && !isGradeValue(args.claimedGrade)) {
    return toolError({
      error: `proof_delegate_submit: claimedGrade must be one of ${GRADES.join(' | ')} `
        + `(got ${typeof args.claimedGrade === 'string' ? JSON.stringify(args.claimedGrade) : 'a non-string value'})`,
    })
  }
  if (args.byWorkspace !== undefined && typeof args.byWorkspace !== 'string') {
    return toolError({ error: `proof_delegate_submit: byWorkspace must be a string (got ${JSON.stringify(args.byWorkspace)})` })
  }
  const verbs = delegationVerbs(deps.engine)
  if (verbs === undefined) return delegationUnavailable('proof_delegate_submit')
  // The bundle's own bytes adjudicate everything from here (digests, chain,
  // claimed vs supported grade); the engine's clean throws ride isError.
  const outcome = await verbs.submitDelegation({
    taskId,
    bundle,
    ...(typeof args.byWorkspace === 'string' ? { byWorkspace: args.byWorkspace } : {}),
    ...(isGradeValue(args.claimedGrade) ? { claimedGrade: args.claimedGrade } : {}),
  })
  return toolResult({ submission: outcome.submission, composed: outcome.composed })
}

/**
 * One delegated task as the overview lists it: identity, place in the DAG, a
 * claim summary short enough to scan a whole graph at a glance, and whether a
 * submission has landed against it.
 */
interface TaskOverviewEntry {
  taskId: string
  parentTaskId: string | null
  claim: string
  submitted: boolean
}

/** A claim folded to 80 characters — the overview is for scanning, not judging. */
function summarizeClaim(claim: string): string {
  return claim.length <= 80 ? claim : `${claim.slice(0, 77)}...`
}

/**
 * The whole-task overview, read back off the evidence chain the way the DSH
 * attestation tools read markers (dsh/tools.ts's markerPayloads precedent):
 * parse each line, keep `delegation/` markers, and classify by label — the
 * engine mints `delegation/created` when an obligation is opened and
 * `delegation/verdict` when a submission lands (`delegation/waive` is a risk
 * acceptance, NOT a submission, so it is deliberately not matched). Defensive
 * by construction: an unreadable log degrades to an empty overview, never a
 * throw, and any field with the wrong shape is skipped, not guessed at.
 */
async function taskOverview(deps: McpEngineDeps): Promise<TaskOverviewEntry[]> {
  const tasks = new Map<string, TaskOverviewEntry>()
  let lines: readonly string[]
  try {
    lines = await deps.engine.fsView.readLines(deps.evidenceLogPath)
  } catch {
    return []
  }
  for (const line of lines) {
    let envelope: { kind?: unknown; payload?: unknown }
    try {
      envelope = JSON.parse(line) as { kind?: unknown; payload?: unknown }
    } catch {
      continue
    }
    if (envelope?.kind !== 'marker') continue
    const payload = envelope.payload
    if (typeof payload !== 'object' || payload === null) continue
    const record = payload as Record<string, unknown>
    const label = typeof record.label === 'string' ? record.label : ''
    if (!label.startsWith('delegation/')) continue
    const taskId = record.taskId
    if (typeof taskId !== 'string') continue
    if (label.includes('created')) {
      const claim = record.claim
      if (typeof claim !== 'string') continue
      const parentTaskId = typeof record.parentTaskId === 'string' ? record.parentTaskId : null
      tasks.set(taskId, { taskId, parentTaskId, claim: summarizeClaim(claim), submitted: false })
    } else if ((label.includes('verdict') || label.includes('submit')) && tasks.has(taskId)) {
      // A landed submission (`delegation/verdict` in the engine's dialect);
      // 'submit' is matched too so a future engine renaming the label keeps
      // the overview honest.
      const entry = tasks.get(taskId)!
      tasks.set(taskId, { ...entry, submitted: true })
    }
  }
  return [...tasks.values()]
}

async function callTaskTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  if (args.taskId !== undefined && typeof args.taskId !== 'string') {
    return toolError({ error: `proof_task: taskId must be a string (got ${JSON.stringify(args.taskId)})` })
  }
  if (args.ownGrade !== undefined && !isGradeValue(args.ownGrade)) {
    return toolError({
      error: `proof_task: ownGrade must be one of ${GRADES.join(' | ')} `
        + `(got ${typeof args.ownGrade === 'string' ? JSON.stringify(args.ownGrade) : 'a non-string value'}); `
        + 'an unintelligible grade is refused, never silently dropped',
    })
  }
  const verbs = delegationVerbs(deps.engine)
  if (verbs === undefined) return delegationUnavailable('proof_task')
  const taskId = args.taskId as string | undefined
  if (taskId === undefined) {
    const tasks = await taskOverview(deps)
    return toolResult({
      tasks,
      ...(tasks.length === 0
        ? { note: 'no delegations recorded on this chain yet — create one with proof_delegate' }
        : {}),
    })
  }
  const verdict = await verbs.taskVerdict({
    taskId,
    ...(isGradeValue(args.ownGrade) ? { ownGrade: args.ownGrade } : {}),
  })
  return toolResult({ taskId, composed: verdict.composed, nodes: verdict.nodes, cycles: verdict.cycles })
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
      case 'proof_publish': return await callPublishTool(deps)
      case 'proof_log_verify': return await callLogVerifyTool(deps, args)
      case 'proof_delegate': return await callDelegateTool(deps, args)
      case 'proof_delegate_submit': return await callDelegateSubmitTool(deps, args)
      case 'proof_task': return await callTaskTool(deps, args)
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
