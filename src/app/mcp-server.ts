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
 * APP/1.4 cross-agent contract: exactly thirteen tools — `MCP_TOOLS` below is
 * the frozen list every consumer agrees on. (APP/1.0 spoke five; the §6
 * transparency-log expansion took it to seven with `proof_publish` and
 * `proof_log_verify`; the v0.19 responsibility-DAG expansion took it to ten
 * with `proof_delegate`, `proof_delegate_submit` and `proof_task`; the v0.20
 * training-export expansion took it to eleven with `proof_training_export`;
 * the v0.21 verification-economics expansion takes it to thirteen with
 * `proof_economics` and `proof_sla_quote`. Each bump is what lets an older
 * consumer refuse the wider dialect instead of guessing at it.)
 *
 * Transport note: MCP stdio is newline-delimited JSON (one JSON-RPC 2.0
 * message per line), NOT LSP-style Content-Length framing. Protocol-level
 * problems (unknown method, unparseable line, malformed request, a request
 * before `initialize`, a line over the transport cap) answer as JSON-RPC
 * errors; a tool that ran but failed answers as a normal result with
 * `isError: true` — MCP tool-error semantics, never mapped onto the RPC
 * layer. JSON-RPC 2.0 batches (an array of messages) are processed element
 * by element and answered with an array, per the specification.
 *
 * @module dsh-proof/app/mcp-server
 */

import { homedir } from 'node:os'

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
// The APP/1.4 contract — frozen with the other agents. Exactly thirteen tools.
// ---------------------------------------------------------------------------

export const MCP_TOOLS = [
  'proof_status', 'proof_baseline', 'proof_verify', 'proof_claim', 'proof_bundle',
  'proof_publish', 'proof_log_verify',
  // v0.19: the responsibility DAG — delegation, child submission, composed
  // task verdicts. Appended in order so an APP/1.1 consumer reading a list
  // positionally still finds its seven tools where it left them.
  'proof_delegate', 'proof_delegate_submit', 'proof_task',
  // v0.20: the training-data exhaust valve — the deployer's labeled agent
  // behavior dataset, distilled off the chain. Appended so the APP/1.2 prefix
  // is unchanged for a positional reader.
  'proof_training_export',
  // v0.21: the verification-economics pair — the cost ledger read back off the
  // chain's own boundary markers, and the SLA quote that prices what a grade
  // leaves undetected. Appended so the APP/1.3 prefix is unchanged too.
  'proof_economics', 'proof_sla_quote',
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
  /**
   * v0.22: opt-out of the initialize-before-tools gate for embedders that
   * drive `createMcpHandler` directly (unit tests, in-process hosts). The
   * stdio server itself never sets it — there the handshake is mandatory.
   */
  allowUninitializedTools?: boolean
  /**
   * v0.22: the host-side trust root, when the caller knows it — the PTL
   * operator key resolves under it first (`<trustRoot>/ptl-operator-key`,
   * the engine's and the CLI's default) before the log-dir spellings, so a
   * key that notarises a log is never loaded from inside the directory the
   * log's own writer can rewrite.
   */
  trustRoot?: string
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
export const MCP_DEFAULT_VERSION = '0.22.0'

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
const INVALID_PARAMS = -32602

/** A serialized bundle at or above this size is trimmed to manifest + names. */
const BUNDLE_INLINE_LIMIT_BYTES = 256 * 1024

/**
 * v0.22: the largest stdin line the stdio loop will buffer (4 MiB). A longer
 * line is refused with a parse error WITHOUT being buffered to completion or
 * parsed — one JSON-RPC message per line is the transport contract, and a
 * foreign client that sends an unbounded "line" must not get to size the
 * server's memory by violating it.
 */
const MAX_LINE_BYTES = 4 * 1024 * 1024

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
  + 'is trusted. `claimedGrade` (optional, one of the five grades) is YOUR self-claim, recorded verbatim and then '
  + 'adjudicated: a "proven" the artifacts cannot back is recorded as forged and composes regressed; any other '
  + 'grade passes through as the recorded claim — it is attributed, not independently verified, and never '
  + 'silently rounded. Returns the recorded submission and the `composed` verdict the submission produced: a '
  + 'forged or regressed bundle is attributed by taskId, never silently absorbed.'

const TASK_DESCRIPTION =
  'ORCHESTRATOR TOOL. Inspect the responsibility DAG. Without a taskId: the whole-task overview — every delegated '
  + 'task with its parent, an 80-character claim summary and whether a submission has landed. With a taskId: the '
  + 'full composed verdict for that task\'s subtree ({composed, nodes, cycles}) — own grade, forged/regressed/'
  + 'unproven children, waived obligations and blockers. `ownGrade` (optional, one of the five grades) is the '
  + 'caller\'s SELF-REPORT about this workspace\'s own local work — advisory input only: the composed verdict '
  + 'derives from child evidence and bundle verification, never from this claim, and an ownGrade the evidence '
  + 'contradicts is recorded, not trusted. Roles in one line: the orchestrator speaks '
  + 'proof_delegate and proof_task; the worker speaks proof_verify, proof_bundle and proof_delegate_submit; a '
  + 'third-party auditor verifies the published log with proof_log_verify.'

const TRAINING_EXPORT_DESCRIPTION =
  'Export this workspace\'s accumulated agent behavior data as a training dataset — the deployer\'s exhaust valve '
  + 'for the labeled behavior traces the proof chain has been recording all along. Every sample\'s label is a '
  + 'MACHINE-VERIFIED verdict the hash chain protects: credit and blame come from re-running objective checks '
  + 'against the baseline, never from an agent\'s self-report, so the label is ground truth by construction. The '
  + 'manifest carries the reward table, the provenance filter and a chain anchor ({count, head, keyId}) — the '
  + 'anchor makes the whole dataset auditable against the very evidence chain it was distilled from. PRIVACY: '
  + '`fidelity` defaults to `private`, which emits ZERO output text (structure and labels only); `full` emits the '
  + 'raw recorded text and must be a deliberate, license-carrying choice. THE SAMPLES THEMSELVES NEVER RIDE THIS '
  + 'RESPONSE (a dataset can be huge): the value carries the full manifest, the anchor and `sampleCount`; pass '
  + '`path` to have the engine write the samples to disk as JSONL (the value then carries `writtenTo`), or read '
  + 'the samples through the engine API. Requires a baseline and at least one verification on the chain (run '
  + 'proof_baseline, then work and proof_verify — the evidence IS the dataset).'

const ECONOMICS_DESCRIPTION =
  'Read the economics ledger of the most recent verification this workspace ran — WHAT THE PROOF COST, read back '
  + 'off the evidence log\'s own boundary marker, never recomputed here and never taken on the caller\'s word. A '
  + 'ledger exists only when the verification ran WITH a rate card: pass `economics: {computePerMs, humanReviewPerItem?}` '
  + 'to proof_verify (this MCP face accepts it directly), and the boundary marker records the ledger (computeMs, '
  + 'cost, assertions, costPerAssertion, purchased confidence, info nats) plus the prior probability it moved '
  + 'from. This tool then scans the chain and REPLAYS the most recent proof/claim marker that carries one, '
  + 'verbatim — grade and all — after running a chain audit whose verdict rides the response: the hash chain '
  + 'detects rewrites, it does not prevent a writer who can touch the log, so a failing audit means the replayed '
  + 'ledger may be forged. The arguments here are the rate card you are asking under (computePerMs required, '
  + '> 0; humanReviewPerItem optional): they are validated and echoed, but they price nothing new and change no '
  + 'future run — this is a PURE QUERY over evidence that already exists. If the chain holds no economics yet, '
  + 'the error says exactly how to mint one.'

const SLA_QUOTE_DESCRIPTION =
  'Price a service-level agreement over a verification grade — the INSURANCE reading of what proof leaves '
  + 'undetected. The premium is pure risk pricing: premium = coverageAmount × (1 − confidence), the expected '
  + 'loss the run\'s residual risk (`pUndetected` = 1 − confidence) leaves open; the offer carries the '
  + 'deductible and coverage amount verbatim. Honest underwriting, three doors: a `proven` grade earns an '
  + 'OFFER; a `regressed` grade is honestly REFUSED (denied — a run that already failed its own baseline is '
  + 'not a risk to underwrite, and the reason says so); a `stale` grade goes to MANUAL UNDERWRITING (the '
  + 'evidence is not decisive enough to price mechanically). `exclusions` are the known blind spots written '
  + 'into the policy as words — what this quote does NOT cover, made part of the contract instead of fine '
  + 'print. The quote lands on the evidence chain like every other boundary (its `quoteId` addresses it), so a '
  + 'quoted premium cannot be silently rewritten after the fact. Only USD is priced; `deductible` shifts the '
  + 'first losses to you; `minPremium` is the smallest premium worth writing at all.'

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
        economics: {
          type: 'object',
          description: 'Price this run as it verifies: a rate card (computePerMs required > 0, the USD cost of a '
            + 'millisecond of verification compute; humanReviewPerItem optional, per human-reviewed item). The '
            + 'ledger (cost, costPerAssertion, purchased confidence, info nats) rides the boundary marker and is '
            + 'replayable via proof_economics.',
          properties: {
            computePerMs: { type: 'number', description: 'USD per millisecond of verification compute (required, > 0).' },
            humanReviewPerItem: { type: 'number', description: 'USD per human-reviewed item (B/C testimony), optional.' },
          },
          required: ['computePerMs'],
        },
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
          description: 'Reserved, currently not consumed: the api-surface obligation derives its entry points '
            + 'from package.json (or the deployment-level apiEntryPoints config) regardless of this parameter. '
            + 'Omit it; the values are recorded on the contract object only. (Same wording as the DSH tool '
            + 'face — the two faces do not diverge on what a parameter promises.)',
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
          description: 'Optional: the grade you claim for your own work. Recorded verbatim and adjudicated: a '
            + '"proven" the bundle\'s artifacts cannot back is recorded as forged (composing regressed and '
            + 'attributed by taskId); any other grade is recorded as the claim — attributed, not independently '
            + 'verified. Claiming above the evidence is named, never silently rounded down.',
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
          description: 'Optional SELF-REPORT of this workspace\'s own local grade — advisory input, never '
            + 'authoritative: the composed verdict derives from child evidence and bundle verification, not from '
            + 'this claim. One of the five grades — anything else is refused loudly, never silently dropped.',
        },
      },
    },
  },
  {
    name: 'proof_training_export',
    description: TRAINING_EXPORT_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        fidelity: {
          type: 'string',
          enum: ['full', 'private'],
          default: 'private',
          description: 'Privacy tier of the export. DEFAULTS TO `private` when omitted: sample text is reduced '
            + 'to zero output — only structure and labels ride out. `full`: the raw recorded text is included; '
            + 'an unintelligible value is refused loudly, never silently defaulted.',
        },
        provenanceFilter: {
          type: 'string',
          enum: ['agent-only', 'all'],
          description: 'Which sessions the dataset is distilled from: `agent-only` keeps agent-authored work, '
            + '`all` includes every recorded session regardless of provenance.',
        },
        license: {
          type: 'string',
          description: 'Optional license identifier stamped on the manifest (e.g. "CC-BY-4.0") — the deployer\'s '
            + 'terms for the exported dataset, recorded with it.',
        },
        path: {
          type: 'string',
          description: 'Write the samples to this path as JSONL instead of holding them in memory only. Must be '
            + 'WORKSPACE-RELATIVE: absolute paths (including UNC) and any path that escapes the workspace root '
            + 'are refused loudly — this face never hands a foreign caller an arbitrary host write. When given, '
            + 'the engine writes under the workspace and the response carries the absolute `writtenTo` — the '
            + 'samples still never ride the response itself.',
        },
      },
    },
  },
  {
    name: 'proof_economics',
    description: ECONOMICS_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        computePerMs: {
          type: 'number',
          exclusiveMinimum: 0,
          description: 'The rate card\'s compute price per millisecond you are asking under — a number > 0. '
            + 'Required and validated, but priced against nothing here: this tool replays the ledger the last '
            + 'rate-carrying verification recorded on the chain.',
        },
        humanReviewPerItem: {
          type: 'number',
          minimum: 0,
          description: 'Optional price of one human-review item under the same card — echoed with the reply for '
            + 'the record, never used to re-price the past.',
        },
      },
      required: ['computePerMs'],
    },
  },
  {
    name: 'proof_sla_quote',
    description: SLA_QUOTE_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: {
        grade: {
          type: 'string',
          enum: ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'],
          description: 'The verification grade the quote is written against — one of the five-grade scale. The '
            + 'grade decides the door: proven earns an offer, regressed is honestly denied, stale goes to manual '
            + 'underwriting.',
        },
        coverageAmount: {
          type: 'number',
          exclusiveMinimum: 0,
          description: 'What a failure getting through would cost you, in USD — the sum the policy would pay '
            + 'against. A number > 0.',
        },
        confidence: {
          type: 'number',
          minimum: 0,
          maximum: 1,
          description: 'The run\'s confidence you are buying cover for, in [0, 1]. The premium prices exactly '
            + 'the residual: coverageAmount × (1 − confidence).',
        },
        currency: {
          type: 'string',
          enum: ['USD'],
          description: 'The quote\'s currency. Only USD is priced today; any other value is refused loudly, '
            + 'never silently converted.',
        },
        deductible: {
          type: 'number',
          minimum: 0,
          description: 'First-loss amount you carry yourself before the policy pays — shifts cheap claims off '
            + 'the premium. Optional, >= 0.',
        },
        minPremium: {
          type: 'number',
          minimum: 0,
          description: 'The smallest premium worth writing at all — an offer below it is not made. Optional, '
            + '>= 0.',
        },
      },
      required: ['grade', 'coverageAmount'],
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

/**
 * v0.22: fold $HOME-absolute host paths in outbound error text to '~'-relative
 * form. An MCP client is a foreign agent: error messages that quote the
 * server's physical layout (username, trust-root placement) hand it targeting
 * information it has no business having. Best-effort by design — the fold is
 * textual, never a security boundary.
 */
function sanitizeHostText(text: string): string {
  const home = homedir()
  return home.length > 0 ? text.split(home).join('~') : text
}

/**
 * Narrow an untrusted `arguments` object. The DISPATCHER has already refused a
 * non-object `arguments` member as INVALID_PARAMS (v0.22) — this narrows the
 * tool-call params themselves, degrading absent `arguments` to no arguments.
 */
function callArguments(params: unknown): Record<string, unknown> {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return {}
  const args = (params as { arguments?: unknown }).arguments
  if (typeof args !== 'object' || args === null || Array.isArray(args)) return {}
  return args as Record<string, unknown>
}

/**
 * Keep only the string entries of an untrusted array-valued argument — and
 * COUNT what was dropped (v0.22). A silently narrowed `changed` list is
 * under-attribution: the engine verifies fewer checks than the caller thinks
 * it declared, so the drop is surfaced in the response instead of hidden.
 */
interface NarrowedStrings {
  values: string[] | undefined
  droppedNonString: number
}

function stringArray(value: unknown): NarrowedStrings {
  if (!Array.isArray(value)) return { values: undefined, droppedNonString: 0 }
  const values: string[] = []
  let dropped = 0
  for (const entry of value) {
    if (typeof entry === 'string') values.push(entry)
    else dropped += 1
  }
  return { values, droppedNonString: dropped }
}

/** The warning a narrowed array argument carries into the successful result. */
function droppedWarning(tool: string, arg: string, dropped: number): string {
  return `${tool}: dropped ${dropped} non-string ${dropped === 1 ? 'entry' : 'entries'} from ${arg} — `
    + 'array arguments must be arrays of strings; the engine only sees the string entries'
}

/** v0.21: narrow a tool argument into a rate card; an Error means loud usage failure. */
function rateCardOf(value: unknown): { currency: 'USD'; computePerMs: number; humanReviewPerItem?: number } | undefined | Error {
  if (value === undefined) return undefined
  if (typeof value !== 'object' || value === null) return new Error('economics must be an object {computePerMs, humanReviewPerItem?}')
  const raw = value as Record<string, unknown>
  const computePerMs = raw.computePerMs
  if (typeof computePerMs !== 'number' || !Number.isFinite(computePerMs) || computePerMs <= 0) {
    return new Error('economics.computePerMs must be a number > 0 (the USD cost of a millisecond of verification compute)')
  }
  const humanReviewPerItem = raw.humanReviewPerItem
  if (humanReviewPerItem !== undefined
    && (typeof humanReviewPerItem !== 'number' || !Number.isFinite(humanReviewPerItem) || humanReviewPerItem < 0)) {
    return new Error('economics.humanReviewPerItem must be a number >= 0')
  }
  return {
    currency: 'USD',
    computePerMs,
    ...(humanReviewPerItem !== undefined ? { humanReviewPerItem } : {}),
  }
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
  // M50/D3 parity (v0.22): `claim` is the text this verification answers, and
  // the ENGINE records it — VerifyOptions.claim rides the proof/verified
  // boundary marker (bounded to 200 chars), byte-for-byte the same record the
  // DSH tool face forwards. The MCP face must not diverge from what session
  // logs record, so it forwards instead of dropping.
  if (args.claim !== undefined && typeof args.claim !== 'string') {
    return toolError({ error: `proof_verify: claim must be a string (got ${JSON.stringify(args.claim)})` })
  }
  const changed = stringArray(args.changed)
  const rate = rateCardOf(args.economics)
  if (rate instanceof Error) return toolError({ error: `proof_verify: ${rate.message}` })
  const outcome = await deps.engine.verify({
    ...(changed.values !== undefined ? { changed: changed.values } : {}),
    ...(args.all === true ? { all: true } : {}),
    ...(typeof args.claim === 'string' && args.claim.trim() !== '' ? { claim: args.claim } : {}),
    ...(rate !== undefined ? { economics: { rate } } : {}),
    signal: freshSignal(),
  })
  const verified = toVerifyValue(
    outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
    outcome.schedule, outcome.coverage,
  )
  if (changed.droppedNonString > 0) {
    return toolResult({ ...verified, warning: droppedWarning('proof_verify', 'changed', changed.droppedNonString) })
  }
  return toolResult(verified)
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
  // v0.22 (H-29 face half): a perf budget that is not a finite number is a
  // hole, not a budget — `JSON.parse('1e999')` yields Infinity, `typeof` says
  // number, and a within-budget obligation compared against Infinity is
  // satisfied by any benchmark whatsoever. Every numeric argument on this
  // face is finite-checked; budgetMs joins them.
  if (args.budgetMs !== undefined
    && (typeof args.budgetMs !== 'number' || !Number.isFinite(args.budgetMs) || args.budgetMs < 0)) {
    return toolError({
      error: `proof_claim: budgetMs must be a finite number >= 0 (got ${typeof args.budgetMs === 'number' ? String(args.budgetMs) : JSON.stringify(args.budgetMs) ?? 'a non-number value'}) `
        + '— an infinite budget satisfies any benchmark and is therefore not a budget',
    })
  }
  if (args.review !== undefined && typeof args.review !== 'string') {
    return toolError({ error: `proof_claim: review must be a string (got ${JSON.stringify(args.review)})` })
  }
  const changed = stringArray(args.changed)
  const entryPoints = stringArray(args.entryPoints)
  const warnings: string[] = []
  if (changed.droppedNonString > 0) warnings.push(droppedWarning('proof_claim', 'changed', changed.droppedNonString))
  if (entryPoints.droppedNonString > 0) warnings.push(droppedWarning('proof_claim', 'entryPoints', entryPoints.droppedNonString))
  if (isClaimKind(args.kind)) {
    const contract: ClaimContract = {
      kind: args.kind,
      claim,
      ...(typeof args.budgetMs === 'number' ? { budgetMs: args.budgetMs } : {}),
      ...(typeof args.review === 'string' ? { review: args.review } : {}),
      ...(entryPoints.values !== undefined ? { entryPoints: entryPoints.values } : {}),
    }
    const outcome = await deps.engine.verifyContract({
      contract,
      ...(changed.values !== undefined ? { changed: changed.values } : {}),
      signal: freshSignal(),
    })
    const verified = toVerifyValue(
      outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
      outcome.schedule, outcome.coverage,
    )
    const claimed = toClaimValue(claim, outcome.report, verified, outcome.contract)
    if (warnings.length > 0) return toolResult({ ...claimed, warnings })
    return toolResult(claimed)
  }
  const outcome = await deps.engine.verify({
    ...(changed.values !== undefined ? { changed: changed.values } : {}),
    signal: freshSignal(),
  })
  const verified = toVerifyValue(
    outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
    outcome.schedule, outcome.coverage,
  )
  const claimed = toClaimValue(claim, outcome.report, verified)
  if (warnings.length > 0) return toolResult({ ...claimed, warnings })
  return toolResult(claimed)
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
      error: 'proof_bundle: no evidence log in this workspace\'s store — establish a baseline with '
        + 'proof_baseline first (storeDir-relative: evidence.jsonl)',
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
  // v0.22: the limit prices the WHOLE wire payload, not one of its two copies.
  // An MCP result carries the value twice — the pretty-printed text content
  // and structuredContent — so a bundle near 256KB actually rode ~512KB+ and
  // the advertised ceiling was fiction. Count both copies against the limit.
  if (size * 2 < BUNDLE_INLINE_LIMIT_BYTES) {
    return toolResult({ bundle })
  }
  return toolResult({
    bundle: {
      manifest: bundle.manifest,
      files: bundleFileNames(bundle.files),
      note: `bundle serialized to ${size} bytes (>= half the ${BUNDLE_INLINE_LIMIT_BYTES}-byte response limit, `
        + 'which counts both wire copies); only the manifest and the file-name list ride this response '
        + '— re-export on the host for full contents',
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
 *
 * v0.22 candidate chain, matching the engine's and the ptl CLI's resolution:
 * `<trustRoot>/ptl-operator-key` first (outside the published log dir — a key
 * beside the log it notarises can be rewritten together with that log), then
 * `<ptlDir>/ptl-operator-key`, then the legacy `<ptlDir>/operator-key` so an
 * existing deployment's heads keep verifying after an upgrade.
 */
async function operatorSignerFor(
  fs: FsPort,
  ptlDir: string,
  trustRoot: string | undefined,
): Promise<SignerPort | undefined> {
  const candidates = [
    ...(trustRoot !== undefined && trustRoot.length > 0 ? [`${trustRoot.replace(/[\/]+$/, '')}/ptl-operator-key`] : []),
    `${ptlDir.replace(/[\/]+$/, '')}/ptl-operator-key`,
    `${ptlDir.replace(/[\/]+$/, '')}/operator-key`,
  ]
  for (const dir of candidates) {
    try {
      const names = await fs.readDir(dir)
      if (names !== undefined && names.some(name => name.endsWith('proof-signing-key.pem'))) {
        if (dir.endsWith('/operator-key')) {
          // N-8: the legacy in-log-dir spelling — kept so an upgraded
          // deployment's heads keep verifying, said out loud because a key
          // beside the log it notarises is the self-reference H-07 closed
          // for new deployments.
          process.stderr.write('[agent-proof-protocol] note: operator key loaded from the legacy log-dir '
            + `location ${dir} — move it under the trust root so it does not live inside the directory it notarises\n`)
        }
        return await NodeEd25519Signer.load(dir)
      }
    } catch {
      // A key directory we cannot even probe is a missing capability, not an
      // accusation — reported as not-checked by the caller.
    }
  }
  return undefined
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
      error: 'proof_log_verify: the configured transparency log (ptlDir) holds no entries — publish with '
        + 'proof_publish first',
    })
  }
  const problems: string[] = []
  if (badLines > 0) {
    problems.push(`${badLines} malformed entry line(s) skipped while loading the transparency log — the readable prefix was audited, but the log is not sound`)
  }
  const treeSize = log.size
  // The root is recomputed from the published leaves before anything else is
  // said: every later check compares against THIS number, never against a
  // root the head file or the caller handed over.
  const root = log.merkleRoot()

  // -- the signed tree head: present, honest about the tree, genuinely signed --
  let treeHead: Record<string, unknown> | undefined
  if (head === undefined) {
    problems.push('no signed tree head in the transparency log — the published tree carries no operator commitment')
  } else {
    const sizeMatches = head.treeSize === treeSize
    const rootMatches = head.root === root
    if (!sizeMatches) {
      problems.push(`tree head speaks treeSize ${head.treeSize} but the log holds ${treeSize} entries — entries were appended after the last head, or the head was rewritten`)
    }
    if (!rootMatches) {
      problems.push(`tree head root ${head.root} does not match the root recomputed from the log (${root})`)
    }
    const operator = await operatorSignerFor(fs, deps.ptlDir, deps.trustRoot)
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
 * parse each line, keep the engine's own `delegation/created` and
 * `delegation/verdict` labels (matched EXACTLY — the engine mints exactly
 * those two, and a loose `includes()` would fold any future label into a
 * submission signal). Defensive by construction against bad shapes: a field
 * with the wrong shape is skipped, not guessed at. Absence is distinguished
 * from content (v0.22): a missing log reports `logPresent: false` so the
 * caller sees "nothing recorded yet", never a silent fake-empty chain.
 */
async function taskOverview(deps: McpEngineDeps): Promise<{ tasks: TaskOverviewEntry[]; logPresent: boolean }> {
  const tasks = new Map<string, TaskOverviewEntry>()
  const raw = await deps.engine.fsView.readFile(deps.evidenceLogPath)
  if (raw === undefined) return { tasks: [], logPresent: false }
  const lines = raw.split('\n')
  for (const line of lines) {
    if (line.trim().length === 0) continue
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
    if (label !== 'delegation/created' && label !== 'delegation/verdict') continue
    const taskId = record.taskId
    if (typeof taskId !== 'string') continue
    if (label === 'delegation/created') {
      const claim = record.claim
      if (typeof claim !== 'string') continue
      const parentTaskId = typeof record.parentTaskId === 'string' ? record.parentTaskId : null
      tasks.set(taskId, { taskId, parentTaskId, claim: summarizeClaim(claim), submitted: false })
    } else if (tasks.has(taskId)) {
      // A landed submission (`delegation/verdict` — the engine's exact label
      // for "a submission was adjudicated").
      const entry = tasks.get(taskId)!
      tasks.set(taskId, { ...entry, submitted: true })
    }
  }
  return { tasks: [...tasks.values()], logPresent: true }
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
    const overview = await taskOverview(deps)
    return toolResult({
      tasks: overview.tasks,
      ...(overview.tasks.length === 0
        ? {
            note: overview.logPresent
              ? 'no delegations recorded on this chain yet — create one with proof_delegate'
              : 'no evidence log exists yet — nothing is recorded on this chain (proof_baseline or proof_delegate creates it)',
          }
        : {}),
    })
  }
  const verdict = await verbs.taskVerdict({
    taskId,
    ...(isGradeValue(args.ownGrade) ? { ownGrade: args.ownGrade } : {}),
  })
  return toolResult({ taskId, composed: verdict.composed, nodes: verdict.nodes, cycles: verdict.cycles })
}

// ---------------------------------------------------------------------------
// v0.20: the training-export tool (APP/1.3's 10 → 11 expansion)
//
// The verb itself lives in the engine (exportTrainingData — distilling the
// chain's recorded agent behavior into a labeled dataset). This face only
// adjudicates untrusted ARGUMENTS (the fidelity/provenance enums are refused
// loudly, never silently defaulted) and projects the outcome onto the wire:
// the manifest, the anchor and sampleCount — the SAMPLES themselves never
// ride an MCP response (a dataset can be huge; `path` writes them to disk as
// JSONL and the response then carries `writtenTo` instead).
// ---------------------------------------------------------------------------

/**
 * The engine-side training-export contract, as frozen with the engine
 * workstream (F2). Declared HERE (not imported) for the same reason as
 * `DelegationVerbs` above: the engine grows into it in parallel, and
 * `trainingExportVerbs` narrows the live engine against it at runtime, so
 * this server degrades to a clean capability error — never a crash — on a
 * build whose engine has not landed the export yet.
 */
interface TrainingExportVerbs {
  exportTrainingData(input: {
    fidelity?: 'full' | 'private'
    provenanceFilter?: 'agent-only' | 'all'
    changedPaths?: string[]
    license?: string
    path?: string
  }): Promise<{
    manifest: {
      schema: 'dsh-training/1'
      fidelity: 'full' | 'private'
      workspaceKey: string
      generatedAt: string
      counts: Record<string, number>
      rewardTable: unknown
      license?: string
      provenanceFilter: 'agent-only' | 'all'
      root: string
    }
    samples: unknown[]
    anchor: { count: number; head: string; keyId?: string }
  }>
}

/**
 * The live engine's training-export verb, or undefined when this build's
 * engine does not implement the export yet. Same per-call existence check as
 * the delegation seam — the one place the engine's newer surface is reached
 * through a cast.
 */
function trainingExportVerbs(engine: ProofEngine): TrainingExportVerbs | undefined {
  const candidate = engine as unknown as Partial<Record<keyof TrainingExportVerbs, unknown>>
  return typeof candidate.exportTrainingData === 'function'
    ? (candidate as TrainingExportVerbs)
    : undefined
}

function trainingExportUnavailable(): McpToolResult {
  return toolError({
    error: 'proof_training_export: this engine build does not implement the training-export verb '
      + '(exportTrainingData) — the dataset cannot be distilled on this build',
  })
}

/** The two privacy tiers `proof_training_export` accepts — F2's fidelity scale. */
const FIDELITY_TIERS: readonly string[] = ['full', 'private']

/** The two provenance scopes `proof_training_export` accepts. */
const PROVENANCE_FILTERS: readonly string[] = ['agent-only', 'all']

function isFidelityTier(value: unknown): value is 'full' | 'private' {
  return typeof value === 'string' && FIDELITY_TIERS.includes(value)
}

function isProvenanceFilter(value: unknown): value is 'agent-only' | 'all' {
  return typeof value === 'string' && PROVENANCE_FILTERS.includes(value)
}

/**
 * H-16 (v0.22, face-layer confinement — the engine's exportRelPath gate is
 * the second layer, and the two are aligned): `path` hands the engine a write
 * destination, and the engine's write goes through mkdirp + writeFile with
 * the fs port's full authority. An MCP caller is a foreign agent, so the
 * destination is confined to THIS workspace: absolute paths (drive-rooted,
 * slash-rooted, UNC — both `\\srv\share` and `//srv/share`) and any path
 * whose `.`/`..` segments normalize outside the root are refused loudly.
 * The returned `rel` is what the engine receives (its own contract is
 * workspace-relative, and IT anchors the write at the workspace root);
 * `abs` is the workspace-absolute destination reported back as `writtenTo`.
 */
function confinedExportPath(raw: string, root: string): { rel: string; abs: string } | Error {
  if (/^\\\\/.test(raw) || /^\/\//.test(raw)) {
    return new Error('proof_training_export: path refuses UNC paths — the export valve writes inside this workspace only (name a workspace-relative path)')
  }
  if (/^([A-Za-z]:[\\/]|[\\/])/.test(raw)) {
    return new Error('proof_training_export: path must be workspace-RELATIVE — absolute paths are refused on this face (the deployer exports to host paths through the engine API on the host)')
  }
  const segments: string[] = []
  for (const segment of raw.replace(/\\/g, '/').split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (segments.length === 0) {
        return new Error('proof_training_export: path escapes the workspace root after normalization — the export valve writes inside this workspace only')
      }
      segments.pop()
      continue
    }
    segments.push(segment)
  }
  if (segments.length === 0) {
    return new Error('proof_training_export: path normalizes to the workspace root itself — name a file inside the workspace')
  }
  const rel = segments.join('/')
  const abs = `${root.replace(/\\/g, '/').replace(/\/+$/, '')}/${rel}`
  return { rel, abs }
}

async function callTrainingExportTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  // Same loud-argument discipline as proof_claim's kind guard: an optional
  // enum that arrived with a value the scale does not name is an ERROR — a
  // foreign agent asking for a privacy tier that does not exist must be told,
  // never silently handed the default (which is `private`, the safe side).
  if (args.fidelity !== undefined && !isFidelityTier(args.fidelity)) {
    return toolError({
      error: `proof_training_export: fidelity must be one of ${FIDELITY_TIERS.join(' | ')} `
        + `(got ${typeof args.fidelity === 'string' ? JSON.stringify(args.fidelity) : 'a non-string value'}); `
        + 'omitted fidelity exports the private tier — zero output text — by default',
    })
  }
  if (args.provenanceFilter !== undefined && !isProvenanceFilter(args.provenanceFilter)) {
    return toolError({
      error: `proof_training_export: provenanceFilter must be one of ${PROVENANCE_FILTERS.join(' | ')} `
        + `(got ${typeof args.provenanceFilter === 'string' ? JSON.stringify(args.provenanceFilter) : 'a non-string value'})`,
    })
  }
  if (args.license !== undefined && typeof args.license !== 'string') {
    return toolError({ error: `proof_training_export: license must be a string (got ${JSON.stringify(args.license)})` })
  }
  if (args.path !== undefined && typeof args.path !== 'string') {
    return toolError({ error: `proof_training_export: path must be a string (got ${JSON.stringify(args.path)})` })
  }
  // H-16: the face gate. The path is confined to the workspace BEFORE the
  // engine sees it — the engine's own exportRelPath gate (workspace-relative
  // only, root-anchored write) is the second layer, not the only one. The
  // engine receives the normalized RELATIVE path (its contract); `writtenTo`
  // reports the workspace-absolute destination the engine wrote.
  let exportPath: { rel: string; abs: string } | undefined
  if (typeof args.path === 'string') {
    const confined = confinedExportPath(args.path, deps.engine.root)
    if (confined instanceof Error) return toolError({ error: confined.message })
    exportPath = confined
  }
  const verbs = trainingExportVerbs(deps.engine)
  if (verbs === undefined) return trainingExportUnavailable()
  const fidelity = args.fidelity as 'full' | 'private' | undefined
  const provenanceFilter = args.provenanceFilter as 'agent-only' | 'all' | undefined
  // Semantic preconditions (an empty chain, an unwritable path, …) are the
  // ENGINE's to enforce; a clean throw rides the dispatcher's isError path.
  const outcome = await verbs.exportTrainingData({
    ...(fidelity !== undefined ? { fidelity } : {}),
    ...(provenanceFilter !== undefined ? { provenanceFilter } : {}),
    ...(typeof args.license === 'string' ? { license: args.license } : {}),
    ...(exportPath !== undefined ? { path: exportPath.rel } : {}),
  })
  // The samples NEVER ride the response — manifest, anchor and count only.
  // A caller that wants the dataset itself passes `path` (the engine wrote
  // the JSONL; writtenTo says where, workspace-absolute) or reads the engine
  // API directly.
  return toolResult({
    manifest: outcome.manifest,
    anchor: outcome.anchor,
    sampleCount: outcome.samples.length,
    ...(exportPath !== undefined ? { writtenTo: exportPath.abs } : {}),
  })
}

// ---------------------------------------------------------------------------
// v0.21 (APP/1.4): the verification-economics tools — the 11 → 13 expansion.
//
// Two halves of one question ("what is proof worth?"), split by where the
// truth lives: `proof_economics` READS (the cost ledger is a chain fact —
// this face replays the most recent rate-carrying proof/claim marker,
// exactly like the task overview reads delegation markers back off the log),
// and `proof_sla_quote` ASKS THE ENGINE (the underwriting math — premium,
// refusal doors, exclusions — is the engine's `slaQuote` verb, frozen with
// the engine workstream; this face adjudicates untrusted ARGUMENTS and passes
// the quote through verbatim, never re-deriving a premium).
// ---------------------------------------------------------------------------

/**
 * The engine-side SLA-quote contract, as frozen with the engine workstream
 * (E2). Declared HERE (not imported) for the same reason as
 * `DelegationVerbs`/`TrainingExportVerbs` above: the engine grows into it in
 * parallel, and `slaQuoteVerbs` narrows the live engine against it at
 * runtime, so this server degrades to a clean capability error — never a
 * crash — on a build whose engine has not landed the quote yet. The return is
 * intentionally opaque: the decision shape (offer / denied /
 * manual-underwriting, exclusions, quoteId, the chain marker) is the engine's
 * to define and this face's to carry, verbatim.
 */
interface SlaQuoteVerbs {
  slaQuote(input: {
    grade: string
    coverageAmount: number
    confidence?: number
    /** The rate card the quote is written under — currency plus its price legs. */
    rate: { currency: string; computePerMs: number; humanReviewPerItem?: number }
    deductible?: number
    minPremium?: number
  }): Promise<Record<string, unknown>>
}

/**
 * The live engine's SLA-quote verb, or undefined when this build's engine
 * does not implement the quote yet. Same per-call existence check as the
 * delegation and training-export seams.
 */
function slaQuoteVerbs(engine: ProofEngine): SlaQuoteVerbs | undefined {
  const candidate = engine as unknown as Partial<Record<keyof SlaQuoteVerbs, unknown>>
  return typeof candidate.slaQuote === 'function'
    ? (candidate as SlaQuoteVerbs)
    : undefined
}

function slaQuoteUnavailable(): McpToolResult {
  return toolError({
    error: 'proof_sla_quote: this engine build does not implement the SLA-quote verb (slaQuote) '
      + '— no quote can be written on this build',
  })
}

/**
 * A boundary marker that carries an economics ledger: the label it rode on,
 * when the chain recorded it, and the ledger payload verbatim. `label`/`at`
 * are read but never trusted for anything beyond naming the reply — the
 * `economics` object itself is the artifact being replayed.
 */
interface EconomicsMarker {
  label: string
  at: string | null
  economics: Record<string, unknown>
}

/**
 * The most recent proof/claim boundary marker on the evidence chain whose
 * payload carries an `economics` object — the ledger a rate-carrying
 * verification recorded. Same defensive read as `taskOverview`: the raw log
 * is read through the engine's own fs port, a missing log is distinguished
 * from a scanned-but-empty one (v0.22 — a read failure must not masquerade
 * as "this chain never priced anything"), and any line with the wrong shape
 * is skipped, not guessed at. Newest wins: the chain is an append-only log,
 * so the LAST matching marker in file order is the last one minted.
 */
async function latestEconomicsMarker(deps: McpEngineDeps): Promise<{ marker?: EconomicsMarker; logPresent: boolean }> {
  const raw = await deps.engine.fsView.readFile(deps.evidenceLogPath)
  if (raw === undefined) return { logPresent: false }
  let found: EconomicsMarker | undefined
  for (const line of raw.split('\n')) {
    if (line.trim().length === 0) continue
    let envelope: { kind?: unknown; at?: unknown; payload?: unknown }
    try {
      envelope = JSON.parse(line) as { kind?: unknown; at?: unknown; payload?: unknown }
    } catch {
      continue
    }
    if (envelope?.kind !== 'marker') continue
    const payload = envelope.payload
    if (typeof payload !== 'object' || payload === null) continue
    const record = payload as Record<string, unknown>
    const label = typeof record.label === 'string' ? record.label : ''
    // Only the verification boundaries can carry a ledger — a delegation or
    // synthetic marker with a stray `economics` field is not a run's account.
    if (!label.startsWith('proof/') && !label.startsWith('claim/')) continue
    const economics = record.economics
    if (typeof economics !== 'object' || economics === null || Array.isArray(economics)) continue
    found = {
      label,
      at: typeof envelope.at === 'string' ? envelope.at : null,
      economics: economics as Record<string, unknown>,
    }
  }
  return { marker: found, logPresent: true }
}

async function callEconomicsTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  // The rate card is validated loudly even though this query prices nothing:
  // a caller handing a malformed card must be told NOW, not on the next
  // rate-carrying verification — same loud-argument discipline as every enum
  // guard in this face.
  const computePerMs = args.computePerMs
  if (typeof computePerMs !== 'number' || !Number.isFinite(computePerMs) || computePerMs <= 0) {
    return toolError({
      error: 'proof_economics: computePerMs is required — the rate card\'s compute price per millisecond, '
        + `a number > 0 (got ${typeof computePerMs === 'number' ? String(computePerMs) : JSON.stringify(computePerMs) ?? 'absent'})`,
    })
  }
  const humanReviewPerItem = args.humanReviewPerItem
  if (humanReviewPerItem !== undefined
    && (typeof humanReviewPerItem !== 'number' || !Number.isFinite(humanReviewPerItem) || humanReviewPerItem < 0)) {
    return toolError({
      error: `proof_economics: humanReviewPerItem must be a number >= 0 (got ${JSON.stringify(humanReviewPerItem)})`,
    })
  }
  // The read itself: the chain's own bytes, never a recomputation. No match =
  // the honest absence, with the exact remedy pinned (and a missing log named
  // as a missing log, never as "this chain never priced anything").
  const { marker: found, logPresent } = await latestEconomicsMarker(deps)
  if (found === undefined) {
    return toolError({
      error: !logPresent
        ? 'proof_economics: no evidence log exists yet — nothing is recorded on this chain (run proof_baseline '
        + 'and a rate-carrying proof_verify first)'
        : 'proof_economics: no economics on the last run — no proof/claim marker on this chain carries a '
        + 'ledger yet. Mint one: pass economics: {computePerMs, humanReviewPerItem?} to proof_verify on this '
        + 'MCP face (it accepts the rate card directly) or to proof_claim, then query this tool to replay '
        + 'the ledger',
    })
  }
  // v0.22 (M-51): replaying a marker is quoting LOG BYTES, and a writer who
  // can touch evidence.jsonl can forge one — the hash chain detects rewrites
  // after the fact, it does not prevent the write. So the replay is guarded
  // by a real chain audit whose verdict rides the response; a failing audit
  // names the tools that adjudicate (proof_status for the workspace chain,
  // proof_log_verify for the published mirror) instead of vouching for bytes
  // it did not check.
  const audit = await deps.engine.audit()
  const chainOk = audit.ok
  return toolResult({
    label: found.label,
    ...(found.at !== null ? { at: found.at } : {}),
    economics: found.economics,
    chainAudit: { checked: true, ok: chainOk },
    rate: {
      currency: 'USD',
      computePerMs,
      ...(typeof humanReviewPerItem === 'number' ? { humanReviewPerItem } : {}),
    },
    note: 'replayed verbatim from the evidence log\'s boundary marker — never recomputed, never taken from the '
      + `caller's word. The hash chain does not make these bytes facts by itself: a writer who can touch the log `
      + `can forge a marker, so this call ran a chain audit first (ok: ${chainOk}). On failure treat the ledger as `
      + 'suspect and adjudicate with proof_status (workspace chain) or proof_log_verify (published mirror). The '
      + 'rate above is the card you asked under, priced against nothing',
    ...(chainOk ? {} : { warning: `chain audit FAILED (ok: false) — the replayed ledger may be forged; run proof_status / proof_log_verify before trusting it` }),
  })
}

async function callSlaQuoteTool(deps: McpEngineDeps, args: Record<string, unknown>): Promise<McpToolResult> {
  // Argument adjudication first, engine second: every usage error is a tool
  // error naming the offending argument, mirroring the enum guards above.
  if (!isGradeValue(args.grade)) {
    return toolError({
      error: `proof_sla_quote: grade must be one of ${GRADES.join(' | ')} `
        + `(got ${typeof args.grade === 'string' ? JSON.stringify(args.grade) : 'a non-string value'}); `
        + 'the grade is what the quote underwrites — an unintelligible grade is refused, never guessed at',
    })
  }
  const grade = args.grade as string
  const coverageAmount = args.coverageAmount
  if (typeof coverageAmount !== 'number' || !Number.isFinite(coverageAmount) || coverageAmount <= 0) {
    return toolError({
      error: `proof_sla_quote: coverageAmount is required — what a failure getting through would cost you, a number > 0 (got ${JSON.stringify(coverageAmount) ?? 'absent'})`,
    })
  }
  const confidence = args.confidence
  if (confidence !== undefined
    && (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1)) {
    return toolError({
      error: `proof_sla_quote: confidence must be a number in [0, 1] (got ${JSON.stringify(confidence)})`,
    })
  }
  // Only USD is priced today: an explicit currency is checked against the
  // singleton, never silently converted.
  const currency = args.currency
  if (currency !== undefined && currency !== 'USD') {
    return toolError({
      error: `proof_sla_quote: currency must be 'USD' (got ${JSON.stringify(currency)}) — the only currency the `
        + 'quote prices today; a foreign currency is refused loudly, never converted at a rate nobody agreed to',
    })
  }
  const deductible = args.deductible
  if (deductible !== undefined
    && (typeof deductible !== 'number' || !Number.isFinite(deductible) || deductible < 0)) {
    return toolError({
      error: `proof_sla_quote: deductible must be a number >= 0 (got ${JSON.stringify(deductible)})`,
    })
  }
  const minPremium = args.minPremium
  if (minPremium !== undefined
    && (typeof minPremium !== 'number' || !Number.isFinite(minPremium) || minPremium < 0)) {
    return toolError({
      error: `proof_sla_quote: minPremium must be a number >= 0 (got ${JSON.stringify(minPremium)})`,
    })
  }
  const verbs = slaQuoteVerbs(deps.engine)
  if (verbs === undefined) return slaQuoteUnavailable()
  // The bridge rate card: this MCP face deliberately carries NO compute price
  // (the premium is pure risk pricing — coverageAmount × (1 − confidence) —
  // so a compute leg would be a placeholder used by nothing). The card is
  // still owed to the engine contract, so it gets the one honest value for
  // "no compute component priced here": zero. Callers who want compute-priced
  // economics pass a real rate through the verify face and read it back with
  // proof_economics.
  const quote = await verbs.slaQuote({
    grade,
    coverageAmount,
    ...(typeof confidence === 'number' ? { confidence } : {}),
    rate: { currency: 'USD', computePerMs: 0 },
    ...(typeof deductible === 'number' ? { deductible } : {}),
    ...(typeof minPremium === 'number' ? { minPremium } : {}),
  })
  // Verbatim pass-through: the decision shape (offer/denied/manual-
  // underwriting), exclusions, quoteId and the marker flag are the engine's
  // value object — this face re-derives nothing.
  return toolResult(quote)
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
      case 'proof_training_export': return await callTrainingExportTool(deps, args)
      case 'proof_economics': return await callEconomicsTool(deps, args)
      case 'proof_sla_quote': return await callSlaQuoteTool(deps, args)
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
    // internal tool errors are NOT protocol-level JSON-RPC errors). The name
    // already carries its proof_ prefix (v0.22: no doubled "proof_proof_"),
    // and host-absolute paths fold to '~' before they reach a foreign agent.
    const message = error instanceof Error ? error.message : String(error)
    return toolError({ error: `${String(name)} failed: ${sanitizeHostText(message)}` })
  }
}

// ---------------------------------------------------------------------------
// The dispatcher — pure per message: one parsed message in, {response} or
// nothing out. Never touches stdio; notifications (no id) never produce a
// response. Two pieces of protocol edge (v0.22):
//   * a tools/* request BEFORE `initialize` is answered with a JSON-RPC
//     INVALID_REQUEST naming the missing handshake — not silently served
//     (an un-handshaked client is exactly the foreign caller most likely to
//     be speaking the wrong dialect);
//   * a JSON-RPC 2.0 batch (an array of messages) is processed element by
//     element and answered with an array of the responses, in order; a batch
//     of only notifications produces no output at all.
// ---------------------------------------------------------------------------

export function createMcpHandler(
  deps: McpEngineDeps,
): (message: unknown) => Promise<{ response?: unknown }> {
  async function handleOne(message: unknown): Promise<{ response?: unknown }> {
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
    if (params !== undefined && (typeof params !== 'object' || params === null || Array.isArray(params))) {
      return { response: rpcError(id, INVALID_PARAMS, `invalid params: params of ${method} must be an object`) }
    }
    // The handshake gate: initialize, ping and notifications answer before
    // it; every other method — the whole tools/* surface — requires a
    // completed initialize first.
    if (method !== 'initialize' && method !== 'ping' && !deps.allowUninitializedTools && !initialized) {
      return {
        response: rpcError(
          id,
          INVALID_REQUEST,
          `server not initialized — send an initialize request before ${method}`,
        ),
      }
    }
    switch (method) {
      case 'initialize': {
        initialized = true
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
      case 'tools/call': {
        // A tool call's params carry `arguments`; a malformed one is a
        // malformed REQUEST (protocol-level), not a tool failure — the tool
        // never got arguments it could adjudicate.
        if (params !== undefined) {
          const callArgs = (params as { arguments?: unknown }).arguments
          if (callArgs !== undefined
            && (typeof callArgs !== 'object' || callArgs === null || Array.isArray(callArgs))) {
            return {
              response: rpcError(id, INVALID_PARAMS, 'invalid params: tools/call arguments must be an object'),
            }
          }
        }
        return { response: rpcResult(id, await callTool(deps, params)) }
      }
      default:
        return { response: rpcError(id, METHOD_NOT_FOUND, `method not found: ${method}`) }
    }
  }

  let initialized = false

  return async function handleMessage(message: unknown): Promise<{ response?: unknown }> {
    if (Array.isArray(message)) {
      if (message.length === 0) {
        return { response: rpcError(null, INVALID_REQUEST, 'invalid request: a batch must carry at least one message') }
      }
      const responses: unknown[] = []
      for (const entry of message) {
        const handled = await handleOne(entry)
        if (handled.response !== undefined) responses.push(handled.response)
      }
      // A batch of nothing but notifications gets no output at all.
      return responses.length > 0 ? { response: responses } : {}
    }
    return handleOne(message)
  }
}

// ---------------------------------------------------------------------------
// The stdio loop — newline-delimited JSON both ways.
// ---------------------------------------------------------------------------

/**
 * One buffered line of input, or the marker of a line that blew the cap.
 * An oversized line is reported, never delivered — the stdio contract is one
 * JSON-RPC message per line, and a client violating it by orders of magnitude
 * must not size this server's memory.
 */
type CappedLine = { text: string } | { oversized: true }

/**
 * Read newline-delimited text from a stream with a hard per-line byte cap.
 * Bytes of an over-cap line are DISCARDED as they arrive (only the first
 * cap-crossing chunk is inspected), so neither a giant single line nor a
 * giant unterminated tail can grow the buffer without bound.
 */
function readCappedLines(input: NodeJS.ReadableStream, capBytes: number): AsyncIterable<CappedLine> {
  type Pending = { item: CappedLine | undefined; error?: Error }
  const queue: Pending[] = []
  let wake: ((entry: Pending) => void) | undefined
  let finished = false
  let buffer = ''
  let discarding = false

  const push = (entry: Pending): void => {
    if (wake !== undefined) {
      const waiter = wake
      wake = undefined
      waiter(entry)
    } else {
      queue.push(entry)
    }
  }
  const onChunk = (chunk: unknown): void => {
    const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('utf8')
    if (discarding) {
      const nl = text.indexOf('\n')
      if (nl < 0) return // still inside the oversized line — keep discarding
      discarding = false
      push({ item: { oversized: true } }) // the discarded line is complete
      buffer = text.slice(nl + 1)
    } else {
      buffer += text
    }
    let nl = buffer.indexOf('\n')
    while (nl >= 0) {
      const line = buffer.slice(0, nl)
      buffer = buffer.slice(nl + 1)
      push({ item: Buffer.byteLength(line, 'utf8') > capBytes ? { oversized: true } : { text: line } })
      nl = buffer.indexOf('\n')
    }
    // An unterminated tail already past the cap: start discarding now — the
    // single {oversized} marker is pushed when its newline (or the stream's
    // end) eventually arrives.
    if (!discarding && buffer.length > 0 && Buffer.byteLength(buffer, 'utf8') > capBytes) {
      discarding = true
      buffer = ''
    }
  }
  const onEnd = (): void => {
    if (finished) return
    finished = true
    if (discarding) push({ item: { oversized: true } })
    else if (buffer.length > 0) push({ item: { text: buffer } })
    push({ item: undefined })
  }
  const onError = (error: Error): void => {
    if (finished) return
    finished = true
    push({ item: undefined, error })
  }
  input.on('data', onChunk)
  input.on('end', onEnd)
  input.on('close', onEnd)
  input.on('error', onError)

  return {
    [Symbol.asyncIterator](): AsyncIterator<CappedLine> {
      return {
        async next(): Promise<IteratorResult<CappedLine>> {
          const entry = queue.length > 0
            ? queue.shift()!
            : await new Promise<Pending>((resolve) => { wake = resolve })
          if (entry.error !== undefined) throw entry.error
          if (entry.item === undefined) return { done: true, value: undefined }
          return { done: false, value: entry.item }
        },
      }
    },
  }
}

/**
 * Run the MCP server over newline-delimited JSON-RPC 2.0: one message per
 * line on stdin, one response per line on stdout. Resolves when the input
 * stream ends. Protocol-level failures (an unparseable line, a line over the
 * 4 MiB cap) are emitted as JSON-RPC error responses with id null, because
 * the offending line carried no readable id to echo. Writes respect
 * backpressure, and a dead output stream (EPIPE) ends the loop instead of
 * crashing the process.
 */
export async function runMcpServer(options: McpServerOptions): Promise<void> {
  const input = options.input ?? process.stdin
  const output = options.output ?? process.stdout
  const handleMessage = createMcpHandler(options)
  let outputBroken = false
  output.on('error', () => { outputBroken = true })
  const writeResponse = async (response: unknown): Promise<void> => {
    if (outputBroken) return
    const flushed = output.write(`${JSON.stringify(response)}\n`)
    if (!flushed) await new Promise<void>((resolve) => { output.once('drain', () => resolve()) })
  }
  for await (const line of readCappedLines(input, MAX_LINE_BYTES)) {
    let response: unknown
    if ('oversized' in line) {
      response = rpcError(null, PARSE_ERROR, `parse error: line exceeds the ${MAX_LINE_BYTES}-byte transport limit — refused without buffering or parsing`)
    } else {
      const text = line.text.trim()
      if (text.length === 0) continue
      let parsed: unknown
      let parseFailed = false
      try {
        parsed = JSON.parse(text)
      } catch {
        parseFailed = true
      }
      response = parseFailed
        ? rpcError(null, PARSE_ERROR, `parse error: line is not valid JSON: ${text.slice(0, 80)}`)
        : (await handleMessage(parsed)).response
    }
    if (response !== undefined) await writeResponse(response)
    if (outputBroken) break
  }
}
