/**
 * The nine model-facing tools.
 *
 * Contract discipline (DSH's hard rules, applied):
 *  - `execute` returns exactly one canonical JSON value; all human prose lives
 *    in `output.render`.
 *  - `presentCall` / `presentResult` / `presentationMeta` are pure projections
 *    of `args` and the canonical value, so a session-log replay reproduces the
 *    identical card. No I/O, no clock, no session reads.
 *
 * @module dsh-proof/dsh/tools
 */

import type {
  ContentBlock, JsonValue, ParameterSchemaSpec, ToolDefinition, ToolResult,
  ToolCallView, ToolResultView, ToolRunContext,
} from '../vendor/dsh-tools.ts'
import type { ProofEngine } from '../engine.ts'
import type { AuditReport, CheckStatus, ProofGrade, ProofReport } from '../core/evidence.ts'
import type { ConfidenceBasis, GradedProofReport } from '../core/report.ts'
import type { ClaimContract, ClaimKind, ObligationResult } from '../core/contract.ts'
import { proofNarrative } from '../core/regression.ts'
import { firstInformativeLine } from '../core/excerpt.ts'
import {
  DEFAULT_TRUST_WEIGHTS, RUBRIC_V1, attestationFactor, claimIdOf, juryPrompt,
  type HumanAttestation, type JuryAttestation,
} from '../core/attest.ts'
import { SYNTHETIC_DIR_DEFAULT } from '../core/synthetic.ts'
import { sha256 } from '../core/hash.ts'

// ---------------------------------------------------------------------------
// Canonical value shapes (the programmatic API Code Mode sees)
// ---------------------------------------------------------------------------

export interface StatusValue {
  hasBaseline: boolean
  baselineCreatedAt: string | null
  baselineRoot: string | null
  discovered: number
  checks: { id: string; label: string; kind: string; lastStatus: string | null; recordedAt: string | null }[]
  evidenceRecords: number
  evidenceLogIntact: boolean
  /** Trust telemetry from the hash chain + signed checkpoints (v0.2). */
  chainMode: 'signed' | 'unsigned' | 'legacy'
  checkpoints: number
  chainIntact: boolean
  tailRecords: number
  rewindDetected: boolean
  baselineTampered: boolean
  /**
   * Present only when > 0 (v0.7): checkpoints carrying a signature this host
   * cannot adjudicate — key lost or foreign machine. A missing capability is
   * not an accusation, so it never flips `chainIntact`; it only rides along
   * when non-zero to keep the normal-path canonical value byte-stable.
   */
  unverifiableCheckpoints?: number
  /** Present only when true (v0.7): the anchor failed its own signature check. */
  anchorForged?: boolean
  dirtyFiles: number
  summary: string
}

export interface BaselineValue {
  ok: boolean
  baselineId: string | null
  root: string | null
  ran: number
  passing: number
  failing: number
  skipped: number
  durationMs: number
  failingLabels: string[]
  summary: string
  /**
   * Present only when the run aborted (v0.7, engine E1): the engine refused to
   * anchor a batch that did not observe every check, so no baseline file was
   * written — the next verify will honestly report `no-baseline`.
   */
  aborted?: true
}

export interface VerifyValue {
  grade: ProofGrade
  root: string
  changed: string[]
  attributionMethod: string
  externalChanged: string[]
  impactPrecision: string
  affectedChecks: number
  untouchedChecks: number
  /**
   * Present only when the engine flagged degradation (v0.7, engine E3): git
   * facts were unavailable, so impact analysis was skipped and the full check
   * set was forced. Surfaced so "we ran everything because we couldn't tell
   * what moved" stays loud instead of reading like a deliberate `all: true`.
   */
  degraded?: true
  /**
   * Posterior probability that every affected check is healthy (γ): the "p" in
   * `proven (p≈0.97)`, pre-rounded to two decimals for display. Present exactly
   * when the report carried graded trust; the legacy binary path omits every
   * field below so its canonical value stays byte-stable.
   */
  confidence?: number
  /** How `confidence` was earned; rides with it, never alone. */
  confidenceBasis?: ConfidenceBasis
  /** Checks the wave plan never dispatched, resting on their priors (>0 only). */
  certifiedSkips?: number
  /** Why the wave plan ended before every affected check ran; only when it did. */
  stoppedEarly?: 'certified' | 'failed' | 'budget'
  /** Waves the bayesian plan actually dispatched; present only with a schedule. */
  waves?: number
  regressions: { label: string; suspects: string[]; detail: string }[]
  fixed: string[]
  preExisting: string[]
  unverified: string[]
  passing: number
  failing: number
  summary: string
}

export interface ClaimValue {
  claim: string
  grade: ProofGrade
  proven: boolean
  root: string
  /**
   * The verification posterior (γ), transferred when the run carried one so a
   * claim card can speak in probabilities. Absent on the legacy binary path.
   */
  confidence?: number
  /**
   * ζ: the contract kind this claim was typed against. Present exactly when the
   * call carried a `kind` (the typed path); the legacy path omits every field
   * below so its canonical value stays byte-identical to pre-ζ session logs.
   */
  kind?: ClaimKind
  /** ζ: per-obligation verdicts under the claim's contract, in engine order. */
  obligations?: ReadonlyArray<{ id: string; met: boolean; detail: string }>
  /**
   * ζ: docs-only whose every obligation held — the verdict is jury evidence
   * (the author's self-attestation, structurally capped), never a measurement.
   */
  jury?: true
  /** Checks that regressed against the baseline — blame, not credit. */
  regressions: VerifyValue['regressions']
  blockers: string[]
  summary: string
}

/**
 * λ: the Class B protocol, step 1 — the frozen deliberation prompt handed to
 * the juror. The canonical value carries the prompt verbatim because the
 * prompt is the evidence bundle's replay key: a third party re-runs exactly
 * these bytes against the declared model and compares outputs.
 */
export interface JuryRequestValue {
  claimId: string
  rubricVersion: string
  prompt: string
  /** The one-line charge to the juror: deliberate, then submit via the tool. */
  instruction: string
}

/** λ: the Class B protocol, step 2 — the verdict exactly as it landed on-chain. */
export interface JurySubmitValue {
  recorded: true
  claimId: string
  /** Deliberation generation: max existing gen for the claim + 1 (appeals supersede). */
  gen: number
  verdict: 'uphold' | 'reject' | 'abstain'
  probability: number
  /**
   * The pure Class B factor under the default trust policy — p^classB, full
   * precision (abstain carries 1). Recomputable by anyone from the record;
   * the engine's own fusion may weigh it differently, this number never lies
   * about which policy produced it.
   */
  factor: number
  note: string
}

/** λ: Class C — a named human's endorsement/rejection exactly as recorded. */
export interface EndorseValue {
  recorded: true
  claimId: string
  decision: 'endorse' | 'reject'
  approver: string
  /** Exactly what the approver took responsibility for. */
  scope: { claim: string; evidenceRoot: string | null }
  note: string
}

/**
 * ρ: PTC synthesis, step 1 — the synthetic-verification request exactly as it
 * was committed to the chain. The canonical value carries the scaffold
 * template VERBATIM because the model writes from it: a digest alone cannot be
 * filled in, and the template's header is where the content-addressing warning
 * lives (an assertion deleted is a different scriptDigest, forever).
 */
export interface ConjureValue {
  claimId: string
  /** Sandbox-relative script name the model must copy the template to. */
  entry: string
  /** Paths the conjured test must exercise, as the request locked them. */
  paths: string[]
  /** Workspace-relative sandbox directory the entry lives in. */
  sandboxDir: string
  /** The scaffold, byte for byte — the model's writing surface. */
  template: string
  /** The standing charge: copy, fill, run via proof_conjure_run. */
  instruction: string
}

/** ρ: PTC synthesis, step 2 — a script that ran and landed as evidence. */
export interface ConjureRunValue {
  recorded: true
  checkId: string
  status: CheckStatus
  /** sha256 of the script as it existed at execution time — proves what ran. */
  scriptDigest: string
  /** Screening findings for exactly that digest; empty = cleared to run. */
  screened: string[]
  sandbox: 'screened-subprocess' | 'ptc-runtime'
  /** Excerpt of the run's output (or the refusal reason when skipped). */
  outputHead: string
  note: string
}

/**
 * ρ: a script the capability screen refused — `recorded: false` is a
 * protocol-internal outcome, NOT a tool error: the model's next move is to
 * edit the script and call proof_conjure_run again, which an isError result
 * would only obscure.
 */
export interface ConjureRefusedValue {
  recorded: false
  entry: string
  screened: string[]
  reason: string
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const statusParams: ParameterSchemaSpec = {}

const baselineParams: ParameterSchemaSpec = {
  reason: { type: 'string', description: 'Why a fresh baseline is being established.' },
}

const verifyParams: ParameterSchemaSpec = {
  changed: {
    type: 'array',
    items: { type: 'string' },
    description: 'Files this session changed, relative to the workspace root. Omit to use git working-tree state.',
  },
  all: { type: 'boolean', description: 'Ignore impact analysis and re-run every discovered check.' },
  claim: { type: 'string', description: 'The claim being verified, for the record.' },
}

const claimParams: ParameterSchemaSpec = {
  claim: {
    type: 'string',
    required: true,
    description: 'The exact completion claim, e.g. "fixed the login redirect bug and added a regression test".',
  },
  kind: {
    type: 'string',
    enum: ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'],
    description: 'Optional typed contract for the claim: refactor/optimization → behavior-preserving '
      + '(the public API surface must not move); new feature → behavior-adding (every new source path covered '
      + 'by a passing check); performance → perf-budget (with budgetMs); documentation → docs-only (with review); '
      + 'a subjective claim machines cannot measure → llm-jury (deliberate via proof_jury / proof_jury_submit first). '
      + 'Omit to verify without a contract.',
  },
  budgetMs: {
    type: 'number',
    description: 'perf-budget only: benchmark checks must stay within this many milliseconds.',
  },
  review: {
    type: 'string',
    description: 'docs-only only: the self-review that jury evidence carries — what a human reviewer should double-check.',
  },
  entryPoints: {
    type: 'array',
    items: { type: 'string' },
    description: 'API-face entry points (workspace-relative files) the surface check covers; omit to let the engine '
      + 'derive them from package.json. Advanced usage.',
  },
  changed: {
    type: 'array',
    items: { type: 'string' },
    description: 'Files this session changed, relative to the workspace root.',
  },
}

const CLAIM_KINDS: readonly string[] = ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury']

const juryParams: ParameterSchemaSpec = {
  claim: {
    type: 'string',
    required: true,
    description: 'The exact claim the jury deliberates on.',
  },
  context: {
    type: 'string',
    description: 'Materials the juror may judge from (diff summary, excerpts, how the claim maps to evidence). '
      + 'Omit to deliberate on the claim text alone.',
  },
}

const jurySubmitParams: ParameterSchemaSpec = {
  claimId: {
    type: 'string',
    required: true,
    description: 'The claimId proof_jury returned — binds the verdict to its pending on-chain request.',
  },
  verdict: {
    type: 'string',
    required: true,
    enum: ['uphold', 'reject', 'abstain'],
    description: 'Your ruling: uphold when the materials support the claim, reject when they contradict it, '
      + 'abstain when they are insufficient to decide.',
  },
  probability: {
    type: 'number',
    required: true,
    description: 'Your subjective probability the claim is true, in [0,1] — the number your own reasoning supports, '
      + 'not a measurement.',
  },
  reasoning: {
    type: 'string',
    required: true,
    description: 'Your complete deliberation output, verbatim — it is recorded on the chain as the jury record '
      + 'and replayed by third parties.',
  },
  model: {
    type: 'string',
    description: 'Declared identity of the deliberating model. The plugin cannot verify a model\'s self-report, '
      + 'so it is recorded as a claim. Defaults to "session-model (unverified)".',
  },
}

const endorseParams: ParameterSchemaSpec = {
  claim: {
    type: 'string',
    required: true,
    description: 'The claim the human endorses or rejects, exactly as it was proven.',
  },
  decision: {
    type: 'string',
    required: true,
    enum: ['endorse', 'reject'],
    description: 'endorse = the human accepts the claim\'s residual risk (unlocks the grade gap, never inflates '
      + 'the number); reject = the human denies it (collapses the confidence).',
  },
  approver: {
    type: 'string',
    description: 'Signature name of the endorsing human. Defaults to "host-approver" — the human behind the '
    + 'host approval prompt.',
  },
}

const conjureParams: ParameterSchemaSpec = {
  claim: {
    type: 'string',
    required: true,
    description: 'The exact assertion NO existing check covers — the property or minimal repro the conjured '
    + 'test must prove, e.g. "parse rejects unbalanced quotes with input positions".',
  },
  paths: {
    type: 'array',
    items: { type: 'string' },
    required: true,
    description: 'Workspace-relative source files the conjured test must exercise. Call this tool only for '
    + 'assertions no discovered check covers: proof_conjure opens a request that lets you draft a property '
    + 'test / minimal repro from a scaffold, which the verifier then screens, executes and records as '
    + 'synthetic evidence.',
  },
}

const conjureRunParams: ParameterSchemaSpec = {
  claim: {
    type: 'string',
    required: true,
    description: 'The exact claim text the proof_conjure request was opened with — the run binds the verdict '
    + 'to the entry minted for this claim.',
  },
  entry: {
    type: 'string',
    required: true,
    description: 'The sandbox script name proof_conjure returned (e.g. synthetic-<claimId>-0.mjs), already '
    + 'written inside the conjure sandbox with your assertions filled in.',
  },
}

/** ζ: narrow an untrusted `kind` argument to the four-value union, or nothing. */
function isClaimKind(value: unknown): value is ClaimKind {
  return typeof value === 'string' && CLAIM_KINDS.includes(value)
}

/**
 * λ: `evidenceLogPath` is the physical evidence-log location, derived by the
 * plugin entry with the same rule ProofEngine applies to its own private copy
 * (the store exposes no marker read-back, and the engine exports neither the
 * path nor its derivation). The Class B/C tools read attestation markers off
 * the chain through the engine's own fs port with it. When absent (direct
 * construction), every read-backed guard degrades to refusal rather than
 * trusting an unverifiable submitter.
 */
export function createProofTools(
  engine: ProofEngine,
  touched?: () => readonly string[],
  evidenceLogPath?: string,
): ToolDefinition[] {
  return [
    createStatusTool(engine),
    createBaselineTool(engine),
    createVerifyTool(engine, touched),
    createClaimTool(engine, touched),
    createJuryTool(engine),
    createJurySubmitTool(engine, evidenceLogPath),
    createEndorseTool(engine, evidenceLogPath),
    createConjureTool(engine),
    createConjureRunTool(engine),
  ]
}

function createStatusTool(engine: ProofEngine): ToolDefinition {
  return {
    name: 'proof_status',
    description:
      'Report the current proof state: whether a baseline exists, which objective checks the workspace declares, '
      + 'the latest evidence for each, and whether the evidence log is intact. Read-only. Call this before claiming '
      + 'anything is done.',
    parameters: statusParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          hasBaseline: { type: 'boolean' },
          baselineCreatedAt: { type: ['string', 'null'] },
          baselineRoot: { type: ['string', 'null'] },
          discovered: { type: 'integer' },
          checks: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' }, label: { type: 'string' }, kind: { type: 'string' },
                lastStatus: { type: ['string', 'null'] }, recordedAt: { type: ['string', 'null'] },
              },
            },
          },
          evidenceRecords: { type: 'integer' },
          evidenceLogIntact: { type: 'boolean' },
          chainMode: { type: 'string', enum: ['signed', 'unsigned', 'legacy'] },
          checkpoints: { type: 'integer' },
          chainIntact: { type: 'boolean' },
          tailRecords: { type: 'integer' },
          rewindDetected: { type: 'boolean' },
          baselineTampered: { type: 'boolean' },
          // Present only when abnormal (see StatusValue) — declared so the
          // schema stays truthful about what a degraded host may emit.
          unverifiableCheckpoints: { type: 'integer' },
          anchorForged: { type: 'boolean' },
          dirtyFiles: { type: 'integer' },
          summary: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderStatus(value as unknown as StatusValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    isConcurrencySafe: () => true,
    presentCall: () => ({ card: 'generic', title: 'Proof status', kind: 'read' }),
    presentResult: (_args, result) => {
      const meta = result.meta as StatusValue | undefined
      return {
        card: 'generic',
        title: meta?.hasBaseline ? 'Proof status' : 'Proof status — no baseline',
        content: [text(meta ? oneLine(meta.summary) : 'no status')],
      }
    },
    async execute(_args, exec: ToolRunContext) {
      assertActive(exec)
      const specs = await engine.loadChecks()
      const baseline = await engine.baseline()
      const latest = await engine.latestEvidence()
      const audit = await engine.audit()
      const snapshot = await engine.workspaceSnapshot()
      return toStatusValue({ specs, baseline, latest, audit, snapshot }) as unknown as JsonValue
    },
  }
}

function createBaselineTool(engine: ProofEngine): ToolDefinition {
  return {
    name: 'proof_baseline',
    description:
      'Establish (or refresh) the verification baseline: run every objective check the workspace declares and record '
      + 'the outcomes as evidence. This is the anchor every later claim is diffed against. '
      + 'Do this once at the start of work, before making changes.',
    parameters: baselineParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' }, baselineId: { type: ['string', 'null'] }, root: { type: ['string', 'null'] },
          ran: { type: 'integer' }, passing: { type: 'integer' }, failing: { type: 'integer' },
          skipped: { type: 'integer' }, durationMs: { type: 'integer' },
          failingLabels: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' },
          // Present only when the run aborted — declared so the schema stays
          // truthful about what a cancelled baseline may emit.
          aborted: { type: 'boolean' },
        },
      },
      render: (_args, value) => [text(renderBaseline(value as unknown as BaselineValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    timeoutMs: 600_000,
    presentCall: (args) => ({
      card: 'generic',
      title: 'Establish verification baseline',
      kind: 'search',
      rawInput: args,
    }),
    presentResult: (_args, result) => {
      const meta = result.meta as BaselineValue | undefined
      return {
        card: 'generic',
        // An aborted run never became the anchor; the title must not imply it did.
        title: meta?.aborted === true
          ? 'Baseline aborted — not anchored'
          : meta?.ok ? `Baseline established · ${meta.passing}/${meta.ran} passing` : 'Baseline failed',
        content: [text(meta ? oneLine(meta.summary) : 'no baseline result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const { records, baseline } = await engine.establishBaseline({
        signal: exec.signal,
        onProgress: (label, index, total) => {
          void label; void index; void total
        },
      })
      void args
      return toBaselineValue(baseline, records) as unknown as JsonValue
    },
  }
}

function createVerifyTool(engine: ProofEngine, touched?: () => readonly string[]): ToolDefinition {
  return {
    name: 'proof_verify',
    description:
      'Re-run the objective checks this change set made stale and grade the outcome against the baseline. '
      + 'Uses change-impact analysis to run only what is affected unless `all` is set. '
      + 'A check that passed at baseline and now fails is a REGRESSION charged to this work; '
      + 'a check already failing at baseline is pre-existing.',
    parameters: verifyParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          grade: { type: 'string', enum: ['proven', 'unproven', 'regressed', 'no-baseline', 'stale'] },
          root: { type: 'string' }, changed: { type: 'array', items: { type: 'string' } },
          attributionMethod: { type: 'string' },
          externalChanged: { type: 'array', items: { type: 'string' } },
          impactPrecision: { type: 'string', enum: ['lsp-verified', 'approximate', 'forced'] },
          affectedChecks: { type: 'integer' }, untouchedChecks: { type: 'integer' },
          // Present only when git facts were unavailable (see VerifyValue).
          degraded: { type: 'boolean' },
          // Present only when the run carries graded trust (γ) — declared so
          // the schema stays truthful about what a bayesian run may emit.
          confidence: { type: 'number' },
          confidenceBasis: { type: 'string', enum: ['full-coverage', 'certified-subset', 'degraded'] },
          certifiedSkips: { type: 'integer' },
          stoppedEarly: { type: 'string', enum: ['certified', 'failed', 'budget'] },
          waves: { type: 'integer' },
          regressions: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' }, suspects: { type: 'array', items: { type: 'string' } },
                detail: { type: 'string' },
              },
            },
          },
          fixed: { type: 'array', items: { type: 'string' } },
          preExisting: { type: 'array', items: { type: 'string' } },
          unverified: { type: 'array', items: { type: 'string' } },
          passing: { type: 'integer' }, failing: { type: 'integer' }, summary: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderVerify(value as unknown as VerifyValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    timeoutMs: 900_000,
    presentCall: (args) => ({ card: 'generic', title: 'Verify against baseline', kind: 'search', rawInput: args }),
    presentResult: (_args, result) => {
      const meta = result.meta as VerifyValue | undefined
      return {
        card: 'generic',
        title: meta?.grade ? `Verification · ${String(meta.grade).toUpperCase()}` : 'Verification',
        content: [text(meta?.summary ? oneLine(meta.summary) : 'no verification result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as { changed?: string[]; all?: boolean; claim?: string }
      const outcome = await engine.verify({
        ...(Array.isArray(parsed.changed) ? { changed: parsed.changed } : {}),
        ...(parsed.all === true ? { all: true } : {}),
        ...(touched !== undefined ? { touched: touched() } : {}),
        signal: exec.signal,
      })
      return toVerifyValue(
        outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
        outcome.schedule,
      ) as unknown as JsonValue
    },
  }
}

function createClaimTool(engine: ProofEngine, touched?: () => readonly string[]): ToolDefinition {
  return {
    name: 'proof_claim',
    description:
      'State a completion claim AND prove it in one call. Runs the affected objective checks against the baseline and '
      + 'returns `proven: true` only when nothing regressed and full coverage was achieved. '
      + 'Call this instead of asserting completion in prose. If it returns `proven: false`, the blockers tell you '
      + 'exactly what to fix before the claim can stand.',
    parameters: claimParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          claim: { type: 'string' },
          grade: { type: 'string', enum: ['proven', 'unproven', 'regressed', 'no-baseline', 'stale'] },
          proven: { type: 'boolean' }, root: { type: 'string' },
          // Present only when the verification carried a posterior (γ).
          confidence: { type: 'number' },
          // Present only when the claim carried a `kind` (ζ) — declared so the
          // schema stays truthful about what a typed contract may emit.
          kind: { type: 'string', enum: ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'] },
          obligations: {
            type: 'array',
            items: {
              type: 'object',
              properties: { id: { type: 'string' }, met: { type: 'boolean' }, detail: { type: 'string' } },
            },
          },
          jury: { type: 'boolean' },
          regressions: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' }, suspects: { type: 'array', items: { type: 'string' } },
                detail: { type: 'string' },
              },
            },
          },
          blockers: { type: 'array', items: { type: 'string' } },
          summary: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderClaim(value as unknown as ClaimValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    timeoutMs: 900_000,
    presentCall: (args) => {
      const parsed = (args ?? {}) as { claim?: string }
      return {
        card: 'generic',
        title: `Prove: ${truncate(parsed.claim ?? 'completion claim', 60)}`,
        kind: 'read',
        rawInput: args,
      }
    },    presentResult: (_args, result) => {
      const meta = result.meta as ClaimValue | undefined
      // ζ: a typed claim names its contract in the title; the untyped card keeps
      // its exact legacy wording.
      const kind = typeof meta?.kind === 'string' ? meta.kind : undefined
      return {
        card: 'generic',
        title: meta?.proven === true
          ? (kind !== undefined ? `✓ Claim (${kind})` : '✓ Proven')
          : (kind !== undefined
            ? `✗ Claim (${kind}) · ${meta?.grade ?? 'unknown'}`
            : `✗ Not proven · ${meta?.grade ?? 'unknown'}`),
        content: [text(meta?.summary ? oneLine(meta.summary) : 'no claim result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as {
        claim: string
        changed?: string[]
        kind?: string
        budgetMs?: number
        review?: string
        entryPoints?: string[]
      }
      // ζ typed-contract path: a `kind` binds the claim to its obligations via
      // engine.verifyContract. Everything else (no kind) keeps the legacy
      // verify() path byte-for-byte.
      if (isClaimKind(parsed.kind)) {
        const contract: ClaimContract = {
          kind: parsed.kind,
          claim: parsed.claim,
          ...(typeof parsed.budgetMs === 'number' ? { budgetMs: parsed.budgetMs } : {}),
          ...(typeof parsed.review === 'string' ? { review: parsed.review } : {}),
          ...(Array.isArray(parsed.entryPoints)
            ? { entryPoints: parsed.entryPoints.filter((e): e is string => typeof e === 'string') }
            : {}),
        }
        const outcome = await engine.verifyContract({
          contract,
          ...(Array.isArray(parsed.changed) ? { changed: parsed.changed } : {}),
          ...(touched !== undefined ? { touched: touched() } : {}),
          signal: exec.signal,
        })
        const verified = toVerifyValue(
          outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
          outcome.schedule,
        )
        return toClaimValue(parsed.claim, outcome.report, verified, outcome.contract) as unknown as JsonValue
      }
      const outcome = await engine.verify({
        ...(Array.isArray(parsed.changed) ? { changed: parsed.changed } : {}),
        ...(touched !== undefined ? { touched: touched() } : {}),
        signal: exec.signal,
      })
      const verified = toVerifyValue(
        outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
        outcome.schedule,
      )
      return toClaimValue(parsed.claim, outcome.report, verified) as unknown as JsonValue
    },
  }
}

// ---------------------------------------------------------------------------
// λ: Classes B and C — testimony as evidence. The jury protocol is a
// request/submit pair (the prompt is frozen on-chain before the juror speaks,
// so the verdict binds to bytes a third party can replay), and the human
// endorsement only reaches execute after the host approval seam said yes
// (the plugin entry registers that gate; here the body assumes a human did).
// ---------------------------------------------------------------------------

/** The standing charge to the juror, returned with every jury request. */
const JURY_INSTRUCTION = 'deliberate strictly per the rubric, then call proof_jury_submit with your JSON verdict; '
  + 'your output becomes permanent Class B evidence, replayable by any third party with this exact prompt'

function createJuryTool(engine: ProofEngine): ToolDefinition {
  return {
    name: 'proof_jury',
    description:
      'Class B evidence, step 1 of 2: request an LLM jury deliberation on a claim. Returns the frozen deliberation '
      + 'prompt (rubric, claim, context) and records the request on the evidence chain. Read the returned prompt in '
      + 'full, deliberate strictly per the rubric, then record your JSON verdict with proof_jury_submit.',
    parameters: juryParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          claimId: { type: 'string' },
          rubricVersion: { type: 'string' },
          prompt: { type: 'string' },
          instruction: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderJuryRequest(value as unknown as JuryRequestValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    presentCall: (args) => {
      const parsed = (args ?? {}) as { claim?: string }
      return {
        card: 'generic',
        title: `Jury deliberation: ${truncate(parsed.claim ?? 'claim', 60)}`,
        kind: 'read',
        rawInput: args,
      }
    },
    presentResult: (_args, result) => {
      const meta = result.meta as JuryRequestValue | undefined
      return {
        card: 'generic',
        title: `Jury requested · ${typeof meta?.claimId === 'string' ? meta.claimId : 'claim'}`,
        content: [text(typeof meta?.instruction === 'string' ? oneLine(meta.instruction) : 'jury prompt issued')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as { claim?: unknown; context?: unknown }
      if (typeof parsed.claim !== 'string' || parsed.claim.trim().length === 0) {
        throw new Error('proof_jury: claim is required — the exact text the jury deliberates on')
      }
      const prompt = juryPrompt(
        parsed.claim,
        typeof parsed.context === 'string' ? parsed.context : '<no additional context>',
      )
      const claimId = claimIdOf(parsed.claim)
      // The request marker is the on-chain pre-image of the deliberation. The
      // prompt rides verbatim (a digest alone cannot be replayed), so the
      // later submit binds its verdict to exactly these bytes — and anyone
      // auditing the chain can check promptDigest against them.
      await engine.storeView.mark('attest/jury-requested', {
        claimId,
        promptDigest: sha256(prompt).slice(0, 16),
        rubricVersion: RUBRIC_V1,
        prompt,
      })
      return {
        claimId,
        rubricVersion: RUBRIC_V1,
        prompt,
        instruction: JURY_INSTRUCTION,
      } as unknown as JsonValue
    },
  }
}

function createJurySubmitTool(engine: ProofEngine, evidenceLogPath?: string): ToolDefinition {
  return {
    name: 'proof_jury_submit',
    description:
      'Class B evidence, step 2 of 2: record a jury verdict as PERMANENT evidence. Your verdict, probability, '
      + 'reasoning (verbatim), the exact prompt and your declared model identity are appended to the tamper-evident '
      + 'chain — any third party may replay the prompt and compare outputs, and a re-deliberation supersedes rather '
      + 'than erases. Only call this after deliberating on the prompt proof_jury returned; the claimId must match the '
      + 'pending request, or the submission is refused.',
    parameters: jurySubmitParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          recorded: { type: 'boolean' },
          claimId: { type: 'string' },
          gen: { type: 'integer' },
          verdict: { type: 'string', enum: ['uphold', 'reject', 'abstain'] },
          probability: { type: 'number' },
          factor: { type: 'number' },
          note: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderJurySubmit(value as unknown as JurySubmitValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    presentCall: (args) => {
      const parsed = (args ?? {}) as { verdict?: string }
      return {
        card: 'generic',
        title: `Record jury verdict: ${truncate(parsed.verdict ?? 'pending', 12)}`,
        kind: 'read',
        rawInput: args,
      }
    },
    presentResult: (_args, result) => {
      const meta = result.meta as JurySubmitValue | undefined
      return {
        card: 'generic',
        title: meta?.recorded === true
          ? `✓ Jury verdict recorded · gen ${typeof meta.gen === 'number' ? meta.gen : '?'}`
          : 'Jury verdict',
        content: [text(meta?.note ? oneLine(meta.note) : 'no verdict result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as {
        claimId?: unknown; verdict?: unknown; probability?: unknown; reasoning?: unknown; model?: unknown
      }
      // Defensive guards: the schema is a promise to the model, not a boundary
      // — every field is re-checked before anything touches the chain.
      if (typeof parsed.claimId !== 'string' || parsed.claimId.length === 0) {
        throw new Error('proof_jury_submit: claimId is required — the value proof_jury returned')
      }
      if (parsed.verdict !== 'uphold' && parsed.verdict !== 'reject' && parsed.verdict !== 'abstain') {
        throw new Error(`proof_jury_submit: verdict must be 'uphold' | 'reject' | 'abstain' `
          + `(got ${typeof parsed.verdict === 'string' ? JSON.stringify(parsed.verdict) : 'nothing usable'})`)
      }
      if (typeof parsed.probability !== 'number' || !Number.isFinite(parsed.probability)
        || parsed.probability < 0 || parsed.probability > 1) {
        throw new Error(`proof_jury_submit: probability must be a finite number in [0,1] `
          + `(got ${typeof parsed.probability === 'string' ? JSON.stringify(parsed.probability) : String(parsed.probability)})`)
      }
      if (typeof parsed.reasoning !== 'string' || parsed.reasoning.trim().length === 0) {
        throw new Error('proof_jury_submit: reasoning is required — the verbatim deliberation output that lands on the chain')
      }
      // The verdict must bind to a pending on-chain request: no request, no
      // record; a claimId that is not the latest request's is a mismatch (the
      // model may be several requests behind — the fix is a fresh proof_jury).
      const request = await latestJuryRequest(engine, evidenceLogPath)
      if (request === undefined) {
        throw new Error('proof_jury_submit: no attest/jury-requested marker on the chain — call proof_jury for this claim first')
      }
      if (request.claimId !== parsed.claimId) {
        throw new Error(`proof_jury_submit: claimId mismatch — the pending jury request is for claim `
          + `${String(request.claimId)}, not ${parsed.claimId}. Call proof_jury for this claim before submitting.`)
      }
      if (request.prompt === undefined) {
        throw new Error('proof_jury_submit: the pending request marker carries no verbatim prompt — refusing to record '
          + 'a deliberation whose prompt is not on file. Call proof_jury again.')
      }
      // Appeals supersede by generation: the new deliberation lands at the
      // highest existing gen for this claim + 1, never overwriting its foil.
      const gen = (await maxAttestationGen(engine, evidenceLogPath, 'attest/jury', parsed.claimId)) + 1
      const attestation: JuryAttestation = {
        kind: 'attest/jury',
        claimId: parsed.claimId,
        gen,
        prompt: request.prompt,
        rubricVersion: request.rubricVersion ?? RUBRIC_V1,
        // The submitter's declaration, recorded as exactly that: an LLM's
        // self-report is not a signature, and a replay that disagrees is the
        // audit that catches it.
        model: typeof parsed.model === 'string' && parsed.model.trim().length > 0
          ? parsed.model
          : 'session-model (unverified)',
        // The host exposes no isolated-model seam yet: this deliberation ran
        // inside the authoring session's own context, and honesty demands
        // that be named rather than dressed up as independence.
        independence: 'same-session',
        verdict: parsed.verdict,
        probability: parsed.probability,
        output: parsed.reasoning,
        at: Date.now(),
      }
      await engine.storeView.mark('attest/jury', { ...attestation })
      return {
        recorded: true as const,
        claimId: attestation.claimId,
        gen,
        verdict: attestation.verdict,
        probability: attestation.probability,
        // The pure Class B factor under the default trust policy, full
        // precision so a third party recomputing p^classB gets these bytes.
        factor: attestationFactor(attestation, DEFAULT_TRUST_WEIGHTS),
        note: 'Class B evidence recorded. Re-deliberation supersedes: call proof_jury again to appeal — '
          + 'the appeal lands at gen + 1 and readers resolve to the highest gen.',
      } as unknown as JsonValue
    },
  }
}

function createEndorseTool(engine: ProofEngine, evidenceLogPath?: string): ToolDefinition {
  return {
    name: 'proof_endorse',
    description:
      'Class C evidence: a named human endorses or rejects a claim. The call itself triggers the host approval '
      + 'prompt — nothing is recorded until a human consciously approves. Endorsement is risk acceptance: it unlocks '
      + 'the grade gap a machine run could not cross, it never inflates the number; rejection collapses it. The '
      + 'decision lands on the tamper-evident chain with the approver name and the reviewed evidence scope.',
    parameters: endorseParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          recorded: { type: 'boolean' },
          claimId: { type: 'string' },
          decision: { type: 'string', enum: ['endorse', 'reject'] },
          approver: { type: 'string' },
          scope: {
            type: 'object',
            properties: {
              claim: { type: 'string' },
              evidenceRoot: { type: ['string', 'null'] },
            },
          },
          note: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderEndorse(value as unknown as EndorseValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    presentCall: (args) => {
      const parsed = (args ?? {}) as { claim?: string; decision?: string }
      const decision = parsed.decision === 'endorse' || parsed.decision === 'reject' ? parsed.decision : 'decide on'
      return {
        card: 'generic',
        title: `Human ${decision}: ${truncate(parsed.claim ?? 'claim', 48)}`,
        kind: 'read',
        rawInput: args,
      }
    },
    presentResult: (_args, result) => {
      const meta = result.meta as EndorseValue | undefined
      return {
        card: 'generic',
        title: meta?.recorded === true
          ? `${meta.decision === 'reject' ? '✗' : '✓'} Human ${String(meta.decision ?? 'decision')} · `
            + `${typeof meta.approver === 'string' ? meta.approver : 'unknown approver'}`
          : 'Human endorsement',
        content: [text(meta?.note ? oneLine(meta.note) : 'no endorsement result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      // This body only runs once the host approval seam said yes (the plugin
      // entry routes proof_endorse through `ask`): the human's consciousness
      // is the evidence being recorded, not the model's say-so.
      const parsed = (args ?? {}) as { claim?: unknown; decision?: unknown; approver?: unknown }
      if (typeof parsed.claim !== 'string' || parsed.claim.trim().length === 0) {
        throw new Error('proof_endorse: claim is required — the exact claim the human is endorsing or rejecting')
      }
      if (parsed.decision !== 'endorse' && parsed.decision !== 'reject') {
        throw new Error(`proof_endorse: decision must be 'endorse' | 'reject' `
          + `(got ${typeof parsed.decision === 'string' ? JSON.stringify(parsed.decision) : 'nothing usable'})`)
      }
      const approver = typeof parsed.approver === 'string' && parsed.approver.trim().length > 0
        ? parsed.approver
        : 'host-approver'
      // v0.1 best-effort evidence root: the audit report exposes no chain-head
      // digest, so the scope names the baseline root the decision rides on —
      // the strongest addressable evidence root available — and null when no
      // baseline exists (an endorsement of an unanchored claim says exactly
      // that, which is more honest than a made-up root).
      let evidenceRoot: string | null = null
      try {
        const baseline = await engine.baseline()
        if (typeof baseline?.root === 'string') evidenceRoot = baseline.root
      } catch {
        evidenceRoot = null
      }
      // A re-endorsement (or retraction) supersedes by generation, exactly like
      // a jury appeal: gen + 1, readers resolve to the highest gen.
      const claimId = claimIdOf(parsed.claim)
      const gen = (await maxAttestationGen(engine, evidenceLogPath, 'attest/human', claimId)) + 1
      const attestation: HumanAttestation = {
        kind: 'attest/human',
        claimId,
        gen,
        approver,
        approvedAt: Date.now(),
        scope: { claim: parsed.claim, evidenceRoot },
        decision: parsed.decision,
      }
      await engine.storeView.mark('attest/human', { ...attestation })
      return {
        recorded: true as const,
        claimId,
        decision: attestation.decision,
        approver,
        scope: attestation.scope,
        note: 'Class C evidence recorded. Endorsement is risk acceptance: it unlocks the grade gap, '
          + 'it never inflates the number; rejection collapses it.',
      } as unknown as JsonValue
    },
  }
}

// ---------------------------------------------------------------------------
// ρ: PTC synthesis — the conjure protocol. Some assertions have no existing
// check (the change touched a path no suite covers, the claim is about a
// property nobody ever tested), so the plugin lets the AGENT draft the test
// under structural anti-forgery: the request is committed to the chain BEFORE
// any script exists, the script is content-addressed into its own evidence,
// screened against a capability deny-list, executed by the plugin's own port —
// never the agent's — and priced at a raised false-pass because a test written
// by the claimant is self-graded homework. The pair mirrors proof_jury's
// request/submit shape for exactly the same reason: the protocol's first half
// must be on the record before the second half can bind to it.
// ---------------------------------------------------------------------------

/**
 * ρ: the one fact the engine's instruction cannot state for itself — what the
 * evidence will be worth once it lands. Rendered with every request so the
 * model prices its own homework honestly before writing it.
 */
const CONJURE_WEIGHT_NOTE = 'Your script will enter the evidence chain as synthetic evidence, weighted below '
  + 'every existing test — it lifts confidence less than an organic check, because you wrote the test that '
  + 'proves your own claim.'

/** ρ: what a recorded synthetic run is worth — the note rides every success. */
const CONJURE_RUN_NOTE = 'Synthetic evidence recorded: conjured by the agent, executed by the plugin\'s own port, '
  + 'priced at elevated false-pass (0.15) — it lifts confidence less than organic checks.'

/** ρ: literal reason a refused run carries; the protocol's corrective next step. */
const CONJURE_REFUSED_REASON = 'capability screening refused this script — remove the flagged imports and retry'

function createConjureTool(engine: ProofEngine): ToolDefinition {
  return {
    name: 'proof_conjure',
    description:
      'PTC synthesis, step 1 of 2: construct a synthetic verification for an assertion NO existing check '
      + 'covers. Commits the claim and the paths it must exercise to the evidence chain, then returns the '
      + 'scaffold template (verbatim) and the sandbox entry to write it to. Fill the scaffold with a real '
      + 'property test / minimal repro of the claim, then execute and record it with proof_conjure_run — '
      + 'the verifier screens and runs the script itself; your script lands as synthetic evidence, weighted '
      + 'below every organic check.',
    parameters: conjureParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          claimId: { type: 'string' },
          entry: { type: 'string' },
          paths: { type: 'array', items: { type: 'string' } },
          sandboxDir: { type: 'string' },
          template: { type: 'string' },
          instruction: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderConjure(value as unknown as ConjureValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    presentCall: (args) => {
      const parsed = (args ?? {}) as { claim?: string }
      return {
        card: 'generic',
        title: `Conjure synthetic test: ${truncate(parsed.claim ?? 'claim', 48)}`,
        kind: 'read',
        rawInput: args,
      }
    },
    presentResult: (_args, result) => {
      const meta = result.meta as ConjureValue | undefined
      return {
        card: 'generic',
        title: `Synthetic test requested · ${typeof meta?.entry === 'string' ? meta.entry : 'entry'}`,
        content: [text(meta?.instruction ? oneLine(meta.instruction) : 'conjure request issued')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as { claim?: unknown; paths?: unknown }
      if (typeof parsed.claim !== 'string' || parsed.claim.trim().length === 0) {
        throw new Error('proof_conjure: claim is required — the exact assertion no existing check covers')
      }
      if (!Array.isArray(parsed.paths) || parsed.paths.length === 0
        || !parsed.paths.every(p => typeof p === 'string' && p.trim().length > 0)) {
        throw new Error(`proof_conjure: paths is required — the workspace-relative file(s) the conjured test `
          + `must exercise (got ${Array.isArray(parsed.paths) ? 'an empty list' : 'nothing usable'})`)
      }
      const { request, template, instruction } = await engine.conjureRequest({
        claim: parsed.claim,
        paths: parsed.paths as string[],
      })
      return {
        claimId: request.claimId,
        entry: request.entry,
        paths: [...request.paths],
        sandboxDir: sandboxDirOf(instruction, request.entry),
        template,
        instruction,
      } as unknown as JsonValue
    },
  }
}

function createConjureRunTool(engine: ProofEngine): ToolDefinition {
  return {
    name: 'proof_conjure_run',
    description:
      'PTC synthesis, step 2 of 2: screen, execute and record the conjured script you wrote after '
      + 'proof_conjure. The capability screen refuses forbidden imports (process spawning, network, workers, '
      + 'environment reads) BEFORE execution — a refusal returns recorded: false with the findings and nothing '
      + 'lands on the chain; remove the flagged imports and retry. A clean script is executed by the plugin\'s '
      + 'own port (never your tools) and its result enters the tamper-evident chain as synthetic evidence, '
      + 'priced at elevated false-pass — it lifts confidence less than organic checks.',
    parameters: conjureRunParams,
    output: {
      schema: {
        type: 'object',
        properties: {
          recorded: { type: 'boolean' },
          // Recorded path — what ran and what it proved.
          checkId: { type: 'string' },
          status: { type: 'string', enum: ['pass', 'fail', 'error', 'timeout', 'aborted', 'skipped'] },
          scriptDigest: { type: 'string' },
          screened: { type: 'array', items: { type: 'string' } },
          sandbox: { type: 'string', enum: ['screened-subprocess', 'ptc-runtime'] },
          outputHead: { type: 'string' },
          note: { type: 'string' },
          // Refusal path — the protocol outcome, not an error.
          entry: { type: 'string' },
          reason: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderConjureRun(value as unknown as ConjureRunValue | ConjureRefusedValue))],
      presentationMeta: (_args, value) => JSON.parse(JSON.stringify(value)) as JsonValue,
    },
    timeoutMs: 600_000,
    presentCall: (args) => {
      const parsed = (args ?? {}) as { entry?: string }
      return {
        card: 'generic',
        title: `Run synthetic test: ${truncate(parsed.entry ?? 'entry', 48)}`,
        kind: 'read',
        rawInput: args,
      }
    },
    presentResult: (_args, result) => {
      const meta = result.meta as ConjureRunValue | ConjureRefusedValue | undefined
      const run = meta as ConjureRunValue | undefined
      return {
        card: 'generic',
        title: meta?.recorded === true
          ? `${run?.status === 'pass' ? '✓' : '✗'} Synthetic evidence · ${String(run?.status ?? 'recorded')}`
          : 'Synthetic run refused — not recorded',
        content: [text(
          meta === undefined ? 'no conjure-run result'
            : meta.recorded === true
              ? (typeof run?.note === 'string' && run.note.length > 0 ? oneLine(run.note) : 'synthetic evidence recorded')
              : (typeof (meta as ConjureRefusedValue).reason === 'string'
                ? oneLine((meta as ConjureRefusedValue).reason)
                : 'screening refused this script'),
        )],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as { claim?: unknown; entry?: unknown }
      if (typeof parsed.claim !== 'string' || parsed.claim.trim().length === 0) {
        throw new Error('proof_conjure_run: claim is required — the exact claim text the proof_conjure request was opened with')
      }
      if (typeof parsed.entry !== 'string' || parsed.entry.trim().length === 0) {
        throw new Error('proof_conjure_run: entry is required — the sandbox script name proof_conjure returned')
      }
      const run = await engine.conjureRun({ claim: parsed.claim, entry: parsed.entry })
      // A screening refusal is a protocol-internal outcome, not a tool error:
      // returning it as the canonical value (isError stays false) is what tells
      // the model "edit the script and call me again" instead of "the tool
      // broke".
      if (run.status === 'skipped') {
        return {
          recorded: false as const,
          entry: parsed.entry,
          screened: [...run.screened],
          reason: CONJURE_REFUSED_REASON,
        } as unknown as JsonValue
      }
      return {
        recorded: true as const,
        checkId: run.checkId,
        status: run.status,
        scriptDigest: run.scriptDigest,
        screened: [...run.screened],
        sandbox: run.sandbox,
        outputHead: run.outputHead,
        note: CONJURE_RUN_NOTE,
      } as unknown as JsonValue
    },
  }
}

/**
 * ρ: the sandbox directory the engine actually mounted, recovered from the
 * instruction the engine itself produced (its step 1 names
 * `<sandboxDir>/<entry>.template.mjs`). The engine's options are private and
 * growing its public surface is not this batch's to do; an instruction whose
 * shape is not recognised degrades to the domain default rather than
 * inventing a path.
 */
function sandboxDirOf(instruction: string, entry: string): string {
  const match = new RegExp(`Copy (.+)/${escapeRegExp(entry)}\\.template\\.mjs to `).exec(instruction)
  return match?.[1] ?? SYNTHETIC_DIR_DEFAULT
}

/** ρ: quote regex metacharacters so an engine-minted entry anchors a literal. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// ---------------------------------------------------------------------------
// λ: chain read-back. The store appends markers but never reads them back, so
// the attestation tools parse the raw log lines through the engine's own fs
// port — the same route the engine's fusion pass takes. Parsing is defensive
// because the input is chain data: anything unreadable degrades to absence,
// never to a throw, and (per the guards above) absence means refusal.
// ---------------------------------------------------------------------------

/** Marker payloads under the given labels, in log order (newest last). */
async function markerPayloads(
  engine: ProofEngine,
  logPath: string | undefined,
  labels: ReadonlySet<string>,
): Promise<Record<string, unknown>[]> {
  if (logPath === undefined) return []
  try {
    const found: Record<string, unknown>[] = []
    for (const line of await engine.fsView.readLines(logPath)) {
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
      if (labels.has(String(record.label))) found.push(record)
    }
    return found
  } catch {
    // An unreadable log cannot invent testimony; every caller degrades to
    // absence (the log's own integrity is audit()'s charge, not this read's).
    return []
  }
}

/** The most recent attest/jury-requested marker, narrowed to its usable fields. */
async function latestJuryRequest(
  engine: ProofEngine,
  logPath: string | undefined,
): Promise<{ claimId: unknown; prompt: string | undefined; rubricVersion: string | undefined } | undefined> {
  const payloads = await markerPayloads(engine, logPath, new Set(['attest/jury-requested']))
  const last = payloads[payloads.length - 1]
  if (last === undefined) return undefined
  return {
    claimId: last.claimId,
    prompt: typeof last.prompt === 'string' ? last.prompt : undefined,
    rubricVersion: typeof last.rubricVersion === 'string' ? last.rubricVersion : undefined,
  }
}

/**
 * Highest recorded generation of one attestation kind for one claim, −1 when
 * none exists — the next record lands at +1, whatever the chain's history.
 */
async function maxAttestationGen(
  engine: ProofEngine,
  logPath: string | undefined,
  label: 'attest/jury' | 'attest/human',
  claimId: string,
): Promise<number> {
  const payloads = await markerPayloads(engine, logPath, new Set([label]))
  let max = -1
  for (const payload of payloads) {
    if (payload.claimId !== claimId) continue
    if (typeof payload.gen === 'number' && Number.isInteger(payload.gen) && payload.gen > max) max = payload.gen
  }
  return max
}

// ---------------------------------------------------------------------------
// Pure projections (engine facts -> canonical values)
//
// Exported so the wiring tests can pin the contract with minimal fixtures;
// every one is a total function of its inputs — no I/O, no clock.
// ---------------------------------------------------------------------------

/** Structural view of the engine facts `toStatusValue` reads; the real engine
 * types satisfy it, and tests can hand-pick the interesting corner. */
export interface StatusProjectInput {
  readonly specs: readonly { id: string; label: string; kind: string }[]
  readonly baseline?: { readonly createdAt: string; readonly root: string; readonly checks: readonly unknown[] }
  readonly latest: { get(id: string): { status: string; recordedAt: string } | undefined }
  readonly audit: AuditReport
  readonly snapshot: { readonly dirty: readonly string[] }
}

export function toStatusValue(input: StatusProjectInput): StatusValue {
  const { specs, baseline, latest, audit, snapshot } = input
  const checks = specs.map((spec) => {
    const ev = latest.get(spec.id)
    return {
      id: spec.id,
      label: spec.label,
      kind: spec.kind,
      lastStatus: ev?.status ?? null,
      recordedAt: ev?.recordedAt ?? null,
    }
  })

  const trustLine = `chain ${audit.chain.mode}, ${audit.chain.checkpoints} checkpoint(s)`
    + (audit.chain.tailRecords > 0 ? `, ${audit.chain.tailRecords} record(s) since last checkpoint` : '')
    + (audit.chain.rewind ? ', REWIND DETECTED' : '')
    + (audit.chain.anchorMismatch ? ', ANCHOR MISMATCH' : '')
    + (audit.chain.baselineTampered ? ', BASELINE TAMPERED' : '')

  return {
    hasBaseline: baseline !== undefined,
    baselineCreatedAt: baseline?.createdAt ?? null,
    baselineRoot: baseline?.root ?? null,
    discovered: specs.length,
    checks,
    evidenceRecords: audit.total,
    evidenceLogIntact: audit.ok,
    chainMode: audit.chain.mode,
    checkpoints: audit.chain.checkpoints,
    chainIntact: audit.chain.breaks.length === 0
      && audit.chain.badCheckpoints.length === 0
      && audit.chain.unsignedCheckpoints.length === 0
      && audit.chain.headMismatches.length === 0,
    tailRecords: audit.chain.tailRecords,
    rewindDetected: audit.chain.rewind,
    baselineTampered: audit.chain.baselineTampered,
    dirtyFiles: snapshot.dirty.length,
    // Honest trust signals ride along only when abnormal: the audit
    // deliberately does not fail on unverifiable checkpoints (a missing key is
    // not a forgery charge), so they must not flip `chainIntact` either — but
    // the model still deserves to know protection is weaker than it looks.
    // Omitted on the clean path so the canonical value stays byte-stable.
    ...(audit.chain.unverifiableCheckpoints.length > 0
      ? { unverifiableCheckpoints: audit.chain.unverifiableCheckpoints.length }
      : {}),
    ...(audit.chain.anchorForged ? { anchorForged: true } : {}),
    summary: baseline === undefined
      ? `No baseline. ${specs.length} objective check(s) discovered. Establish one with proof_baseline before editing. ${trustLine}.`
      : `Baseline from ${baseline.createdAt} (${baseline.checks.length} checks, root ${baseline.root.slice(0, 12)}). `
        + `${specs.length} check(s) discovered, ${audit.total} evidence record(s), `
        + `${audit.ok ? `log intact (${trustLine})` : `LOG CORRUPT (${audit.corrupt.length}; ${trustLine})`}, `
        + `${snapshot.dirty.length} dirty file(s).`,
  }
}

export function toBaselineValue(
  baseline: { readonly baselineId: string; readonly root: string; readonly aborted?: true },
  records: readonly { status: string; label: string; durationMs: number }[],
): BaselineValue {
  const passing = records.filter(r => r.status === 'pass').length
  const failing = records.filter(r => r.status === 'fail' || r.status === 'error' || r.status === 'timeout').length
  const skipped = records.filter(r => r.status === 'skipped' || r.status === 'aborted').length
  return {
    ok: failing === 0 && skipped === 0,
    baselineId: baseline.baselineId,
    root: baseline.root,
    ran: records.length,
    passing, failing, skipped,
    durationMs: records.reduce((acc, r) => acc + r.durationMs, 0),
    failingLabels: records.filter(r => r.status !== 'pass' && r.status !== 'skipped').map(r => r.label),
    summary: `Baseline ${baseline.baselineId.slice(0, 12)}: ${passing} passing, ${failing} failing, ${skipped} skipped/unrun `
      + `across ${records.length} check(s). Failures here are pre-existing — they are NOT charged to later work.`,
    // The engine refuses to persist a batch that did not observe every check
    // (E1); the refusal travels with the value so the model never mistakes an
    // aborted run for the anchor it did not become. Absent on the normal path
    // to keep the canonical value byte-stable.
    ...(baseline.aborted === true ? { aborted: true as const } : {}),
  }
}

export function toVerifyValue(
  report: GradedProofReport,
  changed: readonly string[],
  checks: readonly { label: string; verdict: string; suspects: readonly string[]; current?: { outputHead?: string } }[],
  selection?: { readonly untouched?: readonly unknown[]; readonly precision?: string },
  attribution?: { method: string; records: readonly { path: string; provenance: string }[] },
  degraded?: true,
  schedule?: {
    readonly mode: 'bayesian'
    readonly waves: number
    readonly stoppedEarly: 'certified' | 'failed' | 'budget' | null
    readonly skippedByPlan: ReadonlyArray<{ checkId: string; priorHealthy: number }>
  },
): VerifyValue {
  const externalChanged = attribution?.records.filter(r => r.provenance === 'external').map(r => r.path) ?? []
  // The check list covers every discovered spec (attribution included), so the
  // old `discovered - checks.length` formula was structurally always 0 — the
  // honest count of proven-untouched checks lives on the selection itself.
  const untouched = selection?.untouched
  // γ graded trust: the scheduler's by-products ride only when they exist.
  // Every read is guarded so a partial or hostile outcome shape degrades to
  // absence instead of throwing; the display value is pre-rounded to two
  // decimals while the report keeps the full-precision number.
  const confidence = typeof report.confidence === 'number'
    ? Math.round(report.confidence * 100) / 100
    : undefined
  const confidenceBasis = report.confidenceBasis === 'full-coverage'
    || report.confidenceBasis === 'certified-subset'
    || report.confidenceBasis === 'degraded'
    ? report.confidenceBasis
    : undefined
  const skippedByPlan = Array.isArray(schedule?.skippedByPlan) ? schedule.skippedByPlan : []
  const stoppedEarly = schedule?.stoppedEarly
  const waves = typeof schedule?.waves === 'number' ? schedule.waves : undefined
  return {
    grade: report.grade,
    root: report.root,
    changed: [...changed],
    attributionMethod: attribution?.method ?? 'explicit',
    externalChanged,
    impactPrecision: selection?.precision ?? 'approximate',
    affectedChecks: checks.filter(c => c.verdict !== 'not-run').length,
    untouchedChecks: Array.isArray(untouched) ? untouched.length : 0,
    // E3 pass-through: forced-because-blind must read differently from
    // forced-because-asked-for. Present only on the degraded path.
    ...(degraded === true ? { degraded: true as const } : {}),
    // γ pass-through: posterior, basis and wave-plan footprint — each key
    // appears only when it carries information, so the ungraded canonical
    // value stays byte-identical to what session logs already hold.
    ...(confidence !== undefined ? { confidence } : {}),
    ...(confidence !== undefined && confidenceBasis !== undefined ? { confidenceBasis } : {}),
    ...(skippedByPlan.length > 0 ? { certifiedSkips: skippedByPlan.length } : {}),
    ...(stoppedEarly === 'certified' || stoppedEarly === 'failed' || stoppedEarly === 'budget'
      ? { stoppedEarly }
      : {}),
    ...(waves !== undefined ? { waves } : {}),
    regressions: checks
      .filter(c => c.verdict === 'regression' || c.verdict === 'new-failure')
      .map(c => ({
        label: c.label,
        suspects: [...c.suspects].slice(0, 5),
        detail: firstInformativeLine(c.current?.outputHead ?? ''),
      })),
    fixed: checks.filter(c => c.verdict === 'fixed').map(c => c.label),
    preExisting: checks.filter(c => c.verdict === 'still-failing').map(c => c.label),
    unverified: [...report.unverified],
    passing: report.summary.passing,
    failing: report.summary.failing,
    summary: proofNarrative(report),
  }
}

export function toClaimValue(
  claim: string,
  report: ProofReport,
  verified: VerifyValue,
  /** ζ: the engine's contract verdict; present only on the typed (kind) path. */
  contract?: { readonly kind: ClaimKind; readonly obligations: readonly ObligationResult[] },
): ClaimValue {
  const blockers: string[] = []
  if (report.grade === 'no-baseline') blockers.push('No baseline exists. Run proof_baseline first.')
  if (report.grade === 'stale') blockers.push(`Stale evidence: ${report.unverified.join(', ') || 'affected checks not re-run'}.`)
  for (const reg of verified.regressions) blockers.push(`Regression: ${reg.label} — ${reg.detail}`)
  if (report.grade === 'unproven') blockers.push('Verification was incomplete (skipped, aborted or timed out).')

  // γ graded trust: the posterior rides onto the claim exactly when the
  // verification had one — same two-decimal number, never a bare probability.
  // The no-posterior branches keep their exact legacy text.
  const p = typeof verified.confidence === 'number' ? verified.confidence : undefined

  // ζ typed-contract half: rides only when the engine judged a contract. The
  // obligation list is defensively copied into plain records (the canonical
  // value owns its shape, whatever the engine object grows into), and each
  // unmet obligation is a blocker in its own right — its detail is the model's
  // action item, phrased by core/contract.ts. Both-or-nothing: a contract
  // without a legible kind or obligations degrades to the legacy value rather
  // than half-announcing a contract.
  const kind = contract !== undefined && typeof contract.kind === 'string' ? contract.kind : undefined
  const obligations = contract !== undefined && Array.isArray(contract.obligations)
    ? contract.obligations.map(o => ({ id: o.id, met: o.met === true, detail: o.detail }))
    : undefined
  if (kind !== undefined && obligations !== undefined) {
    for (const obligation of obligations) {
      if (obligation.met !== true) blockers.push(`contract unmet: ${obligation.id} — ${obligation.detail}`)
    }
  }
  // The jury flag marks a docs-only claim whose every obligation held: that
  // verdict is self-attestation carrying the structural cap, and the render
  // must be able to say so. An empty obligation list is not a standing jury.
  const jury = kind === 'docs-only'
    && obligations !== undefined
    && obligations.length > 0
    && obligations.every(o => o.met === true)

  return {
    claim,
    grade: report.grade,
    proven: report.grade === 'proven',
    root: report.root,
    ...(p !== undefined ? { confidence: p } : {}),
    ...(kind !== undefined && obligations !== undefined ? { kind, obligations } : {}),
    ...(jury ? { jury: true as const } : {}),
    regressions: verified.regressions,
    blockers,
    summary: report.grade === 'proven'
      ? `PROVEN${p !== undefined ? ` (p≈${p.toFixed(2)})` : ''} — "${claim}" is backed by evidence root ${report.root.slice(0, 12)}: `
        + `${report.summary.passing} check(s) passing, ${report.summary.regressions} regression(s), `
        + `${report.summary.preExisting} pre-existing failure(s) left untouched.`
      : `NOT PROVEN (${report.grade}${p !== undefined ? `, p≈${p.toFixed(2)}` : ''}) — "${claim}". ${blockers.join(' ')}`,
  }
}

/**
 * Display path must be TOTAL: these run during live streaming AND session-log
 * replay, so a malformed or older `meta` degrades to prose rather than throws.
 */
function renderStatus(value: StatusValue): string {
  const v = value ?? ({} as StatusValue)
  const checks = Array.isArray(v.checks) ? v.checks : []
  const summary = typeof v.summary === 'string' ? v.summary : 'no status available'
  const lines = [summary, '']
  if (v.rewindDetected === true || v.baselineTampered === true || v.chainIntact === false) {
    lines.push('⚠️ Evidence log trust: TAMPER-EVIDENCE TRIPPED — do not trust grades until restored from a known-good copy.')
    lines.push('')
  }
  // New trust signals, each appearing only in its abnormal state so the
  // normal render stays byte-identical to what session logs already hold.
  if (v.anchorForged === true) {
    lines.push('⚠️ ANCHOR SIGNATURE INVALID — the out-of-band anchor failed its own signature check. '
      + 'Treat every grade as untrusted and restore the anchor from a known-good copy.')
    lines.push('')
  }
  const tailRecords = typeof v.tailRecords === 'number' ? v.tailRecords : 0
  const unverifiable = typeof v.unverifiableCheckpoints === 'number' ? v.unverifiableCheckpoints : 0
  if (tailRecords > 0) {
    lines.push(`⚠ ${tailRecords} record(s) after the last signed checkpoint — chain-only protection window.`)
  }
  if (unverifiable > 0) {
    lines.push(`ℹ ${unverifiable} checkpoint(s) signed by a key this host cannot verify — protection is weaker than `
      + '"signed" suggests, but this is a missing key on our side, not a forgery charge.')
  }
  if (tailRecords > 0 || unverifiable > 0) lines.push('')
  if (checks.length === 0) lines.push('No objective checks discovered. Add `checks` to the plugin config, or give the project a test/build script.')
  else {
    lines.push('Objective checks:')
    for (const check of checks) {
      lines.push(`  · ${check.label} [${check.kind}] — ${check.lastStatus ?? 'never run'}`)
    }
  }
  return lines.join('\n')
}

function renderBaseline(value: BaselineValue): string {
  const v = value ?? ({} as BaselineValue)
  const lines = [typeof v.summary === 'string' ? v.summary : 'no baseline result']
  if (v.aborted === true) {
    // The engine already refused to write the baseline (E1); saying so here is
    // the difference between "try again" and silently anchoring on nothing.
    lines.push('', '⚠ ABORTED — this run did not observe every check, so nothing was written: it is NOT the baseline '
      + 'and not an anchor. The next proof_verify will report no-baseline; re-run proof_baseline.')
  }
  const failing = Array.isArray(v.failingLabels) ? v.failingLabels : []
  if (failing.length > 0) {
    lines.push('', 'Pre-existing failures (not caused by future work):')
    for (const label of failing) lines.push(`  · ${label}`)
  }
  return lines.join('\n')
}

/**
 * The γ confidence line: `confidence p≈0.97 (certified-subset · 3 wave(s) ·
 * 2 check(s) certified by prior)`. The basis names the regime; the tail says
 * what earned it — full-coverage: every affected check ran; certified-subset:
 * the posterior crossed the target and the unrun checks rest on their priors;
 * degraded: the run ended below target (with the stop reason when there was
 * one). Total on replay: every field is individually guarded, and a value
 * without a posterior produces no line at all.
 */
function confidenceLine(v: VerifyValue): string | null {
  if (typeof v.confidence !== 'number') return null
  const p = v.confidence.toFixed(2)
  const basis = v.confidenceBasis === 'full-coverage' || v.confidenceBasis === 'certified-subset'
    || v.confidenceBasis === 'degraded'
    ? v.confidenceBasis
    : null
  const waves = typeof v.waves === 'number' ? v.waves : null
  const skips = typeof v.certifiedSkips === 'number' ? v.certifiedSkips : 0
  const stopped = v.stoppedEarly === 'certified' || v.stoppedEarly === 'failed' || v.stoppedEarly === 'budget'
    ? v.stoppedEarly
    : null
  const parts: string[] = []
  if (basis !== null) parts.push(basis)
  if (waves !== null) parts.push(`${waves} wave(s)`)
  if (basis === 'certified-subset') {
    parts.push(skips > 0 ? `${skips} check(s) certified by prior` : 'certified by prior')
  } else if (basis === 'full-coverage') {
    parts.push('all checks run')
  } else if (basis === 'degraded') {
    parts.push(stopped !== null ? `stopped early: ${stopped}` : 'below target')
  } else if (skips > 0) {
    // Unknown or missing basis (partial replay): keep whatever schedule facts
    // survive instead of throwing.
    parts.push(`${skips} check(s) certified by prior`)
  }
  return parts.length > 0 ? `confidence p≈${p} (${parts.join(' · ')})` : `confidence p≈${p}`
}

function renderVerify(value: VerifyValue): string {
  const v = value ?? ({} as VerifyValue)
  const root = typeof v.root === 'string' ? v.root.slice(0, 12) : '<none>'
  const changed = Array.isArray(v.changed) ? v.changed : []
  const externalChanged = Array.isArray(v.externalChanged) ? v.externalChanged : []
  const regressions = Array.isArray(v.regressions) ? v.regressions : []
  const fixed = Array.isArray(v.fixed) ? v.fixed : []
  const preExisting = Array.isArray(v.preExisting) ? v.preExisting : []
  const unverified = Array.isArray(v.unverified) ? v.unverified : []
  const lines = [
    `GRADE: ${String(v.grade ?? 'unknown').toUpperCase()}   evidence root ${root}`,
    `changed: ${changed.length} file(s) · attribution ${String(v.attributionMethod ?? 'explicit')}` +
      (externalChanged.length > 0 ? ` · ${externalChanged.length} external edit(s)` : '') +
      ` · impact ${String(v.impactPrecision ?? 'approximate')}`,
  ]
  // γ graded trust: one line stating the posterior and how it was earned.
  // Absent on the legacy path so the normal render stays byte-identical.
  const confidence = confidenceLine(v)
  if (confidence !== null) lines.push(confidence)
  lines.push('')
  if (v.degraded === true) {
    // Without this line "impact forced" reads like the caller asked for `all`;
    // the honest cause is that git facts were missing, so everything ran.
    lines.push('⚠ DEGRADED — git facts unavailable → full check set forced: impact analysis was skipped and every discovered check ran.')
    lines.push('')
  }
  if (externalChanged.length > 0) {
    lines.push('EXTERNAL edits (outside your tool stream, not charged to you):')
    for (const f of externalChanged.slice(0, 10)) lines.push(`  ↗ ${f}`)
    lines.push('')
  }
  if (regressions.length > 0) {
    lines.push('REGRESSIONS (vs baseline):')
    for (const r of regressions) lines.push(`  ✖ ${r.label}${r.suspects?.length ? ` — suspects: ${r.suspects.join(', ')}` : ''}${r.detail ? `\n      ${r.detail}` : ''}`)
    lines.push('')
  }
  if (fixed.length > 0) { lines.push('FIXED by this work:'); for (const f of fixed) lines.push(`  ✔ ${f}`); lines.push('') }
  if (preExisting.length > 0) { lines.push('PRE-EXISTING failures (not yours):'); for (const f of preExisting) lines.push(`  · ${f}`); lines.push('') }
  if (unverified.length > 0) { lines.push('STALE — no decisive result for:'); for (const f of unverified) lines.push(`  ? ${f}`); lines.push('') }
  if (typeof v.summary === 'string') lines.push(v.summary)
  return lines.join('\n')
}

function renderClaim(value: ClaimValue): string {
  const v = value ?? ({} as ClaimValue)
  const proven = v.proven === true
  const head = proven ? `✓ PROVEN — ${v.claim ?? ''}` : `✗ NOT PROVEN (${String(v.grade ?? 'unknown').toUpperCase()}) — ${v.claim ?? ''}`
  const root = typeof v.root === 'string' ? v.root.slice(0, 12) : '<none>'
  const lines = [head, `evidence root: ${root}`, '']
  // ζ typed-contract section: present only when the value carries a kind, so a
  // legacy (pre-ζ) replay renders byte-identically — no kind, no section, and
  // every field below is individually guarded against hostile meta.
  const kind = typeof v.kind === 'string' ? v.kind : undefined
  if (kind !== undefined) {
    lines.push(`contract: ${kind}`)
    const obligations = Array.isArray(v.obligations) ? v.obligations : []
    for (const entry of obligations) {
      const o = (entry ?? {}) as { id?: unknown; met?: unknown; detail?: unknown }
      const id = typeof o.id === 'string' ? o.id : 'unknown'
      const detail = typeof o.detail === 'string' ? o.detail : ''
      lines.push(o.met === true ? `  ✓ ${id}` : `  ✖ ${id}${detail.length > 0 ? ` — ${detail}` : ''}`)
    }
    if (v.jury === true) {
      // The cap rides as the claim's confidence on the jury path; stating it
      // here keeps self-attestation from reading like check coverage.
      const cap = typeof v.confidence === 'number' ? ` at p≈${v.confidence.toFixed(2)}` : ''
      lines.push(`  jury evidence — no objective check ran; self-attestation is capped${cap}`)
    }
    lines.push('')
  }
  const blockers = Array.isArray(v.blockers) ? v.blockers : []
  if (blockers.length > 0) {
    lines.push('Blockers:')
    for (const b of blockers) lines.push(`  · ${b}`)
    lines.push('')
  }
  if (typeof v.summary === 'string') lines.push(v.summary)
  return lines.join('\n')
}

/**
 * λ: the jury request render carries the FULL prompt — the juror must read the
 * rubric, claim and context exactly as they were frozen, because that is the
 * text a third party will replay. Total on replay like every render above.
 */
function renderJuryRequest(value: JuryRequestValue): string {
  const v = value ?? ({} as JuryRequestValue)
  const lines: string[] = []
  const instruction = typeof v.instruction === 'string' ? v.instruction : ''
  if (instruction.length > 0) lines.push(`ACTION: ${instruction}`, '')
  const prompt = typeof v.prompt === 'string' ? v.prompt : ''
  lines.push(prompt.length > 0 ? prompt : '(no deliberation prompt on record — do not submit a verdict without one)')
  return lines.join('\n')
}

function renderJurySubmit(value: JurySubmitValue): string {
  const v = value ?? ({} as JurySubmitValue)
  const probability = typeof v.probability === 'number' ? ` (p=${v.probability})` : ''
  const lines = [
    `Class B verdict recorded — ${String(v.verdict ?? 'unknown')}${probability}`
      + ` · gen ${typeof v.gen === 'number' ? v.gen : '?'}`
      + ` · claim ${typeof v.claimId === 'string' ? v.claimId : 'unknown'}`,
  ]
  if (typeof v.factor === 'number') {
    lines.push(`pure factor ${v.factor} (p^0.7 under the default jury trust policy; an abstain carries 1)`)
  }
  if (typeof v.note === 'string' && v.note.length > 0) lines.push('', v.note)
  return lines.join('\n')
}

function renderEndorse(value: EndorseValue): string {
  const v = value ?? ({} as EndorseValue)
  const scope = (v.scope ?? {}) as { claim?: unknown; evidenceRoot?: unknown }
  const root = typeof scope.evidenceRoot === 'string'
    ? scope.evidenceRoot.slice(0, 12)
    : scope.evidenceRoot === null ? 'none (nothing anchored at endorse time)' : 'unknown'
  const lines = [
    `Class C decision recorded — ${String(v.decision ?? 'unknown')} `
      + `by ${typeof v.approver === 'string' ? v.approver : 'unknown approver'}`,
    `claim: ${typeof scope.claim === 'string' ? scope.claim : 'unknown'}`,
    `evidence root reviewed: ${root}`,
  ]
  if (typeof v.note === 'string' && v.note.length > 0) lines.push('', v.note)
  return lines.join('\n')
}

/**
 * ρ: the conjure request render carries the FULL scaffold — the model writes
 * the test from these exact bytes, and the template's own header is where the
 * content-addressing warning lives. The weight note rides between instruction
 * and template so the model knows what the evidence will be worth before it
 * writes a line. Total on replay like every render above.
 */
function renderConjure(value: ConjureValue): string {
  const v = value ?? ({} as ConjureValue)
  const lines: string[] = []
  const instruction = typeof v.instruction === 'string' ? v.instruction : ''
  if (instruction.length > 0) lines.push(instruction, '')
  lines.push(CONJURE_WEIGHT_NOTE, '')
  const template = typeof v.template === 'string' ? v.template : ''
  lines.push(template.length > 0 ? template : '(no scaffold on record — do not write a conjured test without one)')
  return lines.join('\n')
}

/**
 * ρ: the conjure-run render speaks the two protocol outcomes in their own
 * voices: a refusal states the findings and the corrective next step (nothing
 * ran, nothing was recorded), a recorded run states its status, digest and
 * regime — and on a FAIL keeps the output's first informative line, the one
 * line that usually names the assertion that broke. Total on replay.
 */
function renderConjureRun(value: ConjureRunValue | ConjureRefusedValue): string {
  const v = (value ?? {}) as Partial<ConjureRunValue> & Partial<ConjureRefusedValue>
  if (v.recorded !== true) {
    const lines = ['NOT RECORDED — capability screening refused this script; it never ran.']
    const screened = Array.isArray(v.screened) ? v.screened : []
    if (screened.length > 0) {
      lines.push('Findings:')
      for (const finding of screened) lines.push(`  · ${String(finding)}`)
    }
    if (typeof v.reason === 'string' && v.reason.length > 0) lines.push('', v.reason)
    return lines.join('\n')
  }
  const status = typeof v.status === 'string' ? v.status : 'unknown'
  const lines = [
    `SYNTHETIC ${status.toUpperCase()} — recorded on the chain as synthetic evidence.`,
    `digest ${typeof v.scriptDigest === 'string' ? v.scriptDigest.slice(0, 16) : 'unknown'}`
      + ` · sandbox ${String(v.sandbox ?? 'unknown')}`
      + ` · screening ${Array.isArray(v.screened) && v.screened.length > 0 ? `${v.screened.length} finding(s)` : 'clean'}`,
  ]
  if (status === 'fail' || status === 'error' || status === 'timeout') {
    const detail = firstInformativeLine(typeof v.outputHead === 'string' ? v.outputHead : '')
    if (detail.length > 0) lines.push(`first informative output: ${detail}`)
  }
  if (typeof v.note === 'string' && v.note.length > 0) lines.push('', v.note)
  return lines.join('\n')
}

function text(value: string): ContentBlock {
  return { type: 'text', text: value }
}

function oneLine(value: unknown): string {
  if (typeof value !== 'string') return ''
  return truncate(value.replace(/\s+/g, ' ').trim(), 240)
}

function truncate(value: unknown, max: number): string {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function assertActive(exec: ToolRunContext): void {
  if (exec.signal.aborted) throw new Error('verification aborted before it started')
}

export type { ToolResult, ToolResultView, ToolCallView }
