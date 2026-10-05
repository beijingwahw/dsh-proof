/**
 * The four model-facing tools.
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
import type { AuditReport, ProofGrade, ProofReport } from '../core/evidence.ts'
import { proofNarrative } from '../core/regression.ts'
import { firstInformativeLine } from '../core/excerpt.ts'

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
  /** Checks that regressed against the baseline — blame, not credit. */
  regressions: VerifyValue['regressions']
  blockers: string[]
  summary: string
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
  changed: {
    type: 'array',
    items: { type: 'string' },
    description: 'Files this session changed, relative to the workspace root.',
  },
}

export function createProofTools(engine: ProofEngine, touched?: () => readonly string[]): ToolDefinition[] {
  return [
    createStatusTool(engine),
    createBaselineTool(engine),
    createVerifyTool(engine, touched),
    createClaimTool(engine, touched),
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
      return {
        card: 'generic',
        title: meta?.proven === true ? '✓ Proven' : `✗ Not proven · ${meta?.grade ?? 'unknown'}`,
        content: [text(meta?.summary ? oneLine(meta.summary) : 'no claim result')],
      }
    },
    async execute(args, exec: ToolRunContext) {
      assertActive(exec)
      const parsed = (args ?? {}) as { claim: string; changed?: string[] }
      const outcome = await engine.verify({
        ...(Array.isArray(parsed.changed) ? { changed: parsed.changed } : {}),
        ...(touched !== undefined ? { touched: touched() } : {}),
        signal: exec.signal,
      })
      const verified = toVerifyValue(
        outcome.report, outcome.changed, outcome.checks, outcome.selection, outcome.attribution, outcome.degraded,
      )
      return toClaimValue(parsed.claim, outcome.report, verified) as unknown as JsonValue
    },
  }
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
  report: ProofReport,
  changed: readonly string[],
  checks: readonly { label: string; verdict: string; suspects: readonly string[]; current?: { outputHead?: string } }[],
  selection?: { readonly untouched?: readonly unknown[]; readonly precision?: string },
  attribution?: { method: string; records: readonly { path: string; provenance: string }[] },
  degraded?: true,
): VerifyValue {
  const externalChanged = attribution?.records.filter(r => r.provenance === 'external').map(r => r.path) ?? []
  // The check list covers every discovered spec (attribution included), so the
  // old `discovered - checks.length` formula was structurally always 0 — the
  // honest count of proven-untouched checks lives on the selection itself.
  const untouched = selection?.untouched
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

export function toClaimValue(claim: string, report: ProofReport, verified: VerifyValue): ClaimValue {
  const blockers: string[] = []
  if (report.grade === 'no-baseline') blockers.push('No baseline exists. Run proof_baseline first.')
  if (report.grade === 'stale') blockers.push(`Stale evidence: ${report.unverified.join(', ') || 'affected checks not re-run'}.`)
  for (const reg of verified.regressions) blockers.push(`Regression: ${reg.label} — ${reg.detail}`)
  if (report.grade === 'unproven') blockers.push('Verification was incomplete (skipped, aborted or timed out).')

  return {
    claim,
    grade: report.grade,
    proven: report.grade === 'proven',
    root: report.root,
    regressions: verified.regressions,
    blockers,
    summary: report.grade === 'proven'
      ? `PROVEN — "${claim}" is backed by evidence root ${report.root.slice(0, 12)}: `
        + `${report.summary.passing} check(s) passing, ${report.summary.regressions} regression(s), `
        + `${report.summary.preExisting} pre-existing failure(s) left untouched.`
      : `NOT PROVEN (${report.grade}) — "${claim}". ${blockers.join(' ')}`,
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
    '',
  ]
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
  const blockers = Array.isArray(v.blockers) ? v.blockers : []
  if (blockers.length > 0) {
    lines.push('Blockers:')
    for (const b of blockers) lines.push(`  · ${b}`)
    lines.push('')
  }
  if (typeof v.summary === 'string') lines.push(v.summary)
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
