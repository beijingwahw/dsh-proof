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
import type { ProofGrade, ProofReport } from '../core/evidence.ts'
import { proofNarrative } from '../core/regression.ts'

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
}

export interface VerifyValue {
  grade: ProofGrade
  root: string
  changed: string[]
  affectedChecks: number
  untouchedChecks: number
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
  verified: VerifyValue['regressions']
  blockers: string[]
  summary: string
}

// ---------------------------------------------------------------------------
// Value -> canonical JSON projection (shared by render + presentationMeta)
// ---------------------------------------------------------------------------

function toStatusValue(value: StatusValue): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue
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

export function createProofTools(engine: ProofEngine): ToolDefinition[] {
  return [
    createStatusTool(engine),
    createBaselineTool(engine),
    createVerifyTool(engine),
    createClaimTool(engine),
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
          dirtyFiles: { type: 'integer' },
          summary: { type: 'string' },
        },
      },
      render: (_args, value) => [text(renderStatus(value as unknown as StatusValue))],
      presentationMeta: (_args, value) => toStatusValue(value as unknown as StatusValue),
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

      const value: StatusValue = {
        hasBaseline: baseline !== undefined,
        baselineCreatedAt: baseline?.createdAt ?? null,
        baselineRoot: baseline?.root ?? null,
        discovered: specs.length,
        checks,
        evidenceRecords: audit.total,
        evidenceLogIntact: audit.ok,
        dirtyFiles: snapshot.dirty.length,
        summary: baseline === undefined
          ? `No baseline. ${specs.length} objective check(s) discovered. Establish one with proof_baseline before editing.`
          : `Baseline from ${baseline.createdAt} (${baseline.checks.length} checks, root ${baseline.root.slice(0, 12)}). `
            + `${specs.length} check(s) discovered, ${audit.total} evidence record(s), `
            + `${audit.ok ? 'log intact' : `LOG CORRUPT (${audit.corrupt.length})`}, ${snapshot.dirty.length} dirty file(s).`,
      }
      return value as unknown as JsonValue
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
        title: meta?.ok ? `Baseline established · ${meta.passing}/${meta.ran} passing` : 'Baseline failed',
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
      const passing = records.filter(r => r.status === 'pass').length
      const failing = records.filter(r => r.status === 'fail' || r.status === 'error' || r.status === 'timeout').length
      const skipped = records.filter(r => r.status === 'skipped' || r.status === 'aborted').length
      const value: BaselineValue = {
        ok: failing === 0 && skipped === 0,
        baselineId: baseline.baselineId,
        root: baseline.root,
        ran: records.length,
        passing, failing, skipped,
        durationMs: records.reduce((acc, r) => acc + r.durationMs, 0),
        failingLabels: records.filter(r => r.status !== 'pass' && r.status !== 'skipped').map(r => r.label),
        summary: `Baseline ${baseline.baselineId.slice(0, 12)}: ${passing} passing, ${failing} failing, ${skipped} skipped/unrun `
          + `across ${records.length} check(s). Failures here are pre-existing — they are NOT charged to later work.`,
      }
      return value as unknown as JsonValue
    },
  }
}

function createVerifyTool(engine: ProofEngine): ToolDefinition {
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
          affectedChecks: { type: 'integer' }, untouchedChecks: { type: 'integer' },
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
        signal: exec.signal,
      })
      return toVerifyValue(outcome.report, outcome.changed, outcome.checks) as unknown as JsonValue
    },
  }
}

function createClaimTool(engine: ProofEngine): ToolDefinition {
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
          verified: {
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
        signal: exec.signal,
      })
      const value = toVerifyValue(outcome.report, outcome.changed, outcome.checks)
      const blockers: string[] = []
      if (outcome.report.grade === 'no-baseline') blockers.push('No baseline exists. Run proof_baseline first.')
      if (outcome.report.grade === 'stale') blockers.push(`Stale evidence: ${outcome.report.unverified.join(', ') || 'affected checks not re-run'}.`)
      for (const reg of value.regressions) blockers.push(`Regression: ${reg.label} — ${reg.detail}`)
      if (outcome.report.grade === 'unproven') blockers.push('Verification was incomplete (skipped, aborted or timed out).')

      const claim: ClaimValue = {
        claim: parsed.claim,
        grade: outcome.report.grade,
        proven: outcome.report.grade === 'proven',
        root: outcome.report.root,
        verified: value.regressions,
        blockers,
        summary: outcome.report.grade === 'proven'
          ? `PROVEN — "${parsed.claim}" is backed by evidence root ${outcome.report.root.slice(0, 12)}: `
            + `${outcome.report.summary.passing} check(s) passing, ${outcome.report.summary.regressions} regression(s), `
            + `${outcome.report.summary.preExisting} pre-existing failure(s) left untouched.`
          : `NOT PROVEN (${outcome.report.grade}) — "${parsed.claim}". ${blockers.join(' ')}`,
      }
      return claim as unknown as JsonValue
    },
  }
}

// ---------------------------------------------------------------------------
// Pure projections
// ---------------------------------------------------------------------------

function toVerifyValue(report: ProofReport, changed: readonly string[], checks: readonly { label: string; verdict: string; suspects: readonly string[]; current?: { outputHead?: string } }[]): VerifyValue {
  return {
    grade: report.grade,
    root: report.root,
    changed: [...changed],
    affectedChecks: checks.filter(c => c.verdict !== 'not-run').length,
    untouchedChecks: Math.max(0, report.discovered - checks.length),
    regressions: checks
      .filter(c => c.verdict === 'regression' || c.verdict === 'new-failure')
      .map(c => ({
        label: c.label,
        suspects: [...c.suspects].slice(0, 5),
        detail: firstLine(c.current?.outputHead ?? ''),
      })),
    fixed: checks.filter(c => c.verdict === 'fixed').map(c => c.label),
    preExisting: checks.filter(c => c.verdict === 'still-failing').map(c => c.label),
    unverified: [...report.unverified],
    passing: report.summary.passing,
    failing: report.summary.failing,
    summary: proofNarrative(report),
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
  const regressions = Array.isArray(v.regressions) ? v.regressions : []
  const fixed = Array.isArray(v.fixed) ? v.fixed : []
  const preExisting = Array.isArray(v.preExisting) ? v.preExisting : []
  const unverified = Array.isArray(v.unverified) ? v.unverified : []
  const lines = [
    `GRADE: ${String(v.grade ?? 'unknown').toUpperCase()}   evidence root ${root}`,
    `changed: ${changed.length} file(s) · affected ${v.affectedChecks ?? 0} check(s) · untouched ${v.untouchedChecks ?? 0}`,
    '',
  ]
  if (regressions.length > 0) {
    lines.push('REGRESSIONS (caused by this work):')
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

function firstLine(value: unknown): string {
  if (typeof value !== 'string') return ''
  return truncate(value.split('\n').find(l => l.trim().length > 0) ?? '', 160)
}

function truncate(value: unknown, max: number): string {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function assertActive(exec: ToolRunContext): void {
  if (exec.signal.aborted) throw new Error('verification aborted before it started')
}

export type { ToolResult, ToolResultView, ToolCallView }
