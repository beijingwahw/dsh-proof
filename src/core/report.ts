/**
 * Proof assembly: the verdict the model is allowed to state, and the root that
 * makes it recomputable by anyone holding the evidence log.
 *
 * Grades are deliberately pessimistic. "Proven" means: a baseline exists, every
 * check the change set touches was re-run, and none of them regressed. Anything
 * less is `unproven` — the model may still say the task is done, but the plugin
 * will not co-sign it.
 *
 * @module dsh-proof/core/report
 */

import type {
  Baseline, CheckReport, Evidence, ProofGrade, ProofReport, WorkspaceSnapshot,
} from './evidence.ts'
import { buildBaseline } from './evidence.ts'
import { merkleRoot } from './hash.ts'
import type { CheckSpec, Clock } from './ports.ts'
import type { RelPath, DependencyGraph } from './impact.ts'
import { selectAffectedChecks } from './impact.ts'
import { attributeChecks, type AttributedCheck } from './regression.ts'
import type { ChangeProvenance } from './changeset.ts'

export interface AssembleInput {
  readonly specs: readonly CheckSpec[]
  readonly baseline?: Baseline | undefined
  readonly records: readonly Evidence[]
  readonly changed: readonly RelPath[]
  readonly graph?: DependencyGraph
  readonly workspace: WorkspaceSnapshot
  readonly clock: Clock
  /** Provenance per changed file: agent tool stream vs external edit (v0.3). */
  readonly provenance?: ReadonlyMap<RelPath, ChangeProvenance>
  /** When true, an incremental run must cover every affected check to be `proven`. */
  readonly requireFullCoverage?: boolean
  /** When true, impact analysis is bypassed and every check counts as affected. */
  readonly forceAll?: boolean
}

export interface AssembleResult {
  readonly report: ProofReport
  readonly checks: readonly AttributedCheck[]
}

export function assembleProof(input: AssembleInput): AssembleResult {
  const baselineById = new Map((input.baseline?.checks ?? []).map(e => [e.checkId, e]))
  const currentById = new Map(input.records.map(e => [e.checkId, e]))

  const attributed = attributeChecks({
    checks: input.specs,
    baselineById,
    currentById,
    changed: input.changed,
    ...(input.graph !== undefined ? { graph: input.graph } : {}),
    ...(input.provenance !== undefined ? { provenance: input.provenance } : {}),
  })

  const selection = input.forceAll === true
    ? { affected: input.specs, untouched: [], forcedAll: true, closure: input.changed, uncertain: false, precision: 'forced' as const }
    : selectAffectedChecks(input.specs, input.changed, input.graph)
  const affectedIds = new Set(selection.affected.map(c => c.id))

  // Coverage: an affected check counts as verified only when this run produced
  // a decisive outcome for it. `skipped`, `aborted`, `timeout` and silence all
  // mean the same thing to a reader: no verdict, so no proof.
  const unverified = [...affectedIds].filter((id) => {
    const record = currentById.get(id)
    return record === undefined || !DECISIVE.has(record.status)
  }).sort()

  const grade = decideGrade({
    hasBaseline: input.baseline !== undefined,
    changed: input.changed,
    affectedCount: affectedIds.size,
    unverifiedCount: unverified.length,
    discoveredCount: input.specs.length,
    records: input.records,
    attributed,
    requireFullCoverage: input.requireFullCoverage ?? true,
  })

  const summary = {
    passing: attributed.filter(c => isPassing(c.verdict)).length,
    failing: attributed.filter(c => isFailing(c.verdict)).length,
    regressions: attributed.filter(c => c.verdict === 'regression').length,
    fixed: attributed.filter(c => c.verdict === 'fixed').length,
    preExisting: attributed.filter(c => c.verdict === 'still-failing').length,
    newChecks: attributed.filter(c => c.verdict === 'new-check').length,
  }

  const report: ProofReport = {
    grade,
    root: merkleRoot(input.records.map(r => r.evidenceId)),
    baselineRoot: input.baseline?.root ?? null,
    baselineCreatedAt: input.baseline?.createdAt ?? null,
    generatedAt: new Date(input.clock.now()).toISOString(),
    workspace: input.workspace,
    checks: attributed.map(toCheckReport),
    discovered: input.specs.length,
    unverified,
    summary,
    regressions: attributed
      .filter(c => c.verdict === 'regression' || c.verdict === 'new-failure')
      .map(c => `${c.label}: ${c.rationale}`),
  }

  return { report, checks: attributed }
}

/** Build the baseline view over a full run. */
export function assembleBaseline(
  specs: readonly CheckSpec[],
  records: readonly Evidence[],
  workspace: WorkspaceSnapshot,
  clock: Clock,
): Baseline {
  void specs
  return buildBaseline(records, workspace, clock)
}

interface GradeInput {
  hasBaseline: boolean
  changed: readonly RelPath[]
  affectedCount: number
  unverifiedCount: number
  discoveredCount: number
  records: readonly Evidence[]
  attributed: readonly AttributedCheck[]
  requireFullCoverage: boolean
}

/** Statuses that actually answer the question. */
const DECISIVE = new Set(['pass', 'fail'])

function decideGrade(input: GradeInput): ProofGrade {
  const regressions = input.attributed.filter(c => c.verdict === 'regression').length
  const newFailures = input.attributed.filter(c => c.verdict === 'new-failure').length

  if (!input.hasBaseline) return 'no-baseline'
  if (regressions > 0 || newFailures > 0) return 'regressed'
  if (input.unverifiedCount > 0 && input.requireFullCoverage) return 'stale'
  // Nothing objective speaks for the claim: the workspace declares no checks,
  // or the change set touches none of them. Honest answer is "unproven".
  if (input.discoveredCount === 0 || input.affectedCount === 0) return 'unproven'
  return 'proven'
}

function isPassing(verdict: CheckReport['verdict']): boolean {
  return verdict === 'still-passing' || verdict === 'fixed' || verdict === 'new-check'
}

function isFailing(verdict: CheckReport['verdict']): boolean {
  return verdict === 'regression' || verdict === 'still-failing' || verdict === 'new-failure'
}

function toCheckReport(check: AttributedCheck): CheckReport {
  return {
    checkId: check.checkId,
    label: check.label,
    kind: check.kind,
    verdict: check.verdict,
    ...(check.baseline !== undefined ? { baseline: check.baseline } : {}),
    ...(check.current !== undefined ? { current: check.current } : {}),
    attributedTo: check.attributedTo,
    ...(check.externalSuspects !== undefined ? { externalSuspects: check.externalSuspects } : {}),
  }
}
