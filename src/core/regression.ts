/**
 * Regression attribution: turning "something is broken" into "this change
 * broke this check, and here is the file that owns it".
 *
 * A regression is charged to the current session only when the check passed at
 * baseline and fails now. Anything already red at baseline is pre-existing and
 * is reported as such — otherwise an agent "fixing" one thing inherits every
 * historical failure and learns to lie about the rest.
 *
 * @module dsh-proof/core/regression
 */

import type { CheckReport, CheckVerdict, Evidence, ProofReport } from './evidence.ts'
import { isDecisiveStatus, verdictOf } from './evidence.ts'
import type { CheckSpec } from './ports.ts'
import type { RelPath } from './impact.ts'
import { attributeChange, isGlobalInvalidator, matchesAny } from './impact.ts'
import type { DependencyGraph } from './impact.ts'
import type { ChangeProvenance } from './changeset.ts'
import type { GradedProofReport } from './report.ts'
import { firstInformativeLine } from './excerpt.ts'

/** The minimum a report needs to decide who owns a red check. */
export interface AttributionInput {
  readonly checks: readonly CheckSpec[]
  readonly baselineById: ReadonlyMap<string, Evidence>
  readonly currentById: ReadonlyMap<string, Evidence>
  readonly changed: readonly RelPath[]
  readonly graph?: DependencyGraph
  /**
   * Provenance of each changed file (agent tool stream vs external edit).
   * Absent for legacy callers — everything then counts as attributable.
   */
  readonly provenance?: ReadonlyMap<RelPath, ChangeProvenance>
}

export interface AttributedCheck extends CheckReport {
  /** Candidate owner files, most specific first. Empty when unattributable. */
  readonly suspects: readonly RelPath[]
  /** Why this verdict was reached, in one line. */
  readonly rationale: string
}

/**
 * Attribute every check in the batch. `attributedTo` is the changed-file subset
 * that lands inside the check's impact set; `suspects` additionally ranks those
 * files by how narrowly they map to this check.
 */
export function attributeChecks(input: AttributionInput): AttributedCheck[] {
  const table = attributeChange(input.checks, input.changed, input.graph)
  const changed = new Set(input.changed)
  const provenance = input.provenance
  const isExternal = (file: RelPath): boolean => provenance?.get(file) === 'external'

  return input.checks.map((spec) => {
    const baseline = input.baselineById.get(spec.id)
    const current = input.currentById.get(spec.id)
    const verdict = verdictOf(baseline, current)

    // Files that (transitively) reach this check's impact set.
    const suspects = new Set<RelPath>()
    for (const [file, owners] of table) {
      if (owners.includes(spec.id)) suspects.add(file)
    }
    for (const file of input.changed) {
      if (spec.paths.includes('*') || matchesAny(file, spec.paths)) suspects.add(file)
    }
    // Blame only what the session (or an explicit assertion) owns; edits that
    // arrived outside the agent's tool stream are reported, not charged.
    const attributedTo = [...suspects].filter(f => changed.has(f) && !isExternal(f)).sort()
    const externalSuspects = [...suspects].filter(f => changed.has(f) && isExternal(f)).sort()

    return {
      checkId: spec.id,
      label: spec.label,
      kind: spec.kind,
      verdict,
      ...(baseline !== undefined ? { baseline } : {}),
      ...(current !== undefined ? { current } : {}),
      attributedTo,
      ...(externalSuspects.length > 0 ? { externalSuspects } : {}),
      suspects: rankSuspects([...suspects], spec),
      rationale: rationaleFor(verdict, spec, baseline, current, attributedTo, externalSuspects),
    }
  })
}

function rankSuspects(files: readonly RelPath[], spec: CheckSpec): RelPath[] {
  return [...files].sort((a, b) => {
    const score = (f: RelPath) => {
      // Ranking only — never correctness. Reuse the one true list of global
      // invalidators instead of a second regex: the old local `.*lock.*`
      // pattern scored `deadlock.ts` and `blockchain.md` as lockfiles.
      if (isGlobalInvalidator(f)) return 0
      if (spec.paths.some(p => p !== '*' && matchesAny(f, [p]))) return 1
      return 2
    }
    const d = score(a) - score(b)
    return d !== 0 ? d : a.length - b.length
  })
}

function rationaleFor(
  verdict: CheckVerdict,
  spec: CheckSpec,
  baseline: Evidence | undefined,
  current: Evidence | undefined,
  attributedTo: readonly RelPath[] = [],
  externalSuspects: readonly RelPath[] = [],
): string {
  const b = baseline?.status ?? 'absent'
  const c = current?.status ?? 'absent'
  switch (verdict) {
    case 'regression':
      if (attributedTo.length === 0 && externalSuspects.length > 0) {
        return `"${spec.label}" passed at baseline (${b}) and now fails (${c}), but every suspect file changed outside the agent's tool stream — external edit, present but not charged to this session.`
      }
      if (externalSuspects.length > 0) {
        return `"${spec.label}" passed at baseline (${b}) and now fails (${c}) — charged to this session (suspects also include external edits: ${externalSuspects.slice(0, 3).join(', ')}).`
      }
      return `"${spec.label}" passed at baseline (${b}) and now fails (${c}) — charged to this session.`
    case 'still-failing':
      return `"${spec.label}" was already failing at baseline (${b}) and still fails (${c}) — pre-existing, not caused here.`
    case 'still-passing':
      return `"${spec.label}" passed at baseline and still passes.`
    case 'fixed':
      return `"${spec.label}" failed at baseline (${b}) and now passes (${c}) — this work fixed it.`
    case 'new-failure':
      return `"${spec.label}" has no baseline and fails (${c}) — cannot distinguish new breakage from pre-existing.`
    case 'new-check':
      return `"${spec.label}" is newly discovered${c === 'absent' ? ' and not yet run' : ` and passes (${c})`}.`
    case 'not-run':
      return `"${spec.label}" was not re-run; its evidence is stale relative to this change set.`
    case 'indeterminate':
      // Two distinct ignorances, one honest verdict each: a baseline that
      // never settled the question, or a current run that could not.
      if (!isDecisiveStatus(baseline?.status)) {
        return `"${spec.label}" had no decisive result at baseline (${b}) — neither credit nor blame can be derived from an unknown.`
      }
      return `"${spec.label}" produced no decisive result this run (${c}) — the question stays open; no credit, no blame.`
  }
}

/**
 * Human-readable regression lines ready for `agent.inject()`. Short on purpose:
 * this is corrective context, not a report.
 */
export function regressionNarrative(checks: readonly AttributedCheck[]): string[] {
  const out: string[] = []
  for (const check of checks) {
    if (check.verdict !== 'regression' && check.verdict !== 'new-failure') continue
    const externalOnly = check.verdict === 'regression' && check.attributedTo.length === 0
      && (check.externalSuspects?.length ?? 0) > 0
    const owners = check.suspects.length > 0
      ? ` Suspect files: ${check.suspects.slice(0, 5).join(', ')}.`
      : ''
    const detail = check.current?.outputHead
      ? ` Last output: ${firstInformativeLine(check.current.outputHead)}`
      : ''
    out.push(`${externalOnly ? '↗' : '✖'} ${check.label}: ${check.rationale}${owners}${detail}`)
  }
  return out
}

/**
 * The display default for the certify target in the narrative — mirrors
 * `certifyTarget`'s config default ("proven (p≈0.97)"). Callers that know the
 * run's actual target can pass it; the plain `ProofReport` carries only the
 * posterior, not the threshold it was certified against.
 */
const DEFAULT_CERTIFY_TARGET = 0.97

/** Plain-language summary of what is and is not proven. */
export function proofNarrative(report: ProofReport, certifyTarget: number = DEFAULT_CERTIFY_TARGET): string {
  const s = report.summary
  const parts = [
    `${report.grade.toUpperCase()}`,
    `${s.passing} passing`,
    `${s.failing} failing`,
  ]
  if (s.regressions > 0) parts.push(`${s.regressions} regression(s)`)
  if (s.fixed > 0) parts.push(`${s.fixed} fixed`)
  if (s.preExisting > 0) parts.push(`${s.preExisting} pre-existing failure(s)`)
  if (s.indeterminate > 0) parts.push(`${s.indeterminate} indeterminate`)
  if (report.unverified.length > 0) parts.push(`${report.unverified.length} stale/unrun`)
  // β graded trust: with a posterior on the report the grade line becomes a
  // trust statement — `PROVEN (p≈0.97)` / `STALE (p≈0.61, target 0.97)`. The
  // counts keep their exact legacy form; only the head grows a tail. Whether
  // the target was met is read off `confidenceBasis` first (the report's own
  // record of certification) with the numeric comparison as fallback, so a
  // deployment with a non-default target still reads correctly.
  const graded = report as GradedProofReport
  if (graded.confidence !== undefined) {
    const p = graded.confidence.toFixed(2)
    const met = graded.confidenceBasis === 'certified-subset' || graded.confidence >= certifyTarget
    const head = met
      ? `${report.grade.toUpperCase()} (p≈${p})`
      : `${report.grade.toUpperCase()} (p≈${p}, target ${certifyTarget.toFixed(2)})`
    return [head, ...parts.slice(1)].join(' — ')
  }
  return parts.join(' · ')
}
