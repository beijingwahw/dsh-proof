/**
 * The `proof:policy` system-prompt section.
 *
 * Prompt text is deliberately short and imperative. The enforcement lives in
 * the tool pipeline; this section only tells the model the rules exist so it
 * does not have to discover them by failing.
 *
 * @module dsh-proof/dsh/prompt
 */

import type { CheckSpec } from '../core/ports.ts'

export interface PromptFacts {
  readonly discovered: readonly CheckSpec[]
  readonly hasBaseline: boolean
  readonly requireBaseline: 'off' | 'warn' | 'ask'
}

/**
 * B8-L7: `label` and `command` come from package.json discovery — workspace-
 * writable data injected into the system prompt's authoritative voice. Newlines
 * could forge extra rule lines, backticks could break the code spans; both are
 * flattened to spaces and the result capped, so a check's name may only ever
 * arrive as one inert line of text.
 */
const SPEC_TEXT_CAP = 120

function sanitizeSpecText(value: string): string {
  const flattened = value.replace(/[\r\n`]+/g, ' ').trim()
  return flattened.length > SPEC_TEXT_CAP ? `${flattened.slice(0, SPEC_TEXT_CAP)}…` : flattened
}

export function buildPolicySection(facts: PromptFacts): string {
  const lines: string[] = [
    '# Completion proof (proof:policy)',
    '',
    'This workspace verifies claims with `dsh-proof`. "Done" is a statement about evidence, not about effort.',
    '',
    'Rules:',
    '1. Before editing, call `proof_baseline` (or confirm one exists with `proof_status`). The baseline decides what later failures are *yours*.',
    '2. Do not assert completion in prose. Call `proof_claim` with the exact claim; it re-runs the objective checks this change set made stale and returns `proven: true` only when nothing regressed.',
    '3. A check that passed at baseline and now fails is a REGRESSION caused by this work — fix it before claiming done. A check already failing at baseline is pre-existing; leave it, but say so.',
    '4. If `proof_claim` returns `proven: false`, its `blockers` are the contract. Work them off, then claim again.',
    '5. If you are told files changed outside your tool calls, re-read them. Your in-context copies are stale.',
  ]

  if (facts.requireBaseline !== 'off') {
    lines.push(`6. Baseline policy is \`${facts.requireBaseline}\`: mutation tools ${facts.requireBaseline === 'ask' ? 'require user approval' : 'warn'} until a baseline exists.`)
  }

  lines.push('')
  if (facts.discovered.length === 0) {
    lines.push('No objective checks are currently discovered in this workspace. Proof will be limited to `no-baseline`/`stale` grades; add test/build/lint scripts or explicit `checks` in the plugin config to enable real proof.')
  } else {
    lines.push(`Objective checks available (${facts.discovered.length}):`)
    for (const spec of facts.discovered.slice(0, 12)) {
      lines.push(`  · [${sanitizeSpecText(spec.kind)}] ${sanitizeSpecText(spec.label)} — \`${sanitizeSpecText(spec.command.join(' '))}\``)
    }
    if (facts.discovered.length > 12) lines.push(`  · …and ${facts.discovered.length - 12} more (see proof_status)`)
  }
  lines.push('')
  lines.push(facts.hasBaseline
    ? 'A baseline is already established for this workspace.'
    : '⚠️ No baseline is established yet. Establish one before your first edit.')
  return lines.join('\n')
}
