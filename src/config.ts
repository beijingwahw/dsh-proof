/**
 * Plugin configuration.
 *
 * DSH's rule: "anything two deployments may want to set differently is a
 * configuration field". Nothing tunable is hardcoded here.
 *
 * @module dsh-proof/config
 */

import Schema from '@deepseek-ai/schemastery'

export interface CheckEntryConfig {
  label?: string
  command: string | string[]
  kind?: 'test' | 'build' | 'lint' | 'typecheck' | 'other'
  paths?: string[]
  timeoutMs?: number
  exclusive?: boolean
}

export interface Config {
  /** Where evidence lives, relative to the workspace root. */
  evidenceDir: string
  /** Discover objective checks from the project's own build metadata. */
  autoDiscover: boolean
  /** Explicit checks, merged over (or instead of) auto-discovery. */
  checks: CheckEntryConfig[]
  /** Per-check timeout in milliseconds. */
  checkTimeoutMs: number
  /** Total verification budget for one `proof_verify` call, in milliseconds. */
  verifyBudgetMs: number
  /** Concurrent check processes. */
  concurrency: number
  /** Build the reverse-dependency graph for precise impact analysis. */
  impactGraph: boolean
  /** Hard cap on graph size, so a monorepo cannot stall the plugin. */
  impactGraphLimit: number
  /**
   * Block mutation tools until a baseline exists. `off` never blocks, `warn`
   * attaches a corrective notice, `ask` routes the call through user approval.
   */
  requireBaseline: 'off' | 'warn' | 'ask'
  /** Watch for workspace changes the agent did not make and surface them. */
  driftDetection: boolean
  /** Staleness threshold for drift notices, in milliseconds. */
  driftNoticeMs: number
  /** Inject a corrective message when the turn ends with unproven claims. */
  enforceOnTurnEnd: boolean
  /** Add a `proof:policy` section to the system prompt. */
  promptSection: boolean
  /** Namespace for the prompt section; lets a deployment shadow ours. */
  promptScope: string
  /** Maximum evidence head retained per record, in characters. */
  headChars: number
  /** Emit plugin diagnostics to stdout. */
  verbose: boolean
}

export const Config: Schema<Config> = Schema.object({
  evidenceDir: Schema.string().default('.proof'),
  autoDiscover: Schema.boolean().default(true),
  checks: Schema.array(Schema.object({
    label: Schema.string(),
    command: Schema.union([Schema.string(), Schema.array(Schema.string())]).required(),
    kind: Schema.union(['test', 'build', 'lint', 'typecheck', 'other']),
    paths: Schema.array(Schema.string()),
    timeoutMs: Schema.number(),
    exclusive: Schema.boolean(),
  })).default([]),
  checkTimeoutMs: Schema.number().default(120_000),
  verifyBudgetMs: Schema.number().default(300_000),
  concurrency: Schema.number().default(2),
  impactGraph: Schema.boolean().default(true),
  impactGraphLimit: Schema.number().default(20_000),
  requireBaseline: Schema.union(['off', 'warn', 'ask']).default('warn'),
  driftDetection: Schema.boolean().default(true),
  driftNoticeMs: Schema.number().default(1_500),
  enforceOnTurnEnd: Schema.boolean().default(true),
  promptSection: Schema.boolean().default(true),
  promptScope: Schema.string().default('proof:policy'),
  headChars: Schema.number().default(2_000),
  verbose: Schema.boolean().default(false),
}) as unknown as Schema<Config>
