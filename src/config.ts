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
  /**
   * Where the evidence log lives. `host` keeps it under the host trust root
   * (`$DSH_HOME/proof/workspaces/<key>`), outside the agent's writable
   * workspace — the default and the recommended setting. `workspace` puts it
   * back at `evidenceDir` inside the project (legacy behaviour; still
   * chain- and checkpoint-protected, but the agent could read or delete it).
   */
  evidenceStore: 'host' | 'workspace'
  /** Where evidence lives, relative to the workspace root (workspace mode only). */
  evidenceDir: string
  /**
   * Host-side trust root: checkpoint signing keys and rewind anchors. Must
   * stay outside every agent-writable workspace. Defaults to
   * `$DSH_PROOF_TRUST_DIR` or `$DSH_HOME/proof`.
   */
  trustDir: string | undefined
  /** Append a signed checkpoint after this many records (boundaries always do). */
  checkpointEvery: number
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
  /**
   * Scheduling strategy for `proof_verify` (β). `bayesian` (the default and
   * this version's product stance) ranks the affected checks by expected
   * information gain per unit cost, runs them in waves, updates each check's
   * health posterior from the wave's real outcomes, and stops as soon as the
   * claim probability crosses `certifyTarget` — "proven (p≈0.97)" instead of
   * all-or-nothing. `set` is the behavioural escape hatch: the legacy
   * whole-batch run with legacy grading, for deployments that must reproduce
   * pre-β outcomes exactly.
   */
  scheduler: 'bayesian' | 'set'
  /**
   * Posterior probability the whole affected set must reach before the claim
   * is certified without running every check. The "p≈" in `proven (p≈0.97)`.
   */
  certifyTarget: number
  /** Build the reverse-dependency graph for precise impact analysis. */
  impactGraph: boolean
  /** Hard cap on graph size, so a monorepo cannot stall the plugin. */
  impactGraphLimit: number
  /**
   * Use the host's LSP (when a language server is available) to verify and
   * extend impact edges — including tsconfig `paths` aliases and other
   * workspace-internal imports regex cannot resolve.
   */
  lspImpact: boolean
  /** Maximum language-server round-trips per graph build. */
  lspQueryBudget: number
  /**
   * Block mutation tools until a baseline exists. `off` never blocks, `warn`
   * attaches a corrective notice, `ask` routes the call through user approval.
   */
  requireBaseline: 'off' | 'warn' | 'ask'
  /** Watch for workspace changes the agent did not make and surface them. */
  driftDetection: boolean
  /** Inject a corrective message when the turn ends with unproven claims. */
  enforceOnTurnEnd: boolean
  /** Add a `proof:policy` section to the system prompt. */
  promptSection: boolean
  /** Namespace for the prompt section; lets a deployment shadow ours. */
  promptScope: string
  /**
   * How check output is excerpted into evidence records. `balanced` (default)
   * keeps head + salient failure lines + tail under the budget; `head` is the
   * legacy first-N-characters behaviour.
   */
  excerptStrategy: 'head' | 'balanced'
  /** Excerpt budget per evidence record, in characters. */
  headChars: number
  /**
   * Canonicalise the user's home directory to `$HOME` in captured output —
   * keeps usernames out of evidence records (privacy) and makes digests
   * identical across machines (cross-machine comparability).
   */
  normalizeHome: boolean
  /** Emit plugin diagnostics to stdout. */
  verbose: boolean
}

export const Config: Schema<Config> = Schema.object({
  evidenceStore: Schema.union(['host', 'workspace']).default('host'),
  evidenceDir: Schema.string().default('.proof'),
  trustDir: Schema.string(),
  checkpointEvery: Schema.number().default(25),
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
  scheduler: Schema.union(['bayesian', 'set']).default('bayesian'),
  // 0–1 posterior displayed as a percentage by schema-aware hosts; the
  // meaningful band is 0.5–0.999 (below 0.5 certifies nothing, 1.0 is
  // unreachable by construction — every factor keeps a flake residual).
  certifyTarget: Schema.percent().default(0.97),
  impactGraph: Schema.boolean().default(true),
  impactGraphLimit: Schema.number().default(20_000),
  lspImpact: Schema.boolean().default(true),
  lspQueryBudget: Schema.number().default(400),
  requireBaseline: Schema.union(['off', 'warn', 'ask']).default('warn'),
  driftDetection: Schema.boolean().default(true),
  enforceOnTurnEnd: Schema.boolean().default(true),
  promptSection: Schema.boolean().default(true),
  promptScope: Schema.string().default('proof:policy'),
  excerptStrategy: Schema.union(['head', 'balanced']).default('balanced'),
  headChars: Schema.number().default(2_000),
  normalizeHome: Schema.boolean().default(true),
  verbose: Schema.boolean().default(false),
}) as unknown as Schema<Config>
