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
  kind?: 'test' | 'build' | 'lint' | 'typecheck' | 'benchmark' | 'other'
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
  /**
   * Entry points (workspace-relative paths) for the API-surface snapshot the
   * baseline carries. Default `[]` means the engine derives them from the
   * project's own `package.json` (`main`, `exports["."]`, `types`) — set this
   * only when the declared fields do not point at the real source entries.
   */
  apiEntryPoints?: string[]
  /**
   * Confidence ceiling for docs-only claims (ζ). A docs-only change is judged
   * by jury review (the author's self-attestation) rather than objective
   * checks, so its `proven` grade can never carry more confidence than this
   * cap — honest self-reporting, structurally bounded.
   */
  juryConfidenceCap: number
  /**
   * Trust weight for Class B evidence — an LLM jury's on-chain verdict (κ).
   * The weight is a log-odds exponent: a B-class factor is the jury's own
   * `probability` raised to this power, so a weak witness can only ever
   * *weaken* a claim (any probability below 1 discounts; nothing inflates).
   */
  classBTrust: number
  /**
   * Trust weight for Class C evidence — a human endorsement or rejection (κ).
   * Same log-odds-exponent semantics as `classBTrust`: an endorse discounts
   * gently (0.95^0.9 ≈ 0.955), a reject collapses the claim ((1-0.95)^0.9).
   */
  classCTrust: number
  /**
   * π: where conjured-test sandboxes live, relative to the workspace root.
   * `proof_conjure_request` scaffolds templates here, the model writes its
   * test next to them, and `proof_conjure_run` executes it inside this
   * directory. Discovery ignores it (it rides `DEFAULT_IGNORE_DIRS`), so a
   * sandbox never becomes an objective check by accident.
   */
  syntheticDir: string
  /**
   * π: β priced into agent-authored (synthetic) checks — P(observed pass |
   * actually broken). A test written by the claim's interested party is
   * evidence, but weaker evidence than a check the workspace declared
   * before the claim existed; 0.15 prices that conflict of interest
   * (vs the 0.02 organic default in `core/bayes.ts`).
   */
  syntheticFalsePass: number
  /** π: cooperative timeout for one conjured-test execution, in milliseconds. */
  syntheticTimeoutMs: number
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
    kind: Schema.union(['test', 'build', 'lint', 'typecheck', 'benchmark', 'other']),
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
  // ζ: `[]` = derive entry points from package.json; an explicit list wins.
  apiEntryPoints: Schema.array(Schema.string()).default([]),
  // ζ: docs-only self-attestation tops out below objective proof — the same
  // percent band as certifyTarget (0–1), defaulted to a deliberately humble 0.8.
  juryConfidenceCap: Schema.percent().default(0.8),
  // κ: graded-evidence trust weights — log-odds exponents, so weak witnesses
  // can only weaken a claim (probability^weight < 1 whenever probability < 1).
  classBTrust: Schema.percent().default(0.7),
  classCTrust: Schema.percent().default(0.9),
  // π: PTC synthesis — the sandbox the model writes conjured tests into, the
  // false-pass rate its tests are priced at, and how long one may run. All
  // three mirror the engine-side defaults (`core/synthetic.ts` /
  // `ProofEngine`), exposed here because two deployments may disagree on how
  // much an interested party's own test is worth.
  syntheticDir: Schema.string().default('.proof-synthetic'),
  syntheticFalsePass: Schema.percent().default(0.15),
  syntheticTimeoutMs: Schema.number().default(60_000),
  verbose: Schema.boolean().default(false),
}) as unknown as Schema<Config>
