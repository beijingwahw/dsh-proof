/**
 * Plugin configuration.
 *
 * DSH's rule: "anything two deployments may want to set differently is a
 * configuration field". Nothing tunable is hardcoded here.
 *
 * @module dsh-proof/config
 */
import Schema from '@deepseek-ai/schemastery';
// W15-L12: the certifyTarget default is bound by import to core/bayes's one
// true constant, not re-typed here (re-exported for callers that know it as
// a config fact).
import { DEFAULT_CERTIFY_TARGET } from "./core/bayes.js";
export { DEFAULT_CERTIFY_TARGET };
export const Config = Schema.object({
    evidenceStore: Schema.union(['host', 'workspace']).default('host'),
    // M-48 + W11-L-H: a segment that collapses to nothing ('.', './', '') parks
    // the log at the workspace root where the guard's prefix comparison can
    // never match, and `a/..` reaches the same collapse at RUNTIME while
    // passing a pure-dot pattern — any `..` SEGMENT (either separator flavour)
    // is rejected here rather than silently disarming workspace mode. V5-M3:
    // a DRIVE-ABSOLUTE spelling ('C:/outside') gets syntheticDir's arm too —
    // it walks past the `(?!\/)` leading-slash guard and parks the store
    // outside the workspace while the workspace-mode guard keeps comparing as
    // if it were inside (structural net self-dismantled by configuration).
    // The runtime guards (paths.ts foldHostPath) still fold defensively; this
    // is the loud first line.
    evidenceDir: Schema.string().pattern(/^(?![./\\]+$)(?!\/)(?![A-Za-z]:)(?!.*(?:^|[\/\\])\.\.(?:[\/\\]|$)).+$/).default('.proof'),
    // "Must stay outside every agent-writable workspace" (see the interface
    // comment) is enforced as a loud containment warn at derivation time
    // (adapters/shared/paths.ts), where the workspace root is finally known —
    // a schema field cannot see both values at once. A RELATIVE trust root now
    // fails loudly there too (X-H-15).
    trustDir: Schema.string(),
    // Positive domains (M-46): a zero/negative checkpoint cadence, timeout,
    // budget or worker count silently changes engine behaviour (never vs every
    // record checkpoints; checks that cannot be dispatched at all).
    checkpointEvery: Schema.number().step(1).min(1).default(25),
    autoDiscover: Schema.boolean().default(true),
    checks: Schema.array(Schema.object({
        label: Schema.string(),
        command: Schema.union([Schema.string(), Schema.array(Schema.string())]).required(),
        kind: Schema.union(['test', 'build', 'lint', 'typecheck', 'benchmark', 'other']),
        paths: Schema.array(Schema.string()),
        // Y-L-18 (v0.24): the per-check override gets checkTimeoutMs's positive
        // domain — a 0/negative override used to sail past the schema and become
        // a check that can only ever time out (constant red, the over-rejection
        // direction), discovered one run at a time instead of at config load.
        timeoutMs: Schema.number().min(1),
        exclusive: Schema.boolean(),
    })).default([]),
    checkTimeoutMs: Schema.number().min(1).default(120_000),
    verifyBudgetMs: Schema.number().min(1).default(300_000),
    concurrency: Schema.number().step(1).min(1).max(64).default(2),
    scheduler: Schema.union(['bayesian', 'set']).default('bayesian'),
    // 0–1 posterior displayed as a percentage by schema-aware hosts; the
    // meaningful band is 0.5–0.999 (below 0.5 certifies nothing, 1.0 is
    // unreachable by construction — every factor keeps a flake residual).
    // W6-F2/W11-M7: schemastery's percent() is a CLOSED [0,1] — certifyTarget 0
    // made certification trivially reachable, so the schema domain here is the
    // OPEN interval (0,1), spelled min 0.01 / max 0.99 on the 0.01 step grid.
    // (EngineOptions direct construction is validated on the engine face.)
    certifyTarget: Schema.percent().min(0.01).max(0.99).default(DEFAULT_CERTIFY_TARGET),
    impactGraph: Schema.boolean().default(true),
    // W11-L-E: these two were the M-46 stragglers — 0/negative silently
    // truncates the impact walk (precise impact analysis degrades to a
    // truncated-flag guess) or skips every LSP query.
    impactGraphLimit: Schema.number().min(1).default(20_000),
    lspImpact: Schema.boolean().default(true),
    lspQueryBudget: Schema.number().min(1).default(400),
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
    // V5-M4: the OPEN interval, same as the κ knobs — ζ=1 removes the docs-only
    // confidence ceiling entirely (jury self-attestation certifies at full
    // confidence, the cap's whole reason to exist), so the domain is
    // [0.01, 0.99] on the 0.01 grid like its three siblings.
    juryConfidenceCap: Schema.percent().min(0.01).max(0.99).default(0.8),
    // κ: graded-evidence trust weights — log-odds exponents, so weak witnesses
    // can only weaken a claim (probability^weight < 1 whenever probability < 1).
    // W11-M5/W6-F2: that invariant is FALSE at κ=0 (p^0 = 1: jury and human
    // rejects stop discounting anything — grade inflation by configuration),
    // and κ=1 merely disables the exponents, so the domain is the OPEN interval
    // (0,1) like certifyTarget's.
    classBTrust: Schema.percent().min(0.01).max(0.99).default(0.7),
    classCTrust: Schema.percent().min(0.01).max(0.99).default(0.9),
    // π: PTC synthesis — the sandbox the model writes conjured tests into, the
    // false-pass rate its tests are priced at, and how long one may run. All
    // three mirror the engine-side defaults (`core/synthetic.ts` /
    // `ProofEngine`), exposed here because two deployments may disagree on how
    // much an interested party's own test is worth.
    // W11-M-D: syntheticDir gets evidenceDir's pattern discipline PLUS the two
    // escapes that pattern alone leaves — a `..` SEGMENT would park the conjure
    // sandbox OUTSIDE the workspace, and a drive-absolute spelling ('C:/abs')
    // walks past the `(?!\/)` leading-slash guard entirely ('.' parks it AT the
    // root, also rejected: the sandbox must be a real subdirectory).
    syntheticDir: Schema.string().pattern(/^(?![./\\]+$)(?!\/)(?![A-Za-z]:)(?!.*(?:^|[\/\\])\.\.(?:[\/\\]|$)).+$/).default('.proof-synthetic'),
    // V5-M4: β also lives on the OPEN interval — β=0 prices an interested
    // party's own conjured test at "cannot falsely pass", quietly cancelling
    // the synthetic-weaker-than-organic premise the whole π contract rests on.
    syntheticFalsePass: Schema.percent().min(0.01).max(0.99).default(0.15),
    syntheticTimeoutMs: Schema.number().min(1).default(60_000),
    // υ: coverage-aware proof gating — observe by default so real Node check
    // processes get execution-coverage honesty while data-less environments
    // (fakes, non-Node toolchains) degrade visibly to basis 'none' instead of
    // being blocked on data they structurally cannot produce.
    coverage: Schema.union(['observe', 'require', 'off']).default('observe'),
    // v0.19: experimental agent-team seam — runtime duck-typed, opt-in, default
    // off (see the interface comment above).
    agentTeamBridge: Schema.boolean().default(false),
    verbose: Schema.boolean().default(false),
});
//# sourceMappingURL=config.js.map