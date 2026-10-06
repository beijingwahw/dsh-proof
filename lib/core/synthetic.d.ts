/**
 * Synthetic evidence (ο) — the pure domain of PTC evidence synthesis.
 *
 * Some assertions a session wants to prove have no existing check: the change
 * touched a path no discovered suite covers, or the claim is about a property
 * nobody ever tested. This module lets the *plugin* construct a verification
 * for exactly that gap: a property-test / minimal-repro script the agent
 * drafts from a scaffold, the host screens for forbidden capabilities, the
 * screened script runs in a sandbox, and the run's evidence enters the chain
 * with a `synthetic` marker — weighted below every discovered check.
 *
 * The standing tension this module is built around: the agent is a
 * *co-conspirator in constructing the evidence* — it writes the test that
 * proves its own claim — but the evidence chain must not let it *forge* one.
 * Three structural answers, all visible in the API below:
 *
 * 1. **The script is content-addressed into its own evidence.** The record
 *    carries `scriptDigest` (sha256 of the verbatim source) and the digest
 *    participates in `evidenceId`, so "the test that passed" and "the source
 *    that ran" cannot quietly diverge — weakening an assertion mints a new
 *    address, and the old pass cannot be re-used for the new script.
 * 2. **The capability screen is deny-list, not trust-list.** The script may
 *    only reach the outside world through modules the screener never named.
 *    Static screening is admitted to be *not* a sandbox (see `screenScript`);
 *    the real boundary is the sandbox cwd, the run timeout, the output cap
 *    and the host's ptc-runtime profile. The screen exists to make the easy
 *    exfiltration attempts fail loudly and *before* execution.
 * 3. **The math discounts self-graded homework.** `core/bayes.ts` prices a
 *    synthetic check's false-pass at 0.15, not 0.02 (see the long comment at
 *    the use site) — a passing synthetic check lifts the posterior less than
 *    a passing independent suite, without forbidding the agent from ever
 *    proving anything itself.
 *
 * ## Determinism
 *
 * Everything here is a pure function of its inputs: no clock (the request's
 * `requestedAt` is injected by the caller), no randomness, no filesystem, no
 * imports at all beyond `checkId` (pure identity) and a type. When a digest
 * of a script is needed — `SyntheticEvidenceMeta.scriptDigest` — callers use
 * `sha256` from `./hash.ts`, the project's one sanctioned digest source.
 * Findings and labels are sorted so identical inputs yield byte-identical
 * outputs, the content-addressing discipline demands.
 *
 * @module dsh-proof/core/synthetic
 */
import type { CheckSpec } from './ports.ts';
/**
 * Default sandbox directory (workspace-relative) where synthetic scripts and
 * their fixtures live before the runner executes them. The directory is added
 * to `DEFAULT_IGNORE_DIRS` (see `core/checks.ts`) so the sandbox never enters
 * the dependency graph and never triggers check discovery — the sandbox is an
 * *output* of verification, not a source input that could invalidate it.
 */
export declare const SYNTHETIC_DIR_DEFAULT = ".proof-synthetic";
/**
 * The scaffold the agent fills in (ESM `.mjs`, top-level await allowed).
 *
 * Design constraints the template encodes:
 *
 * - **Deterministic assertion loop** — no clock, no randomness in the oracle:
 *   the same source must print the same output every run, forever, or the
 *   content-addressed evidence record is not reproducible.
 * - **Fixed last-line protocol** — `SYNTHETIC: PASS` or
 *   `SYNTHETIC: FAIL: <reason>`. The host's output excerpt and the runner's
 *   exit-code convention (`process.exitCode = 1` on failure) both key on it,
 *   so a scaffolded script can never "pass" by printing nothing.
 * - **The chain warning rides in the file itself** — the first thing the
 *   model reads after instantiation is that this exact text becomes the
 *   `scriptDigest` of a piece of evidence. Deleting an assertion is not a
 *   private edit; it mints a new address and the old pass stops applying.
 *
 * The template itself passes `screenScript` (module names appear in the
 * warning prose *unquoted*, and the screener only matches quoted specifiers)
 * — a scaffold plus filled business assertions starts from a clean screen,
 * so any finding on a submitted script came from the author's additions.
 */
export declare const SYNTHETIC_TEMPLATE: string;
/** What the agent asks to prove synthetically: one claim, its paths, one script. */
export interface SyntheticRequest {
    /** Identity of the claim — `claimIdOf(claim)` (see `core/attest.ts`). */
    readonly claimId: string;
    /** The human-readable claim text, excerpted into the spec's label. */
    readonly claim: string;
    /** Paths the test must exercise; they become the spec's `paths`. */
    readonly paths: readonly string[];
    /** Sandbox-relative script name (`sandboxEntryFor` mints it). */
    readonly entry: string;
    /** Epoch millis, injected by the caller — this module owns no clock. */
    readonly requestedAt: number;
}
/**
 * Sandbox-relative script name: `synthetic-<claimId>-<seq>.mjs`.
 *
 * The `seq` is collision insurance only — two scripts for the same claim
 * (a re-write after a FAIL, or several properties proven separately) must not
 * overwrite each other on disk — and deliberately carries *no* identity
 * semantics: the evidence identity is the script *content* (scriptDigest)
 * plus the command, never the sequence number, so re-running "the same test,
 * regenerated" dedupes only if the bytes really are the same.
 */
export declare function sandboxEntryFor(claimId: string, seq: number): string;
/**
 * Modules a synthetic script may never reach, under any of their spellings:
 * process spawning (`child_process`), the environment bag (`process` /
 * `node:process` — an `import { env } from 'node:process'` would otherwise
 * bypass the whole `process.env` read check, and env reads are the classic
 * exfiltration channel), the network (`net`/`http`/`https`/`dgram`, and as
 * of H-31 also `dns`/`tls` — a DNS lookup or a raw TLS socket is an outbound
 * channel exactly like http, and dns tunnelling is the classic covert one),
 * parallel kernels that would escape the sandbox's cwd and timeout
 * (`worker_threads`, `cluster` — fork() is child_process with a friendlier
 * name). The list is a locked contract with the engine and tool wiring —
 * additions are a breaking change to what hosts must enforce at the
 * ptc-runtime tier, not a casual edit.
 *
 * W15-M3 (v0.23) added the eval-grade execution seams that walk in through a
 * CLEAN literal specifier: `node:vm` (`vm.runInThisContext` is `eval` with a
 * function name — it used to pass all four import regexes AND the global
 * screen) and `node:module` (the `createRequire` door; the escape itself is a
 * documented residual, but the module NAME is statically sealable, so the
 * door is). `node:inspector` stays out for now: it is an execution seam, but
 * a strictly weaker one than vm, and the contract cost of list growth is
 * real — additions belong to deliberate versioned changes like this one.
 *
 * `'node:process'` is listed for the contract's sake (the engine's conjure
 * instruction and the tool prose render this list verbatim, and both
 * spellings must be named to the model); matching itself reduces through the
 * `node:` strip in `forbiddenModuleOf`, where the single `'process'` entry
 * answers for both. `vm`/`module` follow the same convention.
 */
export declare const FORBIDDEN_CAPABILITIES: readonly string[];
/**
 * H-31: zero-import outbound GLOBALS a synthetic script may never touch.
 * Node ≥ 18 ships `fetch` (and ≥ 22 `WebSocket`) on the global object — no
 * `import` text for the module screen to see — so a script with a clean
 * import section could still POST the workspace to any address. W15-M2: the
 * screen flags every statically decidable call shape of every name here —
 * direct `fetch(…)`, computed member `globalThis['fetch'](…)`, optional call
 * `fetch?.(…)`, indirect `(0, fetch)(…)` and the alias declaration
 * `const f = fetch` (see `screenScript`). V7-M3 extends the same net to the
 * statically decidable VALUE shapes — the tagged template `` fetch`url` ``
 * (a call), the destructuring rename `const { fetch: f } = globalThis`, the
 * bare assignment alias `f = fetch` and `Reflect.apply(fetch, …)`; passing
 * the global bare to an arbitrary higher-order callee stays a documented
 * residual (not statically decidable). A local helper that happens to be
 * named `fetch` is over-reported, the deny-list's documented safe direction
 * (refuse the inert script, never run the live one).
 */
export declare const FORBIDDEN_GLOBALS: readonly string[];
/** One screened script: `ok` only when `findings` is empty (empty = cleared to run). */
export interface ScreenResult {
    readonly ok: boolean;
    readonly findings: readonly string[];
}
/**
 * Deny-list capability screen over a script's verbatim source. Returns every
 * finding; the script may only execute when the list is empty. Findings are
 * deduplicated and sorted, so the same source always screens to the same
 * verdict — screening output is recorded next to the run (see
 * `SyntheticEvidenceMeta.screened`), and it must address identically.
 *
 * What it catches: static imports (including multi-line lists and re-export
 * `from`-clauses), bare side-effect imports, literal-specifier dynamic
 * imports and `require` calls of any `FORBIDDEN_CAPABILITIES` module — with
 * or without the `node:` prefix — plus `process.env` reads in member and
 * computed-member form, and (H-31) the zero-import outbound globals named by
 * `FORBIDDEN_GLOBALS` in every statically decidable call shape (W15-M2:
 * direct, computed-member, optional-call, indirect-call and alias-binding)
 * and value shape (V7-M3: tagged-template, destructuring-alias,
 * assignment-alias and Reflect.apply — a global used as a VALUE at a
 * nameable site is as live as a call).
 * M11: all four import shapes accept backtick-quoted specifiers (an
 * uninterpolated template literal is statically decidable), and specifiers
 * are `\u`/`\x`-unescaped before the deny-list sees them, so
 * `'child_\u0070rocess'` screens as `'child_process'`. The scan runs over
 * the *raw text, comments included*: a commented-out forbidden import is
 * flagged rather than missed. That is deliberate over-reporting — this is a
 * deny-list, and for a screener the safe direction is refusing an inert
 * script, never running a live one.
 *
 * Admitted limits of static screening (this is a *screen*, not a sandbox):
 * computed specifiers (`import(buildName())`), runtime aliases that need no
 * literal (`eval`/`new Function` — the eval-tier escapes themselves),
 * case-mangled specifiers that would simply fail at runtime, and a global
 * passed BARE as an argument to an arbitrary callee
 * (`queueMicrotask(fetch, url)` — whether the callee invokes its argument is
 * not a static fact) are not caught — text cannot see runtime values. (W15-M3 closed the two module DOORS to
 * eval-tier power: `node:vm` and `node:module` are denied by name, so the
 * escapes now need an actual computed specifier, not a clean import.) The
 * enforcement that actually bounds a runaway script is the sandbox cwd
 * restriction, the run timeout, the output cap and the host's ptc-runtime
 * profile; the screen's job is only to make the *easy* variants fail loudly,
 * before execution.
 *
 * `fs` is deliberately allowed in both directions: a property test that
 * cannot read its fixture cannot test anything. The directory it may read is
 * the sandbox the host mounted — that boundary is enforced by cwd, not here.
 */
export declare function screenScript(source: string): ScreenResult;
/**
 * The self-certifying half of a synthetic evidence record: what ran, where,
 * under which screen, authored by whom. Participates in `evidenceId` (see
 * `makeEvidence`), so the record cannot claim a cleaner script, sandbox or
 * screen verdict than the one that actually produced it.
 */
export interface SyntheticEvidenceMeta {
    /** sha256 of the script's verbatim source — the record proves what ran. */
    readonly scriptDigest: string;
    /** Where the host executed it: a screened subprocess, or the ptc-runtime tier. */
    readonly sandbox: 'screened-subprocess' | 'ptc-runtime';
    /** The screener's findings for exactly `scriptDigest`; empty = cleared to run. */
    readonly screened: readonly string[];
    /**
     * v0.12 has a single grade: the test was written by the agent (attributed
     * via WorkspaceWatch provenance). A future 'host' grade — the human or the
     * host drafting the script — would earn a lower falsePass; the type is a
     * literal union, not a boolean, so adding it is a visible contract change.
     */
    readonly author: 'agent';
}
/**
 * The check spec a synthetic request becomes — an ordinary `CheckSpec` the
 * runner, store and scheduler treat like any other, except for `source:
 * 'synthetic'`, which is where the discounting lives (bayes β, contract
 * detail, report wording all key on it — never on a special record shape).
 *
 * Identity is `checkId('synthetic', ['node', entry], sandboxDir)`: the
 * *command and sandbox* make the id, the script *content* makes the evidence
 * (via `scriptDigest`). Two different scripts for one claim share a checkId
 * but never share evidence — re-writing the test after a FAIL is visible as
 * a new evidenceId under the same check, exactly like any re-run.
 */
export declare function syntheticSpec(request: SyntheticRequest, sandboxDir: string, timeoutMs: number): CheckSpec;
//# sourceMappingURL=synthetic.d.ts.map