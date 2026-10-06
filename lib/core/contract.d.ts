/**
 * Typed claim contracts (ε): a `proof_claim` stops being free text and becomes
 * a *kind*, and every kind binds the claim to a different set of evidence
 * obligations.
 *
 * Why kinds at all: "I refactored X" and "I added feature Y" and "it got
 * faster" are claims with completely different proof obligations, and a single
 * generic "no regressions" gate cannot tell them apart. A `behavior-preserving`
 * claim must show the public API surface did not move; a `behavior-adding`
 * claim must show every new source path is exercised by a passing check; a
 * `perf-budget` claim must show a benchmark measurement inside the stated
 * budget; a `docs-only` claim must show the change set really is documents —
 * and gets a capped confidence instead of machine checks; an `llm-jury`
 * claim (ι) outsources its verdict to Class B testimony entirely: it must
 * show a jury deliberation on the exact claim text, and that the active
 * verdict upholds it.
 *
 * Purity note: obligation verdicts are destined for the evidence chain, so
 * everything here is a pure function of its inputs — no clock, no randomness,
 * no filesystem — and every list that reaches a `detail` string is sorted
 * first, so the same input always yields the byte-identical verdict.
 *
 * @module dsh-proof/core/contract
 */
import type { CheckSpec } from './ports.ts';
import type { Baseline, Evidence } from './evidence.ts';
import { type Attestation } from './attest.ts';
export type ClaimKind = 'behavior-preserving' | 'behavior-adding' | 'perf-budget' | 'docs-only'
/** ι: judged by Class B testimony, not machine checks (`skipChecks` is true for it). */
 | 'llm-jury';
/** The typed half of a `proof_claim`; `claim` itself stays human-readable. */
export interface ClaimContract {
    readonly kind: ClaimKind;
    /** Human-readable statement of what was done (not the normative part). */
    readonly claim: string;
    /** Required by `perf-budget`: the wall-clock budget a benchmark must beat. */
    readonly budgetMs?: number;
    /** Required by `docs-only`: the self-review a human jury should check against. */
    readonly review?: string;
    /** API-face entry points to cover; omitted means the engine derives them. */
    readonly entryPoints?: readonly string[];
}
/** One obligation under one contract: met or not, and what to do about it. */
export interface ObligationResult {
    readonly id: string;
    readonly met: boolean;
    /** Human-readable, model-actionable: when not met, says what is missing and how to fix it. */
    readonly detail: string;
}
/** One file reachable from the API face: its path and its full text. */
export interface SurfaceEntry {
    readonly rel: string;
    readonly content: string;
}
/**
 * The exports a set of files makes public, as sorted, deduplicated
 * `'${rel}#${exportName}'` strings.
 *
 * Extraction is line-regex based and deliberately biased to OVER-report:
 * `behavior-preserving` requires the surface diff to be empty, so a missed
 * export is a missed breaking change (a wrong pass), while a phantom extra
 * export only makes an honest claim work harder (a wrong fail). When in doubt,
 * report.
 *
 * Five forms are recognised, per line:
 * 1. `export` named declarations (`const`/`let`/`var`/`function`/`class`/
 *    `abstract class`/`interface`/`type`/`enum`, plus `async`/`declare`/
 *    `function*`/`const enum` variants and multi-declarator `const a = 1, b = 2`);
 *    type annotations are tolerated — `export const x: number = 1` reports
 *    `x`, and a destructuring declarator reports the pattern's names but never
 *    its annotation (`export const { a }: Foo = o` reports `a`, not `Foo`);
 * 2. `export { a, b as c }` (single- or multi-line, `export type { … }` included);
 * 3. `export default …` → recorded as `#default`;
 * 4. `export * from …` → recorded as `#*` (a changed re-export face is a face
 *    change; `export * as ns from …` also records the `ns` binding);
 * 5. `export = …` (TS CommonJS) → recorded as `#=`.
 */
export declare function extractApiSurface(entries: readonly SurfaceEntry[]): string[];
/** Set difference of two surfaces, both directions, sorted. */
export declare function diffApiSurface(before: readonly string[], after: readonly string[]): {
    added: string[];
    removed: string[];
};
/**
 * True when a path is a pure documentation / outside-config asset: a docs
 * extension AND not a global invalidator. The second clause matters because
 * `requirements-dev.txt` carries a docs extension while being exactly the kind
 * of dependency declaration whose change invalidates every check — a docs-only
 * claim over it would launder a config change past the jury. The invalidator
 * set is `GLOBAL_INVALIDATORS` from `core/impact.ts`, imported so the two
 * modules can never drift.
 */
export declare function isDocsPath(rel: string): boolean;
/** Everything `evaluateContract` needs; `graph` is accepted for engine
 * convenience but deliberately unused — verdicts must stay recomputable from
 * the evidence log alone, and a dependency graph is not evidence. */
export interface ContractInput {
    readonly contract: ClaimContract;
    /** RelPaths changed this session. */
    readonly changed: readonly string[];
    /** Every discovered check. */
    readonly specs: readonly CheckSpec[];
    /** Evidence records produced by this run (may contain re-runs). */
    readonly records: readonly Evidence[];
    /** The baseline the run is differentially judged against, if one exists. */
    readonly baseline: Baseline | undefined;
    /** Engine-read `baseline.apiSurface`; `undefined` = baseline predates capture. */
    readonly apiSurfaceBefore: readonly string[] | undefined;
    /** Engine-computed current surface; `undefined` = engine did not provide it. */
    readonly apiSurfaceAfter: readonly string[] | undefined;
    /** Engine dependency graph, tolerated for signature symmetry, never consulted. */
    readonly graph: unknown | undefined;
    /**
     * Attestations read off the chain (ι), for `llm-jury` claims. Optional so
     * pre-ι callers (and every other kind) pass their old shape untouched;
     * `undefined` simply means "no testimony on record", which fails
     * `jury-delivered` rather than the whole evaluation. Shapes are re-validated
     * and gens resolved by `activeAttestations` — this input is chain data, not
     * a promise.
     */
    readonly attestations?: readonly Attestation[];
    /**
     * ο: latest evidence per check, read off the store by the engine
     * (`store.latest()`). `new-paths-covered` uses it as a *fallback*: a
     * changed source path with no covering pass among this run's records may
     * still be covered by the latest passing evidence on record. Organic
     * passes carry that coverage as-is — stale independent evidence is
     * stronger than fresh self-written evidence, so if the fallback opens at
     * all, refusing the organic case would be incoherent. Synthetic passes
     * (record `source`/`synthetic` markers) carry it visibly *discounted*:
     * met stays true, but the detail says so, and the Bayesian layer already
     * prices the underlying check lower. Optional and absent in pre-ο callers;
     * without it the obligation judges exactly as it did before.
     */
    readonly latestByCheckId?: ReadonlyMap<string, Evidence>;
}
export interface ContractVerdict {
    readonly kind: ClaimKind;
    /** `zero-regressions` first, then the kind's obligations in fixed order. */
    readonly obligations: readonly ObligationResult[];
    /** Present only for a fully-met docs-only contract: the jury's confidence cap. */
    readonly juryCappedConfidence?: number;
    /** True only for docs-only and llm-jury: the engine may skip dispatching checks entirely. */
    readonly skipChecks: boolean;
}
/**
 * Judge a typed claim against the evidence. Obligation ids are stable — the
 * engine and tooling wire on them — and their order is fixed: `zero-regressions`
 * always first, then the kind-specific obligations in the order the kinds are
 * documented. All multi-value details are sorted, so the verdict string is a
 * pure function of the input.
 */
export declare function evaluateContract(input: ContractInput, juryConfidenceCap?: number): ContractVerdict;
//# sourceMappingURL=contract.d.ts.map