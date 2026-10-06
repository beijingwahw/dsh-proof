/**
 * Canonicalisation + content addressing.
 *
 * Every evidence record is addressed by the digest of its *canonical* form, so
 * two runs that produced the same observable outcome collapse to the same id.
 * That is what makes an evidence chain recomputable: a reader can re-hash the
 * record and check it still addresses itself, and a `proofRoot` can be compared
 * across sessions without trusting the writer.
 *
 * @module dsh-proof/core/hash
 */
/**
 * Deterministic JSON: object keys sorted recursively, `undefined` dropped,
 * numbers normalised through `String()` so `-0` and `0` agree.
 *
 * A value whose JSON rendering is not *injective* — where two distinct values
 * would canonicalise to the same bytes and thus mint the same address,
 * silently deduplicating things that are not the same — is rejected with a
 * `TypeError` naming the problem, the same discipline as the circular check
 * below. Rejected kinds:
 *
 * - `bigint` — would alias the equal-looking string (`1n` ≡ `"1"`);
 * - `symbol`, `function` — would alias each other and `null`;
 * - non-plain objects — anything whose prototype is neither
 *   `Object.prototype` nor `null`: `Date`, `RegExp`, `Error`, boxed
 *   primitives, `Map`/`Set`, and class instances (even with enumerable
 *   keys — better to refuse than to address a lossy subset of the value).
 *   Most canonicalise as `'{}'`, aliasing every other such object.
 *
 * One deliberate residual: non-finite numbers (`NaN`, `±Infinity`) still
 * fold to `'null'` instead of throwing. They collide with `null` exactly as
 * the rejected kinds do, but the adjudication read paths
 * (`checkpointSignedData` under `EvidenceStore.audit` and the bundle trust
 * check) feed `JSON.parse`-derived numbers where a forged `"count":1e999`
 * parses to `Infinity` — throwing there would crash the audit mid-walk
 * instead of adjudicating the checkpoint as malformed (the fold makes its
 * signature verify fail, which is the correct verdict, and the walk's own
 * safe-integer gate already flags the lie). Flipping this to a `TypeError`
 * is blocked on those call sites catching (or pre-gating) it first.
 *
 * Plain objects (both prototypes), arrays, and the JSON primitives
 * canonicalise exactly as before; `undefined` is still dropped from objects
 * and rendered as `null` inside arrays.
 *
 * This is a public addressing primitive (`addressOf` promises to address
 * "any canonicalisable value"), and a silent collision is strictly worse
 * than a loud refusal: "Maximum call stack size exceeded" or `{}` for a
 * `Date` is not an answer a caller can act on.
 */
export declare function canonicalJson(value: unknown): string;
/** SHA-256 of a UTF-8 string, hex-encoded. */
export declare function sha256(text: string): string;
/** Content address of any canonicalisable value: `sha256(canonicalJson(v))`. */
export declare function addressOf(value: unknown): string;
/**
 * Merkle-style root over a set of addresses: the digest of the sorted,
 * newline-joined addresses. Order-independent, so re-derivation cannot be
 * faked by shuffling the evidence, and stable under re-runs.
 */
export declare function merkleRoot(addresses: Iterable<string>): string;
/**
 * Roots substituted out of captured output before hashing, making evidence
 * location-independent: the same outcome on any machine, under any checkout
 * directory, yields the same digest — which is what cross-session dedupe,
 * cross-machine comparison, and third-party recomputation all rest on.
 * `root` (more specific) is replaced before `home` (less specific), so a
 * workspace under the user's home still collapses to `$WORKSPACE/...`.
 */
export interface NormalizeOptions {
    readonly root?: string;
    readonly home?: string;
}
export declare function normalizeOutput(raw: string, opts?: NormalizeOptions): string;
//# sourceMappingURL=hash.d.ts.map