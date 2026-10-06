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
import { createHash } from 'node:crypto';
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
export function canonicalJson(value) {
    return stringify(value, new WeakSet());
}
function stringify(value, seen) {
    if (value === null)
        return 'null';
    const t = typeof value;
    if (t === 'number') {
        // The M17 residual named in the doc comment above: fold, don't throw —
        // `Infinity` reaches here from forged chain bytes (`1e999`) via the
        // checkpoint signature checks, where the fold's verify-false is the
        // correct adjudication and a throw would kill the audit mid-walk.
        return Number.isFinite(value) ? JSON.stringify(Object.is(value, -0) ? 0 : value) : 'null';
    }
    if (t === 'boolean' || t === 'string')
        return JSON.stringify(value);
    if (t === 'bigint')
        throw uncanonicalisable('bigint');
    // `undefined` is JSON's absence, not an exotic value: object fields holding
    // it are dropped by the key filter below, array slots render it as null.
    if (t === 'undefined')
        return 'null';
    if (t === 'function')
        throw uncanonicalisable('function');
    if (t === 'symbol')
        throw uncanonicalisable('symbol');
    if (Array.isArray(value)) {
        if (seen.has(value))
            throw circularError();
        seen.add(value);
        try {
            return `[${value.map(item => stringify(item, seen)).join(',')}]`;
        }
        finally {
            seen.delete(value);
        }
    }
    const obj = value;
    // Only plain objects (Object.prototype or null prototype) canonicalise:
    // everything else — Date, RegExp, Error, boxed primitives, Map, Set, class
    // instances — has state this format cannot render injectively, and two
    // distinct such values collapsing onto one address is the exact failure
    // (silent false dedupe) the address exists to prevent.
    const proto = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
        throw uncanonicalisable(constructorName(obj) ?? 'non-plain object');
    }
    if (seen.has(obj))
        throw circularError();
    seen.add(obj);
    try {
        const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
        return `{${keys.map(k => `${JSON.stringify(k)}:${stringify(obj[k], seen)}`).join(',')}}`;
    }
    finally {
        seen.delete(obj);
    }
}
/** The value's constructor name when it carries a usable one (e.g. 'Date'). */
function constructorName(obj) {
    const name = obj.constructor?.name;
    return typeof name === 'string' && name.length > 0 ? name : undefined;
}
function uncanonicalisable(what) {
    return new TypeError(`${what} cannot be canonicalised`);
}
function circularError() {
    return new TypeError('circular structure cannot be canonicalised');
}
/** SHA-256 of a UTF-8 string, hex-encoded. */
export function sha256(text) {
    return createHash('sha256').update(text, 'utf8').digest('hex');
}
/** Content address of any canonicalisable value: `sha256(canonicalJson(v))`. */
export function addressOf(value) {
    return sha256(canonicalJson(value));
}
/**
 * Merkle-style root over a set of addresses: the digest of the sorted,
 * newline-joined addresses. Order-independent, so re-derivation cannot be
 * faked by shuffling the evidence, and stable under re-runs.
 */
export function merkleRoot(addresses) {
    const sorted = [...addresses].sort();
    return sha256(sorted.join('\n'));
}
/**
 * H-28: the placeholder shapes the folds themselves produce. Output that
 * ALREADY carries one of these literals is not honest input for the fold: an
 * author who can shape a check's stdout could pre-print `$WORKSPACE/src/a.ts`
 * (or a literal `<duration>`) and mint the digest of a *different* real
 * output, breaking the content-addressing promise that same digest implies
 * same observable outcome. When any of these appear in the raw text, the
 * normalized result is prefixed with `RAW_PLACEHOLDER_MARKER` (once), so a
 * literal-bearing output can never byte-equal a folded honest one.
 *
 * W14-M3: the marker line's own text is in the detection set. Without it, a
 * literal-free output that merely PRE-PRINTS the marker line normalised to
 * exactly the marker + folded body — byte-equal to the marked product of a
 * genuinely literal-bearing output — reopening the cross-class equality
 * H-28 exists to close. With the marker text detected, a marker-bearing
 * output normalises to `MARKER + k marker lines + folded body` (k preserved
 * in the text itself), which is distinct from every k=0 class and from every
 * other k.
 *
 * Residual, documented: the marker separates the literal-bearing class from
 * the folded class; two DIFFERENT literal-bearing outputs can still agree
 * where the underlying folds already equate them (the pre-existing
 * equivalence class of this function). Digests of outputs that contain none
 * of these literals are byte-for-byte unchanged.
 */
const LITERAL_PLACEHOLDER_SHAPES = [
    /\$(?:WORKSPACE|HOME)(?![\w$-])/,
    /<(?:duration|timestamp)>/,
    /\[raw output contained literal placeholders\]/,
];
/** H-28: one-line escape prefix stating the raw output carried placeholder literals. */
const RAW_PLACEHOLDER_MARKER = '[raw output contained literal placeholders]\n';
export function normalizeOutput(raw, opts = {}) {
    let text = raw.replace(/\r\n/g, '\n');
    // H-28: detect BEFORE folding — after substitution, real paths and
    // pre-printed literals are indistinguishable by construction.
    const carriesLiteral = LITERAL_PLACEHOLDER_SHAPES.some(re => re.test(text));
    const foldRoot = foldsSeparators(opts.root);
    const foldHome = foldsSeparators(opts.home);
    for (const variant of pathVariants(opts.root))
        text = substituteLiteral(text, variant, '$WORKSPACE', foldRoot);
    for (const variant of pathVariants(opts.home))
        text = substituteLiteral(text, variant, '$HOME', foldHome);
    const lines = text
        .split('\n')
        .map(line => line.replace(/[ \t]+$/g, ''))
        .map(line => line.replace(/\b\d+(\.\d+)?\s?(ms|s|sec|secs|seconds|minutes|min)\b/gi, '<duration>'))
        .map(line => line.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<timestamp>'));
    while (lines.length > 0 && lines[lines.length - 1] === '')
        lines.pop();
    return (carriesLiteral ? RAW_PLACEHOLDER_MARKER : '') + lines.join('\n');
}
/**
 * A path and every spelling output may legitimately use for it: the
 * slash-flipped twin, so Windows output matches in both styles, plus — for a
 * drive-form path — the case-flipped drive twins, because Windows drives are
 * case-insensitive while tools routinely emit the *other* case from the
 * configured root (`c:\ws\src` vs root `C:/ws`). V7-L5: the fold is
 * BIDIRECTIONAL — both the lowercased AND the uppercased drive are emitted
 * with their slash variants. The pre-fix list generated only the lowered
 * twin, so a root configured as `c:/ws` never matched output spelled
 * `C:\ws\src` (dedupe broke in the false-inequality direction; the uppercase
 * root had the mirror-image hole until now). Variant generation stays a pure
 * function of the path, and a variant only substitutes where it literally
 * occurs, so honest outputs that spell the root one way digest byte-for-byte
 * as before.
 */
function pathVariants(path) {
    if (path === undefined || path.length === 0)
        return [];
    const out = [];
    const add = (candidate) => { if (!out.includes(candidate))
        out.push(candidate); };
    const addDriveForms = (drivePath) => {
        add(drivePath);
        add(drivePath.replace(/\\/g, '/'));
        add(drivePath.replace(/\//g, '\\'));
    };
    add(path);
    add(path.replace(/\\/g, '/'));
    if (isDriveForm(path)) {
        addDriveForms(path.slice(0, 1).toLowerCase() + path.slice(1));
        addDriveForms(path.slice(0, 1).toUpperCase() + path.slice(1));
    }
    return out;
}
/** Windows drive-absolute path (`C:/ws`, `c:\ws`). */
function isDriveForm(path) {
    return path !== undefined && /^[A-Za-z]:[\\/]/.test(path);
}
/**
 * A drive-form root supplied in forward-slash form (`C:/ws`) declares the
 * canonical separator for everything under it, so substituted paths fold
 * their backslash tails: `c:\ws\src\a.ts` and `c:/ws/src/a.ts` are the same
 * file and must digest identically. Backslash-form roots keep their historic
 * substitution byte-for-byte (their tails are left as the output spelled
 * them), so already-minted digests stay stable.
 */
function foldsSeparators(path) {
    return path !== undefined && /^[A-Za-z]:\//.test(path);
}
/**
 * A root always appears in output as a *complete path prefix*, so a match is
 * only meaningful when it ends at a path boundary: separator, quote,
 * whitespace, end of line/text — or (B6-L2) the punctuation a path is
 * routinely glued to without whitespace: `(`/`)` (linter and stack-frame
 * renderings), `:` (line numbers right after a bare root), `,`/`;` (lists).
 * Without the anchor, root `/app` would chew into `/application` and mint
 * `$WORKSPACElication` — a false equivalence (or false diff) between two
 * different locations in a content-addressed digest; with only the original
 * anchor set, `(/app)` and `/app:` failed to substitute AT ALL — the false
 * INEQUALITY direction, breaking cross-machine dedupe. The lookahead consumes
 * nothing, so every legitimately-prefixed path substitutes exactly as it did
 * before the guard existed.
 */
const PATH_BOUNDARY = "(?=[/\\\\'\"`():,;\\s]|$)";
/** The path continuation after a root match: separator-led segments, greedily up to the next boundary. */
const PATH_TAIL = '((?:[/\\\\][^/\\\\\'"`\\s]+)*)';
function substituteLiteral(text, literal, placeholder, foldTail = false) {
    if (literal.length === 0)
        return text;
    const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!foldTail)
        return text.replace(new RegExp(escaped + PATH_BOUNDARY, 'g'), placeholder);
    // Folding mode captures the substituted path's tail and canonicalises its
    // separators; the boundary lookahead still runs first, so a longer path
    // sharing the prefix (`c:/wsx`) never matches.
    return text.replace(new RegExp(escaped + PATH_BOUNDARY + PATH_TAIL, 'g'), (_match, tail) => placeholder + tail.replace(/\\/g, '/'));
}
//# sourceMappingURL=hash.js.map