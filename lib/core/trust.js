/**
 * Tamper-evidence for the evidence log: a hash chain, signed checkpoints,
 * and an out-of-band anchor.
 *
 * Threat model this module exists for: the *agent itself* is the adversary.
 * Self-addressing alone (`audit()` re-hashing every record) only catches
 * naive tampering — an agent that can write files can rewrite the whole log
 * and recompute every self-consistent address with the very functions this
 * package exports. Three mechanisms close that hole:
 *
 * 1. **Hash chain** — every appended line carries `prev = sha256(previous
 *    line)`, so editing or removing any line breaks the link into the next.
 * 2. **Signed checkpoints** — a checkpoint records `{count, head}` and is
 *    signed with a host-held key the model cannot read (see `SignerPort`).
 *    The agent can chain-forge all day; it cannot forge a signature.
 * 3. **Out-of-band anchor** — the highest checkpoint ever written is also
 *    stored next to the key, outside the workspace. Truncating or rewinding
 *    the log to before that checkpoint is detected as a rewind.
 *
 * Honest limits: records appended *after* the last checkpoint are chain-
 * covered but not checkpoint-covered; that window is bounded by
 * `checkpointEvery`, and every baseline/verify/claim boundary closes it.
 *
 * @module dsh-proof/core/trust
 */
import { canonicalJson, sha256 } from "./hash.js";
/** `prev` of the first line ever appended to a log. */
export const GENESIS_PREV = sha256('dsh-proof/chain/genesis');
/**
 * sha256 of one appended log line (excluding its trailing newline).
 *
 * W1-L10 (v0.23): trailing `\r` is stripped before digesting. `JSON.stringify`
 * never emits a raw `\r` — a carriage return can only ride a line that was
 * externally re-terminated (git autocrlf, a CRLF editor) — so honest lines
 * hash identically with or without the strip and **every existing chain
 * digest is unchanged**. Without the normalization, one CRLF rewrite of the
 * file mass-invalidated every `prev` link: loud, but indistinguishable from
 * real tampering and unrecoverable by honest means. Chosen over the stricter
 * "a `\r`-carrying line is itself corrupt" reading precisely because it never
 * breaks an old chain: tolerance extends only to a byte no honest writer
 * ever produced. (A `\r` in the *middle* of a line is not a line terminator
 * and still changes the digest — mid-line edits remain fully detected.)
 *
 * V1-L13 (documented residual): the same tolerance means a trailing `\r`
 * APPENDED to a line is undetectable by any digest-based check — the chain
 * link, `headRef` witnesses and checkpoint heads all digest the stripped
 * form, and `JSON.parse` tolerates the trailing whitespace, so the edited
 * bytes parse, chain and address exactly like the honest ones. That is the
 * accepted price of never mass-invalidating an honest chain on a CRLF
 * rewrite; it buys no attacker anything (the edit changes no JSON value any
 * consumer reads), and it is pinned by the W1-L10 tests rather than silently
 * smoothed over. Everything but the terminator byte stays fully detected.
 */
export function lineDigest(line) {
    return sha256(line.endsWith('\r') ? line.replace(/\r+$/, '') : line);
}
/**
 * Walk the log and verify chain linkage. Pure: no I/O, no signature checks —
 * the store layer does cryptographic verification with its own signer.
 *
 * Chain rule: each v2 line's `prev` must equal the digest of the physically
 * previous line (of any kind), so legacy v1 lines participate in the chain
 * once a v2 line follows them.
 *
 * V1-M8 (v0.24): the line-array contract is pinned here as the ONE
 * convention every chain-side consumer derives from — the node-ports
 * `readLines` semantics, blank lines removed. The v0.23 code trusted the
 * caller to hand in a filtered array, so the store face (filtered) and the
 * MCP face (a raw `split('\n')`) could disagree about whether a marker's
 * physical predecessor was a blank line — the same log, two faces, two
 * suspect verdicts. Normalising defensively at entry makes every caller
 * converge: an honest writer never emits blank lines, so filtering them can
 * never change an honest chain's walk, and all reported line indexes refer
 * to the normalised array.
 */
export function walkChain(input) {
    const lines = input.filter(line => line.trim().length > 0);
    let sawV1 = false;
    let sawV2 = false;
    let records = 0;
    const chainBreaks = [];
    const corruptLines = [];
    const checkpoints = [];
    const malformedCheckpoints = [];
    let prevDigest = GENESIS_PREV;
    lines.forEach((line, index) => {
        let parsed;
        try {
            parsed = JSON.parse(line);
        }
        catch {
            corruptLines.push(index);
            prevDigest = lineDigest(line);
            return;
        }
        const envelope = parsed;
        if (envelope !== null && typeof envelope === 'object' && envelope.v === 1) {
            sawV1 = true;
            if (envelope.kind === 'evidence' || envelope.kind === 'marker')
                records += 1;
            prevDigest = lineDigest(line);
            return;
        }
        if (envelope !== null && typeof envelope === 'object' && envelope.v === 2 && typeof envelope.prev === 'string'
            && typeof envelope.kind === 'string') {
            sawV2 = true;
            if (envelope.prev !== prevDigest)
                chainBreaks.push(index);
            if (envelope.kind === 'checkpoint') {
                const payload = envelope.payload;
                if (typeof payload?.count === 'number' && typeof payload?.head === 'string') {
                    // Records walked to this line is the count an honest writer stamps
                    // (checkpoints are not themselves counted), so the self-report is
                    // judged against the walk, not against arithmetic the writer chose.
                    const expectedCount = records;
                    checkpoints.push({
                        index,
                        payload: {
                            count: payload.count,
                            head: payload.head,
                            workspaceKey: typeof payload.workspaceKey === 'string' ? payload.workspaceKey : null,
                            at: typeof payload.at === 'string' ? payload.at : '',
                        },
                        sig: typeof envelope.sig === 'string' ? envelope.sig : null,
                        keyId: typeof envelope.keyId === 'string' ? envelope.keyId : null,
                        sigError: typeof envelope.sigError === 'string' ? envelope.sigError : null,
                        expectedHead: prevDigest,
                        headLiared: payload.head !== prevDigest,
                        expectedCount,
                    });
                    if (!isWellFormedCount(payload.count, expectedCount))
                        malformedCheckpoints.push(index);
                }
                else {
                    corruptLines.push(index);
                }
            }
            else if (envelope.kind === 'evidence' || envelope.kind === 'marker') {
                records += 1;
            }
            else {
                // A v2 envelope of a kind no honest writer emits (L-A1-11): it chains
                // and parses, but nothing in the protocol vouches for what it is or
                // how it counts. Named as malformed — loud, not silent.
                malformedCheckpoints.push(index);
            }
            prevDigest = lineDigest(line);
            return;
        }
        corruptLines.push(index);
        prevDigest = lineDigest(line);
    });
    const mode = sawV2
        ? (checkpoints.some(cp => cp.sig !== null) ? 'signed' : 'unsigned')
        : (sawV1 ? 'legacy' : 'unsigned');
    // Tail cover is measured from the last checkpoint whose count the walk
    // corroborates. A forged count — inflated to Infinity or merely past the
    // truth — used to zero out the tail (`records - ∞` clamped to 0) and
    // launder a rewrite as "fully checkpoint-covered"; against the walked
    // `expectedCount` the same forgery is malformed and the true tail survives.
    // Honest logs are byte-identical: there `count === expectedCount`.
    const malformed = new Set(malformedCheckpoints);
    const lastGood = checkpoints.findLast(cp => !malformed.has(cp.index));
    const tailRecords = lastGood === undefined ? records : Math.max(0, records - lastGood.expectedCount);
    return { mode, records, chainBreaks, corruptLines, checkpoints, malformedCheckpoints, tailRecords };
}
/**
 * A checkpoint count is well-formed when it is a non-negative safe integer
 * equal to the records the walk counted to that position. Out-of-range or
 * fractional self-reports (`1e999` → `Infinity`, `-1`, `2.5`) and inflated or
 * deflated ones fail alike — the walked count is the only admissible truth.
 */
function isWellFormedCount(count, expectedCount) {
    return Number.isSafeInteger(count) && count >= 0 && count === expectedCount;
}
/**
 * v0.22 (H-32/M-33): the `sigError` banner under which the store records that
 * it *refused* to sign a checkpoint because its own pre-sign audit found the
 * physical chain tampered (H-27) — as opposed to a transient signing failure
 * ("key directory locked by a scanner"). The walk carries the string; the
 * audit splits the two into different channels with different `ok` semantics.
 */
export const SIG_REFUSED_PREFIX = 'refused-to-sign';
/**
 * Parse an anchor document into a {@link AnchorParseOutcome}; `undefined`
 * means "no document at all" (no file / nothing to read).
 */
export function parseAnchorEx(raw) {
    if (raw === undefined)
        return undefined;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        return { problem: 'unparseable' };
    }
    if (value === null || typeof value !== 'object' || value.v !== 1)
        return { problem: 'unparseable' };
    // Shape: the fields every anchor carries must be present with the right
    // type. `sig` is the exception — an absent signature is shape-legal text
    // but domain-dishonest (see below), so it is normalised here and charged
    // as `invalid`, keeping "cannot parse" and "parses but lies" separable.
    if (typeof value.keyId !== 'string' || typeof value.count !== 'number' || typeof value.head !== 'string') {
        return { problem: 'unparseable' };
    }
    if (value.workspaceKey !== undefined && typeof value.workspaceKey !== 'string')
        return { problem: 'unparseable' };
    const sig = typeof value.sig === 'string' ? value.sig : '';
    // Domain: no honest writer can produce these values (H-09). `-5`, `1e999`
    // and `2.5` counts, an empty keyId, a stripped signature — each is the
    // documented disarm recipe, and each now fails loudly instead of
    // silently switching the anchor's checks off.
    if (value.keyId === '' || sig === '' || !Number.isSafeInteger(value.count) || value.count < 0) {
        return { problem: 'invalid' };
    }
    return {
        anchor: {
            v: 1,
            keyId: value.keyId,
            count: value.count,
            head: value.head,
            sig,
            at: typeof value.at === 'string' ? value.at : '',
            // Present only on newer anchors; absence is tolerated (older anchor,
            // sig check reconstructed against workspaceKey: null by the audit
            // layer, data checks still apply).
            ...(typeof value.workspaceKey === 'string' ? { workspaceKey: value.workspaceKey } : {}),
        },
    };
}
/**
 * Parse and validate an anchor file's contents; `undefined` when unreadable
 * *or* when the document is a domain-invalid disarm shape (see
 * {@link parseAnchorEx} — callers that need the distinction use that).
 */
export function parseAnchor(raw) {
    return parseAnchorEx(raw)?.anchor;
}
/** The exact bytes a checkpoint signature commits to. */
export function checkpointSignedData(payload) {
    return canonicalJson(payload);
}
//# sourceMappingURL=trust.js.map