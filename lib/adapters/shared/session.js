/**
 * The adapter watcher's session state, as a value.
 *
 * `WorkspaceWatch` (dsh/observe.ts) is a long-lived object: one instance per
 * DSH plugin, mutated in place, memory is the truth. Adapter hosts give us no
 * such home — every hook invocation is a separate process that starts with
 * nothing — so the same semantics (touched / read / fingerprints, drift
 * detection) are re-expressed here as a plain serialisable snapshot plus pure
 * functions: load it, apply one observation, save it back. The drift rules
 * mirror observe.ts:184-214 case for case; where this file diverges it says so
 * and why in a comment.
 *
 * H-19 (v0.23): the snapshot file is self-checking. It carries a canonical
 * digest as its tail field, recomputed on every load; a file whose body does
 * not address itself is treated as damaged — reset to empty and announced on
 * stderr — instead of being trusted. This is a CONTENT check, not an
 * authenticated one: a same-user process can recompute the digest too. What
 * it buys honestly: the cheap forgery (hand-edit `firedNotices`, swap in a
 * pre-burned ledger, splice observations) stops being SILENT — the reset is
 * loud, and one-time notices that were "already fired" fire again. The
 * boundary of this defence is documented in the adapters: chain integrity
 * lives in the signed evidence log, not here.
 *
 * @module dsh-proof/adapters/shared/session
 */
import * as fsp from 'node:fs/promises';
import { canonicalJson, sha256 } from "../../core/hash.js";
import { isShellToolName, WorkspaceWatch, isMutationToolName, toWorkspaceRelative } from "../../dsh/observe.js";
/** A fresh session: nothing observed, window starting now. */
export function emptySession(nowIso) {
    return { touched: [], read: [], fingerprints: {}, windowStartedAt: nowIso, firedNotices: [], shellUsed: false };
}
/** Append without duplicates, preserving first-seen order (Set semantics as a value). */
function withPath(paths, rel) {
    return paths.includes(rel) ? [...paths] : [...paths, rel];
}
/**
 * Record one completed tool call against a session. Pure: returns a new
 * session (or the same reference when the call contributes nothing).
 *
 * Classification is the two-way split the adapter contract fixes:
 * mutation-name → touched, everything else with paths → read. observe.ts's
 * unknown-name default IS mutation now (H-01's anchored list), so the split
 * here inherits the conservative charge — an unrecognised write tool can
 * only over-record a touch, never escape attribution.
 *
 * Shell tools remain a documented blind spot for PATHS: a command line
 * carries no structured paths, and mining one for path-shaped words would
 * fingerprint noise. The safety net is that drift detection still catches a
 * shell changing a previously observed file — the bytes no longer match the
 * recorded fingerprint and no tool claimed the touch — so a shell cannot
 * silently invalidate what the session already knows; only attribution of
 * brand-new files escapes. What a shell call DOES contribute is the session
 * fact `shellUsed` (set once, never cleared), so the drift narrative never
 * asserts "outside your tool calls" in a session where that is unknowable.
 */
export async function applyObservation(session, toolName, toolInput, root, readFile) {
    if (isShellToolName(toolName)) {
        return session.shellUsed === true ? session : { ...session, shellUsed: true };
    }
    // Observer view (no contentKeys): 'source' stays out because in tool
    // arguments it far more often carries content than a path. The evidence
    // guard in gates.ts uses its own over-detecting view on purpose.
    const rels = WorkspaceWatch.pathsIn(toolInput)
        .map(raw => toWorkspaceRelative(raw, root))
        .filter((rel) => rel !== undefined);
    if (rels.length === 0)
        return session;
    const mutation = isMutationToolName(toolName);
    let touched = session.touched;
    let read = session.read;
    const fingerprints = { ...session.fingerprints };
    for (const rel of rels) {
        if (mutation)
            touched = withPath(touched, rel);
        else
            read = withPath(read, rel);
        // observe.ts's rule: fingerprint what the tool just saw, keep the old
        // record when the read fails (a file that no longer exists still has a
        // useful last-seen fingerprint — its disappearance IS drift signal).
        const content = await readFile(`${root}/${rel}`);
        if (content !== undefined)
            fingerprints[rel] = sha256(content);
    }
    return { ...session, touched, read, fingerprints };
}
/**
 * Compare the filesystem against the session's recorded fingerprints.
 *
 * Mirrors WorkspaceWatch.detectDrift (observe.ts:184-214), case for case:
 * - on disk ≠ recorded, and no tool touched it → drifted (external change);
 * - a drifted file the agent had READ → also staleReads (its in-context copy
 *   is now wrong — the corruption that matters most);
 * - file gone though once recorded → drifted (deletion is a change);
 * - on disk but never recorded (a read whose fingerprint failed) and not
 *   touched → drifted (arrived from outside the tool stream);
 * - a touched file never counts as drift, however its bytes moved — the
 *   agent's own work is exactly what drift must NOT cry wolf about.
 */
export async function computeDrift(session, root, readFile) {
    const touched = new Set(session.touched);
    const read = new Set(session.read);
    const drifted = [];
    const staleReads = [];
    // Candidate set = every fingerprint plus every read (a read without a
    // fingerprint is still worth one honest look at the disk).
    const candidates = [...new Set([...Object.keys(session.fingerprints), ...session.read])];
    for (const rel of candidates) {
        const content = await readFile(`${root}/${rel}`);
        const current = content === undefined ? undefined : sha256(content);
        const recorded = session.fingerprints[rel];
        if (current === undefined) {
            if (recorded !== undefined) {
                // File disappeared under us.
                drifted.push(rel);
                if (read.has(rel) && !touched.has(rel))
                    staleReads.push(rel);
            }
            continue;
        }
        if (recorded === undefined) {
            // Never fingerprinted through a tool: present on disk but not claimed.
            if (!touched.has(rel))
                drifted.push(rel);
            continue;
        }
        if (current !== recorded && !touched.has(rel)) {
            drifted.push(rel);
            if (read.has(rel))
                staleReads.push(rel);
        }
    }
    return {
        drifted: [...new Set(drifted)].sort(),
        staleReads: [...new Set(staleReads)].sort(),
    };
}
/**
 * Open a new drift window at a turn boundary: this-window touches reset (the
 * next turn's mutations start from zero), while fingerprints, reads and fired
 * notices survive — last-seen bytes and one-time notices are session facts,
 * not per-turn ones.
 */
export function windowStart(session, nowIso) {
    return { ...session, touched: [], windowStartedAt: nowIso };
}
/**
 * Where a session's snapshot lives. The session id is host-supplied (a
 * conversation id, anything), so every character outside [A-Za-z0-9._-] is
 * replaced with '_' before it ever touches the filesystem — '../../x' becomes
 * '.._.._x', a filename inside the session dir, not a walk out of it. Dots
 * survive but cannot traverse alone: a path segment needs a separator to
 * escape, and separators are exactly what is sanitised away.
 */
export function sessionPath(dir, sessionId) {
    const safe = sessionId.replace(/[^A-Za-z0-9._-]/g, '_');
    return `${dir.replace(/\/+$/, '')}/${safe}.json`;
}
// ---------------------------------------------------------------------------
// Persistence — atomic write, self-checking read (H-19)
// ---------------------------------------------------------------------------
/**
 * The snapshot's content digest: sha256 over the canonical form of the
 * session bound to its session id, so a file cannot be replayed into another
 * session (or another workspace's ledger — the dir itself is workspace-keyed)
 * without the check noticing. Tail-field discipline: everything the watcher
 * knows, then the digest of exactly that.
 */
export function sessionDigest(sessionId, session) {
    return sha256(canonicalJson({ sessionId, session }));
}
function isStringArray(value) {
    return Array.isArray(value) && value.every(item => typeof item === 'string');
}
/** Structural guard: a file that is not shaped like a session is not a session. */
function isAdapterSession(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const v = value;
    const fingerprints = v.fingerprints;
    return isStringArray(v.touched)
        && isStringArray(v.read)
        && isStringArray(v.firedNotices)
        && typeof v.windowStartedAt === 'string'
        && (v.shellUsed === undefined || typeof v.shellUsed === 'boolean')
        && typeof fingerprints === 'object' && fingerprints !== null && !Array.isArray(fingerprints)
        && Object.values(fingerprints).every(h => typeof h === 'string');
}
/** Best-effort stderr — the tamper/reset announcement must be visible, never fatal. */
function defaultAnnounce(line) {
    try {
        process.stderr.write(`${line}\n`);
    }
    catch {
        /* a closed stderr cannot stop the reset either */
    }
}
/**
 * Load a session snapshot; undefined when it does not exist, fails to parse,
 * does not look like a session, or FAILS ITS OWN DIGEST (H-19: a body that
 * does not address itself is damaged goods — reset and say so, never trust
 * it). The next hook process is the reader this function serves — it must
 * never crash on a half-written, foreign or forged file, it must just start
 * over (an empty session re-learns the workspace in one turn of observation),
 * with the reset ANNOUNCED so a tampered ledger cannot pass silently as a
 * working one. V5-L2 (v0.24): ALL THREE damage routes announce — unparsable
 * bytes and wrong-shaped bodies used to reset silently while only the digest
 * mismatch was loud, so the CHEAPER forgeries (overwriting the file with
 * garbage, splicing a foreign object) were the quiet ones, exactly backwards
 * from H-19's "tamper cannot pass silently" promise. An ABSENT file stays
 * silent on purpose: a first run is not damage.
 */
export async function loadSession(dir, sessionId, onDamaged) {
    const announce = onDamaged ?? defaultAnnounce;
    const at = sessionPath(dir, sessionId);
    let raw;
    try {
        raw = await fsp.readFile(at, 'utf8');
    }
    catch {
        return undefined;
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        announce(`dsh-proof: session snapshot ${at} is not parsable JSON (torn write or hand damage); `
            + `resetting the observation ledger — one-time notices will re-fire and drift re-learns in one turn of observation.`);
        return undefined;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        announce(`dsh-proof: session snapshot ${at} holds valid JSON that is not a session object; `
            + `resetting the observation ledger — one-time notices will re-fire and drift re-learns in one turn of observation.`);
        return undefined;
    }
    const record = parsed;
    const { digest, ...body } = record;
    if (!isAdapterSession(body)) {
        announce(`dsh-proof: session snapshot ${at} is not shaped like a session (missing or rotten fields); `
            + `resetting the observation ledger — one-time notices will re-fire and drift re-learns in one turn of observation.`);
        return undefined;
    }
    if (typeof digest !== 'string' || digest !== sessionDigest(sessionId, body)) {
        announce(`dsh-proof: session snapshot ${at} failed its integrity check `
            + `(hand-edited, forged, or written by a pre-v0.23 build); resetting the observation ledger — `
            + `one-time notices will re-fire and drift re-learns in one turn of observation.`);
        return undefined;
    }
    return body;
}
/**
 * Persist a session snapshot atomically: write a temp file beside the target,
 * then rename over it, with the content digest as the tail field (H-19). A
 * torn write is not hypothetical here — the writer and the reader are
 * different processes racing across hook invocations, and a crash mid-write
 * would otherwise hand the next hook a truncated JSON that (at best) resets
 * the watcher blind. Rename-on-POSIX and MoveFileEx on Windows both make the
 * replace all-or-nothing, so a reader sees the old or the new snapshot, never
 * half of either.
 */
export async function saveSession(dir, sessionId, session) {
    const target = sessionPath(dir, sessionId);
    await fsp.mkdir(dir, { recursive: true });
    const temp = `${target}.${process.pid}.tmp`;
    const body = `${JSON.stringify({ ...session, digest: sessionDigest(sessionId, session) }, null, 2)}\n`;
    await fsp.writeFile(temp, body, 'utf8');
    await fsp.rename(temp, target);
}
//# sourceMappingURL=session.js.map