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
/**
 * Everything the watcher knows about one session, in JSON.
 *
 * - `touched`/`read` are workspace-relative paths, session-cumulative,
 *   de-duplicated, insertion-ordered.
 * - `fingerprints` records the LAST bytes a tool call observed per path —
 *   the anchor drift detection compares the disk against. It survives
 *   `windowStart` (bytes do not become un-seen because a turn ended).
 * - `shellUsed` (M-29): a shell-class tool ran at least once this session.
 *   Like observe.ts's session-level fact it is never cleared — once a shell
 *   ran, "not in the touched set" no longer proves "changed outside the
 *   agent's tools", and the drift narrative must say so instead of accusing.
 *   Optional: pre-v0.23 snapshots predate it.
 */
export interface AdapterSession {
    readonly touched: string[];
    readonly read: string[];
    readonly fingerprints: Record<string, string>;
    readonly windowStartedAt: string;
    /** One-time notice ids already fired ('baseline'); 'verify' re-arms per turn since v0.23. */
    readonly firedNotices: string[];
    readonly shellUsed?: boolean;
}
/** A fresh session: nothing observed, window starting now. */
export declare function emptySession(nowIso: string): AdapterSession;
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
export declare function applyObservation(session: AdapterSession, toolName: string, toolInput: unknown, root: string, readFile: (abs: string) => Promise<string | undefined>): Promise<AdapterSession>;
/** What `computeDrift` found on the disk versus what tools claimed. */
export interface DriftResult {
    readonly drifted: string[];
    readonly staleReads: string[];
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
export declare function computeDrift(session: AdapterSession, root: string, readFile: (abs: string) => Promise<string | undefined>): Promise<DriftResult>;
/**
 * Open a new drift window at a turn boundary: this-window touches reset (the
 * next turn's mutations start from zero), while fingerprints, reads and fired
 * notices survive — last-seen bytes and one-time notices are session facts,
 * not per-turn ones.
 */
export declare function windowStart(session: AdapterSession, nowIso: string): AdapterSession;
/**
 * Where a session's snapshot lives. The session id is host-supplied (a
 * conversation id, anything), so every character outside [A-Za-z0-9._-] is
 * replaced with '_' before it ever touches the filesystem — '../../x' becomes
 * '.._.._x', a filename inside the session dir, not a walk out of it. Dots
 * survive but cannot traverse alone: a path segment needs a separator to
 * escape, and separators are exactly what is sanitised away.
 */
export declare function sessionPath(dir: string, sessionId: string): string;
/**
 * The snapshot's content digest: sha256 over the canonical form of the
 * session bound to its session id, so a file cannot be replayed into another
 * session (or another workspace's ledger — the dir itself is workspace-keyed)
 * without the check noticing. Tail-field discipline: everything the watcher
 * knows, then the digest of exactly that.
 */
export declare function sessionDigest(sessionId: string, session: AdapterSession): string;
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
export declare function loadSession(dir: string, sessionId: string, onDamaged?: (line: string) => void): Promise<AdapterSession | undefined>;
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
export declare function saveSession(dir: string, sessionId: string, session: AdapterSession): Promise<void>;
//# sourceMappingURL=session.d.ts.map