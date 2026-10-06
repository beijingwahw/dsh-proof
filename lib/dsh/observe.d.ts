/**
 * Workspace truth tracking: which files the agent actually moved, and which
 * files moved behind its back.
 *
 * The failure this exists for: the user edits a file in their IDE (or a build
 * step, a formatter, a background process does), and the agent keeps reasoning
 * about the version it read ten minutes ago. "改了一个地方，另一个地方坏了".
 *
 * Method: record a content fingerprint whenever a tool reports a path, then
 * compare against the filesystem at turn boundaries. Files whose fingerprint
 * moved without a corresponding tool call are drift, and drift is injected as
 * corrective context rather than silently ignored.
 *
 * @module dsh-proof/dsh/observe
 */
import type { ToolExecution, ToolExecutionResult } from '../vendor/dsh-tools.ts';
import type { FsPort } from '../core/ports.ts';
/**
 * Tool-name classification — the single source both adapter layers consult
 * (the pre-execute gates in index.ts / gates.ts and the read/write split
 * below). It lives here so the watcher cannot drift from the gates again.
 *
 * H-01 (v0.23): the classification is an ANCHORED NAME LIST, not a word
 * pattern. The pre-v0.23 regex required a mutation verb to be delimited by
 * `^|[_-]`, so the camelCase names real hosts ship (`MultiEdit`,
 * `NotebookEdit` — both documented Claude Code mutators) matched nothing,
 * and because the gates are allowlist-shaped ("not a mutation → pass
 * through") those names walked every pre-execute gate while carrying a
 * `file_path` straight into the evidence store. Names are now enumerated;
 * anything the lists do not recognize is classified as a MUTATION — the
 * conservative charge — so an unrecognized write tool can only cost the
 * agent an over-recorded touch, never an unguarded write. Only a name on
 * the read-only list may classify as a read.
 */
/**
 * Explicitly recognized mutation tool names (matched case-insensitively,
 * whole-name anchored). The list is documentation plus override: unknown
 * names default to mutation anyway, but an explicit entry wins even if a
 * future read-only addition ever collided with it.
 */
export declare const MUTATION_TOOL_NAMES: readonly string[];
/**
 * Shell-class tool names (matched case-insensitively, whole-name anchored):
 * calls that execute an arbitrary host command — which can mutate anything,
 * through a `command` string this observer deliberately does not parse.
 */
export declare const SHELL_TOOL_NAMES: readonly string[];
/**
 * Read-only tool names (matched case-insensitively). The ONLY names that
 * classify as reads — camelCase host spellings (`Read`, `Grep`, `View`,
 * `Glob`, `LS`, `WebFetch`) fold onto their lowercase forms.
 */
export declare const READ_ONLY_TOOL_NAMES: readonly string[];
/** Tools whose calls constitute a workspace mutation. */
export declare const MUTATION_TOOL_RE: RegExp;
/** Tools that execute arbitrary host commands (which can mutate anything). */
export declare const SHELL_TOOL_RE: RegExp;
/** True when a tool call of this name can move workspace state. */
export declare function isMutationToolName(toolName: string): boolean;
/** True when a tool call of this name runs an arbitrary host command. */
export declare function isShellToolName(toolName: string): boolean;
export declare function shellCommandMentionsPath(command: string, targets: readonly string[]): boolean;
export declare function sweepToolInputStrings(toolInput: unknown): string[];
export interface DriftReport {
    /** Files whose content changed without a tool call touching them. */
    readonly drifted: readonly string[];
    /** Files the tool stream claims to have touched in this window. */
    readonly touched: readonly string[];
    /** Files the agent read but that are now different. */
    readonly staleReads: readonly string[];
    readonly scanned: number;
}
export declare class WorkspaceWatch {
    private readonly fs;
    private readonly root;
    /** path -> sha256 of the content last observed through a tool. */
    private readonly fingerprints;
    /** Paths touched by tool calls in the current window. */
    private readonly touched;
    /** Paths the agent has ever mutated through a tool, across windows (v0.3). */
    private readonly sessionTouched;
    /** Paths the agent has read through a tool (so staleness is meaningful). */
    private readonly read;
    /**
     * Tool names that only read, so their paths are "read" not "touched".
     * Consulted only after `isMutationToolName` says no (see `observe`) — the
     * shared, case-insensitive {@link READ_ONLY_TOOL_NAMES} list (H-01: a
     * camelCase `Read` from a real host used to miss the case-sensitive set,
     * fall to the default mutation charge, and permanently silence drift
     * detection for the files it read).
     */
    private readonly readOnlyTools;
    constructor(fs: FsPort, root: string);
    /**
     * Extract every path named by a tool call's arguments.
     *
     * Only keys name paths: a string counts when it sits under a path key
     * (`path`, `files`, …), and an array's string items count only when the
     * array itself sits under one (H9a) — a bare array anywhere else is argv
     * or content, not a path list. Nested objects still contribute their own
     * path keys.
     *
     * `contentKeys: true` re-admits the `source` key (and its array form) for
     * callers that prefer over-detection to precision — the evidence-store
     * guard in index.ts. A false positive there costs one user approval prompt;
     * a false negative lets a `move {source: '.proof/evidence.jsonl', dest: …}`
     * carry the log out of the guarded directory un-asked. The watcher itself
     * keeps the precise view: its misclassification cost is a wrong attribution,
     * which no prompt can undo.
     */
    static pathsIn(args: unknown, options?: {
        contentKeys?: boolean;
    }): string[];
    /**
     * True once this session has run any shell-class tool (`SHELL_TOOL_RE`) —
     * a session-level fact, deliberately NOT cleared by `windowStart`: once the
     * agent has had a shell, "file X is not in the touched set" no longer
     * proves "file X was changed outside the agent" — the shell's edits are
     * invisible to path extraction by construction (the command string is not
     * parsed). Consumers (drift attribution, change classification) must use
     * this to demote `external` to `unknown` rather than report a false
     * "edited behind your back". This observer states the fact; it does not
     * guess which paths the shell moved.
     */
    private shellUsed;
    /** Record one completed tool call. */
    observe(exec: Readonly<ToolExecution>, _result: Readonly<ToolExecutionResult>): Promise<void>;
    /** Files touched by tool calls since the last `windowStart`. */
    touchedPaths(): string[];
    /**
     * Files the agent has mutated through tools since the watcher was created —
     * the provenance set for change attribution (windows come and go; the
     * session's responsibility does not).
     */
    sessionTouchedPaths(): string[];
    /**
     * Whether any shell-class tool ran this session (H9b). Session-scoped like
     * `sessionTouchedPaths`: windows do not reset it, because the epistemic
     * fact it encodes ("a shell ran; path extraction has a blind spot") does
     * not age out.
     */
    sessionShellUsed(): boolean;
    /** Clear the touched window (called at turn boundaries). */
    windowStart(): void;
    /**
     * Compare the filesystem against recorded fingerprints.
     *
     * `drifted` is the interesting set: a file whose bytes moved without any
     * tool call claiming it. `staleReads` is the subset the agent has actually
     * seen, i.e. the ones that will corrupt its reasoning.
     */
    detectDrift(files?: readonly string[]): Promise<DriftReport>;
    /** Fingerprint every listed path without marking it touched. */
    snapshot(paths: readonly string[]): Promise<void>;
    private fingerprint;
}
/**
 * Project any path a tool can name onto the workspace's relative path space:
 * POSIX-absolute, Windows drive-absolute (`C:\ws\…` or `C:/ws/…`), and
 * already-relative forms all describe workspace files. A path that is absolute
 * but outside the root describes a different filesystem neighbourhood and
 * yields undefined — treating it as relative would let external files
 * masquerade as workspace state and agent edits be misattributed as external.
 *
 * Drive-absolute paths compare against the root case-insensitively: the same
 * Windows workspace legitimately arrives as `C:\…` from the host and as
 * `c:/…` from tools and language servers. POSIX stays case-sensitive.
 *
 * W13-L11 (v0.23): the relative branch folds `.`/`..` segments and refuses
 * the ones that ESCAPE. `../outside.txt` used to pass through verbatim and
 * the fingerprinter then read `${root}/../outside.txt` — a file OUTSIDE the
 * workspace, whose later external change reported as workspace drift; and
 * `a/../../b` walked out the same way. A relative path whose folded form
 * still carries a leading `..` names no workspace file and yields undefined,
 * exactly like an absolute path outside the root.
 */
export declare function toWorkspaceRelative(raw: string, root: string): string | undefined;
export declare function driftNarrative(report: DriftReport, options?: {
    shellUsed?: boolean;
}): string | undefined;
//# sourceMappingURL=observe.d.ts.map