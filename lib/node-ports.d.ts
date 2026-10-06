/**
 * Real Node implementations of the core ports.
 *
 * Kept out of `core/` on purpose: the domain layer must not know it is running
 * on Node, and these adapters are the only place allowed to spawn processes or
 * touch `node:fs`.
 *
 * @module dsh-proof/node-ports
 */
import type { Clock, CommandPort, CommandResult, CommandRunOptions, FileStat, FsPort, SignerPort, WalkOptions, WalkResult, WorkspacePort } from './core/ports.ts';
export declare class SystemClock implements Clock {
    now(): number;
}
/** What a parsed `.cmd` shim reduces to: a `node <script>` vector, a direct exe, or nothing. */
export type CmdShimResolution = {
    readonly node: string;
    readonly script: string;
} | {
    readonly exe: string;
};
/**
 * Parses an npm-generated `.cmd` shim into a spawnable argv head — the
 * world's fix for "user configured `pnpm test` and spawn said ENOENT"
 * without ever opening a shell.
 *
 * Conservative by contract: ANY ambiguity — two different targets, an
 * unresolved `%VAR%` inside the target, a directly-invoked script that would
 * itself need a shell or interpreter — returns `undefined`, and the caller
 * lets the raw spawn fail with its clean spawnError instead. Never guess.
 */
export declare function resolveCmdShim(cmdPath: string): CmdShimResolution | undefined;
/**
 * H-18: how long the port keeps waiting for `close` (exit + stdio EOF) after
 * it already knows the child is gone — the window in which a grandchild still
 * holding an inherited pipe must either let go or be declared "the pipes are
 * stuck". Also the grace added to the kill deadline for the absolute
 * settle-or-error backstop. Injectable so the deadline behaviour is testable
 * in real time instead of sleeping five seconds per case.
 */
export declare const PROCESS_TREE_GRACE_MS = 5000;
/** Spawns argv vectors without a shell — no quoting games, no injection surface. */
export declare class NodeCommandPort implements CommandPort {
    private readonly settleGraceMs;
    constructor(settleGraceMs?: number);
    run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult>;
}
export declare class NodeFsPort implements FsPort {
    readFile(filePath: string): Promise<string | undefined>;
    readDir(dirPath: string): Promise<string[] | undefined>;
    stat(filePath: string): Promise<FileStat | undefined>;
    walk(root: string, options?: WalkOptions): Promise<WalkResult>;
    appendLine(filePath: string, line: string): Promise<void>;
    readLines(filePath: string): Promise<string[]>;
    writeFile(filePath: string, contents: string): Promise<void>;
    mkdirp(dirPath: string): Promise<void>;
    /**
     * υ: recursive best-effort directory removal for transient artifacts (the
     * V8-coverage scratch tree a verification collects and then throws away).
     * Failure is swallowed on purpose: what lives under these paths is
     * regenerable staging, and a cleanup error must never fail a verification
     * that already produced its proof. `force` rides along so a read-only
     * leftover file or a Windows file-lock wart degrades to "still there until
     * the next run overwrites it" instead of an exception.
     */
    removeDir(dirPath: string): Promise<void>;
}
/**
 * Ed25519 checkpoint signer whose key lives in a host-side directory the
 * agent's sandboxed tools cannot write to (default DSH_HOME, never the
 * workspace). The private key is created with owner-only permissions on
 * first use and never leaves the directory.
 *
 * The trust asymmetry this buys: the model can recompute every hash in the
 * evidence log, but only this key can produce the checkpoint signatures the
 * audit chain accepts.
 */
export declare class NodeEd25519Signer implements SignerPort {
    readonly keyId: string;
    private readonly privateKeyPem;
    private readonly publicKeyPem;
    private constructor();
    /** Load the key from `dir`, creating it on first use. */
    static load(dir: string): Promise<NodeEd25519Signer>;
    sign(data: string): Promise<string>;
    verify(data: string, signature: string): Promise<boolean>;
}
/**
 * Parses `git status --porcelain -z` output into the set of paths it mentions.
 *
 * The `-z` stream is a sequence of NUL-terminated fields. Each entry begins
 * with a status field `XY <path>` (two status letters, a space, the path);
 * when the status contains `R` (rename) or `C` (copy) the ORIGINAL path
 * follows as a second bare field with no prefix — both halves are workspace
 * facts, so both are collected. Paths are emitted verbatim (`-z` performs no
 * C-quoting, so `sp ace.ts` arrives unquoted).
 *
 * Tolerant by design: a field without a status prefix (truncated or garbage
 * stream) is kept verbatim rather than dropped — dirtiness must never be
 * under-reported.
 */
export declare function parsePorcelainZ(output: string): string[];
/** Git-backed workspace facts. Degrades to "unknown" outside a work tree. */
export declare class GitWorkspace implements WorkspacePort {
    readonly root: string;
    private readonly commands;
    /**
     * Cached availability probe — with a B8-L4 twist: only a DEFINITIVE answer
     * (git ran and said "true", or ran and exited non-zero) is remembered for
     * the process lifetime. A probe that produced no answer at all (timeout
     * while an AV scanner warms up git.exe, a spawn failure) may have been
     * transient, so exactly one in-session re-probe is allowed before the
     * failure is believed — "the probe could not run" is not "there is no git".
     */
    private gitAvailablePromise;
    private gitAvailableDefinitive;
    private gitProbeAttempts;
    constructor(root: string, commands?: CommandPort, clock?: Clock);
    /**
     * Whether git can answer questions about this workspace at all — the binary
     * is present AND the root sits inside a work tree (E3). Probed and
     * remembered as described on the fields above: definitive answers never
     * re-probe; answer-less probes get one retry.
     *
     * `--is-inside-work-tree` exits non-zero outside any repository, but exits
     * ZERO with "false" inside a bare one — so the output is checked too, not
     * just the exit code, or a bare repo would pass as verifiable.
     */
    gitAvailable(): Promise<boolean>;
    gitHead(): Promise<string | null>;
    /**
     * H6: a failed git query is not an empty answer. `git status` returning
     * 128 (index.lock contention, a mid-crash repository) and a query killed
     * by its own timeout used to coerce into `[]` — indistinguishable from
     * "clean", which let committed changes vanish from change sets and old
     * evidence pass as fresh. Now the failure THROWS, naming the subcommand
     * and the exit code, and callers degrade loudly (the change-set resolution
     * marks itself degraded and forces a full run). `gitHead` keeps its
     * `string | null` contract — "no commit" is a legitimate answer there —
     * and `gitAvailable` keeps probing softly: "no git installed" is an
     * environment fact, not a query failure.
     */
    private requireGitOk;
    gitDirty(): Promise<string[]>;
    /**
     * Files modified since `ref`, relative to root — the session's change set.
     *
     * `git diff --name-only -z` emits a plain NUL-separated path list: every
     * path terminated by NUL, no status prefixes, no rename pairing, no
     * quoting — so `split('\0')` + dropping empty strings is the exact inverse.
     * A failed query rejects (see `requireGitOk`): never a silent empty set.
     */
    changedSince(ref: string): Promise<string[]>;
    /**
     * Untracked files (honouring .gitignore), relative to root.
     *
     * `git ls-files --others --exclude-standard -z` also emits a plain
     * NUL-separated path list (no prefixes, no quoting), so `split('\0')` +
     * dropping empty strings parses it exactly. A failed query rejects (see
     * `requireGitOk`): never a silent empty set.
     */
    untracked(): Promise<string[]>;
}
//# sourceMappingURL=node-ports.d.ts.map