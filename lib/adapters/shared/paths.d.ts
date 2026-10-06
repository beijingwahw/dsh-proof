/**
 * Physical artifact locations for a host adapter (Claude Code, OpenCode, …).
 *
 * Adapter hooks do not share an address space with the MCP server that runs
 * the engine — every hook invocation is its own process — so the only way the
 * two sides can agree on where the evidence log, the baseline and the anchor
 * live is to derive those paths from the same inputs by the same rules. This
 * module IS that rule set, mirroring the engine's private derivations
 * (engine.ts constructor) and the standalone MCP entry's assembly
 * (app/mcp-entry.ts) so a hook process and a server process land on the same
 * bytes without either being able to ask the other.
 *
 * The evidence-store guard here (`touchesEvidencePath`) compares paths
 * through {@link foldHostPath} — THE one fold (X-H-12): device-namespace
 * prefixes (`\\?\`), separators, drive-relative forms, per-segment Win32
 * deformations, case and `..`/`.` detours all fold in that single function,
 * on both sides of every comparison. The guards used to carry private folds
 * (case in one, trailing dots in another, nothing anywhere for device
 * prefixes or drive-relative forms), and every seam between them was a
 * working bypass (W11/W12: real NTFS write into the store through `\\?\`
 * while all four lexical layers compared as false). src/index.ts's guard
 * mirrors the same rule set — if either face learns a new normalisation, the
 * other must learn it in the same batch (the lockstep rule, see the guard's
 * own comment).
 *
 * `resolveAdapterEnv` is the ONE place the DSH_PROOF_* environment contract
 * is parsed. Both host adapters consume it, and app/mcp-entry.ts (F9) aligns
 * with the same variable names through it — a variable only one face reads is
 * a forked deployment, not a configuration (H-21).
 *
 * @module dsh-proof/adapters/shared/paths
 */
/** Every location a host adapter needs, in one derivable bundle. */
export interface ProofPaths {
    /** Workspace root, POSIX-style ('/' separators, drive letters kept). */
    readonly root: string;
    /** Host-side trust root (keys, anchors, adapter sessions) — outside the workspace. */
    readonly trustRoot: string;
    /** 'workspace' keeps evidence inside the project; 'host' (default) moves it under trustRoot. */
    readonly evidenceStore: 'host' | 'workspace';
    /** The evidence store's relative segment inside the workspace (e.g. '.proof'). */
    readonly evidenceDir: string;
    /** Directory holding evidence.jsonl + baseline.json. */
    readonly logDir: string;
    /** The hash-chained evidence log. */
    readonly logPath: string;
    /** The anchored baseline the gates probe for. */
    readonly baselinePath: string;
    /** Out-of-band anchor directory (engine.ts's `${trustDir}/anchors/<key>` layout). */
    readonly anchorDir: string;
    /** The anchor file checkpoints mirror to. */
    readonly anchorPath: string;
    /** Where adapters persist per-session watcher snapshots — isolated per workspaceKey (H-19). */
    readonly sessionDir: string;
    /** Stable workspace identity: sha256(normalised root).slice(0, 16) — see {@link normalizeWorkspaceRoot}. */
    readonly workspaceKey: string;
}
/**
 * Windows drive letter, drive-letter path, backslash-UNC, or any leading
 * slash — ENGINE.TS's private absolute-path test VERBATIM (`[A-Za-z]:[\/]`,
 * `\\\\`, `\/`), plus the forward-slash UNC spelling that test folds through
 * its `\/` arm anyway (H-25: a backslashed UNC used to read as "relative",
 * silently parking the store INSIDE the workspace the operator asked to keep
 * it out of). The store-dir derivation must agree with the engine's or
 * adapters would read a different log than the one the engine appends to.
 *
 * V5-M6 (v0.24): exported, and src/index.ts's private third mirror RETIRED
 * onto it — that mirror lacked the backslash-UNC arm (`\\server\share\store`
 * read as a relative segment and was glued onto the workspace root), so a
 * UNC evidenceDir silently produced a garbage evidenceLogPath. One rule, one
 * spelling of the rule, consumed by both faces; if engine.ts's rule ever
 * moves, this mirror must move with it (M-65's glue, now literal).
 */
export declare function isAbsoluteHostPath(p: string): boolean;
/**
 * Canonical spelling for workspace IDENTITY (H-25 / M-39): backslashes fold
 * to '/', a Windows drive letter folds to lowercase, trailing slashes drop.
 * The pre-v0.23 key hashed the root exactly as the host spelled it, so one
 * directory legitimately arrived as four identities (`C:\proj`, `C:/proj`,
 * `c:\proj`, `C:\proj\`) and gates, engine and MCP server silently split
 * their stores. Hashing THIS form makes spelling variants one identity.
 *
 * Exported so index.ts / mcp-entry.ts (which mint the same key from
 * process.cwd() or DSH_PROOF_ROOT) can hash the identical string — the
 * byte-parity rule now lives in one function instead of N mirrors.
 */
export declare function normalizeWorkspaceRoot(raw: string): string;
/** The identity pair a root carries: the canonical spelling's key and the pre-v0.23 raw-hash key. */
export declare function workspaceKeyPair(rawRoot: string): {
    readonly normalized: string;
    readonly legacy: string;
};
/** Knobs for {@link deriveProofPaths}: the disk probe and diagnostics sink. */
export interface DeriveOptions {
    /**
     * Existence probe over the real filesystem. Default: `fs.existsSync`
     * guarded to `false`. Only consulted when the normalised and legacy
     * workspace keys DIFFER (a Windows-flavoured root); a pure derivation can
     * pass `{ pure: true }` and skip it.
     */
    readonly exists?: (p: string) => boolean;
    /** Diagnostics sink, one line per call. Default: best-effort process.stderr. */
    readonly warn?: (line: string) => void;
    /** Skip the on-disk identity probe: the key is then always the normalised one. */
    readonly pure?: boolean;
}
/**
 * Fail loudly on a RELATIVE trust root (X-H-15).
 *
 * Exported for the standalone entry faces (app/mcp-entry.ts and friends) that
 * parse `DSH_PROOF_TRUST_DIR` / `DSH_HOME` before they derive anything: call
 * this the moment the value is known, so a relative spelling kills the
 * process with a message naming the variable, instead of silently resolving
 * against the CWD (an agent-writable workspace) and writing the signing keys
 * into the sandbox. `deriveProofPaths` runs the same assertion itself — a
 * face that forgets to call this still cannot slip through. Drive-RELATIVE
 * forms (`C:rel`) count as relative: they resolve against the per-drive
 * current directory, which is the workspace for the hook process.
 */
export declare function assertAbsoluteTrustRoot(trustRoot: string): void;
/**
 * Derive every adapter-facing artifact path from a host's configuration.
 *
 * - `root` defaults to `process.cwd()` (what harnesses set as the session
 *   workspace, mirroring index.ts's `hostWorkspaceRoot` fallback).
 * - `trustRoot` defaults to `$DSH_HOME/proof` with `DSH_HOME` itself defaulting
 *   to `~/.dsh` — the mcp-entry derivation, byte for byte.
 * - `evidenceStore` switches to 'workspace' only on the exact string, like
 *   mcp-entry's env parse; anything else means host mode.
 * - `evidenceDir` is the workspace-mode relative segment (default '.proof').
 *
 * X-H-15: a relative `trustRoot` (from the argument or from a relative
 * DSH_HOME) THROWS here — see {@link assertAbsoluteTrustRoot}. The
 * derivation itself stays free of filesystem reads: the only disk contact is
 * the optional on-disk identity probe below, which `{ pure: true }` skips.
 *
 * Identity (H-25): the workspace key hashes {@link normalizeWorkspaceRoot}'s
 * output. Existing on-disk state is never orphaned: when the normalised key
 * has no anchor/workspace directory but the LEGACY (raw-hash) key does, the
 * legacy key stays in use and one stderr line explains the migration. Probe
 * order is anchors first (the engine's out-of-band commitment), then
 * workspaces (baselines exist without a signer too).
 *
 * Sessions (H-19): `sessionDir` is per-workspaceKey, so the same session id
 * in two workspaces can never observe into one ledger.
 */
export declare function deriveProofPaths(env?: {
    root?: string;
    trustRoot?: string;
    evidenceStore?: string;
    evidenceDir?: string;
}, options?: DeriveOptions): ProofPaths;
/**
 * THE one fold for host-path comparison (X-H-12): every guard in this module
 * and in gates.ts compares `foldHostPath` outputs, never raw spellings — the
 * pre-v0.23 guards each carried a private fold (case here, trailing dots
 * there, no prefix strip anywhere), and W11/W12 kept finding the seam between
 * them. One spelling in, one comparison string out:
 *
 * - `\\?\` / `\\.\` device prefixes stripped (either slash flavour, `UNC`
 *   sub-prefix folded to the UNC form) — the verbatim passthrough that made
 *   device-spelled writes invisible to four layers of lexical guards.
 * - backslashes folded to '/'.
 * - drive-relative `C:foo` projected onto the C-drive's current directory —
 *   for the hook process that directory IS the workspace root (the host
 *   contract), so `C:.proof/x` becomes the absolute store path it really
 *   names. A drive the process CWD is not on gets the drive root
 *   (`q:/foo`) — fresh-process semantics for the per-drive CWD; an inherited
 *   `=X:` environment variable pointing elsewhere is the documented residual
 *   approximation (over-deny direction, vanishing corner).
 * - drive letter and every segment lowercased: on Windows `.PROOF` is
 *   `.proof`; on a genuinely case-sensitive filesystem a case-colliding
 *   sibling also matches — the same over-deny price the H10 fold already
 *   paid, now paid uniformly in ONE place. (IDENTITY hashing is NOT this
 *   function: {@link normalizeWorkspaceRoot} keeps POSIX case-sensitive on
 *   purpose; this fold is for guard comparison only.)
 * - per-segment trailing dots/spaces folded (Win32 deformation, H-25).
 * - `.`/`..` segments lexically collapsed (leading `..` on a relative path
 *   kept as the escape marker).
 * - NUL truncation modelled: everything after the first NUL never reaches a
 *   native host's filename API, so the fold keeps the prefix the OS would
 *   keep (`.proof/evidence.jsonl\0junk` folds to `.proof/evidence.jsonl`)
 *   instead of rejecting the string outright (rejecting was the under-deny:
 *   a truncated write into the store compared as "not a path").
 *
 * No length cap, deliberately: the pre-fold guards blanked out on candidates
 * over 4096 bytes exactly when the `\\?\` prefix made such paths writable —
 * the cap and the attack were the same feature.
 *
 * RESIDUAL, comment-pinned (V5-L1 / W11-L-F): Win32 8.3 short names
 * (`EVIDEN~1.JSO`) are NOT folded. Expanding one is a filesystem QUERY, not
 * a lexical rule — the fold is pure by contract (every consumer compares
 * strings, several in synchronous gates), and Node exposes no
 * GetShortPathName. Pinned by test on a Windows volume where short-name
 * generation is off (the modern default): `dir /x` shows no alias for
 * `evidence.jsonl`, so the attack requires a volume with 8.3 creation
 * enabled AND the short spelling of an artifact — at which point the textual
 * sweep's bare-name needles are equally blind and the structured guard is
 * the only honest layer left. If a future fold learns short names, it must
 * do so for BOTH sides of every comparison in the same batch.
 */
export declare function foldHostPath(p: string): string;
/**
 * Does a candidate tool-call path land inside the evidence store this
 * workspace is configured to protect?
 *
 * Semantics mirror index.ts's guard, through {@link foldHostPath} — the ONE
 * fold both faces are contractually in lockstep on: project the candidate
 * onto the workspace's relative space (absolute host paths, either slash
 * flavour, drive OR UNC, device prefixes stripped, drive-relative forms
 * projected against the hook CWD, `.`/`..` detours collapsed; a path escaping
 * the root keeps its leading `..` and therefore never matches), then compare
 * case-folded segments. On a Windows host, `.PROOF/evidence.jsonl`,
 * `.proof./…` AND `\\?\C:\ws\.proof\…` name the same file as
 * `.proof/evidence.jsonl`; a comparison that missed any one of those
 * spellings let the agent walk the guard by respelling one letter, one dot or
 * one prefix. The price is that on a genuinely case-sensitive filesystem a
 * sibling `.PROOF` directory also matches — an over-deny that costs one
 * blocked call, versus an under-deny that costs the evidence log the whole
 * plugin exists to keep honest. If either guard face learns a new
 * normalisation, the other must learn it in the same batch.
 *
 * The `evidenceDir` segment folds here too even though `deriveProofPaths`
 * usually hands it over POSIX-spelled: a hand-assembled `ProofPaths` (a host
 * adapter, a future entry point) must not be able to re-open the
 * `'.\proof'`-vs-`./proof` hole index.ts closed — defence in depth on the
 * segment that names the store.
 *
 * A degenerate segment ('.', '', or anything that collapses to it like
 * 'a/..' — M-48/L-H) cannot be prefix-matched, so the guard narrows to what
 * the store concretely IS there: the artifact file names themselves.
 *
 * Host mode matches only ABSOLUTE candidates: the store lives outside the
 * workspace, so nothing the agent can name relatively is it — but an absolute
 * path into the trust-side store is exactly the H-26 write the guard exists
 * to refuse. Callers that can see both identity spellings (a migrated
 * deployment may still hold its store under the legacy workspace key) sweep
 * both with {@link absoluteInside} directly, as the gates do.
 */
/**
 * Lexical absolute-path containment, folded by {@link foldHostPath} on BOTH
 * sides (the one fold): separators unified, device prefixes stripped,
 * drive-relative forms projected, `..`/`.` collapsed, Win32
 * trailing-dot/space deformation folded, case folded (the over-deny price —
 * one blocked call on a case-sensitive host — versus an under-deny that costs
 * the chain). A relative candidate never contains an absolute dir; a
 * drive-relative candidate (`C:foo`, X-H-12) becomes the absolute path the OS
 * will really open, so it compares like any other.
 */
export declare function absoluteInside(candidate: string, dir: string): boolean;
export declare function touchesEvidencePath(candidate: string, paths: ProofPaths): boolean;
/**
 * Y-H-11 (v0.24): the Ed25519 signing-key pair's file names (node-ports'
 * spellings — the signer loads them from `<trustRoot>/keys`). A string value
 * naming either is worth refusing wherever it points — the key pair IS the
 * trust fabric (whoever holds the private half can forge every checkpoint
 * signature), and no legitimate workspace file carries these names. Exported
 * here so BOTH guard faces (gates.ts and src/index.ts) refuse the same names:
 * pre-v0.24 only the DSH plugin face listed them, and
 * `cp <trust>/keys/proof-signing-key.pem x` sailed through the adapter hooks
 * measured. Matched as segment-boundaried substrings after separator/case
 * folding by `shellCommandMentionsPath`; if node-ports ever renames a key
 * file, this list must move with it (grep-anchored there).
 */
export declare const SIGNING_KEY_FILE_NAMES: readonly string[];
/** What {@link guardedTargets} needs: where the store is, and where trust lives. */
export interface GuardedTargetOptions {
    readonly evidenceStore: 'host' | 'workspace';
    readonly evidenceDir: string;
    /**
     * The host trust root, when the caller knows it — adds the trust-side
     * artifacts (host-mode store, anchors, session ledgers, signing keys) to
     * the target set. Optional for callers that only reproduce the historical
     * workspace-store contract.
     */
    readonly trustRoot?: string;
}
/**
 * Every spelling of the store and trust artifacts a shell command must not
 * name — THE one target-set constructor both guard faces consume (V5-M1,
 * v0.24). Pre-v0.24 gates.ts and index.ts each hand-rolled this list and it
 * forked three ways the audit could drive a command through: the adapter
 * face missed the bare `<trust>/workspaces/<key>` DIRECTORY (`rm -rf` of the
 * whole store passed), BOTH faces missed the signing-key file names (Y-H-11)
 * and every `~`/env spelling of the default trust root (`rm -rf ~/.dsh/proof`
 * passed everywhere — no absolute needle matches a variable). One function,
 * consumed by both faces, so the two nets cannot drift apart again.
 *
 * Targets are FOLDED spellings (`foldHostPath`): `shellCommandMentionsPath`
 * folds the haystack the same way, so one spelling per target is enough
 * (`.proof/evidence.jsonl` also catches `.PROOF\EVIDENCE.JSONL`). The set:
 * - workspace mode: the store segment, its two artifact files, and the
 *   root-anchored spellings an absolute command would use (a degenerate
 *   segment — M-48 — narrows to the artifact file names themselves);
 * - trust side (either store mode, when `trustRoot` is known): the host-mode
 *   store DIRECTORY and files under BOTH identity keys (a migrated
 *   deployment still holds state under the legacy one), the anchor dirs, the
 *   adapter session ledgers, the `keys` directory, and — always — the two
 *   bare signing-key file names (Y-H-11: the names themselves are refused
 *   wherever they point);
 * - when the trust root IS the default `$DSH_HOME/proof` (DSH_HOME itself
 *   defaulting to `~/.dsh`), the `~`/`$DSH_HOME`/`$HOME` spellings of it:
 *   the textual sweep does no variable expansion, so the literal forms are
 *   listed (zero false positives in the default deployment — no legitimate
 *   command writes there; a custom trust root keeps its absolute needle).
 */
export declare function guardedTargets(root: string, options: GuardedTargetOptions): string[];
/**
 * What the DSH_PROOF_* environment spells, parsed once. THE contract for
 * every face that configures dsh-proof through environment variables —
 * the Claude Code hooks, the OpenCode plugin, and app/mcp-entry.ts (which
 * must honour the same variable names or the guard and the server protect
 * different stores: H-21/B3-H1).
 *
 * Semantics (shared, so two faces cannot drift):
 * - `DSH_PROOF_ROOT` / `DSH_PROOF_TRUST_DIR` / `DSH_PROOF_EVIDENCE_DIR`:
 *   non-empty strings pass through, absent/empty mean "not set".
 * - `DSH_PROOF_EVIDENCE_STORE`: only the exact string `'workspace'` means
 *   workspace mode; everything else (including unset) is host mode.
 * - `DSH_PROOF_REQUIRE_BASELINE`: `'off' | 'warn' | 'ask'` only, matched
 *   case-insensitively after a trim (W11-L10 — 'ASK' used to silently fall
 *   to the caller's 'warn' default); an invalid value is `undefined` so the
 *   caller's default (config.ts's 'warn') applies — never a crash, never a
 *   silent stricter/weaker mode.
 * - `DSH_PROOF_DRIFT` / `DSH_PROOF_ENFORCE_TURN_END`: default-on flags; the
 *   off spellings are `'0'`, `'false'`, `'no'`, `'off'` (case-insensitive —
 *   pre-v0.23 only the exact `'0'` turned a flag off, so `false` meant ON).
 */
export interface AdapterEnvValues {
    readonly root?: string;
    readonly trustRoot?: string;
    readonly evidenceStore?: string;
    readonly evidenceDir?: string;
    readonly requireBaseline?: 'off' | 'warn' | 'ask';
    readonly driftDetection?: boolean;
    readonly enforceTurnEnd?: boolean;
}
/**
 * Parse the shared DSH_PROOF_* contract from one environment object. Pure:
 * no defaults beyond "unset", no I/O — callers layer their own precedence
 * (options beat environment beats code default) on top of exactly these
 * values. Name is contract-frozen: every face must resolve through THIS
 * function so a variable cannot mean two things in two processes.
 */
export declare function resolveAdapterEnv(env: NodeJS.ProcessEnv | Record<string, string | undefined>): AdapterEnvValues;
//# sourceMappingURL=paths.d.ts.map