/**
 * Objective check discovery.
 *
 * A "check" is a claim the *workspace itself* can answer: run this command and
 * look at the exit code. The agent never gets to define what counts as passing
 * — that is the whole point. Discovery reads the project's own build metadata
 * and turns it into `CheckSpec`s; explicit user configuration always wins.
 *
 * @module dsh-proof/core/checks
 */
import type { CheckKind, CheckSpec, CheckSource, FsPort } from './ports.ts';
/** Explicit override supplied through plugin configuration. */
export interface CheckConfigEntry {
    /** Human label. Defaults to the command. */
    label?: string;
    /** argv vector, or a shell string which is split on whitespace. */
    command: string | readonly string[];
    kind?: CheckKind;
    /**
     * Path prefixes this check covers. Defaults to `['*']` (always affected).
     * Use this to make incremental verification cheap and precise.
     */
    paths?: readonly string[];
    timeoutMs?: number;
    /** Skip auto-discovery entirely and use only `checks`. */
    exclusive?: boolean;
}
export interface DiscoverOptions {
    /** Explicit entries, always merged (and `exclusive` disables auto-discovery). */
    readonly checks?: readonly CheckConfigEntry[];
    /** Per-check timeout default. */
    readonly timeoutMs?: number;
    /** Names of package.json scripts considered verifiable. */
    readonly scriptKinds?: Readonly<Record<string, CheckKind>>;
}
declare const DEFAULT_SCRIPT_KINDS: Record<string, CheckKind>;
declare const DEFAULT_IGNORE_DIRS: string[];
/** Discover every objective check the workspace declares. */
export declare function discoverChecks(fs: FsPort, root: string, options?: DiscoverOptions): Promise<CheckSpec[]>;
/** Stable check identity: the discovery source plus the exact command. */
export declare function checkId(source: CheckSource, command: readonly string[], cwd?: string): string;
export { DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS };
//# sourceMappingURL=checks.d.ts.map