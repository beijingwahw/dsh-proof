/**
 * Change-set resolution: from "whatever git says is dirty" to a
 * content-anchored, provenance-aware account of what actually moved since
 * the baseline.
 *
 * The failure this exists for: `git status --porcelain` mixes together (a)
 * dirt that existed *before* the baseline was recorded, (b) files the *user*
 * edited in their IDE, and (c) files the agent actually changed through its
 * tool stream. Charging all three to the session is how an honest agent
 * inherits blame for work it never did — and how stale dirt silently
 * widens every incremental verification.
 *
 * The anchor is content, not commits: baseline checks ran against the
 * *working tree as it was* (dirt included), so the reference state is the
 * baseline snapshot — its commit, its dirty list, and a digest of every
 * dirty file's content at that moment. A file counts as changed when its
 * bytes differ from that snapshot, whatever git says.
 *
 * @module dsh-proof/core/changeset
 */
import type { FsPort, WorkspacePort } from './ports.ts';
import type { RelPath } from './impact.ts';
/** Who a change is attributable to. */
export type ChangeProvenance = 'agent' | 'external' | 'explicit' | 'unknown';
export interface ChangeRecord {
    readonly path: RelPath;
    readonly provenance: ChangeProvenance;
}
/** How the change set was derived — surfaced so degradation is visible. */
export type ChangeSetMethod = 'baseline-content' | 'git-head' | 'dirty-fallback' | 'explicit';
export interface ChangeSetResolution {
    /** Sorted paths that actually moved since the baseline (or as asserted). */
    readonly changed: readonly RelPath[];
    /** The same paths with provenance, for attribution. */
    readonly records: readonly ChangeRecord[];
    readonly method: ChangeSetMethod;
    /** Dirt present at baseline whose content has not moved since — excluded. */
    readonly preExistingExcluded: readonly RelPath[];
    /** The commit the baseline was anchored to, when one existed. */
    readonly baselineHead: string | null;
    /**
     * git was reported unavailable. Content anchoring (digest comparison against
     * the baseline's dirty set) remains fully valid — it needs no git — but every
     * git-derived signal is blind here: files that were *clean* at baseline and
     * changed since are invisible. To stay fail-safe, callers should treat this
     * as "force the full check set" rather than trust a narrowed change set.
     */
    readonly degraded?: true;
}
export interface ChangeSetInput {
    readonly fs: FsPort;
    readonly workspace: WorkspacePort;
    /** Caller-asserted change set; skips derivation entirely. */
    readonly explicit?: readonly RelPath[];
    /** The baseline's workspace snapshot (head + dirty + content digests). */
    readonly baseline?: {
        readonly head: string | null;
        readonly dirty: readonly RelPath[];
        readonly dirtyDigests?: Readonly<Record<string, string>>;
    };
    /** Paths the agent's tool stream touched since the baseline, for provenance. */
    readonly touched?: readonly RelPath[];
    /**
     * H9b: a shell-class tool ran this session (`WorkspaceWatch.sessionShellUsed`).
     * Path extraction cannot see through a command string — `bash -c "prettier -w
     * src/a.ts"` mutates files no key of the tool call names — so once a shell
     * has run, "this file is not in `touched`" no longer proves "this file was
     * changed outside the agent's tool stream". When set, non-touched changes
     * classify as `'unknown'` instead of `'external'`: attribution would rather
     * say nothing than misreport an agent edit as an external one (the honest
     * boundary, externalised — drift narratives and external-suspect charging
     * both read the demotion).
     */
    readonly uncertainExternal?: boolean;
}
/** Resolve which files moved since the baseline, and who moved them. */
export declare function resolveChangeSet(input: ChangeSetInput): Promise<ChangeSetResolution>;
//# sourceMappingURL=changeset.d.ts.map