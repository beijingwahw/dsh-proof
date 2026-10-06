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

import { sha256 } from './hash.ts'
import type { FsPort, WorkspacePort } from './ports.ts'
import type { RelPath } from './impact.ts'

/** Who a change is attributable to. */
export type ChangeProvenance = 'agent' | 'external' | 'explicit' | 'unknown'

export interface ChangeRecord {
  readonly path: RelPath
  readonly provenance: ChangeProvenance
}

/** How the change set was derived — surfaced so degradation is visible. */
export type ChangeSetMethod = 'baseline-content' | 'git-head' | 'dirty-fallback' | 'explicit'

export interface ChangeSetResolution {
  /** Sorted paths that actually moved since the baseline (or as asserted). */
  readonly changed: readonly RelPath[]
  /** The same paths with provenance, for attribution. */
  readonly records: readonly ChangeRecord[]
  readonly method: ChangeSetMethod
  /** Dirt present at baseline whose content has not moved since — excluded. */
  readonly preExistingExcluded: readonly RelPath[]
  /** The commit the baseline was anchored to, when one existed. */
  readonly baselineHead: string | null
  /**
   * git was reported unavailable. Content anchoring (digest comparison against
   * the baseline's dirty set) remains fully valid — it needs no git — but every
   * git-derived signal is blind here: files that were *clean* at baseline and
   * changed since are invisible. To stay fail-safe, callers should treat this
   * as "force the full check set" rather than trust a narrowed change set.
   */
  readonly degraded?: true
}

export interface ChangeSetInput {
  readonly fs: FsPort
  readonly workspace: WorkspacePort
  /** Caller-asserted change set; skips derivation entirely. */
  readonly explicit?: readonly RelPath[]
  /** The baseline's workspace snapshot (head + dirty + content digests). */
  readonly baseline?: {
    readonly head: string | null
    readonly dirty: readonly RelPath[]
    readonly dirtyDigests?: Readonly<Record<string, string>>
  }
  /** Paths the agent's tool stream touched since the baseline, for provenance. */
  readonly touched?: readonly RelPath[]
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
  readonly uncertainExternal?: boolean
}

/**
 * Three-state git probe. A missing method means "host never implemented the
 * capability" — treat git as available so existing degradation paths keep
 * their behaviour. `false` is a definitive "git is unusable here": skip the
 * git queries entirely (they can only fail) and mark the resolution degraded.
 * A probe that *throws* is treated as available: we do not know it is broken,
 * and each git query still carries its own failure accounting (H6) — a
 * rejection degrades the resolution rather than answering "clean".
 */
async function gitUsable(workspace: WorkspacePort): Promise<boolean> {
  if (workspace.gitAvailable === undefined) return true
  return workspace.gitAvailable().catch(() => true)
}

/** Resolve which files moved since the baseline, and who moved them. */
export async function resolveChangeSet(input: ChangeSetInput): Promise<ChangeSetResolution> {
  // `touched: []` means "observed: the agent mutated nothing" — everything
  // changed is external. `touched: undefined` means no observation at all.
  const touchedProvided = input.touched !== undefined
  const touchedSet = new Set(input.touched ?? [])

  if (input.explicit !== undefined) {
    const changed = [...new Set(input.explicit)].sort()
    return {
      changed,
      records: changed.map(path => ({ path, provenance: 'explicit' as const })),
      method: 'explicit',
      preExistingExcluded: [],
      baselineHead: input.baseline?.head ?? null,
    }
  }

  const git = await gitUsable(input.workspace)

  if (input.baseline === undefined) {
    // Without git there is no dirty set to fall back to — the resolution
    // degrades to "nothing visible", and says so. A dirty query that FAILS
    // (H6) lands in the same place by the same reasoning: no observable
    // change set, but the blindness is surfaced via `degraded` instead of
    // masquerading as "clean" — downstream, degraded resolutions force a
    // full run rather than trust a narrowed set.
    let dirtyQueryFailed = false
    const dirty: readonly string[] = git
      ? await input.workspace.gitDirty().catch(() => {
          dirtyQueryFailed = true
          return [] as string[]
        })
      : []
    const changed = [...new Set(dirty)].sort()
    return {
      changed,
      records: changed.map(path => ({
        path,
        provenance: classify(path, touchedSet, touchedProvided, input.uncertainExternal === true),
      })),
      method: 'dirty-fallback',
      preExistingExcluded: [],
      baselineHead: null,
      ...(git && !dirtyQueryFailed ? {} : { degraded: true as const }),
    }
  }

  const baselineDirty = new Set(input.baseline.dirty)
  const digests = input.baseline.dirtyDigests
  // When git is down (or the probe is absent-but-unused), every query is
  // skipped rather than fired-and-failed: candidates then come from the
  // baseline's own dirty set, which content digests can still adjudicate
  // without git. When git is up but a query FAILS (H6), that source
  // contributes nothing while the surviving sources keep building the
  // candidate set — and the failure is recorded, because an empty answer
  // from a dead query is not evidence of cleanliness. Conservative by
  // construction: `degraded` resolutions force a full check run
  // downstream, which is exactly the net a lost dimension (committed
  // changes the diff never reported, untracked files ls-files never
  // listed) falls into.
  // M-27: an optional capability that the host never implemented is NOT the
  // same as a query that answered "nothing". A missing `changedSince` (with a
  // baseline head to compare against) means every committed change since the
  // baseline is invisible; a missing `untracked` means every new file is.
  // Both blind a dimension the resolution would otherwise narrow on, so both
  // set the same `degraded` flag a failed query does (H6): capability
  // absence and query failure must have equal weight — the flag, not a
  // quietly thinner candidate set, is what downstream forces the full run on.
  let capabilityMissing = false
  if (git && input.baseline.head !== null && input.workspace.changedSince === undefined) capabilityMissing = true
  if (git && input.workspace.untracked === undefined) capabilityMissing = true

  let gitQueryFailed = false
  let trackedDiff: readonly string[] = []
  let untrackedNow: readonly string[] = []
  let dirtyNow: readonly string[] = []
  if (git && input.baseline.head !== null && input.workspace.changedSince !== undefined) {
    try {
      trackedDiff = await input.workspace.changedSince(input.baseline.head)
    } catch {
      gitQueryFailed = true
    }
  }
  if (git && input.workspace.untracked !== undefined) {
    try {
      untrackedNow = await input.workspace.untracked()
    } catch {
      gitQueryFailed = true
    }
  }
  if (git) {
    try {
      dirtyNow = await input.workspace.gitDirty()
    } catch {
      gitQueryFailed = true
    }
  }

  // Everything that could possibly have moved: differs from the baseline
  // commit, is untracked now, is dirty now, or was already dirty at baseline
  // (the last one catches "dirty at baseline, reverted to HEAD since").
  const candidates = [...new Set([...trackedDiff, ...untrackedNow, ...dirtyNow, ...input.baseline.dirty])].sort()

  const changed: RelPath[] = []
  const excluded: RelPath[] = []
  for (const path of candidates) {
    if (!baselineDirty.has(path)) {
      // Clean at baseline: any observable difference from that state counts.
      if (trackedDiff.includes(path) || untrackedNow.includes(path) || dirtyNow.includes(path)) changed.push(path)
      continue
    }
    // Dirty at baseline: the recorded content digest is the anchor. Without
    // one (legacy baseline) we over-include rather than guess.
    if (digests !== undefined && Object.prototype.hasOwnProperty.call(digests, path)) {
      const content = await input.fs.readFile(`${input.workspace.root}/${path}`)
      const now = content === undefined ? undefined : sha256(content)
      if (now === digests[path]) {
        excluded.push(path) // bytes identical to baseline — stale dirt, not a change
        continue
      }
    }
    changed.push(path)
  }

  return {
    changed,
    records: changed.map(path => ({
      path,
      provenance: classify(path, touchedSet, touchedProvided, input.uncertainExternal === true),
    })),
    method: digests !== undefined ? 'baseline-content' : 'git-head',
    preExistingExcluded: excluded,
    baselineHead: input.baseline.head,
    ...(git && !gitQueryFailed && !capabilityMissing ? {} : { degraded: true as const }),
  }
}

/**
 * Who moved one file. `touched`/`explicit` keep their meaning; the only
 * H9b change is the negative branch: without a shell this session, absence
 * from the touched set is affirmative evidence of an external edit, and with
 * one it is merely an absence of evidence — `'unknown'`, never a false
 * `'external'`.
 */
function classify(
  path: RelPath,
  touchedSet: ReadonlySet<RelPath>,
  touchedProvided: boolean,
  uncertainExternal = false,
): ChangeProvenance {
  if (!touchedProvided) return 'unknown'
  if (touchedSet.has(path)) return 'agent'
  return uncertainExternal ? 'unknown' : 'external'
}
