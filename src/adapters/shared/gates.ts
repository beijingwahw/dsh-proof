/**
 * The three decisions every host adapter needs, as host-agnostic functions.
 *
 * A pre-tool gate ("may this call run?"), a baseline probe ("is there
 * anything to attribute regressions against?") and a turn-end evaluation
 * ("must this turn be stopped and corrected?"). Claude Code and OpenCode
 * differ in how they surface these — permission prompts, stop hooks, message
 * injection — but not in what they mean; the semantics live here, mirroring
 * src/index.ts (the DSH adapter): the workspace evidence-store guard, the
 * requireBaseline off/warn/ask ladder, and drift-then-correction turn
 * stopping. Where this file deviates from index.ts it is deliberate and the
 * comment says why (case-insensitive guard via paths.ts; a deny where the
 * DSH host could only ask; one-time notices tracked in the session file
 * because no adapter process lives long enough to remember them).
 *
 * @module dsh-proof/adapters/shared/gates
 */

import {
  WorkspaceWatch, driftNarrative, isMutationToolName, shellCommandMentionsPath,
} from '../../dsh/observe.ts'
import { absoluteInside, deriveProofPaths, touchesEvidencePath, workspaceKeyPair } from './paths.ts'
import type { ProofPaths } from './paths.ts'
import type { AdapterSession, DriftResult } from './session.ts'
import { addressOf, merkleRoot } from '../../core/hash.ts'

// Re-exported for the host adapters: the gate surface (StopFacts.drift,
// evaluateStop's session parameter) is expressed in these types, so an
// adapter importing the gates should not need to know they were minted in
// session.ts.
export type { AdapterSession, DriftResult }

/** What a host configures for the two pre-tool gates. */
export interface GateOptions {
  readonly evidenceStore: 'host' | 'workspace'
  readonly evidenceDir: string
  readonly requireBaseline: 'off' | 'warn' | 'ask'
  /**
   * The host trust root, when the caller knows it — names the trust-side
   * artifacts (anchors, host-mode store) a shell command must not touch
   * either. Optional for callers that only reproduce the historical
   * workspace-store contract.
   */
  readonly trustRoot?: string
}

/**
 * The three ways a pre-tool call can go. The DSH host only had `ask`;
 * adapters get a real `deny` too — a host with a hard permission seam should
 * not have to fake certainty with a question.
 */
export type GateDecision =
  | { readonly action: 'allow' }
  | { readonly action: 'ask'; readonly reason: string }
  | { readonly action: 'deny'; readonly reason: string }

/**
 * The command string of a shell-class call, from whichever key the host
 * spells it under: a plain string, or a string ARGV (joined — `['node',
 * '-e', 'fs.writeFileSync(...)']` is one command semantically, and a
 * space-join is all the conservative substring sweep needs). Anything else
 * (nested objects, mixed arrays) is not a command this layer can read — and
 * an unreadable command on a mutation-capable tool falls through to the
 * baseline ladder, never to a silent allow.
 */
function shellCommandOf(toolInput: unknown): string | undefined {
  if (toolInput === null || typeof toolInput !== 'object' || Array.isArray(toolInput)) return undefined
  const record = toolInput as Record<string, unknown>
  for (const key of ['command', 'cmd', 'script']) {
    const value = record[key]
    if (typeof value === 'string') return value
    if (Array.isArray(value) && value.every(v => typeof v === 'string')) return value.join(' ')
  }
  return undefined
}

/**
 * Every spelling of the store and trust artifacts a shell command must not
 * name. `shellCommandMentionsPath` folds case and separators on both sides,
 * so one spelling per target is enough (`.proof/evidence.jsonl` also catches
 * `.PROOF\EVIDENCE.JSONL`). Substring semantics are the conservative
 * direction on purpose — `cd .proof && …`, `> .proof/evidence.jsonl` and
 * `rm -rf <trustRoot>/anchors/<key>` must all land; the price is an
 * occasional over-denied call whose reason says exactly why.
 */
function guardedShellTargets(root: string, options: GateOptions): string[] {
  const targets: string[] = []
  if (options.evidenceStore === 'workspace') {
    const dir = options.evidenceDir.replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '')
    if (dir !== '') {
      // The bare store directory, the artifacts inside it, and the
      // root-anchored spellings an absolute command would use.
      targets.push(dir, `${dir}/evidence.jsonl`, `${dir}/baseline.json`)
    } else {
      // Degenerate segment (M-48): the store IS the workspace root; guard the
      // artifact file names themselves.
      targets.push('evidence.jsonl', 'baseline.json')
    }
    const anchored = `${root.replace(/\/+$/, '')}/${dir}`.replace(/\/+$/, '')
    targets.push(anchored, `${anchored}/evidence.jsonl`, `${anchored}/baseline.json`)
  }
  if (options.trustRoot !== undefined && options.trustRoot.length > 0) {
    // Trust-side artifacts are never legitimately agent-writable in EITHER
    // store mode: the anchor mirrors every checkpoint and the host-mode store
    // lives here too. Both identity keys are listed — a migrated deployment
    // still holds state under the legacy one.
    const trust = options.trustRoot.replace(/\\/g, '/').replace(/\/+$/, '')
    const pair = workspaceKeyPair(root)
    for (const key of pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy]) {
      targets.push(`${trust}/anchors/${key}`, `${trust}/workspaces/${key}/evidence.jsonl`, `${trust}/workspaces/${key}/baseline.json`)
    }
  }
  return [...new Set(targets)].filter(t => t.length > 0)
}

/**
 * Decide one tool call before the host executes it.
 *
 * Priority (first match wins):
 * 1. DENY — workspace mode + a mutation tool naming any path inside the
 *    evidence store. The log is the thing auditing the agent; letting the
 *    audited party edit the audit is the one compromise this plugin cannot
 *    survive. Only mutation tools: reading the log back is legitimate (the
 *    model-facing proof tools do exactly that), it is writes the guard
 *    exists for — index.ts's semantics, kept here. The path view is the
 *    over-detecting one (`contentKeys: true`): a `move {source:
 *    '.proof/evidence.jsonl'}` must not slip the log out through a key the
 *    observer treats as content noise. A false positive costs one denied
 *    call; a false negative costs the chain.
 *    Since H-01 the mutation classification is an anchored name list with an
 *    unknown-name default of MUTATION — `MultiEdit` and `NotebookEdit` (real
 *    host mutators the old word-regex could not see) take this path like
 *    every other mutator, and `notebook_path` extracts like every path key.
 * 1b. DENY — a shell-class tool whose command string names the evidence
 *    store or the trust artifacts (H-02, v0.13 H9③ at last closed at the
 *    gate): `bash {command:'echo x > .proof/evidence.jsonl'}` carries no
 *    structured path key, so the structural sweep above is blind to it by
 *    construction. The command is swept textually, conservatively.
 * 2. ASK — a mutation with provably no baseline under requireBaseline 'ask'.
 *    `hasBaseline === undefined` means "unknown" and never blocks (mirrors
 *    index.ts, where a baseline probe that throws passes the call through).
 * 3. ALLOW.
 *
 * requireBaseline 'warn' is invisible here by design: warn passes the call
 * and owes the model a corrective notice instead — that is `evaluateStop`'s
 * rule 2, at turn end, where the model can still act on it.
 */
export function decidePreToolUse(
  toolName: string,
  toolInput: unknown,
  root: string,
  options: GateOptions,
  hasBaseline: boolean | undefined,
): GateDecision {
  if (isMutationToolName(toolName) && (options.evidenceStore === 'workspace' || options.trustRoot !== undefined)) {
    const candidates = WorkspaceWatch.pathsIn(toolInput, { contentKeys: true })
    let touches = false
    let hostMode = false
    if (options.evidenceStore === 'workspace') {
      // pure derivation: this sweep only consumes root/evidenceDir/evidenceStore
      // (the key is never read here), so the identity probe is skipped.
      const paths = deriveProofPaths({
        root,
        evidenceStore: options.evidenceStore,
        evidenceDir: options.evidenceDir,
      }, { pure: true })
      touches = candidates.some(candidate => touchesEvidencePath(candidate, paths))
    } else {
      // H-26 structured half: host mode moves the store under the trust root,
      // outside the workspace — a workspace-RELATIVE path cannot reach it, but
      // an ABSOLUTE path into `<trustRoot>/workspaces/<key>` is precisely the
      // "the store is outside the sandbox" promise this guard must keep. Both
      // identity spellings are swept (a migrated deployment may still hold
      // its store under the legacy key), the same pair the shell rule lists.
      hostMode = true
      const trust = options.trustRoot!.replace(/\\/g, '/').replace(/\/+$/, '')
      const pair = workspaceKeyPair(root)
      const keys = pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy]
      const storeDirs = keys.map(key => `${trust}/workspaces/${key}`)
      touches = candidates.some(candidate => storeDirs.some(dir => absoluteInside(candidate, dir)))
    }
    if (touches) {
      return {
        action: 'deny',
        reason: hostMode
          ? 'dsh-proof: this call writes into the host-side verification evidence store by absolute '
            + 'path — the store lives outside the workspace precisely so the agent it audits cannot '
            + 'edit it. Evidence changes go through a human, never through your own tools.'
          : 'dsh-proof: this call writes into the verification evidence store, which must not be '
            + 'modified by the agent it is meant to audit. Evidence changes go through host mode '
            + '(store outside the workspace) or a human — never through your own tools.',
      }
    }
  }
  if (isMutationToolName(toolName)) {
    const command = shellCommandOf(toolInput)
    // N-1 (red team, v0.22): the sweep is gated on CAPABILITY, not on a name
    // list — any mutation-class call that carries a command string is swept,
    // because hosts mint runner names faster than lists collect them
    // (`sh`, `python`, `node`, `powershell`, `cmd`, `eval`, … all execute
    // commands; only the read-only roster is exempt).
    if (command !== undefined && command.length > 0
      && shellCommandMentionsPath(command, guardedShellTargets(root, options))) {
      return {
        action: 'deny',
        reason: 'dsh-proof: this command names the verification evidence store or its trust files, '
          + 'which must not be modified by the agent they are meant to audit. Command strings cannot be '
          + 'path-checked structurally, so any mention of the store is refused — run the command without '
          + 'the evidence paths, or route evidence changes through a human.',
      }
    }
  }
  if (isMutationToolName(toolName) && hasBaseline === false && options.requireBaseline === 'ask') {
    return {
      action: 'ask',
      reason: `dsh-proof: no verification baseline exists yet, and \`${toolName}\` mutates the workspace. `
        + 'Establish one first with the proof_baseline MCP tool so later failures can be attributed correctly.',
    }
  }
  return { action: 'allow' }
}

/**
 * The evidence-record shape the baseline recompute needs (see
 * {@link hasBaselineOnDisk}). Only the addressing fields are inspected — the
 * full Evidence record carries more, and none of it changes the address.
 */
interface AddressedEvidence {
  readonly checkId?: unknown
  readonly evidenceId?: unknown
}

interface BaselineFileShape {
  readonly baselineId?: unknown
  readonly createdAt?: unknown
  readonly workspace?: unknown
  readonly checks?: unknown
  readonly root?: unknown
}

/**
 * Recompute the baseline's self-address from its own contents, exactly the
 * way `buildBaseline` minted it (evidence.ts): the merkle root over the
 * check evidence addresses, then `addressOf` over {createdAt, workspace,
 * checkIds, root}. This mirrors the engine-side recompute interface (F2's
 * baselineId work); if that formula ever moves, this mirror must move with
 * it — a gate that validates against a stale formula is worse than none.
 */
function baselineSelfAddress(parsed: BaselineFileShape): string | undefined {
  if (typeof parsed.createdAt !== 'string'
    || parsed.workspace === null || typeof parsed.workspace !== 'object' || Array.isArray(parsed.workspace)) {
    return undefined
  }
  if (!Array.isArray(parsed.checks) || typeof parsed.root !== 'string') return undefined
  const checks = parsed.checks as AddressedEvidence[]
  if (!checks.every(c => c !== null && typeof c === 'object' && !Array.isArray(c)
    && typeof c.checkId === 'string' && typeof c.evidenceId === 'string')) {
    return undefined
  }
  // The recorded merkle root must BE the root of the recorded evidence —
  // buildBaseline never writes a mismatched pair, so a mismatch is damage.
  const root = merkleRoot(checks.map(c => c.evidenceId as string))
  if (root !== parsed.root) return undefined
  const material = {
    createdAt: parsed.createdAt,
    workspace: parsed.workspace,
    checkIds: checks.map(c => c.checkId as string),
    root,
  }
  try {
    return addressOf(material)
  } catch {
    // A workspace snapshot that cannot canonicalise (exotic prototype) is
    // not a baseline any engine wrote; "no baseline" is the honest verdict.
    return undefined
  }
}

/**
 * Does a REAL baseline exist at the adapter-derived path?
 *
 * H-20 (v0.23): shape is not enough. The old check accepted any parsable
 * JSON with a string `baselineId` — and in workspace mode the baseline file
 * sits in the agent-writable area, so a 20-byte `{"baselineId":"forged"}`
 * permanently dismissed the baseline gate (ask ladder released, notices
 * silenced). True now requires the file to address ITSELF: the check
 * evidence addresses must merkle to the recorded root, and the recorded
 * id must equal the address of exactly that material — the same identity
 * `buildBaseline` computes. A forged file that satisfies this is a fully
 * self-consistent baseline, which is a strictly harder lie than 20 bytes and
 * the strongest statement this layer can make without the signing key (the
 * chain's `baseline/saved` digest remains the engine-side authority).
 */
export async function hasBaselineOnDisk(
  paths: ProofPaths,
  readFile: (abs: string) => Promise<string | undefined>,
): Promise<boolean> {
  const raw = await readFile(paths.baselinePath)
  if (raw === undefined) return false
  try {
    const parsed = JSON.parse(raw) as BaselineFileShape
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false
    if (typeof parsed.baselineId !== 'string') return false
    return baselineSelfAddress(parsed) === parsed.baselineId
  } catch {
    return false
  }
}

/** The facts a turn-end evaluation needs, gathered by the host adapter. */
export interface StopFacts {
  /** This turn's drift computation, when drift detection is on. */
  readonly drift: DriftResult | undefined
  /** How many files this window's tool calls touched. */
  readonly touchedCount: number
  readonly hasBaseline: boolean
  readonly requireBaseline: 'off' | 'warn' | 'ask'
  readonly enforceOnTurnEnd: boolean
  readonly driftDetection: boolean
}

/**
 * Decide whether a turn may stop, and what to tell the model if not.
 *
 * Returns `{ block, fire }`: `block` is the message the host must surface
 * (and keep the turn alive for); `fire` is the one-time notice id the CALLER
 * must write back into the session's `firedNotices` — evaluateStop never
 * mutates the session (pure function, session-as-value discipline), it only
 * names what its caller owes the ledger.
 *
 * Priority (first match wins):
 * 1. Drift blocks, EVERY time — "the workspace moved outside your tool
 *    calls" is a fact about the present disk, not a nag; by next turn it can
 *    be a different file. Not a one-time notice, so no `fire`. The text is
 *    `driftNarrative`'s, exactly: staleReads first (the corruption that
 *    poisons the model's in-context copies), then the rest of the drift,
 *    then the remedy — re-read, then proof_verify. When the session has used
 *    a shell this session, the narrative says so instead of accusing (a
 *    shell's edits are invisible to path attribution — the accusation would
 *    be false in the plugin's authoritative voice).
 * 2. One-time 'baseline': mutations happened, no baseline exists, the ladder
 *    is not 'off' (both 'warn' and 'ask' end a turn here — 'ask' already
 *    gated each call, but an unknown tool can still have slipped a mutation
 *    through, and the turn end is the last honest checkpoint). ONE-TIME per
 *    session: the missing-baseline state does not change turn to turn.
 * 3. 'verify': mutations happened, a baseline exists, turn-end enforcement
 *    is on — the work was never re-verified against it. Re-arms EVERY turn
 *    (v0.23, M-45): the DSH host's turn-end rule fires every turn that
 *    mutated without a proven claim, and a notice the audited party can
 *    burn once (ignore it, let it fire, stay silent forever after) is not
 *    enforcement — each mutating turn owes its own verification. `fire` is
 *    still returned (the ledger keeps the fact) but no longer suppresses.
 * 4. Nothing to say: the turn may stop.
 */
export function evaluateStop(
  facts: StopFacts,
  session: AdapterSession,
): { block?: string; fire?: string } {
  if (facts.driftDetection && facts.drift !== undefined
    && (facts.drift.drifted.length > 0 || facts.drift.staleReads.length > 0)) {
    const narrative = driftNarrative({
      drifted: [...facts.drift.drifted],
      touched: [...session.touched],
      staleReads: [...facts.drift.staleReads],
      // DriftResult does not carry the scan count; the narrative never reads
      // it, and what it would describe (how many files were compared) is not
      // a fact this gate decides on.
      scanned: facts.drift.drifted.length + facts.drift.staleReads.length,
    }, { shellUsed: session.shellUsed === true })
    if (narrative !== undefined) return { block: narrative }
  }
  if (facts.touchedCount > 0 && !facts.hasBaseline && facts.requireBaseline !== 'off'
    && !session.firedNotices.includes('baseline')) {
    return {
      block: '⚠️ dsh-proof: this turn mutated the workspace, but it has no completion-proof baseline. '
        + 'Call the proof_baseline MCP tool to establish one so later failures can be attributed to your changes.',
      fire: 'baseline',
    }
  }
  if (facts.touchedCount > 0 && facts.hasBaseline && facts.enforceOnTurnEnd) {
    return {
      block: '⚠️ dsh-proof: this turn mutated the workspace, but the changes have not been verified against the '
        + 'baseline. Call the proof_verify MCP tool before reporting completion — a prose assertion is not evidence.',
      fire: 'verify',
    }
  }
  return {}
}
