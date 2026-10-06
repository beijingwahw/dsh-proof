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

import { WorkspaceWatch, driftNarrative, isMutationToolName } from '../../dsh/observe.ts'
import { deriveProofPaths, touchesEvidencePath } from './paths.ts'
import type { ProofPaths } from './paths.ts'
import type { AdapterSession, DriftResult } from './session.ts'

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
  if (options.evidenceStore === 'workspace' && isMutationToolName(toolName)) {
    const paths = deriveProofPaths({
      root,
      evidenceStore: options.evidenceStore,
      evidenceDir: options.evidenceDir,
    })
    const touches = WorkspaceWatch.pathsIn(toolInput, { contentKeys: true })
      .some(candidate => touchesEvidencePath(candidate, paths))
    if (touches) {
      return {
        action: 'deny',
        reason: 'dsh-proof: this call writes into the verification evidence store, which must not be '
          + 'modified by the agent it is meant to audit. Evidence changes go through host mode '
          + '(store outside the workspace) or a human — never through your own tools.',
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
 * Does a real, loadable baseline exist at the adapter-derived path? True only
 * when the file reads AND parses AND carries a string `baselineId` — a
 * truncated or foreign JSON is honestly "no baseline", because that is
 * exactly what the engine's own loader would conclude from it.
 */
export async function hasBaselineOnDisk(
  paths: ProofPaths,
  readFile: (abs: string) => Promise<string | undefined>,
): Promise<boolean> {
  const raw = await readFile(paths.baselinePath)
  if (raw === undefined) return false
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed === null || typeof parsed !== 'object') return false
    return typeof (parsed as { baselineId?: unknown }).baselineId === 'string'
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
 *    then the remedy — re-read, then proof_verify.
 * 2. One-time 'baseline': mutations happened, no baseline exists, the ladder
 *    is not 'off' (both 'warn' and 'ask' end a turn here — 'ask' already
 *    gated each call, but an unknown tool can still have slipped a mutation
 *    through, and the turn end is the last honest checkpoint).
 * 3. One-time 'verify': mutations happened, a baseline exists, turn-end
 *    enforcement is on — the work was never re-verified against it.
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
    })
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
  if (facts.touchedCount > 0 && facts.hasBaseline && facts.enforceOnTurnEnd
    && !session.firedNotices.includes('verify')) {
    return {
      block: '⚠️ dsh-proof: this turn mutated the workspace, but the changes have not been verified against the '
        + 'baseline. Call the proof_verify MCP tool before reporting completion — a prose assertion is not evidence.',
      fire: 'verify',
    }
  }
  return {}
}
