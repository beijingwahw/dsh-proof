/**
 * `dsh-proof` — Evidence-Driven Completion Proof & Regression Attribution.
 *
 * A DeepSeek Harness plugin that turns "I'm done" from a self-report into a
 * recomputable evidence chain, and "I fixed it but broke something else" from a
 * post-mortem into in-flight attribution.
 *
 * Architecture (three layers, one thesis):
 *
 *   src/core/*      pure domain — checks, evidence, impact, verdicts, reports
 *                   zero `@deepseek-ai/*` imports, all I/O through ports
 *   src/engine.ts   ProofEngine — the imperative façade hosts call
 *   src/dsh/*       thin Cordis adapter — tools, hooks, prompt section
 *
 * @module dsh-proof
 */
import type { Context } from '@deepseek-ai/cordis';
import type { Config } from './config.ts';
import { ProofEngine } from './engine.ts';
export declare const name = "dsh-proof";
export declare const inject: string[];
export { Config } from './config.ts';
export type { Config as DshProofConfig } from './config.ts';
export declare function apply(ctx: Context, config: Config): void;
/**
 * v0.19: the worker's handoff instruction the agent-team bridge injects into
 * a delegated subtask's context. Worded after the MCP `proof_delegate` face's
 * own handoff (src/app/mcp-server.ts `handoffInstruction`) — same protocol
 * steps, same precondition sentence — so a worker reached through the bridge
 * and one reached through proof_direct MCP are told exactly the same thing.
 * Exported for the wiring tests, which pin its textual elements.
 */
export declare function teamHandoffInstruction(taskId: string, obligationId: string, claim: string): string;
/**
 * H-02/X-H-13: the Ed25519 signing-key pair's file names — MOVED (Y-H-11,
 * v0.24) to paths.ts `SIGNING_KEY_FILE_NAMES` so both guard faces refuse the
 * same names; see there. This face and the adapter gates both consume the
 * shared export through `guardedTargets` now.
 */
export { ProofEngine };
export type { ProofReport, ProofGrade } from './core/evidence.ts';
//# sourceMappingURL=index.d.ts.map