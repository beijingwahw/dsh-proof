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

import type { Context } from '@deepseek-ai/cordis'
import { homedir } from 'node:os'
import * as nodePath from 'node:path'

import type { Config } from './config.ts'
import { ProofEngine } from './engine.ts'
import { createProofTools } from './dsh/tools.ts'
import { WorkspaceWatch, driftNarrative } from './dsh/observe.ts'
import { buildPolicySection } from './dsh/prompt.ts'
import { sha256 } from './core/hash.ts'
import type { FsPort } from './core/ports.ts'
import type {
  ContentBlock, PreToolDecision, ToolExecution, ToolExecutionResult, ToolRuntimeLike, UserMessage,
} from './vendor/dsh-tools.ts'

export const name = 'dsh-proof'
export const inject = ['tools']

// The Schemastery schema AND the `Config` type, exactly as DSH's contract asks.
export { Config } from './config.ts'
export type { Config as DshProofConfig } from './config.ts'

// ---------------------------------------------------------------------------
// Host surface this adapter consumes.
//
// Declared structurally instead of through `declare module '@deepseek-ai/cordis'`
// on purpose: the real `@deepseek-ai/dsh-tools` already augments `Events` and
// `Context`, and two augmentations of the same member with different `this`
// types are a hard compile error. A narrow local interface costs nothing at
// runtime (it is erased) and cannot clash with upstream.
// ---------------------------------------------------------------------------

interface PromptSection {
  id: string
  title?: string
  order?: number
  scope?: string
  content: string | (() => string)
}

interface AgentLike {
  inject(message: UserMessage): void
  readonly id?: unknown
}

interface Emitter {
  on(event: 'tools/pre-execute', handler: (exec: ToolExecution, next: () => Promise<PreToolDecision>) => Promise<PreToolDecision>): unknown
  on(event: 'tools/post-execute', handler: (exec: ToolExecution, result: Readonly<ToolExecutionResult>, next: () => Promise<unknown>) => Promise<unknown>): unknown
  on(event: 'tools/result', handler: (exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>) => void): unknown
  on(event: 'agent/turn-stopping', handler: (payload: { agent: AgentLike; turn: number; signal: AbortSignal }) => Promise<void> | void): unknown
}

interface HostContext extends Emitter {
  tools: ToolRuntimeLike
  systemPrompt?: { section(section: PromptSection): () => void }
  effect(disposer: () => void | (() => void)): unknown
}

/** Tools whose calls constitute a workspace mutation. */
const MUTATION_TOOL_RE = /(^|[_-])(write|edit|create|patch|delete|remove|move|rename|mkdir|touch|apply|install|update|upsert)([_-]|$)/i
const SHELL_TOOL_RE = /^(bash|shell|exec|run_code|run_command|terminal|process|task|npm|pnpm|yarn|pip|cargo|go|make)$/i

function isMutationTool(toolName: string): boolean {
  return MUTATION_TOOL_RE.test(toolName) || SHELL_TOOL_RE.test(toolName)
}

export function apply(ctx: Context, config: Config): void {
  const host = ctx as unknown as HostContext
  const root = process.env.DSH_PROOF_ROOT
    ?? hostWorkspaceRoot(ctx)

  // -- trust root: keys and anchors live with the host, never in the workspace.
  const trustRoot = (config.trustDir && config.trustDir.length > 0 ? config.trustDir : undefined)
    ?? process.env.DSH_PROOF_TRUST_DIR
    ?? nodePath.join(dshHome(), 'proof')
  const workspaceKey = sha256(root).slice(0, 16)
  const evidenceDir = config.evidenceStore === 'workspace'
    ? config.evidenceDir
    : nodePath.join(trustRoot, 'workspaces', workspaceKey)

  const engine = new ProofEngine({
    root,
    evidenceDir,
    trustDir: trustRoot,
    workspaceKey,
    checkpointEvery: config.checkpointEvery,
    autoDiscover: config.autoDiscover,
    checks: config.checks.map(c => ({
      ...(c.label !== undefined ? { label: c.label } : {}),
      command: c.command,
      ...(c.kind !== undefined ? { kind: c.kind } : {}),
      ...(c.paths !== undefined ? { paths: c.paths } : {}),
      ...(c.timeoutMs !== undefined ? { timeoutMs: c.timeoutMs } : {}),
      ...(c.exclusive !== undefined ? { exclusive: c.exclusive } : {}),
    })),
    checkTimeoutMs: config.checkTimeoutMs,
    verifyBudgetMs: config.verifyBudgetMs,
    concurrency: config.concurrency,
    impactGraph: config.impactGraph,
    impactGraphLimit: config.impactGraphLimit,
    headChars: config.headChars,
  })

  const watch = new WorkspaceWatch(engineFs(engine), root)
  /** True once a `proof_claim` ran during the current turn. */
  let claimedThisTurn = false
  let mutating = false

  const log = (...args: unknown[]) => { if (config.verbose) console.log('[dsh-proof]', ...args) }

  // -- model-facing tools -------------------------------------------------
  for (const tool of createProofTools(engine)) {
    host.tools.register(tool)
    log(`registered tool ${tool.name}`)
  }
  // -- evidence-store guard: the log must not be agent-writable ------------
  // In `workspace` mode the log still lives inside the project, so mutation
  // tools touching it are routed through user approval. In `host` mode the
  // log is outside the sandboxed workspace and needs no gate.
  if (config.evidenceStore === 'workspace') {
    const evidenceSegment = config.evidenceDir.replace(/^\.\/+/, '').replace(/\/+$/, '')
    const touchesEvidence = (candidate: string): boolean => {
      const normalized = candidate.replace(/\\/g, '/')
      return normalized === evidenceSegment || normalized.includes(`/${evidenceSegment}/`) || normalized.startsWith(`${evidenceSegment}/`)
    }
    host.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
      if (!isMutationTool(exec.name)) return next()
      const paths = WorkspaceWatch.pathsIn(exec.arguments)
      if (!paths.some(touchesEvidence)) return next()
      return {
        kind: 'ask',
        reason: 'dsh-proof: this call writes into the verification evidence store, which must not be modified by the agent it is meant to audit.',
        displayReason: {
          en: 'dsh-proof: block writes to the evidence log?',
          'zh-CN': 'dsh-proof：拒绝写入证据日志？',
        },
      }
    })
  }
  // -- policy gate: no baseline, no unreviewed mutation --------------------
  if (config.requireBaseline !== 'off') {
    host.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
      if (!isMutationTool(exec.name)) return next()
      try {
        const baseline = await engine.baseline()
        if (baseline !== undefined) return next()
      } catch {
        return next()
      }
      const message = `dsh-proof: no verification baseline exists yet, and \`${exec.name}\` mutates the workspace. `
        + 'Establish one first with proof_baseline so later failures can be attributed correctly.'
      if (config.requireBaseline === 'ask') {
        return {
          kind: 'ask',
          reason: message,
          displayReason: {
            en: 'dsh-proof: run proof_baseline before mutating the workspace?',
            'zh-CN': 'dsh-proof：改动工作区之前先建立验证基线？',
          },
        }
      }
      log(`warn-gated ${exec.name}`)
      return next()
    })
  }

  // -- observation: what actually moved -----------------------------------
  host.on('tools/result', (exec, result) => {
    void (async () => {
      try {
        await watch.observe(exec, result)
        if (isMutationTool(exec.name)) mutating = true
        if (exec.name === 'proof_claim') claimedThisTurn = true
      } catch (error) {
        log('observe failed', error)
      }
    })()
  })

  // -- drift + unproven-claim enforcement ---------------------------------
  if (config.driftDetection || config.enforceOnTurnEnd) {
    host.on('agent/turn-stopping', async (payload) => {
      try {
        const notices: string[] = []

        if (config.driftDetection) {
          const drift = await watch.detectDrift()
          const narrative = driftNarrative(drift)
          if (narrative !== undefined) notices.push(narrative)
          if (drift.drifted.length > 0) await watch.snapshot(drift.drifted)
        }

        if (config.enforceOnTurnEnd && mutating && !claimedThisTurn) {
          notices.push(
            '⚠️ dsh-proof: this turn mutated the workspace but made no proven completion claim. '
            + 'Before telling the user it is done, call proof_claim with the exact claim. '
            + 'A prose assertion is not evidence.',
          )
        }

        if (notices.length > 0) {
          payload.agent.inject({
            role: 'user',
            content: [{ type: 'text', text: notices.join('\n\n') }] as ContentBlock[],
            source: { kind: 'plugin', plugin: name },
          } as UserMessage)
        }
      } catch (error) {
        log('turn-stopping hook failed', error)
      } finally {
        claimedThisTurn = false
        mutating = false
        watch.windowStart()
      }
    })
  }

  // -- system-prompt section ----------------------------------------------
  let disposeSection: (() => void) | undefined
  if (config.promptSection && host.systemPrompt) {
    const register = (): void => {
      disposeSection = host.systemPrompt!.section({
        id: config.promptScope,
        title: 'Completion proof',
        order: 60,
        scope: config.promptScope,
        content: () => {
          const specs = engine.cachedChecks()
          return buildPolicySection({
            discovered: specs,
            hasBaseline: engine.hasBaselineSync(),
            requireBaseline: config.requireBaseline,
          })
        },
      })
    }
    // The section reads engine state lazily; register immediately and refresh
    // discovery in the background so the first prompt is not empty.
    register()
    void engine.loadChecks().catch(() => undefined)
  }

  // -- teardown -----------------------------------------------------------
  host.effect(() => () => {
    disposeSection?.()
    disposeSection = undefined
    log('unloaded')
  })

  log(`loaded (root=${root}, requireBaseline=${config.requireBaseline}, evidence=${config.evidenceStore}, trust=${trustRoot})`)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** The harness home directory: keys and anchors live under `<home>/proof`. */
function dshHome(): string {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv
  return nodePath.join(homedir(), '.dsh')
}

/**
 * Resolve the workspace root. `ctx` does not expose a portable workspace path
 * across DSH versions, so this walks the documented surfaces and falls back to
 * the process working directory — which is what the harness sets for the
 * session workspace anyway.
 */
function hostWorkspaceRoot(ctx: Context): string {
  const candidate = (ctx as unknown as { workspace?: { root?: unknown } }).workspace?.root
  if (typeof candidate === 'string' && candidate.length > 0) return candidate
  return process.cwd()
}

/** The engine's FsPort, reused by the watcher so both see the same filesystem. */
function engineFs(engine: ProofEngine): FsPort {
  return engine.fsView
}

export { ProofEngine }
export type { ProofReport, ProofGrade } from './core/evidence.ts'
