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
import { WorkspaceWatch, driftNarrative, isMutationToolName, toWorkspaceRelative } from './dsh/observe.ts'
import { buildPolicySection } from './dsh/prompt.ts'
import { createLspResolver } from './dsh/lsp-impact.ts'
import { sha256 } from './core/hash.ts'
import { NodeFsPort } from './node-ports.ts'
import type { FsPort } from './core/ports.ts'
import type {
  ContentBlock, LspLike, PreToolDecision, ToolExecution, ToolExecutionResult, ToolRuntimeLike, UserMessage,
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
  /** The host's language-server seam; used for precise impact edges when present. */
  lsp?: LspLike
  effect(disposer: () => void | (() => void)): unknown
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

  // Shared filesystem port: the engine, the LSP resolver and the watcher all
  // see the same files (and the resolver's cache keys off the same stats).
  const sharedFs = new NodeFsPort()
  const lspResolver = config.lspImpact === false
    ? undefined
    : createLspResolver(host.lsp, root, sharedFs, { budget: config.lspQueryBudget })

  const engine = new ProofEngine({
    root,
    evidenceDir,
    trustDir: trustRoot,
    workspaceKey,
    checkpointEvery: config.checkpointEvery,
    fs: sharedFs,
    ...(lspResolver !== undefined ? { resolver: lspResolver } : {}),
    excerptStrategy: config.excerptStrategy,
    ...(config.normalizeHome ? { homeDir: homedir() } : {}),
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
    scheduler: config.scheduler,
    certifyTarget: config.certifyTarget,
    ...(config.apiEntryPoints !== undefined && config.apiEntryPoints.length > 0
      ? { apiEntryPoints: config.apiEntryPoints }
      : {}),
    juryConfidenceCap: config.juryConfidenceCap,
    classBTrust: config.classBTrust,
    classCTrust: config.classCTrust,
  })

  const watch = new WorkspaceWatch(engineFs(engine), root)
  /** True once a `proof_claim` ran during the current turn. */
  let claimedThisTurn = false
  let mutating = false
  /** Set when `warn` passes a baseline-less mutation; consumed by turn end. */
  let pendingBaselineNotice = false

  // λ: the physical evidence-log location, derived with the same rule
  // ProofEngine applies to its own private copy (the engine exports neither
  // the path nor its derivation, and EvidenceStore exposes no marker
  // read-back). The Class B/C tools read attestation markers back through the
  // engine's fs port with it — keep in lockstep with engine.ts's constructor.
  const evidenceLogPath = `${isAbsoluteHostPath(evidenceDir)
    ? evidenceDir.replace(/[\/]+$/, '')
    : `${root.replace(/[\/]+$/, '')}/${evidenceDir}`}/evidence.jsonl`

  const log = (...args: unknown[]) => { if (config.verbose) console.log('[dsh-proof]', ...args) }

  // -- model-facing tools -------------------------------------------------
  for (const tool of createProofTools(engine, () => watch.sessionTouchedPaths(), evidenceLogPath)) {
    host.tools.register(tool)
    log(`registered tool ${tool.name}`)
  }
  // -- evidence-store guard: the log must not be agent-writable ------------
  // In `workspace` mode the log still lives inside the project, so mutation
  // tools touching it are routed through user approval. In `host` mode the
  // log is outside the sandboxed workspace and needs no gate.
  if (config.evidenceStore === 'workspace') {
    const evidenceSegment = collapseSegments(config.evidenceDir.replace(/^\.\/+/, '').replace(/\/+$/, ''))
    const touchesEvidence = (candidate: string): boolean => {
      // The guard must reason in one path space. A candidate is first projected
      // onto the workspace's relative space (absolute host-style paths, either
      // slash flavour, drive case and all) and its `.`/`..` detours collapsed;
      // otherwise "can the agent write the evidence log" degenerates into a
      // string-matching puzzle the agent can simply walk around.
      const rel = toWorkspaceRelative(candidate, root)
      if (rel === undefined) return false
      const target = collapseSegments(rel)
      return target === evidenceSegment || target.startsWith(`${evidenceSegment}/`)
    }
    host.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
      if (!isMutationToolName(exec.name)) return next()
      // contentKeys: the guard prefers over-detection — a `move {source:
      // '.proof/evidence.jsonl', dest: …}` carries the log out through the
      // very key the watcher excludes as content-noise. A false positive here
      // costs one approval prompt; a false negative costs the log.
      const paths = WorkspaceWatch.pathsIn(exec.arguments, { contentKeys: true })
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
      if (!isMutationToolName(exec.name)) return next()
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
      // 'warn' owes the model a corrective notice, not a silent pass: flag the
      // gap now and inject it at turn end, where the model can still act on it.
      pendingBaselineNotice = true
      log(`warn-gated ${exec.name}`)
      return next()
    })
  }
  // -- Class C human-endorsement seam (λ) ----------------------------------
  // proof_endorse records a named human's decision as evidence, and the
  // human's consciousness IS the evidence — the tool must never run on the
  // model's say-so alone. Routing it through `ask` hands the call to the
  // host's approval seam: the model calls, the host prompts, a human decides,
  // and only an approval lets execute append the attestation. Registered
  // after the evidence-store guard and the baseline gate, not between them:
  // the three hooks match on disjoint tool names so their order carries no
  // behavior, and keeping the established gates' registration order intact
  // means hosts (and tests) that index this pipeline keep their reading.
  host.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    if (exec.name !== 'proof_endorse') return next()
    const claim = (exec.arguments as { claim?: unknown } | null | undefined)?.claim
    const head = typeof claim === 'string' ? claim.slice(0, 80) : '(no claim text)'
    return {
      kind: 'ask',
      reason: `dsh-proof: a human must consciously endorse/reject this claim — approve to record Class C evidence? `
        + `claim: "${head}"`,
      displayReason: {
        en: 'dsh-proof: a human must consciously endorse/reject this claim — approve to record Class C evidence?',
        'zh-CN': 'dsh-proof：需要人类有意识地背书/否决此主张——批准以记录 Class C 证据？',
      },
    }
  })

  // -- observation: what actually moved -----------------------------------
  // Each event is still fire-and-forget (a tool result must never be delayed
  // by bookkeeping), but the latest observation's promise is kept: the turn
  // can stop right behind the last tool result, and drift/enforcement computed
  // from a half-written observation would read yesterday's state.
  let pendingObserve: Promise<void> = Promise.resolve()
  host.on('tools/result', (exec, result) => {
    pendingObserve = (async () => {
      try {
        await watch.observe(exec, result)
        if (isMutationToolName(exec.name)) mutating = true
        if (exec.name === 'proof_claim') claimedThisTurn = true
      } catch (error) {
        log('observe failed', error)
      }
    })()
  })

  // -- drift + unproven-claim enforcement ---------------------------------
  // The hook must also exist when only `warn` is active: that mode defers its
  // baseline notice to here.
  if (config.driftDetection || config.enforceOnTurnEnd || config.requireBaseline === 'warn') {
    host.on('agent/turn-stopping', async (payload) => {
      try {
        // The last tool result of a turn can still be mid-observation when
        // this hook fires; drift computed before it lands reads stale
        // fingerprints/touched state. Wait for it — defensively: an observation
        // that rejects must be swallowed here too, since a failed fingerprint
        // can never be allowed to wedge the turn's wind-down.
        await pendingObserve.catch(() => undefined)

        const notices: string[] = []

        if (config.driftDetection) {
          const drift = await watch.detectDrift()
          const narrative = driftNarrative(drift)
          if (narrative !== undefined) notices.push(narrative)
          if (drift.drifted.length > 0) await watch.snapshot(drift.drifted)
        }

        if (pendingBaselineNotice) {
          pendingBaselineNotice = false
          notices.push(
            '⚠️ dsh-proof: this turn mutated the workspace, but it has no completion-proof baseline. '
            + 'Run proof_baseline to establish one so later failures can be attributed to your changes.',
          )
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
    // discovery in the background so the first prompt is not empty. The same
    // prewarm probes the baseline: without it, a plugin loaded over a
    // workspace that already has a baseline on disk keeps saying "no baseline
    // yet" — `content()` re-evaluates on every render, so once `baselineSeen`
    // flips, the next frame tells the truth.
    register()
    void engine.loadChecks().catch(() => undefined)
    void engine.baseline().catch(() => undefined)
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

/**
 * Windows drive letter or leading slash — engine.ts's private absolute-path
 * test, mirrored here so `evidenceLogPath` derives from exactly the same rule
 * the engine used for its own copy. If engine.ts's rule ever moves, this
 * mirror must move with it (the wiring test pins the derived path).
 */
function isAbsoluteHostPath(p: string): boolean {
  return /^([A-Za-z]:[\\/]|\/)/.test(p)
}

/**
 * Collapse `.` and `..` segments in a workspace-relative path (`a/../b` ->
 * `b`). A leading `..` that would escape the root is kept, so paths that
 * leave the workspace never come out looking like they are inside it.
 */
function collapseSegments(rel: string): string {
  const out: string[] = []
  for (const segment of rel.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..' && out.length > 0 && out[out.length - 1] !== '..') out.pop()
    else out.push(segment)
  }
  return out.join('/')
}

export { ProofEngine }
export type { ProofReport, ProofGrade } from './core/evidence.ts'
