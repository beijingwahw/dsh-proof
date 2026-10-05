/**
 * The verification runner: budget-aware, incremental, cancellable.
 *
 * Runs only the checks a change set made stale, in a deterministic order, with
 * bounded concurrency and a per-check cooperative timeout. Every outcome —
 * including a timeout or an abort — becomes evidence, because "we didn't run
 * it" is itself a fact the model must not paper over.
 *
 * @module dsh-proof/core/runner
 */

import type { CheckSpec, Clock, CommandPort, WorkspacePort } from './ports.ts'
import type { CheckStatus, Evidence, RunOutcome, WorkspaceSnapshot } from './evidence.ts'
import { makeEvidence, snapshotWorkspace } from './evidence.ts'
import type { ExcerptOptions } from './excerpt.ts'

export interface RunnerOptions {
  readonly concurrency?: number
  readonly signal?: AbortSignal
  /** Wall-clock budget for the whole batch; unused checks are marked `skipped`. */
  readonly totalBudgetMs?: number
  /** Snapshot the workspace once and reuse it for every record in the batch. */
  readonly workspace?: WorkspaceSnapshot
  /** Called as each check settles, for streaming UIs. */
  readonly onEvidence?: (evidence: Evidence, index: number, total: number) => void
}

export interface BatchResult {
  readonly records: readonly Evidence[]
  readonly workspace: WorkspaceSnapshot
  readonly ranIds: readonly string[]
  readonly skippedIds: readonly string[]
  readonly aborted: boolean
  readonly totalDurationMs: number
}

export class VerificationRunner {
  private readonly commands: CommandPort
  private readonly workspace: WorkspacePort
  private readonly clock: Clock
  private readonly excerpt: ExcerptOptions

  constructor(commands: CommandPort, workspace: WorkspacePort, clock: Clock, excerpt: ExcerptOptions = { budget: 2_000, strategy: 'head' }) {
    this.commands = commands
    this.workspace = workspace
    this.clock = clock
    this.excerpt = excerpt
  }

  /** Run a batch of checks and turn every outcome into evidence. */
  async run(specs: readonly CheckSpec[], options: RunnerOptions = {}): Promise<BatchResult> {
    const concurrency = Math.max(1, Math.min(options.concurrency ?? 2, 8))
    const started = this.clock.now()
    const snapshot = options.workspace ?? await snapshotWorkspace(this.workspace)
    const records: Evidence[] = []
    const skippedIds: string[] = []
    const ranIds: string[] = []
    let aborted = false

    const queue = [...specs]
    const total = queue.length
    let index = 0

    const worker = async (): Promise<void> => {
      for (;;) {
        if (aborted || options.signal?.aborted) { aborted = true; return }
        const spec = queue.shift()
        if (spec === undefined) return
        const budgetExhausted = options.totalBudgetMs !== undefined
          && this.clock.now() - started >= options.totalBudgetMs
        if (budgetExhausted) {
          const skipped = makeEvidence(spec, {
            status: 'skipped', exitCode: null, durationMs: 0,
            output: `skipped: total verification budget of ${options.totalBudgetMs}ms exhausted`,
          }, snapshot, this.clock, this.excerpt)
          records.push(skipped)
          skippedIds.push(spec.id)
          options.onEvidence?.(skipped, index++, total)
          continue
        }

        const outcome = await this.runOne(spec, options.signal, snapshot)
        const evidence = makeEvidence(spec, outcome, snapshot, this.clock, this.excerpt)
        records.push(evidence)
        ranIds.push(spec.id)
        options.onEvidence?.(evidence, index++, total)
      }
    }

    await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, total)) }, worker))
    return {
      records,
      workspace: snapshot,
      ranIds,
      skippedIds,
      aborted: aborted || options.signal?.aborted === true,
      totalDurationMs: this.clock.now() - started,
    }
  }

  private async runOne(spec: CheckSpec, signal: AbortSignal | undefined, _snapshot: WorkspaceSnapshot): Promise<RunOutcome> {
    const started = this.clock.now()
    const controller = new AbortController()
    const onAbort = () => controller.abort()
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      const result = await this.commands.run(spec.command, {
        cwd: this.workspace.root,
        timeoutMs: spec.timeoutMs,
        signal: controller.signal,
        maxOutputChars: 64_000,
      })
      const status: CheckStatus = result.aborted
        ? 'aborted'
        : result.spawnError !== undefined
          ? 'error'
          : result.exitCode === 0
            ? 'pass'
            : result.exitCode === null
              ? 'timeout'
              : 'fail'
      return {
        status,
        exitCode: result.exitCode,
        durationMs: result.durationMs || this.clock.now() - started,
        output: result.spawnError !== undefined
          ? `${result.spawnError}\n${result.output}`
          : result.output,
      }
    } catch (error) {
      return {
        status: 'error',
        exitCode: null,
        durationMs: this.clock.now() - started,
        output: `runner error: ${errorMessage(error)}`,
      }
    } finally {
      signal?.removeEventListener('abort', onAbort)
    }
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  try { return String(error) } catch { return '<unprintable>' }
}
