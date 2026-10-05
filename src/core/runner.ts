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
import { sha256 } from './hash.ts'
import type { ExcerptOptions } from './excerpt.ts'
import type { NormalizeOptions } from './hash.ts'

/** How raw outcomes become evidence records: excerpt budget + canonical roots. */
export interface EvidenceShape {
  readonly excerpt?: ExcerptOptions
  readonly canonical?: NormalizeOptions
}

export interface RunnerOptions {
  readonly concurrency?: number
  readonly signal?: AbortSignal
  /** Wall-clock budget for the whole batch; unused checks are marked `skipped`. */
  readonly totalBudgetMs?: number
  /** Snapshot the workspace once and reuse it for every record in the batch. */
  readonly workspace?: WorkspaceSnapshot
  /** Called as each check settles, for streaming UIs. */
  readonly onEvidence?: (evidence: Evidence, index: number, total: number) => void
  /**
   * υ: base directory for V8 execution-coverage collection. When set, every
   * spec executes with `NODE_V8_COVERAGE=<coverageDir>/<sanitised specId>` in
   * its environment — see `coverageSubdir` for why the id is hashed. Absent
   * (the default) injects nothing and the batch is byte-for-byte pre-υ.
   */
  readonly coverageDir?: string
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
  private readonly canonical: NormalizeOptions

  constructor(commands: CommandPort, workspace: WorkspacePort, clock: Clock, shape: EvidenceShape = {}) {
    this.commands = commands
    this.workspace = workspace
    this.clock = clock
    this.excerpt = shape.excerpt ?? { budget: 2_000, strategy: 'head' }
    this.canonical = shape.canonical ?? {}
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
          }, snapshot, this.clock, this.excerpt, this.canonical)
          records.push(skipped)
          skippedIds.push(spec.id)
          options.onEvidence?.(skipped, index++, total)
          continue
        }

        const outcome = await this.runOne(spec, options.signal, snapshot, options.coverageDir)
        const evidence = makeEvidence(spec, outcome, snapshot, this.clock, this.excerpt, this.canonical)
        records.push(evidence)
        ranIds.push(spec.id)
        options.onEvidence?.(evidence, index++, total)
      }
    }

    await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, total)) }, worker))
    // Workers settle in wall-clock order, but evidence identity is
    // order-sensitive downstream: `buildBaseline` hashes the checkId sequence,
    // so a concurrent batch must not leak completion order into baselineIds.
    // Re-project records (and ran ids) onto the spec order; the stable sort
    // keeps completion order for any id the spec list does not know.
    const specRank = new Map<string, number>(specs.map((s, i) => [s.id, i]))
    const rankOf = (id: string): number => {
      const rank = specRank.get(id)
      return rank === undefined ? total : rank
    }
    const orderedRecords = [...records].sort((a, b) => rankOf(a.checkId) - rankOf(b.checkId))
    const orderedRanIds = [...ranIds].sort((a, b) => rankOf(a) - rankOf(b))
    const orderedSkippedIds = [...skippedIds].sort((a, b) => rankOf(a) - rankOf(b))
    return {
      records: orderedRecords,
      workspace: snapshot,
      ranIds: orderedRanIds,
      skippedIds: orderedSkippedIds,
      aborted: aborted || options.signal?.aborted === true,
      totalDurationMs: this.clock.now() - started,
    }
  }

  /**
   * υ: filesystem-safe subdirectory for one spec's V8 coverage output.
   *
   * specIds embed their command (and may carry colons, hashes, spaces, even
   * whole argv strings), none of which are safe as a path segment on every
   * platform this runner executes on. `sha256(id).slice(0,16)` is: 16 hex
   * characters, collision-safe for any realistic check pool, and deterministic
   * — the engine collecting the output re-derives the exact same name from the
   * exact same spec.
   */
  private coverageSubdir(coverageDir: string, specId: string): string {
    return `${coverageDir.replace(/[\/]+$/, '')}/${sha256(specId).slice(0, 16)}`
  }

  private async runOne(
    spec: CheckSpec,
    signal: AbortSignal | undefined,
    _snapshot: WorkspaceSnapshot,
    coverageDir?: string,
  ): Promise<RunOutcome> {
    const started = this.clock.now()
    const controller = new AbortController()
    const onAbort = () => controller.abort()
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      const result = await this.commands.run(spec.command, {
        // Monorepo checks execute inside the subpackage that declares them;
        // everything else runs at the workspace root, exactly as before.
        cwd: spec.cwd === undefined
          ? this.workspace.root
          : `${this.workspace.root.replace(/[\/]+$/, '')}/${spec.cwd.replace(/^\/+/, '')}`,
        timeoutMs: spec.timeoutMs,
        signal: controller.signal,
        maxOutputChars: 64_000,
        // υ: zero-instrumentation execution coverage. `NODE_V8_COVERAGE` is a
        // Node runtime flag delivered through the environment: any node process
        // that inherits it — the check itself, and any nested node the check
        // spawns through npm/.cmd shims or scripts, because the overlay merges
        // into the child's full inherited environment at the port — writes its
        // raw V8 coverage profile to <dir>/coverage-<pid>-<seq>.json on exit.
        // No mocks, no babel hooks, no import rewriting: the evidence of what
        // the check executed is produced by the same V8 instance that executed
        // it, which is precisely what makes it hard to fake from inside the
        // checked code. Command ports that ignore `env` (the test fakes)
        // simply produce no coverage directory — the engine's observe mode
        // treats that as "no data" and declines to gate on it, so this
        // injection is invisible to every pre-υ consumer.
        ...(coverageDir !== undefined
          ? { env: { NODE_V8_COVERAGE: this.coverageSubdir(coverageDir, spec.id) } as Readonly<Record<string, string>> }
          : {}),
      })
      // Death-cause honesty: `exitCode === null` alone cannot tell "our
      // timeout killed it" from "something outside killed it". A port that
      // observed an external signal (OOM-killer, user `kill -9`) reports it
      // via `killedBySignal`; that is a different fact from a timeout — the
      // model reading the evidence must be able to distinguish "ran too slow,
      // we killed it" from "killed by the outside world" — so it maps to
      // `error`, with the signal named on the first output line. Both
      // `aborted` (we chose to stop) and `spawnError` (it never ran) outrank
      // the signal reading, matching the port contract that leaves
      // `killedBySignal` unset in exactly those cases.
      const externalSignal = result.aborted || result.spawnError !== undefined
        ? undefined
        : result.killedBySignal
      const status: CheckStatus = result.aborted
        ? 'aborted'
        : result.spawnError !== undefined || externalSignal !== undefined
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
          : externalSignal !== undefined
            ? `killed by signal ${externalSignal}\n${result.output}`
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
