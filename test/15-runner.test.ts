/**
 * RUNNER — direct unit tests.
 *
 * Until now `VerificationRunner` was only covered through the engine, which
 * asserts its *grades*, never its mechanics. These tests drive the runner
 * directly with the port fakes and pin down the behaviours every grade
 * silently rests on: the concurrency clamp, budget-exhaustion evidence, abort
 * handling, honest death-cause classification, completion-order determinism,
 * spawn errors, and the excerpt budget flowing into every record.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { VerificationRunner } from '../src/core/runner.ts'
import type { Clock, CommandPort, CommandResult, CommandRunOptions } from '../src/core/ports.ts'
import { sha256 } from '../src/core/hash.ts'
import { FakeClock, FakeCommands, FakeWorkspace, spec } from './helpers.ts'

const ROOT = '/ws'

/**
 * A fake for outcomes the table-driven FakeCommands cannot express: its rule
 * path coerces `exitCode: null` to `0` (`rule.result.exitCode ?? 0`) and drops
 * `killedBySignal`, so an externally-killed process is unwritable as a rule.
 * This subclass maps argv markers to exact `CommandResult`s — the call still
 * flows through super so `calls` keeps recording. The `aborting` variant
 * deliberately reports a signal on an aborted run (against the port contract)
 * so the runner's "aborted outranks the signal" guard is exercised rather
 * than trusted blind.
 */
class ScriptedCommands extends FakeCommands implements CommandPort {
  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    if (argv.includes('aborting')) {
      await super.run(argv, options)
      return { exitCode: null, output: '', durationMs: 5, aborted: true, killedBySignal: 'SIGKILL' }
    }
    if (argv.includes('sigkill-me')) {
      await super.run(argv, options)
      return { exitCode: null, output: 'partial output', durationMs: 5, aborted: false, killedBySignal: 'SIGKILL' }
    }
    if (argv.includes('hang')) {
      await super.run(argv, options)
      return { exitCode: null, output: 'running forever', durationMs: 5, aborted: false }
    }
    if (argv.includes('too-slow')) {
      // H7: the REAL port's timeout shape — exitCode null, the legacy
      // spawnError text for pre-v0.16 consumers, and the first-class
      // timedOut fact. The runner must read the fact, not the channel.
      await super.run(argv, options)
      return {
        exitCode: null, output: 'partial output before the kill', durationMs: 5, aborted: false,
        spawnError: 'timed out after 1000ms', timedOut: true,
      }
    }
    if (argv.includes('trap-timeout')) {
      // H-18(d)/B7-M1, the POSIX shape a real port can now produce: the child
      // TRAPPED the port's SIGTERM and exited with a code (graceful shutdown,
      // jest worker pools). The port carries the first-class timedOut fact on
      // the close(code !== null) shape too; the runner must rank it over the
      // exit code or the timeout launders into a decisive 'fail' — a false
      // regression on the session's ledger.
      await super.run(argv, options)
      return { exitCode: 1, output: 'graceful shutdown after SIGTERM', durationMs: 5, aborted: false, timedOut: true }
    }
    if (argv.includes('enoent')) {
      await super.run(argv, options)
      return { exitCode: null, output: '', durationMs: 0, aborted: false, spawnError: 'spawn failed: ENOENT' }
    }
    return super.run(argv, options)
  }
}

/** FakeCommands that observes how many commands are in flight at once. */
class CountingCommands extends FakeCommands implements CommandPort {
  inFlight = 0
  maxInFlight = 0

  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    this.inFlight += 1
    if (this.inFlight > this.maxInFlight) this.maxInFlight = this.inFlight
    try {
      return await super.run(argv, options)
    } finally {
      this.inFlight -= 1
    }
  }
}

// 1. Concurrency clamp -------------------------------------------------------

test('RUNNER: concurrency is clamped to [1, 8] whatever the caller asks for', async () => {
  // Every command delays 5ms so a serial runner visibly never overlaps.
  const serial = new CountingCommands().on(() => true, { output: 'ok' }, { delayMs: 5 })
  const serialRun = await new VerificationRunner(serial, new FakeWorkspace(ROOT), new FakeClock())
    .run([spec({ id: 'a' }), spec({ id: 'b' }), spec({ id: 'c' })], { concurrency: 0 })
  assert.equal(serial.maxInFlight, 1, 'concurrency 0 clamps up to 1, not a zero-worker deadlock')
  assert.deepEqual(serialRun.ranIds, ['a', 'b', 'c'])

  const wide = new CountingCommands().on(() => true, { output: 'ok' }, { delayMs: 5 })
  const many = Array.from({ length: 24 }, (_, i) => spec({ id: `check-${i}` }))
  await new VerificationRunner(wide, new FakeWorkspace(ROOT), new FakeClock())
    .run(many, { concurrency: 100 })
  assert.equal(wide.maxInFlight, 8, 'concurrency 100 clamps down to 8')
})

// 2. Budget exhaustion -------------------------------------------------------

test('RUNNER: an exhausted total budget turns not-yet-started checks into skipped evidence', async () => {
  const commands = new FakeCommands()
  // FakeClock ticks 1ms per read and every executed spec costs several reads
  // (budget probe, run start, record timestamp), so a 2ms budget admits
  // exactly the first spec; the rest must become `skipped` evidence without
  // ever spawning a command.
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([spec({ id: 'first' }), spec({ id: 'second' }), spec({ id: 'third' })],
      { concurrency: 1, totalBudgetMs: 2 })

  assert.deepEqual(result.ranIds, ['first'])
  assert.deepEqual(result.skippedIds, ['second', 'third'])
  assert.equal(commands.calls.length, 1, 'a skipped check must not spawn a command')

  const skipped = result.records.filter(r => r.status === 'skipped')
  assert.equal(skipped.length, 2, 'the unstarted checks still become evidence records')
  assert.match(skipped[0]?.outputHead ?? '', /budget/, 'the record says why it was skipped')
  assert.equal(result.aborted, false, 'a budget exhaustion is not an abort')
})

// 3. Pre-aborted external signal ----------------------------------------------

test('RUNNER: a signal aborted before the run executes nothing and flags the batch aborted', async () => {
  const commands = new FakeCommands()
  const controller = new AbortController()
  controller.abort()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([spec({ id: 'a' }), spec({ id: 'b' })], { signal: controller.signal })

  assert.equal(result.aborted, true)
  assert.equal(commands.calls.length, 0, 'a pre-aborted batch must not spawn a single command')
  assert.deepEqual(result.records, [], 'no check was observed, so no record may exist')
  assert.deepEqual(result.ranIds, [])
  assert.deepEqual(result.skippedIds, [], 'aborted is not skipped: nothing was budgeted away')
})

test('RUNNER (W15-L8): a signal that dies after the loop check but before the registration still aborts the check', async () => {
  // The window: the worker's top-of-iteration check read the signal as live,
  // then the signal aborted before runOne subscribed — an aborted signal
  // never fires a new listener, so the inner controller the port sees stayed
  // green and the check used to run to its own timeout as ordinary evidence.
  // The registration is now atomic with a synchronous re-check. The window
  // is forced deterministically through the injected clock: its second read
  // (the worker's budget check — after the top check, before runOne's
  // registration) kills the signal.
  const controller = new AbortController()
  let reads = 0
  const clock = {
    now: (): number => {
      reads += 1
      if (reads === 2) controller.abort()
      return 1_700_000_000_000
    },
  }
  const commands = new FakeCommands()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), clock)
    .run([spec({ id: 'a' }), spec({ id: 'b' })], {
      signal: controller.signal,
      totalBudgetMs: 60_000, // forces the budget-check clock read inside the window
    })

  assert.equal(result.aborted, true)
  assert.equal(result.records.length, 1)
  assert.equal(result.records[0]?.status, 'aborted', 'the mid-window death reaches the port as an abort, not a green run')
  assert.deepEqual(result.ranIds, ['a'])
  assert.deepEqual(result.skippedIds, [])
})

// 4. killedBySignal -> 'error' (S1) -------------------------------------------

test('RUNNER: an external signal kill is an honest error, not a timeout — and names the signal', async () => {
  const commands = new ScriptedCommands()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([
      spec({ id: 'killed', command: ['node', 'sigkill-me'] }),
      spec({ id: 'aborting', command: ['node', 'sigkill-me', 'aborting'] }),
      spec({ id: 'hung', command: ['node', 'hang'] }),
    ], { concurrency: 3 })
  const byId = new Map(result.records.map(r => [r.checkId, r]))

  const killed = byId.get('killed')
  assert.equal(killed?.status, 'error', 'killed by the outside world is a distinct death cause')
  assert.equal(killed?.exitCode, null)
  assert.match(killed?.outputHead ?? '', /^killed by signal SIGKILL/, 'the signal is the first thing a reader sees')
  assert.ok(killed?.outputHead.includes('partial output'), 'the captured output before the kill is kept')

  // A port that (against its contract) reports a signal on an aborted run must
  // still get 'aborted': our own cancellation outranks a foreign death cause.
  const aborting = byId.get('aborting')
  assert.equal(aborting?.status, 'aborted')
  assert.doesNotMatch(aborting?.outputHead ?? '', /killed by signal/)

  // The old, lossy mapping: exitCode null without a signal is still a timeout.
  const hung = byId.get('hung')
  assert.equal(hung?.status, 'timeout', '"too slow, we killed it" is a different fact from "externally killed"')
})

// 5. Completion-order determinism ----------------------------------------------

test('RUNNER: wall-clock completion order never leaks into records or ranIds', async () => {
  const commands = new FakeCommands()
    .on(argv => argv.includes('slow'), { output: 'slow done' }, { delayMs: 60 })
    .on(argv => argv.includes('fast'), { output: 'fast done' }, { delayMs: 1 })
  const specs = [
    spec({ id: 'slow-1', command: ['node', 'slow'] }),
    spec({ id: 'fast', command: ['node', 'fast'] }),
    spec({ id: 'slow-2', command: ['node', 'slow'] }),
  ]
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run(specs, { concurrency: 3 })

  assert.deepEqual(result.records.map(r => r.checkId), ['slow-1', 'fast', 'slow-2'],
    'records follow spec order even though the fast check settles first')
  assert.deepEqual(result.ranIds, ['slow-1', 'fast', 'slow-2'])
})

// 6. spawnError -> 'error' ------------------------------------------------------

test('RUNNER: a spawn error becomes an error record that names the spawn failure', async () => {
  const commands = new ScriptedCommands()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([spec({ id: 's', command: ['node', 'enoent'] })])

  const record = result.records[0]
  assert.equal(record?.status, 'error')
  assert.equal(record?.exitCode, null)
  assert.match(record?.outputHead ?? '', /spawn failed: ENOENT/)
})

// 7. Excerpt options flow through makeEvidence ---------------------------------

test('RUNNER: the excerpt budget constrains outputHead while the digest covers the full output', async () => {
  const big = 'x'.repeat(5_000)
  const commands = new FakeCommands().on(() => true, { exitCode: 0, output: big })
  const runner = new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock(), {
    excerpt: { budget: 120, strategy: 'head' },
  })
  const result = await runner.run([spec({ id: 'e' })])

  const record = result.records[0]
  assert.ok(record, 'one record for one spec')
  assert.equal(record.outputHead.length, 120, `head strategy keeps exactly the budget, got ${record.outputHead.length}`)
  assert.ok(record.outputHead.length <= 120, 'the budget is an upper bound the record must respect')
  assert.equal(record.outputTruncated, true)
  assert.equal(record.outputOmittedChars, 5_000 - 120)
  // Content addressing is over the FULL normalised output — the excerpt is a
  // reading aid, never part of the identity.
  assert.equal(record.outputDigest, sha256(big))
})

// 8. timedOut outranks the legacy spawnError channel (H7) ------------------------

test('RUNNER: timedOut=true maps to timeout even though the result carries a spawnError (H7)', async () => {
  // The real port reports timeouts through the spawnError channel for
  // pre-v0.16 consumers; before the timedOut field the runner read that
  // channel as "never ran" and labelled every real timeout 'error'. The
  // first-class fact must win, and the death-cause partition must hold on
  // all three shapes at once:
  //   timedOut + spawnError -> timeout   (the real port's timeout shape)
  //   exitCode null, no fields  -> timeout (legacy/fake hang shape)
  //   spawnError alone         -> error   (genuinely never ran)
  const commands = new ScriptedCommands()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([
      spec({ id: 'too-slow', command: ['node', 'too-slow'] }),
      spec({ id: 'hung', command: ['node', 'hang'] }),
      spec({ id: 's', command: ['node', 'enoent'] }),
    ], { concurrency: 3 })
  const byId = new Map(result.records.map(r => [r.checkId, r]))

  const tooSlow = byId.get('too-slow')
  assert.equal(tooSlow?.status, 'timeout', 'the real port\'s timeout shape must reach the timeout status')
  assert.equal(tooSlow?.exitCode, null)
  // Canonical normalisation scrubs the duration figure to '<duration>' (evidence
  // identity must not wobble on timing), so match the stable prefix.
  assert.match(tooSlow?.outputHead ?? '', /^timed out after/, 'the budget text leads the record')
  assert.ok(tooSlow?.outputHead.includes('partial output before the kill'), 'captured pre-kill output is kept')

  const hung = byId.get('hung')
  assert.equal(hung?.status, 'timeout', 'the legacy hang shape (exitCode null, nothing else) stays a timeout')

  const enoent = byId.get('s')
  assert.equal(enoent?.status, 'error', 'a spawnError WITHOUT timedOut is still "never ran" — an error')
})

// 9. timedOut with a non-null exitCode stays a timeout (H-18d/B7-M1) --------------

test('RUNNER: timedOut=true with a non-null exitCode is still a timeout, not a decisive fail (H-18d)', async () => {
  // The POSIX SIGTERM-trap shape: the port killed the child for exceeding its
  // budget, the child's handler ran process.exit(1) on the way down. Before
  // the port carried `timedOut` through the close(code !== null) path, this
  // landed as exitCode 1 → 'fail' — a DECISIVE outcome, recording a false
  // regression for a check that was merely slow. The first-class fact wins.
  const commands = new ScriptedCommands()
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), new FakeClock())
    .run([spec({ id: 'trapped', command: ['node', 'trap-timeout'] })])

  const record = result.records[0]
  assert.equal(record?.status, 'timeout', '"we killed it for exceeding the budget" outranks the corpse exit code')
  assert.equal(record?.exitCode, 1, 'the exit code itself is preserved as a fact')
  assert.match(record?.outputHead ?? '', /graceful shutdown/, 'captured pre-death output rides along')
})

// 10. In-flight budget overrun is recorded, not hidden (M-08) -----------------------

/** Clock the test advances explicitly — no per-read ticking to hand-count. */
class ManualClock implements Clock {
  nowMs = 1_000
  now(): number { return this.nowMs }
}

/** FakeCommands whose every run advances the manual clock by a fixed cost. */
class AdvancingCommands extends FakeCommands implements CommandPort {
  private readonly clock: ManualClock
  constructor(clock: ManualClock) { super(); this.clock = clock }
  async run(argv: readonly string[], options: CommandRunOptions): Promise<CommandResult> {
    const result = await super.run(argv, options)
    this.clock.nowMs += 50
    return result
  }
}

test('RUNNER: a check finishing past the budget flags budgetExceeded without being killed (M-08)', async () => {
  // totalBudgetMs gates which checks START; the third check is admitted at
  // t=100 (budget 120 still has room), runs its 50ms, and lands at t=150 —
  // 30ms past the line. The old behaviour: nothing recorded the overrun, and
  // the "wall-clock budget for the whole batch" claim quietly failed. The
  // fix keeps the evidence real (no hard kill) and flags the batch.
  const clock = new ManualClock()
  const commands = new AdvancingCommands(clock)
  const result = await new VerificationRunner(commands, new FakeWorkspace(ROOT), clock)
    .run([spec({ id: 'a' }), spec({ id: 'b' }), spec({ id: 'c' })],
      { concurrency: 1, totalBudgetMs: 120 })

  assert.deepEqual(result.ranIds, ['a', 'b', 'c'], 'an in-flight check is never hard-killed — it finished')
  assert.deepEqual(result.skippedIds, [], 'nothing was left unstarted: the budget never blocked a START')
  assert.equal(result.budgetExceeded, true, 'the batch overran its wall-clock budget and says so')
  assert.ok(result.records.every(r => r.status === 'pass'), 'the overrun check\'s evidence is a real pass, not a mangled skip')

  // Control: the same batch inside the budget does not flag.
  const fineClock = new ManualClock()
  const fine = await new VerificationRunner(new AdvancingCommands(fineClock), new FakeWorkspace(ROOT), fineClock)
    .run([spec({ id: 'a' }), spec({ id: 'b' }), spec({ id: 'c' })],
      { concurrency: 1, totalBudgetMs: 10_000 })
  assert.equal(fine.budgetExceeded, undefined, 'a batch that fits its budget carries no flag')
})
