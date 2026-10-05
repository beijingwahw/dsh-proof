/**
 * NODE PORTS FIDELITY — the adapter layer must be byte-accurate and must
 * report git facts exactly as git states them.
 *
 * Covers the three fidelity bugs fixed in src/node-ports.ts:
 *   D1  `git status --porcelain -z` rename entries are TWO NUL fields
 *       (`R  <new>\0<old>\0`) — both halves are workspace facts, and the
 *       prefix-less old path must not be status-parsed.
 *   D2  Multi-byte UTF-8 characters straddling chunk boundaries must survive
 *       capture as the exact character, never U+FFFD.
 *   D3  An already-aborted signal must prevent the spawn entirely.
 * plus the env-merge contract (D4) and real-git integration for the
 * changedSince/untracked `-z` parsing (D7).
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { GitWorkspace, NodeCommandPort, parsePorcelainZ } from '../src/node-ports.ts'
import type { CommandPort, CommandResult } from '../src/core/ports.ts'

// <workspace>/.openclaw/tmp/... — the designated scratch area.
const WORKSPACE = fileURLToPath(new URL('../../', import.meta.url))
const SCRATCH = join(WORKSPACE, '.openclaw', 'tmp')
const GIT_ROOT = join(SCRATCH, `node-ports-git-${process.pid}`)

const commands = new NodeCommandPort()

async function git(...args: string[]): Promise<CommandResult> {
  return commands.run(['git', ...args], {
    cwd: GIT_ROOT, timeoutMs: 20_000, signal: AbortSignal.timeout(20_000),
  })
}

before(async () => {
  await fsp.rm(GIT_ROOT, { recursive: true, force: true })
  await fsp.mkdir(join(GIT_ROOT, 'src'), { recursive: true })

  const step = async (label: string, ...args: string[]) => {
    const result = await git(...args)
    assert.equal(result.exitCode, 0, `${label} failed: ${result.output.slice(0, 300)}`)
  }
  await step('git init', 'init')
  await step('git config user.email', 'config', 'user.email', 'dsh-proof@test.local')
  await step('git config user.name', 'config', 'user.name', 'dsh-proof test')
  await step('git config core.autocrlf', 'config', 'core.autocrlf', 'false')

  await fsp.writeFile(join(GIT_ROOT, 'src', 'old.ts'), 'export const a = 1\n')
  await fsp.writeFile(join(GIT_ROOT, 'keep.ts'), 'export const b = 2\n')
  await step('git add', 'add', '-A')
  await step('git commit', 'commit', '-m', 'init')

  // A staged rename (the D1 killer), an unstaged modification, untracked
  // files — one nested, so `?? sub/` collapses in status but not in ls-files.
  await step('git mv', 'mv', 'src/old.ts', 'src/new.ts')
  await fsp.writeFile(join(GIT_ROOT, 'keep.ts'), 'export const b = 3\n')
  await fsp.writeFile(join(GIT_ROOT, 'untracked.ts'), 'untracked\n')
  await fsp.mkdir(join(GIT_ROOT, 'sub'))
  await fsp.writeFile(join(GIT_ROOT, 'sub', 'new.ts'), 'nested\n')
})

after(async () => {
  await fsp.rm(GIT_ROOT, { recursive: true, force: true })
})

// -- parsePorcelainZ (pure, D1) ----------------------------------------------

test('parsePorcelainZ: a rename contributes BOTH paths — no phantom truncation', () => {
  assert.deepEqual(parsePorcelainZ('R  src/new.ts\0src/old.ts\0'), ['src/new.ts', 'src/old.ts'])
  // The old bug sliced 3 chars off the prefix-less old path ('src/old.ts'
  // became 'old.ts') and polluted the dirty set with a phantom path.
  assert.ok(!parsePorcelainZ('R  src/new.ts\0src/old.ts\0').includes('old.ts'))
})

test('parsePorcelainZ: copy entries are rename-shaped too', () => {
  assert.deepEqual(parsePorcelainZ('C  dst.ts\0src.ts\0'), ['dst.ts', 'src.ts'])
})

test('parsePorcelainZ: staged-then-modified rename (RM) still pairs both fields', () => {
  assert.deepEqual(parsePorcelainZ('RM n.ts\0o.ts\0'), ['n.ts', 'o.ts'])
})

test('parsePorcelainZ: ordinary and untracked entries parse by status prefix', () => {
  assert.deepEqual(
    parsePorcelainZ('M  a.ts\0 M b.ts\0?? c.ts\0MM d.ts\0UU e.ts\0'),
    ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'e.ts'],
  )
})

test('parsePorcelainZ: paths with spaces survive verbatim (no trim, no quoting in -z)', () => {
  assert.deepEqual(parsePorcelainZ('R  a/new.ts\0my old file .ts\0'), ['a/new.ts', 'my old file .ts'])
  assert.deepEqual(parsePorcelainZ('?? sp ace.ts\0'), ['sp ace.ts'])
})

test('parsePorcelainZ: a rename followed by more entries does not desync the walk', () => {
  assert.deepEqual(parsePorcelainZ('R  n.ts\0o.ts\0?? u.ts\0M  m.ts\0'), ['m.ts', 'n.ts', 'o.ts', 'u.ts'])
})

test('parsePorcelainZ: untracked directories keep their trailing slash', () => {
  assert.deepEqual(parsePorcelainZ('?? build/\0'), ['build/'])
})

test('parsePorcelainZ: empty and NUL-only input yield an empty set', () => {
  assert.deepEqual(parsePorcelainZ(''), [])
  assert.deepEqual(parsePorcelainZ('\0\0\0'), [])
})

test('parsePorcelainZ: garbage input is tolerated, never thrown, never dropped', () => {
  // A field without a status prefix is kept verbatim rather than eaten.
  assert.deepEqual(parsePorcelainZ('plain-garbage\0'), ['plain-garbage'])
  assert.deepEqual(parsePorcelainZ('?? only\0junk-field\0'), ['junk-field', 'only'])
  assert.deepEqual(parsePorcelainZ('R  new.ts\0'), ['new.ts']) // truncated rename: old path missing
})

// -- NodeCommandPort (D2, D3, D4) ---------------------------------------------

test('NODE-PORTS: an already-aborted signal returns without spawning', async () => {
  const controller = new AbortController()
  controller.abort()
  const startedAt = Date.now()
  const result = await commands.run(
    [process.execPath, '-e', 'setTimeout(() => process.stdout.write("late"), 3000)'],
    { cwd: WORKSPACE, timeoutMs: 8_000, signal: controller.signal },
  )
  const wallMs = Date.now() - startedAt
  assert.equal(result.aborted, true)
  assert.equal(result.exitCode, null)
  assert.equal(result.output, '')
  assert.equal(result.durationMs, 0)
  assert.ok(wallMs < 3_000, `run() took ${wallMs}ms — an aborted signal must not wait on a live child`)
})

test('NODE-PORTS: multi-byte UTF-8 across stdout chunk boundaries captures exactly', async () => {
  // 200k x (3-byte U+5BF9) = 600 KB through a ~64 KB pipe: boundaries land
  // mid-character constantly. Evidence digests are only stable if capture is
  // byte-faithful.
  const expected = '对'.repeat(200_000)
  const result = await commands.run(
    [process.execPath, '-e', "process.stdout.write('对'.repeat(200000))"],
    { cwd: WORKSPACE, timeoutMs: 30_000, signal: AbortSignal.timeout(30_000), maxOutputChars: 300_000 },
  )
  assert.equal(result.exitCode, 0, result.output.slice(0, 200))
  assert.ok(!result.output.includes('\uFFFD'), 'capture contains U+FFFD replacement characters')
  assert.equal(result.output, expected)
})

test('NODE-PORTS: multi-byte UTF-8 across stderr chunk boundaries captures exactly', async () => {
  const expected = '错'.repeat(100_000)
  const result = await commands.run(
    [process.execPath, '-e', "process.stderr.write('错'.repeat(100000))"],
    { cwd: WORKSPACE, timeoutMs: 30_000, signal: AbortSignal.timeout(30_000), maxOutputChars: 150_000 },
  )
  assert.equal(result.exitCode, 0, result.output.slice(0, 200))
  assert.ok(!result.output.includes('\uFFFD'), 'capture contains U+FFFD replacement characters')
  assert.equal(result.output, expected)
})

test('NODE-PORTS: deterministic env defaults apply, options.env overrides them', async () => {
  const read = async (env?: Record<string, string>): Promise<string> => {
    const result = await commands.run(
      [process.execPath, '-e', 'process.stdout.write(String(process.env.NO_COLOR))'],
      {
        cwd: WORKSPACE, timeoutMs: 10_000, signal: AbortSignal.timeout(10_000),
        ...(env === undefined ? {} : { env }),
      },
    )
    assert.equal(result.exitCode, 0, result.output.slice(0, 200))
    return result.output
  }
  // Default: forced deterministic output, even if the host environment says otherwise.
  assert.equal(await read(undefined), '1')
  // A host overlay wins over the forced defaults.
  assert.equal(await read({ NO_COLOR: 'host-choice' }), 'host-choice')
})

// -- GitWorkspace against a real git repository (D1, D7) ----------------------

test('GIT: gitDirty reports both ends of a staged rename and no phantom paths', async () => {
  const ws = new GitWorkspace(GIT_ROOT)
  const dirty = await ws.gitDirty()
  assert.deepEqual(dirty, ['keep.ts', 'src/new.ts', 'src/old.ts', 'sub/', 'untracked.ts'])
  assert.ok(!dirty.includes('old.ts'), `phantom truncated path 'old.ts' leaked into the dirty set: ${dirty.join(', ')}`)
})

test('GIT: gitHead returns the commit hash', async () => {
  const head = await new GitWorkspace(GIT_ROOT).gitHead()
  assert.match(head ?? '', /^[0-9a-f]{40,64}$/)
})

test('GIT: changedSince parses the plain NUL-separated diff list (D7)', async () => {
  const changed = await new GitWorkspace(GIT_ROOT).changedSince('HEAD')
  // keep.ts is modified; the rename surfaces as src/new.ts (rename detection
  // may or may not also list src/old.ts — both are honest git facts).
  assert.ok(changed.includes('keep.ts'), `got: ${changed.join(', ')}`)
  assert.ok(changed.includes('src/new.ts'), `got: ${changed.join(', ')}`)
  const allowed = new Set(['keep.ts', 'src/new.ts', 'src/old.ts'])
  for (const path of changed) assert.ok(allowed.has(path), `unexpected path in change set: ${path}`)
})

test('GIT: untracked parses the plain NUL-separated ls-files list (D7)', async () => {
  const files = await new GitWorkspace(GIT_ROOT).untracked()
  assert.deepEqual(files, ['sub/new.ts', 'untracked.ts'])
})

test('GIT: non-zero git exits degrade to empty facts, not garbage', async () => {
  const failing: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: 128,
      output: 'fatal: not a git repository (or any of the parent directories): .git\n',
      durationMs: 1,
      aborted: false,
    }),
  }
  const ws = new GitWorkspace('C:/definitely/not/a/repo', failing)
  assert.equal(await ws.gitHead(), null)
  assert.deepEqual(await ws.gitDirty(), [])
  assert.deepEqual(await ws.changedSince('HEAD'), [])
  assert.deepEqual(await ws.untracked(), [])
})

// -- gitAvailable (E3) ---------------------------------------------------------

test('GIT: gitAvailable is true inside a real work tree', async () => {
  assert.equal(await new GitWorkspace(GIT_ROOT).gitAvailable(), true)
})

test('GIT: gitAvailable is false outside any repository, and probed only once', async () => {
  // Stubbed rather than a real scratch dir: any ancestor .git would make a
  // real dir "inside a work tree" (the shared tmp area lives under one), and
  // availability must not depend on where the suite happens to be checked out.
  let probes = 0
  const notARepo: CommandPort = {
    run: async (argv): Promise<CommandResult> => {
      if (argv.includes('rev-parse')) probes += 1
      return {
        exitCode: 128,
        output: 'fatal: not a git repository (or any of the parent directories): .git\n',
        durationMs: 1,
        aborted: false,
      }
    },
  }
  const ws = new GitWorkspace('C:/definitely/not/a/repo', notARepo)
  assert.equal(await ws.gitAvailable(), false)
  assert.equal(await ws.gitAvailable(), false, 'the cached answer is returned')
  assert.equal(probes, 1, 'availability is probed once per instance — git usability does not flip mid-process')
})

test('GIT: gitAvailable demands "true" output, not just exit 0 (bare repos exit 0 with "false")', async () => {
  const bare: CommandPort = {
    run: async (): Promise<CommandResult> => ({ exitCode: 0, output: 'false\n', durationMs: 1, aborted: false }),
  }
  assert.equal(await new GitWorkspace('/ws', bare).gitAvailable(), false)
})
