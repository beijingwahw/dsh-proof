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
 *
 * Node adapter fidelity round 2:
 *   R1  npm-style `.cmd` shims are PARSED (never shelled) so a user-configured
 *       `pnpm test` argv vector actually runs on Windows; anything non-standard
 *       degrades to the clean spawnError, not mojibake.
 *   R2  `CommandResult.killedBySignal` carries external signal deaths to the
 *       port boundary (Windows cannot propagate signals — asserted as such).
 *   R3  concurrent writeFile temp names no longer collide within one process.
 *
 * Node adapter fidelity round 3 (v0.16 correctness batch):
 *   H7  a real port timeout sets `timedOut: true` on the CommandResult (the
 *       spawnError text stays for legacy consumers) — the first real-process
 *       timeout test in the suite.
 *   H11 a private-key read failure that is NOT ENOENT (EISDIR/EPERM/EBUSY)
 *       makes NodeEd25519Signer.load REJECT instead of silently rotating the
 *       signing key over the old one.
 *   H6  failed git fact queries (non-zero exit, timeout kill, spawnError)
 *       REJECT with the subcommand and exit code in the message; a failing
 *       query must never answer "clean".
 *
 * Node adapter fidelity round 4 (v0.22 H-18/M-batch):
 *   H-18 a timeout kill takes the pipe-holding GRANDCHILD down with the tree
 *       (POSIX: detached process-group kill; Windows: libuv job object —
 *       pinned with a real process tree and a post-kill liveness marker,
 *       the D1-corrected evidence design: the marker is written only if the
 *       grandchild is still alive well AFTER the kill).
 *   H-18b a child that exits while a grandchild still holds the pipes settles
 *       by the grace deadline (injectable), never hangs.
 *   B7-L1 a truncated capture ends with an explicit marker line.
 *   B8-L2 an inherited NODE_V8_COVERAGE is stripped; the runner's overlay wins.
 *   M-31 appendLine refuses a redirected (symlink/directory) log path.
 *   M-83 the signer public half is atomic, verified against the private key,
 *       and repaired from it on mismatch — keyId can never drift.
 *   B8-L1 gitHead distinguishes "no commit" (answered non-zero → null) from
 *       "no answer" (timeout/spawn failure → REJECT, landing in the engine's
 *       git-blind degradation).
 *   B8-L4 an answer-less availability probe is retried exactly once.
 *   B8-L5 changedSince separates the ref from pathspecs with `--`.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { generateKeyPairSync } from 'node:crypto'

import { GitWorkspace, NodeCommandPort, NodeEd25519Signer, NodeFsPort, parsePorcelainZ, resolveCmdShim } from '../src/node-ports.ts'
import type { CommandPort, CommandResult } from '../src/core/ports.ts'
import { MemoryFs } from './helpers.ts'

// <workspace>/.openclaw/tmp/... — the designated scratch area (one level
// ABOVE the repo: the workspace root, not the checkout).
const WORKSPACE = fileURLToPath(new URL('../../', import.meta.url))
const REPO = fileURLToPath(new URL('../', import.meta.url))
const SCRATCH = join(WORKSPACE, '.openclaw', 'tmp')
const GIT_ROOT = join(SCRATCH, `node-ports-git-${process.pid}`)

// .cmd shim fixtures (R1): npm-template shims in a fake PATH directory, with
// their target OUTSIDE that directory — the `..\pkg\target` shape real
// node_modules layouts produce.
const SHIM_ROOT = join(SCRATCH, `node-ports-shim-${process.pid}`)
const SHIM_BIN = join(SHIM_ROOT, 'bin')
const SHIM_TARGET_DIR = join(SHIM_ROOT, 'target')
const SHIM_ENTRY = join(SHIM_TARGET_DIR, 'entry.js')
const ATOMIC_DIR = join(SCRATCH, `node-ports-atomic-${process.pid}`)
// H-18 fixtures: a real two-level process tree. The grandchild inherits the
// port's stdout/stderr pipes (stdio 'inherit' in the child), stays alive, and
// only writes its liveness marker well AFTER the port's kill moment — marker
// presence therefore proves post-kill survival (the v0.21 B7 experiment wrote
// the marker at spawn, proving only that the grandchild started; D1 refuted
// its "Windows grandchild survives" reading with exactly this correction).
const TREE_DIR = join(SCRATCH, `node-ports-tree-${process.pid}`)

const commands = new NodeCommandPort()

async function git(...args: string[]): Promise<CommandResult> {
  return commands.run(['git', ...args], {
    cwd: GIT_ROOT, timeoutMs: 20_000, signal: AbortSignal.timeout(20_000),
  })
}

/** Byte-faithful copy of the npm cmd-shim template (cf. node_modules/.bin/tsc.cmd). */
function npmStyleCmd(targetRel: string): string {
  return [
    '@ECHO off',
    'GOTO start',
    ':find_dp0',
    'SET dp0=%~dp0',
    'EXIT /b',
    ':start',
    'SETLOCAL',
    'CALL :find_dp0',
    '',
    'IF EXIST "%dp0%\\node.exe" (',
    '  SET "_prog=%dp0%\\node.exe"',
    ') ELSE (',
    '  SET "_prog=node"',
    '  SET PATHEXT=%PATHEXT:;.JS;=;%',
    ')',
    '',
    `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\${targetRel}" %*`,
    '',
  ].join('\r\n')
}

/**
 * PATH overlay naming the REAL key Windows handed us ('Path' as often as
 * 'PATH'): a differently-cased duplicate would leave two PATH entries in the
 * child env and make the winner undefined.
 */
function envWithShimBin(): Record<string, string> {
  const pathKey = Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH'
  return { [pathKey]: `${SHIM_BIN};${process.env[pathKey] ?? ''}` }
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

  // R1 fixtures: the fake entry echoes its forwarded argv so the test can
  // prove args (including ones with spaces) ride along the rewrite.
  await fsp.mkdir(SHIM_BIN, { recursive: true })
  await fsp.mkdir(SHIM_TARGET_DIR, { recursive: true })
  await fsp.writeFile(SHIM_ENTRY, "process.stdout.write('shim-ok:' + process.argv.slice(2).join('|'))\n", 'utf8')
  await fsp.writeFile(join(SHIM_BIN, 'dshfakeshim.cmd'), npmStyleCmd('..\\target\\entry.js'), 'utf8')

  // H-18 fixtures (CommonJS so they run identically under every launch mode):
  // grandchild-hold.cjs <marker> <markerAtMs> <exitAtMs> — inherits the pipes,
  // writes the marker only if still alive at markerAtMs, self-exits at
  // exitAtMs (nothing leaks past the test even where the port cannot kill it).
  await fsp.mkdir(TREE_DIR, { recursive: true })
  await fsp.writeFile(join(TREE_DIR, 'grandchild-hold.cjs'), [
    "const fs = require('fs')",
    'const marker = process.argv[2]',
    'const markerAtMs = Number(process.argv[3] || 2000)',
    'const exitAtMs = Number(process.argv[4] || 5000)',
    'if (markerAtMs > 0) setTimeout(() => { try { fs.writeFileSync(marker, "grandchild-alive\\n") } catch {} }, markerAtMs)',
    'setTimeout(() => process.exit(0), exitAtMs)',
    "setInterval(() => {}, 1000) // hold the inherited pipes open, stay alive",
    '',
  ].join('\n'), 'utf8')
  // spawn-gc-stay.cjs <gcScript> <marker> <markerAtMs> <exitAtMs> — spawns the
  // grandchild with INHERITED stdio (the port's pipes), then stays alive so
  // the port's timeout must kill this tree.
  await fsp.writeFile(join(TREE_DIR, 'spawn-gc-stay.cjs'), [
    "const { spawn } = require('child_process')",
    "const gc = spawn(process.execPath, [process.argv[2], process.argv[3], process.argv[4], process.argv[5]], { stdio: ['ignore', 'inherit', 'inherit'] })",
    "process.stdout.write('gc=' + gc.pid + '\\n')",
    "setInterval(() => {}, 1000) // stay alive: the timeout must kill us",
    '',
  ].join('\n'), 'utf8')
  // spawn-gc-exit0.cjs — same shape, but the child exits 0 immediately: the
  // grandchild alone keeps the pipes open.
  await fsp.writeFile(join(TREE_DIR, 'spawn-gc-exit0.cjs'), [
    "const { spawn } = require('child_process')",
    "const gc = spawn(process.execPath, [process.argv[2], process.argv[3], process.argv[4], process.argv[5]], { stdio: ['ignore', 'inherit', 'inherit'] })",
    "process.stdout.write('gc=' + gc.pid + '\\n')",
    'process.exit(0)',
    '',
  ].join('\n'), 'utf8')
})

after(async () => {
  await fsp.rm(GIT_ROOT, { recursive: true, force: true })
  await fsp.rm(SHIM_ROOT, { recursive: true, force: true })
  await fsp.rm(ATOMIC_DIR, { recursive: true, force: true })
  await fsp.rm(TREE_DIR, { recursive: true, force: true })
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

test('NODE-PORTS (W15-L8b): a non-finite or non-positive timeoutMs is refused before spawning — never booked as a timeout', async () => {
  // NaN made `Math.max(1, NaN)` NaN and `setTimeout(NaN, …)` fire in ~0ms;
  // Node silently clamps Infinity (and anything above 2^31-1) to 1ms. Every
  // one of those shapes used to kill the child instantly and report it as
  // `timedOut` — "ran too slow" about a process that never ran. A budget
  // that is not a finite positive number is a caller bug: the port refuses
  // to spawn and names it, so the evidence books a plain error instead of a
  // misattributed death cause.
  for (const timeoutMs of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0, -5]) {
    const startedAt = Date.now()
    const result = await commands.run(
      [process.execPath, '-e', 'setTimeout(() => process.stdout.write("late"), 3000)'],
      { cwd: WORKSPACE, timeoutMs, signal: AbortSignal.timeout(10_000) },
    )
    const wallMs = Date.now() - startedAt
    assert.equal(result.exitCode, null, `timeoutMs ${timeoutMs}: nothing ran, so there is no exit code`)
    assert.equal(result.aborted, false)
    assert.equal(result.timedOut, undefined, `timeoutMs ${timeoutMs}: the death cause must not say "too slow"`)
    assert.match(result.spawnError ?? '', /invalid timeoutMs/, `timeoutMs ${timeoutMs}: the refusal names the bug`)
    assert.ok(wallMs < 3_000, `timeoutMs ${timeoutMs}: run() took ${wallMs}ms — no child was ever spawned`)
    assert.equal(result.output, '')
  }
})

test('NODE-PORTS (W15-L8b): a finite positive budget beyond Node\'s timer domain is clamped, not coerced to a 1ms kill', async () => {
  // 3e9 ms is beyond setTimeout's 2^31-1 domain: Node coerces it to 1ms —
  // an instant timeout death for a budget that asked for ~35 days. The port
  // clamps to the timer domain instead, which is the closest a timer can
  // come to "effectively unlimited": the quick command below completes.
  const result = await commands.run(
    [process.execPath, '-e', "process.stdout.write('survived')"],
    { cwd: WORKSPACE, timeoutMs: 3_000_000_000, signal: AbortSignal.timeout(10_000) },
  )
  assert.equal(result.exitCode, 0, result.spawnError ?? result.output)
  assert.equal(result.output, 'survived')
  assert.equal(result.timedOut, undefined)
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

test('GIT: gitHead survives non-zero exits as null, the fact queries REJECT (H6)', async () => {
  // v0.16 tightened behaviour: a failed `git status`/`git diff`/`git
  // ls-files` used to coerce into `[]` — indistinguishable from "clean",
  // which is how committed changes vanished from change sets (H6, fake
  // proven direction). The fact queries must now throw, naming the
  // subcommand and the exit code; only `gitHead` keeps its `string | null`
  // contract ("no commit" is a legitimate answer, not a query failure).
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
  await assert.rejects(ws.gitDirty(), /status --porcelain[^]*exit code 128/)
  await assert.rejects(ws.changedSince('HEAD'), /diff --name-only[^]*exit code 128/)
  await assert.rejects(ws.untracked(), /ls-files --others[^]*exit code 128/)
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

// -- .cmd shim parsing, no shell ever (R1) --------------------------------------

test('CMD-SHIM: the real npm-generated tsc.cmd parses to node + typescript/bin/tsc', () => {
  const shim = join(REPO, 'node_modules', '.bin', 'tsc.cmd')
  assert.ok(existsSync(shim), `fixture missing: ${shim}`)
  const resolution = resolveCmdShim(shim)
  assert.ok(resolution !== undefined, 'the real npm template must parse')
  assert.ok('script' in resolution, `expected a node+script resolution, got ${JSON.stringify(resolution)}`)
  if (!('script' in resolution)) return
  assert.equal(resolution.node, process.execPath, 'no node.exe lives next to the shim')
  assert.equal(resolution.script, join(REPO, 'node_modules', 'typescript', 'bin', 'tsc').toLowerCase())
})

test('CMD-SHIM: the legacy two-branch template collapses to one target; ambiguity is refused', async () => {
  const legacy = join(SHIM_BIN, 'legacy.cmd')
  await fsp.writeFile(legacy, [
    '@IF EXIST "%~dp0\\node.exe" (',
    `  "%~dp0\\node.exe"  "%~dp0\\..\\target\\entry.js" %*`,
    ') ELSE (',
    `  node  "%~dp0\\..\\target\\entry.js" %*`,
    ')',
    '',
  ].join('\r\n'), 'utf8')
  const legacyResolution = resolveCmdShim(legacy)
  assert.ok(legacyResolution !== undefined, 'both branches name the same target — that is one program')
  assert.ok('script' in legacyResolution, `expected node+script, got ${JSON.stringify(legacyResolution)}`)
  if ('script' in legacyResolution) {
    assert.equal(legacyResolution.script, SHIM_ENTRY.toLowerCase())
    assert.equal(legacyResolution.node, process.execPath)
  }

  // Two DIFFERENT targets: refuse outright, even though one is unreadable
  // garbage — never pick a "most likely" branch.
  const ambiguous = join(SHIM_BIN, 'ambiguous.cmd')
  await fsp.writeFile(ambiguous, [
    '@echo off',
    `"%_prog%"  "%dp0%\\..\\target\\entry.js" %*`,
    `node  "%~dp0\\..\\target\\other.js" %*`,
    '',
  ].join('\r\n'), 'utf8')
  assert.equal(resolveCmdShim(ambiguous), undefined)
})

test('CMD-SHIM: a shim that directly invokes an .exe resolves to that exe', async () => {
  const exeTarget = join(SHIM_TARGET_DIR, 'tool.exe')
  await fsp.writeFile(exeTarget, '', 'utf8') // existence is all the resolver can vouch for
  const shim = join(SHIM_BIN, 'direct-exe.cmd')
  // npm's non-node tail: same template, but the invocation target IS the exe.
  await fsp.writeFile(shim, [
    '@ECHO off',
    'GOTO start',
    ':find_dp0',
    'SET dp0=%~dp0',
    'EXIT /b',
    ':start',
    'SETLOCAL',
    'CALL :find_dp0',
    '',
    `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%dp0%\\..\\target\\tool.exe" %*`,
    '',
  ].join('\r\n'), 'utf8')
  assert.deepEqual(resolveCmdShim(shim), { exe: exeTarget.toLowerCase() })
})

test('NODE-PORTS: a user-configured .cmd shim command runs, no shell (R1)', async () => {
  const result = await commands.run(['dshfakeshim', 'alpha', 'beta gamma'], {
    cwd: SCRATCH, timeoutMs: 30_000, signal: AbortSignal.timeout(30_000), env: envWithShimBin(),
  })
  assert.equal(result.spawnError, undefined)
  assert.equal(result.exitCode, 0, result.output.slice(0, 300))
  // Args ride the rewrite verbatim — spaces included, no quoting games.
  assert.equal(result.output, 'shim-ok:alpha|beta gamma')
})

test('NODE-PORTS: the same shim command without the PATH entry is a clean ENOENT spawnError', async () => {
  const result = await commands.run(['dshfakeshim', 'x'], {
    cwd: SCRATCH, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
  })
  assert.equal(result.exitCode, null)
  assert.equal(result.aborted, false)
  assert.equal(result.spawnError, 'spawn failed: ENOENT')
})

test('NODE-PORTS: a non-standard .cmd shim degrades to a clean spawnError, never mojibake', async () => {
  const shim = join(SHIM_BIN, 'dshweirdshim.cmd')
  await fsp.writeFile(shim, '@echo off\r\npowershell -NoProfile -File "%~dp0\\weird.ps1" %*\r\n', 'utf8')
  // A powershell tail is shell-only — the parser must refuse it, and the raw
  // spawn of the bare name then fails ENOENT (probed on node 24.19/win32).
  assert.equal(resolveCmdShim(shim), undefined)
  const result = await commands.run(['dshweirdshim', 'x'], {
    cwd: SCRATCH, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000), env: envWithShimBin(),
  })
  assert.equal(result.exitCode, null)
  assert.equal(result.spawnError, 'spawn failed: ENOENT')
  assert.ok(/^[\x20-\x7E]+$/.test(result.spawnError ?? ''), 'spawnError must be clean printable ASCII')
})

// -- killedBySignal (R2) ---------------------------------------------------------

test('NODE-PORTS: a child terminated by an external signal carries killedBySignal (R2)', async () => {
  const result = await commands.run(
    [process.execPath, '-e', "process.kill(process.pid, 'SIGTERM')"],
    { cwd: WORKSPACE, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000) },
  )
  assert.equal(result.aborted, false)
  if (process.platform === 'win32') {
    // Windows cannot propagate POSIX signals across processes: TerminateProcess
    // surfaces as a plain exit code with no signal (probed: close(1, null)).
    // The field must stay unset rather than invent a signal.
    assert.equal(result.exitCode, 1)
    assert.equal(result.killedBySignal, undefined)
  } else {
    assert.equal(result.exitCode, null)
    assert.equal(result.killedBySignal, 'SIGTERM')
  }
})

// -- concurrent writeFile temp names (R3) ----------------------------------------

test('FS: 100 concurrent writeFile calls leave one intact winner and no temp residue (R3)', async () => {
  const fs = new NodeFsPort()
  const target = join(ATOMIC_DIR, 'anchor.json')
  const payloads = Array.from({ length: 100 }, (_, i) => JSON.stringify({ writer: i, blob: 'x'.repeat(512) }))
  await Promise.all(payloads.map((p) => fs.writeFile(target, p)))
  const final = await fs.readFile(target)
  assert.ok(final !== undefined && payloads.includes(final),
    `final content is not any single writer's complete write: ${final?.slice(0, 80)}`)
  const residue = (await fsp.readdir(ATOMIC_DIR)).filter((name) => name.endsWith('.tmp'))
  assert.deepEqual(residue, [])
})

// -- real-process timeout (H7) ----------------------------------------------------

test('NODE-PORTS: a real port timeout sets timedOut, keeps the legacy spawnError text (H7)', async () => {
  // The first real timeout in the suite: every previous 'timeout' status was
  // fed by fakes. The child outlives the 400ms budget by orders of magnitude.
  const startedAt = Date.now()
  const result = await commands.run(
    [process.execPath, '-e', 'setTimeout(() => {}, 10000)'],
    { cwd: WORKSPACE, timeoutMs: 400, signal: AbortSignal.timeout(30_000) },
  )
  const wallMs = Date.now() - startedAt
  assert.equal(result.timedOut, true, '"we killed it for exceeding the budget" is a first-class fact')
  assert.equal(result.exitCode, null, 'a killed process has no exit code')
  assert.equal(result.aborted, false, 'the caller did not cancel — the budget did')
  assert.ok(result.durationMs >= 350, `durationMs ${result.durationMs} — the budget must actually elapse`)
  assert.ok(wallMs < 5_000, `run() took ${wallMs}ms — the timeout must not wait on the dead child`)
  // Legacy compatibility: consumers matching on the text keep working.
  assert.ok((result.spawnError ?? '').includes('timed out'), `spawnError: ${result.spawnError}`)
  assert.ok((result.spawnError ?? '').includes('400'), 'the spawnError names the budget that was exceeded')
})

// -- signer key must not silently rotate (H11) -------------------------------------

test('SIGNER: a non-ENOENT private-key read failure rejects instead of rotating the key (H11)', async () => {
  const dir = join(SCRATCH, `node-ports-signer-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(join(dir, 'proof-signing-key.pem'), { recursive: true }) // EISDIR on read
  await assert.rejects(
    NodeEd25519Signer.load(dir),
    (error: unknown) => {
      const code = (error as NodeJS.ErrnoException).code
      assert.ok(code !== 'ENOENT', 'the failure must be the read error itself, rethrown')
      return true
    },
    'EPERM/EBUSY/EISDIR must surface, not trigger key generation',
  )
  // No rotation happened: the "key" is still the directory the read tripped
  // over, and no public half was ever written next to it.
  assert.ok((await fsp.stat(join(dir, 'proof-signing-key.pem'))).isDirectory(),
    'a fresh PEM must not have replaced the unreadable path')
  assert.equal(existsSync(join(dir, 'proof-signing-key.pub.pem')), false,
    'no public half may appear for a key that was never loaded')
  await fsp.rm(dir, { recursive: true, force: true })
})

// -- failed git fact queries reject (H6) -------------------------------------------

test('GIT: a timeout-killed git query (exitCode null) rejects, never answers clean (H6)', async () => {
  const killed: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: null, output: '', durationMs: 15_000, aborted: false,
      spawnError: 'timed out after 15000ms', timedOut: true,
    }),
  }
  const ws = new GitWorkspace(GIT_ROOT, killed)
  await assert.rejects(ws.gitDirty(), /status --porcelain[^]*produced no answer[^]*timed out/)
  await assert.rejects(ws.changedSince('HEAD'), /diff --name-only/)
  await assert.rejects(ws.untracked(), /ls-files --others/)
})

test('GIT: a spawnError git query rejects with the spawn failure named (H6)', async () => {
  const broken: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: null, output: '', durationMs: 0, aborted: false,
      spawnError: 'spawn failed: ENOENT',
    }),
  }
  const ws = new GitWorkspace(GIT_ROOT, broken)
  await assert.rejects(ws.gitDirty(), /status --porcelain[^]*produced no answer[^]*spawn failed: ENOENT/)
})

test('GIT: one failing fact query does not take the others down (H6)', async () => {
  // index.lock contention hits `git status` while diff/ls-files still answer:
  // each query fails (or succeeds) on its own merits.
  const flaky: CommandPort = {
    run: async (argv): Promise<CommandResult> => {
      if (argv.includes('status')) {
        return { exitCode: 128, output: 'fatal: Unable to create index.lock: File exists.\n', durationMs: 1, aborted: false }
      }
      if (argv.includes('diff')) {
        return { exitCode: 0, output: 'keep.ts\0', durationMs: 1, aborted: false }
      }
      return { exitCode: 0, output: 'untracked.ts\0', durationMs: 1, aborted: false }
    },
  }
  const ws = new GitWorkspace(GIT_ROOT, flaky)
  await assert.rejects(ws.gitDirty(), /status --porcelain[^]*exit code 128[^]*index\.lock/)
  assert.deepEqual(await ws.changedSince('HEAD'), ['keep.ts'])
  assert.deepEqual(await ws.untracked(), ['untracked.ts'])
})

// -- walk truncation is a first-class fact (M8) -----------------------------------
//
// The fidelity bug this pins: `FsPort.walk` used to return a bare file list,
// so a workspace with more files than the limit produced a complete-LOOKING
// prefix and the impact graph built on it never said it was partial. The
// walk must now carry `truncated` — verified here against a real directory.

test('FS: walk reports truncated=true when a real directory exceeds the limit (M8)', async () => {
  const dir = join(SCRATCH, `node-ports-walk-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(join(dir, 'src'), { recursive: true })
  await fsp.writeFile(join(dir, 'a.ts'), 'a', 'utf8')
  await fsp.writeFile(join(dir, 'b.ts'), 'b', 'utf8')
  await fsp.writeFile(join(dir, 'src', 'c.ts'), 'c', 'utf8')
  try {
    const fs = new NodeFsPort()

    const capped = await fs.walk(dir, { limit: 2 })
    assert.equal(capped.files.length, 2, 'the walk stops at the limit')
    assert.equal(capped.truncated, true, 'stopping at the cap means the listing is a prefix, never a census')

    const full = await fs.walk(dir, {})
    assert.deepEqual([...full.files], ['a.ts', 'b.ts', 'src/c.ts'])
    assert.equal(full.truncated, false, 'a walk that never hits the cap is complete')

    // Hitting the cap EXACTLY is also truncation: without walking past N the
    // port cannot distinguish "exactly N files" from "N and more" — the
    // conservative, honest answer at the cap is truncated.
    const exact = await fs.walk(dir, { limit: 3 })
    assert.deepEqual([...exact.files], [...full.files])
    assert.equal(exact.truncated, true, 'the cap itself stops the walk — conservatively truncated')
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

// -- the process tree dies with the kill (H-18) -----------------------------------
//
// The fidelity bug this pins: a timeout used to kill ONLY the direct child.
// A grandchild holding an inherited stdio pipe keeps `close` (exit + stdio
// EOF) from ever firing after that — on POSIX the CommandResult stayed
// pending FOREVER and the whole verification batch hung (no engine budget
// covers a single port promise). The fix takes the tree down: POSIX kills the
// detached process group, Windows relies on libuv's job object (a controlled
// experiment on win/node24 — D1 cross-validation — showed both a kill of the
// direct child AND its voluntary exit already take the tree with them, so no
// detached/group machinery is added there).

test('NODE-PORTS: a timeout kill reclaims the pipe-holding grandchild with the tree (H-18)', async () => {
  const marker = join(TREE_DIR, 'marker-b.txt')
  await fsp.rm(marker, { force: true })
  const startedAt = Date.now()
  // The child stays alive (the timeout must kill it); the grandchild holds
  // the pipes and writes its marker at +2000ms — 1.5s AFTER the 500ms kill,
  // so the marker can only exist if the tree reclamation failed.
  const result = await commands.run(
    [process.execPath, join(TREE_DIR, 'spawn-gc-stay.cjs'),
      join(TREE_DIR, 'grandchild-hold.cjs'), marker, '2000', '5000'],
    { cwd: WORKSPACE, timeoutMs: 500, signal: AbortSignal.timeout(60_000) },
  )
  const wallMs = Date.now() - startedAt
  assert.equal(result.timedOut, true, 'the budget kill happened')
  assert.equal(result.exitCode, null)
  // `close` only fires once the pipes are released — i.e. once the grandchild
  // died with the tree. A settle slower than the kill+grace means reclamation
  // regressed to the old hang (or its 5s deadline band-aid).
  assert.ok(wallMs < 5_000, `run() took ${wallMs}ms — a pipe-holding grandchild must not stall the result`)
  await new Promise((resolve) => setTimeout(resolve, 2_300))
  assert.equal(existsSync(marker), false,
    'the grandchild wrote its +2000ms liveness marker — it survived the 500ms kill; the process tree was not reclaimed')
})

test('NODE-PORTS: a child exiting under a pipe-holding grandchild settles by grace, not hang (H-18b)', async () => {
  // The child exits 0 voluntarily; the grandchild alone keeps the pipes open.
  // `close` cannot fire until the pipes are released — on POSIX nothing ever
  // kills that grandchild, on Windows the job object takes it down with the
  // child's exit. Both platforms must settle fast with the child's own exit
  // code; only the mechanism (grace deadline vs real EOF) differs.
  const port = new NodeCommandPort(250) // injectable grace: real deadline, no 5s sleep
  const marker = join(TREE_DIR, 'marker-a.txt')
  await fsp.rm(marker, { force: true })
  const startedAt = Date.now()
  const result = await port.run(
    [process.execPath, join(TREE_DIR, 'spawn-gc-exit0.cjs'),
      join(TREE_DIR, 'grandchild-hold.cjs'), marker, '700', '1500'],
    { cwd: WORKSPACE, timeoutMs: 20_000, signal: AbortSignal.timeout(60_000) },
  )
  const wallMs = Date.now() - startedAt
  assert.equal(result.exitCode, 0, 'the child exited 0 — whatever settled the result keeps that fact')
  assert.equal(result.aborted, false)
  if (process.platform === 'win32') {
    // Job-object semantics: the tree died with the child, real EOF arrived,
    // no forced settle should even be needed.
    assert.equal(result.spawnError, undefined, `win32: expected plain close, got spawnError ${result.spawnError}`)
    assert.ok(wallMs < 1_000, `win32 settle took ${wallMs}ms — the tree should die with the child`)
  } else {
    // POSIX: the grandchild survives (nothing kills it), EOF never arrives,
    // and the grace deadline settles with the exit facts plus a loud note.
    assert.match(result.spawnError ?? '', /stdio still open/,
      'the forced settle must say why there is no close')
    assert.ok(wallMs < 1_400,
      `POSIX settle took ${wallMs}ms — expected the 250ms grace deadline, not the grandchild's own exit at 1500ms`)
  }
  // Prove the mechanism did what the branch above claims: the grandchild's
  // +700ms marker exists only where it survived the child (POSIX), and must
  // NOT exist where the tree died with the child (win32).
  await new Promise((resolve) => setTimeout(resolve, process.platform === 'win32' ? 800 : 600))
  assert.equal(existsSync(marker), process.platform !== 'win32',
    process.platform === 'win32'
      ? 'win32: the grandchild must die with the tree (job object)'
      : 'POSIX: the grandchild outlives the child — it was the grace deadline, not EOF, that settled')
})

// -- truncated capture is stated in the record (B7-L1) -----------------------------

test('NODE-PORTS: a truncated capture ends with an explicit truncation marker (B7-L1)', async () => {
  const result = await commands.run(
    [process.execPath, '-e', "process.stdout.write('x'.repeat(70000))"],
    { cwd: WORKSPACE, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000), maxOutputChars: 1_000 },
  )
  assert.equal(result.exitCode, 0, result.output.slice(0, 200))
  assert.ok(result.output.startsWith('x'.repeat(1_000)), 'the head is kept verbatim')
  assert.match(result.output, /\n\[dsh-proof\] output truncated: kept 1000 of \d+ chars\s*$/,
    'the marker is the last line — truncation is a stated fact, not an implication of the cap')
})

// -- inherited NODE_V8_COVERAGE does not leak into children (B8-L2) -----------------

test('NODE-PORTS: an inherited NODE_V8_COVERAGE is stripped; an explicit overlay wins (B8-L2)', async () => {
  const read = async (env?: Record<string, string>): Promise<string> => {
    const result = await commands.run(
      [process.execPath, '-e', 'process.stdout.write(String(process.env.NODE_V8_COVERAGE))'],
      { cwd: WORKSPACE, timeoutMs: 10_000, signal: AbortSignal.timeout(10_000), ...(env === undefined ? {} : { env }) },
    )
    assert.equal(result.exitCode, 0, result.output.slice(0, 200))
    return result.output
  }
  const saved = process.env.NODE_V8_COVERAGE
  process.env.NODE_V8_COVERAGE = join(SCRATCH, 'host-coverage-leak')
  try {
    assert.equal(await read(undefined), 'undefined',
      'the host process being instrumented must not leak its coverage dir into every check/git child')
    // Absolute, like the runner's real staging dir (Node resolves a relative
    // NODE_V8_COVERAGE against the child's cwd and normalises the absolute
    // form to native separators — compare against the resolved path).
    const runnerStaging = join(SCRATCH, 'runner-staging')
    assert.equal(await read({ NODE_V8_COVERAGE: runnerStaging }), runnerStaging,
      'the runner deliberate per-run injection (options.env) stays authoritative')
  } finally {
    if (saved === undefined) delete process.env.NODE_V8_COVERAGE
    else process.env.NODE_V8_COVERAGE = saved
  }
})

// -- appendLine refuses redirected log paths (M-31) ---------------------------------

test('FS: appendLine appends to a regular file and refuses a redirected log path (M-31)', async () => {
  const fs = new NodeFsPort()
  const dir = join(SCRATCH, `node-ports-append-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(dir, { recursive: true })
  try {
    const log = join(dir, 'evidence.jsonl')
    await fs.appendLine(log, '{"v":1}')
    await fs.appendLine(log, '{"v":2}')
    assert.deepEqual(await fs.readLines(log), ['{"v":1}', '{"v":2}'], 'the happy path is untouched')

    // A directory where the log should be: refused loudly by the guard itself
    // (deterministic on every platform), not by an OS EISDIR at append time.
    const sub = join(dir, 'sub')
    await fsp.mkdir(sub, { recursive: true })
    await assert.rejects(fs.appendLine(sub, 'x'), /not a regular file \(directory\)/)

    // The M-31 shape: a symlink where the log lives must not redirect
    // host-side appends into an arbitrary victim. Creating one needs
    // privileges some Windows hosts do not grant — where the OS refuses,
    // skip (the directory case above already pins the lstat guard).
    const victim = join(dir, 'victim.txt')
    const linkedLog = join(dir, 'linked.jsonl')
    try {
      await fsp.symlink(victim, linkedLog)
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'EPERM' || code === 'EACCES') return
      throw error
    }
    await assert.rejects(fs.appendLine(linkedLog, 'x'), /not a regular file \(symlink\)/)
    assert.equal(existsSync(victim), false, 'the file on the other side of the link stays untouched')
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

// -- the signer public half cannot tear, drift, or get swapped (M-83) ---------------

test('SIGNER: a public half that does not match the private key is repaired; keyId stays stable (M-83)', async () => {
  const dir = join(SCRATCH, `node-ports-signer2-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  try {
    const first = await NodeEd25519Signer.load(dir)
    const originalPublic = await fsp.readFile(join(dir, 'proof-signing-key.pub.pem'), 'utf8')

    // Torn first write: half a PEM on disk (the old bug drifted keyId to the
    // sha256 of the torn bytes and made every verify() throw → false).
    await fsp.writeFile(join(dir, 'proof-signing-key.pub.pem'), originalPublic.slice(0, 30), 'utf8')
    let repaired = await NodeEd25519Signer.load(dir)
    assert.equal(repaired.keyId, first.keyId, 'a torn public half must not drift the keyId')
    assert.equal(await fsp.readFile(join(dir, 'proof-signing-key.pub.pem'), 'utf8'), originalPublic,
      'the public file is restored from the authoritative private half')

    // Swapped for ANOTHER pair's valid public key entirely.
    const stranger = generateKeyPairSync('ed25519').publicKey
      .export({ type: 'spki', format: 'pem' }) as string
    await fsp.writeFile(join(dir, 'proof-signing-key.pub.pem'), stranger, 'utf8')
    repaired = await NodeEd25519Signer.load(dir)
    assert.equal(repaired.keyId, first.keyId, 'a swapped public half must not take effect')
    assert.equal(await fsp.readFile(join(dir, 'proof-signing-key.pub.pem'), 'utf8'), originalPublic,
      'the stranger PEM is replaced with the true public half')

    // The repaired pair still works end to end (the load self-test already
    // ran a sign+verify round-trip; prove it against the ORIGINAL instance too).
    const signature = await repaired.sign('payload')
    assert.equal(await first.verify('payload', signature), true)
    assert.equal(await repaired.verify('payload', signature), true)

    // Atomic (re)writes leave no temp residue.
    assert.deepEqual((await fsp.readdir(dir)).filter((name) => name.endsWith('.tmp')), [])
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

// -- gitHead: "no commit" vs "no answer" (B8-L1) -------------------------------------

test('GIT: gitHead keeps "no commit" as null but REJECTS a query that produced no answer (B8-L1)', async () => {
  // The pre-fix bug: a timeout/spawn-failure HEAD query resolved null —
  // indistinguishable from an unborn branch — so changedSince was silently
  // skipped and committed changes vanished from change sets with no degraded
  // flag anywhere. Now the no-answer shapes reject (the engine's existing
  // git-blind path turns that into a forced full run); only an ANSWERED
  // non-zero exit stays the legitimate null.
  const timedOut: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: null, output: '', durationMs: 5_000, aborted: false,
      spawnError: 'timed out after 5000ms', timedOut: true,
    }),
  }
  await assert.rejects(
    new GitWorkspace(GIT_ROOT, timedOut).gitHead(),
    /rev-parse HEAD[^]*produced no answer[^]*timed out/,
  )

  const neverRan: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: null, output: '', durationMs: 0, aborted: false, spawnError: 'spawn failed: ENOENT',
    }),
  }
  await assert.rejects(
    new GitWorkspace(GIT_ROOT, neverRan).gitHead(),
    /produced no answer[^]*spawn failed: ENOENT/,
  )

  const unborn: CommandPort = {
    run: async (): Promise<CommandResult> => ({
      exitCode: 128, output: "fatal: ambiguous argument 'HEAD': unknown revision\n", durationMs: 1, aborted: false,
    }),
  }
  assert.equal(await new GitWorkspace(GIT_ROOT, unborn).gitHead(), null,
    'an answered non-zero exit is the legitimate "no commit yet"')
})

// -- answer-less availability probes get exactly one retry (B8-L4) ------------------

test('GIT: an answer-less availability probe is retried once, then believed (B8-L4)', async () => {
  // First probe times out (AV scanner warming git.exe), second answers true:
  // the transient failure must not be memoized as "no git for the session".
  let probes = 0
  const transient: CommandPort = {
    run: async (): Promise<CommandResult> => {
      probes += 1
      return probes === 1
        ? { exitCode: null, output: '', durationMs: 5_000, aborted: false, spawnError: 'timed out after 5000ms', timedOut: true }
        : { exitCode: 0, output: 'true\n', durationMs: 1, aborted: false }
    },
  }
  const ws = new GitWorkspace(GIT_ROOT, transient)
  assert.equal(await ws.gitAvailable(), false, 'a probe that produced no answer is not an availability proof')
  assert.equal(await ws.gitAvailable(), true, '…nor proof of absence — one in-session re-probe flips it')
  assert.equal(await ws.gitAvailable(), true, 'definitive answers are final')
  assert.equal(probes, 2)

  // A probe that stays answer-less is believed after the single retry — a
  // stuck probe must not burn its 5s timeout on every call.
  let stuckProbes = 0
  const alwaysStuck: CommandPort = {
    run: async (): Promise<CommandResult> => {
      stuckProbes += 1
      return { exitCode: null, output: '', durationMs: 5_000, aborted: false, spawnError: 'timed out after 5000ms', timedOut: true }
    },
  }
  const stuck = new GitWorkspace(GIT_ROOT, alwaysStuck)
  assert.equal(await stuck.gitAvailable(), false)
  assert.equal(await stuck.gitAvailable(), false)
  assert.equal(await stuck.gitAvailable(), false)
  assert.equal(stuckProbes, 2, 'exactly one retry, never more')
})

// -- changedSince ends its revision list with `--` (B8-L5) ---------------------------

test('GIT: changedSince separates the ref from pathspecs with "--" (B8-L5)', async () => {
  let seen: readonly string[] = []
  const recording: CommandPort = {
    run: async (argv): Promise<CommandResult> => {
      if (argv.includes('diff')) {
        seen = [...argv]
        return { exitCode: 0, output: 'keep.ts\0', durationMs: 1, aborted: false }
      }
      return { exitCode: 0, output: '', durationMs: 1, aborted: false }
    },
  }
  await new GitWorkspace(GIT_ROOT, recording).changedSince('HEAD')
  assert.deepEqual(seen, ['git', 'diff', '--name-only', '-z', 'HEAD', '--'],
    'a ref beginning with "-" must never be parseable as a git option')
  // The separator changes nothing on the real repository.
  assert.ok((await new GitWorkspace(GIT_ROOT).changedSince('HEAD')).includes('keep.ts'))
})

// -- V8-L3: MemoryFs fidelity with the production port's directory semantics ----------

test('V8-L3: MemoryFs.readDir answers [] for an existing-but-empty dir and undefined for no dir — same as NodeFsPort', async () => {
  // The production port (fsp.readdir) answers [] for a directory that exists
  // and holds nothing, and undefined (via the catch) only for a path that is
  // not a directory at all; the fake used to fold both into undefined, so
  // "exists, empty" was unexpressible in tests. Real-port parity is asserted
  // against an actual empty directory on the real filesystem.
  const realDir = join(SCRATCH, `node-ports-emptydir-${process.pid}`)
  await fsp.rm(realDir, { recursive: true, force: true })
  await fsp.mkdir(realDir, { recursive: true })
  try {
    const real = new NodeFsPort()
    assert.deepEqual(await real.readDir(realDir), [], 'production: exists-but-empty answers []')

    const fake = new MemoryFs()
    assert.equal(await fake.readDir('/ws/never-made'), undefined, 'fake: a path with no files and no mkdirp is not a directory')
    await fake.mkdirp('/ws/empty')
    assert.deepEqual(await fake.readDir('/ws/empty'), [], 'fake: an explicitly created empty dir answers [] (production parity)')
    await fake.writeFile('/ws/full/a.txt', 'a')
    await fake.writeFile('/ws/full/sub/b.txt', 'b')
    assert.deepEqual(await fake.readDir('/ws/full'), ['a.txt', 'sub'], 'fake: names only, sorted, directories included as names')

    // removeDir — the optional τ capability, mirroring NodeFsPort.removeDir:
    // deletes the whole subtree, best-effort, never throws.
    assert.equal(typeof fake.removeDir, 'function', 'the fake implements the optional capability')
    await fake.removeDir('/ws/full')
    assert.equal(await fake.readFile('/ws/full/a.txt'), undefined, 'the tree is gone')
    assert.equal(await fake.readFile('/ws/full/sub/b.txt'), undefined)
    assert.equal(await fake.readDir('/ws/full'), undefined, 'an implicitly-existing dir with no files left is no longer one')

    // Cross-port parity for removeDir on the real filesystem.
    await fsp.mkdir(join(realDir, 'nested'), { recursive: true })
    await fsp.writeFile(join(realDir, 'nested', 'x.txt'), 'x', 'utf8')
    await real.removeDir(realDir)
    assert.equal(existsSync(realDir), false, 'production removeDir takes the tree down')
  } finally {
    await fsp.rm(realDir, { recursive: true, force: true })
  }
})
