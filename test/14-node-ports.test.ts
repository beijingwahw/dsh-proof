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
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { GitWorkspace, NodeCommandPort, NodeEd25519Signer, NodeFsPort, parsePorcelainZ, resolveCmdShim } from '../src/node-ports.ts'
import type { CommandPort, CommandResult } from '../src/core/ports.ts'

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
})

after(async () => {
  await fsp.rm(GIT_ROOT, { recursive: true, force: true })
  await fsp.rm(SHIM_ROOT, { recursive: true, force: true })
  await fsp.rm(ATOMIC_DIR, { recursive: true, force: true })
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
