import { test } from 'node:test'
import assert from 'node:assert/strict'

import { checkId, discoverChecks } from '../src/core/checks.ts'
import { sha256 } from '../src/core/hash.ts'
import { MemoryFs } from './helpers.ts'

test('discovers npm scripts by kind, skipping pre/post hooks', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({
      name: 'demo',
      scripts: {
        build: 'tsc -b',
        test: 'vitest run',
        typecheck: 'tsc --noEmit',
        lint: 'eslint .',
        prettier: 'prettier -c .',
        pretest: 'echo warm',
        posttest: 'echo cool',
        dev: 'vite',
      },
    }),
    '/ws/src/index.ts': 'export const x = 1\n',
  })
  const checks = await discoverChecks(fs, '/ws')
  const labels = checks.map(c => c.label).sort()
  assert.deepEqual(labels, ['npm script "build"', 'npm script "lint"', 'npm script "test"', 'npm script "typecheck"'])
  assert.ok(!labels.some(l => l.includes('pretest')))
  assert.ok(checks.every(c => c.command[0] === 'npm'))
})

test('explicit checks always win and exclusive disables discovery', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ scripts: { test: 'vitest run' } }),
  })
  const merged = await discoverChecks(fs, '/ws', {
    checks: [{ label: 'custom', command: ['make', 'verify'], kind: 'test' }],
  })
  assert.equal(merged.length, 2)

  const exclusive = await discoverChecks(fs, '/ws', {
    checks: [{ label: 'custom', command: ['make', 'verify'], exclusive: true }],
  })
  assert.equal(exclusive.length, 1)
  assert.equal(exclusive[0]?.label, 'custom')
})

test('config and discovery of the same invocation collapse: config wins, different commands coexist', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ scripts: { test: 'vitest run', build: 'tsc -b' } }),
  })
  const checks = await discoverChecks(fs, '/ws', {
    checks: [{ label: 'my tests', command: 'npm run --silent test' }],
  })
  // `npm run --silent test` is both configured and discoverable; ids differ
  // (source is part of the material) but the script is one invocation — it
  // must surface exactly once, as the config entry (user intent overrides
  // machine inference), while unrelated commands keep their discovery.
  const same = checks.filter(c => c.command.join(' ') === 'npm run --silent test')
  assert.equal(same.length, 1, `one invocation must mean one check, got ${JSON.stringify(checks.map(c => c.label))}`)
  assert.equal(same[0]?.source, 'config')
  assert.equal(same[0]?.label, 'my tests')
  assert.ok(
    checks.some(c => c.source === 'package.json' && c.label === 'npm script "build"'),
    'commands the config does not cover are unaffected',
  )
})

test('discovers python, go, rust and make checks', async () => {
  const fs = MemoryFs.of({
    '/ws/pyproject.toml': '[tool.pytest.ini_options]\n[tool.mypy]\n[tool.ruff]\n',
    '/ws/go.mod': 'module example.com/x\n',
    '/ws/Cargo.toml': '[package]\nname="x"\n',
    '/ws/Makefile': 'test:\n\tnpm test\nbuild:\n\ntarget:\n',
    '/ws/requirements.txt': 'pytest\n',
  })
  const checks = await discoverChecks(fs, '/ws')
  const labels = checks.map(c => c.label).sort()
  for (const expected of ['cargo check', 'cargo test', 'go build', 'go test', 'go vet', 'make build', 'make test', 'mypy', 'pytest', 'ruff check']) {
    assert.ok(labels.includes(expected), `missing ${expected} in ${labels.join(', ')}`)
  }
  assert.ok(!labels.includes('make target'), 'unrecognised make targets must not become checks')
})

test('check ids are stable and command-sensitive', () => {
  assert.equal(checkId('config', ['a', 'b']), checkId('config', ['a', 'b']))
  assert.notEqual(checkId('config', ['a', 'b']), checkId('config', ['a', 'c']))
  assert.notEqual(checkId('config', ['a']), checkId('package.json', ['a']))
})

test('checkId without cwd is byte-identical to the legacy format', () => {
  // Locked literally: the material is exactly `command.join('\0')` under
  // sha256, truncated to 12 hex chars. Baselines minted before `cwd` existed
  // must keep addressing, so any drift here is a breaking change.
  assert.equal(checkId('config', ['a', 'b']), 'config:59b271ae1bbc')
  assert.equal(checkId('config', ['a', 'b'], undefined), 'config:59b271ae1bbc')
  // A cwd joins the material and separates same-argv monorepo siblings.
  assert.equal(checkId('config', ['a', 'b'], 'packages/a'), 'config:3364fe166591')
  assert.notEqual(checkId('config', ['a', 'b'], 'packages/a'), checkId('config', ['a', 'b'], 'packages/b'))
  assert.notEqual(checkId('config', ['a', 'b'], 'packages/a'), checkId('config', ['a', 'b']))
})

const MONOREPO: Record<string, string> = {
  '/ws/package.json': JSON.stringify({
    name: 'root',
    scripts: { test: 'vitest run' },
    workspaces: ['packages/*'],
  }),
  '/ws/packages/a/package.json': JSON.stringify({ name: '@demo/a', scripts: { test: 'node test.js' } }),
  '/ws/packages/b/package.json': JSON.stringify({ name: '@demo/b', scripts: { test: 'node test.js', build: 'tsc -b' } }),
  '/ws/packages/b/README.md': 'not a workspace member on its own',
}

test('monorepo: glob workspaces discover subpackage scripts with distinct ids', async () => {
  const checks = await discoverChecks(MemoryFs.of(MONOREPO), '/ws')
  const labels = checks.map(c => c.label)
  assert.ok(labels.includes('npm script "test"'), 'root test survives')
  assert.ok(labels.includes('npm script "test" (packages/a)'), `got ${labels.join(', ')}`)
  assert.ok(labels.includes('npm script "test" (packages/b)'))
  assert.ok(labels.includes('npm script "build" (packages/b)'))

  // Root and subpackages share the argv for `test` (npm run --silent test);
  // only distinct ids keep them from deduping into one invisible check.
  const testIds = checks.filter(c => c.label.includes('test')).map(c => c.id)
  assert.equal(new Set(testIds).size, testIds.length, 'same argv in different packages must not collide')

  const sub = checks.find(c => c.label === 'npm script "test" (packages/a)')
  assert.equal(sub?.cwd, 'packages/a')
  assert.deepEqual(sub?.paths, ['packages/a/**'])
  assert.deepEqual(sub?.command, ['npm', 'run', '--silent', 'test'])
  const root = checks.find(c => c.label === 'npm script "test"')
  assert.equal(root?.cwd, undefined, 'root checks stay root-scoped')
})

test('monorepo: literal workspace directories discover subpackages too', async () => {
  const fs = MemoryFs.of({
    ...MONOREPO,
    '/ws/package.json': JSON.stringify({
      name: 'root',
      scripts: { test: 'vitest run' },
      workspaces: ['packages/a', 'packages/b'],
    }),
  })
  const checks = await discoverChecks(fs, '/ws')
  assert.deepEqual(
    checks.filter(c => c.cwd !== undefined).map(c => c.cwd).sort(),
    ['packages/a', 'packages/b', 'packages/b'],
    'a:test, b:test and b:build — one cwd-bearing check each',
  )
})

test('pre/post prefixes only hide scripts whose base name is also a script', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({
      scripts: {
        test: 'vitest run',
        pretest: 'echo warm', // base `test` exists -> npm lifecycle hook
        posttest: 'echo cool', // base `test` exists -> npm lifecycle hook
        prettier: 'prettier -c .', // base `ttier` is not a script -> ordinary
        postcss: 'postcss build', // base `css` is not a script -> ordinary
      },
    }),
  })
  const checks = await discoverChecks(fs, '/ws', {
    scriptKinds: { test: 'test', pretest: 'other', posttest: 'other', prettier: 'lint', postcss: 'build' },
  })
  const labels = checks.map(c => c.label).sort()
  assert.deepEqual(labels, ['npm script "postcss"', 'npm script "prettier"', 'npm script "test"'])
})

test('tox.ini is its own source; pytest.ini alone still discovers pytest', async () => {
  const toxOnly = await discoverChecks(MemoryFs.of({ '/ws/tox.ini': '[tox]\nenvlist = py\n' }), '/ws')
  assert.equal(toxOnly.length, 1)
  assert.equal(toxOnly[0]?.source, 'tox.ini')
  assert.ok(toxOnly[0]?.id.startsWith('tox.ini:'), 'id derives from the honest source')

  const pytestIniOnly = await discoverChecks(MemoryFs.of({ '/ws/pytest.ini': '[pytest]\n' }), '/ws')
  assert.deepEqual(pytestIniOnly.map(c => c.label), ['pytest'], 'pytest.ini without pyproject.toml is not invisible')
})

test('a workspace with no build metadata yields no checks', async () => {
  const fs = MemoryFs.of({ '/ws/README.md': '# hi' })
  assert.deepEqual(await discoverChecks(fs, '/ws'), [])
})

test('checks inherit the configured timeout', async () => {
  const fs = MemoryFs.of({ '/ws/package.json': JSON.stringify({ scripts: { test: 'x' } }) })
  const checks = await discoverChecks(fs, '/ws', { timeoutMs: 777 })
  assert.equal(checks[0]?.timeoutMs, 777)
})

test('B6-L3: a quoted config command string splits shell-words style, not on raw whitespace', () => {
  // `pytest -k "foo bar"` used to shred into [..., '"foo', 'bar"'] — quote
  // fragments riding into argv, the label AND the checkId material.
  return (async () => {
    const fs = MemoryFs.of({})
    const quoted = await discoverChecks(fs, '/ws', { checks: [{ label: 't', command: 'pytest -k "foo bar"' }] })
    assert.deepEqual(quoted[0]?.command, ['pytest', '-k', 'foo bar'])
    const single = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: "eslint 'src/**/*.{ts,tsx}' --max-warnings 0" }] })
    assert.deepEqual(single[0]?.command, ['eslint', 'src/**/*.{ts,tsx}', '--max-warnings', '0'])
    // Quote-free strings are byte-identical to the legacy splitter, so every
    // existing id stays put (the compatibility red line).
    const plain = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: 'make   all ' }] })
    assert.deepEqual(plain[0]?.command, ['make', 'all'])
    // An unterminated quote keeps the rest as one token — never an invented
    // split the author did not write.
    const open = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: "echo 'unclosed argument" }] })
    assert.deepEqual(open[0]?.command, ['echo', 'unclosed argument'])
    // Array commands pass through untouched.
    const arr = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: ['a', 'b c'] }] })
    assert.deepEqual(arr[0]?.command, ['a', 'b c'])
  })()
})

test('W14-L8: single quotes have no escapes (POSIX); outside-quote backslashes are literal (documented choice)', () => {
  return (async () => {
    // POSIX: inside '…' every character is literal, backslash included, and
    // only a bare quote closes. The old reader unescaped \' there.
    const fs0 = MemoryFs.of({})
    const literalBackslash = await discoverChecks(fs0, '/ws', { checks: [{ label: 't', command: "echo 'a\\'" }] })
    assert.deepEqual(literalBackslash[0]?.command, ['echo', 'a\\'], "the backslash is content and the bare quote closes — 'a\\'")
    const inner = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: "echo 'it\\'s'" }] })
    assert.deepEqual(inner[0]?.command, ['echo', 'it\\s'], 'close at the bare quote, then the rest reopens and runs to end')
    // Double quotes still unescape \" (the common shell reading, unchanged).
    const dq = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: 'echo "a\\"b"' }] })
    assert.deepEqual(dq[0]?.command, ['echo', 'a"b'])
    // Outside quotes a backslash stays LITERAL: Windows paths survive
    // (`C:\ws\bin\tool` would be shredded to `C:wsbintool` under POSIX
    // escaping) — the documented deviation, pinned here.
    const win = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: 'C:\\ws\\bin\\tool --flag' }] })
    assert.deepEqual(win[0]?.command, ['C:\\ws\\bin\\tool', '--flag'])
  })()
})

test('W14-L10: a non-finite timeoutMs is refused loudly, not passed through the ?? gate', async () => {
  // `NaN ?? fallback` is NaN — ?? only catches null/undefined — so an
  // explicit NaN used to ride the spec into the runner (the same hole H-33
  // sealed at the excerpt layer). Refuse at both spellings.
  await assert.rejects(
    discoverChecks(MemoryFs.of({}), '/ws', { timeoutMs: Number.NaN }),
    /timeoutMs must be a finite number of milliseconds/,
  )
  await assert.rejects(
    discoverChecks(MemoryFs.of({}), '/ws', { timeoutMs: Number.POSITIVE_INFINITY }),
    /timeoutMs must be a finite number of milliseconds/,
  )
  await assert.rejects(
    discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: ['x'], timeoutMs: Number.NaN }] }),
    /timeoutMs must be a finite number of milliseconds/,
  )
  // Legal values are untouched — including 0/negative, which stay the
  // caller's policy (the gate is about non-finite delivery, not taste).
  const zero = await discoverChecks(MemoryFs.of({}), '/ws', { checks: [{ label: 't', command: ['x'], timeoutMs: 0 }] })
  assert.equal(zero[0]?.timeoutMs, 0)
})

test('B6-L4: perf script names are not promoted to benchmark checks by name alone', () => {
  return (async () => {
    // A script merely NAMED bench/benchmark/perf:bench is usually a
    // long-running local helper; name-key discovery used to promote it to a
    // must-pass benchmark check under the default 120s timeout — a red check
    // the project never opted into. The default name map stays test/verify
    // semantics only; perf coverage arrives via explicit config.
    const fs = MemoryFs.of({
      '/ws/package.json': JSON.stringify({ scripts: { test: 'vitest run', bench: 'autocannon table', benchmark: 'hyperfine' } }),
    })
    const checks = await discoverChecks(fs, '/ws')
    assert.deepEqual(checks.map(c => c.label), ['npm script "test"'], 'no name-keyed benchmark promotion')

    // The opt-in still works: explicit config with kind benchmark, or a
    // scriptKinds override, is where perf evidence comes from.
    const withKind = await discoverChecks(MemoryFs.of({ '/ws/package.json': JSON.stringify({ scripts: { bench: 'hyperfine' } }) }), '/ws', {
      checks: [{ label: 'perf', command: ['node', 'bench/run.ts'], kind: 'benchmark' }],
    })
    assert.equal(withKind.find(c => c.label === 'perf')?.kind, 'benchmark')
    const overridden = await discoverChecks(fs, '/ws', { scriptKinds: { bench: 'benchmark' } })
    assert.equal(overridden.find(c => c.label === 'npm script "bench"')?.kind, 'benchmark')
  })()
})

// ---------------------------------------------------------------------------
// scriptDigest (H5a) — the discovery half of check-definition drift.
//
// A checkId pins source+command+cwd, so `"test": "vitest run"` and
// `"test": "exit 0"` mint the SAME id: after a baseline, an agent could gut a
// script and keep its full-confidence identity. The digest on the spec is the
// discovery layer's answer — same id, provably different body. It must never
// leak into the id (byte-compat red line above) nor into the evidence payload.
// ---------------------------------------------------------------------------

test('a discovered npm script carries scriptDigest: the sha256 of its body, recomputed independently', async () => {
  const body = 'vitest run --coverage'
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ scripts: { test: body } }),
  })
  const checks = await discoverChecks(fs, '/ws')
  const test = checks.find(c => c.label === 'npm script "test"')
  assert.equal(test?.scriptDigest, sha256(body), 'the digest is exactly the script text, verbatim')
})

test('monorepo member scripts digest their own bodies, not the root\u2019s', async () => {
  const checks = await discoverChecks(MemoryFs.of(MONOREPO), '/ws')
  const sub = checks.find(c => c.label === 'npm script "test" (packages/a)')
  const root = checks.find(c => c.label === 'npm script "test"')
  assert.equal(sub?.scriptDigest, sha256('node test.js'), 'the member digest is the member body')
  assert.equal(root?.scriptDigest, sha256('vitest run'), 'the root digest is the root body')
  assert.notEqual(sub?.scriptDigest, root?.scriptDigest)
})

test('rewriting the script body moves the digest and leaves the id alone — identity theft made visible', async () => {
  const fixture = (body: string) => MemoryFs.of({
    '/ws/package.json': JSON.stringify({ scripts: { test: body } }),
  })
  const before = (await discoverChecks(fixture('vitest run'), '/ws')).find(c => c.label === 'npm script "test"')
  const after = (await discoverChecks(fixture('exit 0'), '/ws')).find(c => c.label === 'npm script "test"')
  // The id is unchanged (same source, argv and cwd — baselines keep
  // addressing), the digest is not: the drift is now detectable on the spec.
  assert.equal(after?.id, before?.id, 'checkId material never included the body')
  assert.equal(after?.scriptDigest, sha256('exit 0'))
  assert.notEqual(after?.scriptDigest, before?.scriptDigest)
})

test('config entries and python/make checks leave scriptDigest undefined — those bodies are not enumerable', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ scripts: { test: 'vitest run' } }),
    '/ws/pyproject.toml': '[tool.pytest.ini_options]\n',
    '/ws/Makefile': 'test:\n\tnpm test\n',
  })
  const checks = await discoverChecks(fs, '/ws', {
    checks: [{ label: 'custom', command: ['make', 'verify'], kind: 'test' }],
  })
  const config = checks.find(c => c.source === 'config')
  assert.equal(config?.scriptDigest, undefined, 'explicit config has no script body to digest')
  for (const c of checks.filter(x => x.source !== 'package.json')) {
    assert.equal(c.scriptDigest, undefined, `${c.source}:${c.label} must stay digest-free`)
  }
  const npm = checks.find(c => c.source === 'package.json')
  assert.equal(npm?.scriptDigest, sha256('vitest run'), 'only the npm script carries its body')
})

test('a config entry shadowing a discovered script keeps the dedupe: one survivor, no digest', async () => {
  // Same invocation (command+cwd) still collapses config-first — the digest
  // must not become a back door to resurrect the displaced discovery as a
  // second check, and the surviving config spec carries no digest.
  const fs = MemoryFs.of({ '/ws/package.json': JSON.stringify({ scripts: { test: 'exit 0' } }) })
  const checks = await discoverChecks(fs, '/ws', {
    checks: [{ label: 'my tests', command: 'npm run --silent test' }],
  })
  const same = checks.filter(c => c.command.join(' ') === 'npm run --silent test')
  assert.equal(same.length, 1, 'dedupe key is command+cwd, unchanged by the digest')
  assert.equal(same[0]?.source, 'config')
  assert.equal(same[0]?.scriptDigest, undefined)
})
