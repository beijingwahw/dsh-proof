import { test } from 'node:test'
import assert from 'node:assert/strict'

import { checkId, discoverChecks } from '../src/core/checks.ts'
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

test('a workspace with no build metadata yields no checks', async () => {
  const fs = MemoryFs.of({ '/ws/README.md': '# hi' })
  assert.deepEqual(await discoverChecks(fs, '/ws'), [])
})

test('checks inherit the configured timeout', async () => {
  const fs = MemoryFs.of({ '/ws/package.json': JSON.stringify({ scripts: { test: 'x' } }) })
  const checks = await discoverChecks(fs, '/ws', { timeoutMs: 777 })
  assert.equal(checks[0]?.timeoutMs, 777)
})
