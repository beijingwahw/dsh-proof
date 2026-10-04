import { test } from 'node:test'
import assert from 'node:assert/strict'

import { WorkspaceWatch, driftNarrative } from '../src/dsh/observe.ts'
import { MemoryFs } from './helpers.ts'

const ROOT = '/ws'

function exec(name: string, args: unknown) {
  return {
    callId: 'c1', rootCallId: 'c1', name, arguments: args,
    token: Symbol('t'), signal: new AbortController().signal,
  } as never
}

const OK = { isError: false, value: null, content: [] } as never

test('pathsIn extracts file arguments from nested shapes', () => {
  const found = WorkspaceWatch.pathsIn({
    path: 'src/a.ts',
    files: ['src/b.ts', 'src/c.ts'],
    nested: { file_path: 'src/d.ts' },
    note: 'not a path',
  })
  assert.deepEqual(found.sort(), ['src/a.ts', 'src/b.ts', 'src/c.ts', 'src/d.ts'])
})

test('pathsIn ignores values that cannot be paths', () => {
  assert.deepEqual(WorkspaceWatch.pathsIn({ note: 'hello world', count: 3 }), [])
  assert.deepEqual(WorkspaceWatch.pathsIn(null), [])
})

test('a tool write is "touched", a tool read is not', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)

  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  assert.deepEqual(watch.touchedPaths(), [], 'reads do not count as mutations')

  await watch.observe(exec('write', { path: 'src/b.ts', content: 'v1\n' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['src/b.ts'])
})

test('DRIFT: a file changed outside the tool stream is detected as stale', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)

  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  const clean = await watch.detectDrift()
  assert.deepEqual(clean.drifted, [])
  assert.deepEqual(clean.staleReads, [])

  // The user edits the file in their IDE.
  fs.mutate(`${ROOT}/src/a.ts`, 'v2 — the user rewrote this\n')
  const dirty = await watch.detectDrift()
  assert.deepEqual(dirty.drifted, ['src/a.ts'])
  assert.deepEqual(dirty.staleReads, ['src/a.ts'], 'the agent has a stale copy in context')
})

test('a change made through a tool is NOT drift', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  await watch.observe(exec('write', { path: 'src/a.ts', content: 'v2\n' }), OK)
  const result = await watch.detectDrift()
  assert.deepEqual(result.drifted, [])
  assert.deepEqual(result.touched, ['src/a.ts'])
})

test('a file that vanishes is drift', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  fs.files.delete(`${ROOT}/src/a.ts`)
  const result = await watch.detectDrift()
  assert.deepEqual(result.drifted, ['src/a.ts'])
})

test('an absolute path outside the workspace is ignored', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('read_file', { path: '/etc/passwd' }), OK)
  assert.deepEqual(watch.touchedPaths(), [])
  const result = await watch.detectDrift(['/etc/passwd'])
  assert.deepEqual(result.drifted, [])
})

test('windowStart clears the touched set without losing fingerprints', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('write', { path: 'src/a.ts', content: 'v1\n' }), OK)
  watch.windowStart()
  assert.deepEqual(watch.touchedPaths(), [])
  // The next external edit must still be detected.
  fs.mutate(`${ROOT}/src/a.ts`, 'v2\n')
  assert.deepEqual((await watch.detectDrift()).drifted, ['src/a.ts'])
})

test('driftNarrative is silent when nothing drifted', () => {
  assert.equal(driftNarrative({ drifted: [], touched: [], staleReads: [], scanned: 0 }), undefined)
})

test('driftNarrative names stale reads first and tells the model what to do', () => {
  const text = driftNarrative({
    drifted: ['src/a.ts', 'src/b.ts'],
    touched: [],
    staleReads: ['src/a.ts'],
    scanned: 2,
  })
  assert.ok(text)
  assert.match(text ?? '', /stale/i)
  assert.match(text ?? '', /src\/a\.ts/)
  assert.match(text ?? '', /src\/b\.ts/)
  assert.match(text ?? '', /proof_verify/)
})
