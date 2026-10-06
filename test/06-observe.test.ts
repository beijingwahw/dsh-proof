import { test } from 'node:test'
import assert from 'node:assert/strict'

import { WorkspaceWatch, driftNarrative, isMutationToolName, MUTATION_TOOL_RE, SHELL_TOOL_RE, toWorkspaceRelative } from '../src/dsh/observe.ts'
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

// ---------------------------------------------------------------------------
// `source` is content, not a path (T4): search/replace tools pass the old text
// under `source`, and a snippet with a slash in it would otherwise be recorded
// as a touched path — charging the agent with an edit it never made.
// ---------------------------------------------------------------------------

test('a `source` argument holding content is not mistaken for a path', async () => {
  // 'src/old/text' is the shape that used to leak through: a code snippet
  // containing slashes passes looksLikePath with room to spare.
  assert.deepEqual(WorkspaceWatch.pathsIn({ source: 'src/old/text' }), [])

  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('str_replace', { path: 'src/a.ts', source: 'src/old/text' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['src/a.ts'], 'only the path key names a file')
  assert.deepEqual(watch.sessionTouchedPaths(), ['src/a.ts'], 'content keys must not enter the provenance set')
})

test('a tool write is "touched", a tool read is not', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)

  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  assert.deepEqual(watch.touchedPaths(), [], 'reads do not count as mutations')

  await watch.observe(exec('write', { path: 'src/b.ts', content: 'v1\n' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['src/b.ts'])
})

// ---------------------------------------------------------------------------
// Single-source classification (T3): the mutation/shell patterns are exported
// from observe.ts and both adapter layers must consult the same one. Unknown
// tools stay classified as mutations — the conservative direction.
// ---------------------------------------------------------------------------

test('isMutationToolName is the one classification the adapter exports', () => {
  for (const name of ['write', 'edit_file', 'apply_patch', 'create_thing', 'bash', 'npm', 'run_command', 'DELETE_FILE']) {
    assert.ok(isMutationToolName(name), `${name} mutates workspace state`)
  }
  for (const name of ['read', 'read_file', 'grep', 'find', 'head', 'tail', 'view', 'glob']) {
    assert.ok(!isMutationToolName(name), `${name} only reads`)
  }
  // The exported patterns are the contract; both layers import these symbols.
  assert.ok(MUTATION_TOOL_RE.test('mkdir'), 'a mutation verb matches')
  assert.ok(SHELL_TOOL_RE.test('pnpm'), 'a shell runner matches')
  assert.ok(!SHELL_TOOL_RE.test('pnpm_audit_logs'), 'the shell pattern is anchored, not a substring sniff')
})

test('classification: regex-named mutations touch, whitelist names read, unknowns default to mutation', async () => {
  const fs = MemoryFs.of({
    [`${ROOT}/src/a.ts`]: 'v1\n',
    [`${ROOT}/src/b.ts`]: 'v1\n',
    [`${ROOT}/src/c.ts`]: 'v1\n',
    [`${ROOT}/src/d.ts`]: 'v1\n',
    [`${ROOT}/src/e.ts`]: 'v1\n',
  })
  const watch = new WorkspaceWatch(fs, ROOT)

  await watch.observe(exec('bash', { path: 'src/a.ts' }), OK)               // shell-classified -> touched
  await watch.observe(exec('find', { path: 'src/b.ts' }), OK)               // read whitelist
  await watch.observe(exec('mystery_analyzer', { path: 'src/c.ts' }), OK)   // unknown -> mutation (conservative)
  await watch.observe(exec('apply_patch', { target: 'src/d.ts' }), OK)      // mutation verb -> touched
  await watch.observe(exec('head', { file: 'src/e.ts' }), OK)               // read whitelist

  assert.deepEqual(watch.touchedPaths(), ['src/a.ts', 'src/c.ts', 'src/d.ts'])
  assert.deepEqual(watch.sessionTouchedPaths(), ['src/a.ts', 'src/c.ts', 'src/d.ts'])
})

test('a read-sounding name composed around a mutation verb still mutates', async () => {
  // The whitelist is an exact-name set consulted only after the pattern says
  // no: "show_update_log" may read like a viewer, but the `update` token makes
  // it a mutation. The pattern, not the whitelist, has the last word on
  // attribution.
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('show_update_log', { path: 'src/a.ts' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['src/a.ts'], 'the mutation verb inside the name classifies it as a mutation')
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

test('windows drive-letter absolute paths are recognised and land in touched', async () => {
  const fs = MemoryFs.of({ 'C:/ws/src/a.ts': 'v1\n' })
  const watch = new WorkspaceWatch(fs, 'C:/ws')

  await watch.observe(exec('write', { path: 'C:\\ws\\src\\a.ts', content: 'v2\n' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['src/a.ts'], 'a real agent edit must not be misattributed as external drift')
  assert.deepEqual(watch.sessionTouchedPaths(), ['src/a.ts'])
})

test('drive-letter case does not defeat root matching', async () => {
  const fs = MemoryFs.of({ 'c:/ws/src/a.ts': 'v1\n' })
  const watch = new WorkspaceWatch(fs, 'c:/ws')

  await watch.observe(exec('write', { path: 'C:/ws/src/a.ts', content: 'v2\n' }), OK)
  assert.deepEqual(watch.sessionTouchedPaths(), ['src/a.ts'], 'the host says c:/ws, the tool says C:/ws — same workspace')
})

test('a drive-letter path outside the workspace root is ignored', async () => {
  const fs = MemoryFs.of({ 'C:/ws/src/a.ts': 'v1\n' })
  const watch = new WorkspaceWatch(fs, 'C:/ws')

  await watch.observe(exec('write', { path: 'D:/elsewhere/src/a.ts', content: 'v2\n' }), OK)
  assert.deepEqual(watch.touchedPaths(), [])
  await watch.observe(exec('write', { path: 'C:/other/src/a.ts', content: 'v2\n' }), OK)
  assert.deepEqual(watch.touchedPaths(), [], 'same drive, different directory: still outside the root')
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

test('toWorkspaceRelative is the one path discipline for every flavour of input', () => {
  assert.equal(toWorkspaceRelative('/ws/src/a.ts', '/ws'), 'src/a.ts')
  assert.equal(toWorkspaceRelative('C:\\ws\\src\\a.ts', 'C:/ws'), 'src/a.ts', 'backslashes and slashes describe the same file')
  assert.equal(toWorkspaceRelative('C:/ws/src/a.ts', 'c:/ws/'), 'src/a.ts', 'drive case and trailing slash are not distinctions')
  assert.equal(toWorkspaceRelative('C:/elsewhere/a.ts', 'C:/ws'), undefined, 'absolute but outside the root')
  assert.equal(toWorkspaceRelative('/etc/passwd', 'C:/ws'), undefined, 'a POSIX path is never inside a drive root')
  assert.equal(toWorkspaceRelative('./src/a.ts', '/ws'), 'src/a.ts')
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

// ---------------------------------------------------------------------------
// H9a: arrays only carry paths when a path key names them. The old generic
// array branch collected every string in every array — a patch's line list,
// an argv vector, a `source` content array — which walked straight around the
// key whitelist this extractor exists to enforce (`{source: ['src/old/text']}`
// used to leak the snippet as a touched path, charging the agent with an edit
// it never made).
// ---------------------------------------------------------------------------

test('H9a: a bare array under a non-path key contributes no paths', () => {
  // The exact shape that used to bypass the whitelist: content snippets in
  // array form under `source` sailed through as paths.
  assert.deepEqual(WorkspaceWatch.pathsIn({ source: ['src/old/text'] }), [])
  // An argv vector is not a path list, however path-shaped item[1] looks.
  assert.deepEqual(WorkspaceWatch.pathsIn({ command: ['node', 'scripts/build.ts'] }), [])
  // A patch body's line array likewise.
  assert.deepEqual(WorkspaceWatch.pathsIn({ patch: ['--- a/src/x.ts', '+++ b/src/x.ts', '@@ -1 +1 @@'] }), [])
})

test('H9a: arrays under path keys still contribute their string items', () => {
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ files: ['src/a.ts', 'src/b.ts'] }),
    ['src/a.ts', 'src/b.ts'],
  )
  // The single-key form (`paths`) is the shape the adapters' tests pin.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ paths: ['src/gone.ts', 'src/there.ts'] }),
    ['src/gone.ts', 'src/there.ts'],
  )
  // A path key holding a one-element array, and the string-in-array-key form.
  assert.deepEqual(WorkspaceWatch.pathsIn({ file: ['src/one.ts'] }), ['src/one.ts'])
})

test('H9a: nested objects inside arrays still expose their path keys', () => {
  // Legal deep shapes must stay reachable — only bare strings were the leak.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ patches: [{ file: 'src/x.ts' }, { file: 'src/y.ts' }] }),
    ['src/x.ts', 'src/y.ts'],
  )
  // Object elements inside a genuinely path-keyed array keep both routes.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ files: ['src/a.ts', { path: 'src/b.ts' }] }),
    ['src/a.ts', 'src/b.ts'],
  )
})

test('H9a: the guard view (contentKeys) still collects source arrays', () => {
  // Over-detection is the guard's designed direction: a `move` sourcing the
  // evidence log as an array must not slip the gate just because arrays got
  // stricter for everyone else.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ source: ['.proof/x'] }, { contentKeys: true }),
    ['.proof/x'],
  )
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ sources: ['.proof/x', '.proof/y'] }, { contentKeys: true }),
    ['.proof/x', '.proof/y'],
  )
  // And the precise view stays precise on the same payload.
  assert.deepEqual(WorkspaceWatch.pathsIn({ source: ['.proof/x'] }), [])
})

test('H9a end-to-end: an argv array no longer charges the agent with phantom edits', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('run_command', { command: ['node', 'scripts/build.ts'] }), OK)
  assert.deepEqual(watch.touchedPaths(), [], 'argv items are not files the agent touched')
  assert.deepEqual(watch.sessionTouchedPaths(), [], 'nor provenance')
})

// ---------------------------------------------------------------------------
// H9b: shell visibility. bash/exec-class tools name their paths only inside a
// command string this observer deliberately does not parse — so once one has
// run, "not in the touched set" stops proving "external". The watcher records
// the session-level fact; consumers use it to demote `external` to `unknown`.
// ---------------------------------------------------------------------------

test('H9b: a shell tool call flips sessionShellUsed for the session', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  assert.equal(watch.sessionShellUsed(), false, 'no shell has run yet')

  await watch.observe(exec('bash', { command: 'prettier -w src/a.ts' }), OK)
  assert.equal(watch.sessionShellUsed(), true, 'the session has used a shell')
})

test('H9b: sessionShellUsed survives windowStart — it is a session-level fact', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('exec', { command: 'true' }), OK)
  watch.windowStart()
  assert.equal(watch.sessionShellUsed(), true, 'windows reset the touched set, not this fact')
  watch.windowStart()
  assert.equal(watch.sessionShellUsed(), true)
})

test('H9b: read-only and non-shell mutation tools do not flip the flag', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('read_file', { path: 'src/a.ts' }), OK)
  await watch.observe(exec('write', { path: 'src/a.ts', content: 'v2\n' }), OK)
  await watch.observe(exec('mystery_analyzer', { path: 'src/a.ts' }), OK)
  assert.equal(watch.sessionShellUsed(), false, 'only SHELL_TOOL_RE names flip it')
  // The anchored pattern, not a substring sniff: a name merely containing a
  // shell word never flips the flag.
  await watch.observe(exec('npm_audit_viewer', { path: 'src/a.ts' }), OK)
  assert.equal(watch.sessionShellUsed(), false)
})
