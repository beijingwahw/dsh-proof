import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MUTATION_TOOL_NAMES, MUTATION_TOOL_RE, READ_ONLY_TOOL_NAMES, SHELL_TOOL_NAMES, SHELL_TOOL_RE,
  WorkspaceWatch, driftNarrative, isMutationToolName, shellCommandMentionsPath, sweepToolInputStrings,
  toWorkspaceRelative,
} from '../src/dsh/observe.ts'
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
// V5-M2 (v0.24): the key-name fold is case AND separator aware, and the key
// roster carries directory/folder/uri (the X2 plan's list, finally complete).
// Pre-v0.24 `{File-Name: '.proof/evidence.jsonl'}` and `{directory: '.proof'}`
// extracted nothing — the value sweep still caught the strings, but the
// watcher's attribution and the guards' STRUCTURAL half never saw the path.
// ---------------------------------------------------------------------------

test('V5-M2: key names fold case AND separators — File-Name, file_name, fileName are one key', () => {
  for (const key of ['File-Name', 'file_name', 'fileName', 'FILE NAME', 'FilePath', 'file-path']) {
    assert.deepEqual(
      WorkspaceWatch.pathsIn({ [key]: 'src/a.ts' }),
      ['src/a.ts'],
      `${key} is a path key after the separator fold`,
    )
  }
  // Array keys fold the same way.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ GLOBS: ['src/a.ts'] }),
    ['src/a.ts'],
    'array keys fold case',
  )
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ 'Notebook-Path': 'notebooks/a.ipynb' }),
    ['notebooks/a.ipynb'],
    'a hyphenated notebook_path folds onto the roster entry',
  )
  // The fold must not START matching non-path keys: content stays content.
  assert.deepEqual(WorkspaceWatch.pathsIn({ 'my-content': 'src/old/text' }), [])
})

test('V5-M2: directory/folder/uri join the path-key roster (X2 plan complete)', () => {
  assert.deepEqual(WorkspaceWatch.pathsIn({ directory: 'src' }), ['src'])
  assert.deepEqual(WorkspaceWatch.pathsIn({ folder: 'src/lib' }), ['src/lib'])
  assert.deepEqual(WorkspaceWatch.pathsIn({ uri: 'notebooks/a.ipynb' }), ['notebooks/a.ipynb'])
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ directories: ['src', 'test'] }).sort(),
    ['src', 'test'],
  )
  assert.deepEqual(WorkspaceWatch.pathsIn({ folders: ['src/lib'] }), ['src/lib'])
  assert.deepEqual(WorkspaceWatch.pathsIn({ uris: ['a.ipynb', 'b.ipynb'] }), ['a.ipynb', 'b.ipynb'])
})

// ---------------------------------------------------------------------------
// Y-H-10 (v0.24): the ONE sweep's bounds are double-ended with tail
// preference. Direct unit pins — the guard-level pins in test/24 drive the
// same semantics through decidePreToolUse on both faces.
// ---------------------------------------------------------------------------

test('Y-H-10: sweepToolInputStrings keeps the FIRST 32 and the LAST 32 strings — pads-first cannot climb past the bound', () => {
  // ≤64 strings: everything is swept, in order.
  const small: Record<string, string> = {}
  for (let i = 0; i < 10; i++) small[`k${i}`] = `s${i}`
  assert.deepEqual(sweepToolInputStrings(small).length, 10)
  // 64 pads AHEAD of the needle: the needle is last, the tail window keeps it.
  const padsFirst: Record<string, string> = {}
  for (let i = 0; i < 64; i++) padsFirst[`k${i}`] = `pad-${i}`
  padsFirst.cmd = 'echo x > .proof/evidence.jsonl'
  const swept = sweepToolInputStrings(padsFirst)
  assert.equal(swept.length, 64, 'the window holds 64 strings, not 64 FIRST strings')
  assert.ok(swept.includes('echo x > .proof/evidence.jsonl'),
    'the LAST string is in the window (the pre-v0.24 first-64 ladder is dead)')
  assert.ok(swept.includes('pad-0') && swept.includes('pad-63'),
    'the window spans both ends of the insertion order')
  // The middle residual: padding on both sides buries a string between windows.
  const middle: Record<string, string> = {}
  for (let i = 0; i < 40; i++) middle[`a${i}`] = `pad-${i}`
  middle.cmd = 'buried'
  for (let i = 0; i < 40; i++) middle[`z${i}`] = `pad-${i}`
  assert.ok(!sweepToolInputStrings(middle).includes('buried'),
    'a string buried between the two window halves is the documented residual')
})

test('Y-H-10: an over-budget string keeps BOTH end windows (双端保窗) — redirect targets live at either end', () => {
  const needle = 'echo x > .proof/evidence.jsonl'
  // Padding AHEAD of the write used to drop the whole string (gates copy) or
  // keep only the head (observe copy); the shared sweep keeps the last 8192.
  const tailKept = sweepToolInputStrings({ commandLine: `${'x'.repeat(9_000)} ${needle}` })
  assert.equal(tailKept.length, 2, 'over-budget strings contribute both windows')
  assert.ok(tailKept[1]!.endsWith(needle), 'the tail window ends with the needle')
  assert.equal(tailKept[1]!.length, 8192, 'the per-string window is exactly 8192 chars')
  // The head residual: a needle pushed off the FRONT is not swept — pinned as
  // the documented price of the bound.
  // v0.24: oversize strings keep BOTH end windows — a needle that OPENS the
  // string is as live as one that closes it; only the strict middle of a
  // >2x-budget string is outside every window (the documented residual).
  const headKept = sweepToolInputStrings({ commandLine: `${needle} && ${'x'.repeat(9_000)}` })
  assert.equal(headKept.length, 2, 'an over-budget string contributes a head window and a tail window')
  assert.ok(headKept[0]!.startsWith(needle), 'the head window starts with the needle')
  assert.ok(headKept[0]!.length === 8192 && headKept[1]!.length === 8192, 'both windows are exactly 8192 chars')
})

test('Y-H-10/V5-M5: argv joins ONLY after measuring — a giant argv never allocates before the bound is consulted', () => {
  // A fitting argv is ONE command-line string (split needles reunite).
  const fitting = sweepToolInputStrings({ command: ['echo', 'x', '>', '.proof/evid', 'ence.jsonl'] })
  assert.deepEqual(fitting, ['echo x > .proof/evid ence.jsonl'], 'fitting argv joins into one line')
  // An over-budget argv sweeps its elements individually, each tail-capped —
  // the join is skipped rather than performed and discarded.
  const giant = ['node', '-e', `${'x'.repeat(9_000)} echo x > .proof/evidence.jsonl`]
  const swept = sweepToolInputStrings({ command: giant })
  assert.ok(swept.includes('node') && swept.includes('-e'), 'small elements sweep individually')
  assert.ok(swept.some(s => s.endsWith('echo x > .proof/evidence.jsonl')),
    'the big element keeps its tail window')
  // Mixed argv (the X-H-13 PoC shape): string elements still join/reach the
  // sweep; the number never breaks it.
  assert.ok(
    sweepToolInputStrings({ command: ['node', '-e', 'writeFileSync(".proof/evidence.jsonl")', 0] })
      .some(s => s.includes('.proof/evidence.jsonl')),
    'mixed argv reaches the needle',
  )
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

test('driftNarrative marks truncation — a wide drift shows its true size (V5-L4)', () => {
  // Pre-v0.24 the lists sliced to ten with no marker: a shell-shaped drift
  // over 25 files showed the model 10 of them with "re-read these" pointing
  // at an incomplete list and nothing saying anything was missing.
  const drifted = Array.from({ length: 25 }, (_, i) => `src/f${i}.ts`)
  const text = driftNarrative({ drifted, touched: [], staleReads: [], scanned: 25 })
  assert.ok(text)
  assert.match(text, /…and 15 more/, 'the overflow line names what the slice hid')
  assert.match(text, /src\/f0\.ts/, 'the first ten still lead')
  assert.ok(!text.includes('src/f10.ts'), 'past the cap, only the count speaks')
  // Both lists overflow independently: staleReads AND plain drift each get
  // their own marker.
  const staleReads = drifted.slice(0, 12)
  const both = driftNarrative({ drifted, touched: [], staleReads, scanned: 25 })
  assert.ok(both)
  assert.match(both, /…and 2 more/, 'the stale-read list carries its own overflow marker')
  assert.match(both, /…and 3 more/, 'the drift-only list carries its own overflow marker')
  // Ten or fewer: no marker — the lists were always complete.
  const exact = driftNarrative({ drifted: drifted.slice(0, 10), touched: [], staleReads: [], scanned: 10 })
  assert.ok(exact)
  assert.ok(!exact.includes('more'), 'a complete list has no overflow line')
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
  assert.equal(watch.sessionShellUsed(), false, 'only shell-class names flip it')
  // The anchored pattern, not a substring sniff: a name merely containing a
  // shell word never flips the flag.
  await watch.observe(exec('npm_audit_viewer', { path: 'src/a.ts' }), OK)
  assert.equal(watch.sessionShellUsed(), false)
})

// ---------------------------------------------------------------------------
// H-01: anchored name-list classification. The pre-v0.23 delimited-verb
// pattern was blind to camelCase host names — `MultiEdit`/`NotebookEdit`
// (documented Claude Code mutators) matched nothing, and because every
// pre-execute gate is allowlist-shaped they walked straight through while
// carrying a `file_path` into the evidence store; in the other direction a
// camelCase `Read` missed the case-sensitive read-only set, fell to the
// default mutation charge, and permanently silenced drift detection for the
// files it read. Unknown names default to mutation (the conservative charge).
// ---------------------------------------------------------------------------

test('H-01: camelCase mutators classify as mutations — no gate walks around the classifier', () => {
  for (const name of ['MultiEdit', 'NotebookEdit', 'Write', 'Edit', 'SafeWrite', 'writeFile', 'applyPatch',
    'createFile', 'ExecuteCommand', 'execute_command', 'run_shell_command', 'shell_exec']) {
    assert.ok(isMutationToolName(name), `${name} must classify as a mutation — it can move workspace state`)
  }
  // The exported lists are the contract (both adapter layers import the
  // functions; the lists pin the anchor names the functions consult).
  assert.ok(MUTATION_TOOL_NAMES.includes('multiedit'), 'the CC camel mutators are on the explicit list')
  assert.ok(SHELL_TOOL_NAMES.includes('run_shell_command'), 'host shell spellings are on the shell list')
  // Unknown names keep the conservative default: mutation.
  assert.ok(isMutationToolName('mystery_analyzer'), 'an unknown name is charged as a mutation')
  assert.ok(isMutationToolName('brand_new_editor_9000'), 'no name escapes the gate by being novel')
})

test('H-01: camelCase readers classify as reads — drift detection keeps working for them', async () => {
  for (const name of ['Read', 'Grep', 'View', 'Glob', 'LS', 'WebFetch']) {
    assert.ok(!isMutationToolName(name), `${name} only reads`)
  }
  assert.ok(READ_ONLY_TOOL_NAMES.includes('webfetch'), 'camelCase host readers fold onto the read-only list')
  // The C7 scenario end-to-end: a camelCase Read must land in the read set,
  // so a later external edit of the same file still reports as drift.
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('Read', { path: 'src/a.ts' }), OK)
  assert.deepEqual(watch.touchedPaths(), [], 'a camelCase read is not an edit')
  fs.mutate(`${ROOT}/src/a.ts`, 'v2 — the user rewrote this\n')
  const dirty = await watch.detectDrift()
  assert.deepEqual(dirty.drifted, ['src/a.ts'], 'the file the camelCase reader saw still reports drift')
  assert.deepEqual(dirty.staleReads, ['src/a.ts'])
})

test('H-01: NotebookEdit paths are extracted — notebook_path joins the path keys', async () => {
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ notebook_path: 'notebooks/analysis.ipynb' }),
    ['notebooks/analysis.ipynb'],
    'a notebook edit names its file under notebook_path',
  )
  const fs = MemoryFs.of({ [`${ROOT}/notebooks/analysis.ipynb`]: '{}\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('NotebookEdit', { notebook_path: 'notebooks/analysis.ipynb', new_source: 'x' }), OK)
  assert.deepEqual(watch.touchedPaths(), ['notebooks/analysis.ipynb'], 'the notebook edit is charged to the agent')
  assert.deepEqual(watch.sessionTouchedPaths(), ['notebooks/analysis.ipynb'])
})

test('H-01: host shell spellings flip the session shell fact', async () => {
  const fs = MemoryFs.of({ [`${ROOT}/src/a.ts`]: 'v1\n' })
  const watch = new WorkspaceWatch(fs, ROOT)
  await watch.observe(exec('execute_command', { command: 'prettier -w src/a.ts' }), OK)
  assert.equal(watch.sessionShellUsed(), true, 'execute_command is a shell-class name (H9b must see it)')
})

// ---------------------------------------------------------------------------
// H-02: the shell command string is the one argument shape path extraction
// structurally cannot see. The guard's conservative textual sweep lives here
// so both gate layers (index.ts and adapters/shared/gates.ts) consult the
// same one.
// ---------------------------------------------------------------------------

test('H-02: shellCommandMentionsPath catches command strings naming guarded targets', () => {
  const targets = ['.proof', 'evidence.jsonl', 'baseline.json', 'anchor.json']
  const hits = [
    'echo x > .proof/evidence.jsonl',
    'echo x > .PROOF/EVIDENCE.jsonl',           // case folding (H10's discipline)
    'echo x > .proof\\evidence.jsonl',           // backslash spelling
    'rm -rf .proof',
    'cd .proof && rm -f *',
    'cat baseline.json | head -1',
    'printf "%s" x >> ./anchor.json',
  ]
  for (const command of hits) {
    assert.ok(shellCommandMentionsPath(command, targets), `a shell naming the store must hit: ${command}`)
  }
  // Ordinary commands pass: over-blocking every shell call would teach the
  // model to avoid the verifier, so only store-naming strings hit.
  const misses = ['npm test', 'node scripts/build.ts', 'git status --porcelain', 'echo done > ok.txt']
  for (const command of misses) {
    assert.ok(!shellCommandMentionsPath(command, targets), `an ordinary command must pass: ${command}`)
  }
  // Degenerate shapes never throw and never hit.
  assert.equal(shellCommandMentionsPath('', targets), false)
  assert.equal(shellCommandMentionsPath('npm test', []), false)
})

// ---------------------------------------------------------------------------
// M2 (H9② narrative half): once a shell ran this session, "changed outside
// your tool calls" is a false accusation in the plugin's authoritative voice
// — the narrative must demote to what is actually known.
// ---------------------------------------------------------------------------

test('M2: driftNarrative stops accusing "outside your tool calls" once a shell ran this session', () => {
  const report = { drifted: ['src/a.ts'], touched: [], staleReads: ['src/a.ts'], scanned: 1 }
  const legacy = driftNarrative(report)
  assert.match(legacy ?? '', /outside your tool calls/, 'no shell fact: the legacy accusation stands')

  const withShell = driftNarrative(report, { shellUsed: true })
  assert.ok(withShell)
  assert.ok(!withShell.includes('outside your tool calls'), 'the false accusation is withdrawn')
  assert.match(withShell, /shell ran this session/)
  assert.match(withShell, /indistinguishable/)
  assert.match(withShell, /src\/a\.ts/, 'the drifted file is still named')
  assert.match(withShell, /proof_verify/, 'the remedy line is unchanged')
})
