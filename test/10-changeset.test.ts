/**
 * CHANGE-SET RESOLUTION — content-anchored, provenance-aware attribution.
 *
 * The old behaviour charged everything `git status` reported to the session:
 * dirt that predates the baseline, and edits the *user* made in their IDE.
 * v0.3 anchors the change set to the baseline's working-tree snapshot (with
 * per-file content digests) and classifies every change by who made it.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { resolveChangeSet } from '../src/core/changeset.ts'
import { sha256 } from '../src/core/hash.ts'
import { ProofEngine } from '../src/engine.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs } from './helpers.ts'

function project(extra: Record<string, string> = {}) {
  return {
    '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'vitest run', build: 'tsc -b' } }),
    '/ws/src/a.ts': 'export const a = 1\n',
    '/ws/src/b.ts': "import { a } from './a'\nexport const b = a + 1\n",
    '/ws/test/a.test.ts': "import { a } from '../src/a'\nvoid a\n",
    ...extra,
  }
}

test('explicit change sets are honoured as-is', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  const resolution = await resolveChangeSet({ fs, workspace: ws, explicit: ['src/b.ts', 'src/a.ts'] })
  assert.deepEqual(resolution.changed, ['src/a.ts', 'src/b.ts'])
  assert.equal(resolution.method, 'explicit')
  assert.deepEqual(resolution.records.map(r => r.provenance), ['explicit', 'explicit'])
})

test('no baseline falls back to the plain dirty set', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  ws.dirty = ['src/a.ts']
  const resolution = await resolveChangeSet({ fs, workspace: ws })
  assert.deepEqual(resolution.changed, ['src/a.ts'])
  assert.equal(resolution.method, 'dirty-fallback')
})

test('THE HEADLINE: dirt that predates the baseline and has not moved is excluded', async () => {
  const fs = MemoryFs.of(project({ '/ws/src/legacy.ts': 'old but stable\n' }))
  const ws = new FakeWorkspace('/ws')
  const baseline = {
    head: 'abc123',
    dirty: ['src/legacy.ts'],
    dirtyDigests: { 'src/legacy.ts': sha256('old but stable\n') },
  }
  // Still dirty, still the same bytes, plus one real change by the agent.
  ws.dirty = ['src/legacy.ts', 'src/a.ts']
  ws.changedSinceFiles = ['src/a.ts']
  fs.mutate('/ws/src/a.ts', 'export const a = 2\n')

  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline, touched: ['src/a.ts'] })
  assert.equal(resolution.method, 'baseline-content')
  assert.deepEqual(resolution.changed, ['src/a.ts'], 'stale dirt must not be charged to the session')
  assert.deepEqual(resolution.preExistingExcluded, ['src/legacy.ts'])
  assert.deepEqual(resolution.records, [{ path: 'src/a.ts', provenance: 'agent' }])
})

test('dirty-at-baseline file whose content moved IS a change', async () => {
  const fs = MemoryFs.of(project({ '/ws/src/legacy.ts': 'edited after baseline\n' }))
  const ws = new FakeWorkspace('/ws')
  const baseline = {
    head: 'abc123',
    dirty: ['src/legacy.ts'],
    dirtyDigests: { 'src/legacy.ts': sha256('old but stable\n') },
  }
  ws.dirty = ['src/legacy.ts']
  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline })
  assert.deepEqual(resolution.changed, ['src/legacy.ts'])
})

test('dirty-at-baseline file reverted to HEAD content is still a change', async () => {
  // Baseline checks ran against the DIRTY bytes; reverting to the commit is
  // itself a change relative to that snapshot. git diff vs HEAD sees nothing.
  const fs = MemoryFs.of(project({ '/ws/src/legacy.ts': 'committed version\n' }))
  const ws = new FakeWorkspace('/ws')
  const baseline = {
    head: 'abc123',
    dirty: ['src/legacy.ts'],
    dirtyDigests: { 'src/legacy.ts': sha256('dirty version\n') },
  }
  ws.dirty = [] // no longer dirty: content matches HEAD again
  ws.changedSinceFiles = []
  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline })
  assert.deepEqual(resolution.changed, ['src/legacy.ts'], 'revert-to-HEAD must count as a change vs the baseline snapshot')
})

test('untracked files and provenance classification', async () => {
  const fs = MemoryFs.of(project({ '/ws/scratch.ts': 'new\n' }))
  const ws = new FakeWorkspace('/ws')
  const baseline = { head: 'abc123', dirty: [], dirtyDigests: {} }
  ws.untrackedFiles = ['scratch.ts']
  ws.dirty = ['src/b.ts', 'src/user-edit.ts']
  ws.changedSinceFiles = ['src/b.ts', 'src/user-edit.ts']
  fs.mutate('/ws/src/b.ts', 'export const b = 2\n')

  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline, touched: ['src/b.ts'] })
  assert.deepEqual(resolution.changed, ['scratch.ts', 'src/b.ts', 'src/user-edit.ts'])
  const byPath = new Map(resolution.records.map(r => [r.path, r.provenance]))
  assert.equal(byPath.get('src/b.ts'), 'agent')
  assert.equal(byPath.get('src/user-edit.ts'), 'external', 'user IDE edits are external, not the agent\'s')
  assert.equal(byPath.get('scratch.ts'), 'external')
})

test('legacy baselines without digests stay conservative (include all candidates)', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  const baseline = { head: 'abc123', dirty: ['src/legacy.ts'] }
  ws.dirty = ['src/legacy.ts']
  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline })
  assert.equal(resolution.method, 'git-head')
  assert.deepEqual(resolution.changed, ['src/legacy.ts'], 'cannot prove it is unchanged, so include it')
})

// -- git unavailable: degrade visibly instead of silently under-attributing ----
// FakeWorkspace.gitAvailableValue (helpers.ts, E3) drives the optional probe:
// false = git definitively down, null = host never implemented the capability.

test('git reported unavailable: the dirty fallback degrades to empty AND says so', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  ws.gitAvailableValue = false
  ws.dirty = ['src/a.ts'] // what git *would* have said, had git existed
  const resolution = await resolveChangeSet({ fs, workspace: ws })
  assert.equal(resolution.method, 'dirty-fallback')
  assert.deepEqual(resolution.changed, [], 'with git down there is no dirty set to read')
  assert.equal(resolution.degraded, true, 'the blindness itself must be part of the answer')
})

test('git unavailable: content anchoring still works (digests need no git) but is marked degraded', async () => {
  const fs = MemoryFs.of(project({
    '/ws/src/legacy.ts': 'old but stable\n',
    '/ws/src/edited.ts': 'changed after baseline\n',
  }))
  const ws = new FakeWorkspace('/ws')
  ws.gitAvailableValue = false
  const baseline = {
    head: 'abc123',
    dirty: ['src/legacy.ts', 'src/edited.ts'],
    dirtyDigests: {
      'src/legacy.ts': sha256('old but stable\n'),
      'src/edited.ts': sha256('original\n'),
    },
  }
  const resolution = await resolveChangeSet({ fs, workspace: ws, baseline, touched: ['src/edited.ts'] })
  assert.equal(resolution.method, 'baseline-content')
  assert.deepEqual(resolution.preExistingExcluded, ['src/legacy.ts'], 'stale dirt is still excluded by content')
  assert.deepEqual(resolution.changed, ['src/edited.ts'], 'moved dirty-at-baseline content is still caught by content')
  assert.equal(resolution.degraded, true, 'files clean at baseline are invisible without git — surface it')
})

test('git available (or unprobed): resolutions are NOT marked degraded', async () => {
  const fs = MemoryFs.of(project())
  const wsNoProbe = new FakeWorkspace('/ws') // capability absent: gitAvailable === undefined
  wsNoProbe.gitAvailableValue = null
  wsNoProbe.dirty = ['src/a.ts']
  const withoutProbe = await resolveChangeSet({ fs, workspace: wsNoProbe })
  assert.equal(withoutProbe.degraded, undefined, 'a missing probe keeps the current behaviour')

  const wsYes = new FakeWorkspace('/ws') // capability present, git up
  wsYes.dirty = ['src/a.ts']
  const withProbe = await resolveChangeSet({ fs, workspace: wsYes })
  assert.equal(withProbe.degraded, undefined, 'git up means no degradation flag')
  assert.deepEqual(withProbe.changed, ['src/a.ts'])
})

test('ENGINE: stale dirt no longer widens verification, external regressions are not charged', async () => {
  const fs = MemoryFs.of(project({ '/ws/src/legacy.ts': 'old but stable\n' }))
  const ws = new FakeWorkspace('/ws')
  ws.dirty = ['src/legacy.ts']
  const engine = new ProofEngine({
    root: '/ws', fs, commands: new FakeCommands(), workspace: ws,
    clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()

  // The agent edits src/a.ts through its tools; src/legacy.ts stays as it was.
  fs.mutate('/ws/src/a.ts', 'export const a = 2\n')
  ws.dirty = ['src/legacy.ts', 'src/a.ts']
  ws.changedSinceFiles = ['src/a.ts']

  const outcome = await engine.verify({ touched: ['src/a.ts'] })
  assert.equal(outcome.attribution.method, 'baseline-content')
  assert.deepEqual(outcome.changed, ['src/a.ts'])
  assert.deepEqual(outcome.attribution.preExistingExcluded, ['src/legacy.ts'])
  assert.equal(outcome.report.grade, 'proven')
})

test('ENGINE: a regression caused by an external edit is reported but not charged', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  const commands = new FakeCommands()
  const engine = new ProofEngine({
    root: '/ws', fs, commands, workspace: ws,
    clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()

  // The user breaks the build in their IDE; the agent touched nothing.
  commands.on(argv => argv.includes('build'), { exitCode: 2, output: 'src/user-file.ts(1,1): error' })
  ws.dirty = ['src/user-file.ts']
  ws.changedSinceFiles = ['src/user-file.ts']
  fs.mutate('/ws/src/user-file.ts', 'broken by the user\n')

  const outcome = await engine.verify({ touched: [] })
  const build = outcome.checks.find(c => c.kind === 'build')
  assert.ok(build, 'build check present')
  assert.equal(build.verdict, 'regression', 'it regressed vs baseline — honesty first')
  assert.deepEqual(build.attributedTo, [], 'nothing is charged to the session')
  assert.deepEqual(build.externalSuspects, ['src/user-file.ts'])
  assert.match(build.rationale, /outside the agent's tool stream/)
  assert.equal(outcome.report.grade, 'regressed')
  assert.ok(outcome.report.regressions[0]?.includes('external'), `narrative: ${outcome.report.regressions.join(' ')}`)
})

test('ENGINE: the same file broken by the agent is still charged normally', async () => {
  const fs = MemoryFs.of(project())
  const ws = new FakeWorkspace('/ws')
  const commands = new FakeCommands()
  const engine = new ProofEngine({
    root: '/ws', fs, commands, workspace: ws,
    clock: new FakeClock(), impactGraphLimit: 1_000,
  })
  await engine.establishBaseline()

  commands.on(argv => argv.includes('build'), { exitCode: 2, output: 'boom' })
  ws.dirty = ['src/b.ts']
  ws.changedSinceFiles = ['src/b.ts']
  fs.mutate('/ws/src/b.ts', 'export const b = 2\n')

  const outcome = await engine.verify({ touched: ['src/b.ts'] })
  const build = outcome.checks.find(c => c.kind === 'build')
  assert.deepEqual(build?.attributedTo, ['src/b.ts'], 'agent-touched files keep their charge')
  assert.equal(build?.externalSuspects, undefined)
  assert.match(build?.rationale ?? '', /charged to this session/)
})
