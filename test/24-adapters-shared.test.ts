/**
 * The shared adapter layer (src/adapters/shared/*): host-agnostic paths,
 * the serialisable watcher session, and the two gates.
 *
 * The flagship discipline here is PARITY: a hook process and the engine (or
 * the spawned MCP server) must derive the same artifact bytes without ever
 * talking to each other — so the engine test below runs a real ProofEngine
 * and checks the files land exactly where deriveProofPaths said they would.
 * The rest pins the contract matrices: the evidence-store guard (including
 * the case-variant hole the DSH adapter never closed), observation/drift as
 * session-as-value, atomic persistence across processes, and the pre-tool /
 * turn-end gate priorities.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import { join } from 'node:path'

import { deriveProofPaths, touchesEvidencePath } from '../src/adapters/shared/paths.ts'
import {
  applyObservation, computeDrift, emptySession, loadSession, saveSession, sessionPath, windowStart,
} from '../src/adapters/shared/session.ts'
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from '../src/adapters/shared/gates.ts'
import type { AdapterSession, DriftResult } from '../src/adapters/shared/session.ts'
import type { StopFacts } from '../src/adapters/shared/gates.ts'

import { sha256 } from '../src/core/hash.ts'
import { ProofEngine } from '../src/engine.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs } from './helpers.ts'

const ROOT = '/ws'

function project() {
  return {
    [`${ROOT}/package.json`]: JSON.stringify({
      name: 'demo',
      scripts: { test: 'vitest run', build: 'tsc -b' },
    }),
    [`${ROOT}/src/a.ts`]: 'export const a = 1\n',
    [`${ROOT}/src/b.ts`]: "import { a } from './a'\nexport const b = a + 1\n",
  }
}

/** Deterministic stand-in for the host key (test/09's FakeSigner, same trick). */
class FakeSigner implements SignerPort {
  readonly keyId = 'adapter-test-key'
  async sign(data: string): Promise<string> { return `sig:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> { return signature === `sig:${sha256(data)}` }
}

/** A readFile port over an in-memory table: present paths hash, absent skip. */
function memoryReader(files: Record<string, string>): (abs: string) => Promise<string | undefined> {
  return async abs => files[abs]
}

// ===========================================================================
// paths.ts — derivation + the engine-parity flagship
// ===========================================================================

test('deriveProofPaths: host mode parks evidence under the trust root keyed by workspace identity', () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust' })
  assert.equal(paths.evidenceStore, 'host', 'host is the default store mode')
  assert.equal(paths.workspaceKey, sha256(ROOT).slice(0, 16))
  assert.equal(paths.root, ROOT)
  assert.equal(paths.logDir, `/trust/workspaces/${paths.workspaceKey}`)
  assert.equal(paths.logPath, `/trust/workspaces/${paths.workspaceKey}/evidence.jsonl`)
  assert.equal(paths.baselinePath, `/trust/workspaces/${paths.workspaceKey}/baseline.json`)
  assert.equal(paths.anchorDir, `/trust/anchors/${paths.workspaceKey}`)
  assert.equal(paths.anchorPath, `/trust/anchors/${paths.workspaceKey}/anchor.json`)
  assert.equal(paths.sessionDir, '/trust/adapter-sessions')
})

test('deriveProofPaths: workspace mode resolves the evidence segment against the root', () => {
  const def = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace' })
  assert.equal(def.evidenceDir, '.proof', "'.proof' is the default segment")
  assert.equal(def.logDir, `${ROOT}/.proof`)
  assert.equal(def.logPath, `${ROOT}/.proof/evidence.jsonl`)

  // A sloppy configured segment normalises to one clean relative form.
  const custom = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace', evidenceDir: './proof2/' })
  assert.equal(custom.evidenceDir, 'proof2')
  assert.equal(custom.logDir, `${ROOT}/proof2`)
})

test('deriveProofPaths: trust root default follows DSH_HOME, then ~/.dsh — mcp-entry derivation verbatim', () => {
  const previous = process.env.DSH_HOME
  try {
    process.env.DSH_HOME = '/xdsh'
    assert.equal(deriveProofPaths({ root: ROOT }).trustRoot, '/xdsh/proof', '$DSH_HOME wins when set')
    delete process.env.DSH_HOME
    const expected = `${homedir().replace(/\\/g, '/')}/.dsh/proof`
    assert.equal(deriveProofPaths({ root: ROOT }).trustRoot, expected)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

test('deriveProofPaths: a backslashed Windows root is normalised for paths but hashed RAW for identity', () => {
  const raw = 'C:\\ws\\proj'
  const paths = deriveProofPaths({ root: raw, trustRoot: '/trust' })
  assert.equal(paths.root, 'C:/ws/proj', 'ProofPaths speaks one separator style')
  // The key must hash the host's spelling, not ours: mcp-entry computes
  // sha256(process.cwd()) on the raw backslashed string, and normalising
  // first would point the adapter at a different workspaces/<key> directory.
  assert.equal(paths.workspaceKey, sha256(raw).slice(0, 16))
  assert.equal(paths.logDir, `/trust/workspaces/${sha256(raw).slice(0, 16)}`)
})

test('deriveProofPaths: root defaults to the POSIX-spelled cwd', () => {
  assert.equal(deriveProofPaths({}).root, process.cwd().replace(/\\/g, '/'))
})

test('THE ANCHOR PROOF: a real engine writes evidence, baseline and anchor exactly where deriveProofPaths says', async () => {
  // The whole point of paths.ts: hook processes and the engine must agree on
  // artifact locations without sharing an address space. So we do not compare
  // derivations against derivations — we run the engine and read the disk.
  for (const evidenceStore of ['host', 'workspace'] as const) {
    const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore })
    const fs = MemoryFs.of(project())
    const engine = new ProofEngine({
      root: ROOT,
      // What index.ts hands the engine: host mode the absolute store dir,
      // workspace mode the relative segment.
      evidenceDir: evidenceStore === 'host' ? paths.logDir : paths.evidenceDir,
      trustDir: '/trust',
      workspaceKey: paths.workspaceKey,
      fs,
      commands: new FakeCommands(),
      workspace: new FakeWorkspace(ROOT),
      clock: new FakeClock(),
      signer: () => Promise.resolve(new FakeSigner()),
    })
    await engine.establishBaseline()

    const log = await fs.readFile(paths.logPath)
    assert.ok(log !== undefined && log.length > 0, `${evidenceStore}: engine appended the chain at ${paths.logPath}`)
    const baseline = await fs.readFile(paths.baselinePath)
    assert.ok(baseline !== undefined, `${evidenceStore}: baseline.json landed at ${paths.baselinePath}`)
    assert.equal(typeof (JSON.parse(baseline) as { baselineId?: unknown }).baselineId, 'string')
    const anchor = await fs.readFile(paths.anchorPath)
    assert.ok(anchor !== undefined, `${evidenceStore}: the signed checkpoint mirrored to ${paths.anchorPath}`)
  }
})

test('touchesEvidencePath: the guard matrix — direct, detoured, case-folded, innocent, host-mode', () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace' })
  assert.equal(touchesEvidencePath('.proof/evidence.jsonl', paths), true, 'direct relative write')
  assert.equal(touchesEvidencePath(`${ROOT}/foo/../.proof/evidence.jsonl`, paths), true,
    'an absolute path whose .. detour collapses into the store still hits')
  assert.equal(touchesEvidencePath('.PROOF/evidence.jsonl', paths), true,
    'H10: the case variant MUST hit — the adapter guard does not inherit index.ts\'s hole')
  assert.equal(touchesEvidencePath('src/a.ts', paths), false, 'a normal workspace file is nobody\'s evidence')
  assert.equal(touchesEvidencePath('../evil/.proof/evidence.jsonl', paths), false,
    'a path escaping the root keeps its leading .. and never matches')
  assert.equal(touchesEvidencePath(`${ROOT}/.proof`, paths), true, 'the store root itself is the store')

  const host = deriveProofPaths({ root: ROOT, trustRoot: '/trust' })
  assert.equal(touchesEvidencePath('.proof/evidence.jsonl', host), false,
    'host mode: the store lives outside the workspace, the guard is not armed')
})

// ===========================================================================
// session.ts — observation and drift as pure session-as-value
// ===========================================================================

test('applyObservation: a write claims the file AND fingerprints its bytes; a read only witnesses them', async () => {
  const disk = { [`${ROOT}/src/a.ts`]: 'a1\n', [`${ROOT}/src/b.ts`]: 'b1\n' }
  let session = emptySession('2026-10-06T10:00:00Z')

  session = await applyObservation(session, 'write', { file_path: 'src/a.ts' }, ROOT, memoryReader(disk))
  assert.deepEqual(session.touched, ['src/a.ts'])
  assert.deepEqual(session.read, [])
  assert.equal(session.fingerprints['src/a.ts'], sha256('a1\n'))

  session = await applyObservation(session, 'read', { path: 'src/b.ts' }, ROOT, memoryReader(disk))
  assert.deepEqual(session.touched, ['src/a.ts'], 'reads never claim authorship')
  assert.deepEqual(session.read, ['src/b.ts'])
  assert.equal(session.fingerprints['src/b.ts'], sha256('b1\n'), 'reads fingerprint the last seen bytes too')

  // Same file seen twice: de-duplicated, order preserved.
  session = await applyObservation(session, 'write', { paths: ['src/b.ts', 'src/a.ts'] }, ROOT, memoryReader(disk))
  assert.deepEqual(session.touched, ['src/a.ts', 'src/b.ts'])
})

test('applyObservation: bash records nothing — the shell blind spot is deliberate, not an oversight', async () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const after = await applyObservation(session, 'bash', { command: 'echo hi > src/a.ts' }, ROOT, memoryReader({}))
  assert.equal(after, session, 'a shell call returns the session untouched (same reference, same facts)')
})

test('applyObservation: an unreadable fingerprint is skipped, a foreign path is not our business, input stays pure', async () => {
  const before = emptySession('2026-10-06T10:00:00Z')
  const disk = { [`${ROOT}/src/there.ts`]: 'present\n' }

  // src/gone.ts does not exist: claimed as touched, no fingerprint recorded.
  let session = await applyObservation(before, 'write', { paths: ['src/gone.ts', 'src/there.ts'] }, ROOT, memoryReader(disk))
  assert.deepEqual(session.touched, ['src/gone.ts', 'src/there.ts'])
  assert.equal(session.fingerprints['src/gone.ts'], undefined, 'no bytes to hash — skipped, not faked')
  assert.equal(session.fingerprints['src/there.ts'], sha256('present\n'))

  // An absolute path outside the root describes another neighbourhood.
  session = await applyObservation(session, 'write', { file_path: '/elsewhere/x.ts' }, ROOT, memoryReader(disk))
  assert.deepEqual(session.touched, ['src/gone.ts', 'src/there.ts'], 'foreign paths change nothing')

  // Purity: the session handed in was never mutated behind the caller's back.
  assert.deepEqual(before, emptySession('2026-10-06T10:00:00Z'))
})

test('computeDrift: the four verdicts — external change, stale read, disappearance, own work', async () => {
  // Window 1: the agent reads src/read.ts, writes src/own.ts and src/watched.ts
  // (a file it authored but never read back — fingerprints, no read entry).
  let session = emptySession('2026-10-06T10:00:00Z')
  const v1 = {
    [`${ROOT}/src/read.ts`]: 'read v1\n',
    [`${ROOT}/src/own.ts`]: 'own v1\n',
    [`${ROOT}/src/watched.ts`]: 'watched v1\n',
  }
  session = await applyObservation(session, 'read', { path: 'src/read.ts' }, ROOT, memoryReader(v1))
  session = await applyObservation(session, 'write', { file_path: 'src/own.ts' }, ROOT, memoryReader(v1))
  session = await applyObservation(session, 'write', { file_path: 'src/watched.ts' }, ROOT, memoryReader(v1))

  // Turn ends, new window: touched resets, fingerprints (last seen bytes) stay.
  session = windowStart(session, '2026-10-06T11:00:00Z')
  assert.deepEqual(session.touched, [])
  assert.ok(Object.keys(session.fingerprints).length === 3, 'fingerprints survive the window boundary')

  // Window 2: the agent touches src/own.ts again (at v1 bytes) and writes
  // src/gone.ts. After the tool calls, the world moves behind the stream:
  // read.ts edited (read earlier — a STALE read), watched.ts edited (written
  // in window 1, never read — drift the agent's context never held), own.ts
  // edited TOO (but this window's touch vouches for it), gone.ts deleted.
  session = await applyObservation(session, 'write', { file_path: 'src/own.ts' }, ROOT, memoryReader(v1))
  session = await applyObservation(session, 'write', { file_path: 'src/gone.ts' }, ROOT,
    memoryReader({ ...v1, [`${ROOT}/src/gone.ts`]: 'gone v1\n' }))
  const disk = {
    [`${ROOT}/src/read.ts`]: 'read v2\n',
    [`${ROOT}/src/own.ts`]: 'own v2\n',
    [`${ROOT}/src/watched.ts`]: 'watched v2\n',
    // src/gone.ts: absent on disk now.
  }
  const drift = await computeDrift(session, ROOT, memoryReader(disk))
  assert.deepEqual(drift.drifted.sort(), ['src/gone.ts', 'src/read.ts', 'src/watched.ts'])
  assert.deepEqual(drift.staleReads, ['src/read.ts'], 'only the file the agent READ counts as a stale read')
  assert.ok(!drift.drifted.includes('src/own.ts'),
    'own.ts moved outside the tools too, but this window\'s touch vouches for it — over-attribution is the accepted cost')
})

test('computeDrift: a read whose fingerprint failed still gets one honest look at the disk', async () => {
  // The agent "read" src/new.ts while it did not exist yet: no fingerprint.
  let session = emptySession('2026-10-06T10:00:00Z')
  session = await applyObservation(session, 'read', { path: 'src/new.ts' }, ROOT, memoryReader({}))
  assert.deepEqual(session.read, ['src/new.ts'])
  assert.equal(session.fingerprints['src/new.ts'], undefined)

  // Now it exists and no tool ever claimed it: it arrived from outside.
  const drift = await computeDrift(session, ROOT, memoryReader({ [`${ROOT}/src/new.ts`]: 'appeared\n' }))
  assert.deepEqual(drift.drifted, ['src/new.ts'])
})

test('windowStart clears the claim window but keeps fingerprints, reads and fired notices', () => {
  const session: AdapterSession = {
    touched: ['src/a.ts'],
    read: ['src/b.ts'],
    fingerprints: { 'src/a.ts': 'aa', 'src/b.ts': 'bb' },
    windowStartedAt: '2026-10-06T10:00:00Z',
    firedNotices: ['baseline'],
  }
  const next = windowStart(session, '2026-10-06T12:00:00Z')
  assert.deepEqual(next.touched, [])
  assert.deepEqual(next.read, ['src/b.ts'])
  assert.deepEqual(next.fingerprints, { 'src/a.ts': 'aa', 'src/b.ts': 'bb' })
  assert.deepEqual(next.firedNotices, ['baseline'], 'one-time notices are session facts, not per-turn ones')
  assert.equal(next.windowStartedAt, '2026-10-06T12:00:00Z')
})

// -- persistence: the session survives its process ---------------------------

const WORKSPACE_DIR = fileURLToPath(new URL('../../', import.meta.url))
const SESSION_TMP = `${WORKSPACE_DIR.replace(/\\/g, '/')}/.openclaw/tmp/proof-adapter-sessions-${process.pid}`

before(async () => {
  await fsp.rm(SESSION_TMP, { recursive: true, force: true })
})
after(async () => {
  await fsp.rm(SESSION_TMP, { recursive: true, force: true })
})

const realReader = (abs: string): Promise<string | undefined> =>
  fsp.readFile(abs, 'utf8').catch(() => undefined)

test('a session survives its process: save in one, load in the next, byte for byte', async () => {
  const dir = `${SESSION_TMP}/nested/deeper`
  const session: AdapterSession = {
    touched: ['src/a.ts', 'src/b.ts'],
    read: ['src/read.ts'],
    fingerprints: { 'src/a.ts': sha256('a\n') },
    windowStartedAt: '2026-10-06T10:00:00Z',
    firedNotices: ['baseline'],
  }
  await saveSession(dir, 'session-1', session) // dirs created implicitly
  assert.deepEqual(await loadSession(dir, 'session-1'), session)
})

test('a corrupt, foreign or absent session file reads as "start over", never as a crash', async () => {
  const dir = `${SESSION_TMP}/broken`
  await fsp.mkdir(dir, { recursive: true })
  await fsp.writeFile(join(dir, 'garbage.json'), '{not json at all', 'utf8')
  await fsp.writeFile(join(dir, 'foreign.json'), JSON.stringify({ hello: 'world' }), 'utf8')
  await fsp.writeFile(join(dir, 'half.json'), JSON.stringify({ touched: 'not-an-array' }), 'utf8')

  assert.equal(await loadSession(dir, 'garbage.json'), undefined, 'unparsable bytes')
  assert.equal(await loadSession(dir, 'foreign.json'), undefined, 'valid JSON that is not a session')
  assert.equal(await loadSession(dir, 'half.json'), undefined, 'a session shape with a rotten field')
  assert.equal(await loadSession(dir, 'missing'), undefined, 'never written')
})

test('a hostile session id becomes a filename, never a path', async () => {
  const dir = `${SESSION_TMP}/sanitize`
  const path = sessionPath(dir, '../../x')
  assert.ok(path.startsWith(`${dir}/`), 'stays inside the session dir')
  assert.ok(!path.slice(dir.length + 1).includes('/'), 'no separator survives sanitisation')

  // And it round-trips: the hostile id is just a (dull) name on disk.
  const session = emptySession('2026-10-06T10:00:00Z')
  await saveSession(dir, '../../x', session)
  assert.deepEqual(await loadSession(dir, '../../x'), session)
  const names = await fsp.readdir(dir)
  assert.deepEqual(names, ['.._.._x.json'], `file materialised inside the dir as ${names.join(',')}`)
})

// ===========================================================================
// gates.ts — pre-tool priority matrix and turn-end evaluation
// ===========================================================================

const HOST_GATES = { evidenceStore: 'host' as const, evidenceDir: '.proof', requireBaseline: 'off' as const }
const WS_GATES = { evidenceStore: 'workspace' as const, evidenceDir: '.proof', requireBaseline: 'off' as const }

test('decidePreToolUse: the evidence-store guard denies writes, detours and case tricks in workspace mode', () => {
  const deny = decidePreToolUse('write', { file_path: '.proof/evidence.jsonl' }, ROOT, { ...WS_GATES, requireBaseline: 'ask' }, false)
  assert.equal(deny.action, 'deny')
  if (deny.action === 'deny') assert.match(deny.reason, /evidence store/)

  assert.equal(
    decidePreToolUse('edit', { file_path: `${ROOT}/foo/../.proof/evidence.jsonl` }, ROOT, WS_GATES, true).action,
    'deny',
    'a collapsed .. detour into the store is still the store',
  )
  assert.equal(
    decidePreToolUse('move', { source: '.PROOF/evidence.jsonl', destination: 'stolen.jsonl' }, ROOT, WS_GATES, true).action,
    'deny',
    'H10: the case variant hits, and contentKeys:true catches the source key a move smuggles through',
  )
  assert.equal(
    decidePreToolUse('read', { file_path: '.proof/evidence.jsonl' }, ROOT, WS_GATES, true).action,
    'allow',
    'reading the log back is legitimate (the proof tools do it) — the guard is about writes',
  )
  assert.equal(
    decidePreToolUse('write', { file_path: 'src/a.ts' }, ROOT, WS_GATES, true).action,
    'allow',
    'ordinary workspace writes are none of the guard\'s business',
  )
})

test('decidePreToolUse: host mode never arms the store guard, whatever the path looks like', () => {
  assert.equal(
    decidePreToolUse('write', { file_path: '.proof/evidence.jsonl' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, false).action,
    'ask',
    'host mode: no deny for the store (it is outside the workspace) — the baseline gate speaks instead',
  )
})

test('decidePreToolUse: the baseline ladder — ask intercepts, warn passes, unknown never blocks', () => {
  const ask = decidePreToolUse('edit', { file_path: 'src/a.ts' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, false)
  assert.equal(ask.action, 'ask')
  if (ask.action === 'ask') {
    assert.match(ask.reason, /proof_baseline/, 'the reason names the remedy')
    assert.match(ask.reason, /edit/, 'and the tool it is refusing')
  }

  assert.equal(
    decidePreToolUse('edit', { file_path: 'src/a.ts' }, ROOT, { ...HOST_GATES, requireBaseline: 'warn' }, false).action,
    'allow',
    'warn passes the call and owes a turn-end correction instead',
  )
  assert.equal(
    decidePreToolUse('edit', { file_path: 'src/a.ts' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, true).action,
    'allow',
    'a baseline exists: nothing to ask',
  )
  assert.equal(
    decidePreToolUse('edit', { file_path: 'src/a.ts' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, undefined).action,
    'allow',
    'hasBaseline unknown (probe failed) must not block — index.ts\'s swallow-the-error behaviour',
  )
  assert.equal(
    decidePreToolUse('read', { file_path: 'src/a.ts' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, false).action,
    'allow',
    'only mutations can owe a baseline',
  )
})

test('decidePreToolUse: deny outranks ask — the store guard fires even with no baseline either', () => {
  const both = decidePreToolUse('write', { file_path: '.proof/evidence.jsonl' }, ROOT, { ...WS_GATES, requireBaseline: 'ask' }, false)
  assert.equal(both.action, 'deny', 'when two gates match, the evidence-store deny wins the priority')
})

test('hasBaselineOnDisk: true only for a real, parseable baseline carrying an id', async () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust' })
  const good = memoryReader({ [paths.baselinePath]: JSON.stringify({ baselineId: 'b1', checkIds: [] }) })
  assert.equal(await hasBaselineOnDisk(paths, good), true)

  assert.equal(await hasBaselineOnDisk(paths, memoryReader({})), false, 'no file')
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: '{broken' })),
    false,
    'unparsable file',
  )
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: JSON.stringify({ hello: 1 }) })),
    false,
    'parsable but not a baseline',
  )
})

function stopFacts(over: Partial<StopFacts> = {}): StopFacts {
  return {
    drift: undefined,
    touchedCount: 0,
    hasBaseline: true,
    requireBaseline: 'warn',
    enforceOnTurnEnd: false,
    driftDetection: false,
    ...over,
  }
}

test('evaluateStop: drift blocks EVERY time, stale reads named first, remedy last', () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const drift: DriftResult = { drifted: ['src/other.ts', 'src/read.ts'], staleReads: ['src/read.ts'] }
  const verdict = evaluateStop(stopFacts({ drift, driftDetection: true, touchedCount: 3 }), session)
  assert.ok(verdict.block !== undefined)
  assert.equal(verdict.fire, undefined, 'drift is not a one-time notice — next drift must block too')
  const text = verdict.block ?? ''
  assert.ok(text.indexOf('src/read.ts') < text.indexOf('src/other.ts'),
    'the stale read (the corruption poisoning the model\'s context) leads')
  assert.match(text, /outside your tool calls|not made through your tools/)
  assert.match(text, /proof_verify/)

  // Same drift next turn: still blocks. The disk is a fact, not a nag.
  const again = evaluateStop(stopFacts({ drift, driftDetection: true, touchedCount: 3 }), session)
  assert.ok(again.block !== undefined)
})

test('evaluateStop: the missing-baseline correction fires exactly once, then stays quiet', () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const facts = stopFacts({ touchedCount: 2, hasBaseline: false, requireBaseline: 'warn' })
  const first = evaluateStop(facts, session)
  assert.match(first.block ?? '', /proof_baseline/)
  assert.equal(first.fire, 'baseline')

  // The caller writes the notice back; the same facts may not nag again.
  const after = { ...session, firedNotices: [...session.firedNotices, first.fire ?? ''] }
  assert.deepEqual(evaluateStop(facts, after), {}, 'one-time: the second identical turn ends clean')

  // 'off' opts out of the ladder entirely.
  assert.deepEqual(evaluateStop(stopFacts({ touchedCount: 2, hasBaseline: false, requireBaseline: 'off' }), session), {})
  // Nothing touched, nothing owed.
  assert.deepEqual(evaluateStop(stopFacts({ touchedCount: 0, hasBaseline: false }), session), {})
})

test('evaluateStop: unverified work with a baseline fires the one-time verify notice', () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const facts = stopFacts({ touchedCount: 1, hasBaseline: true, enforceOnTurnEnd: true })
  const first = evaluateStop(facts, session)
  assert.match(first.block ?? '', /proof_verify/)
  assert.equal(first.fire, 'verify')

  const after = { ...session, firedNotices: [...session.firedNotices, 'verify'] }
  assert.deepEqual(evaluateStop(facts, after), {}, 'fired once, silent after')

  // Without enforcement the turn ends clean.
  assert.deepEqual(evaluateStop(stopFacts({ touchedCount: 1, hasBaseline: true, enforceOnTurnEnd: false }), session), {})
})

test('evaluateStop: drift outranks the baseline and verify notices', () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const drift: DriftResult = { drifted: ['src/moved.ts'], staleReads: [] }
  const verdict = evaluateStop(
    stopFacts({ drift, driftDetection: true, touchedCount: 1, hasBaseline: false, requireBaseline: 'warn' }),
    session,
  )
  assert.match(verdict.block ?? '', /src\/moved.ts/)
  assert.equal(verdict.fire, undefined, 'a drift block carries no notice id — priority one returns as-is')

  // Drift detection off: the same facts fall through to the baseline notice.
  const fallback = evaluateStop(
    stopFacts({ drift, driftDetection: false, touchedCount: 1, hasBaseline: false, requireBaseline: 'warn' }),
    session,
  )
  assert.equal(fallback.fire, 'baseline')
})

test('evaluateStop: a quiet turn — no drift, no touches — says nothing at all', () => {
  assert.deepEqual(evaluateStop(stopFacts(), emptySession('2026-10-06T10:00:00Z')), {})
})

// ===========================================================================
// The flagship lifecycle: three hook processes and one external edit
// ===========================================================================

test('THE TURN THAT WOULD NOT END CLEANLY: three processes, one session file, one external edit', async () => {
  const root = `${SESSION_TMP}/lifecycle-ws`
  const dir = `${SESSION_TMP}/lifecycle-sessions`
  await fsp.mkdir(`${root}/src`, { recursive: true })
  await fsp.writeFile(`${root}/src/app.ts`, 'v1\n', 'utf8')
  await fsp.writeFile(`${root}/src/lib.ts`, 'v1\n', 'utf8')

  // Process 1 (a post-tool hook): the agent writes app.ts and reads lib.ts.
  let session = emptySession('2026-10-06T10:00:00Z')
  session = await applyObservation(session, 'write', { file_path: `${root}/src/app.ts` }, root, realReader)
  session = await applyObservation(session, 'read', { file_path: `${root}/src/lib.ts` }, root, realReader)
  await saveSession(dir, 'conv-42', session)

  // Behind the tool stream: the user's IDE saves a new lib.ts.
  await fsp.writeFile(`${root}/src/lib.ts`, 'v2-edited-in-the-IDE\n', 'utf8')

  // Process 2 (the stop hook): cold start, loads the snapshot, judges the turn.
  const reloaded = await loadSession(dir, 'conv-42')
  assert.ok(reloaded !== undefined, 'the session outlived the process that wrote it')
  const drift = await computeDrift(reloaded, root, realReader)
  assert.deepEqual(drift.drifted, ['src/lib.ts'])
  assert.deepEqual(drift.staleReads, ['src/lib.ts'], 'the agent READ lib.ts — its context copy is now wrong')

  const stop = evaluateStop(
    stopFacts({ drift, driftDetection: true, touchedCount: reloaded.touched.length, hasBaseline: true, enforceOnTurnEnd: true }),
    reloaded,
  )
  assert.match(stop.block ?? '', /src\/lib\.ts/)
  assert.equal(stop.fire, undefined, 'drift is every-time, never one-time')

  // Turn accepted anyway (host policy): open the next window, persist, leave.
  await saveSession(dir, 'conv-42', windowStart(reloaded, '2026-10-06T11:00:00Z'))

  // Process 3 (the next stop hook): the window is clean now — the fingerprint
  // remembers lib.ts's new bytes only after a tool re-observes them, but no
  // NEW drift happened, so the turn ends on the verify notice, exactly once.
  const next = await loadSession(dir, 'conv-42')
  assert.ok(next !== undefined)
  const stillDrifting = await computeDrift(next, root, realReader)
  const verdict = evaluateStop(
    stopFacts({ drift: stillDrifting, driftDetection: true, touchedCount: 1, hasBaseline: true, enforceOnTurnEnd: true }),
    next,
  )
  // lib.ts is still drifted (nobody re-fingerprinted it) — and that is right:
  // the IDE's edit remains a fact until a tool sees the file again.
  assert.ok(stillDrifting.drifted.includes('src/lib.ts'))
  assert.match(verdict.block ?? '', /src\/lib\.ts/, 'unchanged facts must keep blocking, not wear out')
})
