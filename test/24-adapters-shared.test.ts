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

import {
  assertAbsoluteTrustRoot, deriveProofPaths, foldHostPath, guardedTargets, isAbsoluteHostPath,
  normalizeWorkspaceRoot, resolveAdapterEnv, SIGNING_KEY_FILE_NAMES, touchesEvidencePath, workspaceKeyPair,
} from '../src/adapters/shared/paths.ts'
import {
  applyObservation, computeDrift, emptySession, loadSession, saveSession, sessionPath, windowStart,
} from '../src/adapters/shared/session.ts'
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from '../src/adapters/shared/gates.ts'
import type { AdapterSession, DriftResult } from '../src/adapters/shared/session.ts'
import type { StopFacts } from '../src/adapters/shared/gates.ts'
import { Config } from '../src/config.ts'

import { addressOf, merkleRoot, sha256 } from '../src/core/hash.ts'
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
  // H-19: the adapter ledger is per-workspace — a session id is host-scoped,
  // and a flat directory let two workspaces' same-id sessions cross-pollinate.
  assert.equal(paths.sessionDir, `/trust/adapter-sessions/${paths.workspaceKey}`)
  const other = deriveProofPaths({ root: '/ws-2', trustRoot: '/trust' })
  assert.notEqual(other.sessionDir, paths.sessionDir, 'two workspaces never share a session directory')
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

test('deriveProofPaths: root spelling variants are ONE workspace identity — normalised before hashing (H-25/M-39)', () => {
  const raw = 'C:\\ws\\proj'
  const paths = deriveProofPaths({ root: raw, trustRoot: '/trust' })
  assert.equal(paths.root, 'C:/ws/proj', 'ProofPaths speaks one separator style')
  // The identity hashes the NORMALISED spelling now: `C:\ws\proj`, `C:/ws/proj`,
  // `c:\ws\proj` and `C:\ws\proj\` are one directory and must be one key —
  // pre-v0.23 hashed the raw string, so a hook fed payload.cwd and a server
  // fed its own cwd silently split gates, engine and MCP server into
  // different `workspaces/<key>` stores. (The drive letter folds to
  // lowercase; POSIX stays case-sensitive.)
  assert.equal(normalizeWorkspaceRoot(raw), 'c:/ws/proj')
  assert.equal(paths.workspaceKey, sha256('c:/ws/proj').slice(0, 16))
  assert.equal(paths.workspaceKey, deriveProofPaths({ root: 'C:/ws/proj', trustRoot: '/trust' }).workspaceKey)
  assert.equal(paths.workspaceKey, deriveProofPaths({ root: 'c:\\ws\\proj', trustRoot: '/trust' }).workspaceKey)
  assert.equal(paths.workspaceKey, deriveProofPaths({ root: 'C:/ws/proj/', trustRoot: '/trust' }).workspaceKey)
  // A POSIX root is its own normalisation (no probe, no case folding).
  assert.equal(normalizeWorkspaceRoot('/ws'), '/ws')
  assert.equal(workspaceKeyPair('/ws').normalized, workspaceKeyPair('/ws').legacy)
})

test('deriveProofPaths: existing legacy-key state on disk is probed, not orphaned (migration rule)', () => {
  const pair = workspaceKeyPair('C:\\ws\\proj')
  assert.notEqual(pair.normalized, pair.legacy, 'the Windows root really has two spellings')
  const warnings: string[] = []
  const saw = (key: string): Record<string, boolean> => ({
    [`/trust/anchors/${key}`]: true,
    [`/trust/workspaces/${key}`]: true,
  })

  // Fresh workspace (nothing on disk): the canonical normalised key.
  const fresh = deriveProofPaths({ root: 'C:\\ws\\proj', trustRoot: '/trust' },
    { exists: p => false, warn: line => warnings.push(line) })
  assert.equal(fresh.workspaceKey, pair.normalized)

  // Already migrated (engine wrote the normalised key): stays normalised, no noise.
  const migrated = deriveProofPaths({ root: 'C:\\ws\\proj', trustRoot: '/trust' },
    { exists: p => (saw(pair.normalized)[p] ?? false), warn: line => warnings.push(line) })
  assert.equal(migrated.workspaceKey, pair.normalized)

  // Legacy state only (a pre-v0.23 deployment's anchor/baseline): fall back
  // to the legacy key — the gate must keep finding the engine's store — and
  // SAY so; silent key switches are how stores get split.
  const legacy = deriveProofPaths({ root: 'C:\\ws\\proj', trustRoot: '/trust' },
    { exists: p => (saw(pair.legacy)[p] ?? false), warn: line => warnings.push(line) })
  assert.equal(legacy.workspaceKey, pair.legacy, 'existing on-disk identity wins over the new spelling')
  assert.equal(legacy.anchorDir, `/trust/anchors/${pair.legacy}`)
  assert.ok(warnings.some(l => l.includes('pre-normalisation key') && l.includes(pair.legacy)),
    `the fallback announces itself, got: ${warnings.join(' | ')}`)

  // `pure` skips the probe entirely (the in-gate derivation is probe-free).
  assert.equal(
    deriveProofPaths({ root: 'C:\\ws\\proj', trustRoot: '/trust' }, { pure: true, exists: () => true }).workspaceKey,
    pair.normalized,
  )

  // W11-M5: the adapter session ledger is trust-side state too. A legacy
  // deployment whose anchors/workspaces migrated but whose session dir did
  // not must keep its identity — otherwise every ledger (shellUsed,
  // firedNotices, fingerprints) silently orphans on the next hook process and
  // the drift narrative goes back to authoritatively accusing the agent.
  const legacySessionsOnly = deriveProofPaths({ root: 'C:\\ws\\proj', trustRoot: '/trust' },
    { exists: p => p === `/trust/adapter-sessions/${pair.legacy}`, warn: () => undefined })
  assert.equal(legacySessionsOnly.workspaceKey, pair.legacy,
    'a legacy session ledger alone keeps the legacy identity (the probe covers adapter-sessions/)')
})

test('deriveProofPaths: a trust root inside the workspace is warned about, never silently accepted (M-47)', () => {
  const warnings: string[] = []
  deriveProofPaths({ root: 'C:/ws/proj', trustRoot: 'C:/ws/proj/.trust' }, { exists: () => false, warn: line => warnings.push(line) })
  assert.ok(warnings.some(l => l.includes('INSIDE the workspace')), `got: ${warnings.join(' | ')}`)
  warnings.length = 0
  // Case-folded spellings of the same directory still count as inside.
  deriveProofPaths({ root: 'C:/ws/proj', trustRoot: 'c:/WS/PROJ/.trust' }, { exists: () => false, warn: line => warnings.push(line) })
  assert.ok(warnings.some(l => l.includes('INSIDE the workspace')), 'the containment check case-folds with the platform')
  warnings.length = 0
  deriveProofPaths({ root: 'C:/ws/proj', trustRoot: 'C:/elsewhere/trust' }, { exists: () => false, warn: line => warnings.push(line) })
  assert.equal(warnings.length, 0, 'an outside trust root says nothing')
})

test('deriveProofPaths: resolveAdapterEnv is the one parser for the DSH_PROOF_* contract (H-21)', () => {
  assert.deepEqual(resolveAdapterEnv({}), {
    root: undefined, trustRoot: undefined, evidenceStore: undefined, evidenceDir: undefined,
    requireBaseline: undefined, driftDetection: undefined, enforceTurnEnd: undefined,
  }, 'nothing set means nothing claimed — callers apply their own defaults')
  assert.deepEqual(
    resolveAdapterEnv({
      DSH_PROOF_ROOT: 'C:/ws', DSH_PROOF_TRUST_DIR: '/trust', DSH_PROOF_EVIDENCE_STORE: 'workspace',
      DSH_PROOF_EVIDENCE_DIR: '.evi', DSH_PROOF_REQUIRE_BASELINE: 'ask',
      DSH_PROOF_DRIFT: '0', DSH_PROOF_ENFORCE_TURN_END: 'off',
    }),
    {
      root: 'C:/ws', trustRoot: '/trust', evidenceStore: 'workspace', evidenceDir: '.evi',
      requireBaseline: 'ask', driftDetection: false, enforceTurnEnd: false,
    },
  )
  // Store mode is exact-string; an invalid ladder value is "unset"; flags
  // accept the honest off-spellings, not just '0'.
  const parsed = resolveAdapterEnv({
    DSH_PROOF_EVIDENCE_STORE: 'Workspace', DSH_PROOF_REQUIRE_BASELINE: 'nonsense',
    DSH_PROOF_DRIFT: 'FALSE', DSH_PROOF_ENFORCE_TURN_END: 'no',
  })
  assert.equal(parsed.evidenceStore, 'Workspace', 'the raw string passes through; only the exact value means workspace at the consumer')
  assert.equal(parsed.requireBaseline, undefined, 'invalid ladder values fall back to the caller default, never to a stricter or looser mode')
  assert.equal(parsed.driftDetection, false)
  assert.equal(parsed.enforceTurnEnd, false)
  assert.equal(resolveAdapterEnv({ DSH_PROOF_DRIFT: '1' }).driftDetection, true, 'any non-off spelling means on (default-on)')
  assert.equal(resolveAdapterEnv({ DSH_PROOF_DRIFT: '' }).driftDetection, undefined, 'empty is unset')
  // W11-L10: the ladder folds case + whitespace — 'ASK'/'ask\n' used to fall
  // to undefined and the `?? 'warn'` defaults then SILENTLY downgraded
  // ask→warn, breaking the "never a silent stricter/weaker mode" contract.
  assert.equal(resolveAdapterEnv({ DSH_PROOF_REQUIRE_BASELINE: 'ASK' }).requireBaseline, 'ask')
  assert.equal(resolveAdapterEnv({ DSH_PROOF_REQUIRE_BASELINE: ' ask\n' }).requireBaseline, 'ask')
  assert.equal(resolveAdapterEnv({ DSH_PROOF_REQUIRE_BASELINE: 'Off' }).requireBaseline, 'off')
  assert.equal(resolveAdapterEnv({ DSH_PROOF_REQUIRE_BASELINE: 'nonsense ' }).requireBaseline, undefined,
    'garbage is still unset — the caller default applies, loudly documented there')
})

test('deriveProofPaths: a RELATIVE trust root fails loudly, never silently lands in the workspace (X-H-15)', () => {
  // The pre-v0.23 containment check was lexical and blind to relative values:
  // 'rel/trust' does not start with the workspace root, so it never warned —
  // and the derivation then happily wrote keys, anchors and the host-mode
  // store against the process CWD (an agent-writable workspace; the audit's
  // four-part PoC got a private key PEM written into the CWD). A relative
  // trust root is a deployment misconfiguration, and misconfigurations fail
  // loudly at derivation time.
  for (const bad of ['rel/trust', '.trust', './trust', '..', 'trust', 'C:rel']) {
    assert.throws(() => deriveProofPaths({ root: '/ws', trustRoot: bad }, { pure: true }),
      /RELATIVE/i, `trustRoot ${JSON.stringify(bad)} must throw at derivation`)
  }
  // Drive-relative 'C:rel' counts as relative: it resolves against the
  // per-drive current directory — the workspace, for a hook process.
  assert.throws(() => assertAbsoluteTrustRoot('C:rel'), /RELATIVE/i)
  // Every absolute spelling passes: slash root, drive, UNC, device-prefixed.
  for (const good of ['/trust', 'C:/trust', 'c:\\trust', '//server/share/trust', String.raw`\\?\C:\trust`]) {
    assert.doesNotThrow(() => assertAbsoluteTrustRoot(good), `${JSON.stringify(good)} is absolute`)
  }
  assert.doesNotThrow(() => deriveProofPaths({ root: '/ws', trustRoot: '/trust' }, { pure: true }))

  // DSH_HOME inherits the same rule: a relative home makes the DEFAULT trust
  // root relative, and the derivation throws instead of resolving into CWD.
  const previous = process.env.DSH_HOME
  try {
    process.env.DSH_HOME = 'rel-home'
    assert.throws(() => deriveProofPaths({ root: '/ws' }, { pure: true }), /RELATIVE/i,
      'a relative DSH_HOME must fail as loudly as a relative DSH_PROOF_TRUST_DIR')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
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

test('touchesEvidencePath: Win32 deformations — trailing dots/spaces per segment (H-25), UNC root case', () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace' })
  // Win10-and-older CreateFile strips trailing dots and spaces from every
  // segment: `.proof.` IS `.proof`. Over-deny on modern hosts (one blocked
  // call) is the accepted cost; under-deny costs the chain.
  assert.equal(touchesEvidencePath('.proof./evidence.jsonl', paths), true, 'trailing dot on the store segment')
  assert.equal(touchesEvidencePath('.proof /evidence.jsonl', paths), true, 'trailing space on the store segment')
  assert.equal(touchesEvidencePath('.proof/evidence.jsonl./', paths), true, 'trailing dot on the file segment')
  assert.equal(touchesEvidencePath('.PROOF. /BASELINE.json', paths), true, 'dot + space + case together')

  // A degenerate segment ('.' — the store IS the workspace root, M-48) narrows
  // to the artifact names instead of silently guarding nothing.
  const degenerate = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace', evidenceDir: '.' })
  assert.equal(degenerate.evidenceDir, '', "the '.' segment collapses to nothing (the schema rejects this; the guard must not)")
  assert.equal(touchesEvidencePath('evidence.jsonl', degenerate), true, 'the log by name is the store')
  assert.equal(touchesEvidencePath('baseline.json', degenerate), true, 'the baseline by name is the store')
  assert.equal(touchesEvidencePath('src/a.ts', degenerate), false, 'everything else in the root is not')

  // UNC root, case-folded on both sides: `//SERVER/SHARE/ws/.proof/…` and
  // `\\server\share\ws\.PROOF\…` are the same store (H-25: the root-level
  // case hole re-opened the segment-level H10 fix).
  const uncRoot = '//server/share/ws'
  const uncPaths = deriveProofPaths({ root: uncRoot, trustRoot: '/trust', evidenceStore: 'workspace' })
  assert.equal(touchesEvidencePath('//server/share/ws/.proof/evidence.jsonl', uncPaths), true, 'exact UNC spelling hits')
  assert.equal(touchesEvidencePath('//SERVER/SHARE/ws/.proof/evidence.jsonl', uncPaths), true,
    'a UNC root case variant is the same workspace — the guard folds the root too')
  assert.equal(touchesEvidencePath(String.raw`\\SERVER\SHARE\ws\.PROOF\evidence.jsonl`, uncPaths), true,
    'backslash + case variants of a UNC root still hit')
})

test('foldHostPath: THE one fold — device prefixes, drive-relative projection, case, dots, detours, NUL (X-H-12)', () => {
  // Device-namespace prefixes fold away: `\\?\`, `//?/`, `\\.\` and the
  // `\\?\UNC\` sub-form all name the same files as their plain spellings
  // (Node's fs passes them through to CreateFile verbatim — the W11 devpath
  // PoC wrote into the store through exactly these spellings while every
  // lexical guard compared as false).
  assert.equal(foldHostPath(String.raw`\\?\C:\WS\.PROOF\evidence.jsonl`), 'c:/ws/.proof/evidence.jsonl')
  assert.equal(foldHostPath('//?/C:/WS/.proof/x'), 'c:/ws/.proof/x')
  assert.equal(foldHostPath(String.raw`\\.\C:\ws\.proof\x`), 'c:/ws/.proof/x')
  assert.equal(foldHostPath(String.raw`\\?\UNC\Server\Share\ws\.proof\x`), '//server/share/ws/.proof/x')
  // Separators, drive case and segment case fold; trailing dots/spaces per
  // segment fold; '.'/'..' segments collapse lexically; a leading '..' on a
  // RELATIVE path survives as the escape marker.
  assert.equal(foldHostPath(String.raw`C:\WS\.PROOF\EVIDENCE.jsonl`), 'c:/ws/.proof/evidence.jsonl')
  assert.equal(foldHostPath('.proof./evidence.jsonl. '), '.proof/evidence.jsonl')
  assert.equal(foldHostPath('/ws/foo/../.proof/./x'), '/ws/.proof/x')
  assert.equal(foldHostPath('../evil/x'), '../evil/x')
  assert.equal(foldHostPath('.'), '', 'the degenerate segment collapses to nothing')
  assert.equal(foldHostPath('a/..'), '', 'a/.. collapses to nothing too — same store-root case (W11-L-H)')
  assert.equal(foldHostPath(''), '')
  // '..' above an absolute root clamps (C:/.. is C:/), it does not escape.
  assert.equal(foldHostPath('C:/../ws/x'), 'c:/ws/x')
  // NUL truncation is modelled, not rejected: the OS keeps the prefix, so the
  // fold keeps it too (rejecting was the under-deny — the write happened).
  assert.equal(foldHostPath('.proof/evidence.jsonl\0junk'), '.proof/evidence.jsonl')

  // Drive-relative projection (the second X-H-12 vector): `C:foo` resolves
  // against the C-drive's current directory. For this process's own drive
  // that IS process.cwd() — the hook contract (CWD = workspace root) is what
  // turns `C:.proof/x` into the store path; a drive the CWD is not on gets
  // the drive root (fresh-process per-drive-CWD semantics, the documented
  // approximation).
  const cwdDrive = /^([A-Za-z]):/.exec(process.cwd())?.[1]?.toLowerCase()
  const sampleDrive = cwdDrive ?? 'c'
  const sample = `${sampleDrive}:.proof/x`
  const cwdFolded = foldHostPath(process.cwd())
  if (cwdDrive !== undefined) {
    assert.equal(foldHostPath(sample), `${cwdFolded}/.proof/x`,
      'C:foo on the CWD\'s own drive projects against the CWD')
  } else {
    assert.equal(foldHostPath(sample), `${sampleDrive}:/.proof/x`,
      'with no drive-letter CWD, the projection falls to the drive root')
  }
  const foreignDrive = cwdDrive === 'q' ? 'z' : 'q'
  assert.equal(foldHostPath(`${foreignDrive}:foo/bar`), `${foreignDrive}:/foo/bar`,
    'a drive the process is not on projects against the drive root')
  // Idempotence: folding a folded path changes nothing (guards fold BOTH
  // sides; a non-idempotent fold would make the two sides incomparable).
  const folded = foldHostPath(String.raw`\\?\C:\Ws\.PROOF.\x\\y/./z..txt `)
  assert.equal(foldHostPath(folded), folded)
})

test('touchesEvidencePath: X-H-12 — device-prefixed and drive-relative spellings of the store hit like plain ones', () => {
  const ws = deriveProofPaths({ root: 'C:/ws', trustRoot: '/trust', evidenceStore: 'workspace' }, { pure: true })
  assert.equal(touchesEvidencePath(String.raw`\\?\C:\ws\.proof\evidence.jsonl`, ws), true, 'backslash device prefix')
  assert.equal(touchesEvidencePath('//?/C:/ws/.proof/evidence.jsonl', ws), true, 'forward-slash device prefix')
  assert.equal(touchesEvidencePath(String.raw`\\?\C:\WS\.PROOF.\EVIDENCE.jsonl`, ws), true,
    'device prefix + case + trailing-dot deformations together')
  // Host mode: the absolute containment sweep folds the same way. (Normal
  // template with doubled backslashes — inside String.raw a `\` before `${`
  // would escape the interpolation and pin nothing.)
  const host = deriveProofPaths({ root: 'C:/ws', trustRoot: 'C:/trust' }, { pure: true })
  const devStore = `\\\\?\\C:\\trust\\workspaces\\${host.workspaceKey}\\evidence.jsonl`
  assert.equal(touchesEvidencePath(devStore, host), true, 'host-mode store via device prefix')
  // A device-prefixed path into some OTHER directory is still nobody's business.
  assert.equal(touchesEvidencePath(String.raw`\\?\C:\tmp\notes.md`, ws), false)

  // The 4096 blind spot is gone: over-long candidates used to be rejected by
  // the projection exactly when the `\\?\` prefix made such paths writable.
  const longName = `${'a'.repeat(5000)}.ts`
  assert.equal(touchesEvidencePath(`.proof/${longName}`, ws), true,
    'a >4096-byte candidate inside the store still compares')
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

test('applyObservation: bash records no PATHS — the shell blind spot is deliberate — but remembers that a shell ran', async () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const first = await applyObservation(session, 'bash', { command: 'echo hi > src/a.ts' }, ROOT, memoryReader({}))
  // Paths: nothing (a command string is not path-shaped input). The session
  // fact `shellUsed` flips once — from then on the drift narrative cannot
  // honestly say "outside your tool calls", so it stops saying it.
  assert.deepEqual(first.touched, [])
  assert.deepEqual(first.read, [])
  assert.deepEqual(first.fingerprints, {})
  assert.equal(first.shellUsed, true, 'the first shell call sets the session-level fact')
  const again = await applyObservation(first, 'bash', { command: 'rm -rf somewhere' }, ROOT, memoryReader({}))
  assert.equal(again, first, 'an already-shell session is returned untouched (same reference)')
  // And it survives the window boundary like fingerprints do.
  assert.equal(windowStart(first, '2026-10-06T11:00:00Z').shellUsed, true)
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

test('X-H-12 (NTFS adversarial): device-prefixed and drive-relative writes REALLY land in the store — and the guard sees them', async () => {
  // Win32-only semantics (the audit's W11-devpath.cjs rewrite): on any other
  // platform there is no `\\?\` passthrough and no per-drive CWD, so the
  // guard-level pins above already carry the contract.
  if (process.platform !== 'win32') return
  const wsRoot = `${SESSION_TMP}/devpath-ws`
  const store = `${wsRoot}/.proof`
  await fsp.mkdir(store, { recursive: true })
  const paths = deriveProofPaths({ root: wsRoot, evidenceStore: 'workspace' }, { pure: true })
  const gates = { evidenceStore: 'workspace' as const, evidenceDir: '.proof', requireBaseline: 'off' as const }
  const exists = async (p: string): Promise<boolean> => fsp.readFile(p, 'utf8').then(() => true, () => false)

  // (1) The attack is real, not theoretical: Node's fs hands `\\?\` straight
  // to CreateFile, and the write lands in the store.
  const devBack = `\\\\?\\${store.replace(/\//g, '\\')}\\dev.jsonl`
  await fsp.writeFile(devBack, 'x')
  assert.equal(await exists(`${store}/dev.jsonl`), true,
    'the device-prefixed write physically landed in the store (W11 devpath PoC)')
  // (2) The guard folds the same spelling and denies the tool call that
  // carried it.
  assert.equal(touchesEvidencePath(devBack, paths), true, 'the backslash device prefix hits after the fold')
  assert.equal(decidePreToolUse('write', { file_path: devBack }, wsRoot, gates, true).action, 'deny')
  const devFwd = `//?/${store}/dev2.jsonl`
  await fsp.writeFile(devFwd, 'x')
  assert.equal(await exists(`${store}/dev2.jsonl`), true, 'the forward-slash device form lands too')
  assert.equal(touchesEvidencePath(devFwd, paths), true, 'and hits the same fold')

  // (3) Drive-relative: `<drive>:.proof/x` resolves against the per-drive
  // current directory, which for this process's own drive is the CWD — the
  // hook contract puts the workspace root there, so the spelling names the
  // store. Chdir into the workspace to reproduce the hook's world exactly.
  const drive = wsRoot[0]
  const previousCwd = process.cwd()
  process.chdir(wsRoot)
  try {
    const drvRel = `${drive}:.proof/drvrel.jsonl`
    await fsp.writeFile(drvRel, 'x')
    assert.equal(await exists(`${store}/drvrel.jsonl`), true,
      'the drive-relative write physically landed in the store (per-drive CWD = workspace root)')
    assert.equal(touchesEvidencePath(drvRel, paths), true, 'the drive-relative spelling hits after projection')
    assert.equal(decidePreToolUse('write', { file_path: drvRel }, wsRoot, gates, true).action, 'deny')
    // Command-string form of the same vector.
    assert.equal(
      decidePreToolUse('bash', { command: `echo x > ${drvRel}` }, wsRoot, gates, true).action,
      'deny',
      'the textual sweep sees the drive-relative spelling as a bare store-relative hit',
    )
  } finally {
    process.chdir(previousCwd)
  }
})

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
  await fsp.writeFile(join(dir, 'scalar.json'), '42', 'utf8')
  await fsp.writeFile(join(dir, 'foreign.json'), JSON.stringify({ hello: 'world' }), 'utf8')
  await fsp.writeFile(join(dir, 'half.json'), JSON.stringify({ touched: 'not-an-array' }), 'utf8')

  // V5-L2: ALL damage routes announce, not just the digest mismatch — the
  // cheap forgeries (garbage bytes, a foreign object) must not be the QUIET
  // ones while the expensive one is loud. An ABSENT file stays silent: a
  // first run is not damage. (Ids carry no '.json' suffix: sessionPath adds
  // it, and the pre-v0.24 spelling of this test read 'garbage.json.json' —
  // silently pinning the ABSENT route while claiming to pin the parse one.)
  const complaints: string[] = []
  const sink = (line: string): void => { complaints.push(line) }
  assert.equal(await loadSession(dir, 'garbage', sink), undefined, 'unparsable bytes')
  assert.equal(await loadSession(dir, 'scalar', sink), undefined, 'valid JSON that is not an object')
  assert.equal(await loadSession(dir, 'foreign', sink), undefined, 'valid JSON that is not a session')
  assert.equal(await loadSession(dir, 'half', sink), undefined, 'a session shape with a rotten field')
  assert.equal(complaints.length, 4, `every damaged route announces exactly once: ${complaints.join(' | ')}`)
  assert.ok(complaints[0]!.includes('not parsable JSON'), 'the parse failure names its damage')
  assert.ok(complaints[1]!.includes('not a session object'), 'the non-object failure names its damage')
  assert.ok(complaints[2]!.includes('not shaped like a session'), 'the foreign-object failure names its damage')
  assert.ok(complaints[3]!.includes('not shaped like a session'), 'the shape failure names its damage')

  const absent: string[] = []
  assert.equal(await loadSession(dir, 'missing', line => absent.push(line)), undefined, 'never written')
  assert.deepEqual(absent, [], 'an absent snapshot is a first run, not damage — no announcement')
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

test('a tampered session snapshot fails its own digest and resets LOUDLY — pre-burned notices cannot silence the gates (H-19)', async () => {
  const dir = `${SESSION_TMP}/tamper`
  await fsp.mkdir(dir, { recursive: true })

  // The attack from the audit: write a shape-valid session by hand with both
  // one-time notices pre-fired, so the turn-end rules stay quiet forever.
  // Pre-v0.23 the loader shape-checked it and believed every field.
  const forged = {
    touched: [], read: [], fingerprints: {}, windowStartedAt: '2026-10-06T10:00:00Z',
    firedNotices: ['baseline', 'verify'],
  }
  const target = sessionPath(dir, 'audit-me')
  await fsp.writeFile(target, JSON.stringify(forged), 'utf8')
  const complaints: string[] = []
  assert.equal(await loadSession(dir, 'audit-me', line => complaints.push(line)), undefined,
    'a snapshot without a valid digest is damaged goods, not a session')
  assert.ok(complaints.some(l => l.includes('integrity check')), `the reset announces itself, got: ${complaints.join(' | ')}`)

  // A surgical edit (flip one field, keep the digest) is caught the same way.
  const real = emptySession('2026-10-06T10:00:00Z')
  await saveSession(dir, 'surgical', { ...real, firedNotices: ['baseline'] })
  const bytes = JSON.parse(await fsp.readFile(sessionPath(dir, 'surgical'), 'utf8')) as Record<string, unknown>
  bytes.firedNotices = ['baseline', 'verify']
  await fsp.writeFile(sessionPath(dir, 'surgical'), JSON.stringify(bytes), 'utf8')
  complaints.length = 0
  assert.equal(await loadSession(dir, 'surgical', line => complaints.push(line)), undefined)
  assert.ok(complaints.length > 0, 'the digest mismatch is said on stderr, never silently absorbed')

  // And the honest round-trip keeps working: same session, same digest.
  await saveSession(dir, 'honest', { ...real, firedNotices: ['baseline'] })
  assert.deepEqual(await loadSession(dir, 'honest'), { ...real, firedNotices: ['baseline'] })

  // A snapshot cannot be replayed into ANOTHER session id either: the digest
  // binds the id along with the body.
  const copied = await fsp.readFile(sessionPath(dir, 'honest'), 'utf8')
  await fsp.writeFile(sessionPath(dir, 'other-session'), copied, 'utf8')
  assert.equal(await loadSession(dir, 'other-session', () => undefined), undefined,
    'same bytes under a different session id fail the check')
})

test('evaluateStop: a session that used a shell gets the honest drift wording, not an accusation (M-29)', () => {
  const drift: DriftResult = { drifted: ['src/a.ts'], staleReads: ['src/a.ts'] }
  const plain = emptySession('2026-10-06T10:00:00Z')
  const withShell = { ...plain, shellUsed: true }
  const plainVerdict = evaluateStop(stopFacts({ drift, driftDetection: true, touchedCount: 0 }), plain)
  assert.match(plainVerdict.block ?? '', /outside your tool calls/,
    'without a shell the accusation is the true statement')
  const shellVerdict = evaluateStop(stopFacts({ drift, driftDetection: true, touchedCount: 0 }), withShell)
  assert.match(shellVerdict.block ?? '', /shell ran this session/,
    'with a shell in the session, the narrative says what is actually known')
  assert.ok(!/outside your tool calls/.test(shellVerdict.block ?? ''), 'the false accusation is gone')
  assert.match(shellVerdict.block ?? '', /proof_verify/, 'the remedy survives the honesty')
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
  // X-H-13 note: this call now DENIES — the textual value sweep reads strings,
  // not keys, and cannot tell a read tool's file_path from a command string.
  // Reading the log back through the model-facing proof MCP tools remains the
  // sanctioned route; 宁误拦 — the over-deny is one blocked call, the
  // under-deny was `grep {command: 'echo x > .proof/evidence.jsonl'}`.
  // (Pinned explicitly in the X-H-13 test below.)
  assert.equal(
    decidePreToolUse('write', { file_path: 'src/a.ts' }, ROOT, WS_GATES, true).action,
    'allow',
    'ordinary workspace writes are none of the guard\'s business',
  )
})

test('decidePreToolUse: host mode — a relative path cannot name the store, the baseline ladder speaks instead', () => {
  assert.equal(
    decidePreToolUse('write', { file_path: '.proof/evidence.jsonl' }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, false).action,
    'ask',
    'host mode: a workspace-relative spelling is not the host-side store (it lives under the trust root) — no store deny, the baseline ladder answers',
  )
})

test('decidePreToolUse: H-26 — host mode arms the store guard for ABSOLUTE paths into the trust-side store', () => {
  const TRUST = '/trust/proof-home'
  const paths = deriveProofPaths({ root: ROOT, trustRoot: TRUST, evidenceStore: 'host' }, { pure: true })
  const gates = { ...HOST_GATES, requireBaseline: 'off' as const, trustRoot: TRUST }

  // The canonical spelling: an absolute write straight into the host store.
  const deny = decidePreToolUse('write', { file_path: paths.logPath }, ROOT, gates, false)
  assert.equal(deny.action, 'deny', 'the absolute path into the host-side store is refused')
  if (deny.action === 'deny') {
    assert.match(deny.reason, /absolute/, 'the reason names the absolute-path vector')
  }

  // The legacy identity spelling: a migrated deployment may still hold its
  // store under the pre-normalisation key — both are guarded.
  const pair = workspaceKeyPair(ROOT)
  if (pair.normalized !== pair.legacy) {
    const legacy = decidePreToolUse(
      'write', { file_path: `${TRUST}/workspaces/${pair.legacy}/evidence.jsonl` }, ROOT, gates, false,
    )
    assert.equal(legacy.action, 'deny', 'the legacy-key store spelling is refused too')
  }

  // Case/separator deformation of the same path is still the same path.
  const deformed = decidePreToolUse(
    'write', { file_path: paths.logPath.replace('/workspaces/', '\\WORKSPACES\\') }, ROOT, gates, false,
  )
  assert.equal(deformed.action, 'deny', 'separator/case variants of the store path are refused')

  // An absolute path that is NOT the store is nobody's business here.
  const elsewhere = decidePreToolUse('write', { file_path: '/tmp/scratch/notes.md' }, ROOT, gates, false)
  assert.equal(elsewhere.action, 'allow', 'absolute paths outside the trust-side store pass')

  // Without the trust root the gate cannot know where the host store lives —
  // it stays disarmed rather than guessing (the caller who omits trustRoot
  // reproduces the historical contract; the wiring that has it arms it).
  const blind = decidePreToolUse('write', { file_path: paths.logPath }, ROOT, { ...HOST_GATES, requireBaseline: 'off' }, false)
  assert.equal(blind.action, 'allow', 'no trustRoot, no host-store sweep — the historical contract')
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

test('decidePreToolUse: real host mutators MultiEdit and NotebookEdit take the deny path (H-01)', () => {
  // The pre-v0.23 word-regex could not see camelCase names, and the gates
  // were allowlist-shaped — `MultiEdit {file_path: '.proof/evidence.jsonl'}`
  // walked straight through while Write/Edit were denied. The anchored name
  // list classifies both; the baseline ask ladder sees them too.
  assert.equal(
    decidePreToolUse('MultiEdit', { file_path: '.proof/evidence.jsonl', edits: [] }, ROOT, { ...WS_GATES, requireBaseline: 'ask' }, false).action,
    'deny',
    'MultiEdit writing the log is denied',
  )
  assert.equal(
    decidePreToolUse('NotebookEdit', { notebook_path: '.proof/evidence.jsonl' }, ROOT, { ...WS_GATES, requireBaseline: 'ask' }, false).action,
    'deny',
    'NotebookEdit + its notebook_path key is denied (name AND path key both recognised)',
  )
  assert.equal(
    decidePreToolUse('MultiEdit', { file_path: 'src/a.ts', edits: [] }, ROOT, HOST_GATES, false).action,
    'allow',
    'an ordinary MultiEdit outside the store is none of the guard\'s business (warn ladder)',
  )
  assert.equal(
    decidePreToolUse('MultiEdit', { file_path: 'src/a.ts', edits: [] }, ROOT, { ...HOST_GATES, requireBaseline: 'ask' }, false).action,
    'ask',
    'the baseline ask ladder sees MultiEdit as the mutation it is',
  )
})

test('decidePreToolUse: a shell command naming the store or trust files is denied; honest commands pass (H-02)', () => {
  const gates = { ...WS_GATES, trustRoot: '/trust' }
  // The v0.13 H9③ channel: a command string carries no path key, so the
  // structural sweep is blind to it — the textual sweep takes over.
  const redirect = decidePreToolUse('bash', { command: 'echo x > .proof/evidence.jsonl' }, ROOT, gates, true)
  assert.equal(redirect.action, 'deny')
  if (redirect.action === 'deny') assert.match(redirect.reason, /command names the verification evidence store/i)

  assert.equal(
    decidePreToolUse('bash', { command: 'cp evil.jsonl .PROOF/EVIDENCE.JSONL' }, ROOT, gates, true).action,
    'deny',
    'case and separator variants fold on both sides',
  )
  assert.equal(
    decidePreToolUse('bash', { command: 'cd .proof && rm *' }, ROOT, gates, true).action,
    'deny',
    'the bare store directory is a hit',
  )
  assert.equal(
    decidePreToolUse('bash', { command: `rm -rf /trust/anchors/${workspaceKeyPair(ROOT).normalized}/anchor.json` }, ROOT, gates, true).action,
    'deny',
    'trust-side artifacts (the anchor) are guarded in either store mode',
  )
  assert.equal(
    decidePreToolUse('bash', { command: `rm -rf /trust/workspaces/${workspaceKeyPair(ROOT).legacy}/evidence.jsonl` }, ROOT, gates, true).action,
    'deny',
    'the host-mode store and the LEGACY identity key are guarded too (migration-era state)',
  )
  // The honest commands the whole test suite has always allowed.
  assert.equal(decidePreToolUse('bash', { command: 'npm test' }, ROOT, gates, true).action, 'allow')
  assert.equal(decidePreToolUse('bash', { command: 'node scripts/build.ts --proof-mode' }, ROOT, gates, true).action, 'allow')
  // Without a trustRoot configured the trust sweep is simply not armed (the
  // historical GateOptions contract) — the workspace store sweep still is.
  assert.equal(
    decidePreToolUse('bash', { command: 'echo x > .proof/evidence.jsonl' }, ROOT, WS_GATES, true).action,
    'deny',
  )
})

test('decidePreToolUse: N-1 — the command sweep is capability-gated, not name-gated (runner-name variants and argv)', () => {
  const gates = { ...WS_GATES, trustRoot: '/trust' }
  // Hosts mint runner names faster than any list collects them: a tool the
  // roster has never heard of that carries a command string is still swept.
  for (const runner of ['sh', 'python', 'node', 'powershell', 'cmd', 'zsh', 'ruby', 'run', 'execute', 'eval', 'SomeRunnerTool']) {
    assert.equal(
      decidePreToolUse(runner, { command: 'echo x > .proof/evidence.jsonl' }, ROOT, gates, true).action,
      'deny',
      `runner name ${runner} carrying a store-writing command is denied`,
    )
  }
  // The argv form is one command semantically — a space-join is all the
  // conservative substring sweep needs.
  assert.equal(
    decidePreToolUse('execute_command', { command: ['node', '-e', "require('fs').writeFileSync('.proof/evidence.jsonl','x')"] }, ROOT, gates, true).action,
    'deny',
    'a string-argv command naming the store is denied',
  )
  // X-H-13: the read-only roster no longer exempts the textual sweep — a
  // read-NAMED tool carrying a command string is an execution signal (audit
  // PoC #4: `grep {command: 'echo x > .proof/evidence.jsonl'}` used to pass).
  // The roster still exempts the STRUCTURAL path sweep only.
  assert.equal(
    decidePreToolUse('read', { command: 'cat .proof/evidence.jsonl' }, ROOT, gates, true).action,
    'deny',
    'read-class tools carrying a store-naming command string are swept too',
  )
  // And the accepted over-deny, pinned on purpose: a read tool naming the
  // store PATH is denied as well — the sweep cannot tell keys apart, and
  // 宁误拦. The proof MCP tools remain the sanctioned read route.
  assert.equal(
    decidePreToolUse('read', { file_path: '.proof/evidence.jsonl' }, ROOT, gates, true).action,
    'deny',
    'a read tool naming the store is denied — one blocked call beats one laundered write',
  )
  // Honest runner commands keep passing — over-deny is the price, not the goal.
  assert.equal(
    decidePreToolUse('python', { command: 'python -m pytest tests/' }, ROOT, gates, true).action,
    'allow',
    'an honest unlisted-runner command passes',
  )
})

test('decidePreToolUse: X-H-13 — the command sweep reads VALUES, not key names (every spelling of a command key)', () => {
  const gates = { ...WS_GATES, trustRoot: '/trust' }
  // The audit walked the v0.22 key list with the fourth spelling; a value
  // sweep cannot be walked by renaming a key. Every one of these used to be
  // `shellCommandOf → undefined → ALLOW`.
  const needle = 'echo x > .proof/evidence.jsonl'
  const shapes: Array<[string, unknown]> = [
    ['a fourth command key', { commandLine: needle }],
    ['a code-execution key', { code: `fs.writeFileSync('.proof/evidence.jsonl','x')` }],
    ['mixed argv (non-string element used to void the join)', { command: ['node', '-e', needle, 0] }],
    ['nested command object', { command: { cmd: needle } }],
    ['an args array', { args: [needle] }],
    ['a nested nest', { tool: { spec: { commandLine: needle } } }],
  ]
  for (const [name, input] of shapes) {
    const verdict = decidePreToolUse('my_runner', input, ROOT, gates, true)
    assert.equal(verdict.action, 'deny', `${name}: the VALUE is swept wherever it sits`)
    if (verdict.action === 'deny') assert.match(verdict.reason, /command names the verification evidence store/i)
  }
  // The documented over-deny, pinned on purpose (宁误拦): a mutation call
  // whose CONTENT legitimately mentions the store is denied once, with a
  // reason — the alternative was laundering writes through content keys.
  assert.equal(
    decidePreToolUse('write', { file_path: 'docs/notes.md', content: 'see .proof/evidence.jsonl for the log' }, ROOT, gates, true).action,
    'deny',
    'content mentioning the store is the accepted over-deny price',
  )
})

test('decidePreToolUse: X-H-13/Y-H-10 — depth ≤ 3, and a DOUBLE-ENDED sweep window no ladder climbs', () => {
  const gates = { ...WS_GATES, trustRoot: '/trust' }
  const needle = 'echo x > .proof/evidence.jsonl'
  // Depth: a command nested three levels down is reachable…
  assert.equal(
    decidePreToolUse('run', { a: { b: { c: { commandLine: needle } } } }, ROOT, gates, true).action,
    'deny',
    'depth-3 nesting is still swept',
  )
  // …a fourth level is past the bound and NOT swept — the bound exists so a
  // hostile blob cannot turn the gate into a regex sink; pinned as the
  // documented window, not as a promise.
  assert.equal(
    decidePreToolUse('run', { a: { b: { c: { d: { commandLine: needle } } } } }, ROOT, gates, true).action,
    'allow',
    'past depth 3 the sweep stops (bound pinned deliberately)',
  )
  // >8k string: the TAIL is kept (截头保尾) — redirect targets and trailing
  // commands live at the END of real shell strings. Pre-v0.24 the two sweep
  // copies forked here exactly: the gates' local copy dropped the whole
  // string, the observe copy kept only its head — 8k of padding ahead of the
  // store write hid it from one face and 8k after it hid it from the other.
  assert.equal(
    decidePreToolUse('run', { commandLine: `${'x'.repeat(9_000)} ${needle}` }, ROOT, gates, true).action,
    'deny',
    'a >8k string keeps its last 8192 chars — a TAIL needle lands (head padding no longer hides it)',
  )
  // v0.24: oversize strings keep BOTH end windows — a needle at the head is
  // swept too; only the strict middle of a >2x-budget string is outside
  // every window (the documented residual).
  assert.equal(
    decidePreToolUse('run', { commandLine: `${needle} && ${'x'.repeat(9_000)}` }, ROOT, gates, true).action,
    'deny',
    'a HEAD needle of an over-budget string lands in the head window (trailing padding no longer hides it)',
  )
  assert.equal(
    decidePreToolUse('run', { commandLine: `${'x'.repeat(1_000)} ${needle}` }, ROOT, gates, true).action,
    'deny',
    'a ≤8k string carrying the needle is swept whole',
  )
  // 64 strings: with 63 clean values the needle lands inside the window…
  const within: Record<string, string> = {}
  for (let i = 0; i < 63; i++) within[`k${i}`] = `clean-${i}`
  within.cmd = needle
  assert.equal(decidePreToolUse('run', within, ROOT, gates, true).action, 'deny', 'within 64 strings the needle lands')
  // …and the pads-first ladder is DEAD: 64 clean values ahead of the needle
  // used to make it the unswept 65th string (insertion-order first-64); the
  // window now keeps the FIRST 32 and the LAST 32, and the real command —
  // the last string — is always inside.
  const padsFirst: Record<string, string> = {}
  for (let i = 0; i < 64; i++) padsFirst[`k${i}`] = `clean-${i}`
  padsFirst.cmd = needle
  assert.equal(decidePreToolUse('run', padsFirst, ROOT, gates, true).action, 'deny',
    'the LAST string is always swept (Y-H-10: pads-first no longer climbs past the bound)')
  // The middle residual: padding on BOTH sides buries the needle between the
  // first 32 and the last 32 — the deliberate price of a bounded sweep, and
  // the reason the STRUCTURAL path guard (next test) stays load-bearing: a
  // path-KEYED value the textual middle window hides is still folded and
  // compared by the store guard.
  const middle: Record<string, string> = {}
  for (let i = 0; i < 40; i++) middle[`a${i}`] = `clean-${i}`
  middle.cmd = needle
  for (let i = 0; i < 40; i++) middle[`z${i}`] = `clean-${i}`
  assert.equal(decidePreToolUse('run', middle, ROOT, gates, true).action, 'allow',
    'a needle buried between the two window halves is the documented middle residual')
})

test('decidePreToolUse: Y-H-10 — the textual middle window cannot smuggle a PATH-KEYED store write past the STRUCTURAL guard', () => {
  // The audit's composite PoC: 64 pads ahead of `file_path` used to beat the
  // first-64 textual window, and the workspace branch's old local fold was
  // blind to the device-prefix / trailing-dot spellings — the two failures
  // stacked into an unasked direct write. Both halves are fixed; this pin
  // drives the STACK through the gates: the needle sits in the textual
  // middle residual (81 strings, position 41) and must still DENY through
  // the structured touchesEvidencePath fold (Y-H-12's fold, shared).
  const gates = { ...WS_GATES, requireBaseline: 'off' as const }
  const spellings = [
    String.raw`\\?\C:\ws\.proof\evidence.jsonl`, // device-prefixed: verbatim passthrough to CreateFile
    '.proof./evidence.jsonl', // Win32 trailing-dot deformation
    `${'C:/ws'.toUpperCase()}/.PROOF/EVIDENCE.jsonl`, // case-folded absolute
  ]
  for (const file_path of spellings) {
    const args: Record<string, string> = {}
    for (let i = 0; i < 40; i++) args[`a${i}`] = `clean-${i}`
    args.file_path = file_path
    for (let i = 0; i < 40; i++) args[`z${i}`] = `clean-${i}`
    const verdict = decidePreToolUse('write', args, 'C:\\ws', gates, true)
    assert.equal(verdict.action, 'deny',
      'a path-keyed store spelling in the textual middle window still hits the structural fold')
    if (verdict.action === 'deny') assert.match(verdict.reason, /evidence store/)
  }
  // Same construction, innocent path: allow — the middle window is not an
  // excuse to over-deny ordinary writes.
  const innocent: Record<string, string> = {}
  for (let i = 0; i < 40; i++) innocent[`a${i}`] = `clean-${i}`
  innocent.file_path = 'src/a.ts'
  for (let i = 0; i < 40; i++) innocent[`z${i}`] = `clean-${i}`
  assert.equal(decidePreToolUse('write', innocent, 'C:\\ws', gates, true).action, 'allow')
})

test('decidePreToolUse: Y-H-10/Y-H-12 — the drive-relative spelling rides the same stack (per-drive CWD = workspace root)', async () => {
  // The hook contract puts the workspace at the process CWD; `C:.proof/x`
  // names `<CWD>/.proof/x` on the CWD's own drive. Drive-relative projection
  // is only faithful from inside that world, so this test chdirs (the X-H-12
  // devpath test's discipline). Non-Windows has no per-drive CWD.
  if (process.platform !== 'win32') return
  const wsRoot = `${SESSION_TMP}/midwin-ws`
  await fsp.mkdir(wsRoot, { recursive: true })
  const gates = { evidenceStore: 'workspace' as const, evidenceDir: '.proof', requireBaseline: 'off' as const }
  const previousCwd = process.cwd()
  process.chdir(wsRoot)
  try {
    const drive = wsRoot[0]
    const args: Record<string, string> = {}
    for (let i = 0; i < 40; i++) args[`a${i}`] = `clean-${i}`
    args.file_path = `${drive}:.proof/evidence.jsonl`
    for (let i = 0; i < 40; i++) args[`z${i}`] = `clean-${i}`
    const verdict = decidePreToolUse('write', args, wsRoot.replace(/\//g, '\\'), gates, true)
    assert.equal(verdict.action, 'deny',
      'the drive-relative store spelling, buried mid-window from the textual sweep, hits the structural fold')
    if (verdict.action === 'deny') assert.match(verdict.reason, /evidence store/)
  } finally {
    process.chdir(previousCwd)
  }
})

test('decidePreToolUse: X-H-14 consumer side — unknown or case-variant PATH KEYS cannot smuggle the store', () => {
  // The key-name fold (PATH_KEYS toLowerCase) is observe.ts's own fix on the
  // extractor face; this pins the CONSUMER promise of the gates: whatever key
  // spelling a mutation tool hides the store under — a key the extractor does
  // not know yet, or a case variant of one it does — the call still denies,
  // because the X-H-13 value sweep reads the string wherever it sits. The
  // pin holds both before and after the extractor-side fold lands.
  for (const input of [
    { FileName: '.proof/evidence.jsonl' },
    { FILE_PATH: '.proof/evidence.jsonl' },
    { file_path: '.PROOF/evidence.jsonl' },
  ]) {
    assert.equal(
      decidePreToolUse('write', input, ROOT, { ...WS_GATES, requireBaseline: 'ask' }, false).action,
      'deny',
      `the gate denies the store under any key spelling: ${JSON.stringify(input)}`,
    )
  }
})

test('decidePreToolUse: Y-H-11 — signing-key exfiltration is denied on the ADAPTER face too (textual and structural)', () => {
  const TRUST = '/trust/proof-home'
  const gates = { ...HOST_GATES, trustRoot: TRUST }
  // The audit's PoC: `cp <trust>/keys/proof-signing-key.pem <tmp>` used to
  // ALLOW here — the target set had neither the file names nor the keys dir,
  // and the private key is the ability to forge every checkpoint signature.
  // Textual half: the bare file name is a target in every mode.
  for (const command of [
    `cp ${TRUST}/keys/proof-signing-key.pem /tmp/stolen.pem`,
    `cat ${TRUST}\\keys\\proof-signing-key.pub.pem`,
    'cp proof-signing-key.pem .',
  ]) {
    assert.equal(
      decidePreToolUse('bash', { command }, ROOT, gates, true).action,
      'deny',
      `a command naming a signing key is refused: ${command}`,
    )
  }
  // Structural half: an absolute write into the keys directory folds into the
  // trust-side guardedDirs (a file-level addition — not the whole trust root).
  for (const target of [`${TRUST}/keys/proof-signing-key.pem`, `${TRUST}/keys/proof-signing-key.pub.pem`]) {
    const verdict = decidePreToolUse('write', { file_path: target }, ROOT, gates, true)
    assert.equal(verdict.action, 'deny', `an absolute write into ${target} is denied`)
    if (verdict.action === 'deny') assert.match(verdict.reason, /absolute/)
  }
  // The names stay bare in the workspace-mode target set too — a mention of a
  // key file is worth refusing wherever it points.
  assert.equal(
    decidePreToolUse('bash', { command: 'cp proof-signing-key.pem .' }, ROOT, WS_GATES, true).action,
    'deny',
    'workspace mode guards the bare key file names as well',
  )
})

test('decidePreToolUse + guardedTargets: V5-M1 — the bare store DIRECTORY and the default trust root\'s ~/$ spellings are targets on BOTH faces', () => {
  // Whole-tree deletions name no file inside the tree: `rm -rf <store-dir>`
  // used to pass the adapter face (only the two FILES were listed) and
  // `rm -rf ~/.dsh/proof` passed BOTH faces (no absolute needle matches a
  // variable). The shared constructor lists both.
  const TRUST = '/trust/proof-home'
  const pair = workspaceKeyPair(ROOT)
  const key = pair.normalized === pair.legacy ? pair.normalized : pair.legacy
  const hostGates = { ...HOST_GATES, trustRoot: TRUST }
  for (const command of [
    `rm -rf ${TRUST}/workspaces/${key}`, // bare store directory, legacy identity spelling
    `rm -rf ${TRUST}/workspaces/${pair.normalized}`, // …and the canonical one
    `rm -rf ${TRUST}/adapter-sessions/${key}`,
  ]) {
    assert.equal(
      decidePreToolUse('bash', { command }, ROOT, hostGates, true).action,
      'deny',
      `whole-tree deletions of trust-side state are refused: ${command}`,
    )
  }

  // The tilde/env spellings fire only for the DEFAULT trust root. Isolate
  // DSH_HOME so the default is deterministic, then arm both spellings.
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = '/xdsh'
  try {
    const defaultGates = { ...HOST_GATES, trustRoot: '/xdsh/proof' }
    for (const command of [
      'rm -rf ~/.dsh/proof',
      'rm -rf $dsh_home/proof',
      'rm -rf ${dsh_home}/proof',
      'rm -rf $HOME/.dsh/proof',
      'rm -rf ~\\.dsh\\proof', // separator variant folds the same way
    ]) {
      assert.equal(
        decidePreToolUse('bash', { command }, ROOT, defaultGates, true).action,
        'deny',
        `a variable spelling of the default trust root is refused: ${command}`,
      )
    }
    // A CUSTOM trust root does not arm the literals (its own absolute needle
    // covers it) — `~/.dsh/proof` names a directory this deployment does not
    // use, and the historical allow must not regress into noise.
    const customGates = { ...HOST_GATES, trustRoot: TRUST }
    assert.equal(
      decidePreToolUse('bash', { command: 'ls ~/.dsh/proof' }, ROOT, customGates, true).action,
      'allow',
      'the tilde literals are armed only for the default trust root',
    )
  } finally {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
  }
})

test('guardedTargets: the ONE target-set constructor both faces consume (contract)', () => {
  const pair = workspaceKeyPair(ROOT)
  const keys = pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy]
  const targets = guardedTargets(ROOT, { evidenceStore: 'host', evidenceDir: '.proof', trustRoot: '/trust' })
  // Host mode: every identity's store directory AND files, the anchors, the
  // session ledgers, the keys dir, and the bare signing-key names.
  for (const key of keys) {
    for (const expected of [
      `/trust/workspaces/${key}`,
      `/trust/workspaces/${key}/evidence.jsonl`,
      `/trust/workspaces/${key}/baseline.json`,
      `/trust/anchors/${key}`,
      `/trust/adapter-sessions/${key}`,
    ]) {
      assert.ok(targets.includes(expected), `host-mode target set lists ${expected}`)
    }
  }
  assert.ok(targets.includes('/trust/keys'), 'the signing-key directory is a target')
  assert.ok(targets.includes('/trust/proof-signing-key.pem') === false,
    'the under-trust key spelling rides the bare name, not a trust-qualified duplicate')
  for (const name of SIGNING_KEY_FILE_NAMES) {
    assert.ok(targets.includes(name), `the bare signing-key name ${name} guards every mode`)
  }
  // Workspace mode adds the store segment spellings and keeps everything else.
  const wsTargets = guardedTargets(ROOT, { evidenceStore: 'workspace', evidenceDir: '.proof', trustRoot: '/trust' })
  for (const expected of ['.proof', '.proof/evidence.jsonl', '.proof/baseline.json', '/ws/.proof']) {
    assert.ok(wsTargets.includes(expected), `workspace-mode target set lists ${expected}`)
  }
  for (const target of targets) {
    assert.ok(wsTargets.includes(target), `workspace mode guards everything host mode does: ${target}`)
  }
  // No trust root: the historical contract — store segment only, plus the
  // bare key names (Y-H-11 guards them even bare).
  const bare = guardedTargets(ROOT, { evidenceStore: 'workspace', evidenceDir: '.proof' })
  assert.deepEqual(bare, ['.proof', '.proof/evidence.jsonl', '.proof/baseline.json', '/ws/.proof', '/ws/.proof/evidence.jsonl', '/ws/.proof/baseline.json', ...SIGNING_KEY_FILE_NAMES])
})

test('isAbsoluteHostPath: the ONE absolute-path rule, UNC arms included (V5-M6)', () => {
  // index.ts's retired third mirror lacked the backslash-UNC arm; the shared
  // export carries it, so a UNC evidenceDir derives an absolute log path on
  // every face.
  for (const absolute of ['C:/x', 'C:\\x', '\\\\server\\share\\x', '//server/share/x', '/x']) {
    assert.equal(isAbsoluteHostPath(absolute), true, `${absolute} is absolute`)
  }
  for (const relative of ['rel/x', '.\\proof', 'C:rel', 'proof']) {
    assert.equal(isAbsoluteHostPath(relative), false, `${relative} is relative`)
  }
})

test('decidePreToolUse: W11-M3 — absolute writes into anchors and adapter sessions are denied in BOTH store modes', () => {
  const TRUST = '/trust/proof-home'
  const pair = workspaceKeyPair(ROOT)
  const keys = pair.normalized === pair.legacy ? [pair.normalized] : [pair.normalized, pair.legacy]

  // Host mode (the audit's PoC #12: the structural sweep used to guard only
  // workspaces/<key> — the anchor, the chain's trust root, was a free write).
  const hostGates = { ...HOST_GATES, trustRoot: TRUST }
  for (const key of keys) {
    for (const target of [
      `${TRUST}/anchors/${key}/anchor.json`,
      `${TRUST}/adapter-sessions/${key}/ledger.json`,
      `${TRUST}/workspaces/${key}/evidence.jsonl`,
    ]) {
      const verdict = decidePreToolUse('write', { file_path: target }, ROOT, hostGates, true)
      assert.equal(verdict.action, 'deny', `host mode: an absolute write into ${target} is denied`)
      if (verdict.action === 'deny') assert.match(verdict.reason, /absolute/, 'the reason names the absolute-path vector')
    }
  }
  // Device-prefixed spellings of the same targets fold the same way (X-H-12):
  // a drive-style trust root with its `\\?\` spelling of the anchors write.
  const winTrust = 'C:/trust'
  const winPair = workspaceKeyPair('C:/ws')
  const winKeys = winPair.normalized === winPair.legacy ? [winPair.normalized] : [winPair.normalized, winPair.legacy]
  for (const key of winKeys) {
    const devSpelled = `\\\\?\\C:\\trust\\anchors\\${key}\\anchor.json`
    assert.equal(
      decidePreToolUse('write', { file_path: devSpelled }, 'C:/ws', { ...HOST_GATES, trustRoot: winTrust }, true).action,
      'deny',
      'a device-prefixed write into the anchors is denied after the fold',
    )
  }

  // Workspace mode with a trust root guards the same artifacts: the trust
  // side is where the audited process keeps its commitments regardless of
  // where the WORKSPACE store sits.
  const wsGates = { ...WS_GATES, trustRoot: TRUST }
  assert.equal(
    decidePreToolUse('write', { file_path: `${TRUST}/anchors/${keys[0]}/anchor.json` }, ROOT, wsGates, true).action,
    'deny',
    'workspace mode: an absolute write into the anchors is denied too',
  )
  // And the textual sweep names the session ledgers as targets (W11-M3's
  // `rm -rf <trust>/adapter-sessions/<key>` used to be a free command).
  assert.equal(
    decidePreToolUse('bash', { command: `rm -rf ${TRUST}/adapter-sessions/${keys[0]}` }, ROOT, wsGates, true).action,
    'deny',
    'a command destroying the adapter session ledger is denied',
  )
  // An absolute path OUTSIDE the trust artifacts is still nobody's business.
  assert.equal(
    decidePreToolUse('write', { file_path: '/tmp/scratch/notes.md' }, ROOT, hostGates, true).action,
    'allow',
    'absolute paths outside the trust artifacts pass',
  )
})

test('decidePreToolUse: W11-L-H — evidenceDir that collapses at runtime (a/..) guards the same files in BOTH sweeps', () => {
  // The schema rejects this spelling now (config pin below); the gate still
  // folds defensively. The two sweeps must agree on what the store IS: the
  // structural side always collapsed a/.. to the workspace root, the textual
  // side used to keep the literal segment — `echo x > evidence.jsonl` slipped
  // between them (audit PoC #7b).
  const collapsed = { evidenceStore: 'workspace' as const, evidenceDir: 'a/..', requireBaseline: 'off' as const }
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust', evidenceStore: 'workspace', evidenceDir: 'a/..' }, { pure: true })
  assert.equal(touchesEvidencePath('evidence.jsonl', paths), true, 'structural side: the root-level log by name')
  assert.equal(
    decidePreToolUse('bash', { command: 'echo x > evidence.jsonl' }, ROOT, collapsed, true).action,
    'deny',
    'textual side: the same file by the same bare name',
  )
})

test('hasBaselineOnDisk: true only for a baseline that ADDRESSES ITSELF — a 20-byte forgery is not one (H-20)', async () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust' })

  // A self-consistent baseline, built exactly the way buildBaseline mints
  // one: merkle root over the evidence addresses, id = address of the material.
  const checks = [
    { checkId: 'package.json:test', evidenceId: sha256('e1') },
    { checkId: 'package.json:build', evidenceId: sha256('e2') },
  ]
  const workspace = { head: 'h1', dirty: ['src/a.ts'], dirtDigest: sha256('src/a.ts') }
  const createdAt = '2026-10-06T10:00:00.000Z'
  const real = JSON.stringify({
    baselineId: addressOf({ createdAt, workspace, checkIds: checks.map(c => c.checkId), root: merkleRoot(checks.map(c => c.evidenceId)) }),
    createdAt,
    workspace,
    checks,
    root: merkleRoot(checks.map(c => c.evidenceId)),
  })
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: real })), true,
    'a baseline that recomputes to its own id is a real baseline')

  // The H-20 attack: a parsable JSON with a string baselineId, nothing else.
  // Pre-v0.23 this released the ask ladder and silenced the notices forever.
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: JSON.stringify({ baselineId: 'forged' }) })),
    false,
    'a 20-byte {\"baselineId\":\"forged\"} is not a baseline',
  )
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: JSON.stringify({ baselineId: 'x', checks: [] }) })),
    false,
    'a shape-carrying forgery without the self-address is still not one',
  )
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: JSON.stringify({ ...JSON.parse(real), root: sha256('tampered') }) })),
    false,
    'a real baseline whose root field no longer matches its evidence is damaged goods',
  )

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

test('hasBaselineOnDisk: chain binding and the no-chain floor (W11-M4)', async () => {
  const paths = deriveProofPaths({ root: ROOT, trustRoot: '/trust' })
  const checks = [
    { checkId: 'package.json:test', evidenceId: sha256('e1') },
    { checkId: 'package.json:build', evidenceId: sha256('e2') },
  ]
  const workspace = { head: 'h1', dirty: ['src/a.ts'], dirtDigest: sha256('src/a.ts') }
  const createdAt = '2026-10-06T10:00:00.000Z'
  const real = JSON.stringify({
    baselineId: addressOf({ createdAt, workspace, checkIds: checks.map(c => c.checkId), root: merkleRoot(checks.map(c => c.evidenceId)) }),
    createdAt,
    workspace,
    checks,
    root: merkleRoot(checks.map(c => c.evidenceId)),
  })

  // With the chain's recorded digest: matching bytes are the engine's truth;
  // ANY divergence is false — including a hand-recomputed self-consistent
  // forgery, which is exactly what the digest makes impossible to pass off.
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: real }), sha256(real)), true,
    'bytes matching the chain digest are a real baseline')
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: real }), sha256('anything-else')), false,
    'bytes diverging from the chain digest are not, however self-consistent')

  // The audit's PoC #5: an EMPTY self-consistent baseline is five lines away
  // with the package's own exports (addressOf + merkleRoot are public). With
  // no chain to bind to, the floor rises instead — at least one check and a
  // parseable createdAt.
  const emptyMaterial = {
    createdAt: '1970-01-01T00:00:00.000Z',
    workspace: {},
    checkIds: [] as string[],
    root: merkleRoot([]),
  }
  const emptyForged = JSON.stringify({
    baselineId: addressOf(emptyMaterial),
    ...emptyMaterial,
    checks: [],
  })
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: emptyForged })), false,
    'the no-chain floor: a self-addressed but EMPTY forgery is not a baseline')
  assert.equal(
    await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: JSON.stringify({ ...JSON.parse(real), createdAt: 'not-a-date' }) })),
    false,
    'the no-chain floor: an unparseable createdAt is not a baseline',
  )
  // The floor's honest over-deny, pinned deliberately: a genuine ZERO-check
  // baseline (a project nothing was discovered in) reads as "no baseline" and
  // keeps the ladder armed — one ask per mutation, not a five-line forgery.
  const zeroCheckMaterial = {
    createdAt,
    workspace,
    checkIds: [] as string[],
    root: merkleRoot([]),
  }
  const zeroCheck = JSON.stringify({
    baselineId: addressOf(zeroCheckMaterial),
    ...zeroCheckMaterial,
    checks: [],
  })
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: zeroCheck })), false,
    'a real zero-check baseline is the accepted over-deny (chain-digest callers exempt it)')
  assert.equal(await hasBaselineOnDisk(paths, memoryReader({ [paths.baselinePath]: zeroCheck }), sha256(zeroCheck)), true,
    'with the chain digest binding it, the same zero-check file is honoured')
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

test('evaluateStop: unverified work re-arms EVERY mutating turn — a burned notice is not an exemption (M-45)', () => {
  const session = emptySession('2026-10-06T10:00:00Z')
  const facts = stopFacts({ touchedCount: 1, hasBaseline: true, enforceOnTurnEnd: true })
  const first = evaluateStop(facts, session)
  assert.match(first.block ?? '', /proof_verify/)
  assert.equal(first.fire, 'verify')

  // The ledger records the fire — and the NEXT mutating turn still blocks:
  // this mirrors index.ts's per-turn enforcement (every turn that mutated
  // without a verified claim owes its own correction), instead of a notice
  // the audited party could burn once and ignore forever.
  const after = { ...session, firedNotices: [...session.firedNotices, 'verify'] }
  const second = evaluateStop(facts, after)
  assert.match(second.block ?? '', /proof_verify/, 'a second mutating turn owes its own verification')
  assert.equal(second.fire, 'verify')

  // A turn that mutated nothing owes nothing (the window advanced).
  assert.deepEqual(evaluateStop(stopFacts({ touchedCount: 0, hasBaseline: true, enforceOnTurnEnd: true }), after), {},
    'a quiet turn ends clean')

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

// ===========================================================================
// config.ts — domain pins for the path/knob schema faces owned here
// ===========================================================================

test('Config schema: syntheticDir keeps the conjure sandbox inside the workspace (W11-M-D)', () => {
  // The sandbox must be a real subdirectory: degenerate, escaping and
  // absolute spellings are rejected loudly instead of parking proof_conjure
  // outside the workspace ('../x'), at its root ('.'), or on another drive.
  for (const bad of ['../x', 'a/../x', '.', './', '', 'C:/abs', '/abs', 'a/..']) {
    assert.throws(() => Config({ syntheticDir: bad } as never), /match regexp/,
      `syntheticDir ${JSON.stringify(bad)} is rejected`)
  }
  // Legal spellings keep passing, including the documented default.
  assert.equal((Config({} as never) as { syntheticDir: string }).syntheticDir, '.proof-synthetic')
  assert.equal((Config({ syntheticDir: 'proof-sandbox' } as never) as { syntheticDir: string }).syntheticDir, 'proof-sandbox')
  assert.equal((Config({ syntheticDir: '.proof-synthetic' } as never) as { syntheticDir: string }).syntheticDir, '.proof-synthetic')
})

test('Config schema: evidenceDir rejects runtime-collapsing segments (W11-L-H), degenerate ones (M-48) and drive-absolute spellings (V5-M3)', () => {
  for (const bad of ['.', './', '', '/abs', 'a/..', 'a\\..', 'a/../b', 'C:/abs', 'C:\\abs', 'D:rel']) {
    assert.throws(() => Config({ evidenceDir: bad } as never), /match regexp/,
      `evidenceDir ${JSON.stringify(bad)} is rejected`)
  }
  assert.equal((Config({} as never) as { evidenceDir: string }).evidenceDir, '.proof')
  assert.equal((Config({ evidenceDir: './proof2/' } as never) as { evidenceDir: string }).evidenceDir, './proof2/')
  assert.equal((Config({ evidenceDir: 'proof2' } as never) as { evidenceDir: string }).evidenceDir, 'proof2')
})

test('Config schema: the κ/certify knobs live on the OPEN interval (0,1) (W6-F2 / W11-M5)', () => {
  // percent() is a closed [0,1]; κ=0 neutralises every B/C discount (p^0=1 —
  // grade inflation by configuration) and certifyTarget:0 certified nothing
  // required nothing. The schema domain is the open interval now; the
  // EngineOptions direct-construction face is validated on the engine side.
  for (const knob of ['certifyTarget', 'classBTrust', 'classCTrust'] as const) {
    assert.throws(() => Config({ [knob]: 0 } as never), /expected number >= 0\.01/, `${knob}: 0 is out of domain`)
    assert.throws(() => Config({ [knob]: 1 } as never), /expected number <= 0\.99/, `${knob}: 1 is out of domain`)
    const inside = Config({ [knob]: 0.5 } as never) as unknown as Record<string, number>
    assert.equal(inside[knob], 0.5, `${knob}: mid-band values pass`)
  }
  const defaults = Config({} as never) as unknown as Record<string, number>
  assert.equal(defaults.certifyTarget, 0.97)
  assert.equal(defaults.classBTrust, 0.7)
  assert.equal(defaults.classCTrust, 0.9)
})

test('Config schema: ζ and β join the open interval — the last two closed-percent knobs (V5-M4)', () => {
  // ζ=1 (juryConfidenceCap) removes the docs-only confidence ceiling entirely;
  // β=0 (syntheticFalsePass) prices an interested party's own conjured test
  // at "cannot falsely pass", cancelling the synthetic-weaker-than-organic
  // premise the π contract rests on. Both ends clamp like their three
  // siblings; the defaults are unchanged.
  for (const knob of ['juryConfidenceCap', 'syntheticFalsePass'] as const) {
    assert.throws(() => Config({ [knob]: 0 } as never), /expected number >= 0\.01/, `${knob}: 0 is out of domain`)
    assert.throws(() => Config({ [knob]: 1 } as never), /expected number <= 0\.99/, `${knob}: 1 is out of domain`)
    const inside = Config({ [knob]: 0.5 } as never) as unknown as Record<string, number>
    assert.equal(inside[knob], 0.5, `${knob}: mid-band values pass`)
  }
  const defaults = Config({} as never) as unknown as Record<string, number>
  assert.equal(defaults.juryConfidenceCap, 0.8)
  assert.equal(defaults.syntheticFalsePass, 0.15)
})

test('Config schema: impactGraphLimit and lspQueryBudget keep positive domains (W11-L-E)', () => {
  assert.throws(() => Config({ impactGraphLimit: 0 } as never), /expected number >= 1/)
  assert.throws(() => Config({ lspQueryBudget: 0 } as never), /expected number >= 1/)
  assert.throws(() => Config({ impactGraphLimit: -5 } as never), /expected number >= 1/)
  assert.equal((Config({ lspQueryBudget: 12 } as never) as { lspQueryBudget: number }).lspQueryBudget, 12)
})
