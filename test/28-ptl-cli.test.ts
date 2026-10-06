/**
 * PROOF TRANSPARENCY LOG CLI — the auditor's subprocess, for real.
 *
 * Spawns `node --experimental-strip-types src/app/ptl-entry.ts` against a
 * real temp workspace whose evidence chain is minted the light way: an
 * `EvidenceStore` over the REAL filesystem (NodeFsPort) with a deterministic
 * fake signer, exactly the fixture shape 09-trust uses — no npm run, no
 * engine. The CLI under test is the real argv parser, the real workspace
 * discovery (deriveProofPaths over injected env), the real Ed25519 operator
 * key and the real merkle log from core/transparency.
 *
 * Covered: append (publish + STH mint + idempotence + the nothing-to-publish
 * refusal), head (empty and populated), verify self-check (clean, tampered
 * entries.jsonl), and the bundle round-trip — buildBundle with a transparency
 * record verified green over the CLI, then attacked one character at a time
 * (leafHash) and reconciled across log growth (consistency = non-rewrite).
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { buildBundle } from '../src/app/bundle.ts'
import { deriveProofPaths } from '../src/adapters/shared/paths.ts'
import { EvidenceStore, makeEvidence, snapshotWorkspace } from '../src/core/evidence.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { canonicalJson } from '../src/core/hash.ts'
import { GENESIS_PREV, checkpointSignedData, lineDigest, walkChain } from '../src/core/trust.ts'
import { TransparencyLog, loadPtl, ptlLeafHash, sthSignedData } from '../src/core/transparency.ts'
import type { PtlEntry, SignedTreeHead } from '../src/core/transparency.ts'
import { NodeEd25519Signer, NodeFsPort } from '../src/node-ports.ts'
import { FakeClock, spec } from './helpers.ts'

const ENTRY = fileURLToPath(new URL('../src/app/ptl-entry.ts', import.meta.url))
// The task's designated temp area: C:\mimoclaw_workspace\.openclaw\tmp\ptl-it-<pid>.
const TMP = join(fileURLToPath(new URL('../../../.openclaw/tmp', import.meta.url)), `ptl-it-${process.pid}`)

/** Local hex sha256 for hand-forged fixtures. */
function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

// The agent workspace whose chain gets published, and the PTL log directory.
const WS_ROOT = join(TMP, 'ws')
const TRUST_DIR = join(TMP, 'trust')
const PTL_DIR = join(TMP, 'ptl-log')
// A second workspace with no evidence at all (the refusal path).
const EMPTY_WS = join(TMP, 'ws-empty')
const EMPTY_TRUST = join(TMP, 'trust-empty')

const AT = '2026-10-06T00:00:00.000Z'
const WS = snapshotWorkspace('head1', ['src/a.ts'])
const nodeFs = new NodeFsPort()

/**
 * Deterministic stand-in for an engine key this host does NOT hold material
 * for: same shape 09-trust uses. v0.23: the fixture's MAIN signer is a real
 * NodeEd25519 key loaded from <trustRoot>/keys (exactly what the CLI's
 * selection rule verifies with — X-H-11 made verification mandatory, so the
 * happy path must publish under a key the CLI can actually check); the fake
 * remains for the refusal fixtures (an anchored key with no local material).
 */
class FakeSigner implements SignerPort {
  readonly keyId: string
  constructor(keyId = 'fake-key') { this.keyId = keyId }
  async sign(data: string): Promise<string> { return `sig:${createHash('sha256').update(data).digest('hex')}` }
  async verify(data: string, signature: string): Promise<boolean> { return signature === `sig:${createHash('sha256').update(data).digest('hex')}` }
}

const paths = deriveProofPaths({ root: WS_ROOT, trustRoot: TRUST_DIR, evidenceStore: 'host' })
const fakeSigner = new FakeSigner()
let store: EvidenceStore
let engineKeyId = ''

function evidence(id: string) {
  return makeEvidence(spec({ id }), { status: 'pass', exitCode: 0, durationMs: 5, output: 'pass\n' }, WS, new FakeClock())
}

/** Spawn the real CLI; every line of output is captured verbatim. */
function runCli(
  args: string[],
  env: Record<string, string> = { DSH_PROOF_ROOT: WS_ROOT, DSH_PROOF_TRUST_DIR: TRUST_DIR },
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', ENTRY, ...args], {
      cwd: WS_ROOT,
      env: {
        ...process.env,
        DSH_PROOF_ROOT: WS_ROOT,
        DSH_PROOF_TRUST_DIR: TRUST_DIR,
        DSH_PROOF_EVIDENCE_STORE: 'host',
        DSH_HOME: join(TMP, 'dsh-home'),
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout!.setEncoding('utf8')
    child.stdout!.on('data', (chunk: string) => { stdout += chunk })
    child.stderr!.setEncoding('utf8')
    child.stderr!.on('data', (chunk: string) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', code => resolve({ code, stdout, stderr }))
  })
}

/** Exactly one line of stdout, parsed — the CLI's whole output contract. */
function parseSingleLine(stdout: string): Record<string, unknown> {
  const lines = stdout.split('\n').filter(l => l.trim().length > 0)
  assert.equal(lines.length, 1, `stdout must be a single line, got ${JSON.stringify(stdout)}`)
  return JSON.parse(lines[0] as string) as Record<string, unknown>
}

/** A canonical one-line PTL entry for hand-forged logs (v0.23 fixtures). */
function forgedEntry(i: number, over: Partial<PtlEntry> = {}): PtlEntry {
  return {
    v: 1,
    workspaceKey: 'ws-forged',
    keyId: 'forged-key',
    count: 10 + i,
    head: sha256Hex(`forged-head-${i}`),
    at: AT,
    sig: `forged-sig-${i}`,
    ...over,
  }
}

before(async () => {
  await fsp.rm(TMP, { recursive: true, force: true })
  await fsp.mkdir(WS_ROOT, { recursive: true })
  await fsp.mkdir(PTL_DIR, { recursive: true })
  await fsp.mkdir(EMPTY_WS, { recursive: true })
  // v0.23 (X-H-11): the fixture's engine key is a REAL Ed25519 pair at
  // <trustRoot>/keys — the exact material the CLI's must-verify selection
  // rule adjudicates checkpoint signatures with.
  const engineKey = await NodeEd25519Signer.load(join(TRUST_DIR, 'keys'))
  engineKeyId = engineKey.keyId
  store = new EvidenceStore(nodeFs, paths.logPath, paths.baselinePath, new FakeClock(), {
    signer: async () => engineKey,
    anchorPath: paths.anchorPath,
    workspaceKey: paths.workspaceKey,
    checkpointEvery: 1000,
  })
  // Two records, then a signed checkpoint: the minimal chain worth publishing.
  await store.append(evidence('c1'))
  await store.append(evidence('c2'))
  await store.checkpoint()
})

after(async () => {
  await fsp.rm(TMP, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// head / append
// ---------------------------------------------------------------------------

test('head on a fresh log directory answers {empty:true} and exits 0', async () => {
  const { code, stdout, stderr } = await runCli(['head', '--log', join(TMP, 'ptl-fresh')])
  assert.equal(code, 0, `stderr: ${stderr}`)
  assert.deepEqual(parseSingleLine(stdout), { empty: true })
})

test('append with no signed checkpoint in the workspace exits 1 with the guidance message', async () => {
  const { code, stdout, stderr } = await runCli(
    ['append', '--log', join(TMP, 'ptl-refused')],
    { DSH_PROOF_ROOT: EMPTY_WS, DSH_PROOF_TRUST_DIR: EMPTY_TRUST },
  )
  assert.equal(code, 1)
  assert.equal(stdout.trim().length, 0, 'a refusal prints nothing on stdout')
  assert.ok(stderr.includes('no signed checkpoint to publish'), `stderr names the remedy: ${stderr}`)
  assert.ok(!stderr.includes('at '), 'no stack traces, ever')
})

test('append publishes the latest signed checkpoint, lands the entry on disk and signs a fresh STH', async () => {
  const { code, stdout, stderr } = await runCli(['append', '--log', PTL_DIR])
  assert.equal(code, 0, `stderr: ${stderr}`)
  const out = parseSingleLine(stdout) as {
    sequence: number; duplicate: boolean; leafHash: string; treeSize: number; root: string; logId: string
  }
  assert.equal(out.sequence, 0)
  assert.equal(out.duplicate, false)
  assert.match(out.leafHash, /^[0-9a-f]{64}$/)
  assert.equal(out.treeSize, 1)
  assert.match(out.root, /^[0-9a-f]{64}$/)
  assert.ok(typeof out.logId === 'string' && out.logId.length > 0, 'logId names the log (its own identity, not the operator key id)')

  // The entry physically landed: one canonical-JSON line carrying the checkpoint's sig.
  const entries = await fsp.readFile(join(PTL_DIR, 'ptl-entries.jsonl'), 'utf8')
  const entryLines = entries.split('\n').filter(l => l.trim().length > 0)
  assert.equal(entryLines.length, 1)
  const published = JSON.parse(entryLines[0] as string) as { v: number; workspaceKey: string; sig: string }
  assert.equal(published.v, 1)
  assert.equal(published.workspaceKey, paths.workspaceKey, 'the leaf commits to the derived workspace identity')
  assert.match(published.sig, /^[A-Za-z0-9+/]+={0,2}$/, 'the engine checkpoint signature rides along verbatim (real Ed25519, base64)')

  // v0.22 (H-07c): the operator key was minted OUTSIDE the log directory —
  // a key sitting next to the data it notarises is self-referential. The
  // default lives under the trust root; <logDir>/operator-key stays empty.
  const keyStat = await fsp.stat(join(TRUST_DIR, 'ptl-operator-key', 'proof-signing-key.pem'))
  assert.ok(keyStat.isFile())
  await assert.rejects(fsp.stat(join(PTL_DIR, 'operator-key')), 'no key is minted inside the log directory by default')
  // And the STH it signed is what head reports.
  const head = parseSingleLine((await runCli(['head', '--log', PTL_DIR])).stdout) as
    { logId: string; treeSize: number; root: string; at: string; sig: string }
  assert.equal(head.treeSize, 1)
  assert.equal(head.root, out.root)
  assert.equal(head.logId, out.logId)
  assert.ok(head.sig.length > 0)
})

test('re-append without a new checkpoint is idempotent: duplicate=true, no growth', async () => {
  const first = await runCli(['append', '--log', PTL_DIR])
  assert.equal(first.code, 0)
  const out = parseSingleLine(first.stdout) as { sequence: number; duplicate: boolean; treeSize: number }
  assert.equal(out.duplicate, true, 'the same checkpoint republished is recognised, not double-counted')
  assert.equal(out.sequence, 0)
  assert.equal(out.treeSize, 1)
})

// ---------------------------------------------------------------------------
// verify (self-check)
// ---------------------------------------------------------------------------

test('verify self-check is green: recomputed root === STH root, sizes agree, head signature holds', async () => {
  const { code, stdout, stderr } = await runCli(['verify', '--log', PTL_DIR])
  assert.equal(code, 0, `stderr: ${stderr}`)
  const out = parseSingleLine(stdout) as {
    ok: boolean; treeSize: number; checks: { rootMatch: boolean; headSignature: boolean }
  }
  assert.equal(out.ok, true)
  assert.equal(out.treeSize, 1)
  assert.equal(out.checks.rootMatch, true)
  assert.equal(out.checks.headSignature, true, 'the operator key minted by append is at hand, so the STH signature is judged')
})

test('verify self-check fails cleanly after one tampered byte in ptl-entries.jsonl', async () => {
  const entriesPath = join(PTL_DIR, 'ptl-entries.jsonl')
  const original = await fsp.readFile(entriesPath, 'utf8')
  try {
    // Change one value in the single entry: the line still parses, but the
    // merkle root over the entries no longer matches the signed head.
    const entry = JSON.parse(original) as { count: number }
    entry.count += 1
    await fsp.writeFile(entriesPath, `${JSON.stringify(entry)}\n`, 'utf8')

    const { code, stdout } = await runCli(['verify', '--log', PTL_DIR])
    assert.equal(code, 1)
    const out = parseSingleLine(stdout) as { ok: boolean; checks: { rootMatch: boolean } }
    assert.equal(out.ok, false)
    assert.equal(out.checks.rootMatch, false)
  } finally {
    await fsp.writeFile(entriesPath, original, 'utf8')
  }
})

// ---------------------------------------------------------------------------
// verify against a bundle's transparency record
// ---------------------------------------------------------------------------

/** The log as an in-process snapshot, for building publication records. */
async function logSnapshot(): Promise<{ log: TransparencyLog; sth: SignedTreeHead | undefined }> {
  return loadPtl(nodeFs, PTL_DIR)
}

/** The publication record for entry 0 against the CURRENT log state. */
async function recordForEntry0(): Promise<{
  logId: string; sequence: number; leafHash: string
  publishedHead: { logId: string; treeSize: number; root: string; at: string; sig: string }
  inclusionProof: readonly string[]
} > {
  const { log, sth } = await logSnapshot()
  assert.ok(sth !== undefined, 'append always leaves a signed head behind')
  const entry = log.entries[0]
  assert.ok(entry !== undefined)
  return {
    logId: sth.logId,
    sequence: 0,
    leafHash: ptlLeafHash(entry),
    publishedHead: sth,
    inclusionProof: log.inclusionProof(0),
  }
}

test('bundle round-trip: a transparency-stamped bundle verifies green over the CLI', async () => {
  const record = await recordForEntry0()
  const evidenceLog = await fsp.readFile(paths.logPath, 'utf8')
  const bundle = buildBundle({ evidenceLog }, paths.workspaceKey, AT, { transparency: record })
  const bundlePath = join(TMP, 'bundle.json')
  await fsp.writeFile(bundlePath, JSON.stringify(bundle, null, 2), 'utf8')

  const { code, stdout, stderr } = await runCli(['verify', '--log', PTL_DIR, '--bundle', bundlePath])
  assert.equal(code, 0, `stderr: ${stderr}`)
  const out = parseSingleLine(stdout) as {
    ok: boolean
    checks: { leafMatch: boolean; inclusion: boolean; consistency?: boolean; headSignature: boolean }
    sequence: number; treeSize: number
  }
  assert.equal(out.ok, true)
  assert.equal(out.checks.leafMatch, true)
  assert.equal(out.checks.inclusion, true)
  assert.equal(out.checks.consistency, undefined, 'published head IS the current head: nothing to reconcile')
  assert.equal(out.checks.headSignature, true)
  assert.equal(out.sequence, 0)
  assert.equal(out.treeSize, 1)
})

test('consistency: after the log grows, the OLD bundle still verifies — history cannot be rewritten', async () => {
  // A new delivery: more evidence, a new signed checkpoint, a second append.
  await store.append(evidence('c3'))
  await store.checkpoint()
  const second = await runCli(['append', '--log', PTL_DIR])
  assert.equal(second.code, 0)
  const grown = parseSingleLine(second.stdout) as { sequence: number; duplicate: boolean; treeSize: number }
  assert.equal(grown.duplicate, false)
  assert.equal(grown.sequence, 1)
  assert.equal(grown.treeSize, 2)

  // The bundle still records the tree as it stood at size 1 — and that older
  // state must prove to be an unmodified prefix of the size-2 tree.
  const bundlePath = join(TMP, 'bundle.json')
  const { code, stdout, stderr } = await runCli(['verify', '--log', PTL_DIR, '--bundle', bundlePath])
  assert.equal(code, 0, `stderr: ${stderr}`)
  const out = parseSingleLine(stdout) as {
    ok: boolean; checks: { leafMatch: boolean; inclusion: boolean; consistency: boolean; headSignature: boolean }
    sequence: number; treeSize: number
  }
  assert.equal(out.ok, true)
  assert.equal(out.checks.leafMatch, true)
  assert.equal(out.checks.inclusion, true, 'entry 0 is proven into the published head the bundle pins')
  assert.equal(out.checks.consistency, true, 'size-1 head -> size-2 head: the prefix proof that makes rewriting detectable')
  assert.equal(out.checks.headSignature, true)
  assert.equal(out.treeSize, 2)
})

test('one flipped character in the recorded leafHash fails leafMatch and exits 1', async () => {
  const record = await recordForEntry0()
  const flipped = (record.leafHash.startsWith('0') ? '1' : '0') + record.leafHash.slice(1)
  assert.notEqual(flipped, record.leafHash)
  const evidenceLog = await fsp.readFile(paths.logPath, 'utf8')
  const bundle = buildBundle(
    { evidenceLog }, paths.workspaceKey, AT,
    { transparency: { ...record, leafHash: flipped } },
  )
  const bundlePath = join(TMP, 'bundle-bad-leaf.json')
  await fsp.writeFile(bundlePath, JSON.stringify(bundle, null, 2), 'utf8')

  const { code, stdout } = await runCli(['verify', '--log', PTL_DIR, '--bundle', bundlePath])
  assert.equal(code, 1)
  const out = parseSingleLine(stdout) as {
    ok: boolean; checks: { leafMatch: boolean; inclusion: boolean }
  }
  assert.equal(out.ok, false)
  assert.equal(out.checks.leafMatch, false)
  assert.equal(out.checks.inclusion, true, 'the position itself is still provably in the tree — only the claimed hash is wrong')
})

test('verify --bundle on a bundle with no transparency record exits 1 with a clean message', async () => {
  const evidenceLog = await fsp.readFile(paths.logPath, 'utf8')
  const plain = buildBundle({ evidenceLog }, paths.workspaceKey, AT)
  const bundlePath = join(TMP, 'bundle-plain.json')
  await fsp.writeFile(bundlePath, JSON.stringify(plain, null, 2), 'utf8')
  const { code, stdout, stderr } = await runCli(['verify', '--log', PTL_DIR, '--bundle', bundlePath])
  assert.equal(code, 1)
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.includes('transparency'), `stderr names the missing record: ${stderr}`)
})

// ---------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------

test('usage errors exit 2 with the usage text and never a stack', async () => {
  const unknown = await runCli(['frobnicate', '--log', PTL_DIR])
  assert.equal(unknown.code, 2)
  assert.ok(unknown.stderr.includes('usage:'), unknown.stderr)
  assert.ok(unknown.stderr.includes('unknown subcommand'))

  const missingLog = await runCli(['head'])
  assert.equal(missingLog.code, 2)
  assert.ok(missingLog.stderr.includes('--log <dir> is required'))

  const danglingValue = await runCli(['verify', '--log', PTL_DIR, '--bundle'])
  assert.equal(danglingValue.code, 2)
  assert.ok(danglingValue.stderr.includes('--bundle requires a value'))

  const foreignOption = await runCli(['append', '--log', PTL_DIR, '--bundle', 'x.json'])
  assert.equal(foreignOption.code, 2)
  assert.ok(foreignOption.stderr.includes('only applies to verify'))

  for (const result of [unknown, missingLog, danglingValue, foreignOption]) {
    assert.equal(result.stdout.trim().length, 0)
    assert.ok(!result.stderr.includes('    at '), 'no stack traces in usage errors')
  }
})

test('the operator key never materialises as a side effect of verify', async () => {
  // A fresh log directory verified against a key directory that does not
  // exist: checking must not mint an identity the log will later have to
  // honour. (--operator-key takes a directory since v0.22.)
  const neverAppended = join(TMP, 'ptl-never-appended')
  await fsp.mkdir(neverAppended, { recursive: true })
  const absentKeyDir = join(TMP, 'absent-operator-key')
  const { code, stdout } = await runCli(['verify', '--log', neverAppended, '--operator-key', absentKeyDir])
  assert.equal(code, 1, 'no head at all is a failed self-check, not an empty pass')
  const out = parseSingleLine(stdout) as { ok: boolean; treeSize: number; checks: { rootMatch: boolean } }
  assert.equal(out.ok, false)
  assert.equal(out.treeSize, 0)
  assert.equal(out.checks.rootMatch, false)
  await assert.rejects(fsp.stat(absentKeyDir), 'verify must not create the key directory')
})

// ---------------------------------------------------------------------------
// v0.22 adversarial additions — publication trust root (H-06) and the
// verify --bundle signature/absence holes (H-07).
// ---------------------------------------------------------------------------

test('H-06: a foreign-keyId checkpoint appended to the workspace log is never what gets published', async () => {
  // The attacker appends a well-formed, self-consistent checkpoint under its
  // own keyId at the tail of the workspace log. The old selection rule
  // (findLast of any signed checkpoint) would publish THE ATTACKER'S
  // checkpoint; the anchor-gated rule must publish the anchored key's.
  const logPath = paths.logPath
  const lines = (await fsp.readFile(logPath, 'utf8')).split('\n').filter(l => l.trim().length > 0)
  const walk0 = walkChain(lines)
  const lastLine = lines[lines.length - 1] as string
  const attackerEnvelope = JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: '2026-10-06T00:00:00.000Z',
    prev: lineDigest(lastLine),
    payload: { count: walk0.records, head: sha256Hex('attacker-head'), workspaceKey: paths.workspaceKey, at: '2026-10-06T00:00:00.000Z' },
    sig: 'AAAA-attacker-sig',
    keyId: 'attacker-key',
  })
  await fsp.writeFile(logPath, `${[...lines, attackerEnvelope].join('\n')}\n`, 'utf8')
  try {
    const attackDir = join(TMP, 'ptl-attack')
    const { code, stdout, stderr } = await runCli(['append', '--log', attackDir])
    assert.equal(code, 0, `stderr: ${stderr}`)
    const out = parseSingleLine(stdout) as { sequence: number; treeSize: number }
    assert.equal(out.treeSize, 1)
    const published = JSON.parse(
      (await fsp.readFile(join(attackDir, 'ptl-entries.jsonl'), 'utf8')).split('\n')[0] as string,
    ) as { keyId: string; sig: string; count: number }
    const honest = walk0.checkpoints.findLast(cp => cp.keyId === engineKeyId)
    assert.ok(honest !== undefined)
    assert.equal(published.keyId, engineKeyId, 'the anchored key\'s checkpoint is the publication, not the positional tail')
    assert.equal(published.count, honest.payload.count)
    assert.match(published.sig, /^[A-Za-z0-9+/]+={0,2}$/, 'the honest signature rode along — the attacker\'s never entered the tree')
  } finally {
    // Restore the honest tail so later tests see the pristine log.
    await fsp.writeFile(logPath, `${lines.join('\n')}\n`, 'utf8')
  }
})

test('H-06: no anchor and no engine key on hand is a loud refusal, not a best-effort publish', async () => {
  // A workspace whose checkpoints are signed but whose anchor never landed
  // (no anchorPath configured), audited from a trust root that holds no
  // engine key: there is no trust root to publish under, and the CLI says
  // so instead of notarising whoever last wrote to the log.
  const wsRoot = join(TMP, 'ws-no-anchor')
  const trustRoot = join(TMP, 'trust-no-anchor')
  await fsp.mkdir(wsRoot, { recursive: true })
  await fsp.mkdir(trustRoot, { recursive: true })
  const noAnchorPaths = deriveProofPaths({ root: wsRoot, trustRoot, evidenceStore: 'host' })
  const noAnchorStore = new EvidenceStore(nodeFs, noAnchorPaths.logPath, noAnchorPaths.baselinePath, new FakeClock(), {
    signer: async () => fakeSigner,
    workspaceKey: noAnchorPaths.workspaceKey,
    checkpointEvery: 1000,
  })
  await noAnchorStore.append(evidence('n1'))
  await noAnchorStore.checkpoint()
  await assert.rejects(fsp.stat(join(trustRoot, 'anchors', noAnchorPaths.workspaceKey, 'anchor.json')), 'fixture: no anchor on record')
  await assert.rejects(fsp.stat(join(trustRoot, 'keys')), 'fixture: no engine key on record')

  const { code, stdout, stderr } = await runCli(
    ['append', '--log', join(TMP, 'ptl-no-anchor')],
    { DSH_PROOF_ROOT: wsRoot, DSH_PROOF_TRUST_DIR: trustRoot },
  )
  assert.equal(code, 1)
  assert.equal(stdout.trim().length, 0, 'a refusal prints nothing on stdout')
  assert.ok(stderr.includes('no trust root'), `stderr names the missing trust root: ${stderr}`)
  assert.ok(!stderr.includes('at '), 'no stack traces, ever')
})

test('H-07a: a flipped byte in the bundle-pinned publishedHead.sig fails the publication-signature check', async () => {
  const record = await recordForEntry0()
  const tamperedSig = `x${record.publishedHead.sig.slice(1)}`
  assert.notEqual(tamperedSig, record.publishedHead.sig)
  const evidenceLog = await fsp.readFile(paths.logPath, 'utf8')
  const bundle = buildBundle(
    { evidenceLog }, paths.workspaceKey, AT,
    { transparency: { ...record, publishedHead: { ...record.publishedHead, sig: tamperedSig } } },
  )
  const bundlePath = join(TMP, 'bundle-bad-head-sig.json')
  await fsp.writeFile(bundlePath, JSON.stringify(bundle, null, 2), 'utf8')

  const { code, stdout } = await runCli(['verify', '--log', PTL_DIR, '--bundle', bundlePath])
  assert.equal(code, 1)
  const out = parseSingleLine(stdout) as {
    ok: boolean; checks: { leafMatch: boolean; inclusion: boolean; publishedHeadSig: boolean }
  }
  assert.equal(out.ok, false)
  assert.equal(out.checks.leafMatch, true, 'the leaf itself is honest — only the publication proof is forged')
  assert.equal(out.checks.inclusion, true)
  assert.equal(out.checks.publishedHeadSig, false, '"the operator signed this head" is a signed claim, and the signature is checked')
})

test('H-07a: without an operator key the publication signature is reported NOT verified and the verification fails', async () => {
  const bundlePath = join(TMP, 'bundle.json')
  const { code, stdout } = await runCli(
    ['verify', '--log', PTL_DIR, '--bundle', bundlePath, '--operator-key', join(TMP, 'no-such-operator-key')],
  )
  assert.equal(code, 1, 'uncertain = failed: a publication proof nobody verified must not pass silently')
  const out = parseSingleLine(stdout) as {
    ok: boolean
    checks: { leafMatch: boolean; inclusion: boolean; publishedHeadSig: string }
    notes: string[]
  }
  assert.equal(out.ok, false)
  assert.equal(out.checks.leafMatch, true)
  assert.equal(out.checks.inclusion, true)
  assert.equal(out.checks.publishedHeadSig, 'not-checked (operator key absent)')
  assert.ok(
    out.notes.some(n => n.includes('NOT verified')),
    `the absence is stated explicitly, got ${JSON.stringify(out.notes)}`,
  )
})

test('H-07b: a deleted sth.json fails bundle verification — a claimed publication must reconcile with the present', async () => {
  // Clone the log directory without sth.json: entries intact, head gone.
  const headless = join(TMP, 'ptl-headless')
  await fsp.mkdir(headless, { recursive: true })
  await fsp.copyFile(join(PTL_DIR, 'ptl-entries.jsonl'), join(headless, 'ptl-entries.jsonl'))
  const bundlePath = join(TMP, 'bundle.json')
  const { code, stdout } = await runCli(['verify', '--log', headless, '--bundle', bundlePath])
  assert.equal(code, 1, '"published then, promised nothing now" is a failure, not a pass')
  const out = parseSingleLine(stdout) as {
    ok: boolean
    checks: { leafMatch: boolean; inclusion: boolean; consistency: boolean }
    notes: string[]
  }
  assert.equal(out.ok, false)
  assert.equal(out.checks.leafMatch, true)
  assert.equal(out.checks.inclusion, true, 'inclusion pins the PUBLISHED head — it survives the current head\'s absence')
  assert.equal(out.checks.consistency, false)
  assert.ok(out.notes.some(n => n.includes('no current signed head')), JSON.stringify(out.notes))
})

test('H-07c/M-63: a sth that promises more entries than the log holds is adjudicated, and the rewind branch speaks', async () => {
  // Clone the log, then over-commit the head: treeSize beyond the file.
  const overcommitted = join(TMP, 'ptl-overcommitted')
  await fsp.mkdir(overcommitted, { recursive: true })
  await fsp.copyFile(join(PTL_DIR, 'ptl-entries.jsonl'), join(overcommitted, 'ptl-entries.jsonl'))
  const { sth } = await logSnapshot()
  assert.ok(sth !== undefined)
  const bloated = { ...sth, treeSize: sth.treeSize + 500 }
  await fsp.writeFile(join(overcommitted, 'sth.json'), JSON.stringify(bloated), 'utf8')

  const bundlePath = join(TMP, 'bundle.json')
  const over = await runCli(['verify', '--log', overcommitted, '--bundle', bundlePath])
  assert.equal(over.code, 1)
  const overOut = parseSingleLine(over.stdout) as { ok: boolean; checks: { consistency: boolean }; notes: string[] }
  assert.equal(overOut.ok, false)
  assert.equal(overOut.checks.consistency, false)
  assert.ok(overOut.notes.some(n => n.includes('head and log are disconnected')), `got ${JSON.stringify(overOut.notes)}`)

  // And the rewind branch (published head LONGER than the current head) is
  // no longer a silent false: the note names the rewind. The scenario: a
  // bundle pinning the CURRENT two-entry head, verified against a log whose
  // head promises only one entry — the classic "unpublish" shape.
  const shrunk = join(TMP, 'ptl-shrunk')
  await fsp.mkdir(shrunk, { recursive: true })
  const snapshot = await logSnapshot()
  const entriesNow = (await fsp.readFile(join(PTL_DIR, 'ptl-entries.jsonl'), 'utf8')).split('\n').filter(l => l.length > 0)
  assert.ok(snapshot.sth !== undefined && snapshot.sth.treeSize >= 2, 'fixture: the shared log has grown past one entry')
  await fsp.writeFile(join(shrunk, 'ptl-entries.jsonl'), `${entriesNow.slice(0, 1).join('\n')}\n`, 'utf8')
  await fsp.writeFile(join(shrunk, 'sth.json'), JSON.stringify({ ...snapshot.sth, treeSize: 1 }), 'utf8')
  const pinnedCurrent = await recordForEntry0()
  const shrunkBundle = buildBundle(
    { evidenceLog: await fsp.readFile(paths.logPath, 'utf8') }, paths.workspaceKey, AT,
    { transparency: pinnedCurrent },
  )
  const shrunkBundlePath = join(TMP, 'bundle-pins-current.json')
  await fsp.writeFile(shrunkBundlePath, JSON.stringify(shrunkBundle, null, 2), 'utf8')
  const rewind = await runCli(['verify', '--log', shrunk, '--bundle', shrunkBundlePath])
  assert.equal(rewind.code, 1)
  const rewindOut = parseSingleLine(rewind.stdout) as { checks: { consistency: boolean }; notes: string[] }
  assert.equal(rewindOut.checks.consistency, false)
  assert.ok(rewindOut.notes.some(n => n.includes('rewound')), `got ${JSON.stringify(rewindOut.notes)}`)
})

// ---------------------------------------------------------------------------
// v0.23 fix batch — the publication trust-root holes this CLI closed:
// X-H-10 (planted sth.json laundering), X-H-11 (must-verify selection: the
// no-key-material refusal and the tail-twin publication DoS), W9-M4 (a
// disarmed anchor is a refusal, never a silent no-anchor publish), W9-M5
// (cross-workspace identity laundering), W9-M6 (operator key before the log
// is touched — no half-published entry), W9-M6b (self-verify: uncertain =
// fail without the operator key), W9-M9 (badLines surfaced in verify).
// ---------------------------------------------------------------------------

test('X-H-10: a planted sth.json whose signature does not verify stops the publish — the operator never launders it', async () => {
  // The attacker rewrites the entries into a forged history AND plants a
  // self-consistent head over it (correct size, correct forged root, garbage
  // signature). Consistency from the planted head would "prove" fine — the
  // proof is minted from the same planted bytes — so the signature gate is
  // the only thing standing between the forgery and a genuine operator
  // signature over it.
  const plantedDir = join(TMP, 'ptl-planted-sth')
  await fsp.mkdir(plantedDir, { recursive: true })
  const forged = [forgedEntry(0), forgedEntry(1), forgedEntry(2)]
  await fsp.writeFile(join(plantedDir, 'ptl-entries.jsonl'), `${forged.map(e => canonicalJson(e)).join('\n')}\n`, 'utf8')
  const { sth: honest } = await logSnapshot()
  assert.ok(honest !== undefined, 'fixture: the shared log has a signed head (its logId is the operator identity)')
  const planted = {
    logId: honest.logId,
    treeSize: forged.length,
    root: new TransparencyLog(forged).merkleRoot(),
    at: '2026-10-06T05:00:00.000Z',
    sig: 'QUFBQQ==', // garbage — the attacker signed nothing
  }
  await fsp.writeFile(join(plantedDir, 'sth.json'), JSON.stringify(planted), 'utf8')

  const { code, stdout, stderr } = await runCli(['append', '--log', plantedDir])
  assert.equal(code, 1, 'the operator refuses to extend a head nobody can vouch for')
  assert.equal(stdout.trim().length, 0, 'a refusal prints nothing on stdout')
  assert.ok(stderr.includes('does not verify'), `stderr names the forgery: ${stderr}`)
  assert.ok(stderr.includes('out-of-band'), `stderr names the remedy: ${stderr}`)
  // The planted head is untouched by the refusal.
  const after = JSON.parse(await fsp.readFile(join(plantedDir, 'sth.json'), 'utf8')) as { sig: string }
  assert.equal(after.sig, 'QUFBQQ==', 'the refusal wrote nothing')
})

test('W9-M4: a disarmed anchor (stripped signature) is a loud refusal, never a silent no-anchor publish', async () => {
  const anchorPath = paths.anchorPath
  const honestAnchor = await fsp.readFile(anchorPath, 'utf8')
  try {
    const disarmed = { ...(JSON.parse(honestAnchor) as Record<string, unknown>), sig: '' }
    await fsp.writeFile(anchorPath, JSON.stringify(disarmed), 'utf8')
    const refusalDir = join(TMP, 'ptl-disarmed-anchor')
    const { code, stdout, stderr } = await runCli(['append', '--log', refusalDir])
    assert.equal(code, 1, 'a damaged anchor is tampering until proven otherwise')
    assert.equal(stdout.trim().length, 0)
    assert.ok(stderr.includes('DISARMED'), `the refusal names the disarmed anchor: ${stderr}`)
    await assert.rejects(fsp.stat(join(refusalDir, 'ptl-entries.jsonl')), 'nothing was published while the trust root was disarmed')
  } finally {
    await fsp.writeFile(anchorPath, honestAnchor, 'utf8')
  }
})

test('X-H-11: an anchor naming a key this host holds no material for is a loud refusal — keyId matching alone proves nothing', async () => {
  // The workspace's checkpoints are signed (by a key this host genuinely
  // cannot load — the fixture's deterministic signer, whose material does
  // NOT live under this trust root's keys directory), and the anchor names
  // that key. The old rule matched the keyId string and published without
  // ever verifying anything; the new rule refuses and says what to provide.
  const wsRoot = join(TMP, 'ws-foreign-anchor')
  const trustRoot = join(TMP, 'trust-foreign-anchor')
  await fsp.mkdir(wsRoot, { recursive: true })
  await fsp.mkdir(trustRoot, { recursive: true })
  const fPaths = deriveProofPaths({ root: wsRoot, trustRoot, evidenceStore: 'host' })
  const fStore = new EvidenceStore(nodeFs, fPaths.logPath, fPaths.baselinePath, new FakeClock(), {
    signer: async () => fakeSigner,
    anchorPath: fPaths.anchorPath,
    workspaceKey: fPaths.workspaceKey,
    checkpointEvery: 1000,
  })
  await fStore.append(evidence('f1'))
  await fStore.checkpoint()
  await assert.rejects(fsp.stat(join(trustRoot, 'keys')), 'fixture: no engine key material at this trust root')

  const { code, stdout, stderr } = await runCli(
    ['append', '--log', join(TMP, 'ptl-foreign-anchor')],
    { DSH_PROOF_ROOT: wsRoot, DSH_PROOF_TRUST_DIR: trustRoot },
  )
  assert.equal(code, 1)
  assert.equal(stdout.trim().length, 0, 'a refusal prints nothing on stdout')
  assert.ok(stderr.includes('no key material'), `stderr names the missing capability: ${stderr}`)
  assert.ok(!stderr.includes('    at '), 'no stack traces, ever')
})

test('X-H-11/W9-M5: a garbage-signature twin at the tail cannot brick publication — the scan-back finds the earlier verifiable checkpoint', async () => {
  // The attacker appends a well-formed checkpoint CLAIMING the anchored
  // keyId with a garbage signature at the positional tail. The old rule
  // (findLast + one-shot veto) refused to publish anything ever again; the
  // new rule scans back to the newest checkpoint that actually verifies.
  const logPath = paths.logPath
  const lines = (await fsp.readFile(logPath, 'utf8')).split('\n').filter(l => l.trim().length > 0)
  const walk0 = walkChain(lines)
  const lastLine = lines[lines.length - 1] as string
  const twin = JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: AT,
    prev: lineDigest(lastLine),
    payload: { count: walk0.records, head: sha256Hex('twin-head'), workspaceKey: paths.workspaceKey, at: AT },
    sig: 'QUFBQQ==', // claims the anchored key, signs nothing
    keyId: engineKeyId,
  })
  await fsp.writeFile(logPath, `${[...lines, twin].join('\n')}\n`, 'utf8')
  try {
    const twinDir = join(TMP, 'ptl-tail-twin')
    const { code, stdout, stderr } = await runCli(['append', '--log', twinDir])
    assert.equal(code, 0, `the earlier honest checkpoint is still publishable: ${stderr}`)
    const out = parseSingleLine(stdout) as { sequence: number; treeSize: number }
    assert.equal(out.treeSize, 1)
    const published = JSON.parse(
      (await fsp.readFile(join(twinDir, 'ptl-entries.jsonl'), 'utf8')).split('\n')[0] as string,
    ) as { sig: string; keyId: string }
    assert.equal(published.keyId, engineKeyId, 'the anchored key\'s honest checkpoint is the publication')
    assert.match(published.sig, /^[A-Za-z0-9+/]+={0,2}$/, 'the VERIFIED checkpoint was published, not the positional-last twin')
  } finally {
    // Restore the honest tail so later tests see the pristine log.
    await fsp.writeFile(logPath, `${lines.join('\n')}\n`, 'utf8')
  }
})

test('W9-M5: a checkpoint signed for a FOREIGN workspace identity is refused, not laundered', async () => {
  // A one-line chain whose checkpoint is genuinely signed by this trust
  // root's engine key — for a DIFFERENT workspace. Without the cross-check,
  // copying workspace A's chain into workspace B published A's signed
  // checkpoint under B's identity; the log is a notary, not a laundering
  // service.
  const wsRoot = join(TMP, 'ws-cross')
  const trustRoot = join(TMP, 'trust-cross')
  await fsp.mkdir(wsRoot, { recursive: true })
  const cPaths = deriveProofPaths({ root: wsRoot, trustRoot, evidenceStore: 'host' })
  const key = await NodeEd25519Signer.load(join(trustRoot, 'keys'))
  // v0.24 (Y-H-01): the fixture's head is now the HONEST genesis digest — the
  // position must not lie, or the head-liar filter (a different, earlier
  // refusal) answers instead of the workspace cross-check under test.
  const payload = { count: 0, head: GENESIS_PREV, workspaceKey: 'ws-somewhere-else', at: AT }
  const envelope = {
    v: 2,
    kind: 'checkpoint',
    at: AT,
    prev: GENESIS_PREV,
    payload,
    sig: await key.sign(checkpointSignedData(payload)),
    keyId: key.keyId,
  }
  await fsp.mkdir(join(cPaths.logPath, '..'), { recursive: true })
  await fsp.writeFile(cPaths.logPath, `${JSON.stringify(envelope)}\n`, 'utf8')
  const { code, stdout, stderr } = await runCli(
    ['append', '--log', join(TMP, 'ptl-cross')],
    { DSH_PROOF_ROOT: wsRoot, DSH_PROOF_TRUST_DIR: trustRoot },
  )
  assert.equal(code, 1)
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.includes('signed for workspace'), `the refusal names the identity mismatch: ${stderr}`)
})

test('W9-M6: an operator key that cannot be loaded fails BEFORE the log is touched — no half-published entry', async () => {
  const keyAsFile = join(TMP, 'operator-key-as-file')
  await fsp.writeFile(keyAsFile, 'not a directory', 'utf8')
  const fresh = join(TMP, 'ptl-operator-first')
  await fsp.mkdir(fresh, { recursive: true })
  const { code, stdout, stderr } = await runCli(['append', '--log', fresh, '--operator-key', keyAsFile])
  assert.equal(code, 1, 'loading a key from a path that is a file fails loudly')
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.length > 0, 'the failure speaks')
  await assert.rejects(fsp.stat(join(fresh, 'ptl-entries.jsonl')), 'no entry was appended — the half-published state is unreachable')
})

test('W9-M6b: self-verify without the operator key FAILS — uncertain = fail on the no-bundle face too', async () => {
  const { code, stdout, stderr } = await runCli(['verify', '--log', PTL_DIR, '--operator-key', join(TMP, 'no-such-operator-key')])
  assert.equal(code, 1, `a head nobody verified must not carry a green self-check: ${stderr}`)
  const out = parseSingleLine(stdout) as {
    ok: boolean
    checks: { rootMatch: boolean; headSignature?: boolean }
    notes: string[]
  }
  assert.equal(out.ok, false)
  assert.equal(out.checks.rootMatch, true, 'the tree itself is honest — the failure is the unadjudicated signature')
  assert.equal(out.checks.headSignature, undefined, 'headSignature stays absent: never guessed')
  assert.ok(
    out.notes.some(n => n.includes('operator key absent') && n.includes('uncertain')),
    `the absence is stated as a failure: ${JSON.stringify(out.notes)}`,
  )
})

test('W9-M9: malformed lines in the entries file are surfaced and fail the self-check', async () => {
  const damaged = join(TMP, 'ptl-badlines')
  await fsp.mkdir(damaged, { recursive: true })
  await fsp.copyFile(join(PTL_DIR, 'ptl-entries.jsonl'), join(damaged, 'ptl-entries.jsonl'))
  await fsp.copyFile(join(PTL_DIR, 'sth.json'), join(damaged, 'sth.json'))
  // Insert a garbage line AFTER the honest entries: no entry moves, the root
  // still matches — the old self-check was blind to exactly this damage.
  await fsp.appendFile(join(damaged, 'ptl-entries.jsonl'), 'this line is not json at all\n', 'utf8')
  const { code, stdout } = await runCli(['verify', '--log', damaged])
  assert.equal(code, 1)
  const out = parseSingleLine(stdout) as {
    ok: boolean
    badLines: number
    checks: { rootMatch: boolean }
    notes: string[]
  }
  assert.equal(out.ok, false, 'physical damage the tree cannot speak for fails the audit')
  assert.equal(out.badLines, 1, 'the damage is counted in the output')
  assert.equal(out.checks.rootMatch, true, 'the readable prefix still agrees with the head — the damage is named, not smeared')
  assert.ok(out.notes.some(n => n.includes('malformed')), JSON.stringify(out.notes))
})

// ---------------------------------------------------------------------------
// v0.24 fix batch — Y-H-01 (a genuinely-signed checkpoint at a lying chain
// position is never publishable: the CLI half of the publish predicate
// `verified && !headLiared`), V4-M5 (the stored-head refusals fire BEFORE
// the log is touched: rotation and unparseable bytes never leave a
// half-published entry), V4-L10 (an empty log's self-check failure names
// the state), V4-L12 (a repeated flag is a loud usage error, not a silent
// last-wins).
// ---------------------------------------------------------------------------

test('Y-H-01: a genuinely-signed checkpoint transplanted to a lying position is never published', async () => {
  // The transplant: a REAL engine-key signature over a payload whose `head`
  // was computed for another position (or nothing at all). The count is
  // honest for the tail and `prev` chains correctly, so the walk calls the
  // line well-formed — only the head-field lies about where the chain is.
  // The signature VERIFIES (it is real), so the newest-first scan used to
  // pick it: a position forgery wearing a genuine key into the public log.
  const logPath = paths.logPath
  const lines = (await fsp.readFile(logPath, 'utf8')).split('\n').filter(l => l.trim().length > 0)
  const walk0 = walkChain(lines)
  const lastLine = lines[lines.length - 1] as string
  const key = await NodeEd25519Signer.load(join(TRUST_DIR, 'keys'))
  const payload = { count: walk0.records, head: sha256Hex('transplanted-head'), workspaceKey: paths.workspaceKey, at: AT }
  const transplant = JSON.stringify({
    v: 2,
    kind: 'checkpoint',
    at: AT,
    prev: lineDigest(lastLine),
    payload,
    sig: await key.sign(checkpointSignedData(payload)), // genuinely signed
    keyId: key.keyId,
  })
  await fsp.writeFile(logPath, `${[...lines, transplant].join('\n')}\n`, 'utf8')
  try {
    const dir = join(TMP, 'ptl-transplant')
    const { code, stdout, stderr } = await runCli(['append', '--log', dir])
    assert.equal(code, 0, `the earlier honestly-positioned checkpoint still publishes: ${stderr}`)
    const out = parseSingleLine(stdout) as { sequence: number; treeSize: number }
    assert.equal(out.treeSize, 1)
    const published = JSON.parse(
      (await fsp.readFile(join(dir, 'ptl-entries.jsonl'), 'utf8')).split('\n')[0] as string,
    ) as { keyId: string; head: string; count: number }
    assert.equal(published.keyId, engineKeyId)
    assert.notEqual(published.head, sha256Hex('transplanted-head'), 'the position liar never entered the public log')
    const honest = walk0.checkpoints.findLast(cp => cp.keyId === engineKeyId && !cp.headLiared)
    assert.ok(honest !== undefined, 'fixture: an honestly-positioned checkpoint exists under the engine key')
    assert.equal(published.head, honest.payload.head, 'the newest HONESTLY-POSITIONED checkpoint is the publication')
    assert.equal(published.count, honest.payload.count)
  } finally {
    // Restore the honest tail so later tests see the pristine log.
    await fsp.writeFile(logPath, `${lines.join('\n')}\n`, 'utf8')
  }
})

test('Y-H-01: a chain whose ONLY checkpoint is positionally lying is a loud refusal, never a publish', async () => {
  const wsRoot = join(TMP, 'ws-liar-only')
  const trustRoot = join(TMP, 'trust-liar-only')
  await fsp.mkdir(wsRoot, { recursive: true })
  const key = await NodeEd25519Signer.load(join(trustRoot, 'keys'))
  const lPaths = deriveProofPaths({ root: wsRoot, trustRoot, evidenceStore: 'host' })
  // One checkpoint at genesis: count honest (0 records), signature genuine,
  // `head` a lie about what the chain's first position hashes to.
  const payload = { count: 0, head: sha256Hex('genesis-lie'), workspaceKey: lPaths.workspaceKey, at: AT }
  const envelope = {
    v: 2,
    kind: 'checkpoint',
    at: AT,
    prev: GENESIS_PREV,
    payload,
    sig: await key.sign(checkpointSignedData(payload)),
    keyId: key.keyId,
  }
  await fsp.mkdir(join(lPaths.logPath, '..'), { recursive: true })
  await fsp.writeFile(lPaths.logPath, `${JSON.stringify(envelope)}\n`, 'utf8')
  const { code, stdout, stderr } = await runCli(
    ['append', '--log', join(TMP, 'ptl-liar-only')],
    { DSH_PROOF_ROOT: wsRoot, DSH_PROOF_TRUST_DIR: trustRoot },
  )
  assert.equal(code, 1, 'a genuine signature over a lying position is a forgery of position')
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.includes('swears a chain head its own position contradicts'), `names the position forgery: ${stderr}`)
  assert.ok(!stderr.includes('    at '), 'no stack traces, ever')
})

test('V4-M5: logId rotation is refused BEFORE the log is touched — no half-published entry', async () => {
  // A log whose stored head names a DIFFERENT operator (a re-keyed or
  // foreign-run directory). savePtlHead's rotation gate fires at head-write
  // time — which is AFTER the append — so without the preflight the entry
  // landed on the public log with no valid head over it: the exact
  // half-published state the fronting order promises never to produce.
  const rotated = join(TMP, 'ptl-rotated')
  await fsp.mkdir(rotated, { recursive: true })
  const otherOperator = await NodeEd25519Signer.load(join(TMP, 'other-operator-key'))
  const otherUnsigned = { logId: otherOperator.keyId, treeSize: 1, root: sha256Hex('any-root'), at: AT }
  await fsp.writeFile(
    join(rotated, 'sth.json'),
    JSON.stringify({ ...otherUnsigned, sig: await otherOperator.sign(sthSignedData(otherUnsigned)) }),
    'utf8',
  )

  const { code, stdout, stderr } = await runCli(['append', '--log', rotated])
  assert.equal(code, 1, 'the operator identity auditors pin may not flip mid-log')
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.includes('refusing to change the transparency log operator'), `names the rotation: ${stderr}`)
  assert.ok(stderr.includes('BEFORE anything was appended'), `the pre-mutation side of the gate speaks: ${stderr}`)
  await assert.rejects(fsp.stat(join(rotated, 'ptl-entries.jsonl')), 'no entry was appended — the half-published state is unreachable')
})

test('Y-H-06 (CLI): unparseable bytes planted in sth.json refuse the publish BEFORE any entry lands', async () => {
  const garbage = join(TMP, 'ptl-garbage-head')
  await fsp.mkdir(garbage, { recursive: true })
  await fsp.writeFile(join(garbage, 'sth.json'), '{oops', 'utf8')
  const { code, stdout, stderr } = await runCli(['append', '--log', garbage])
  assert.equal(code, 1, 'unparseable is not "no head on record" (cold start)')
  assert.equal(stdout.trim().length, 0)
  assert.ok(stderr.includes('not a parseable signed tree head'), `names the unreadable commitment: ${stderr}`)
  await assert.rejects(fsp.stat(join(garbage, 'ptl-entries.jsonl')), 'no entry was appended behind an unreadable prior commitment')
})

test('V4-L10: self-verify on an empty log names the state instead of failing wordlessly', async () => {
  const emptyLog = join(TMP, 'ptl-empty-note')
  await fsp.mkdir(emptyLog, { recursive: true })
  const { code, stdout } = await runCli(['verify', '--log', emptyLog])
  assert.equal(code, 1, 'a self-check of nothing is not a pass')
  const out = parseSingleLine(stdout) as {
    ok: boolean
    treeSize: number
    checks: { rootMatch: boolean }
    notes: string[]
  }
  assert.equal(out.ok, false)
  assert.equal(out.treeSize, 0)
  assert.equal(out.checks.rootMatch, false)
  assert.ok(
    out.notes.some(n => n.includes('nothing has been published to this log yet')),
    `the empty state is named, not smeared: ${JSON.stringify(out.notes)}`,
  )
})

test('V4-L12: a repeated flag is a loud usage error, not a silent last-wins', async () => {
  const firstLog = join(TMP, 'ptl-dup-first')
  const secondLog = join(TMP, 'ptl-dup-second')
  const dup = await runCli(['append', '--log', firstLog, '--log', secondLog])
  assert.equal(dup.code, 2)
  assert.ok(dup.stderr.includes('duplicate flag: --log'), `names the duplicate: ${dup.stderr}`)
  assert.equal(dup.stdout.trim().length, 0)
  await assert.rejects(fsp.stat(join(firstLog, 'ptl-entries.jsonl')), 'the first spelling was never published to')
  await assert.rejects(fsp.stat(join(secondLog, 'ptl-entries.jsonl')), 'the last spelling never silently won either')
  // The verify face refuses duplicates the same way.
  const dupBundle = await runCli(['verify', '--log', PTL_DIR, '--bundle', 'a.json', '--bundle', 'b.json'])
  assert.equal(dupBundle.code, 2)
  assert.ok(dupBundle.stderr.includes('duplicate flag: --bundle'))
})

