/**
 * CLAIM-CONTRACT TESTS (v0.24) — 让架构主张的落空在 951 绿下当场变红。
 *
 * MISSION. This file pins the v0.23/v0.24 ARCHITECTURAL CLAIMS to their
 * production call surfaces. The v0.23 survey's meta-finding was the
 * "documentation-code-test triple lie": the same unfulfilled promise was
 * written in README, in code comments and in green tests at once, so a claim
 * could rot at 0% fulfillment while the suite stayed green. Every test here
 * therefore checks the CLAIM, not the spelling a fixer chose: static checks
 * read src/ with readFileSync+regex over precise, documented signatures
 * (why this signature and not a looser one is argued per test), behavioral
 * checks drive the real production entry points. If a claim regresses to
 * "built but unconsumed", the suite goes red HERE, in the file whose only
 * job is to notice.
 *
 * OWNERSHIP: this file only. No src/ file is modified by this batch.
 *
 * PARALLEL-FIX DEPENDENCIES (assertions that are red until the matching
 * v0.24 fix lands, recorded here so a red run is legible):
 *   - #2 (Bayes knobs at the construction boundary) — waits on the
 *     validateBayesKnobs wiring in the engine constructor + the config
 *     schema's syntheticFalsePass open interval.
 *   - #3 (one fold) — waits on the engine's export-confinement fold and
 *     index.ts's trustRoot hand-fold retiring into paths.ts foldHostPath.
 *   - #1b (the raw readMarkers import gone from src/) — waits on the last
 *     raw-door consumers (engine's raw position pass, index.ts, dsh/tools.ts,
 *     the two adapter faces) finishing their migration.
 *   - #5b (PROTOCOL.md reference row) — waits on the doc face catching up
 *     to the package version.
 * The claims as asserted are the TRUE end-state semantics; none was relaxed
 * to fit the pre-fix tree.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { Config } from '../src/config.ts'
import {
  createVerifiedView, EvidenceStore, isProtectedMarkerLabel, makeEvidence, snapshotWorkspace,
} from '../src/core/evidence.ts'
import { lineDigest } from '../src/core/trust.ts'
import { sha256 } from '../src/core/hash.ts'
import { loadPtl } from '../src/core/transparency.ts'
import { MCP_DEFAULT_VERSION, markerPayloads } from '../src/app/mcp-server.ts'
import type { McpEngineDeps } from '../src/app/mcp-server.ts'
import { ProofEngine } from '../src/engine.ts'
import type { SignerPort } from '../src/core/ports.ts'
import { FakeClock, FakeCommands, FakeWorkspace, MemoryFs } from './helpers.ts'

// ---------------------------------------------------------------------------
// Shared fixture vocabulary (same shapes test/05, test/08, test/09 use, so
// this file pins the production surface, not a private re-implementation).
// ---------------------------------------------------------------------------

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url))
const SRC_ROOT = join(REPO_ROOT, 'src')

function srcText(rel: string): string {
  return readFileSync(join(SRC_ROOT, rel), 'utf8')
}

/** Every production .ts file under src/ (the static-contract population). */
function listSrcFiles(): string[] {
  return readdirSync(SRC_ROOT, { recursive: true })
    .map(entry => join(SRC_ROOT, String(entry)))
    .filter(p => p.endsWith('.ts'))
}

const LOG = '/ws/.proof/evidence.jsonl'
const BASE = '/ws/.proof/baseline.json'
const ANCHOR = '/trust/anchors/ws/anchor.json'
const WS = snapshotWorkspace('head1', ['src/a.ts'])

/** Deterministic stand-in host key: the attacker knows its keyId, never its secret. */
class FakeSigner implements SignerPort {
  readonly keyId: string
  constructor(keyId = 'fake-key') { this.keyId = keyId }
  async sign(data: string): Promise<string> { return `sig:${this.keyId}:${sha256(data)}` }
  async verify(data: string, signature: string): Promise<boolean> {
    return signature === `sig:${this.keyId}:${sha256(data)}`
  }
}

function trustedStore(fs: MemoryFs, keyId = 'fake-key') {
  const signer = new FakeSigner(keyId)
  const store = new EvidenceStore(fs, LOG, BASE, new FakeClock(), {
    signer: async () => signer,
    anchorPath: ANCHOR,
    workspaceKey: 'ws',
    checkpointEvery: 1000,
  })
  return { store, signer }
}

function evidence(id: string) {
  return makeEvidence(
    { id, label: id, command: ['npm', 't'], kind: 'test', source: 'config', paths: ['*'], timeoutMs: 10_000 },
    { status: 'pass', exitCode: 0, durationMs: 5, output: 'pass\n' },
    WS,
    new FakeClock(),
  )
}

const PROJECT = {
  '/ws/package.json': JSON.stringify({ name: 'demo', scripts: { test: 'vitest run', build: 'tsc -b' } }),
  '/ws/src/a.ts': 'export const a = 1\n',
  '/ws/src/b.ts': "import { a } from './a'\nexport const b = a + 1\n",
}

/**
 * Re-chain one existing signed checkpoint line at the tail of the log — the
 * Y-H-01 transplant shape: a REAL signature over an honest payload, copied
 * to a position whose predecessor it never saw. Signature verification
 * passes; only the position witness (headLiared on the walk) can object.
 */
function transplantLastCheckpoint(fs: MemoryFs, logPath: string): void {
  const lines = fs.files.get(logPath)?.split('\n').filter(l => l.trim().length > 0) ?? []
  let cpLine: string | undefined
  for (const line of lines) {
    try {
      const env = JSON.parse(line) as { kind?: unknown; sig?: unknown }
      if (env.kind === 'checkpoint' && typeof env.sig === 'string' && env.sig.length > 0) cpLine = line
    } catch { /* not an envelope */ }
  }
  assert.ok(cpLine !== undefined, 'fixture needs at least one signed checkpoint line')
  const cp = JSON.parse(cpLine) as Record<string, unknown>
  const tail = lines.length > 0 ? lineDigest(lines[lines.length - 1] as string) : undefined
  const copy = JSON.stringify({ ...cp, ...(tail !== undefined ? { prev: tail } : {}) })
  fs.mutate(logPath, `${[...lines, copy].join('\n')}\n`)
}

// ---------------------------------------------------------------------------
// Claim 1 — "one door for every trust decision" (README.md:374, :378)
// ---------------------------------------------------------------------------

test('claim 1: the verified view has production consumers, and the bare raw-read door is gone from src/ imports', () => {
  // CLAIM (README.md:378, "The verified read (v0.23.0): one door for every
  // trust decision"): "Every trust consumer now reads the chain through one
  // exported view (`createVerifiedView` in `core/evidence.ts`) ... The raw
  // line-parsing paths are `@internal` now; a future consumer cannot
  // accidentally wire itself to the unverified read".
  //
  // WHY A CONTRACT, NOT A DETAIL: v0.23 built the door and wired nobody to
  // it — engine hand-rolled its own parse+excludeSuspect+fallback twin, the
  // MCP/DSH faces called the raw `readMarkers` export, and the README's
  // "MCP face goes through the same view" was falsifiable line by line while
  // 951 tests stayed green (survey Y-H-03). The contract is not "the view
  // exists" (a unit test already says that) but "the view is CONSUMED by
  // production code, and the raw door is not".
  //
  // SIGNATURES: (1a) engine.ts must IMPORT createVerifiedView from
  // core/evidence.ts AND invoke it (a call site `createVerifiedView(`), or —
  // the accepted alternative fix shape — evidence.ts's own store surface
  // delegates to the view internally (`createVerifiedView(this`, a store
  // method handing itself to the one read layer). A doc-comment mention
  // alone fails the invocation half on purpose. (1b) no src/ file outside
  // core/evidence.ts may IMPORT the bare name `readMarkers` — the regex uses
  // a negative lookbehind for `[_\w]` so the renamed `_readMarkers` escape
  // hatch does not trip it: the claim is the NAME is gone from the import
  // surface ("the clean name is deliberately absent"), not that an
  // underscore-marked internal cannot exist.

  const engine = srcText('engine.ts')
  const evidence = srcText('core/evidence.ts')
  const engineImportsView = /import\s*\{[^}]*\bcreateVerifiedView\b[^}]*\}\s*from\s*['"][^'"]*evidence\.ts['"]/.test(engine)
  const engineCallsView = /\bcreateVerifiedView\s*\(/.test(engine)
  const storeDelegatesInternally = /createVerifiedView\(\s*this\b/.test(evidence)
  assert.ok(
    (engineImportsView && engineCallsView) || storeDelegatesInternally,
    'claim 1a (README.md:378 "one door"): engine.ts must consume createVerifiedView '
    + '(import + call site), or evidence.ts\'s store surface must delegate to the view internally '
    + `(import=${engineImportsView} call=${engineCallsView} storeDelegation=${storeDelegatesInternally})`,
  )

  const importers = listSrcFiles()
    .map(p => p.replace(/\\/g, '/'))
    .filter(p => !p.endsWith('/core/evidence.ts'))
    .filter(p => /import\s*\{[^}]*?(?<![_\w])readMarkers\b[^}]*\}\s*from\s*['"][^'"]*evidence\.ts['"]/.test(readFileSync(p, 'utf8')))
  assert.deepEqual(
    importers.map(p => p.slice(p.lastIndexOf('src/'))),
    [],
    'claim 1b (README.md:378 "raw line-parsing paths are @internal"): the bare '
    + `readMarkers import must be gone from src/ — still importing: ${importers.join(', ')}`,
  )
})

// ---------------------------------------------------------------------------
// Claim 2 — "the Bayes knob domain is validated at every boundary" (README.md:384)
// ---------------------------------------------------------------------------

test('claim 2: Bayes knobs are rejected at the construction boundary — engine certifyTarget:0 and config syntheticFalsePass:0 both throw', () => {
  // CLAIM (README.md:384): "the **Bayes knob domain** is validated at every
  // boundary (`driftedFalsePass` of 0 no longer turns the drift defense into
  // a one-shot certify, `certifyTarget` of 0 no longer collapses the target)".
  // src/core/bayes.ts exports `validateBayesKnobs` "for the engine/config
  // layers to consume at their own construction boundaries".
  //
  // WHY A CONTRACT: in v0.23 the validator existed with ZERO callers —
  // `new ProofEngine({certifyTarget: 0})` constructed silently (one forged
  // pass certified everything), and the config face's `syntheticFalsePass`
  // rode schemastery's CLOSED [0,1] percent() into the engine, where the
  // pure core's RangeError fired mid-verify on first use instead of at
  // configuration time (survey Y-H-04: "validated at every boundary" was
  // written in config comments, tests and README simultaneously — the triple
  // lie). The contract is behavioral: BOTH construction boundaries must
  // refuse the degenerate knob LOUDLY, naming it.
  //
  // NOTE: config's certifyTarget already refuses 0 (schema min 0.01) — that
  // half is pinned as a green control proving the config face CAN refuse.

  assert.throws(
    () => new ProofEngine({
      root: '/ws',
      fs: MemoryFs.of(PROJECT),
      commands: new FakeCommands(),
      workspace: new FakeWorkspace('/ws'),
      certifyTarget: 0,
    }),
    /certifyTarget/,
    'claim 2a (README.md:384): ProofEngine construction must reject certifyTarget 0 '
    + '(validateBayesKnobs belongs on the constructor path, not in a drawer)',
  )

  assert.throws(
    () => Config({ syntheticFalsePass: 0 } as never),
    /syntheticFalsePass/,
    'claim 2b (README.md:384): the plugin config face must reject syntheticFalsePass 0 '
    + '(percent() is a CLOSED [0,1]; β=0 makes one forged pass certify)',
  )

  assert.throws(
    () => Config({ certifyTarget: 0 } as never),
    /certifyTarget/,
    'claim 2 control: the config face\'s certifyTarget domain refusal (green pre-fix) must stay',
  )
})

// ---------------------------------------------------------------------------
// Claim 3 — "one foldHostPath ... is now *the* fold" (README.md:382)
// ---------------------------------------------------------------------------

test('claim 3: foldHostPath is the one fold — engine and index.ts carry no hand-rolled fold twins', () => {
  // CLAIM (README.md:382, "Move three: value scanning, not enumeration"):
  // "one `foldHostPath` (device-namespace prefixes stripped, drive-relative
  // `C:x` projections, case, separators, trailing-dot deformation — every
  // fold that used to live in four disagreeing implementations) is now *the*
  // fold, consumed by the gates, the DSH face and the engine's export
  // confinement alike".
  //
  // WHY A CONTRACT: "alike" is the claim. The gates face consumed the one
  // fold while the engine's export confinement kept a local weak-subset
  // lambda (`const foldHost =` — separator+case only, no `\\?\` strip, no
  // drive-relative projection) and index.ts hand-folded the trust root for
  // its host-store spellings (`const trustFolded = trustRoot.replace(...)`)
  // — exactly the four-half-folds drift the claim says died (survey L-level
  // "engine 弱子集 foldHost lambda", Y-H-12's index.ts straggler).
  //
  // SIGNATURES: engine's twin is pinned by its exact local-binding shape
  // `const foldHost =` (an import of the shared foldHostPath never binds a
  // `const` with that name, so no false positive); the positive half
  // requires engine.ts to reference `foldHostPath` at all. index.ts must
  // import the guard helpers (touchesEvidencePath / foldHostPath) from
  // adapters/shared/paths.ts, and must not hand-fold trustRoot itself (the
  // `const trustFolded = trustRoot.replace` prefix is the exact hand-fold
  // line the audit named; a delegation to the shared fold would not match).

  const engine = srcText('engine.ts')
  assert.ok(!/const\s+foldHost\s*=/.test(engine),
    'claim 3a (README.md:382 "one fold ... alike"): engine.ts must not define a local foldHost lambda — the export confinement folds through paths.ts foldHostPath')
  assert.ok(/\bfoldHostPath\b/.test(engine),
    'claim 3b (README.md:382): engine.ts\'s export confinement must consume the shared foldHostPath')

  const index = srcText('index.ts')
  assert.ok(
    /import\s*\{[^}]*(?:touchesEvidencePath|foldHostPath)[^}]*\}\s*from\s*['"][^'']*shared\/paths\.ts['"]/.test(index),
    'claim 3c (README.md:382 "the DSH face"): index.ts must import the paths.ts guard (touchesEvidencePath/foldHostPath) instead of hand-folding',
  )
  assert.ok(!/const\s+trustFolded\s*=\s*trustRoot\.replace/.test(index),
    'claim 3d (README.md:382): index.ts must not hand-fold the trust root — trustRoot spellings fold through the one foldHostPath')
})

// ---------------------------------------------------------------------------
// Claim 4 — "all the same sweep" (README.md:382)
// ---------------------------------------------------------------------------

test('claim 4: sweepToolInputStrings has exactly one implementation — gates.ts imports the observe.ts sweep', () => {
  // CLAIM (README.md:382): "a mutation-class call has *every string value* it
  // carries swept against the guarded spellings ... all the same sweep."
  // src/dsh/observe.ts exports `sweepToolInputStrings` as the sweep;
  // gates.ts's own docblock names the "one sweep" rule: "dsh/observe.ts
  // exports sweepToolInputStrings with exactly these semantics ... semantics
  // MUST move in lockstep".
  //
  // WHY A CONTRACT: in v0.23 gates.ts carried a VERBATIM LOCAL COPY of the
  // sweep while claiming lockstep — and the copies forked within one
  // release (>8192-char strings: gates dropped them whole, observe kept the
  // head; survey Y-H-10). Two implementations under one promise is the
  // minimal shape of the drift the claim forbids. The contract is greppable:
  // gates.ts must IMPORT the sweep from observe.ts and must not define one.
  //
  // SIGNATURES: the local-copy shape is a function definition
  // (`function sweepToolInputStrings`); the import shape is an import
  // statement binding the same name from a path ending in observe.ts.

  const gates = srcText('adapters/shared/gates.ts')
  assert.ok(!/function\s+sweepToolInputStrings/.test(gates),
    'claim 4a (README.md:382 "all the same sweep"): gates.ts must not define its own sweepToolInputStrings — the local copy is how the two faces forked (Y-H-10)')
  assert.ok(
    /import\s*\{[^}]*\bsweepToolInputStrings\b[^}]*\}\s*from\s*['"][^'']*observe\.ts['"]/.test(gates),
    'claim 4b (README.md:382): gates.ts must import sweepToolInputStrings from dsh/observe.ts — one sweep, one implementation',
  )
})

// ---------------------------------------------------------------------------
// Claim 5 — "serverInfo.version is the package version" (README.md:465)
// ---------------------------------------------------------------------------

test('claim 5: version consistency — MCP_DEFAULT_VERSION and PROTOCOL.md both speak the package version', () => {
  // CLAIM (README.md:465): "The MCP `serverInfo.version` is the package
  // version (v0.16): `initialize` answers with `MCP_DEFAULT_VERSION`, kept
  // in step with `package.json` by release discipline". PROTOCOL.md's header
  // table names this repo as the reference implementation
  // ("Reference implementation | dsh-proof vX.Y.Z") — the doc face of the
  // same release discipline.
  //
  // WHY A CONTRACT: "kept in step by release discipline" is exactly the
  // promise that is invisible when broken — v0.24 shipped with the constant
  // still reading '0.22.0' (and an old test PINNING it there, so the lie was
  // triple-witnessed). Reading package.json at test time and comparing is
  // the discipline, mechanically applied to both the wire constant and the
  // protocol document.

  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { version: string }
  assert.equal(MCP_DEFAULT_VERSION, pkg.version,
    'claim 5a (README.md:465): MCP_DEFAULT_VERSION must equal package.json version '
    + `(${MCP_DEFAULT_VERSION} vs ${pkg.version})`)

  const protocol = readFileSync(join(REPO_ROOT, 'PROTOCOL.md'), 'utf8')
  const row = protocol.match(/^\| Reference implementation\s*\|\s*dsh-proof v(\d+\.\d+\.\d+)/m)
  assert.ok(row !== null, 'claim 5b: PROTOCOL.md header must carry a "Reference implementation | dsh-proof vX.Y.Z" row')
  assert.equal(row[1], pkg.version,
    `claim 5b (README.md:465 release discipline): PROTOCOL.md reference row must speak the package version (${row[1]} vs ${pkg.version})`)
})

// ---------------------------------------------------------------------------
// Claim 6 — the suspect position test covers every trust-consumed label
// (README.md:378; src/core/evidence.ts isProtectedMarkerLabel doc)
// ---------------------------------------------------------------------------

test('claim 6: the protected-marker list covers every label trust decisions consume', () => {
  // CLAIM (README.md:378): the one verified read "applies the suspect
  // position test" for every trust consumer; src/core/evidence.ts defines
  // isProtectedMarkerLabel as "Marker labels whose payloads feed *trust
  // decisions* ... Writes under these labels carry a `headRef` witness;
  // readers can filter by it".
  //
  // WHY A CONTRACT: the position test only exists for labels ON this list.
  // Every label below is consumed last-wins by a production trust decision:
  // attest/* (κ fusion), baseline/* (integrity), delegation/* (DAG),
  // proof/verified (taskVerdict/SLA quotes), claim/jury (jury verdict
  // fusion), economics/quote (the price ledger), agent-team/delegated (the
  // team bridge), synthetic/requested (conjureRun's request match). A label
  // missing from the list makes `excludeSuspect` a dead channel for it — an
  // appended forged twin under that label rides the trust decision unflagged
  // (survey M-level "保护名单缺 agent-team/delegated / economics/quote /
  // claim/jury — excludeSuspect 死通道"). The list is a SUPSET contract: it
  // must contain every consumed label (asserted true one by one), and may
  // grow.

  const required: readonly string[] = [
    'attest/jury', 'baseline/saved', 'delegation/created', 'proof/verified',
    'claim/jury', 'economics/quote', 'agent-team/delegated', 'synthetic/requested',
  ]
  for (const label of required) {
    assert.equal(isProtectedMarkerLabel(label), true,
      `claim 6 (README.md:378): "${label}" feeds a trust decision and must carry the headRef witness — otherwise excludeSuspect cannot filter an appended twin under it`)
  }
})

// ---------------------------------------------------------------------------
// Claim 7 — "the publish predicate everywhere" (README.md:380; evidence.ts view doc)
// ---------------------------------------------------------------------------

test('claim 7: the publish predicate is complete — a head-liared checkpoint is never selected, never notarised', async () => {
  // CLAIM (README.md:380, "Move two: epoch awareness"): "the publish
  // predicate everywhere is now 'the selected checkpoint verifies, or the
  // publish refuses'"; the view's doc (src/core/evidence.ts, BestCheckpoint)
  // spells the full predicate: `signature === 'verified' && headLiared !== true`
  // — a replayed signature over a false head must be refused "exactly as
  // preSignAudit's own head-liars rule does before signing".
  //
  // WHY A CONTRACT: v0.23's selection verified the SIGNATURE and never asked
  // WHERE — a transplanted checkpoint (real key, honest bytes, lying
  // position) passed every publish check on the engine face and was
  // notarised into the public Merkle tree (survey Y-H-01, four independent
  // finds), while the v0.23 view merely ADVISED `headLiared: true` and left
  // every consumer to remember the second half of the predicate. The
  // contract is therefore at the SELECTION surface — a head-liared
  // checkpoint is not a publishable candidate at all (latestSignedCheckpoint
  // / view.bestCheckpoint must not select it), so no publish path can
  // notarise a transplant even by forgetting to check — plus the consumer
  // check: whatever the engine publish notarises must be the corroborated
  // selection, never the transplant.
  //
  // FIXTURE NOTE: the transplant is a byte-copy of the store's own signed
  // checkpoint appended at the tail with `prev` re-chained — signature
  // verifies, count stays consistent (no records were added), and ONLY the
  // position witness (headLiared on the walk) can object. That isolates the
  // head-liar rule from the malformed-count rule.

  const engine = new ProofEngine({
    root: '/ws',
    fs: MemoryFs.of(PROJECT),
    commands: new FakeCommands(),
    workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(),
    workspaceKey: 'ws',
    signer: () => Promise.resolve(new FakeSigner('ws-key')),
    ptlDir: '/ws/ptl',
    ptlSigner: () => Promise.resolve(new FakeSigner('operator-key')),
    autoDiscover: false,
    checks: [{ command: ['node', '-e', 'process.exit(0)'], kind: 'test' }],
  })
  await engine.establishBaseline()
  const logPath = '/ws/.proof/evidence.jsonl'
  const realFs = engine.fsView as MemoryFs

  // Mixed shape: the honest checkpoint AND its transplanted twin both sit
  // on the chain. Selection must answer with the honest one.
  transplantLastCheckpoint(realFs, logPath)
  const lines = (realFs.files.get(logPath) ?? '').split('\n').filter(l => l.trim().length > 0)
  const transplantIndex = lines.length - 1

  const selected = await engine.storeView.latestSignedCheckpoint()
  assert.ok(selected !== undefined, 'fixture sanity: the honest checkpoint is publishable')
  assert.notEqual(selected.index, transplantIndex,
    'claim 7 (README.md:380): a head-liared checkpoint must not be the publishable selection — latestSignedCheckpoint cannot hand a transplant to any publish path')

  const best = await createVerifiedView(engine.storeView).bestCheckpoint()
  assert.notEqual(best.signature, 'none', 'the honest checkpoint is still selectable')
  assert.notEqual(best.headLiared, true,
    'claim 7: view.bestCheckpoint must not present a head-liared checkpoint as publishable')
  assert.notEqual(best.checkpoint?.index, transplantIndex,
    'the view selects the corroborated original, not the tail transplant')

  // Consumer half: the engine publish notarises exactly the corroborated
  // selection. (A refusal is also compliant with the claim; a successful
  // publish of the TRANSPLANT is the one forbidden outcome.)
  let published: Awaited<ReturnType<typeof engine.publishCheckpoint>> | undefined
  try {
    published = await engine.publishCheckpoint()
  } catch {
    published = undefined // refusing is the other compliant answer
  }
  if (published !== undefined) {
    const { log: ptl } = await loadPtl(realFs, '/ws/ptl')
    const entry = ptl.entries[ptl.entries.length - 1]
    assert.ok(entry !== undefined, 'fixture sanity: the publish produced a leaf')
    assert.equal(entry.count, selected.payload.count,
      'the notarised leaf carries the corroborated selection\'s count')
    assert.equal(entry.head, selected.payload.head,
      'the notarised leaf carries the corroborated selection\'s head — a transplant\'s stale head never enters the public tree')
    assert.equal(entry.sig, selected.sig,
      'the notarised leaf carries the corroborated selection\'s signature bytes')
  }

  // Pure attack: a rewrite leaves ONLY the transplanted liar on the chain.
  // Nothing is publishable — the transplant does not stand in.
  const firstLine = lines[0] as string
  const honestCp = lines[selected.index] as string
  const sole = JSON.stringify({ ...JSON.parse(honestCp), prev: lineDigest(firstLine) })
  realFs.mutate(logPath, `${[firstLine, sole].join('\n')}\n`)
  assert.equal(await engine.storeView.latestSignedCheckpoint(), undefined,
    'a chain whose only signed checkpoint lies about its position has nothing publishable')
  assert.equal((await createVerifiedView(engine.storeView).bestCheckpoint()).signature, 'none',
    'the view agrees: none — never the transplant')
  await assert.rejects(() => engine.publishCheckpoint(),
    'the engine publish refuses on a chain with nothing publishable — notarising the transplant is the Y-H-01 attack')
})

// ---------------------------------------------------------------------------
// Claim 8 — the documented refusal recovery actually recovers (evidence.ts
// preSignAudit doc; README.md:378 audit.ok consumption)
// ---------------------------------------------------------------------------

test('claim 8: a refused-to-sign generation is forgiven after the documented re-anchor — audit.ok returns to true', async () => {
  // CLAIM (src/core/evidence.ts, preSignAudit): "the next session refuses
  // ONCE and the documented recovery is the re-anchor flow: `saveBaseline`
  // (or the engine's establish) writes a newer SELF-authored marker,
  // superseding the orphan, and signing resumes". README.md:378 makes
  // audit.ok a consumed trust fact ("a chain that fails its own audit
  // cannot mint a `proven`").
  //
  // WHY A CONTRACT: v0.23 kept the refusal line in the refusedToSign channel
  // FOREVER and let a non-empty channel cap `ok` FOREVER — so an honest
  // crash in the adoption window (or the documented re-anchor itself) minted
  // a permanent red audit: every later verdict was capped at stale while
  // the code comment claimed "signing resumes" (survey Y-H-02: four finds,
  // "永久拒签无赦免 × audit.ok 封顶 = 永久 stale"). The behavioral contract
  // is the promise's second half: after the re-anchor (self-authored marker
  // superseding the orphan + a fresh signed checkpoint over the tail), the
  // audit must clear. The refusal stays ON RECORD (channels stay visible) —
  // what must not persist is the verdict cap.

  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint() // a verified vouching boundary

  // The refusal trigger: an authorless baseline/established marker lands on
  // the checkpoint-uncovered tail (X-H-08's shape).
  const lines = (await fs.readLines(LOG)).slice()
  const prev = lineDigest(lines[lines.length - 1] as string)
  const twin = JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
    payload: { label: 'baseline/established', reason: 'never happened', headRef: prev },
  })
  fs.mutate(LOG, `${[...lines, twin].join('\n')}\n`)

  const session2 = trustedStore(fs).store
  await session2.checkpoint()
  const refused = await session2.audit()
  assert.equal((refused.chain.refusedToSign ?? []).length, 1, 'the store refuses ONCE to lend the key over the orphan')
  assert.equal(refused.ok, false, 'the refusal itself is a failed audit — loud, not silent')

  // The documented recovery, verbatim: a newer self-authored marker of the
  // same label supersedes the orphan, then a checkpoint covers the tail.
  await session2.mark('baseline/established', { reason: 'operator re-anchor after refusal' })
  await session2.checkpoint()
  const recovered = await session2.audit()
  assert.equal(recovered.ok, true,
    'claim 8 (evidence.ts preSignAudit doc "signing resumes"): after the documented re-anchor the audit must clear — '
    + `a forever-capped ok turns the promise into a permanent stale (refusedToSign=${JSON.stringify(recovered.chain.refusedToSign)})`)
  assert.ok(recovered.chain.checkpoints > refused.chain.checkpoints,
    'recovery means signed checkpoints resumed, not merely that the accusation aged out of view')
})

// ---------------------------------------------------------------------------
// Claim 9 — "a self-deleting script now records error, not a pass" (README.md:384)
// ---------------------------------------------------------------------------

test('claim 9: a self-deleting synthetic script records status error — the vanished body cannot vouch for its own pass', async () => {
  // CLAIM (README.md:384): "the **require-mode coverage gate** keys its
  // synthetic exclusion on pool membership rather than a record field (a
  // self-deleting script now records `error`, not a pass)". The mechanism
  // (X-H-05) is engine.reattachSyntheticMeta: a re-dispatched synthetic
  // record whose script file no longer exists is rewritten to `error` with
  // the vanished note, because "a self-deleting pass is not a pass" — the
  // deterministic exploit being `fs.rmSync(import.meta.url)` at the end of a
  // passing run, deleting the only bytes the evidence should address.
  //
  // WHY A CONTRACT: the v0.23 fix shipped with ZERO adversarial tests (survey
  // Y-H-17: "自删脚本零钉" — the suite pinned the honest script only). A
  // defense with no adversary-shaped pin is one refactor away from silent
  // removal. This is the adversarial pin: run the honest loop, delete the
  // body at execution time (exactly what the script itself would do), and
  // demand the chain record `error` naming the vanish.

  const fs = MemoryFs.of(PROJECT)
  const commands = new FakeCommands().on(
    argv => argv.includes('node'),
    { exitCode: 0, output: 'SYNTHETIC: PASS' },
  )
  const engine = new ProofEngine({
    root: '/ws', fs, commands, workspace: new FakeWorkspace('/ws'), clock: new FakeClock(),
    autoDiscover: false,
  })
  const claim = 'one plus one is two'
  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  fs.mutate(`/ws/.proof-synthetic/${request.entry}`, "console.log('SYNTHETIC: PASS')\n")
  const run = await engine.conjureRun({ claim, entry: request.entry })
  assert.equal(run.status, 'pass', 'the honest loop still records a pass (fixture sanity)')

  // The self-delete: at the end of its execution the script removed itself.
  fs.files.delete(`/ws/.proof-synthetic/${request.entry}`)

  // The re-dispatch: verify() re-executes the pool (the synthetic spec runs
  // again through the engine's own port) and collects — the file is gone.
  await engine.verify({ changed: ['src/a.ts'] })
  const record = (await engine.latestEvidence()).get(run.checkId)
  assert.ok(record !== undefined, 'the re-dispatched synthetic check recorded evidence')
  assert.equal(record?.status, 'error',
    'claim 9 (README.md:384): a self-deleting script must record error, not a pass — the run cannot vouch for a body it can no longer read')
  assert.match(String(record?.outputHead), /vanish/i,
    'the record\'s first line names WHY it cannot be believed (the vanished-script note)')
})

// ---------------------------------------------------------------------------
// Claim 10 — "the MCP face's marker reads go through the same view" (README.md:378)
// ---------------------------------------------------------------------------

test('claim 10: blank-line semantics agree across the store face and the MCP face — one log, one judgement', async () => {
  // CLAIM (README.md:378): "the MCP face's marker reads go through the same
  // view" — same view means same markers admitted, same markers excluded,
  // for the SAME physical bytes.
  //
  // WHY A CONTRACT: v0.23's MCP face judged the headRef witness over a raw
  // `split('\n')` snapshot while the store face judged over `readLines`
  // output (blank lines filtered) — one physical log, two line-array
  // domains, two disagreeing position verdicts: a single stray blank line
  // made every honest marker after it silently disappear on the MCP face,
  // while a crafted `blank + headRef=sha256('')` pair made a forged
  // carrier's witness PASS on the MCP face and fail everywhere else (survey
  // M-level "MCP 面 readLines 不滤空行与 store 面分叉"). The contract reads
  // the same log through both production surfaces and demands the same
  // admitted set: the honest marker survives on BOTH, the appended forged
  // twin is excluded on BOTH.

  const evidence0 = JSON.stringify({ v: 1, kind: 'evidence', at: '2026-10-06T00:00:00.000Z', payload: { evidenceId: 'e0' } })
  const marker = (label: string, extra: Record<string, unknown>, prev: string, headRef: string) => JSON.stringify({
    v: 2, kind: 'marker', at: '2026-10-06T00:00:00.000Z', prev, payload: { label, ...extra, headRef },
  })
  // The honest writer chained its witness to the last non-blank line; a
  // blank line sits between that line and the marker.
  const honestCreated = marker('delegation/created', { taskId: 'task-1', claim: 'honest obligation' }, 'prev-0', lineDigest(evidence0))
  const honestVerdict = marker('delegation/verdict', { taskId: 'task-1' }, lineDigest(evidence0), lineDigest(honestCreated))
  // The forged twin: appended out of band, its headRef names a line that is
  // not its physical predecessor in ANY honest domain.
  const forgedTwin = marker('delegation/created', { taskId: 'task-evil', claim: 'injected obligation' }, 'prev-x', lineDigest(evidence0))
  const log = [evidence0, '', honestCreated, honestVerdict, forgedTwin].join('\n') + '\n'

  const fs = MemoryFs.of({ '/store/evidence.jsonl': log })
  const store = new EvidenceStore(fs, '/store/evidence.jsonl', '/store/baseline.json', new FakeClock())
  const deps = {
    engine: { fsView: fs, storeView: store },
    evidenceLogPath: '/store/evidence.jsonl',
  } as unknown as McpEngineDeps

  const viaStore = await store.markersWith('delegation/created', { excludeSuspect: true })
  const viaMcp = await markerPayloads(deps, new Set(['delegation/created']))

  assert.deepEqual(viaStore.map(m => m.payload.taskId), ['task-1'],
    'fixture sanity: the engine/store face admits the honest marker and excludes the twin')
  assert.deepEqual(
    viaMcp.map(r => r.payload.taskId).sort(),
    viaStore.map(m => m.payload.taskId).sort(),
    'claim 10 (README.md:378 "the MCP face\'s marker reads go through the same view"): '
    + 'the MCP face must admit exactly the markers the engine face admits for the same log — '
    + 'a blank line must not move a marker\'s verdict on one face only',
  )
  assert.ok(viaMcp.some(r => r.payload.taskId === 'task-1'),
    'the honest marker is visible on BOTH faces (not merely equally invisible)')
  assert.ok(!viaMcp.some(r => r.payload.taskId === 'task-evil'),
    'the forged twin is excluded on BOTH faces — the blank-line domain must not become its witness')
})
