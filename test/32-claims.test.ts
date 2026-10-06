/**
 * CLAIM-CONTRACT TESTS (v0.24, hardened v0.25.1) — 让架构主张的落空在 951 绿下当场变红。
 *
 * MISSION. This file pins the v0.23/v0.24/v0.25 ARCHITECTURAL CLAIMS to their
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
 * OWNERSHIP: the v0.24 batch owned this file only. The v0.25.1 batch (U4)
 * both migrates the four remaining raw-door consumers in src/ (index.ts,
 * dsh/tools.ts, both adapter faces — the migration claim 1b used to wait on)
 * and hardens the assertions here: every static check now runs over
 * comment-STRIPPED source (U4-H2: a commented-out call used to satisfy any
 * existence claim), existence claims match CALL-FORM syntax inside the
 * consuming function's own span, and absence claims match renamed-twin
 * FAMILIES instead of exact spellings (U4-H4).
 *
 * PARALLEL-FIX DEPENDENCIES: none outstanding — the raw-door migration
 * (#1b's dependency) landed in this batch; #2's validateBayesKnobs wiring
 * and #3's foldHostPath consolidation landed in v0.24; #5b's doc face is
 * green. The claims as asserted are the TRUE end-state semantics.
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
import { createProofTools } from '../src/dsh/tools.ts'
import type { ToolRunContext } from '../src/vendor/dsh-tools.ts'
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

/**
 * U4-H2 (v0.25.1): strip `//` line comments and `/* ... *\/` block comments
 * before ANY static assertion runs. A comment could otherwise satisfy every
 * existence claim below ("// vouchedMarkersWith" is not a call; a doc
 * mention of foldHostPath is not a consumption) and mask every absence
 * claim (a commented-out twin reads as present code to a naive regex).
 * Deliberately naive about string literals — the `[^:]` guard keeps `https://`
 * intact and no assertion below keys on text containing comment syntax; the
 * alternative (a real lexer) is not this file's job. Every strip is followed
 * by call-form or span-bounded matching, never bare substring presence.
 */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
}

/**
 * U4-H2/H3 (v0.25.1): the span of a class method, from its declaration to
 * the closing brace at member indent (`\n  }`). Existence claims are judged
 * INSIDE this span so "the call lives in this function's own body" is what
 * is asserted — not "the token appears within N characters of the name"
 * (the fixed-window shape the v0.24 claims used: a long signature or a
 * helper extraction moved the real call out of the window, and a comment or
 * an unrelated call moved in). The `}` must end its line, so a multi-line
 * return-type literal's `}>` does not terminate the span prematurely.
 */
function methodSpan(src: string, declMatch: RegExpExecArray): string {
  const rel = src.slice(declMatch.index).search(/\n  \},?\n/)
  return src.slice(declMatch.index, declMatch.index + (rel === -1 ? src.length - declMatch.index : rel))
}

/** The declaration of a class method by name, tolerant of modifier/async spelling. */
function methodDecl(src: string, name: string): RegExpExecArray {
  const match = new RegExp(`(^|\\n)\\s*(?:(?:private|protected|public)\\s+)?(?:async\\s+)?${name}\\s*\\(`).exec(src)
  assert.ok(match !== null, `${name} must exist as a method declaration`)
  return match
}

/** Minimal tool-execution context: the attest tools only read `signal`. */
function toolExecution(name: string): ToolRunContext {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: {},
    token: Symbol('token'),
    signal: new AbortController().signal,
    deferContext: () => undefined,
    concludeTurn: () => undefined,
  }
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

test('claim 1: the verified view has production consumers, and both raw-read doors are gone from src/ imports', () => {
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
  // 951 tests stayed green (survey Y-H-03). And v0.24's contract had a hole
  // the tree was ALREADY falling through (U4-H1): the v0.24 regex
  // deliberately ignored the underscore rename, so four production
  // consumers walked through `_readMarkers` while this file stayed green —
  // the "accepted escape hatch" WAS the bypass. The contract is therefore
  // not "the view exists" but "the view is CONSUMED, and no raw door —
  // clean-named, underscored, or re-branded — is".
  //
  // SIGNATURES: (1a) engine.ts must IMPORT createVerifiedView from
  // core/evidence.ts AND invoke it — a call site `createVerifiedView(`,
  // judged on comment-stripped source so a doc mention alone cannot satisfy
  // the invocation half. The v0.24 "OR the store delegates internally"
  // alternative is GONE (U4-M6): a comment in evidence.ts used to satisfy
  // the OR while the engine branch was deleted — engine consumption is the
  // claim, so engine consumption is the assertion. (1b) no src/ file
  // outside core/evidence.ts may IMPORT `readMarkers` in ANY spelling the
  // underscore family produces (`_*readMarkers`: readMarkers, _readMarkers,
  // __readMarkers...) — the name is gone from the import surface, not
  // merely the clean spelling. (1c) the one sanctioned engine-less read,
  // `readChainMarkers`, may be imported by exactly the two adapter faces
  // (claude-code hooks, opencode plugin) — processes with no engine and no
  // store. Any engine-holding file importing it is re-opening a raw door
  // with a clean name; the importer set is pinned so widening it is a
  // deliberate, claim-visible decision.

  const engine = stripComments(srcText('engine.ts'))
  const engineImportsView = /import\s*\{[^}]*\bcreateVerifiedView\b[^}]*\}\s*from\s*['"][^'"]*evidence\.ts['"]/.test(engine)
  const engineCallsView = /\bcreateVerifiedView\s*\(/.test(engine)
  assert.ok(
    engineImportsView && engineCallsView,
    'claim 1a (README.md:378 "one door"): engine.ts must consume createVerifiedView '
    + '(import + call site, comment-stripped — the OR alternative that a store-side comment '
    + `used to satisfy is retired; import=${engineImportsView} call=${engineCallsView})`,
  )

  const rawDoorImport = /import\s*\{[^}]*?(?<![_\w])_*readMarkers\b[^}]*\}\s*from\s*['"][^'"]*evidence\.ts['"]/
  const rawImporters = listSrcFiles()
    .map(p => p.replace(/\\/g, '/'))
    .filter(p => !p.endsWith('/core/evidence.ts'))
    .filter(p => rawDoorImport.test(stripComments(readFileSync(p, 'utf8'))))
  assert.deepEqual(
    rawImporters.map(p => p.slice(p.lastIndexOf('src/'))),
    [],
    'claim 1b (README.md:378 "raw line-parsing paths are @internal"): no src/ file may '
    + 'import the raw marker read — not the clean name, not the underscore family '
    + `(the v0.24 escape hatch the tree was actively using; still importing: ${rawImporters.join(', ')})`,
  )

  const enginelessFaces = ['src/adapters/claude-code/hooks.ts', 'src/adapters/opencode/plugin.ts']
  const chainImporters = listSrcFiles()
    .map(p => p.replace(/\\/g, '/'))
    .filter(p => !p.endsWith('/core/evidence.ts'))
    .filter(p => /import\s*\{[^}]*\breadChainMarkers\b[^}]*\}\s*from\s*['"][^'"]*evidence\.ts['"]/.test(stripComments(readFileSync(p, 'utf8'))))
    .map(p => p.slice(p.lastIndexOf('src/')))
  assert.deepEqual(
    [...chainImporters].sort(),
    [...enginelessFaces].slice().sort(),
    'claim 1c (the one public raw read carries the position verdict): readChainMarkers is '
    + 'the declared door for ENGINE-LESS processes only — the two adapter faces. An '
    + 'engine-holding file importing it re-opens a raw door with a clean name '
    + `(importers: ${chainImporters.join(', ')})`,
  )
})

// ---------------------------------------------------------------------------
// Claim 2 — "the Bayes knob domain is validated at every boundary" (README.md:384)
// ---------------------------------------------------------------------------

test('claim 2: Bayes knobs are rejected at the construction boundary — certifyTarget/driftedFalsePass 0 and config syntheticFalsePass edges all throw', () => {
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
  // lie). The contract is behavioral: EVERY construction boundary must
  // refuse the degenerate knob LOUDLY, naming it.
  //
  // U4-M4 (v0.25.1): the v0.24 contract pinned only 2 of the 3 named knob
  // refusals — `driftedFalsePass: 0` (the README's FIRST example) had no
  // engine pin, so deleting that one line from validateBayesKnobs' call
  // left this suite green. Now pinned. The config face's closed-interval
  // UPPER edge (1) joins the lower edge (0): percent() is [0,1], the
  // domain is (0,1), and both ends had to be refused at configuration time.

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
    () => new ProofEngine({
      root: '/ws',
      fs: MemoryFs.of(PROJECT),
      commands: new FakeCommands(),
      workspace: new FakeWorkspace('/ws'),
      driftedFalsePass: 0,
    }),
    /driftedFalsePass/,
    'claim 2c (README.md:384, first example in the sentence): ProofEngine construction '
    + 'must reject driftedFalsePass 0 — the knob whose 0 turns the drift defense into a '
    + 'one-shot certify; the v0.24 contract forgot to pin it',
  )

  assert.throws(
    () => Config({ syntheticFalsePass: 0 } as never),
    /syntheticFalsePass/,
    'claim 2b (README.md:384): the plugin config face must reject syntheticFalsePass 0 '
    + '(percent() is a CLOSED [0,1]; β=0 makes one forged pass certify)',
  )

  assert.throws(
    () => Config({ syntheticFalsePass: 1 } as never),
    /syntheticFalsePass/,
    'claim 2b upper edge (U4-M4): the config face must also refuse the closed interval\'s '
    + 'other end — β=1 makes a fail prove health; only the open interval (0,1) is a domain',
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

test('claim 3: foldHostPath is the one fold — engine and index.ts carry no hand-rolled fold twins, renamed or not', () => {
  // CLAIM (README.md:382, "Move three: value scanning, not enumeration"):
  // "one `foldHostPath` (device-namespace prefixes stripped, drive-relative
  // `C:x` projections, case, separators, trailing-dot deformation — every
  // fold that used to live in four disagreeing implementations) is now *the*
  // fold, consumed by the gates, the DSH face and the engine's export
  // confinement alike".
  //
  // WHY A CONTRACT: "alike" is the claim. The gates face consumed the one
  // fold while the engine's export confinement kept a local weak-subset
  // lambda and index.ts hand-folded the trust root — exactly the
  // four-half-folds drift the claim says died (survey L-level "engine 弱子集
  // foldHost lambda", Y-H-12's index.ts straggler).
  //
  // SIGNATURES (U4-H4, v0.25.1 — renamed twins die too): the v0.24 negative
  // `!/const\s+foldHost\s*=/` pinned one spelling, so `foldHost2`/`hostFold`
  // walked through while the positive half was satisfied by a DEAD IMPORT or
  // a comment mention. The negative is now a FAMILY: no local fold-flavoured
  // arrow (`const <…fold…> = (value|toolInput|input) => …`), no fold-flavoured
  // function declaration, and (index.ts) no fold-named binding over a bare
  // `.replace(` hand-fold — each judged on comment-stripped source, each
  // exempting exactly the shared export names (foldHostPath in paths.ts —
  // a scanned file defining it is re-shipping the fold, which the family
  // match still catches by name collision with the import). The positive
  // half demands a CALL (`foldHostPath(`), not a mention: import lines and
  // comments do not consume anything.

  const engine = stripComments(srcText('engine.ts'))
  const foldTwinArrow = /const\s+(\w*(?:[fF]old|[sS]weep)\w*)\s*=\s*\(?\s*(?:value|toolInput|input)\b[^)]*\)?\s*=>/.exec(engine)
  const foldTwinFn = /function\s+(\w*(?:[fF]old|[sS]weep)\w*)\s*\(/.exec(engine)
  assert.ok(foldTwinArrow === null && foldTwinFn === null,
    'claim 3a (README.md:382 "one fold ... alike"): engine.ts must not define a local '
    + 'fold implementation under ANY name — the export confinement folds through paths.ts '
    + `foldHostPath (twin arrow: ${foldTwinArrow?.[1] ?? 'none'}, twin fn: ${foldTwinFn?.[1] ?? 'none'})`)
  assert.ok(/[^/\w]foldHostPath\s*\(/.test(engine),
    'claim 3b (README.md:382): engine.ts\'s export confinement must CALL the shared '
    + 'foldHostPath — an import line or a comment mention consumes nothing')

  const index = stripComments(srcText('index.ts'))
  assert.ok(
    /import\s*\{[^}]*(?:touchesEvidencePath|foldHostPath)[^}]*\}\s*from\s*['"][^'']*shared\/paths\.ts['"]/.test(index),
    'claim 3c (README.md:382 "the DSH face"): index.ts must import the paths.ts guard (touchesEvidencePath/foldHostPath) instead of hand-folding',
  )
  const handFold = /const\s+(\w*[fF]old\w*)\s*=\s*\w+\.replace\s*\(/.exec(index)
  assert.ok(handFold === null,
    'claim 3d (README.md:382): index.ts must not hand-fold — a fold-named binding over a '
    + `bare .replace( is the hand-fold shape under any name (found: ${handFold?.[1] ?? 'none'}); `
    + 'trustRoot spellings fold through the one foldHostPath')
})

// ---------------------------------------------------------------------------
// Claim 4 — "all the same sweep" (README.md:382)
// ---------------------------------------------------------------------------

test('claim 4: sweepToolInputStrings has exactly one implementation — gates.ts imports AND calls the observe.ts sweep', () => {
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
  // minimal shape of the drift the claim forbids.
  //
  // SIGNATURES (U4-H4, v0.25.1): the v0.24 negative pinned the exact
  // spelling `function sweepToolInputStrings`, so a renamed local copy
  // (`const sweepInputs = (input) => …`) plus the — possibly dead — import
  // passed both halves: v0.23's Y-H-10 fork, reconstructed. The negative is
  // now the family (no sweep-flavoured arrow over value/toolInput/input, no
  // sweep-flavoured function declaration, comment-stripped, exempting the
  // shared export name); the positive now demands a CALL SITE in addition
  // to the import — an import that is never called is the dead half of the
  // double-green.

  const gates = stripComments(srcText('adapters/shared/gates.ts'))
  const sweepTwinArrow = /const\s+(\w*(?:[sS]weep|[fF]old)\w*)\s*=\s*\(?\s*(?:value|toolInput|input)\b[^)]*\)?\s*=>/.exec(gates)
  const sweepTwinFn = /function\s+(\w*(?:[sS]weep|[fF]old)\w*)\s*\(/.exec(gates)
  assert.ok(sweepTwinArrow === null && sweepTwinFn === null,
    'claim 4a (README.md:382 "all the same sweep"): gates.ts must not define its own '
    + 'sweep under ANY name — the renamed local copy is how the two faces forked (Y-H-10) '
    + `(twin arrow: ${sweepTwinArrow?.[1] ?? 'none'}, twin fn: ${sweepTwinFn?.[1] ?? 'none'})`)
  assert.ok(
    /import\s*\{[^}]*\bsweepToolInputStrings\b[^}]*\}\s*from\s*['"][^'']*observe\.ts['"]/.test(gates),
    'claim 4b (README.md:382): gates.ts must import sweepToolInputStrings from dsh/observe.ts — one sweep, one implementation',
  )
  assert.ok(/[^/\w]sweepToolInputStrings\s*\(/.test(gates),
    'claim 4c (README.md:382): gates.ts must CALL the shared sweep — the import alone '
    + '(possibly dead) plus no local twin was the v0.23 double-green the family match now closes')
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
    'attest/jury', 'attest/jury-requested', 'baseline/saved', 'delegation/created', 'delegation/verdict', 'delegation/waive', 'proof/verified',
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

test('claim 7: the publish predicate is complete — a head-liared checkpoint is never selected, never notarised, and an honest selection is never refused', async () => {
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
  // U4-M1 (v0.25.1): the v0.24 consumer half swallowed ANY publish throw
  // (`catch { }`), so a regression to a v0.24-style always-refuse DoS — or
  // any silent failure — skipped the leaf assertions while the comment
  // claimed "a refusal is also compliant". On this MIXED fixture the honest
  // checkpoint is selected and verified, so success is the only compliant
  // outcome: the publish must produce a leaf, and a throw is admissible
  // ONLY as a loud refusal that names its reason.

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
  // selection — and on this fixture it MUST publish at all.
  let published: Awaited<ReturnType<typeof engine.publishCheckpoint>> | undefined
  try {
    published = await engine.publishCheckpoint()
  } catch (error) {
    // U4-M1: a throw is still a documented outcome — but only as a LOUD
    // refusal that names its reason. Anything else is a bug wearing the
    // refusal's coat, and the published-undefined assertion below turns it
    // red anyway.
    const message = error instanceof Error ? error.message : String(error)
    assert.match(message, /refusing to publish: .+|no signed checkpoint on the evidence chain/,
      'claim 7 (U4-M1): a throwing publish must be a loud refusal that names its reason — '
      + 'a generic or silent failure is the DoS the bare catch used to hide')
  }
  assert.ok(published !== undefined,
    'claim 7 (U4-M1): with an honest, verified selection on the chain the publish must '
    + 'SUCCEED — an always-refuse regression used to hide behind the bare catch')
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
  // Nothing is publishable — the transplant does not stand in — and the
  // refusal is loud, naming the liars (not a silent undefined-return).
  const firstLine = lines[0] as string
  const honestCp = lines[selected.index] as string
  const sole = JSON.stringify({ ...JSON.parse(honestCp), prev: lineDigest(firstLine) })
  realFs.mutate(logPath, `${[firstLine, sole].join('\n')}\n`)
  assert.equal(await engine.storeView.latestSignedCheckpoint(), undefined,
    'a chain whose only signed checkpoint lies about its position has nothing publishable')
  assert.equal((await createVerifiedView(engine.storeView).bestCheckpoint()).signature, 'none',
    'the view agrees: none — never the transplant')
  await assert.rejects(() => engine.publishCheckpoint(),
    /refusing to publish: .+|no signed checkpoint on the evidence chain/,
    'the engine publish refuses LOUDLY on a chain with nothing publishable — notarising the transplant is the Y-H-01 attack, and a silent empty-return is its quiet cousin')
})

// ---------------------------------------------------------------------------
// Claim 8 — the documented refusal recovery actually recovers (evidence.ts
// preSignAudit doc; README.md:378 audit.ok consumption)
// ---------------------------------------------------------------------------

test('claim 8: refused-to-sign generations are forgiven after the documented re-anchor — every round, with the refusals staying on record', async () => {
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
  //
  // U4-M5 (v0.25.1): the v0.24 contract ran ONE refuse→re-anchor round, so a
  // one-shot absolution latch passed it and re-bricked the deployment on
  // the second honest blip. The fixture now runs TWO rounds — refuse,
  // re-anchor, refuse again, re-anchor again — and demands the audit clear
  // BOTH times while refusedToSign accumulates visibly on the record.

  const fs = MemoryFs.of({})
  const { store } = trustedStore(fs)
  await store.append(evidence('c1'))
  await store.checkpoint() // a verified vouching boundary

  // The refusal trigger: an authorless baseline/established marker lands on
  // the checkpoint-uncovered tail (X-H-08's shape).
  const orphanOnTail = async (reason: string): Promise<void> => {
    const lines = (await fs.readLines(LOG)).slice()
    const prev = lineDigest(lines[lines.length - 1] as string)
    const twin = JSON.stringify({
      v: 2, kind: 'marker', at: '2026-10-05T00:00:00.000Z', prev,
      payload: { label: 'baseline/established', reason, headRef: prev },
    })
    fs.mutate(LOG, `${[...lines, twin].join('\n')}\n`)
  }

  // -- Round 1 -------------------------------------------------------------
  const session2 = trustedStore(fs).store
  orphanOnTail('never happened')
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
  assert.ok((recovered.chain.refusedToSign ?? []).length >= 1,
    'claim 8 (U4-M5, "refusal stays ON RECORD"): the pardoned refusal must stay visible in '
    + 'the refusedToSign channel after recovery — the scar is evidence, only the verdict cap is lifted')

  // -- Round 2 (U4-M5) -------------------------------------------------------
  // A SECOND orphan generation: a one-shot absolution latch (the exact
  // regression this round exists to forbid) re-bricks the deployment here.
  orphanOnTail('never happened either')
  const session3 = trustedStore(fs).store
  await session3.checkpoint()
  const refused2 = await session3.audit()
  assert.equal((refused2.chain.refusedToSign ?? []).length, 2,
    'the second orphan generation refuses too — refusals accumulate on the record')
  assert.equal(refused2.ok, false, 'the second refusal is a live accusation until re-anchored')

  await session3.mark('baseline/established', { reason: 'operator re-anchor after the second refusal' })
  await session3.checkpoint()
  const recovered2 = await session3.audit()
  assert.equal(recovered2.ok, true,
    'claim 8 (U4-M5): the SECOND documented re-anchor must clear the audit too — a one-shot '
    + 'absolution latch turns the second honest blip into the permanent stale the claim retired')
  assert.equal((recovered2.chain.refusedToSign ?? []).length, 2,
    'claim 8: both refusals stay on the record after both recoveries — "the refusal stays '
    + 'ON RECORD" is an assertion, not a failure message')
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

// ---------------------------------------------------------------------------
// v0.25 claims: the floor and the witness
// ---------------------------------------------------------------------------

test('claim 11: trust reads stop at the vouched floor — every fusion, DAG and drift consumer CALLS the floor-bounded reader in its own body', async () => {
  // Claim origin: the v0.25 "vouched floor everywhere" completion of the
  // v0.24 section's closing bet — README (v0.25): "any trust decision
  // consumes only what lies below the last verified checkpoint; a fresh,
  // properly-shaped append above the floor is structurally inert". The
  // behavioural pins live in test/05 (K1a/K1b/K1c); THIS contract guards the
  // wiring itself: the day someone adds a new trust reader that forgets the
  // floor, the static signature below changes and this claim goes red.
  //
  // U4-H2 (v0.25.1) — the v0.24 shape pinned nothing of the sort: a
  // 3000-character window after `private async <consumer>` containing the
  // SUBSTRING `vouchedMarkersWith` was satisfied by a comment (the
  // logAboveFloor docstring nearly spells it), by an import line, or by a
  // real call from a DIFFERENT method inside the window; and the real call
  // could silently become the floor-less twin `this.markersWith(` — one
  // word apart — with the window none the wiser. Now: comment-stripped
  // source, the consumer's own method SPAN (declaration to closing brace —
  // a helper extraction or a longer signature cannot move the goalposts),
  // a CALL-FORM match (`this.vouchedMarkersWith(`), and the twin's
  // call-form banned from the same span.
  //
  // HONEST COMPLETENESS NOTE: this pins the three NAMED consumers, not the
  // set of all future trust readers — a new reader is this contract's blind
  // spot by construction, and closing that is the K1 behaviour pins' job in
  // test/05 (a new above-floor label must price zero on all three faces).

  const engine = stripComments(srcText('engine.ts'))
  assert.ok(/private\s+async\s+vouchedMarkersWith\s*\(/.test(engine),
    'claim 11a: engine.ts must define the floor-bounded reader (vouchedMarkersWith)')
  for (const consumer of ['activeAttestationsAll', 'delegationObligations', 'scriptDriftFirstSeen']) {
    const body = methodSpan(engine, methodDecl(engine, consumer))
    assert.ok(/this\s*\.\s*vouchedMarkersWith\s*\(/.test(body),
      `claim 11b: ${consumer} must CALL this.vouchedMarkersWith( inside its own method body — `
      + 'a comment, an import line, or a call from another method is not this consumer '
      + 'reading through the floor (U4-H2: the substring window was)')
    assert.ok(!/this\s*\.\s*markersWith\s*\(/.test(body),
      `claim 11c: ${consumer} must not call the floor-less twin this.markersWith( in the `
      + 'same body — the one-word rename is exactly how a floor-less read re-enters while '
      + 'the contract stays green (U4-H2)')
  }
})

test('claim 12: sworn testimony is checkpointed the moment it is recorded — mark and checkpoint share the tool body that swears the witness', async () => {
  // Claim origin: the K1 residual closed in v0.25 — testimony written by the
  // DSH tools after the last boundary checkpoint used to sit ABOVE the floor
  // for a full cycle, invisible to fusion. The fix checkpoints right after
  // each attest write; this contract keeps the two writes together.
  //
  // U4-H3 (v0.25.1) — the v0.24 shape asserted a 700-character window after
  // `mark('<label>'` containing the SUBSTRING `storeView.checkpoint()`:
  // a comment or a conditionally-dead `if (x) storeView.checkpoint()`
  // satisfied it, and the honest parameterised refactor (folding the two
  // copy-paste twins into a loop over labels) broke it. Two halves now:
  // (static) comment-stripped source, the ENCLOSING execute body as the
  // span, and a call-form match — the `await engine.storeView.checkpoint()`
  // must stand in the same function that wrote the marker (a best-effort
  // try/catch around it — U3-L6, landed in this batch — still matches: the
  // call is real and in the same span); (behavioural, the half a regex
  // cannot lie about) a full jury round through the real tool face on a
  // signed chain, asserting the sworn verdict lands BELOW a checkpoint —
  // the exact property a conditionally-dead or removed follow-up checkpoint
  // would violate, because the baseline's checkpoint is the only one left
  // and the marker sits above it.
  const tools = stripComments(srcText('dsh/tools.ts'))
  for (const label of ['attest/jury', 'attest/human']) {
    const markNeedle = `storeView.mark('${label}'`
    const markAt = tools.indexOf(markNeedle)
    assert.ok(markAt !== -1, `claim 12: the ${label} marker write must exist`)
    // The enclosing tool body: execute methods sit at 4-space member indent
    // in the tool factories' returned object literals.
    const execDecl = /\n    async execute\(/g
    let span: string | undefined
    for (let m = execDecl.exec(tools); m !== null; m = execDecl.exec(tools)) {
      const rel = tools.slice(m.index).search(/\n    \},?\n/)
      const end = m.index + (rel === -1 ? tools.length : rel)
      if (markAt > m.index && markAt < end) span = tools.slice(m.index, end)
    }
    assert.ok(span !== undefined, `claim 12: the ${label} marker write must sit inside a tool's execute body`)
    assert.ok(/await\s+engine\.storeView\.checkpoint\(\)/.test(span ?? ''),
      `claim 12: the ${label} write and 'await engine.storeView.checkpoint()' must share the `
      + 'same execute body — testimony above the vouched floor prices nothing, and a comment '
      + 'or a conditionally-dead call in a nearby window proved nothing (U4-H3)')
  }

  // Behavioural half: the sworn verdict is priceable the moment it is sworn.
  const engine = new ProofEngine({
    root: '/ws',
    fs: MemoryFs.of(PROJECT),
    commands: new FakeCommands().on(argv => argv.includes('node'), { exitCode: 0, output: 'pass\n' }),
    workspace: new FakeWorkspace('/ws'),
    clock: new FakeClock(),
    workspaceKey: 'ws',
    signer: () => Promise.resolve(new FakeSigner('ws-key')),
    autoDiscover: false,
    checks: [{ command: ['node', '-e', 'process.exit(0)'], kind: 'test' }],
  })
  await engine.establishBaseline()
  const tools9 = createProofTools(engine, undefined, LOG)
  const jury = tools9.find(t => t.name === 'proof_jury')!
  const submit = tools9.find(t => t.name === 'proof_jury_submit')!
  const claim = 'claim 12 behavioural: the verdict lands below a checkpoint the moment it is sworn'
  const request = await jury.execute({ claim }, toolExecution('proof_jury')) as { claimId: string }
  const verdict = await submit.execute(
    { claimId: request.claimId, verdict: 'uphold', probability: 0.9, reasoning: 'the follow-up checkpoint covered the testimony immediately.' },
    toolExecution('proof_jury_submit'),
  ) as { recorded: boolean; gen: number }
  assert.equal(verdict.recorded, true, 'fixture sanity: the jury round recorded through the real tool face')

  const fs = engine.fsView as MemoryFs
  const lines = (fs.files.get(LOG) ?? '').split('\n').filter(l => l.trim().length > 0)
  let verdictAt = -1
  let lastCheckpointAt = -1
  lines.forEach((line, index) => {
    try {
      const env = JSON.parse(line) as { kind?: unknown; sig?: unknown; payload?: { label?: unknown; gen?: unknown } }
      if (env.kind === 'marker' && env.payload?.label === 'attest/jury' && env.payload?.gen === verdict.gen) verdictAt = index
      if (env.kind === 'checkpoint' && typeof env.sig === 'string' && env.sig.length > 0) lastCheckpointAt = index
    } catch { /* not an envelope */ }
  })
  assert.ok(verdictAt !== -1, 'fixture sanity: the sworn verdict marker is on the chain')
  assert.ok(lastCheckpointAt > verdictAt,
    'claim 12 behavioural (U4-H3): a checkpoint SIGNED AFTER the verdict must cover it — '
    + 'testimony that rides above the last verified checkpoint prices nothing for a full '
    + 'cycle, and only a follow-up checkpoint that actually runs (not one a comment or a '
    + 'conditional names) puts the witness below the vouched floor')
})
