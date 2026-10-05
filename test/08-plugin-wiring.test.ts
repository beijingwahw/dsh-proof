/**
 * Plugin wiring — the DSH adapter surface, exercised without a harness.
 *
 * Loads the real plugin entry point, hands it a stand-in `Context`, and asserts
 * the contract it promises to DSH: seven tools on the registry, the documented
 * pipeline hooks, a `proof:policy` prompt section, and tool bodies that return
 * canonical JSON values with pure presentation projections.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import * as plugin from '../src/index.ts'
import { WorkspaceWatch } from '../src/dsh/observe.ts'
import { createProofTools, toBaselineValue, toClaimValue, toStatusValue, toVerifyValue } from '../src/dsh/tools.ts'
import { ProofEngine } from '../src/engine.ts'
import { NodeFsPort } from '../src/node-ports.ts'
import { DEFAULT_TRUST_WEIGHTS, RUBRIC_V1, claimIdOf, juryPrompt } from '../src/core/attest.ts'
import { sha256 } from '../src/core/hash.ts'
import type { AuditReport, ProofGrade, ProofReport } from '../src/core/evidence.ts'
import type { ConfidenceBasis, GradedProofReport } from '../src/core/report.ts'
import { Config } from '../src/config.ts'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition, ToolRunContext } from '../src/vendor/dsh-tools.ts'

const WORKSPACE = fileURLToPath(new URL('../../', import.meta.url))
const ROOT = join(WORKSPACE, '.openclaw', 'tmp', `proof-wiring-${process.pid}`)

interface Harness {
  registered: ToolDefinition[]
  listeners: Map<string, ((...args: never[]) => unknown)[]>
  sections: { id: string; content: string | (() => string) }[]
  disposed: (() => void)[]
  ctx: Context
}

function makeHarness(): Harness {
  const registered: ToolDefinition[] = []
  const listeners = new Map<string, ((...args: never[]) => unknown)[]>()
  const sections: { id: string; content: string | (() => string) }[] = []
  const disposed: (() => void)[] = []

  const ctx = {
    tools: {
      register: (tool: ToolDefinition) => { registered.push(tool) },
      guard: () => () => undefined,
      restrict: () => () => undefined,
      get: () => undefined,
      schemas: () => [],
    },
    on: (event: string, handler: (...args: never[]) => unknown) => {
      const list = listeners.get(event) ?? []
      list.push(handler)
      listeners.set(event, list)
      return () => undefined
    },
    effect: (factory: () => void | (() => void)) => {
      const disposer = factory()
      if (typeof disposer === 'function') disposed.push(disposer)
      return () => undefined
    },
    systemPrompt: {
      section: (section: { id: string; content: string | (() => string) }) => {
        sections.push(section)
        return () => undefined
      },
    },
  } as unknown as Context

  return { registered, listeners, sections, disposed, ctx }
}

function execution(name: string, args: unknown = {}): ToolRunContext {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: args,
    token: Symbol('token'),
    signal: new AbortController().signal,
    deferContext: () => undefined,
    concludeTurn: () => undefined,
  }
}

function valueOf(result: unknown): Record<string, unknown> {
  return result as Record<string, unknown>
}

before(async () => {
  await fsp.rm(ROOT, { recursive: true, force: true })
  await fsp.mkdir(ROOT, { recursive: true })
  // Keep the host-side trust root (signing keys, anchors) inside the fixture.
  process.env.DSH_PROOF_TRUST_DIR = join(ROOT, 'trust')
  await fsp.writeFile(join(ROOT, 'package.json'), JSON.stringify({
    name: 'wiring-fixture',
    scripts: { test: 'node -e "process.exit(0)"' },
  }))
  await fsp.writeFile(join(ROOT, 'ok.txt'), 'hi\n')
})

after(async () => {
  delete process.env.DSH_PROOF_TRUST_DIR
  await fsp.rm(ROOT, { recursive: true, force: true })
})

function config(overrides: Partial<Parameters<typeof plugin.apply>[1]> = {}) {
  const resolved = Config({} as never) as unknown as Record<string, unknown>
  return { ...resolved, ...overrides } as Parameters<typeof plugin.apply>[1]
}

test('the plugin declares the DSH contract surface', () => {
  assert.equal(plugin.name, 'dsh-proof')
  assert.deepEqual(plugin.inject, ['tools'])
  assert.equal(typeof plugin.apply, 'function')
  assert.ok(plugin.Config, 'the Schemastery config schema is exported alongside the Config type')
})

test('Schemastery fills configuration defaults and rejects bad values', () => {
  const defaults = valueOf(Config({} as never))
  assert.equal(defaults.evidenceDir, '.proof')
  assert.equal(defaults.evidenceStore, 'host', 'evidence defaults to the host trust root, outside the workspace')
  assert.equal(defaults.checkpointEvery, 25)
  assert.equal(defaults.requireBaseline, 'warn')
  assert.equal(defaults.concurrency, 2)
  assert.throws(() => Config({ requireBaseline: 'nonsense' } as never), /invalid|expected|union/i)
  assert.throws(() => Config({ concurrency: 'lots' } as never), /invalid|expected|number/i)
})

test('workspace mode gates writes into the evidence store', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  const denied = await gate(
    { name: 'write', arguments: { path: '.proof/evidence.jsonl', content: 'forged' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(denied.kind, 'ask')
  assert.match(denied.reason ?? '', /evidence/i)

  // Ordinary writes are never gated by the evidence-store guard.
  const allowed = await gate(
    { name: 'write', arguments: { path: 'ok.txt', content: 'fine' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(allowed.kind, 'allow')
})

test('workspace mode cannot be bypassed with absolute paths or dotted detours', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  // Every one of these names the same file: <root>/.proof/evidence.jsonl.
  const forgeries = [
    join(ROOT, '.proof', 'evidence.jsonl'), // host-style absolute
    `${ROOT.replace(/\\/g, '/')}/.proof/evidence.jsonl`, // forward-slash absolute
    'sub/../.proof/evidence.jsonl', // dotted detour
  ]
  for (const forged of forgeries) {
    const denied = await gate(
      { name: 'write', arguments: { path: forged, content: 'forged' }, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'ask', `a write naming the evidence store must ask, whatever path shape it uses: ${forged}`)
    assert.match(denied.reason ?? '', /evidence/i)
  }
})

test('workspace mode gates moves whose source key carries the evidence log out', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  // `source` is excluded from the watcher's path keys (it usually carries
  // content, not paths) — but the guard must still see it: moving the log OUT
  // of the store through the source leg is exactly the exfiltration the gate
  // exists for, and a false positive only costs one approval prompt.
  const denied = await gate(
    { name: 'move', arguments: { source: '.proof/evidence.jsonl', dest: 'exfil.jsonl' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(denied.kind, 'ask', 'a move sourcing the evidence log must ask even though the watcher ignores content keys')
  assert.match(denied.reason ?? '', /evidence/i)

  // The precise view is unchanged: a source holding plain content still
  // contributes nothing to the watcher's path extraction.
  assert.deepEqual(
    WorkspaceWatch.pathsIn({ source: 'src/old/text' }),
    [],
    'content under source stays invisible to the watcher',
  )
  assert.ok(
    WorkspaceWatch.pathsIn({ source: 'src/old/text' }, { contentKeys: true }).includes('src/old/text'),
    'the guard view re-admits the content key',
  )
})

test('apply registers exactly the seven proof tools', () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  // λ: the registry grew by the three testimony tools — Class B (jury
  // request/submit) and Class C (human endorsement). The list is exhaustive
  // on purpose: a tool added or renamed by accident must break this test.
  assert.deepEqual(
    harness.registered.map(t => t.name).sort(),
    ['proof_baseline', 'proof_claim', 'proof_endorse', 'proof_jury', 'proof_jury_submit', 'proof_status', 'proof_verify'],
  )

  for (const tool of harness.registered) {
    assert.ok(tool.description.length > 40, `${tool.name} needs a description the model can act on`)
    assert.ok(tool.output?.schema, `${tool.name} must declare a canonical output schema`)
    assert.equal(typeof tool.output.render, 'function')
    assert.equal(typeof tool.execute, 'function')
    // Replay-safe UI projection: pure functions of (args, value).
    assert.equal(typeof tool.presentCall, 'function')
    assert.equal(typeof tool.presentResult, 'function')
    assert.equal(typeof tool.output.presentationMeta, 'function')
  }

  // Hooks land on the documented extension points.
  assert.ok(harness.listeners.has('tools/pre-execute'), 'baseline gate')
  assert.ok(harness.listeners.has('tools/result'), 'mutation observer')
  assert.ok(harness.listeners.has('agent/turn-stopping'), 'drift + unproven-claim enforcement')

  // The prompt section is registered and renders.
  assert.equal(harness.sections.length, 1)
  const section = harness.sections[0]
  const rendered = typeof section?.content === 'function' ? section.content() : section?.content
  assert.match(String(rendered), /Completion proof/)
  assert.match(String(rendered), /proof_claim/)

  // Teardown is registered as an effect disposer.
  assert.equal(harness.disposed.length, 1)
})

test('presentation projections are pure and replay-stable', () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  for (const tool of harness.registered) {
    const callA = tool.presentCall!({ claim: 'x' })
    const callB = tool.presentCall!({ claim: 'x' })
    assert.deepEqual(callA, callB, `${tool.name}.presentCall must be deterministic`)

    const fakeResult = { content: [{ type: 'text', text: 'x' }], isError: false, meta: { summary: 's' } }
    const resultA = tool.presentResult!({ claim: 'x' }, fakeResult as never)
    const resultB = tool.presentResult!({ claim: 'x' }, fakeResult as never)
    assert.deepEqual(resultA, resultB, `${tool.name}.presentResult must be deterministic`)

    const metaA = tool.output.presentationMeta!({ claim: 'x' }, { summary: 's' })
    const metaB = tool.output.presentationMeta!({ claim: 'x' }, { summary: 's' })
    assert.deepEqual(metaA, metaB, `${tool.name}.presentationMeta must be deterministic`)
  }
})

test('proof_status returns a canonical value and honest "no baseline" text', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const status = harness.registered.find(t => t.name === 'proof_status')!
  const value = valueOf(await status.execute({}, execution('proof_status')))

  assert.equal(value.hasBaseline, false)
  assert.equal(value.discovered, 1, 'the fixture declares one npm test script')
  assert.equal(value.evidenceLogIntact, true)
  assert.equal(typeof value.summary, 'string')
  assert.match(String(value.summary), /No baseline/)

  // render() must turn that value into model-facing content, not leak it raw.
  const content = status.output.render({}, value as never)
  assert.equal(content.length, 1)
  assert.match((content[0] as { text: string }).text, /Proof state|Objective checks|No baseline/i)
})

test('a mutation is gated while no baseline exists', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'ask' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  const denied = await gate(
    { name: 'write', arguments: { path: 'ok.txt' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(denied.kind, 'ask')
  assert.match(denied.reason ?? '', /baseline/i)

  // A read is never gated.
  const allowed = await gate(
    { name: 'read_file', arguments: { path: 'ok.txt' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(allowed.kind, 'allow')
})

test('warn mode passes the mutation and injects a corrective baseline notice at turn end', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    // Drift and claim enforcement off on purpose: the turn-stopping hook must
    // exist for the warn notice alone.
    plugin.apply(harness.ctx, config({ requireBaseline: 'warn', driftDetection: false, enforceOnTurnEnd: false }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string }>
  const allowed = await gate(
    { name: 'write', arguments: { path: 'ok.txt', content: 'x' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(allowed.kind, 'allow', 'warn never blocks the call')

  const injected: { content: { text: string }[] }[] = []
  const turnStop = harness.listeners.get('agent/turn-stopping')![0] as (payload: unknown) => Promise<void>
  const payload = {
    agent: { inject: (message: unknown) => { injected.push(message as { content: { text: string }[] }) } },
    turn: 1,
    signal: new AbortController().signal,
  }
  await turnStop(payload)
  assert.equal(injected.length, 1, 'the deferred notice is delivered when the turn ends')
  assert.match(injected[0]!.content[0]!.text, /baseline/)
  assert.match(injected[0]!.content[0]!.text, /proof_baseline/)

  await turnStop(payload)
  assert.equal(injected.length, 1, 'the pending flag is consumed by the injection, not re-fired')
})

test('apply + teardown leaves nothing behind', () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  for (const dispose of harness.disposed) dispose()
  assert.ok(true, 'disposers ran without throwing')
})

// ---------------------------------------------------------------------------
// Observation/turn-stop ordering (T2): the tools/result watcher is
// fire-and-forget, but the turn can stop immediately behind the last tool
// result — the stop hook must wait for the observation to land before it
// enforces anything.
// ---------------------------------------------------------------------------

test('turn-stopping waits for a still-in-flight tools/result observation', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const onResult = harness.listeners.get('tools/result')![0]! as (exec: unknown, result: unknown) => void
  const turnStop = harness.listeners.get('agent/turn-stopping')![0]! as (payload: unknown) => Promise<void>

  await fsp.writeFile(join(ROOT, 'late.txt'), 'v1\n')
  const injected: string[] = []
  const payload = {
    agent: { inject: (message: unknown) => { injected.push((message as { content: { text: string }[] }).content[0]!.text) } },
    turn: 1,
    signal: new AbortController().signal,
  }

  // Fire the turn's last tool result and the stop hook back-to-back with no
  // await in between, so the observation's fingerprint read is guaranteed
  // still in flight when the hook starts (its fs completion needs an event
  // loop turn; nothing synchronous can outrun it). `mutating` is only set
  // after that read settles: without the wait, the unproven-claim enforcement
  // below reads the pre-observation state and the mutation escapes notice.
  onResult({ name: 'write', arguments: { path: 'late.txt', content: 'v1\n' } }, { isError: false, content: [] })
  await turnStop(payload)

  assert.equal(injected.length, 1, 'the mutation flag from the pending observe() must be visible to turn-end enforcement')
  assert.match(injected[0]!, /mutated the workspace but made no proven completion claim/)
})

test('a hostile observation payload degrades without wedging the turn wind-down', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ driftDetection: true }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const onResult = harness.listeners.get('tools/result')![0]! as (exec: unknown, result: unknown) => void
  const turnStop = harness.listeners.get('agent/turn-stopping')![0]! as (payload: unknown) => Promise<void>

  const injected: string[] = []
  const payload = {
    agent: { inject: (message: unknown) => { injected.push((message as { content: { text: string }[] }).content[0]!.text) } },
    turn: 1,
    signal: new AbortController().signal,
  }

  // A hostile `arguments` payload (null) must neither crash the observation
  // nor the hook: pathsIn degrades to "no paths", the call still counts as a
  // mutation by name, and the turn winds down normally with its notice.
  onResult({ name: 'write', arguments: null }, { isError: true, content: [] })
  await turnStop(payload)
  assert.ok(true, 'turn-stopping completed despite a hostile observation payload')
  assert.equal(injected.length, 1, 'enforcement still sees the mutation even when no paths could be extracted')
})

// ---------------------------------------------------------------------------
// Honest-signal projections (v0.7): the canonical values must carry the
// engine's degradation/abort/verifiability flags, and only when abnormal —
// the normal path stays byte-identical to what README examples pin.
// ---------------------------------------------------------------------------

/** Minimal report satisfying everything toVerifyValue/toClaimValue read. */
function fakeReport(overrides: { grade?: ProofGrade; unverified?: string[] } = {}): ProofReport {
  return {
    grade: overrides.grade ?? 'unproven',
    root: 'ab'.repeat(32),
    unverified: overrides.unverified ?? [],
    summary: { passing: 1, failing: 0, regressions: 0, fixed: 0, preExisting: 0, indeterminate: 0 },
  } as unknown as ProofReport
}

function fakeAudit(chainOverrides: Partial<AuditReport['chain']> = {}): AuditReport {
  return {
    ok: true,
    total: 0,
    corrupt: [],
    chain: {
      mode: 'unsigned',
      breaks: [],
      checkpoints: 0,
      badCheckpoints: [],
      unverifiableCheckpoints: [],
      unsignedCheckpoints: [],
      headMismatches: [],
      tailRecords: 0,
      rewind: false,
      anchorMismatch: false,
      anchorForged: false,
      baselineTampered: false,
      ...chainOverrides,
    },
  }
}

function appliedTools(): ToolDefinition[] {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  return harness.registered
}

function renderedText(tool: ToolDefinition, meta: unknown): string {
  const blocks = tool.output!.render({}, meta as never)
  return (blocks[0] as { text: string }).text
}

test('untouchedChecks reflects the impact selection, not discovered minus checks', () => {
  // The attributed check list covers every discovered spec, so the old
  // `discovered - checks.length` formula was structurally always 0.
  const checks = [
    { label: 'unit', verdict: 'still-passing', suspects: [] },
    { label: 'e2e', verdict: 'not-run', suspects: [] },
  ]
  const selection = { untouched: [{ id: 'lint' }, { id: 'types' }], precision: 'approximate' as const }
  const value = toVerifyValue(fakeReport(), ['src/a.ts'], checks, selection)
  assert.equal(value.untouchedChecks, 2, 'two specs proven untouched by impact analysis')
  assert.equal(value.impactPrecision, 'approximate')

  // Forced runs (degraded or `all`) have an empty untouched list by construction.
  const forced = toVerifyValue(fakeReport(), [], [], { untouched: [], precision: 'forced' })
  assert.equal(forced.untouchedChecks, 0)
})

test('degraded rides along on the verify value only when the engine flagged it', () => {
  const clean = toVerifyValue(fakeReport(), [], [], { untouched: [], precision: 'approximate' })
  assert.ok(!('degraded' in clean), 'clean path canonical value stays byte-identical — no degraded field')

  const degraded = toVerifyValue(fakeReport(), [], [], { untouched: [], precision: 'forced' }, undefined, true)
  assert.equal(degraded.degraded, true, 'git-facts-unavailable degradation must reach the model')

  const rendered = renderedText(
    appliedTools().find(t => t.name === 'proof_verify')!,
    { summary: 's', degraded: true, changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [] },
  )
  assert.match(rendered, /DEGRADED — git facts unavailable → full check set forced/)
})

test('aborted baselines say so in the canonical value, the render and the card title', () => {
  const records = [
    { status: 'pass', label: 'unit', durationMs: 4 },
    { status: 'aborted', label: 'e2e', durationMs: 0 },
  ]
  const anchored = toBaselineValue({ baselineId: 'b'.repeat(32), root: 'r'.repeat(64) }, records.slice(0, 1))
  assert.ok(!('aborted' in anchored), 'clean path canonical value stays byte-identical — no aborted field')

  const aborted = toBaselineValue({ baselineId: 'b'.repeat(32), root: 'r'.repeat(64), aborted: true }, records)
  assert.equal(aborted.aborted, true)
  assert.equal(aborted.ok, false, 'an aborted record is not a clean run')

  const baseline = appliedTools().find(t => t.name === 'proof_baseline')!
  const rendered = renderedText(baseline, { summary: 'Baseline bbbbbbbb: 1 passing, 0 failing, 1 skipped/unrun across 2 check(s).', aborted: true, failingLabels: [] })
  assert.match(rendered, /ABORTED/)
  assert.match(rendered, /not an anchor/)
  assert.match(rendered, /no-baseline/)

  // Even an all-green-but-cancelled batch must not be titled "established".
  const card = baseline.presentResult!({}, { meta: { ok: true, aborted: true, summary: 's', ran: 1, passing: 1 } } as never) as { title: string }
  assert.match(card.title, /aborted — not anchored/)
})

test('unverifiable checkpoints and a forged anchor surface in the status value only when present', () => {
  const clean = toStatusValue({
    specs: [],
    latest: new Map<string, { status: string; recordedAt: string }>(),
    audit: fakeAudit(),
    snapshot: { dirty: [] },
  })
  assert.ok(!('unverifiableCheckpoints' in clean) && !('anchorForged' in clean),
    'clean path canonical value stays byte-identical — neither field emitted')

  const suspicious = toStatusValue({
    specs: [],
    latest: new Map<string, { status: string; recordedAt: string }>(),
    audit: fakeAudit({ unverifiableCheckpoints: [3, 9], anchorForged: true }),
    snapshot: { dirty: [] },
  })
  assert.equal(suspicious.unverifiableCheckpoints, 2)
  assert.equal(suspicious.anchorForged, true)
  // A key we do not hold is a missing capability, not a forgery charge: the
  // audit deliberately does not fail on it, and neither may chainIntact.
  const unverifiableOnly = toStatusValue({
    specs: [],
    latest: new Map<string, { status: string; recordedAt: string }>(),
    audit: fakeAudit({ mode: 'signed', checkpoints: 4, unverifiableCheckpoints: [3, 9] }),
    snapshot: { dirty: [] },
  })
  assert.equal(unverifiableOnly.chainIntact, true)
})

test('renderStatus warns on the new trust signals and replays old meta without throwing', () => {
  const status = appliedTools().find(t => t.name === 'proof_status')!

  const abnormal = renderedText(status, {
    summary: 's', checks: [],
    tailRecords: 4, unverifiableCheckpoints: 2, anchorForged: true,
  })
  assert.match(abnormal, /4 record\(s\) after the last signed checkpoint — chain-only protection window/)
  assert.match(abnormal, /2 checkpoint\(s\) signed by a key this host cannot verify/)
  assert.match(abnormal, /ANCHOR SIGNATURE INVALID/)

  // Pre-v0.7 session meta lacks every new field; replay must degrade to prose.
  let legacy = ''
  assert.doesNotThrow(() => { legacy = renderedText(status, { summary: 's', checks: [] }) })
  assert.ok(!legacy.includes('protection window'), 'no warning lines without the abnormal state')
  assert.doesNotThrow(() => { renderedText(status, {}) })
})

test('ClaimValue no longer lies: regressions are named regressions, and `verified` is gone', () => {
  const report = fakeReport({ grade: 'regressed' })
  const verified = toVerifyValue(
    report,
    ['src/a.ts'],
    [{ label: 'unit', verdict: 'regression', suspects: ['src/a.ts'], current: { outputHead: 'AssertionError: expected 1 to be 2' } }],
    { untouched: [], precision: 'approximate' },
  )
  const claim = toClaimValue('fixed the login redirect bug', report, verified)
  assert.ok(!('verified' in claim), 'the old field name promised credit while carrying blame')
  assert.deepEqual(claim.regressions, verified.regressions)
  assert.equal(claim.proven, false)
  assert.match(claim.summary, /NOT PROVEN/)

  // The declared canonical schema matches the emitted shape.
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!
  const properties = (claimTool.output!.schema.properties ?? {}) as Record<string, unknown>
  assert.ok(!('verified' in properties), 'schema must not advertise the removed field')
  assert.ok('regressions' in properties, 'schema must declare regressions')
})

// ---------------------------------------------------------------------------
// First-frame baseline honesty (T1): loading the plugin over a workspace that
// already has a baseline on disk must not keep the prompt claiming "no
// baseline yet". apply() prewarms the baseline probe alongside check
// discovery; the lazy section re-evaluates on every render, so the truth lands
// on the next frame after the probe settles.
// ---------------------------------------------------------------------------

test('a pre-existing baseline on disk reaches the prompt section after the prewarm probe', async () => {
  const proofDir = join(ROOT, '.proof')
  await fsp.mkdir(proofDir, { recursive: true })
  // Everything loadBaseline() needs to recognise the document: an id and a
  // check table.
  await fsp.writeFile(join(proofDir, 'baseline.json'), JSON.stringify({
    baselineId: 'b'.repeat(32),
    root: 'r'.repeat(64),
    checks: [],
  }))

  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  try {
    assert.equal(harness.sections.length, 1)
    const section = harness.sections[0]!
    const render = (): string => (typeof section.content === 'function' ? section.content() : section.content)

    // The very first frame is rendered synchronously, before the probe's fs
    // read can complete — it still says no baseline, and that is the boundary
    // of the fix: honesty starts on the next frame.
    assert.match(render(), /No baseline is established yet/)

    // Drain the fire-and-forget probe (bounded poll — no timing sensitivity,
    // just an upper bound on how long a local stat+read may take).
    const deadline = Date.now() + 5_000
    let text = render()
    while (!/A baseline is already established/.test(text) && Date.now() < deadline) {
      await new Promise(resolve => { setTimeout(resolve, 10) })
      text = render()
    }
    assert.match(text, /A baseline is already established for this workspace\./)
    assert.ok(!/No baseline is established/.test(text), 'once the probe lands, the lie must stop')
  } finally {
    await fsp.rm(proofDir, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------
// Graded trust (γ): the bayesian scheduler's product — confidence, basis and
// wave-plan footprint — must reach the canonical verify/claim values and the
// render, and only when it exists: the legacy binary path stays byte-identical.
// ---------------------------------------------------------------------------

/** fakeReport grown by the graded-trust pair the bayesian regime produces. */
function gradedReport(
  confidence: number,
  confidenceBasis: ConfidenceBasis,
  overrides: { grade?: ProofGrade; unverified?: string[] } = {},
): GradedProofReport {
  return { ...fakeReport(overrides), confidence, confidenceBasis }
}

const bayesianSchedule = {
  mode: 'bayesian' as const,
  waves: 3,
  stoppedEarly: 'certified' as const,
  skippedByPlan: [
    { checkId: 'lint', priorHealthy: 0.99 },
    { checkId: 'e2e', priorHealthy: 0.98 },
  ],
}

test('graded-trust fields ride the verify value only when the scheduler produced them', () => {
  const value = toVerifyValue(
    gradedReport(0.9654321, 'certified-subset', { grade: 'proven' }),
    ['src/a.ts'], [],
    { untouched: [], precision: 'approximate' },
    undefined, undefined,
    bayesianSchedule,
  )
  assert.equal(value.confidence, 0.97, 'the posterior is pre-rounded to two decimals for display')
  assert.equal(value.confidenceBasis, 'certified-subset')
  assert.equal(value.certifiedSkips, 2, 'planned skips carry their count')
  assert.equal(value.stoppedEarly, 'certified')
  assert.equal(value.waves, 3)

  // A plan that ran to completion: nothing stopped early, nothing was skipped,
  // so neither key may appear even though the confidence does.
  const completed = toVerifyValue(
    gradedReport(0.99, 'full-coverage'),
    [], [], { untouched: [], precision: 'approximate' },
    undefined, undefined,
    { mode: 'bayesian' as const, waves: 1, stoppedEarly: null, skippedByPlan: [] },
  )
  assert.equal(completed.confidence, 0.99)
  assert.equal(completed.confidenceBasis, 'full-coverage')
  assert.ok(!('stoppedEarly' in completed) && !('certifiedSkips' in completed),
    'null stop and empty skip-set emit neither field')

  // The legacy binary path: no confidence on the report, no schedule — none of
  // the graded-trust keys may appear, byte-stable with pre-γ session logs.
  const legacy = toVerifyValue(fakeReport(), [], [], { untouched: [], precision: 'approximate' })
  for (const key of ['confidence', 'confidenceBasis', 'certifiedSkips', 'stoppedEarly', 'waves']) {
    assert.ok(!(key in legacy), `${key} must not appear on the ungraded path`)
  }
})

test('renderVerify states the posterior, its basis and the prior-carried skips, and replays old meta without throwing', () => {
  const verify = appliedTools().find(t => t.name === 'proof_verify')!

  const certified = renderedText(verify, {
    summary: 's', changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [],
    confidence: 0.97, confidenceBasis: 'certified-subset', certifiedSkips: 2, stoppedEarly: 'certified', waves: 3,
  })
  assert.match(certified, /confidence p≈0\.97 \(certified-subset · 3 wave\(s\) · 2 check\(s\) certified by prior\)/)

  const degraded = renderedText(verify, {
    summary: 's', changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [],
    confidence: 0.61, confidenceBasis: 'degraded', stoppedEarly: 'budget', waves: 2,
  })
  assert.match(degraded, /confidence p≈0\.61 \(degraded · 2 wave\(s\) · stopped early: budget\)/)

  const wholeBatch = renderedText(verify, {
    summary: 's', changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [],
    confidence: 0.99, confidenceBasis: 'full-coverage',
  })
  assert.match(wholeBatch, /confidence p≈0\.99 \(full-coverage · all checks run\)/)

  // Pre-γ session meta lacks every new field; replay must degrade to prose,
  // never throw, and never invent a confidence line.
  let legacy = ''
  assert.doesNotThrow(() => {
    legacy = renderedText(verify, {
      summary: 's', changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [],
    })
  })
  assert.ok(!legacy.includes('confidence'), 'no confidence line without a posterior')
  // A partial/hostile value (posterior but no basis) still renders the number.
  assert.doesNotThrow(() => { renderedText(verify, {}) })
  assert.doesNotThrow(() => { renderedText(verify, { summary: 's', confidence: 0.5 }) })
})

test('claim values carry the posterior and say p≈ in the summary when one exists', () => {
  const report = gradedReport(0.9654321, 'certified-subset', { grade: 'proven' })
  const verified = toVerifyValue(report, ['src/a.ts'], [], { untouched: [], precision: 'approximate' })
  const claim = toClaimValue('fixed the flaky retry', report, verified)
  assert.equal(claim.confidence, 0.97, 'the posterior transfers with the claim')
  assert.match(claim.summary, /PROVEN \(p≈0\.97\) — /)

  const stale = gradedReport(0.61, 'degraded', { grade: 'stale', unverified: ['e2e'] })
  const staleClaim = toClaimValue('same claim', stale, toVerifyValue(stale, [], [], { untouched: [], precision: 'approximate' }))
  assert.match(staleClaim.summary, /NOT PROVEN \(stale, p≈0\.61\)/)

  // The legacy binary path: no posterior anywhere, canonical claim unchanged.
  const legacyReport = fakeReport({ grade: 'unproven' })
  const legacyClaim = toClaimValue(
    'same claim', legacyReport, toVerifyValue(legacyReport, [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.ok(!('confidence' in legacyClaim), 'no posterior on the ungraded path — canonical value stays byte-identical')
  assert.ok(!legacyClaim.summary.includes('p≈'))
})

// ---------------------------------------------------------------------------
// Typed claim contracts (ζ): a proof_claim carrying a `kind` is judged by
// engine.verifyContract against the obligations that kind imposes. The tool
// surface must declare the new parameters, the projection must carry the
// obligations into the canonical value (unmet ones as blockers), and the
// untyped path must stay byte-identical to pre-ζ session logs.
// ---------------------------------------------------------------------------

test('proof_claim declares the typed-contract parameters without weakening the legacy surface (ζ)', () => {
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!
  const params = claimTool.parameters as Record<string, Record<string, unknown>>

  assert.equal(params.claim?.required, true, 'claim stays required')
  assert.equal(params.claim?.type, 'string')
  assert.equal(params.changed?.type, 'array', 'the legacy changed parameter survives untouched')

  const kind = params.kind!
  assert.equal(kind.type, 'string')
  assert.deepEqual(kind.enum, ['behavior-preserving', 'behavior-adding', 'perf-budget', 'docs-only', 'llm-jury'])
  assert.match(
    String(kind.description),
    /behavior-preserving.*behavior-adding.*perf-budget.*docs-only.*llm-jury/s,
    'one sentence of guidance: which claim goes with which contract',
  )
  assert.match(String(kind.description), /budgetMs/)
  assert.match(String(kind.description), /review/)

  assert.equal(params.budgetMs?.type, 'number')
  assert.match(String(params.budgetMs?.description), /benchmark checks must stay within this/)
  assert.equal(params.review?.type, 'string')
  assert.match(String(params.review?.description), /the self-review that jury evidence carries/)
  assert.equal(params.entryPoints?.type, 'array')
  assert.deepEqual(params.entryPoints?.items, { type: 'string' })
})

test('typed claims carry obligations and unmet ones block; untyped claims stay byte-identical (ζ)', () => {
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!

  // The engine downgrades a proven-with-unmet run to `stale` — render that corner.
  const report = fakeReport({ grade: 'stale' })
  const verified = toVerifyValue(report, ['src/api.ts'], [], { untouched: [], precision: 'approximate' })
  const contract = {
    kind: 'behavior-preserving' as const,
    obligations: [
      { id: 'zero-regressions', met: true, detail: '2 check(s) compared against the baseline, 0 regressions' },
      { id: 'api-surface-unchanged', met: false, detail: 'public API changed — added: src/api.ts#frobnicate' },
    ],
  }
  const claim = toClaimValue('refactored the retry internals', report, verified, contract)
  assert.equal(claim.kind, 'behavior-preserving')
  assert.deepEqual(
    claim.obligations,
    [
      { id: 'zero-regressions', met: true, detail: '2 check(s) compared against the baseline, 0 regressions' },
      { id: 'api-surface-unchanged', met: false, detail: 'public API changed — added: src/api.ts#frobnicate' },
    ],
    'the obligation verdicts transfer verbatim into the canonical value',
  )
  assert.ok(!('jury' in claim), 'jury marks docs-only verdicts only')
  assert.ok(
    claim.blockers.includes('contract unmet: api-surface-unchanged — public API changed — added: src/api.ts#frobnicate'),
    'an unmet obligation is a blocker carrying its action-item detail',
  )
  assert.ok(
    claim.blockers.some(b => b.startsWith('Stale evidence:')),
    'legacy blockers and contract blockers coexist, both listed',
  )

  const rendered = renderedText(claimTool, claim)
  assert.match(rendered, /^contract: behavior-preserving$/m)
  assert.match(rendered, /✓ zero-regressions/)
  assert.match(rendered, /✖ api-surface-unchanged — public API changed — added: src\/api\.ts#frobnicate/)

  const card = claimTool.presentResult!({}, { meta: claim } as never) as { title: string }
  assert.match(card.title, /Claim \(behavior-preserving\)/)

  // The untyped path: none of the new keys, and the render is byte-identical
  // to what pre-ζ session logs already hold.
  const legacyReport = fakeReport({ grade: 'stale', unverified: ['e2e'] })
  const legacy = toClaimValue(
    'same claim', legacyReport, toVerifyValue(legacyReport, [], [], { untouched: [], precision: 'approximate' }),
  )
  for (const key of ['kind', 'obligations', 'jury']) {
    assert.ok(!(key in legacy), `${key} must not appear on the untyped path`)
  }
  assert.equal(
    renderedText(claimTool, legacy),
    [
      '✗ NOT PROVEN (STALE) — same claim',
      'evidence root: abababababab',
      '',
      'Blockers:',
      '  · Stale evidence: e2e.',
      '',
      'NOT PROVEN (stale) — "same claim". Stale evidence: e2e.',
    ].join('\n'),
    'the untyped render stays byte-identical to the pre-ζ renderer',
  )

  // Defensive replay: partial or hostile meta never throws — it degrades to prose.
  assert.doesNotThrow(() => { renderedText(claimTool, { summary: 's' }) })
  assert.doesNotThrow(() => { renderedText(claimTool, { summary: 's', kind: 'docs-only', obligations: null }) })
  assert.doesNotThrow(() => { renderedText(claimTool, { summary: 's', kind: 42 }) })
})

test('docs-only jury claims mark their verdict as capped jury evidence (ζ)', () => {
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!

  const report = gradedReport(0.8, 'jury-only', { grade: 'proven' })
  const verified = toVerifyValue(report, ['README.md'], [], { untouched: [], precision: 'approximate' })
  const contract = {
    kind: 'docs-only' as const,
    obligations: [
      { id: 'zero-regressions', met: true, detail: 'docs-only claims run no checks — the regression obligation is carried by docs-only-changes instead' },
      { id: 'docs-only-changes', met: true, detail: 'all 1 changed path(s) are docs-only assets' },
      { id: 'jury-review', met: true, detail: 'jury self-review on record: "checked every link"' },
    ],
  }
  const claim = toClaimValue('documented the retry options', report, verified, contract)
  assert.equal(claim.proven, true)
  assert.equal(claim.kind, 'docs-only')
  assert.equal(claim.jury, true, 'a fully-met docs-only contract is standing jury evidence')
  assert.equal(claim.confidence, 0.8, 'the cap rides as the claim confidence')

  const rendered = renderedText(claimTool, claim)
  assert.match(rendered, /^contract: docs-only$/m)
  assert.match(rendered, /✓ jury-review/)
  assert.match(rendered, /jury evidence/)
  assert.match(rendered, /self-attestation is capped at p≈0\.80/)

  const card = claimTool.presentResult!({}, { meta: claim } as never) as { title: string }
  assert.match(card.title, /✓ Claim \(docs-only\)/)

  // A docs-only contract with an unmet obligation is not standing jury evidence.
  const broken = toClaimValue('docs only', gradedReport(0.8, 'jury-only', { grade: 'stale' }), verified, {
    kind: 'docs-only',
    obligations: [
      { id: 'jury-review', met: false, detail: 'docs-only claims require contract.review — write down what a human reviewer should double-check' },
    ],
  })
  assert.ok(!('jury' in broken), 'an unmet jury obligation means the jury does not stand')
  assert.ok(broken.blockers.some(b => b.startsWith('contract unmet: jury-review — ')))
})

// ---------------------------------------------------------------------------
// λ: graded testimony through the tool surface — Class B (LLM jury) as a
// request/submit pair whose prompt is frozen on-chain before the juror
// speaks, and Class C (human endorsement) as a call that only executes after
// the host approval seam said yes. Each test builds its own engine on a
// fresh fixture so its chain is its own.
// ---------------------------------------------------------------------------

/** A fresh workspace + directly-built engine + its tools, chain and all. */
async function attestFixture(name: string): Promise<{
  engine: ProofEngine; tools: ToolDefinition[]; logPath: string; dir: string
}> {
  const dir = join(WORKSPACE, '.openclaw', 'tmp', `proof-attest-${name}-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(dir, { recursive: true })
  await fsp.writeFile(join(dir, 'package.json'), JSON.stringify({
    name: `attest-${name}`,
    scripts: { test: 'node -e "process.exit(0)"' },
  }))
  const evidenceDir = join(dir, 'evi')
  const logPath = `${evidenceDir}/evidence.jsonl`
  const engine = new ProofEngine({ root: dir, evidenceDir, fs: new NodeFsPort() })
  return { engine, tools: createProofTools(engine, undefined, logPath), logPath, dir }
}

/** Every marker payload on a fixture's chain, in log order — the audit read. */
async function markersOf(logPath: string): Promise<Record<string, unknown>[]> {
  const raw = await fsp.readFile(logPath, 'utf8')
  const payloads: Record<string, unknown>[] = []
  for (const line of raw.split('\n')) {
    if (line.trim().length === 0) continue
    const envelope = JSON.parse(line) as { kind?: string; payload?: unknown }
    if (envelope.kind === 'marker' && typeof envelope.payload === 'object' && envelope.payload !== null) {
      payloads.push(envelope.payload as Record<string, unknown>)
    }
  }
  return payloads
}

test('λ: proof_jury freezes the deliberation prompt and lands attest/jury-requested on the chain', async () => {
  const { tools, logPath, dir } = await attestFixture('jury')
  try {
    const claim = 'the retry helper now caps attempts at three'
    const context = 'src/retry.ts: const MAX_ATTEMPTS = 3; tests/retry.test.ts covers the cap'
    const jury = tools.find(t => t.name === 'proof_jury')!

    const value = valueOf(await jury.execute({ claim, context }, execution('proof_jury', { claim, context })))

    // The canonical prompt is the deterministic assembly — byte for byte.
    assert.equal(value.prompt, juryPrompt(claim, context))
    assert.equal(value.claimId, claimIdOf(claim))
    assert.equal(value.rubricVersion, RUBRIC_V1)
    assert.match(String(value.instruction), /proof_jury_submit/)
    assert.match(String(value.instruction), /permanent Class B evidence/)
    assert.match(String(value.instruction), /replayable by any third party/)

    // The request marker is on the chain, digest over the exact prompt bytes.
    const requests = (await markersOf(logPath)).filter(p => p.label === 'attest/jury-requested')
    assert.equal(requests.length, 1)
    assert.equal(requests[0]!.claimId, claimIdOf(claim))
    assert.equal(requests[0]!.promptDigest, sha256(String(value.prompt)).slice(0, 16))
    assert.equal(requests[0]!.rubricVersion, RUBRIC_V1)

    // The render carries the full prompt (the juror must read it) + the charge.
    const rendered = renderedText(jury, value)
    assert.ok(rendered.includes(String(value.prompt)), 'the deliberation prompt rides the render verbatim')
    assert.match(rendered, /ACTION: deliberate strictly per the rubric/)
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

test('λ: proof_jury_submit records at gen+1, refuses mismatches and broken probabilities', async () => {
  const { engine, tools, logPath, dir } = await attestFixture('submit')
  try {
    const claim = 'the migration is idempotent'
    const claimId = claimIdOf(claim)
    const jury = tools.find(t => t.name === 'proof_jury')!
    const submit = tools.find(t => t.name === 'proof_jury_submit')!

    // A standing gen-0 deliberation from a previous session, seeded onto the
    // chain exactly as the attest marker writes it.
    await engine.storeView.mark('attest/jury', {
      kind: 'attest/jury',
      claimId,
      gen: 0,
      prompt: juryPrompt(claim, '<no additional context>'),
      rubricVersion: RUBRIC_V1,
      model: 'previous-juror',
      independence: 'fresh-context',
      verdict: 'abstain',
      probability: 0.5,
      output: 'the previous deliberation abstained',
      at: 1_767_225_600_000,
    })

    await jury.execute({ claim }, execution('proof_jury', { claim }))
    const value = valueOf(await submit.execute(
      {
        claimId,
        verdict: 'uphold',
        probability: 0.9,
        reasoning: 'The context shows the guard clamping attempts; nothing in it contradicts the claim.',
      },
      execution('proof_jury_submit', {}),
    ))

    assert.equal(value.recorded, true)
    assert.equal(value.gen, 1, 'the new deliberation lands at max-gen + 1 over the seeded gen 0')
    assert.equal(value.verdict, 'uphold')
    assert.equal(value.probability, 0.9)
    assert.equal(value.factor, Math.pow(0.9, DEFAULT_TRUST_WEIGHTS.classB), 'the pure p^classB factor, full precision')
    assert.match(String(value.note), /supersedes/)

    const onChain = (await markersOf(logPath)).filter(p => p.label === 'attest/jury')
    assert.equal(onChain.length, 2)
    const recorded = onChain[1]! as Record<string, unknown>
    assert.equal(recorded.gen, 1)
    assert.equal(recorded.verdict, 'uphold')
    assert.equal(recorded.probability, 0.9)
    assert.equal(recorded.independence, 'same-session', 'no isolated-model seam exists yet — recorded as lived')
    assert.equal(recorded.model, 'session-model (unverified)', 'an undeclared model identity is recorded as unverified')
    assert.equal(recorded.output, 'The context shows the guard clamping attempts; nothing in it contradicts the claim.')

    // A claimId that is not the pending request is refused — nothing lands.
    await assert.rejects(
      submit.execute(
        { claimId: 'deadbeefdeadbeef', verdict: 'uphold', probability: 0.9, reasoning: 'x' },
        execution('proof_jury_submit', {}),
      ),
      /claimId mismatch/,
    )
    // A probability outside [0,1] — or not a finite number — is refused first.
    await assert.rejects(
      submit.execute(
        { claimId, verdict: 'uphold', probability: 1.5, reasoning: 'x' },
        execution('proof_jury_submit', {}),
      ),
      /probability/,
    )
    await assert.rejects(
      submit.execute(
        { claimId, verdict: 'uphold', probability: 'high', reasoning: 'x' },
        execution('proof_jury_submit', {}),
      ),
      /probability/,
    )
    assert.equal(
      (await markersOf(logPath)).filter(p => p.label === 'attest/jury').length,
      2,
      'refused submissions never touch the chain',
    )
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

test('λ: proof_endorse asks the host for conscious approval, then records Class C on approval', async () => {
  // The seam: with the workflow gates off, the endorsement ask is the one
  // pre-execute decision the plugin registers.
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const gate = harness.listeners.get('tools/pre-execute')![0]! as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string; displayReason?: Record<string, string> }>

  const claim = 'the evidence chain is safe to hand to the customer'
  const asked = await gate(
    { name: 'proof_endorse', arguments: { claim, decision: 'endorse' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(asked.kind, 'ask', 'an endorsement never executes on the model\'s say-so alone')
  assert.ok(asked.reason?.includes(claim), 'the approval reason carries the claim the human is accepting')
  assert.match(String(asked.reason), /Class C evidence/)
  assert.match(asked.displayReason?.en ?? '', /consciously endorse\/reject/)
  assert.match(asked.displayReason?.['zh-CN'] ?? '', /背书\/否决/)

  // Every other tool passes straight through the endorsement seam.
  const passed = await gate(
    { name: 'proof_status', arguments: {}, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(passed.kind, 'allow')

  // Post-approval: execute records the Class C attestation with the default
  // approver and the evidence scope it could honestly address.
  const { tools, logPath, dir } = await attestFixture('endorse')
  try {
    const endorse = tools.find(t => t.name === 'proof_endorse')!
    const value = valueOf(await endorse.execute(
      { claim, decision: 'endorse' },
      execution('proof_endorse', { claim, decision: 'endorse' }),
    ))

    assert.equal(value.recorded, true)
    assert.equal(value.claimId, claimIdOf(claim))
    assert.equal(value.decision, 'endorse')
    assert.equal(value.approver, 'host-approver', 'no signature given — the human behind the approval is named')
    assert.deepEqual(
      value.scope,
      { claim, evidenceRoot: null },
      'v0.1 scope: best-effort root, honestly null when nothing is anchored',
    )
    assert.match(String(value.note), /risk acceptance/)
    assert.match(String(value.note), /never inflates the number/)
    assert.match(String(value.note), /rejection collapses it/)

    const humans = (await markersOf(logPath)).filter(p => p.label === 'attest/human')
    assert.equal(humans.length, 1)
    assert.equal(humans[0]!.approver, 'host-approver')
    assert.equal(humans[0]!.decision, 'endorse')
    assert.deepEqual(humans[0]!.scope, { claim, evidenceRoot: null })
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})
