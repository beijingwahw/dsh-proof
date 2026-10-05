/**
 * Plugin wiring — the DSH adapter surface, exercised without a harness.
 *
 * Loads the real plugin entry point, hands it a stand-in `Context`, and asserts
 * the contract it promises to DSH: four tools on the registry, the documented
 * pipeline hooks, a `proof:policy` prompt section, and tool bodies that return
 * canonical JSON values with pure presentation projections.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import * as plugin from '../src/index.ts'
import { toBaselineValue, toClaimValue, toStatusValue, toVerifyValue } from '../src/dsh/tools.ts'
import type { AuditReport, ProofGrade, ProofReport } from '../src/core/evidence.ts'
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

test('apply registers exactly the four proof tools', () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  assert.deepEqual(
    harness.registered.map(t => t.name).sort(),
    ['proof_baseline', 'proof_claim', 'proof_status', 'proof_verify'],
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
