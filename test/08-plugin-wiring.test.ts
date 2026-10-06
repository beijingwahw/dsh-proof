/**
 * Plugin wiring — the DSH adapter surface, exercised without a harness.
 *
 * Loads the real plugin entry point, hands it a stand-in `Context`, and asserts
 * the contract it promises to DSH: nine tools on the registry, the documented
 * pipeline hooks, a `proof:policy` prompt section, and tool bodies that return
 * canonical JSON values with pure presentation projections.
 */

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { execSync } from 'node:child_process'
import { promises as fsp } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import * as plugin from '../src/index.ts'
import { WorkspaceWatch } from '../src/dsh/observe.ts'
import { createProofTools, toBaselineValue, toClaimValue, toStatusValue, toVerifyValue } from '../src/dsh/tools.ts'
import { attachTeamBridge, createTeamBridge, normalizeTeamEvent, TEAM_EVENT_SEAMS } from '../src/dsh/agent-team.ts'
import { ProofEngine } from '../src/engine.ts'
import { NodeFsPort } from '../src/node-ports.ts'
import { DEFAULT_TRUST_WEIGHTS, RUBRIC_V1, claimIdOf, juryPrompt } from '../src/core/attest.ts'
import { SYNTHETIC_DIR_DEFAULT, SYNTHETIC_TEMPLATE, sandboxEntryFor } from '../src/core/synthetic.ts'
import { sha256 } from '../src/core/hash.ts'
import { FakeCommands, FakeWorkspace, MemoryFs } from './helpers.ts'
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

  // X-H-13: the write's path VALUE names the store, so the value sweep denies
  // it before the structured ask layer is even consulted — a string that
  // names the store is refused whatever key carried it.
  const denied = await gate(
    { name: 'write', arguments: { path: '.proof/evidence.jsonl', content: 'forged' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(denied.kind, 'deny')
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
    assert.equal(denied.kind, 'deny', `a write naming the evidence store must be denied, whatever path shape it uses: ${forged}`)
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
  // exists for. X-H-13: the value sweep no longer reads keys at all, so the
  // source string denies this before the structured layer runs.
  const denied = await gate(
    { name: 'move', arguments: { source: '.proof/evidence.jsonl', dest: 'exfil.jsonl' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(denied.kind, 'deny', 'a move sourcing the evidence log must be denied even though the watcher ignores content keys')
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

test('apply registers exactly the nine proof tools', () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  // λ grew the registry by the three testimony tools; ρ grew it again by the
  // two conjure tools (PTC synthesis request/run). The list is exhaustive on
  // purpose: a tool added or renamed by accident must break this test.
  assert.deepEqual(
    harness.registered.map(t => t.name).sort(),
    [
      'proof_baseline', 'proof_claim', 'proof_conjure', 'proof_conjure_run', 'proof_endorse',
      'proof_jury', 'proof_jury_submit', 'proof_status', 'proof_verify',
    ],
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

  // X-H-16: the evidence-store guard now registers FIRST in both store
  // modes, so the baseline ladder (registered second, only when its mode is
  // not 'off') sits at index 1.
  const gate = harness.listeners.get('tools/pre-execute')![1] as (
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

  // X-H-16: index 1 = the baseline ladder (the evidence guard is index 0 in
  // every mode now).
  const gate = harness.listeners.get('tools/pre-execute')![1] as (
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
  // H-23 made loadBaseline recompute the document's digest and refuse one
  // that does not reproduce byte-for-byte — the old fixture hand-wrote
  // `{"baselineId":"bbbb…","checks":[]}`, which is exactly the shape-only
  // forgery that loader used to accept. The honest fixture is a baseline the
  // engine itself wrote: mint one with a real ProofEngine over a scratch
  // workspace, then point apply()'s prewarm probe at it.
  const dir = join(WORKSPACE, '.openclaw', 'tmp', `proof-prewarm-${process.pid}`)
  await fsp.rm(dir, { recursive: true, force: true })
  await fsp.mkdir(dir, { recursive: true })
  await fsp.writeFile(join(dir, 'package.json'), JSON.stringify({
    name: 'prewarm-fixture',
    scripts: { test: 'node -e "process.exit(0)"' },
  }))
  const minter = new ProofEngine({
    root: dir,
    evidenceDir: '.proof',
    fs: new NodeFsPort(),
    commands: new FakeCommands(),
    workspace: new FakeWorkspace(dir),
  })
  const { baseline } = await minter.establishBaseline()
  assert.equal(baseline.checks.length, 1, 'fixture setup: one discovered check anchored')

  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = dir
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', evidenceDir: '.proof', requireBaseline: 'off' }))
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
    await fsp.rm(dir, { recursive: true, force: true })
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
  // The seam: with the workflow gates off, the endorsement ask is the last
  // pre-execute decision the plugin registers (X-H-16 moved the
  // evidence-store guard to index 0 in every mode).
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const gate = harness.listeners.get('tools/pre-execute')![1]! as (
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

// ---------------------------------------------------------------------------
// ρ: PTC synthesis through the tool surface — the conjure protocol as the
// model meets it. Step 1 commits the request to the chain and hands back the
// scaffold verbatim; step 2 executes the written script through the plugin's
// own port (or refuses it at screening — a protocol result, never a tool
// error). Like the λ fixtures, each test builds its own engine so its chain
// is its own.
// ---------------------------------------------------------------------------

test('ρ: proof_conjure returns the scaffold verbatim and lands synthetic/requested on the chain', async () => {
  const { tools, logPath, dir } = await attestFixture('conjure')
  try {
    const conjure = tools.find(t => t.name === 'proof_conjure')!
    const claim = 'the parser rejects unbalanced quotes'
    const value = valueOf(await conjure.execute(
      { claim, paths: ['src/parse.ts'] },
      execution('proof_conjure', { claim, paths: ['src/parse.ts'] }),
    ))

    // The canonical value: the request's identity plus the template IN FULL —
    // the model writes the test from these exact bytes.
    assert.equal(value.claimId, claimIdOf(claim))
    assert.equal(value.entry, sandboxEntryFor(claimIdOf(claim), 0), 'a fresh claim mints entry seq 0')
    assert.deepEqual(value.paths, ['src/parse.ts'])
    assert.equal(value.sandboxDir, SYNTHETIC_DIR_DEFAULT)
    assert.equal(value.template, SYNTHETIC_TEMPLATE, 'the template is the domain scaffold itself, byte for byte')
    assert.match(String(value.instruction), /proof_conjure_run/, 'the instruction charges the run tool by name')

    // The request is committed BEFORE any script exists: full request, null digest.
    const requests = (await markersOf(logPath)).filter(p => p.label === 'synthetic/requested')
    assert.equal(requests.length, 1)
    assert.equal(requests[0]!.claimId, claimIdOf(claim))
    assert.equal(requests[0]!.entry, value.entry)
    assert.deepEqual(requests[0]!.paths, ['src/parse.ts'])
    assert.equal(requests[0]!.scriptDigest, null, 'at request time there is nothing to digest yet')

    // The render carries the instruction, the weight warning and the template
    // in full — and the card title names what is being conjured.
    const rendered = renderedText(conjure, value)
    assert.ok(rendered.includes(SYNTHETIC_TEMPLATE), 'the scaffold rides the render verbatim')
    assert.match(rendered, /synthetic evidence/i)
    assert.match(rendered, /weighted below/i)
    const call = conjure.presentCall!({ claim }) as { title: string }
    assert.match(call.title, /Conjure synthetic test/)
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

test('ρ: proof_conjure_run executes through the verifier port and records synthetic evidence', async () => {
  // Light path, deliberately: a real ProofEngine over deterministic ports with
  // the node execution FAKED (a rule that answers 'node' with exit 0). The
  // engine/runner integration of conjureRun — real node, real sandbox — is
  // 05's charge; what this pins is the tool surface: the canonical value, the
  // chain facts and the render, projected faithfully from whatever the engine
  // reports.
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ name: 'conjure-run', scripts: { test: 'node -e "process.exit(0)"' } }),
    '/ws/src/a.ts': 'export const a = 1\n',
  })
  const commands = new FakeCommands().on(
    argv => argv.includes('node'),
    { exitCode: 0, output: 'SYNTHETIC: PASS' },
  )
  const engine = new ProofEngine({ root: '/ws', fs, commands, workspace: new FakeWorkspace('/ws'), autoDiscover: false })
  const run = createProofTools(engine).find(t => t.name === 'proof_conjure_run')!
  const claim = 'one plus one is two'
  const cleanScript = [
    '// conjured test — authored by the agent, executed by the verifier',
    "console.log('SYNTHETIC: PASS')",
    '',
  ].join('\n')

  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  fs.mutate(`/ws/.proof-synthetic/${request.entry}`, cleanScript)

  const value = valueOf(await run.execute({ claim, entry: request.entry }, execution('proof_conjure_run', {})))

  assert.equal(value.recorded, true)
  assert.equal(value.status, 'pass')
  assert.deepEqual(value.screened, [], 'a clean script screens with no findings')
  assert.equal(value.sandbox, 'screened-subprocess')
  assert.equal(value.scriptDigest, sha256(cleanScript), 'the digest proves exactly the bytes that ran')
  assert.match(String(value.outputHead), /SYNTHETIC: PASS/)
  assert.match(String(value.note), /synthetic evidence/i)
  assert.match(String(value.note), /0\.15/)
  assert.match(String(value.note), /less than organic checks/)

  // Execution went through the engine's own command port — the agent's tools
  // never touched the script — and the run landed on the chain.
  assert.equal(commands.calls.length, 1, 'exactly one verifier-side execution')
  assert.ok(commands.calls[0]!.argv.includes(request.entry))
  assert.ok(fs.log.some(l => l.includes('"synthetic/run"') && l.includes(value.checkId as string)),
    'the run marker carries the synthetic check identity')

  // A FAIL keeps the output's first informative line in the render: the one
  // line that usually names the assertion that broke. Same entry, weakened
  // script — a different digest, honestly a different piece of evidence.
  const failingScript = cleanScript.replace('SYNTHETIC: PASS', 'assertion placeholder — never printed')
  fs.mutate(`/ws/.proof-synthetic/${request.entry}`, failingScript)
  commands.on(argv => argv.includes('node'), {
    exitCode: 1,
    output: 'SYNTHETIC: FAIL: 1/1 assertion(s) failed: one plus one is three',
  })
  const failed = valueOf(await run.execute({ claim, entry: request.entry }, execution('proof_conjure_run', {})))
  assert.equal(failed.recorded, true)
  assert.equal(failed.status, 'fail')
  assert.notEqual(failed.scriptDigest, value.scriptDigest, 'a weakened script is a different digest')
  const rendered = renderedText(run, failed)
  assert.match(rendered, /SYNTHETIC FAIL/)
  assert.match(rendered, /SYNTHETIC: FAIL: 1\/1 assertion\(s\) failed/, 'the first informative output line survives the render')

  // The card title speaks the status it recorded.
  const card = run.presentResult!({}, { meta: failed } as never) as { title: string }
  assert.match(card.title, /Synthetic evidence · fail/)
})

test('ρ: proof_conjure_run refuses a screened script as a protocol result, not an error', async () => {
  const fs = MemoryFs.of({
    '/ws/package.json': JSON.stringify({ name: 'conjure-refuse', scripts: { test: 'node -e "process.exit(0)"' } }),
    '/ws/src/a.ts': 'export const a = 1\n',
  })
  const commands = new FakeCommands()
  const engine = new ProofEngine({ root: '/ws', fs, commands, workspace: new FakeWorkspace('/ws'), autoDiscover: false })
  const run = createProofTools(engine).find(t => t.name === 'proof_conjure_run')!
  const claim = 'lists the files'

  const { request } = await engine.conjureRequest({ claim, paths: ['src/a.ts'] })
  fs.mutate(`/ws/.proof-synthetic/${request.entry}`, [
    "import { exec } from 'node:child_process'",
    "exec('ls -la')",
    '',
  ].join('\n'))

  // A refusal RESOLVES (isError stays false at the host seam): it is a
  // protocol-internal outcome whose canonical value carries the findings and
  // the corrective next step, not a broken tool.
  const value = valueOf(await run.execute({ claim, entry: request.entry }, execution('proof_conjure_run', {})))
  assert.equal(value.recorded, false)
  assert.equal(value.entry, request.entry)
  assert.ok((value.screened as string[]).length > 0, 'the findings travel back to the model')
  assert.match((value.screened as string[]).join('; '), /child/i, 'the finding names the forbidden capability')
  assert.match(String(value.reason), /capability screening refused this script — remove the flagged imports and retry/)

  // No execution, no chain writes: a refused test is not evidence of anything
  // except its own refusal.
  assert.equal(commands.calls.length, 0, 'a refused script never reaches the command port')
  assert.ok(!fs.log.some(l => l.includes('"synthetic/run"')), 'a refusal writes no run marker')

  // The render states the refusal and the fix without throwing; the card says
  // "not recorded", not "error".
  const rendered = renderedText(run, value)
  assert.match(rendered, /NOT RECORDED/)
  assert.match(rendered, /child/)
  assert.match(rendered, /remove the flagged imports and retry/)
  const card = run.presentResult!({}, { meta: value } as never) as { title: string }
  assert.match(card.title, /refused — not recorded/)
})

// ---------------------------------------------------------------------------
// Execution coverage (υ): the coverage dimension's verdict must reach the
// canonical verify value and the render in all three states — v8 with the
// change fully executed, v8 with an unexecuted change, and the honest no-data
// basis 'none' — and a claim over an unexecuted change must carry the blocker
// that says so. The no-coverage path (mode `off`, pre-υ session logs) emits no
// coverage key, no coverage line and no coverage blocker, staying
// byte-identical.
// ---------------------------------------------------------------------------

/** fakeReport grown by the coverage summary the υ gate attaches (core/report). */
function coveredReport(
  basis: 'v8' | 'none',
  uncovered: readonly string[],
  overrides: { grade?: ProofGrade; unverified?: string[] } = {},
): GradedProofReport {
  return { ...fakeReport(overrides), coverage: { basis, uncovered } }
}

test('υ: coverage transfers in all three states, renders its line, and absent coverage changes nothing', () => {
  const verify = appliedTools().find(t => t.name === 'proof_verify')!

  // v8, every changed file observed executing: the field carries the counts
  // and the render states the change-executed tail with them.
  const executed = toVerifyValue(
    coveredReport('v8', [], { grade: 'proven' }),
    ['src/a.ts', 'src/b.ts'], [], { untouched: [], precision: 'approximate' },
    undefined, undefined, undefined,
    { basis: 'v8', uncovered: [], executedCount: 2 },
  )
  assert.deepEqual(executed.coverage, { basis: 'v8', executedCount: 2, uncovered: [] })
  assert.match(
    renderedText(verify, executed),
    /coverage: change-executed \(2 file\(s\) of the change observed running\)/,
  )

  // v8, an unexecuted change: the canonical value carries the FULL uncovered
  // list (the three-file cap is render-only), and the render names the first
  // three files, states the gap in υ's own terms and points at the remedy.
  const files = ['src/x.ts', 'src/y.ts', 'src/z.ts', 'src/w.ts']
  const unexecuted = toVerifyValue(
    coveredReport('v8', files, { grade: 'unproven' }),
    files, [], { untouched: [], precision: 'approximate' },
    undefined, undefined, undefined,
    { basis: 'v8', uncovered: files, executedCount: 0 },
  )
  assert.deepEqual(unexecuted.coverage, { basis: 'v8', executedCount: 0, uncovered: files })
  const rendered = renderedText(verify, unexecuted)
  assert.match(rendered, /⚠ coverage: unexecuted change — src\/x\.ts, src\/y\.ts, src\/z\.ts never ran under any green check/)
  assert.match(rendered, /\(paths matched, execution did not\)/)
  assert.match(rendered, /proof_conjure can synthesize a test that executes them/)
  assert.ok(!rendered.includes('src/w.ts'), 'the unexecuted line caps at the first three files')

  // basis 'none': no data was produced — the render says so with the
  // observe/require difference spelled out, and never names a file unexecuted
  // (even though the gate's summary may carry an uncovered list at 'none').
  const blindRendered = renderedText(
    verify,
    toVerifyValue(
      coveredReport('none', files), files, [], { untouched: [], precision: 'approximate' },
      undefined, undefined, undefined,
      { basis: 'none', uncovered: files, executedCount: 0 },
    ),
  )
  assert.match(blindRendered, /ℹ coverage: no execution data this run \(mode observe lets this pass ungated; mode require would not\)/)
  assert.ok(!blindRendered.includes('never ran under any green check'), 'basis none measured nothing — no file may be called unexecuted')

  // Mode off / pre-υ session logs: no coverage key on the canonical value, no
  // coverage line on the render — the no-coverage path stays byte-identical.
  const legacy = toVerifyValue(fakeReport(), [], [], { untouched: [], precision: 'approximate' })
  assert.ok(!('coverage' in legacy), 'off mode emits no coverage key at all')
  let legacyRender = ''
  assert.doesNotThrow(() => {
    legacyRender = renderedText(verify, {
      summary: 's', changed: [], externalChanged: [], regressions: [], fixed: [], preExisting: [], unverified: [],
    })
  })
  assert.ok(!legacyRender.includes('coverage'), 'no coverage line without the field')

  // Defensive projection and replay: a partial or hostile coverage shape
  // degrades to honest zeros instead of throwing, and old meta never throws.
  const hostile = toVerifyValue(
    fakeReport(), [], [], { untouched: [], precision: 'approximate' },
    undefined, undefined, undefined,
    { basis: 'v8', uncovered: 'nope' as never, executedCount: 'many' as never },
  )
  assert.deepEqual(hostile.coverage, { basis: 'v8', executedCount: 0, uncovered: [] })
  assert.doesNotThrow(() => { renderedText(verify, {}) })
  assert.doesNotThrow(() => { renderedText(verify, { summary: 's', coverage: { basis: 'v8' } }) })
  assert.doesNotThrow(() => { renderedText(verify, { summary: 's', coverage: null }) })
  assert.doesNotThrow(() => {
    renderedText(verify, { summary: 's', coverage: { basis: 'strange', uncovered: 'nope', executedCount: null } })
  })
})

test('υ: a claim over an unexecuted change carries an unexecuted-change blocker; no coverage, no such blocker', () => {
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!

  // Each uncovered file is its own blocker; the generic unproven blocker and
  // the coverage blocker coexist, and both reach the summary and the render.
  const report = coveredReport('v8', ['src/x.ts', 'src/y.ts'], { grade: 'unproven' })
  const claim = toClaimValue(
    'rewired the parser',
    report,
    toVerifyValue(
      report, ['src/x.ts', 'src/y.ts'], [], { untouched: [], precision: 'approximate' },
      undefined, undefined, undefined,
      { basis: 'v8', uncovered: ['src/x.ts', 'src/y.ts'], executedCount: 0 },
    ),
  )
  assert.ok(claim.blockers.includes('unexecuted change: src/x.ts was never run by any green check'))
  assert.ok(claim.blockers.includes('unexecuted change: src/y.ts was never run by any green check'))
  // M19c: this τ-demoted claim names its evidence cause — the process-completion
  // canned text would point the wrong cure (a re-run cannot execute the change).
  assert.ok(claim.blockers.includes('The change never executed under any green check — point a check at it (or see proof_conjure).'))
  assert.ok(!claim.blockers.includes('Verification was incomplete (skipped, aborted or timed out).'))
  assert.match(claim.summary, /unexecuted change: src\/x\.ts was never run by any green check/)
  assert.match(renderedText(claimTool, claim), /unexecuted change: src\/x\.ts was never run by any green check/)

  // Basis 'none' measured nothing — no file may be named unexecuted.
  const blind = coveredReport('none', ['src/x.ts'])
  const blindClaim = toClaimValue(
    'same claim', blind,
    toVerifyValue(
      blind, [], [], { untouched: [], precision: 'approximate' },
      undefined, undefined, undefined,
      { basis: 'none', uncovered: ['src/x.ts'], executedCount: 0 },
    ),
  )
  assert.ok(blindClaim.blockers.every(b => !b.startsWith('unexecuted change:')))

  // No coverage at all (mode off / pre-υ session log): the blocker must not
  // appear, and the canonical blockers stay byte-identical.
  const legacyReport = fakeReport({ grade: 'unproven' })
  const legacy = toClaimValue(
    'same claim', legacyReport,
    toVerifyValue(legacyReport, [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.deepEqual(
    legacy.blockers,
    ['Verification was incomplete (skipped, aborted or timed out).'],
    'the no-coverage claim carries exactly its pre-υ blockers',
  )
})

// ---------------------------------------------------------------------------
// H10: the evidence-store guard must compare case-folded. `toWorkspaceRelative`
// preserves the case the tool sent (only the ROOT comparison is
// case-insensitive), so `.PROOF/evidence.jsonl` used to walk straight past a
// case-sensitive `=== '.proof'` on Windows — where both spellings name the
// same file. A backslash-flavoured config (`'.\proof'`) is the same hole on
// the config side and is normalized here too.
// ---------------------------------------------------------------------------

test('H10: workspace mode gates case variants of the evidence store path', async () => {
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

  // On Windows these all name <root>/.proof/evidence.jsonl exactly.
  const variants = [
    '.PROOF/evidence.jsonl', // uppercase directory
    '.Proof/EVIDENCE.jsonl', // mixed-case directory and file
    `${ROOT.replace(/\\/g, '/')}/.PROOF/evidence.jsonl`, // case variant via host-style absolute
  ]
  for (const forged of variants) {
    const denied = await gate(
      { name: 'write', arguments: { path: forged, content: 'forged' }, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'deny', `a case variant of the evidence path must be denied: ${forged}`)
    assert.match(denied.reason ?? '', /evidence/i)
  }

  // Folding the comparison does not smear it onto unrelated directories: an
  // ordinary (non-evidence) path still passes untouched.
  const allowed = await gate(
    { name: 'write', arguments: { path: 'src/a.ts', content: 'fine' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(allowed.kind, 'allow')
})

test('H10: a differently-named evidence dir keeps its case-folded guard', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', evidenceDir: 'proof', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  for (const forged of ['Proof/EVIDENCE.jsonl', 'PROOF/evidence.jsonl']) {
    const denied = await gate(
      { name: 'write', arguments: { path: forged, content: 'forged' }, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'deny', `case variant of configured dir 'proof' must be denied: ${forged}`)
  }
})

test('H10: a backslash-flavoured evidenceDir config still guards the real path', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ evidenceStore: 'workspace', evidenceDir: '.\\proof', requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }

  const gate = harness.listeners.get('tools/pre-execute')![0] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string }>

  // '.\proof' on Windows names <root>/proof — the guard must land there, in
  // both slash flavours and case variants, not silently never-match.
  for (const forged of ['proof/evidence.jsonl', '.\\proof\\evidence.jsonl', 'PROOF/EVIDENCE.jsonl']) {
    const denied = await gate(
      { name: 'write', arguments: { path: forged, content: 'forged' }, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'deny', `a write into the configured store must be denied: ${forged}`)
    assert.match(denied.reason ?? '', /evidence/i)
  }

  // '.proof' (dotted) is a genuinely different directory than 'proof' — the
  // fold must not blur distinct names into one gate.
  const allowed = await gate(
    { name: 'write', arguments: { path: '.proof/evidence.jsonl', content: 'x' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(allowed.kind, 'allow', 'a different directory name is not the configured store')
})

// ---------------------------------------------------------------------------
// M5: the approver a proof_endorse will record is agent-declared free text —
// the human at the approval seam must see the exact name they are about to
// vouch for, or "named accountability" can be counterfeited (the human
// approves a claim; the chain logs a name the agent invented).
// ---------------------------------------------------------------------------

test('M5: the endorsement ask names the agent-declared approver', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  // Index 1 = the endorsement seam (the evidence guard is index 0 in every
  // mode since X-H-16).
  const gate = harness.listeners.get('tools/pre-execute')![1] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string; displayReason?: Record<string, string> }>

  const claim = 'the evidence chain is safe to hand to the customer'
  const asked = await gate(
    {
      name: 'proof_endorse',
      arguments: { claim, decision: 'endorse', approver: 'Zhang San (tech lead)' },
      signal: new AbortController().signal,
    },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(asked.kind, 'ask')
  assert.ok(asked.reason?.includes(claim), 'the claim stays in the approval reason')
  assert.match(String(asked.reason), /approver \(as declared by the agent\): Zhang San \(tech lead\)/)
  assert.match(asked.displayReason?.en ?? '', /approver \(as declared by the agent\): Zhang San/)
  assert.match(asked.displayReason?.['zh-CN'] ?? '', /审批人（由 agent 自报）：Zhang San/)

  // A whitespace-only approver is no approver: the human must see the default,
  // not a blank line that reads as "somehow nobody".
  const blank = await gate(
    {
      name: 'proof_endorse',
      arguments: { claim, decision: 'endorse', approver: '   ' },
      signal: new AbortController().signal,
    },
    async () => ({ kind: 'allow' }),
  )
  assert.match(String(blank.reason), /approver \(as declared by the agent\): host-approver \(default\)/)
})

test('M5: an endorsement without an approver shows the default in the ask', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  // Index 1 = the endorsement seam (X-H-16 put the evidence guard at 0).
  const gate = harness.listeners.get('tools/pre-execute')![1] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string; displayReason?: Record<string, string> }>

  const asked = await gate(
    { name: 'proof_endorse', arguments: { claim: 'ok', decision: 'reject' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(asked.kind, 'ask')
  assert.match(String(asked.reason), /host-approver \(default\)/)
  assert.match(asked.displayReason?.en ?? '', /host-approver \(default\)/)
  assert.match(asked.displayReason?.['zh-CN'] ?? '', /host-approver \(default\)/)
})

// ---------------------------------------------------------------------------
// M4: the confidence basis is six-valued on the report layer, and a plain
// proof_verify reaches three of the testimony regimes without ever touching
// the λ tools — 'synthetic' when every decisive check was conjured by the
// claim's author, 'attested' after the engine's κ fusion, 'jury-only' from
// the ζ jury assembler. The tool surface must carry the basis (a probability
// with no regime dresses testimony up as measurement) and say so in the claim
// head, in proofNarrative's own words.
// ---------------------------------------------------------------------------

test('M4: synthetic/attested/jury-only bases ride the verify value, the confidence line and the claim head', () => {
  const verify = appliedTools().find(t => t.name === 'proof_verify')!
  const claimTool = appliedTools().find(t => t.name === 'proof_claim')!

  // synthetic: plain verify over a conjured-test-only run.
  const synthetic = toVerifyValue(
    gradedReport(0.9321, 'synthetic', { grade: 'proven' }),
    ['src/a.ts'], [], { untouched: [], precision: 'approximate' },
  )
  assert.equal(synthetic.confidence, 0.93)
  assert.equal(synthetic.confidenceBasis, 'synthetic', 'the regime survives the projection instead of being stripped')
  assert.match(synthetic.summary, /synthetic evidence — conjured tests, discounted/)
  assert.match(renderedText(verify, synthetic), /confidence p≈0\.93 \(synthetic · conjured tests, discounted\)/)

  // attested: machine evidence fused with B/C witnesses.
  const attested = toVerifyValue(
    gradedReport(0.97, 'attested', { grade: 'proven' }),
    [], [], { untouched: [], precision: 'approximate' },
  )
  assert.equal(attested.confidenceBasis, 'attested')
  assert.match(attested.summary, /machine \+ B\/C attested/)
  assert.match(renderedText(verify, attested), /confidence p≈0\.97 \(attested · machine \+ B\/C attested\)/)

  // jury-only: the capped self-attestation.
  const jury = toVerifyValue(
    gradedReport(0.8, 'jury-only', { grade: 'proven' }),
    [], [], { untouched: [], precision: 'approximate' },
  )
  assert.equal(jury.confidenceBasis, 'jury-only')
  assert.match(renderedText(verify, jury), /confidence p≈0\.80 \(jury-only · self-attestation is capped\)/)

  // The claim card: the basis rides with the posterior and the head states
  // the regime — never a bare probability over testimony.
  const claim = toClaimValue(
    'added a conjured regression test',
    gradedReport(0.9321, 'synthetic', { grade: 'proven' }),
    synthetic,
  )
  assert.equal(claim.confidenceBasis, 'synthetic')
  assert.match(claim.summary, /PROVEN \(p≈0\.93, synthetic evidence — conjured tests, discounted\) — /)
  const attestedClaim = toClaimValue(
    'shipped with jury and human backing',
    gradedReport(0.97, 'attested', { grade: 'proven' }),
    attested,
  )
  assert.equal(attestedClaim.confidenceBasis, 'attested')
  assert.match(attestedClaim.summary, /PROVEN \(p≈0\.97, machine \+ B\/C attested\) — /)
  const juryClaim = toClaimValue(
    'documented the retry options',
    gradedReport(0.8, 'jury-only', { grade: 'proven' }),
    jury,
  )
  assert.equal(juryClaim.confidenceBasis, 'jury-only')
  assert.match(juryClaim.summary, /PROVEN \(p≈0\.80, jury evidence — self-attestation is capped\) — /)
  // The not-proven head carries the same regime honesty.
  const notProven = toClaimValue(
    'claimed too much',
    gradedReport(0.61, 'attested', { grade: 'stale', unverified: ['e2e'] }),
    toVerifyValue(gradedReport(0.61, 'attested', { grade: 'stale' }), [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.match(notProven.summary, /NOT PROVEN \(stale, p≈0\.61, machine \+ B\/C attested\)/)

  // Machine bases and the ungraded path keep their exact legacy heads — no
  // regime tail where none was earned.
  const machine = toClaimValue(
    'plain machine proof',
    gradedReport(0.97, 'full-coverage', { grade: 'proven' }),
    toVerifyValue(gradedReport(0.97, 'full-coverage', { grade: 'proven' }), [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.match(machine.summary, /PROVEN \(p≈0\.97\) — /)
  const ungraded = toClaimValue(
    'no posterior anywhere',
    fakeReport({ grade: 'proven' }),
    toVerifyValue(fakeReport({ grade: 'proven' }), [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.ok(!('confidence' in ungraded) && !('confidenceBasis' in ungraded),
    'no posterior, no basis — the ungraded claim stays byte-identical')

  // Both tool schemas declare the full six-value union.
  const six = ['full-coverage', 'certified-subset', 'degraded', 'jury-only', 'attested', 'synthetic']
  const verifyProps = (verify.output!.schema.properties ?? {}) as Record<string, { enum?: string[] }>
  assert.deepEqual(verifyProps.confidenceBasis?.enum, six, 'the verify schema declares the six-value union')
  const claimProps = (claimTool.output!.schema.properties ?? {}) as Record<string, { enum?: string[] }>
  assert.deepEqual(claimProps.confidenceBasis?.enum, six, 'the claim schema declares the six-value union')
})

// ---------------------------------------------------------------------------
// M6: proof_claim's two silent degradations — a missing claim and a typo'd
// kind — must fail loudly at the parameter boundary instead of producing a
// claim-less record (legacy path) or running the legacy verify while the
// model believes a contract is binding (typed path).
// ---------------------------------------------------------------------------

test('M6: proof_claim refuses a missing/blank claim and an unknown kind; legal inputs route unchanged', async () => {
  const routed: string[] = []
  const outcome = {
    report: fakeReport({ grade: 'proven' }),
    changed: [],
    checks: [],
    selection: { untouched: [], precision: 'approximate' },
  }
  const engine = {
    verify: async () => { routed.push('verify'); return outcome },
    verifyContract: async () => {
      routed.push('verifyContract')
      return { ...outcome, contract: { kind: 'behavior-preserving' as const, obligations: [] } }
    },
  } as unknown as ProofEngine
  const claimTool = createProofTools(engine).find(t => t.name === 'proof_claim')!

  // claim missing / non-string / blank → a clean parameter error, jury-style.
  await assert.rejects(claimTool.execute({}, execution('proof_claim', {})), /proof_claim: claim is required/)
  await assert.rejects(claimTool.execute({ claim: 42 }, execution('proof_claim', {})), /proof_claim: claim is required/)
  await assert.rejects(claimTool.execute({ claim: '   ' }, execution('proof_claim', {})), /proof_claim: claim is required/)

  // A typo'd kind throws WITH the legal values listed — the model believed a
  // contract was binding; the honest answer names what would have been.
  await assert.rejects(
    claimTool.execute({ claim: 'safe refactor', kind: 'behavior_preserving' }, execution('proof_claim', {})),
    /kind must be one of behavior-preserving \| behavior-adding \| perf-budget \| docs-only \| llm-jury/,
  )
  await assert.rejects(
    claimTool.execute({ claim: 'safe refactor', kind: 7 }, execution('proof_claim', {})),
    /kind must be one of .*\(got nothing usable\)/,
  )
  assert.deepEqual(routed, [], 'nothing reached the engine on any refused call')

  // Legal inputs keep their exact routing: a valid kind → verifyContract…
  const typed = valueOf(await claimTool.execute(
    { claim: 'safe refactor', kind: 'behavior-preserving' },
    execution('proof_claim', {}),
  ))
  assert.equal(routed[0], 'verifyContract')
  assert.equal(typed.kind, 'behavior-preserving')

  // …and no kind → the legacy verify path, byte-for-byte.
  const plain = valueOf(await claimTool.execute({ claim: 'plain claim' }, execution('proof_claim', {})))
  assert.equal(routed[1], 'verify')
  assert.equal(plain.claim, 'plain claim')
  assert.ok(!('kind' in plain))
})

// ---------------------------------------------------------------------------
// M19c: the two diseases behind an `unproven` grade must name their own cure.
// A τ demotion (coverage measured, change never executed by any green check)
// is an evidence verdict — the fix is a check that runs the change, not a
// re-run; a genuinely incomplete process keeps the original canned text.
// ---------------------------------------------------------------------------

test('M19c: τ-demoted unproven names the coverage cause; process-incomplete keeps the process text', () => {
  // τ: the process completed green, the change never executed under it.
  const tauReport = coveredReport('v8', ['src/x.ts'], { grade: 'unproven' })
  const tau = toClaimValue(
    'rewired the parser',
    tauReport,
    toVerifyValue(
      tauReport, ['src/x.ts'], [], { untouched: [], precision: 'approximate' },
      undefined, undefined, undefined,
      { basis: 'v8', uncovered: ['src/x.ts'], executedCount: 0 },
    ),
  )
  assert.ok(tau.blockers.includes('The change never executed under any green check — point a check at it (or see proof_conjure).'))
  assert.ok(
    !tau.blockers.includes('Verification was incomplete (skipped, aborted or timed out).'),
    'the τ demotion completed its process — the re-run guidance would point the wrong cure',
  )
  assert.match(tau.summary, /The change never executed under any green check/)

  // Process: no coverage data at all → the original text stands.
  const processReport = fakeReport({ grade: 'unproven' })
  const process = toClaimValue(
    'same claim', processReport,
    toVerifyValue(processReport, [], [], { untouched: [], precision: 'approximate' }),
  )
  assert.ok(process.blockers.includes('Verification was incomplete (skipped, aborted or timed out).'))
  assert.ok(!process.blockers.some(b => b.includes('never executed under any green check')))

  // Basis 'none' measured nothing — no coverage verdict may be implied either.
  const blindReport = coveredReport('none', ['src/x.ts'], { grade: 'unproven' })
  const blind = toClaimValue(
    'same claim', blindReport,
    toVerifyValue(
      blindReport, [], [], { untouched: [], precision: 'approximate' },
      undefined, undefined, undefined,
      { basis: 'none', uncovered: ['src/x.ts'], executedCount: 0 },
    ),
  )
  assert.ok(
    blind.blockers.includes('Verification was incomplete (skipped, aborted or timed out).'),
    'basis none has no measurement — the process text is the honest cause',
  )
})

// ---------------------------------------------------------------------------
// M19d: the audit fails on an anchor/log disagreement (anchorMismatch), so the
// structured status output must carry it, `chainIntact` must agree with the
// audit, and the render's tamper banner must light — three green booleans must
// never paper over a rewritten history.
// ---------------------------------------------------------------------------

test('M19d: anchorMismatch reaches StatusValue, flips chainIntact and lights the TAMPER banner', () => {
  const status = appliedTools().find(t => t.name === 'proof_status')!

  const clean = toStatusValue({
    specs: [],
    latest: new Map<string, { status: string; recordedAt: string }>(),
    audit: fakeAudit(),
    snapshot: { dirty: [] },
  })
  assert.ok(!('anchorMismatch' in clean), 'clean path canonical value stays byte-identical — no anchorMismatch field')
  assert.equal(clean.chainIntact, true)

  const mismatched = toStatusValue({
    specs: [],
    latest: new Map<string, { status: string; recordedAt: string }>(),
    audit: fakeAudit({ anchorMismatch: true }),
    snapshot: { dirty: [] },
  })
  assert.equal(mismatched.anchorMismatch, true, 'the audit verdict reaches the structured output')
  assert.equal(mismatched.chainIntact, false, 'audit.ok fails on an anchor mismatch — chainIntact must not disagree')
  assert.match(mismatched.summary, /ANCHOR MISMATCH/, 'the trust line has carried the flag since it was introduced')

  // The render's banner lights from the structured value…
  assert.match(renderedText(status, mismatched), /TAMPER-EVIDENCE TRIPPED/)
  // …and from a partial replay value that carries only the new field.
  assert.match(renderedText(status, { summary: 's', checks: [], anchorMismatch: true }), /TAMPER-EVIDENCE TRIPPED/)
  // A legacy value with no field and a clean chain renders no banner.
  const quiet = renderedText(status, {
    summary: 's', checks: [], chainIntact: true, rewindDetected: false, baselineTampered: false,
  })
  assert.ok(!quiet.includes('TAMPER-EVIDENCE TRIPPED'))

  // The schema declares the field so it stays truthful about degraded hosts.
  const props = (status.output!.schema.properties ?? {}) as Record<string, unknown>
  assert.ok('anchorMismatch' in props, 'the status schema declares anchorMismatch')
})

// ---------------------------------------------------------------------------
// D3 (tools side): proof_verify.claim and proof_baseline.reason used to be
// dead parameters — described as "for the record" and then dropped. The tool
// bodies now forward them into the engine calls; these tests pin the wiring
// with a capturing engine so the contract holds the moment the engine side
// lands its recording.
// ---------------------------------------------------------------------------

test('D3 wiring: proof_verify forwards a usable claim and proof_baseline forwards a usable reason', async () => {
  const verifyCalls: Record<string, unknown>[] = []
  const baselineCalls: Record<string, unknown>[] = []
  const outcome = {
    report: fakeReport({ grade: 'proven' }),
    changed: [],
    checks: [],
    selection: { untouched: [], precision: 'approximate' },
  }
  const engine = {
    verify: async (options: Record<string, unknown>) => { verifyCalls.push(options); return outcome },
    establishBaseline: async (options: Record<string, unknown>) => {
      baselineCalls.push(options)
      return { baseline: { baselineId: 'b'.repeat(32), root: 'r'.repeat(64) }, records: [] }
    },
  } as unknown as ProofEngine
  const tools = createProofTools(engine)

  await tools.find(t => t.name === 'proof_verify')!.execute(
    { changed: ['src/a.ts'], claim: 'fixed the redirect' },
    execution('proof_verify', {}),
  )
  assert.equal(verifyCalls[0]!.claim, 'fixed the redirect')
  assert.deepEqual(verifyCalls[0]!.changed, ['src/a.ts'])
  // A blank or missing claim forwards nothing — the engine's options stay
  // shape-identical to the pre-D3 call.
  await tools.find(t => t.name === 'proof_verify')!.execute({ claim: '   ' }, execution('proof_verify', {}))
  assert.ok(!('claim' in verifyCalls[1]!), 'a whitespace-only claim is no claim')
  await tools.find(t => t.name === 'proof_verify')!.execute({}, execution('proof_verify', {}))
  assert.ok(!('claim' in verifyCalls[2]!))

  await tools.find(t => t.name === 'proof_baseline')!.execute(
    { reason: 'fresh session after the flaky baseline' },
    execution('proof_baseline', {}),
  )
  assert.equal(baselineCalls[0]!.reason, 'fresh session after the flaky baseline')
  await tools.find(t => t.name === 'proof_baseline')!.execute({}, execution('proof_baseline', {}))
  assert.ok(!('reason' in baselineCalls[1]!))
})

// ---------------------------------------------------------------------------
// v0.19: the experimental agent-team bridge — the DSH-side on-ramp for the
// cross-agent responsibility DAG. The host's agent-team API is unreleased, so
// everything here is runtime duck-typing over `unknown` with graceful
// degradation, and the whole feature is opt-in (agentTeamBridge, default
// false). Handler logic (normalize/create) is tested directly; the seam probe
// (attach) against synthetic contexts; the opt-in red line through the real
// apply() over the standard harness.
// ---------------------------------------------------------------------------

test('agent-team: normalizeTeamEvent narrows delegation events defensively', () => {
  // The matrix: each recognizable spelling narrows; everything else is
  // undefined — never a throw, never a guess.
  const byClaim = normalizeTeamEvent({ claim: 'x' })
  assert.equal(byClaim?.kind, 'delegated')
  assert.equal(byClaim?.claim, 'x')

  const byPrompt = normalizeTeamEvent({ prompt: 'do x' })
  assert.equal(byPrompt?.prompt, 'do x')
  assert.ok(!('claim' in byPrompt!), 'a prompt-only event narrows to the prompt channel')

  // Nested envelopes — the host dialect is unknown, so the walk descends.
  const nested = normalizeTeamEvent({ toolInput: { task: 'x' } })
  assert.equal(nested?.prompt, 'x', 'a task field is the child instruction: the prompt channel')

  const deep = normalizeTeamEvent({ event: { payload: { description: 'write the tests', taskId: 't-1' } } })
  assert.equal(deep?.prompt, 'write the tests')
  assert.equal(deep?.taskId, 't-1')
  assert.equal(
    (deep?.payload as Record<string, unknown> | undefined)?.description,
    'write the tests',
    'the nested payload object is located as the write-back channel',
  )

  const parent = normalizeTeamEvent({ claim: 'x', parentTaskId: 'task-2' })
  assert.equal(parent?.parentTaskId, 'task-2', 'a parent edge the host named travels along')

  // claim beats prompt when both are present (key precedence).
  assert.equal(normalizeTeamEvent({ prompt: 'lesser', claim: 'greater' })?.claim, 'greater')

  // Not recognizably a delegation: null, primitives, no text field, blank text.
  assert.equal(normalizeTeamEvent(null), undefined)
  assert.equal(normalizeTeamEvent(42), undefined)
  assert.equal(normalizeTeamEvent('agent/delegation'), undefined)
  assert.equal(normalizeTeamEvent({ foo: 'bar' }), undefined)
  assert.equal(normalizeTeamEvent({ claim: '   ' }), undefined)
  assert.equal(normalizeTeamEvent({ toolInput: { description: null } }), undefined)
})

test('agent-team: createTeamBridge delegates and injects the instruction into a mutable payload', async () => {
  const delegated: Record<string, unknown>[] = []
  let instruction = ''
  const bridge = createTeamBridge({
    delegate: async input => {
      delegated.push(input)
      return { taskId: 'task-7', obligationId: 'obl-1', obligation: {} }
    },
    instructionOf: (taskId, obligationId, claim) => {
      instruction = `instruction:${taskId}:${obligationId}:${claim}`
      return instruction
    },
  })

  const event = { claim: 'build the parser', payload: {} as Record<string, unknown> }
  await bridge.onEvent(event)
  assert.equal(delegated.length, 1)
  assert.equal(delegated[0]!.claim, 'build the parser')
  assert.ok(!('parentTaskId' in delegated[0]!), 'an event with no parent edge delegates as a root obligation')
  assert.equal(event.payload.proofObligation, instruction)
  assert.match(String(event.payload.proofObligation), /task-7/)
  assert.match(String(event.payload.proofObligation), /build the parser/)

  // The same event object delivered twice (a host fanning one delegation out
  // to several subscribed seams) is one obligation, not two.
  await bridge.onEvent(event)
  assert.equal(delegated.length, 1)

  // A prompt-only event still yields a claim; the text is capped at 500 chars.
  const calls: Record<string, unknown>[] = []
  const capBridge = createTeamBridge({
    delegate: async input => { calls.push(input); return { taskId: 't', obligationId: 'o', obligation: {} } },
    instructionOf: () => 'x',
  })
  await capBridge.onEvent({ prompt: 'do x' })
  assert.equal(calls[0]!.claim, 'do x')
  await capBridge.onEvent({ claim: 'a'.repeat(600) })
  assert.equal(String(calls[1]!.claim).length, 500, 'an event prompt is not a spec — the obligation claim is capped')

  // H-12: a host parent id is NOT cast into the engine's task-N namespace —
  // an unmapped parent (even one that looks like task-1) mints a root, never
  // a guessed edge. A non-string parent id is dropped, not guessed at.
  await capBridge.onEvent({ claim: 'child work', parentTaskId: 'task-1' })
  assert.ok(!('parentTaskId' in calls[2]!), 'an unmapped host parent is never forwarded as an engine parent')
  await capBridge.onEvent({ claim: 'bad parent', parentTaskId: 42 })
  assert.ok(!('parentTaskId' in calls[3]!), 'a non-string parent id is dropped, not guessed at')

  // An immutable event (no payload object) hands off over stderr instead:
  // the obligation exists on the chain and must not be silently orphaned.
  const lines: string[] = []
  const bare = createTeamBridge({
    delegate: async () => ({ taskId: 'task-8', obligationId: 'obl-2', obligation: {} }),
    instructionOf: taskId => `instruction:${taskId}`,
    stderr: line => { lines.push(line) },
  })
  await bare.onEvent({ claim: 'no payload channel' })
  assert.equal(lines.length, 1)
  assert.match(lines[0]!, /task-8/)
  assert.match(lines[0]!, /obl-2/)
  assert.match(lines[0]!, /manually/)

  // Unrecognizable events are dropped silently — and a failing delegate call
  // degrades to a stderr line, never a throw into the host.
  await bare.onEvent({ unrelated: true })
  await bare.onEvent(null)
  assert.equal(lines.length, 1, 'an unrecognizable event warrants no complaint')
  const failing = createTeamBridge({
    delegate: async () => { throw new Error('chain unavailable') },
    instructionOf: () => 'x',
    stderr: line => { lines.push(line) },
  })
  await failing.onEvent({ claim: 'will not record' })
  assert.equal(lines.length, 2)
  assert.match(lines[1]!, /chain unavailable/)
})

test('agent-team: H-12 — host parentTaskId is translated through a mapping, never shape-guessed', async () => {
  const delegated: Record<string, unknown>[] = []
  const stderrLines: string[] = []
  const markers: { label: string; payload: Record<string, unknown> }[] = []
  let seq = 0
  const bridge = createTeamBridge({
    delegate: async input => {
      delegated.push(input)
      seq += 1
      return { taskId: `task-${seq}`, obligationId: `obl-${seq}`, obligation: {} }
    },
    instructionOf: () => 'x',
    stderr: line => { stderrLines.push(line) },
    mark: async (label, payload) => { markers.push({ label, payload }) },
  })

  // (a) A host parent id nobody delegated through the bridge is unmapped: the
  // obligation still mints — as a ROOT — and the lost edge is recorded on
  // stderr AND as an observation marker, with the host's own id spelled out.
  await bridge.onEvent({ claim: 'orphaned child', parentTaskId: 'session-abc-123', taskId: 'host-child-1' })
  assert.equal(delegated.length, 1)
  assert.ok(!('parentTaskId' in delegated[0]!), 'an unmapped parent never reaches the engine namespace')
  assert.ok(stderrLines.some(l => l.includes('session-abc-123')), 'the degradation names the host parent id')
  assert.equal(markers[0]?.label, 'agent-team/parent-unmapped')
  assert.equal(markers[0]?.payload.hostParentTaskId, 'session-abc-123')

  // The mint recorded the namespace mapping — on-chain, not bridge-private.
  assert.equal(markers[1]?.label, 'agent-team/delegated')
  assert.deepEqual(
    { host: markers[1]?.payload.hostTaskId, engine: markers[1]?.payload.engineTaskId },
    { host: 'host-child-1', engine: 'task-1' },
  )

  // (b) A later host event referencing that host child translates through the
  // mapping: the parent edge lands on the ENGINE id the bridge minted.
  await bridge.onEvent({ claim: 'grandchild', parentTaskId: 'host-child-1' })
  assert.equal(delegated.length, 2)
  assert.equal((delegated[1]! as { parentTaskId?: unknown }).parentTaskId, 'task-1',
    'the host id is translated to the engine id this bridge minted for it')

  // (c) Coincidence defense: a host parent id that merely LOOKS like the
  // engine vocabulary, while that engine id was minted for a different host
  // task, must not mint a wrong signed parent edge — the marker says why.
  await bridge.onEvent({ claim: 'shape collision', parentTaskId: 'task-1' })
  assert.equal(delegated.length, 3)
  assert.ok(!('parentTaskId' in delegated[2]!), 'a task-N-shaped host id is still a host id — no guessed edge')
  const collisionMarker = markers.find(m => m.label === 'agent-team/parent-unmapped'
    && m.payload.hostParentTaskId === 'task-1')
  assert.ok(collisionMarker, 'the collision is recorded')
  assert.match(String(collisionMarker?.payload.reason), /coincides with the engine id minted for host task/)
})

test('agent-team: attachTeamBridge probes every seam and degrades without a usable on()', () => {
  const quiet = createTeamBridge({
    delegate: async () => ({ taskId: 't', obligationId: 'o', obligation: {} }),
    instructionOf: () => 'x',
  })

  // A host that accepts everything: every seam attempted, result true.
  const attempts: string[] = []
  const counting = {
    on: (event: string, handler: (raw: unknown) => unknown) => {
      attempts.push(event)
      assert.equal(typeof handler, 'function')
      return () => undefined
    },
  }
  assert.equal(attachTeamBridge(counting, quiet), true)
  for (const seam of TEAM_EVENT_SEAMS) {
    assert.ok(attempts.includes(seam), `the probe must attempt ${seam}`)
  }

  // A host that refuses everything: all four attempts throw, each caught —
  // one stderr line, a clean false, and no exception in the host.
  const lines: string[] = []
  const refusing = { on: () => { throw new Error('undeclared event') } }
  assert.equal(attachTeamBridge(refusing, quiet, line => { lines.push(line) }), false)
  assert.equal(lines.length, 1)
  assert.match(lines[0]!, /no agent-team delegation seam found/)
  assert.match(lines[0]!, /proof_delegate/)

  // A host where the first seam throws but the second accepts: a single
  // refusing registration must not take the others down with it.
  let nth = 0
  const mixed = {
    on: (event: string) => {
      nth += 1
      if (nth === 1) throw new Error('not this one')
      void event
      return () => undefined
    },
  }
  assert.equal(attachTeamBridge(mixed, quiet), true)

  // No callable on() at all: same clean false. (The null ctx passes no sink,
  // so it stays mute — the two sink-carrying failures above are the two lines.)
  assert.equal(attachTeamBridge({}, quiet, line => { lines.push(line) }), false)
  assert.equal(attachTeamBridge(null, quiet), false)
  assert.equal(lines.length, 2)
})

test('agent-team: the bridge is opt-in — default config subscribes to no team seam', async () => {
  assert.equal(valueOf(Config({} as never)).agentTeamBridge, false, 'the experimental seam defaults to off')

  // Red line: with the default config, apply() must leave zero team seams
  // subscribed — every pre-existing case in this file runs through this path.
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  for (const seam of TEAM_EVENT_SEAMS) {
    assert.ok(!harness.listeners.has(seam), `${seam} must not be subscribed unless agentTeamBridge is set`)
  }

  // Opted in: the seams land on the host (the synthetic harness accepts every
  // registration, so all four do), and a delegation event end-to-end mints a
  // real obligation and injects the real handoff instruction into the payload.
  const enabled = makeHarness()
  try {
    process.env.DSH_PROOF_ROOT = ROOT
    plugin.apply(enabled.ctx, config({ agentTeamBridge: true }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const subscribed = [...enabled.listeners.keys()]
    .filter(seam => (TEAM_EVENT_SEAMS as readonly string[]).includes(seam))
  assert.equal(subscribed.length, TEAM_EVENT_SEAMS.length, 'a host accepting every seam gets all four wired')

  const handler = enabled.listeners.get('agent/team:delegated')![0]! as (raw: unknown) => Promise<void>
  const rootPayload: Record<string, unknown> = {}
  await handler({ claim: 'build the parser, root', payload: rootPayload })
  const text = String(rootPayload.proofObligation)
  assert.match(text, /DELEGATED OBLIGATION task-\d+/, 'the engine minted a real task id')
  assert.match(text, /build the parser, root/)
  assert.match(text, /proof_baseline/)
  assert.match(text, /proof_delegate_submit/)
  assert.match(text, /precondition/)
})

test('agent-team: the handoff instruction carries the claim, the ids and the worker protocol', () => {
  const text = plugin.teamHandoffInstruction('task-3', 'obl-9', 'build the parser end to end')
  assert.ok(text.includes('build the parser end to end'), 'the claim rides verbatim')
  assert.ok(text.includes('task-3'), 'the task id rides')
  assert.ok(text.includes('obl-9'), 'the obligation id rides')
  // The worker's half of the protocol, in order.
  assert.match(text, /proof_baseline/)
  assert.match(text, /proof_verify/)
  assert.match(text, /proof_bundle/)
  assert.match(text, /proof_delegate_submit \{ taskId: "task-3"/)
  // The precondition sentence that makes the DAG legible to the child.
  assert.match(text, /precondition/)
  // M-67: steps 4/5 used to teach the worker to CALL tools that are not on
  // the nine-tool DSH face this plugin registers — the instruction must say
  // where those tools live and what to do when they are out of reach.
  assert.match(text, /MCP tool face/, 'proof_bundle/proof_delegate_submit are named as MCP-face tools')
  assert.match(text, /ask the orchestrator/, 'a worker without the MCP face gets a reachable fallback')
  assert.ok(!text.includes('proof_bundle    — export the tamper-evident APP bundle of your evidence chain.\n'),
    'the old step 4 implied the tool is unconditionally callable')
})

// ---------------------------------------------------------------------------
// H-01/H-02 (v0.23): the two pre-execute-guard escapes the audit found in
// shipped paths — camelCase mutator names the delimited-verb classifier never
// matched (MultiEdit/NotebookEdit walked every gate while carrying a
// file_path into the evidence store), and the shell command string path
// extraction structurally cannot see (`bash {command:'echo x >
// .proof/evidence.jsonl'}` passed with nothing asked).
// ---------------------------------------------------------------------------

test('H-01/H-02: camelCase mutators and store-naming shell commands cannot reach the evidence store', async () => {
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

  // H-01: the Claude Code camel mutators (documented in the CC adapter's own
  // header) must hit the value sweep exactly like `write` does — X-H-13 made
  // the sweep read VALUES, so the camelCase NAME no longer matters at all.
  const camelMutators: [string, Record<string, unknown>][] = [
    ['MultiEdit', { file_path: '.proof/evidence.jsonl', edits: [] }],
    ['NotebookEdit', { notebook_path: '.proof/evidence.jsonl' }],
  ]
  for (const [name, args] of camelMutators) {
    const denied = await gate(
      { name, arguments: args, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'deny', `${name} naming the evidence store must be refused`)
    assert.match(denied.reason ?? '', /evidence/i)
  }

  // H-02: the shell command string names no path key — the value sweep
  // catches it conservatively and REFUSES (a command can rewrite anything;
  // "was that redirect really a write?" is not for a parser to guess).
  const shellForges = [
    'echo x > .proof/evidence.jsonl',
    'echo x >> .PROOF\\evidence.jsonl', // backslash + case variant
    'rm -rf .proof',
    'cat .proof/baseline.json | sha256sum',
  ]
  for (const command of shellForges) {
    const denied = await gate(
      { name: 'bash', arguments: { command }, signal: new AbortController().signal },
      async () => ({ kind: 'allow' }),
    )
    assert.equal(denied.kind, 'deny', `a store-naming shell command must be refused: ${command}`)
    assert.match(denied.reason ?? '', /must not be modified by the agent/)
  }
  // The CC camel spelling of the shell tool is caught by the same sweep.
  const camelShell = await gate(
    { name: 'Bash', arguments: { command: 'echo forged >> .proof/evidence.jsonl' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(camelShell.kind, 'deny')

  // Ordinary shell calls pass — over-blocking every shell would teach the
  // model to route its work around the verifier.
  const ordinary = await gate(
    { name: 'bash', arguments: { command: 'npm test' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(ordinary.kind, 'allow')
  // X-H-13: the read-only roster is NO LONGER exempt — a NAME is not a
  // capability, and the audited PoC's fourth form was exactly a
  // read-only-named call carrying a store-writing command. The price is
  // deliberate and documented: even a genuinely read-only call that names
  // the store (reading the log back with a host file tool) is denied with a
  // reason — the plugin's own proof_* tools read the log through the
  // engine's fs port, never through host tool calls, so verification itself
  // is not in this blast radius.
  const read = await gate(
    { name: 'Read', arguments: { file_path: '.proof/evidence.jsonl' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(read.kind, 'deny')
  // But an ordinary read of an ordinary file still sails through.
  const plainRead = await gate(
    { name: 'Read', arguments: { file_path: 'src/a.ts' }, signal: new AbortController().signal },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(plainRead.kind, 'allow')
})

// ---------------------------------------------------------------------------
// H-29 / M-49 / M-54 (v0.23): proof_claim's parameter boundary. A non-finite
// budgetMs (`JSON.parse('1e999')` yields Infinity) used to pass the typeof
// check and make the within-budget obligation vacuously satisfiable; the
// entryPoints parameter is now honestly described as not consumed (and an
// all-non-string list forwards nothing rather than []); a non-string changed
// element is a parameter error, never a silently narrowed change set.
// ---------------------------------------------------------------------------

test('H-29/M-49/M-54: proof_claim rejects non-finite budgets, forwards entryPoints honestly, validates changed', async () => {
  const contracts: Record<string, unknown>[] = []
  const outcome = {
    report: fakeReport({ grade: 'proven' }),
    changed: [],
    checks: [],
    selection: { untouched: [], precision: 'approximate' as const },
  }
  const engine = {
    verify: async () => outcome,
    verifyContract: async (options: { contract: unknown }) => {
      contracts.push(options.contract as Record<string, unknown>)
      return { ...outcome, contract: { kind: 'perf-budget' as const, obligations: [] } }
    },
  } as unknown as ProofEngine
  const tools = createProofTools(engine)
  const claimTool = tools.find(t => t.name === 'proof_claim')!
  const verifyTool = tools.find(t => t.name === 'proof_verify')!

  // H-29: Infinity / NaN / non-positive budgets are refused loudly, naming
  // the value — nothing reaches the engine on a refusal.
  await assert.rejects(
    claimTool.execute({ claim: 'fast enough', kind: 'perf-budget', budgetMs: Infinity }, execution('proof_claim', {})),
    /finite positive number of milliseconds \(got Infinity\)/,
  )
  await assert.rejects(
    claimTool.execute({ claim: 'fast enough', kind: 'perf-budget', budgetMs: NaN }, execution('proof_claim', {})),
    /finite positive number of milliseconds \(got NaN\)/,
  )
  await assert.rejects(
    claimTool.execute({ claim: 'fast enough', kind: 'perf-budget', budgetMs: -1 }, execution('proof_claim', {})),
    /finite positive number of milliseconds \(got -1\)/,
  )
  assert.deepEqual(contracts, [], 'a refused budget never mints a contract')

  // A finite positive budget still reaches the contract.
  await claimTool.execute(
    { claim: 'fast enough', kind: 'perf-budget', budgetMs: 200 },
    execution('proof_claim', {}),
  )
  assert.equal((contracts[0]! as { budgetMs?: number }).budgetMs, 200)

  // M-49: the schema tells the model the truth — the surface check derives
  // its entries from package.json, this parameter is recorded, not consumed.
  const params = claimTool.parameters as Record<string, Record<string, unknown>>
  assert.match(String(params.entryPoints?.description), /not consumed/)
  assert.match(String(params.entryPoints?.description), /package\.json/)

  // A string list rides the contract object…
  await claimTool.execute(
    { claim: 'stable surface', kind: 'behavior-preserving', entryPoints: ['src/public-api.ts'] },
    execution('proof_claim', {}),
  )
  assert.deepEqual((contracts[1]! as { entryPoints?: string[] }).entryPoints, ['src/public-api.ts'])
  // …but an all-non-string list forwards NOTHING — once the parameter goes
  // live, "override with the empty set" and "derive from package.json" must
  // never share a shape.
  await claimTool.execute(
    { claim: 'stable surface', kind: 'behavior-preserving', entryPoints: [42, {}] },
    execution('proof_claim', {}),
  )
  assert.ok(!('entryPoints' in (contracts[2]! as object)), 'a filtered-empty list forwards no key at all')

  // M-54: non-string changed elements are parameter errors on both tools.
  await assert.rejects(
    claimTool.execute({ claim: 'did things', changed: [42, 'src/a.ts'] }, execution('proof_claim', {})),
    /proof_claim: changed\[0\] must be a string path/,
  )
  await assert.rejects(
    verifyTool.execute({ changed: ['src/a.ts', null] }, execution('proof_verify', {})),
    /proof_verify: changed\[1\] must be a string path/,
  )
})

// ---------------------------------------------------------------------------
// M-80 (v0.23): unbounded strings no longer ride onto the evidence chain —
// the cap bakes a visible truncation flag into the stored text.
// ---------------------------------------------------------------------------

test('M-80: an oversized jury context is capped with a visible truncation flag', async () => {
  const { tools, dir } = await attestFixture('cap')
  try {
    const jury = tools.find(t => t.name === 'proof_jury')!
    const huge = 'z'.repeat(10_000)
    const value = valueOf(await jury.execute({ claim: 'capped context', context: huge }, execution('proof_jury', {})))
    const prompt = String(value.prompt)
    assert.ok(prompt.length < 10_000, 'the frozen prompt cannot carry the whole payload')
    assert.match(prompt, /\[truncated from 10000 chars\]/, 'the truncation itself is a chain fact')
  } finally {
    await fsp.rm(dir, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------
// M-70 (v0.23): the endorsement approval must show the DIRECTION the record
// will carry — endorse has unlock power a reject does not, so "approving the
// recording" while the agent swapped the decision is approving the wrong act.
// ---------------------------------------------------------------------------

test('M-70: the endorsement ask names the decision the record will carry', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  // Index 1 = the endorsement seam (X-H-16 put the evidence guard at 0).
  const gate = harness.listeners.get('tools/pre-execute')![1] as (
    exec: unknown, next: () => Promise<unknown>,
  ) => Promise<{ kind: string; reason?: string; displayReason?: Record<string, string> }>

  const asked = await gate(
    {
      name: 'proof_endorse',
      arguments: { claim: 'the retry is safe', decision: 'reject', approver: 'Li Si' },
      signal: new AbortController().signal,
    },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(asked.kind, 'ask')
  assert.match(String(asked.reason), /decision \(as declared by the agent\): reject/)
  assert.match(asked.displayReason?.en ?? '', /decision \(as declared by the agent\): reject/)
  assert.match(asked.displayReason?.['zh-CN'] ?? '', /方向（由 agent 自报）：reject（否决）/)

  // A bogus decision is shown as exactly that — the human must not be led to
  // believe a usable decision is on its way in.
  const bogus = await gate(
    {
      name: 'proof_endorse',
      arguments: { claim: 'the retry is safe', decision: 'maybe' },
      signal: new AbortController().signal,
    },
    async () => ({ kind: 'allow' }),
  )
  assert.match(String(bogus.reason), /no usable decision — the tool will refuse/)
})

// ---------------------------------------------------------------------------
// M-65 (v0.23): index.ts derives the evidence-log path with a mirror of the
// engine's own private rule, and the comment used to claim a wiring test
// pinned it — none did. This one pins it end-to-end: proof_jury_submit only
// succeeds by reading the request marker back THROUGH the mirrored path, so a
// drift between the two derivations refuses the submission.
// ---------------------------------------------------------------------------

test('the evidenceLogPath mirror stays glued to the engine own derivation (M-65)', async () => {
  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ROOT
  try {
    plugin.apply(harness.ctx, config())
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const jury = harness.registered.find(t => t.name === 'proof_jury')!
  const submit = harness.registered.find(t => t.name === 'proof_jury_submit')!

  const request = valueOf(await jury.execute(
    { claim: 'mirror pin: markers must read back through the derived path' },
    execution('proof_jury', {}),
  ))
  const verdict = valueOf(await submit.execute(
    {
      claimId: request.claimId,
      verdict: 'uphold',
      probability: 0.9,
      reasoning: 'deliberated; the read-back through the mirrored path is itself the pin',
    },
    execution('proof_jury_submit', {}),
  ))
  assert.equal(verdict.recorded, true, 'a drifted mirror degrades to refusal — success pins the derivation')
  assert.equal(verdict.claimId, request.claimId)
  assert.equal(verdict.gen, 0)
})

// ---------------------------------------------------------------------------
// M-66 (v0.23): the H9b shell fact is wired at apply level — a shell tool
// result must demote proof_verify's external accusation to unknown through
// the 4th createProofTools parameter, which nothing previously pinned.
// ---------------------------------------------------------------------------

test('H9b wiring: a shell tool result carries the session shell fact into proof_verify (M-66)', async () => {
  const ws = join(ROOT, 'shell-git-ws')
  await fsp.rm(ws, { recursive: true, force: true })
  await fsp.mkdir(ws, { recursive: true })
  await fsp.writeFile(join(ws, 'a.ts'), 'v1\n')
  const git = (args: string): void => {
    execSync(`git ${args}`, { cwd: ws, stdio: 'ignore' })
  }
  git('init')
  git('-c user.email=t@example.com -c user.name=t add a.ts')
  git('-c user.email=t@example.com -c user.name=t commit -m base')
  // Dirty the committed file from OUTSIDE any tool call: the git-derived
  // change set must charge it to an external editor while no shell ran.
  await fsp.writeFile(join(ws, 'a.ts'), 'v2 — an external edit\n')

  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ws
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off' }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const onResult = harness.listeners.get('tools/result')![0]! as (exec: unknown, result: unknown) => void
  const verify = harness.registered.find(t => t.name === 'proof_verify')!

  const before = valueOf(await verify.execute({}, execution('proof_verify', {})))
  assert.deepEqual(before.externalChanged, ['a.ts'], 'no shell yet: the untouched dirty file reads as external')

  onResult({ name: 'bash', arguments: { command: 'ls' } }, { isError: false, content: [] })
  await new Promise(resolve => setImmediate(resolve))

  const after = valueOf(await verify.execute({}, execution('proof_verify', {})))
  assert.deepEqual(after.externalChanged, [], 'once a shell ran, the external accusation is demoted to unknown (H9b)')
})

// ---------------------------------------------------------------------------
// M2 (v0.23): the drift narrative's output line consumes the session shell
// fact — a file changed behind the FILE tools while a shell ran must not be
// injected as "changed outside your tool calls" in the plugin's voice.
// ---------------------------------------------------------------------------

test('M2 wiring: the turn-end drift narrative stops accusing once a shell ran', async () => {
  const ws = join(ROOT, 'drift-ws')
  await fsp.rm(ws, { recursive: true, force: true })
  await fsp.mkdir(ws, { recursive: true })
  await fsp.writeFile(join(ws, 'package.json'), '{"name":"drift-ws"}\n')
  await fsp.writeFile(join(ws, 'ok.txt'), 'v1\n')

  const harness = makeHarness()
  process.env.DSH_PROOF_ROOT = ws
  try {
    plugin.apply(harness.ctx, config({ requireBaseline: 'off', enforceOnTurnEnd: false, driftDetection: true }))
  } finally {
    delete process.env.DSH_PROOF_ROOT
  }
  const onResult = harness.listeners.get('tools/result')![0]! as (exec: unknown, result: unknown) => Promise<void>
  const turnStop = harness.listeners.get('agent/turn-stopping')![0]! as (payload: unknown) => Promise<void>

  // The agent reads the file (its fingerprint is recorded); the file then
  // changes outside the FILE tools (here directly on disk — a bash edit is
  // the same blind spot); and a shell ran this session. The read observation
  // is AWAITED via the listener's returned promise: the v1 fingerprint must
  // be on record before this test mutates the file, or the watcher reads the
  // post-mutation bytes and finds no drift — a cold-cache solo run loses
  // that race, so determinism lives here, not in event-loop luck.
  await onResult({ name: 'read_file', arguments: { path: 'ok.txt' } }, { isError: false, content: [] })
  await fsp.writeFile(join(ws, 'ok.txt'), 'v2 — changed behind the file tools\n')
  await onResult({ name: 'bash', arguments: { command: 'ls' } }, { isError: false, content: [] })

  const injected: string[] = []
  await turnStop({
    agent: { inject: (message: unknown) => { injected.push((message as { content: { text: string }[] }).content[0]!.text) } },
    turn: 1,
    signal: new AbortController().signal,
  })
  assert.equal(injected.length, 1, 'the drift narrative is injected once')
  const text = injected[0]!
  assert.ok(!text.includes('outside your tool calls'), 'the false accusation is withdrawn at the output line too')
  assert.match(text, /shell ran this session/)
  assert.match(text, /ok\.txt/, 'the drifted file is still named')
})

