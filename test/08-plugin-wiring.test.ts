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
