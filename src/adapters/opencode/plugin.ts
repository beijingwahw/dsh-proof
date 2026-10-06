/**
 * OpenCode host adapter — the three things the MCP tool face cannot do alone.
 *
 * OpenCode consumes dsh-proof's verification tools — the thirteen frozen MCP
 * names of the APP/1.4 contract (`MCP_TOOLS` in src/app/mcp-server.ts; the
 * five-name APP/1.0 roster of proof_status/baseline/verify/claim/bundle grew
 * eight more since) — through the MCP server configured in `opencode.json`
 * (see `examples/opencode.json`). What MCP cannot give it is host-side
 * enforcement, so this plugin hooks the OpenCode plugin API for exactly three
 * jobs:
 *
 *   1. `tool.execute.before` — the front door: evidence-store guard + baseline
 *      gate (the same two gates the DSH adapter installs on `tools/pre-execute`).
 *   2. `tool.execute.after`  — post-observation: which files tool calls actually
 *      moved, fingerprinted for drift detection (provenance).
 *   3. `chat.params`         — policy injection: the `proof:policy` section plus
 *      the MCP tool names, appended to the assembled chat parameters.
 *
 * The OpenCode plugin API is explicitly still evolving (upstream warns about
 * breaking changes), so the core design principle here is **runtime
 * duck-typing + graceful degradation**: every surface is probed with
 * `typeof`/shape checks (`vendor.ts` narrowers), every registered handler and
 * every registration call is wrapped in try/catch, and a surface that does
 * not match simply stays idle with one stderr line. The adapter NEVER throws
 * into the host — the MCP tools keep working regardless of what this plugin
 * could or could not hook.
 *
 * Semantic differences vs the Claude Code adapter (deliberate, documented):
 *
 *   - Drift anchor: Claude Code has a Stop hook, so drift is checked when the
 *     turn tries to end. OpenCode has none, so `ocBeforeHandler` opportunistically
 *     runs the drift check ahead of EVERY tool call ("the next tool call is the
 *     anchor"): the first call after external changes is held with the drift
 *     narrative, the model re-reads the stale files (the read observation
 *     refreshes the fingerprint), and subsequent calls pass. Each distinct
 *     drift set is surfaced at most once per plugin lifetime to avoid holding
 *     every call forever when the message is ignored. The one-time baseline/verify
 *     notices (the shared layer's turn-end rules) surface at the same anchor, once
 *     per session — a held call is the only channel a before hook gives this
 *     adapter for reaching the model.
 *   - Interception shape: Claude Code hooks block via exit code 2 + stderr.
 *     OpenCode's before hook has no stable interception contract, so a held
 *     call returns `{ error: { message } }` (the most commonly documented
 *     form) AND explains itself on stderr — whichever one the running OpenCode
 *     version honors, the model sees the reason.
 *   - `ask` semantics: the shared gate's `ask` decision (route through user
 *     approval) cannot be expressed in OpenCode's before hook, so `ask` and
 *     `deny` both hold the call; `deny` additionally marks the reason as a
 *     refusal. There is no approval round-trip on this host — a held call is
 *     held, and the reason tells the model what to do instead. The one carve-
 *     out is the trusted MCP face: `proof_*` tool names never enter the
 *     baseline ladder (see {@link isProofMcpToolName}), because holding the
 *     only tool that can establish a baseline is a deadlock, not a gate.
 *
 * @module dsh-proof/adapters/opencode/plugin
 */

import { promises as fsp } from 'node:fs'

import { buildPolicySection } from '../../dsh/prompt.ts'
import { MCP_TOOLS } from '../../app/mcp-server.ts'
import { asAfter, asBefore, asPluginContext, directoryOf } from './vendor.ts'
import { deriveProofPaths, resolveAdapterEnv } from '../shared/paths.ts'
import type { ProofPaths } from '../shared/paths.ts'
import { applyObservation, computeDrift, emptySession, loadSession, saveSession, windowStart } from '../shared/session.ts'
import { decidePreToolUse, evaluateStop, hasBaselineOnDisk } from '../shared/gates.ts'
import type { GateOptions, StopFacts } from '../shared/gates.ts'
// v0.25.1 (U4-H1): `readChainMarkers` is the one public read carrying the
// H-32 position verdict, reserved for engine-less faces (this plugin holds
// no store); the `_readMarkers` escape hatch is retired (test/32 claim 1b).
import { readChainMarkers } from '../../core/evidence.ts'

// ---------------------------------------------------------------------------
// Options and the adapter environment
// ---------------------------------------------------------------------------

export interface OcAdapterOptions {
  /** Workspace root to verify. Default: `$DSH_PROOF_ROOT`, then the ctx directory, then cwd. */
  root?: string
  /** Host trust root (keys/anchors/sessions). Default: `$DSH_PROOF_TRUST_DIR`, then the shared layer's default. */
  trustRoot?: string
  /** `'workspace'` puts the evidence store inside the project (guarded); `'host'` (default) keeps it outside. */
  evidenceStore?: string
  /** Evidence directory relative to the root (workspace mode only; default `.proof`). */
  evidenceDir?: string
  /** Baseline gate mode. Default `warn` (same as the DSH/config default). */
  requireBaseline?: 'off' | 'warn' | 'ask'
  /** Opportunistic drift checks at the next tool call. Default `true`. */
  driftDetection?: boolean
  /** Turn-end enforcement facts (used by `ocTurnEndHandler`; not registered in v1). Default `true`. */
  enforceOnTurnEnd?: boolean
  /** Clock for session window stamps (ISO strings). Default: real time. */
  now?: () => string
  /** File reader (returns undefined for missing files). Default: real fs, utf8. */
  readFile?: (abs: string) => Promise<string | undefined>
  /** Diagnostics sink, one line per call. Default: `process.stderr`. */
  stderr?: (line: string) => void
}

/**
 * Everything the handlers need — the η-shared pieces plus this adapter's own
 * knobs. `hasBaseline` is a cache (refreshed before every gate decision and
 * after any `proof_*` tool call, so the injected prompt stays truthful without
 * an fs read per prompt render); `surfacedDrift` dedupes before-time drift
 * holds (and re-arms when the disk comes back clean — M-42). Structurally the
 * same record the Claude Code adapter builds, defined here so this layer
 * imports nothing from the claude-code directory.
 */
export interface OcAdapterEnv {
  readonly paths: ProofPaths
  readonly gate: GateOptions
  readonly driftDetection: boolean
  readonly enforceTurnEnd: boolean
  readonly now: () => string
  readonly readFile: (abs: string) => Promise<string | undefined>
  readonly stderr: (line: string) => void
  /** Cached `baseline.json exists on disk` flag — see interface comment above. */
  hasBaseline: boolean
  /**
   * Drift CONTENT fingerprints already held once at before-time. A drift set
   * is held once per plugin lifetime WHILE IT PERSISTS; once computeDrift
   * comes back clean (every member resolved), the set clears and the same
   * drift shape blocks again on recurrence — ignoring a hold is never a
   * permanent exemption.
   */
  readonly surfacedDrift: Set<string>
  /**
   * W12-M4: has the "before payload shape not recognized" stderr line been
   * spent for this plugin lifetime? The same unrecognized shape repeats on
   * every call; the contract is ONE line, not one per call. Mutable state on
   * an otherwise readonly record — same licence as `hasBaseline`.
   */
  shapeDriftWarned?: boolean
}

function normalizeStore(value: string | undefined): 'host' | 'workspace' {
  return value === 'workspace' ? 'workspace' : 'host'
}

function normalizeRequireBaseline(value: string | undefined): 'off' | 'warn' | 'ask' {
  return value === 'off' || value === 'ask' ? value : 'warn'
}

const defaultNow = (): string => new Date().toISOString()

const defaultReadFile = async (abs: string): Promise<string | undefined> => {
  try {
    return await fsp.readFile(abs, 'utf8')
  } catch {
    return undefined
  }
}

const defaultStderr = (line: string): void => {
  // W12-L11: a host that already closed its stderr pipe turns every write
  // into a throw (or, async, an 'error' event) — a diagnostics sink must
  // never take the handler down with it.
  try {
    process.stderr.write(`${line}\n`)
  } catch {
    /* nothing further to do */
  }
}
// Same rule for the asynchronous arm: an unhandled 'error' event on stderr
// would crash the host process for nothing the host can use. One no-op
// listener, registered once at module load (this plugin shares the host's
// process — the listener changes nothing except "unhandled" becoming
// "handled"). Mirrors entry.ts's stdout/stderr posture on the Claude Code side.
process.stderr.on('error', () => { /* the pipe is gone; nothing left to say */ })

/**
 * Assemble the adapter environment. Environment variables honor the SAME
 * names and semantics as the Claude Code hooks and the MCP entry — parsed by
 * the shared `resolveAdapterEnv` (H-21/M-44): pre-v0.23 this adapter read
 * only ROOT/TRUST_DIR/EVIDENCE_STORE/REQUIRE_BASELINE from the host process
 * environment while the README promised one shared set, so `DSH_PROOF_DRIFT`,
 * `DSH_PROOF_ENFORCE_TURN_END` and `DSH_PROOF_EVIDENCE_DIR` silently did
 * nothing here. Options (opencode.json plugin options) still beat the
 * environment, which beats the code default.
 */
export function ocAdapterEnv(options: OcAdapterOptions, cwd: string): OcAdapterEnv {
  const values = resolveAdapterEnv(process.env)
  const root = options.root ?? values.root ?? cwd
  const evidenceStore = normalizeStore(options.evidenceStore ?? values.evidenceStore)
  const evidenceDir = options.evidenceDir ?? values.evidenceDir
  const paths = deriveProofPaths({
    root,
    trustRoot: options.trustRoot ?? values.trustRoot,
    evidenceStore,
    ...(evidenceDir !== undefined ? { evidenceDir } : {}),
  })
  return {
    paths,
    gate: {
      evidenceStore: paths.evidenceStore,
      evidenceDir: paths.evidenceDir,
      requireBaseline: normalizeRequireBaseline(
        options.requireBaseline ?? values.requireBaseline,
      ),
      // The trust root rides along so the shell-command sweep (H-02) guards
      // the trust-side artifacts on this host too.
      trustRoot: paths.trustRoot,
    },
    driftDetection: options.driftDetection ?? values.driftDetection ?? true,
    enforceTurnEnd: options.enforceOnTurnEnd ?? values.enforceTurnEnd ?? true,
    now: options.now ?? defaultNow,
    readFile: options.readFile ?? defaultReadFile,
    stderr: options.stderr ?? defaultStderr,
    hasBaseline: false,
    surfacedDrift: new Set<string>(),
    shapeDriftWarned: false,
  }
}

// ---------------------------------------------------------------------------
// Input guessing — OpenCode's before/after hook payload shape is not pinned,
// so the tool name, arguments and session id are coaxed out of whichever keys
// are present. Never throws; missing pieces are simply undefined.
// ---------------------------------------------------------------------------

export interface GuessedToolCall {
  readonly tool: string | undefined
  readonly args: unknown
  readonly sessionId: string | undefined
}

function firstString(...values: readonly unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

/**
 * Guess `{ tool, args, sessionId }` from a hook payload:
 *   - tool name: `tool` / `name` / `toolName` as strings, then a nested
 *     `tool.name` when `tool` is an object;
 *   - args: `arguments` / `args` / `input`, first one present;
 *   - session: `sessionID` / `session_id`.
 */
export function guessToolCall(input: unknown): GuessedToolCall {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { tool: undefined, args: undefined, sessionId: undefined }
  }
  const record = input as Record<string, unknown>
  let tool = firstString(record.tool, record.name, record.toolName)
  if (tool === undefined && typeof record.tool === 'object' && record.tool !== null && !Array.isArray(record.tool)) {
    const nested = record.tool as Record<string, unknown>
    tool = firstString(nested.name, nested.toolName)
  }
  const args = record.arguments !== undefined ? record.arguments : record.args !== undefined ? record.args : record.input
  return {
    tool,
    args,
    sessionId: firstString(record.sessionID, record.session_id),
  }
}

/**
 * Trusted-MCP-face test (W20-H4 / W12-F3): is this tool name one of dsh-proof's
 * own `proof_*` MCP tools?
 *
 * CONTRACT with the observe classifier (G5's domain, src/dsh/observe.ts):
 * `isMutationToolName` is being taught that `proof_`-prefixed names are NOT
 * mutations — the MCP tools write through the server process, never through
 * host tool arguments, so the mutation charge buys nothing there. Until (and
 * after — this arm is the defense-in-depth) that lands, THIS consumer exempts
 * them from the baseline ladder itself: `decidePreToolUse` is handed
 * `hasBaseline: undefined` ("unknown") for a proof_* call, and the ask rule
 * (rule 2) never fires on "unknown". The DENY arms (evidence-store guard,
 * shell sweep) stay fully armed — the exemption opens the rescue hatch, not
 * the door.
 *
 * Why the exemption must exist at all: on OpenCode the before hook sees EVERY
 * tool call (no matcher), and `ask`/`deny` both HOLD. Under
 * `requireBaseline:'ask'` with no baseline, `proof_baseline` itself was held
 * by a gate whose hold reason said "Establish one first with the proof_baseline
 * MCP tool" — the remedy held itself, and the agent could never self-rescue
 * (only a human writing a baseline file outside the tools would release it,
 * and in workspace mode even that route is command-swept). Claude Code does
 * not deadlock this way (`ask` there is a real approval round-trip, and the
 * example matchers keep MCP names out of the hook), which is why this fix is
 * OpenCode-side only.
 *
 * Name matching: OpenCode spells MCP tools by their server-declared name
 * (`proof_baseline`); a host that namespaces imported tools (Claude Code's
 * `mcp__proof__proof_baseline`) carries the server-declared name as the last
 * `__`-separated segment, so both spellings are honored.
 */
export function isProofMcpToolName(name: string): boolean {
  const lastSegment = name.toLowerCase().split('__').at(-1) ?? ''
  return lastSegment.startsWith('proof_')
}

/** A short, safe hint about an unrecognized payload's shape (keys or typeof) — diagnostic text only. */
function payloadShapeHint(input: unknown): string {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return typeof input
  const keys = Object.keys(input).join(',')
  return keys.length > 80 ? `${keys.slice(0, 80)}…` : keys
}

/**
 * Host-render sanitization for any model-facing hold/block text (W12-M1).
 *
 * Drift narratives embed workspace FILE NAMES — attacker-controllable data —
 * and a POSIX file name may legally contain newlines, so a crafted name used
 * to arrive inside an authoritative-voice hold as its own forged instruction
 * line. At this render point the text is one flat string, so the honest fix
 * is structural: every original newline becomes a visible ' | ' separator (a
 * forged "instruction line" can no longer occupy a line of its own), other
 * C0 control characters and DEL are dropped, and any single over-long
 * segment (a padded payload) is capped. The producing side (observe.ts's
 * driftNarrative) is the classifier owner's domain; this is the host's
 * defense-in-depth render rule. Mirrored in adapters/claude-code/hooks.ts —
 * keep the two in lockstep.
 */
const HOST_RENDER_SEGMENT_CAP = 200

export function sanitizeBlockForModel(text: string): string {
  return text
    .split(/\r?\n/)
    .map(segment => {
      const clean = segment.replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '').trim()
      return clean.length > HOST_RENDER_SEGMENT_CAP ? `${clean.slice(0, HOST_RENDER_SEGMENT_CAP)}…` : clean
    })
    .filter(segment => segment.length > 0)
    .join(' | ')
}

// ---------------------------------------------------------------------------
// Handlers — separated from registration so each is directly testable
// ---------------------------------------------------------------------------

/**
 * Y-H-13 (v0.24): the digest the evidence chain remembers for the baseline
 * FILE BYTES — the binding argument `hasBaselineOnDisk`'s W11-M4 contract
 * shipped in v0.23 and then never received: every adapter call site invoked
 * the probe two-argument, so the chain floor never engaged and a five-line
 * self-consistent baseline minted with the package's own public
 * `addressOf`/`merkleRoot` walked the ask ladder exactly like a genuine one
 * (the audit's PoC). This read is that third argument.
 *
 * The rule is the ENGINE's, mirrored verbatim — core/evidence.ts's private
 * `lastBaselineDigest`, the same selection `loadBaseline()` and `audit()`
 * bind by: last-wins among `baseline/saved` markers whose `headRef` can vouch
 * for their physical position; when EVERY such marker is suspect (a log
 * written before the headRef witness existed), the last one still speaks, so
 * an upgraded deployment keeps exactly the detection it had, never less. No
 * marker the chain remembers means `undefined`, and `hasBaselineOnDisk` then
 * falls to its own no-chain floor instead of to an accusation — the same
 * degradation `loadBaseline` grants a baseline placed by a flow that never
 * recorded a save.
 *
 * Line discipline: the store's `readLines` (node-ports) splits on '\n' and
 * drops blank lines; the suspect test hashes each marker's PHYSICAL
 * predecessor, so this split must produce the same snapshot the engine's own
 * walk sees, or the two faces would disagree about who is suspect.
 *
 * Cost (deliberately uncached): a gate evaluation now reads TWO files
 * (baseline + log) where it read one. Unlike the Claude Code face (one
 * process per hook event), this plugin lives in the host process and pays
 * the log read per gate call — and an mtime-keyed digest cache was
 * considered and rejected: it would open a staleness window exactly where
 * freshness IS the security property (a swapped baseline must fail the very
 * next gate call, not the first call after the log's mtime moves), and the
 * readFile-only env contract carries no stat seam to key it on. The
 * neighboring drift check already re-walks workspace FILES per call, so this
 * bounded read is not the expensive half of a gate evaluation.
 *
 * Mirrored in adapters/claude-code/hooks.ts — keep the two in lockstep (the
 * sanitizeBlockForModel rule).
 */
async function savedBaselineDigest(
  logPath: string,
  readFile: (abs: string) => Promise<string | undefined>,
): Promise<string | undefined> {
  const raw = await readFile(logPath)
  if (raw === undefined) return undefined
  const lines = raw.split('\n').filter(line => line.trim().length > 0)
  // v0.25.1 (U4-H1): the read goes through `readChainMarkers` — the one
  // PUBLIC read that carries the H-32 position verdict, imported by exactly
  // the two engine-less adapter faces (test/32 claim 1b pins the importer
  // set). Same single-pass core the store's `markersWith` and the verified
  // view derive from; the underscore `_readMarkers` escape hatch is retired.
  const markers = readChainMarkers(lines, { label: 'baseline/saved' })
    .filter(marker => typeof marker.payload.digest === 'string')
  const trusted = markers.filter(marker => !marker.suspect)
  const pool = trusted.length > 0 ? trusted : markers
  const last = pool[pool.length - 1]
  return last === undefined ? undefined : last.payload.digest as string
}

/**
 * The chained refresh behind every `env.hasBaseline` assignment here: the
 * cached flag is only truthful if it is `hasBaselineOnDisk` bound to the
 * digest the chain remembers (Y-H-13), so all four refresh sites — the gate,
 * the post-proof_* refresh, the turn-end handler and the plugin pre-warm —
 * go through this one door.
 */
async function chainedHasBaselineOnDisk(env: OcAdapterEnv): Promise<boolean> {
  return hasBaselineOnDisk(env.paths, env.readFile, await savedBaselineDigest(env.paths.logPath, env.readFile))
}

function driftKey(drift: { readonly drifted: readonly string[]; readonly staleReads: readonly string[] }): string {
  // W12-L6: staleReads join the fingerprint. staleReads ⊆ drifted, so the
  // same drifted set can evolve from stale=[] to stale≠[] — a MORE severe
  // narrative (the stale-reads section leads) — and the second hold must not
  // be silently spent by the first. The \x01 separator keeps the two halves
  // unforgeable by any path content (\x00 is the in-list separator).
  return `${drift.drifted.join('\x00')}\x01${drift.staleReads.join('\x00')}`
}

/**
 * The front door. Returns `{ block }` to hold the call (mapped by the plugin
 * wrapper into OpenCode's `{ error: { message } }` form), or `undefined` to
 * let it through.
 *
 * Order of business:
 *   1. the shared turn-end evaluation runs opportunistically (OpenCode's only
 *      reliable anchor is the next tool call — see the module comment): each
 *      distinct drift set is held once per plugin lifetime, the one-time
 *      baseline/verify notices once per session, and fire ids are paid into
 *      the session ledger before anything is surfaced;
 *   2. the evidence-store guard + baseline gate via the shared `decidePreToolUse`
 *      (`ask` and `deny` both hold here — no approval round-trip on this host;
 *      a `deny` is marked as a refusal in the text).
 */
export async function ocBeforeHandler(env: OcAdapterEnv, input: unknown): Promise<{ block?: string } | undefined> {
  const call = guessToolCall(input)
  if (call.tool === undefined) {
    // W12-M4 (the M-40 family's silent twin): a payload that ARRIVED but whose
    // tool name no spelling guess recognizes is a shape drift — the gate is
    // idle for such calls while registration, log and posture all look
    // healthy. "Registered, healthy, door open" is exactly the silent failure
    // the duck-typing discipline ("every degradation says one stderr line")
    // forbids. Once per plugin lifetime: the same shape repeats every call,
    // and the contract is one line, not one per call. Behavior is unchanged —
    // the call still passes through; only the silence was wrong.
    if (env.shapeDriftWarned !== true) {
      env.shapeDriftWarned = true
      env.stderr(`dsh-proof: before payload shape not recognized (${payloadShapeHint(input)}); `
        + 'the gate is idle for this call — if this persists, this OpenCode version moved the tool name '
        + 'out of every spelling the adapter guesses')
    }
  }
  if (call.tool === undefined && call.sessionId === undefined) return undefined

  // (1) drift + one-time notices, ahead of the gate — advisory: a broken
  //     check must never wedge the door.
  let heldNotice: string | undefined
  if (call.sessionId !== undefined) {
    try {
      const session = await loadSession(env.paths.sessionDir, call.sessionId)
      if (session !== undefined) {
        const drift = env.driftDetection
          ? await computeDrift(session, env.paths.root, env.readFile)
          : undefined
        // M-42: a clean disk re-arms the once-per-lifetime cap. While a drift
        // set PERSISTS, its hold stays spent (a host whose only anchor is the
        // next tool call would otherwise hold every call hostage); once every
        // member is resolved the cap clears, and the same shape recurring
        // blocks again — ignoring a hold is never a permanent exemption.
        if (drift !== undefined && drift.drifted.length === 0 && drift.staleReads.length === 0) {
          env.surfacedDrift.clear()
        }
        const facts: StopFacts = {
          drift,
          touchedCount: session.touched.length,
          hasBaseline: env.hasBaseline,
          requireBaseline: env.gate.requireBaseline,
          // The turn has NOT ended here — the turn-end-only enforcement rule
          // stays off until OpenCode grows a stop seam (ocTurnEndHandler).
          enforceOnTurnEnd: false,
          driftDetection: env.driftDetection,
        }
        const verdict = evaluateStop(facts, session)
        // evaluateStop is pure: a fire id is this caller's ledger debt, paid
        // BEFORE the block is surfaced (a crash in between must not re-fire
        // the notice on the next call).
        if (verdict.fire !== undefined) {
          await saveSession(env.paths.sessionDir, call.sessionId, {
            ...session,
            firedNotices: [...session.firedNotices, verdict.fire],
          })
        }
        if (verdict.block !== undefined) {
          const drifted = drift !== undefined
            && (drift.drifted.length > 0 || drift.staleReads.length > 0)
          if (drifted) {
            // The shared gate blocks on drift EVERY time; on a host whose
            // only anchor is the next tool call that holds every subsequent
            // call hostage once the message is ignored. Each distinct drift
            // set is held exactly once while it persists. (The Claude Code
            // Stop hook needs no such cap — it fires once per real turn
            // boundary.)
            if (!env.surfacedDrift.has(driftKey(drift))) {
              heldNotice = verdict.block
              env.surfacedDrift.add(driftKey(drift))
            }
          } else {
            heldNotice = verdict.block
          }
        }
      }
    } catch {
      /* no drift opinion is better than a thrown one */
    }
  }

  // (2) the gate. Fail-CLOSED (M-40): this is the evidence-store door, and a
  //     door whose errors swing it open is decoration. The Claude Code
  //     adapter answers `ask` on any internal error; the OpenCode posture is
  //     the same conservatism in this host's vocabulary — hold the call and
  //     say why. (The drift block above stays advisory: a broken observation
  //     must never wedge the door, a broken GATE must never open it.)
  let gateBlock: string | undefined
  if (call.tool !== undefined) {
    try {
      try {
        env.hasBaseline = await chainedHasBaselineOnDisk(env)
      } catch {
        /* keep the cached flag; a failed stat is not a policy input */
      }
      // W20-H4: the trusted MCP face never enters the baseline ladder —
      // `hasBaseline: undefined` means "unknown", and rule 2 only fires on
      // `=== false`. The deny arms inside decidePreToolUse stay armed (see
      // isProofMcpToolName for the contract with the observe classifier).
      // Without this, requireBaseline:'ask' held proof_baseline itself, and
      // the hold reason told the model to call the tool it had just been
      // denied — a deadlock only a human could break.
      const decision = decidePreToolUse(
        call.tool,
        call.args,
        env.paths.root,
        env.gate,
        isProofMcpToolName(call.tool) ? undefined : env.hasBaseline,
      )
      if (decision.action === 'deny') gateBlock = `denied — ${decision.reason}`
      else if (decision.action === 'ask') gateBlock = decision.reason
    } catch (error) {
      gateBlock = `denied — dsh-proof: gate internal error (${errorMessage(error)}); the call is held rather than waved through`
    }
  }

  if (heldNotice === undefined && gateBlock === undefined) return undefined
  const parts = [gateBlock, heldNotice].filter((part): part is string => part !== undefined)
  return { block: parts.join('\n\n') }
}

/**
 * Post-observation: apply the shared observation (touched/read split +
 * fingerprints) to the session and persist it. A payload without a guessable
 * session id is a no-op — there is nowhere durable to put the observation.
 * Never blocks, never throws.
 */
export async function ocAfterHandler(env: OcAdapterEnv, input: unknown): Promise<undefined> {
  const call = guessToolCall(input)
  if (call.sessionId === undefined || call.tool === undefined) return undefined
  try {
    const session = (await loadSession(env.paths.sessionDir, call.sessionId)) ?? emptySession(env.now())
    const observed = await applyObservation(session, call.tool, call.args, env.paths.root, env.readFile)
    await saveSession(env.paths.sessionDir, call.sessionId, observed)
  } catch (error) {
    env.stderr(`dsh-proof: post-tool observation failed (${errorMessage(error)}); drift detection may lag`)
  }
  // A proof_* call may have just established a baseline on disk (the MCP
  // server writes it); refresh the cache so the next prompt render is honest.
  if (call.tool.startsWith('proof_')) {
    try {
      env.hasBaseline = await chainedHasBaselineOnDisk(env)
    } catch {
      /* keep the cached flag */
    }
  }
  return undefined
}

/**
 * Turn-end evaluation: full drift + enforcement facts, `windowStart` to roll
 * the observation window. NOT registered in v1 — OpenCode exposes no Stop
 * hook and its event bus shape is not stable enough to guess. Exported so a
 * future version (or an e2e harness that can simulate turn ends) gets the
 * same semantics the Claude Code adapter's Stop hook has; until then drift
 * enforcement rides `ocBeforeHandler`'s next-call anchor instead.
 */
export async function ocTurnEndHandler(env: OcAdapterEnv, sessionId: string | undefined): Promise<{ block?: string } | undefined> {
  try {
    const session = (sessionId !== undefined
      ? await loadSession(env.paths.sessionDir, sessionId)
      : undefined) ?? emptySession(env.now())
    const drift = env.driftDetection
      ? await computeDrift(session, env.paths.root, env.readFile)
      : undefined
    try {
      env.hasBaseline = await chainedHasBaselineOnDisk(env)
    } catch {
      /* keep the cached flag */
    }
    const facts: StopFacts = {
      drift,
      touchedCount: session.touched.length,
      hasBaseline: env.hasBaseline,
      requireBaseline: env.gate.requireBaseline,
      enforceOnTurnEnd: env.enforceTurnEnd,
      driftDetection: env.driftDetection,
    }
    const verdict = evaluateStop(facts, session)
    if (sessionId !== undefined) {
      // Fire ids are this caller's ledger debt (evaluateStop is pure — it
      // never mutates the session); pay them, then roll the window.
      const ledgered = verdict.fire !== undefined
        ? { ...session, firedNotices: [...session.firedNotices, verdict.fire] }
        : session
      await saveSession(env.paths.sessionDir, sessionId, windowStart(ledgered, env.now()))
    }
    return verdict.block !== undefined ? { block: verdict.block } : undefined
  } catch (error) {
    env.stderr(`dsh-proof: turn-end evaluation failed (${errorMessage(error)}); turn proceeds`)
    return undefined
  }
}

// ---------------------------------------------------------------------------
// Prompt injection
// ---------------------------------------------------------------------------

/**
 * One-line blurbs for the frozen MCP tool names (APP/1.4 contract — thirteen
 * tools; the list itself is `MCP_TOOLS`, the single source this map only
 * decorates; an unblurbed name still renders, as its bare self).
 */
const TOOL_BLURB: Record<string, string> = {
  proof_status: 'read the current proof state — baseline? discovered checks? chain intact?',
  proof_baseline: 'establish or refresh the verification baseline, before the first edit',
  proof_verify: 're-run the objective checks this change set made stale; a check that passed at baseline and now fails is YOUR regression',
  proof_claim: 'state the exact completion claim and prove it in one call; proven only when nothing regressed',
  proof_bundle: 'export the tamper-evident evidence bundle for audit or hand-off',
  proof_publish: 'publish the latest signed checkpoint to the public transparency log, minting a signed tree head over it',
  proof_log_verify: 'audit the public log — root recompute, inclusion and consistency proofs; nothing the caller asserts is trusted',
  proof_delegate: 'ORCHESTRATOR: delegate work as a signed obligation on the responsibility DAG; returns the taskId and the worker handoff text',
  proof_delegate_submit: 'WORKER: submit your exported proof_bundle for a delegated task; the bundle is adjudicated from its own bytes',
  proof_task: 'ORCHESTRATOR: inspect the responsibility DAG — whole-graph overview, or one task\'s composed verdict',
  proof_training_export: 'export the workspace\'s machine-verified behavior data as a training dataset (privacy tier defaults to private)',
  proof_economics: 'read what the last rate-carded verification COST, replayed verbatim off the chain\'s own boundary marker',
  proof_sla_quote: 'price an SLA over a verification grade — the insurance reading of residual risk (proven: offer; regressed: refused)',
}

/**
 * The concrete spelling of "the evidence store" for the DETECTED self-check,
 * derived from the adapter's own paths (W12-M2) — never hardcoded. Workspace
 * mode names the workspace-relative file the model can actually attempt; host
 * mode names the absolute store under the trust root (a relative write there
 * is not a store write at all, so the check must spell the absolute path —
 * and that is exactly the absolute-path write the H-26 arm denies).
 */
function evidenceSelfCheckPath(paths: ProofPaths): string {
  if (paths.evidenceStore === 'workspace') {
    return paths.evidenceDir === '' ? 'evidence.jsonl in the workspace root' : `${paths.evidenceDir}/evidence.jsonl`
  }
  return paths.logPath
}

/**
 * The system-prompt addition: the canonical `proof:policy` section plus the
 * host-specific note that the proof tools ride an MCP server here.
 * Injected through `chat.params` when that seam exists; exported regardless
 * so an e2e harness can assert what WOULD be injected.
 */
export function buildSystemPromptAddition(env: OcAdapterEnv): string {
  const policy = buildPolicySection({
    // Check discovery is the MCP server's job on this host; the adapter has
    // no engine. The section honestly says "no checks discovered here" — the
    // tools themselves know better once the server reports for duty.
    discovered: [],
    hasBaseline: env.hasBaseline,
    requireBaseline: env.gate.requireBaseline,
  })
  const lines: string[] = [
    policy,
    // W12-M15: the policy line above says "no objective checks are
    // discovered in this workspace" — true of what THIS ADAPTER can see
    // (nothing: discovery is the engine's, behind the MCP tools). Without
    // this qualifier a model in a repo full of check scripts would take the
    // line as a workspace fact and skip the baseline or go edit
    // package.json.
    'Check discovery does not run in this host adapter — the line above is the adapter\'s view, not the '
    + 'workspace\'s. Ask `proof_status` for the live discovered set before concluding the workspace declares no checks.',
    '',
    '## Proof tools on this host (OpenCode + MCP)',
    '',
    `This workspace runs the dsh-proof MCP server. ${MCP_TOOLS.length} tools, frozen contract (APP/1.4):`,
    ...MCP_TOOLS.map(name => `- \`${name}\` — ${TOOL_BLURB[name] ?? name}`),
    '',
    'Before editing: `proof_baseline`. Before saying work is done: `proof_claim` — a prose assertion is not evidence.',
    'If a tool call is held with a dsh-proof reason, act on the reason instead of retrying the same call.',
    '',
    'Enforcement wiring: the gates above ride host plugin hooks (tool.execute.before / after) that this prompt '
    + 'cannot verify are registered — plugin wiring supplied by the repository travels with the repository. '
    + 'Treat enforcement as DETECTED, not guaranteed: if a write into the evidence store '
    + `(${evidenceSelfCheckPath(env.paths)}) `
    + 'is not held, report the guard as absent instead of assuming oversight.',
  ]
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// The plugin — probe, register, degrade gracefully
// ---------------------------------------------------------------------------

const NO_SURFACE_LINE = 'dsh-proof: no compatible OpenCode plugin surface found; enforcement idle (MCP tools still work)'

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function firstLine(text: string): string {
  return text.split('\n')[0] ?? text
}

/**
 * Build the plugin initializer. Probe a context, register on every surface
 * that duck-types into a known shape, and never let the host see an
 * exception. Returns `(ctx) => Promise<{ dispose }>`; `dispose` revokes what
 * it can (a registrar that handed back an unregister function gets it called).
 */
export function createOpencodePlugin(options: OcAdapterOptions = {}): (ctx: unknown) => Promise<{ dispose: () => void }> {
  return async function init(ctx: unknown): Promise<{ dispose: () => void }> {
    const stderr = options.stderr ?? defaultStderr
    const context = asPluginContext(ctx)
    if (context === undefined) {
      stderr(NO_SURFACE_LINE)
      return { dispose: () => undefined }
    }
    const directory = directoryOf(context) ?? process.cwd()
    const env = ocAdapterEnv(options, directory)
    // Pre-warm the baseline flag so the first prompt render tells the truth
    // about a workspace that already has one.
    try {
      env.hasBaseline = await chainedHasBaselineOnDisk(env)
    } catch {
      /* cache stays false; first gate decision retries */
    }

    const disposers: Array<() => void> = []
    const registered: string[] = []

    /** One registration attempt: a throwing registrar degrades to a stderr line. */
    const register = (label: string, attempt: () => unknown): void => {
      try {
        const undo = attempt()
        if (typeof undo === 'function') {
          disposers.push(() => {
            try {
              undo()
            } catch (error) {
              stderr(`dsh-proof: ${label} dispose failed (${errorMessage(error)})`)
            }
          })
        }
        registered.push(label)
      } catch (error) {
        stderr(`dsh-proof: OpenCode ${label} registration failed (${errorMessage(error)}); that seam stays idle`)
      }
    }

    // -- tool.execute.before: the front door --------------------------------
    const wrappedBefore = async (input: unknown, _output: unknown): Promise<unknown> => {
      try {
        const decision = await ocBeforeHandler(env, input)
        if (decision !== undefined && decision.block !== undefined) {
          stderr(`dsh-proof: holding a tool call via tool.execute.before — ${firstLine(decision.block)}`)
          // OpenCode's before-hook interception shape is not stable across
          // releases; `{ error: { message } }` is the most commonly documented
          // form. The stderr line above covers hosts that report differently.
          // W12-M1: the message is sanitized at this render point — drift
          // narratives embed workspace file names (attacker-controllable;
          // POSIX names may contain newlines), and the hold text speaks with
          // the plugin's authoritative voice.
          return { error: { message: sanitizeBlockForModel(decision.block) } }
        }
        return undefined
      } catch (error) {
        // M-40: the before wrapper is the evidence-store door. A door whose
        // unexpected failures swing it OPEN is decoration — pre-v0.23 this
        // arm said "allowing the call", the exact inverse of the Claude Code
        // adapter's `ask` on internal error. Hold, say why, fail closed.
        const message = `denied — dsh-proof: gate internal error (${errorMessage(error)}); the call is held rather than waved through`
        stderr(`dsh-proof: before hook failed; holding the call (${errorMessage(error)})`)
        return { error: { message: sanitizeBlockForModel(message) } }
      }
    }

    // -- tool.execute.after: observation ------------------------------------
    const wrappedAfter = async (input: unknown, _output: unknown): Promise<undefined> => {
      try {
        await ocAfterHandler(env, input)
      } catch (error) {
        stderr(`dsh-proof: after hook failed (${errorMessage(error)})`)
      }
      return undefined
    }

    // -- chat.params: policy injection ---------------------------------------
    // The seam is guessed as `(handler) => unknown` with the handler receiving
    // the assembled chat parameters as its second argument; a `system` member
    // (string or string array) gets the policy addition appended. Anything
    // unexpected inside the handler is swallowed — a broken prompt append must
    // never break chat assembly.
    const wrappedParams = (input: unknown, output: unknown): unknown => {
      try {
        if (typeof output !== 'object' || output === null || Array.isArray(output)) return undefined
        const record = output as { system?: unknown }
        const addition = buildSystemPromptAddition(env)
        if (typeof record.system === 'string') {
          record.system = record.system.length > 0 ? `${record.system}\n\n${addition}` : addition
        } else if (Array.isArray(record.system)) {
          // W12-L13: hosts assemble `system` either as plain strings or as
          // part objects ({type:'text',…}). Appending a bare string to a
          // parts array could be silently dropped by the host — the policy
          // evaporating without a sound. Probe the element shape: an all-
          // objects array gets a text PART; everything else (all strings,
          // mixed, empty — no signal) keeps the historical string append.
          const parts = record.system
          const allParts = parts.length > 0
            && parts.every(p => typeof p === 'object' && p !== null && !Array.isArray(p))
          record.system = allParts
            ? [...parts, { type: 'text', text: addition }]
            : [...parts, addition]
        }
        // No recognizable `system` member: leave the parameters untouched
        // rather than inventing a key the host might not read.
        return undefined
      } catch (error) {
        stderr(`dsh-proof: prompt injection failed (${errorMessage(error)})`)
        return undefined
      }
    }

    const execute = context.tool?.execute
    const before = asBefore(execute?.before)
    if (before !== undefined) register('tool.execute.before', () => before(wrappedBefore))
    const after = asAfter(execute?.after)
    if (after !== undefined) register('tool.execute.after', () => after(wrappedAfter))
    const params = context.chat?.params
    if (typeof params === 'function') {
      const registrar = params as (handler: (input: unknown, output: unknown) => unknown) => unknown
      register('chat.params', () => registrar(wrappedParams))
    }

    if (registered.length === 0) {
      stderr(NO_SURFACE_LINE)
    } else {
      stderr(`dsh-proof: OpenCode adapter active [${registered.join(', ')}] root=${env.paths.root} `
        + `requireBaseline=${env.gate.requireBaseline} evidenceStore=${env.paths.evidenceStore}`)
    }

    return {
      dispose: () => {
        for (const disposer of disposers) disposer()
      },
    }
  }
}

export default createOpencodePlugin()
