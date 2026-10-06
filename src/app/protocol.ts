/**
 * Agent Proof Protocol (APP/1.3) — the protocol constants layer.
 *
 * Everything a producer emits and a consumer interprets is named here: the
 * wire vocabularies (verdicts, grades, check statuses, chain modes, claim
 * kinds), the media types, the bundle manifest shape, and the implementation
 * fingerprint that binds them together. The point of the module is that a
 * verifier can answer "am I reading the same dialect the producer spoke?"
 * *before* it interprets a single record — by digesting the vocabulary and
 * the three rule strings and comparing the result to the `appFingerprint`
 * stamped in every bundle manifest.
 *
 * Discipline (same as `src/core/`): this module imports nothing from
 * `@deepseek-ai/*`. The protocol layer is framework-free by construction —
 * only `src/core/*` and `node:` builtins — so the standard can be implemented
 * by any host, not only by this plugin's harness.
 *
 * @module dsh-proof/app/protocol
 */

import { canonicalJson, sha256 } from '../core/hash.ts'

/** The standard's name, as it identifies itself on the wire. */
export const PROTOCOL_NAME = 'agent-proof-protocol' as const

/**
 * The version of the vocabulary and rules this module speaks.
 *
 * v0.18 (PROTOCOL.md §6): APP/1.0 → APP/1.1 — the honest version bump for the
 * transparency-log tool-surface expansion (`proof_publish` / `proof_log_verify`
 * joining the MCP contract, the PTL/STH artifacts they speak for). The five
 * vocabularies and the three rule strings are unchanged; what changed is WHAT
 * THE TOOLS CAN SAY, which is exactly the kind of dialect drift a consumer
 * must be able to refuse. Because `appFingerprint` digests `PROTOCOL_VERSION`
 * as material, the bump moves the fingerprint automatically — every APP/1.1
 * manifest self-identifies as mutually unintelligible with every APP/1.0 one,
 * and an APP/1.0 verifier refuses the new dialect instead of guessing at it.
 * Downgrading this constant back is a wire-compatibility break, not a cosmetic
 * edit: both directions are caught by the fingerprint, on purpose.
 *
 * v0.19: APP/1.1 → APP/1.2 — the second tool-surface expansion (7 → 10): the
 * responsibility-DAG vocabulary joins the MCP contract (`proof_delegate`,
 * `proof_delegate_submit`, `proof_task` — delegation obligations, child bundle
 * submissions, composed task verdicts). Same principle as the first bump: the
 * addressing, chaining and bundle formats are byte-for-byte unchanged, but a
 * consumer that never agreed to speak about task graphs must be able to refuse
 * a dialect that does — and because the version is fingerprint material, the
 * refusal is automatic: every APP/1.2 manifest is unintelligible to every
 * APP/1.1 verifier, in both directions, by construction.
 *
 * v0.20: APP/1.2 → APP/1.3 — the third tool-surface expansion (10 → 11): the
 * training-data exhaust valve (`proof_training_export` — the deployer's
 * labeled agent-behavior dataset distilled off the chain, anchor and all).
 * The vocabularies, the content addressing, the chain/checkpoint formats, the
 * bundle format and the responsibility DAG are all byte-for-byte unchanged;
 * what grew is WHAT THE TOOLS CAN SAY again. Same honest mechanics as the two
 * prior bumps: the version is fingerprint material, so every APP/1.3 manifest
 * is unintelligible to every APP/1.2 verifier — and to every earlier one — in
 * both directions, by construction. Downgrading this constant back is a
 * wire-compatibility break, not a cosmetic edit.
 */
export const PROTOCOL_VERSION = 'APP/1.3' as const

/** Media type of a single proof document (a `ProofReport`-shaped value). */
export const PROOF_MEDIA_TYPE = 'application/vnd.app.proof+json' as const

/** Media type of a proof bundle (manifest + files, see §5 of PROTOCOL.md). */
export const BUNDLE_MEDIA_TYPE = 'application/vnd.app.proof-bundle+json' as const

/**
 * The verdict lattice: every value `verdictOf` can produce. A verdict is a
 * *baseline differential* — it names the direction of the comparison between
 * the baseline record and the current record for one check, never an absolute
 * statement about the check. Credit (`still-passing`, `fixed`, a decisively
 * run `new-check`), blame (`regression`, `still-failing`, `new-failure`), or
 * neither (`indeterminate`, `not-run`, a `new-check` that never ran).
 * Unknown never borrows certainty from either side.
 */
export const VERDICT_VALUES = [
  'still-passing',
  'still-failing',
  'regression',
  'fixed',
  'new-failure',
  'new-check',
  'not-run',
  'indeterminate',
] as const

/**
 * The grade scale: what a whole verification run concluded. Deliberately
 * pessimistic — `proven` means a baseline existed, everything the change set
 * touched re-ran to a decisive green outcome (or the posterior crossed the
 * certify target), and nothing regressed. Anything less is a lesser grade;
 * the plugin never co-signs an upgrade the evidence did not pay for.
 */
export const GRADE_VALUES = ['proven', 'regressed', 'stale', 'unproven', 'no-baseline'] as const

/**
 * The three chain modes an audit can report: `legacy` (v1 envelopes, no
 * `prev` linkage), `unsigned` (v2 hash-chained, no signed checkpoints) and
 * `signed` (v2 chained with at least one signature-bearing checkpoint).
 */
export const CHAIN_MODES = ['legacy', 'unsigned', 'signed'] as const

/**
 * The typed claim kinds. A claim is not free text: its kind binds it to a
 * specific set of evidence obligations (`src/core/contract.ts`), all of which
 * sit on the shared `zero-regressions` floor.
 */
export const CLAIM_KINDS = [
  'behavior-preserving',
  'behavior-adding',
  'perf-budget',
  'docs-only',
  'llm-jury',
] as const

/**
 * The statuses one run of one check can end in. Only `pass` and `fail` are
 * *decisive* — they settle the check's question. `error`, `timeout`,
 * `aborted` and `skipped` all mean "ran (or was stopped) without producing a
 * conclusion", and the verdict lattice treats them identically: unknown.
 */
export const CHECK_STATUSES = ['pass', 'fail', 'error', 'timeout', 'aborted', 'skipped'] as const

/**
 * The header of a proof bundle: what the bundle is, who minted it, and the
 * digest of every file it carries. The producer fills `files` in as it packs;
 * `protocolHeader` returns the empty skeleton.
 */
export interface BundleManifest {
  /** The protocol dialect, always `APP/1.3` for this module. */
  protocol: typeof PROTOCOL_VERSION
  /** The producing implementation's vocabulary fingerprint (`appFingerprint()`). */
  appFingerprint: string
  /** Stable identity of the workspace this bundle's log belongs to. */
  workspaceKey: string
  /** ISO timestamp of bundle creation. */
  createdAt: string
  /** One entry per bundled file: its path, content digest and byte length. */
  files: { path: string; sha256: string; bytes: number }[]
}

/**
 * The implementation fingerprint: `sha256(canonicalJson(...))` over the five
 * vocabularies plus one string per load-bearing rule (addressing, chaining,
 * signature). Deterministic by construction — same vocabulary, same rules,
 * same digest, on any machine — and sensitive to any change to either.
 *
 * Conformance (PROTOCOL.md §8): an implementation that changes a vocabulary
 * value or a rule string MUST produce a different fingerprint; a consumer
 * that sees a fingerprint it cannot reproduce MUST refuse to interpret the
 * payload rather than guess at the dialect.
 */
export function appFingerprint(): string {
  return sha256(canonicalJson({
    name: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    verdict: VERDICT_VALUES,
    grade: GRADE_VALUES,
    chainModes: CHAIN_MODES,
    claimKinds: CLAIM_KINDS,
    checkStatuses: CHECK_STATUSES,
    addressing: 'sha256(canonicalJson(v))',
    chain: 'prev=sha256(prevLine)',
    signature: 'ed25519(canonicalJson(checkpointPayload))',
  }))
}

/**
 * The manifest skeleton every bundle starts from: protocol version,
 * implementation fingerprint, workspace identity, timestamp, and an empty
 * `files` list for the packer to fill. A fresh object each call — mutating
 * one manifest's `files` can never leak into the next.
 */
export function protocolHeader(workspaceKey: string, createdAt: string): BundleManifest {
  return {
    protocol: PROTOCOL_VERSION,
    appFingerprint: appFingerprint(),
    workspaceKey,
    createdAt,
    files: [],
  }
}
