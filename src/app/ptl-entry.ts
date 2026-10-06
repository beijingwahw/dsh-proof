#!/usr/bin/env node
/**
 * Proof Transparency Log CLI — the non-MCP auditor's path (v0.18.0).
 *
 * A transparency log turns "the agent's evidence chain looked fine when I
 * checked" into a publicly checkable commitment: the latest *signed*
 * checkpoint of a workspace's evidence chain is appended to an append-only
 * merkle log, and the log operator signs a tree head (STH) over the whole
 * log after every append. From then on, anyone holding a published STH can
 * prove — without trusting the operator's future honesty — that the log was
 * never truncated or rewritten (consistency proofs), and that a given
 * checkpoint really was published at a given position (inclusion proofs).
 *
 * Three subcommands, each one line of JSON on stdout (or a clean one-line
 * error on stderr — never a stack trace):
 *
 *   dsh-proof-ptl append --log <dir>
 *       Extract the latest signed checkpoint from the current workspace's
 *       evidence chain and append it to the log at <dir>, then sign and save
 *       a fresh STH with the operator key at <logDir>/operator-key/
 *       (generated on first use).
 *   dsh-proof-ptl head --log <dir>
 *       Print the current STH, or {"empty":true}.
 *   dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key]
 *       No --bundle: self-check (recomputed merkle root === STH root, tree
 *       sizes agree, plus the STH signature when an operator key is at hand).
 *       With --bundle: audit the bundle's manifest.transparency record against
 *       the log — leaf match, inclusion, consistency (non-rewrite), head
 *       signature.
 *
 * Workspace discovery mirrors app/mcp-entry.ts exactly, through the same
 * derivation adapters/shared/paths.ts applies:
 *   DSH_PROOF_ROOT            workspace root the log publishes for (default cwd)
 *   DSH_PROOF_TRUST_DIR       trust root (default $DSH_HOME/proof)
 *   DSH_PROOF_EVIDENCE_STORE  'host' (default) or 'workspace'
 *   DSH_PROOF_EVIDENCE_DIR    workspace-mode store segment (default '.proof')
 *
 * Exit codes: 0 ok · 1 verification failure or nothing to publish · 2 usage.
 *
 * Discipline (same as src/app/*): imports only src/core/*, the shared path
 * derivation, node-ports and node: builtins — nothing from @deepseek-ai/*.
 *
 * @module dsh-proof/app/ptl-entry
 */

import * as nodePath from 'node:path'

import { deriveProofPaths } from '../adapters/shared/paths.ts'
import { walkChain } from '../core/trust.ts'
import {
  appendPtlEntry, loadPtl, ptlLeafHash, savePtlHead, sthSignedData, verifyInclusion,
  verifyConsistency, verifyTreeHead,
} from '../core/transparency.ts'
import type { PtlEntry, SignedTreeHead } from '../core/transparency.ts'
import { NodeEd25519Signer, NodeFsPort } from '../node-ports.ts'

const USAGE = [
  'usage: dsh-proof-ptl append --log <dir>',
  '       dsh-proof-ptl head --log <dir>',
  '       dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key]',
].join('\n')

const OPERATOR_KEY_DIR = 'operator-key'

interface CliArgs {
  readonly command: 'append' | 'head' | 'verify'
  readonly log?: string
  readonly bundle?: string
  readonly operatorKey: boolean
}

/**
 * Handwritten argv parsing, zero dependencies (same style as the MCP entry):
 * one subcommand, then long options. `--log`/`--bundle` take a value,
 * `--operator-key` is a boolean flag. Returns the error string for anything
 * it refuses to guess at.
 */
function parseArgs(argv: readonly string[]): { args: CliArgs } | { error: string } {
  const [command, ...rest] = argv
  if (command !== 'append' && command !== 'head' && command !== 'verify') {
    return { error: `unknown subcommand: ${JSON.stringify(command ?? '')}` }
  }
  let log: string | undefined
  let bundle: string | undefined
  let operatorKey = false
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]
    if (flag === '--log' || flag === '--bundle') {
      const value = rest[i + 1]
      if (value === undefined || value.startsWith('--')) {
        return { error: `${flag} requires a value` }
      }
      i += 1
      if (flag === '--log') log = value
      else bundle = value
    } else if (flag === '--operator-key') {
      operatorKey = true
    } else {
      return { error: `unknown option: ${JSON.stringify(flag)}` }
    }
  }
  if (log === undefined || log.length === 0) return { error: '--log <dir> is required' }
  if (command !== 'verify' && bundle !== undefined) {
    return { error: `--bundle only applies to verify` }
  }
  if (command !== 'verify' && operatorKey) {
    return { error: '--operator-key only applies to verify' }
  }
  return { args: { command, log, ...(bundle !== undefined ? { bundle } : {}), operatorKey } }
}

function envString(name: string): string | undefined {
  const value = process.env[name]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/** One clean line on stderr — the CLI's whole error vocabulary. No stacks. */
function fail(message: string): number {
  process.stderr.write(`${message}\n`)
  return 1
}

/** The workspace the log publishes for, derived exactly as mcp-entry derives it. */
function workspacePaths(): ReturnType<typeof deriveProofPaths> {
  return deriveProofPaths({
    root: envString('DSH_PROOF_ROOT'),
    trustRoot: envString('DSH_PROOF_TRUST_DIR'),
    evidenceStore: envString('DSH_PROOF_EVIDENCE_STORE'),
    evidenceDir: envString('DSH_PROOF_EVIDENCE_DIR'),
  })
}

/**
 * The log operator's key for a verify pass, or `undefined` when there is
 * nothing to check with. The check applies when the caller asked for it
 * (--operator-key) or the log directory visibly holds a key (post-append
 * logs always do) — but the key is loaded ONLY when it already exists:
 * `NodeEd25519Signer.load` GENERATES a fresh key on first use, and a verify
 * pass must never mint an identity as a side effect. A key the verifier just
 * made could never verify anyone else's head anyway; no key in hand is a
 * missing capability, never an accusation — the same refusal discipline
 * core/trust applies to anchor and checkpoint signatures.
 */
async function resolveOperatorForVerify(fs: NodeFsPort, logDir: string): Promise<NodeEd25519Signer | undefined> {
  const keyDir = nodePath.join(logDir, OPERATOR_KEY_DIR)
  if ((await fs.stat(keyDir)) === undefined) return undefined
  return NodeEd25519Signer.load(keyDir)
}

/** Verify an STH under an operator key: adjudicate exactly what the signature covers. */
async function headSignatureHolds(
  sth: SignedTreeHead,
  operator: NodeEd25519Signer,
): Promise<boolean> {
  return verifyTreeHead(sth, (data, sig) => operator.verify(data, sig))
}

// ---------------------------------------------------------------------------
// append
// ---------------------------------------------------------------------------

/**
 * Extract the workspace's latest *signed* checkpoint and publish it.
 *
 * Selection rule (identical to the engine's `latestSignedCheckpoint`, so the
 * CLI and the MCP `proof_publish` tool can never publish different
 * checkpoints): walk the evidence log (`core/trust.walkChain`) and take the
 * last checkpoint envelope carrying a non-empty `sig` and `keyId` that the
 * walk itself does not refute (`malformedCheckpoints` — a self-reported
 * count the walked records contradict is a lying checkpoint, and a lying
 * checkpoint is never worth publishing even when it is signed). Whether the
 * `prev` chain up to that checkpoint is intact is deliberately NOT
 * adjudicated here — append is a publisher, not an auditor; chain integrity
 * is what `verify`/`audit` answer, and an auditor holding this entry plus
 * the STH can demand that proof separately.
 */
async function runAppend(fs: NodeFsPort, logDir: string): Promise<number> {
  const paths = workspacePaths()
  const lines = await fs.readLines(paths.logPath)
  const walk = walkChain(lines)
  const malformed = new Set(walk.malformedCheckpoints)
  const signed = walk.checkpoints.findLast(
    cp => cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null && cp.keyId.length > 0 && !malformed.has(cp.index),
  )
  if (signed === undefined || signed.sig === null || signed.keyId === null) {
    return fail('no signed checkpoint to publish — run proof_baseline/proof_verify first（checkpoint 由引擎签名）')
  }
  // The published leaf is the checkpoint itself, re-committed under the
  // workspace identity the log indexes by: count/head/at from the signed
  // payload, keyId/sig copied verbatim so a third party can re-verify the
  // checkpoint signature against the engine's key without the workspace.
  const entry: PtlEntry = {
    v: 1,
    workspaceKey: paths.workspaceKey,
    keyId: signed.keyId,
    count: signed.payload.count,
    head: signed.payload.head,
    at: signed.payload.at,
    sig: signed.sig,
  }

  const { sequence, duplicate } = await appendPtlEntry(fs, logDir, entry)
  // Every append closes with a freshly signed tree head — publishing an
  // entry without a head over it would leave the log's newest leaf outside
  // every auditable commitment. Per core/transparency, an STH's `logId` IS
  // the operator's keyId (the public identity of whoever runs the log), and
  // the operator key at <logDir>/operator-key is minted on first use — the
  // same provider rule the engine applies.
  const { log } = await loadPtl(fs, logDir)
  const operator = await NodeEd25519Signer.load(nodePath.join(logDir, OPERATOR_KEY_DIR))
  const unsigned = {
    logId: operator.keyId,
    treeSize: log.size,
    root: log.merkleRoot(),
    at: new Date().toISOString(),
  }
  const sth: SignedTreeHead = { ...unsigned, sig: await operator.sign(sthSignedData(unsigned)) }
  await savePtlHead(fs, logDir, sth)

  process.stdout.write(`${JSON.stringify({
    sequence,
    duplicate,
    leafHash: ptlLeafHash(entry),
    treeSize: sth.treeSize,
    root: sth.root,
    logId: sth.logId,
  })}\n`)
  return 0
}

// ---------------------------------------------------------------------------
// head
// ---------------------------------------------------------------------------

async function runHead(fs: NodeFsPort, logDir: string): Promise<number> {
  const { sth } = await loadPtl(fs, logDir)
  process.stdout.write(`${JSON.stringify(sth ?? { empty: true })}\n`)
  return 0
}

// ---------------------------------------------------------------------------
// verify (self-check)
// ---------------------------------------------------------------------------

/**
 * No bundle: prove the log agrees with its own signed head. The merkle root
 * recomputed over the current entries must equal `sth.root`, and the head's
 * tree size must equal the entry count — either disagreement means the log
 * and the commitment drifted apart (rewrite, truncation, or a stale head).
 */
async function runSelfVerify(fs: NodeFsPort, logDir: string): Promise<number> {
  const { log, sth } = await loadPtl(fs, logDir)
  const rootMatch = sth !== undefined && sth.treeSize === log.size && log.merkleRoot() === sth.root

  let headSignature: boolean | undefined
  const operator = await resolveOperatorForVerify(fs, logDir)
  if (operator !== undefined && sth !== undefined) {
    headSignature = await headSignatureHolds(sth, operator)
  }

  const ok = rootMatch && headSignature !== false
  process.stdout.write(`${JSON.stringify({
    ok,
    treeSize: sth?.treeSize ?? log.size,
    checks: {
      rootMatch,
      ...(headSignature !== undefined ? { headSignature } : {}),
    },
  })}\n`)
  return ok ? 0 : 1
}

// ---------------------------------------------------------------------------
// verify (against a bundle's transparency record)
// ---------------------------------------------------------------------------

/**
 * With --bundle: the log in hand adjudicates the bundle's
 * `manifest.transparency` record, in order:
 *   ① leafMatch   — the entry at `sequence` hashes to `leafHash`;
 *   ② inclusion   — that entry sits in the tree the bundle PINS, i.e. the
 *      published head (audit paths are size-specific per RFC 6962, so a
 *      proof minted at publication size folds only against the publication
 *      head; folding it against today's head would reject every historical
 *      bundle — the exact thing this log exists to honour);
 *   ③ consistency — the published head must still be a provable prefix of
 *      the CURRENT head, chaining ②'s statement to the present. THIS is the
 *      non-rewrite guarantee: a consistency proof is a sequence of tree
 *      nodes from which the old root and the new root are both re-derivable,
 *      so an operator who truncated or edited history cannot produce one —
 *      the best a rewriter can do is replay the old head's bytes, which the
 *      newer (signed) head refutes;
 *   ④ headSignature — the current STH's own signature, when an operator key
 *      is at hand.
 * The bundle-side structural validation of the record happened when the
 * bundle was verified; here every value is read defensively anyway, because
 * the bundle is still producer-controlled input.
 */
async function runBundleVerify(fs: NodeFsPort, logDir: string, bundlePath: string): Promise<number> {
  const bundleRaw = await fs.readFile(bundlePath)
  if (bundleRaw === undefined) return fail(`cannot read bundle: ${bundlePath}`)
  let bundle: { manifest?: { transparency?: unknown } }
  try {
    bundle = JSON.parse(bundleRaw) as { manifest?: { transparency?: unknown } }
  } catch (error) {
    return fail(`bundle is not valid JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
  const record = bundle?.manifest?.transparency
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    return fail('bundle manifest carries no transparency record (was it published with dsh-proof-ptl append?)')
  }
  const t = record as Partial<{
    logId: string; sequence: number; leafHash: string
    publishedHead: Partial<SignedTreeHead>; inclusionProof: readonly string[]
  }>

  const { log, sth } = await loadPtl(fs, logDir)

  // ① the leaf the bundle claims, at the position it claims.
  const sequence = typeof t.sequence === 'number' && Number.isSafeInteger(t.sequence) ? t.sequence : -1
  const entry = sequence >= 0 && sequence < log.size ? log.entries[sequence] : undefined
  const leafMatch = entry !== undefined && typeof t.leafHash === 'string' && ptlLeafHash(entry) === t.leafHash

  // The publication head the bundle pins, narrowed once: both ② and ③
  // adjudicate against it, and a record without a usable one can prove
  // neither inclusion nor non-rewrite.
  const rawPublished = t.publishedHead
  const published = rawPublished !== null && typeof rawPublished === 'object'
    && typeof rawPublished.treeSize === 'number' && Number.isSafeInteger(rawPublished.treeSize) && rawPublished.treeSize >= 1
    && typeof rawPublished.root === 'string'
    ? { treeSize: rawPublished.treeSize, root: rawPublished.root }
    : undefined

  // ② inclusion of that leaf in the PUBLISHED head's tree — the head the
  // bundle pins, not the current one (see the doc comment above).
  const inclusion = entry !== undefined && published !== undefined && Array.isArray(t.inclusionProof)
    && verifyInclusion(entry, sequence, published.treeSize, t.inclusionProof, published.root)

  // ③ non-rewrite: publication head vs current head.
  let consistency: boolean | undefined
  if (sth !== undefined && published !== undefined) {
    if (published.treeSize === sth.treeSize && published.root === sth.root) {
      consistency = undefined // the log has not moved: nothing to reconcile
    } else if (published.treeSize > sth.treeSize) {
      consistency = false // the current log is SHORTER than what was published — a rewind
    } else {
      consistency = verifyConsistency(
        published.treeSize, published.root, sth.treeSize, sth.root,
        log.consistencyProof(published.treeSize, sth.treeSize),
      )
    }
  }

  // ④ the head's own signature.
  let headSignature: boolean | undefined
  const operator = await resolveOperatorForVerify(fs, logDir)
  if (operator !== undefined && sth !== undefined) {
    headSignature = await headSignatureHolds(sth, operator)
  }

  const ok = leafMatch && inclusion && consistency !== false && headSignature !== false
  process.stdout.write(`${JSON.stringify({
    ok,
    checks: {
      leafMatch,
      inclusion,
      ...(consistency !== undefined ? { consistency } : {}),
      ...(headSignature !== undefined ? { headSignature } : {}),
    },
    sequence,
    treeSize: sth?.treeSize ?? log.size,
  })}\n`)
  return ok ? 0 : 1
}

// ---------------------------------------------------------------------------

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2))
  if ('error' in parsed) {
    process.stderr.write(`${parsed.error}\n${USAGE}\n`)
    return 2
  }
  const { command, log, bundle, operatorKey } = parsed.args
  const fs = new NodeFsPort()
  if (log === undefined) {
    process.stderr.write(`--log <dir> is required\n${USAGE}\n`)
    return 2
  }
  // --operator-key is an explicit request for head-signature checking; the
  // same check also engages whenever the log directory holds an operator
  // key, so the flag is accepted (and validated) but needs no threading —
  // resolveOperatorForVerify decides with the key directory in hand.
  void operatorKey
  try {
    if (command === 'append') return await runAppend(fs, log)
    if (command === 'head') return await runHead(fs, log)
    if (bundle === undefined) return await runSelfVerify(fs, log)
    return await runBundleVerify(fs, log, bundle)
  } catch (error) {
    return fail(`ptl ${command} failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

main().then((code) => {
  // exitCode, never process.exit(): a forced exit can discard stdio writes
  // still sitting in the Windows pipe buffer, and this CLI's whole contract
  // is one honest line of output. With no servers or timers alive, setting
  // the code lets the process drain and exit with it.
  process.exitCode = code
}).catch((error: unknown) => {
  // A rejection here is a bug, not a verdict — still one clean line, never a stack.
  process.stderr.write(`[dsh-proof-ptl] fatal: ${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
})
