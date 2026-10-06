#!/usr/bin/env node
/**
 * Proof Transparency Log CLI — the non-MCP auditor's path (v0.22.0).
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
 *   dsh-proof-ptl append --log <dir> [--operator-key <keydir>]
 *       Extract the latest publishable checkpoint from the current
 *       workspace's evidence chain and append it to the log at <dir>, then
 *       sign and save a fresh STH with the operator key. Selection is
 *       anchor-gated (identical to the engine's `latestSignedCheckpoint`):
 *       with an anchor on record only checkpoints signed by the ANCHORED key
 *       are publishable — never a positionally-later checkpoint under some
 *       foreign keyId; without an anchor a checkpoint is publishable only
 *       when its signature actually verifies under the local engine key
 *       ($TRUST_DIR/keys). No anchor and no verifiable key is a loud
 *       refusal: publication needs a trust root.
 *   dsh-proof-ptl head --log <dir>
 *       Print the current STH, or {"empty":true}.
 *   dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key <keydir>]
 *       No --bundle: self-check (recomputed merkle root === STH root, tree
 *       sizes agree, plus the STH signature when an operator key is at hand).
 *       With --bundle: audit the bundle's manifest.transparency record against
 *       the log — leaf match, inclusion, consistency (non-rewrite), the
 *       operator's signature over the bundle-PINNED published head, the
 *       current head's signature, and the operator identity (`logId`)
 *       agreement between the pinned head and the current one.
 *
 * The operator key NEVER lives in the log directory by default (v0.22): a
 * key sitting next to the data it notarises is self-referential — whoever
 * can rewrite the log can replace the key and re-sign the rewrite.
 * Resolution order: the --operator-key <keydir> flag, then
 * $DSH_PROOF_OPERATOR_KEY_DIR, then <trustRoot>/ptl-operator-key where
 * <trustRoot> is the workspace discovery's trust root below. Existing
 * pre-0.22 logs whose key still sits at <logDir>/operator-key must pass
 * that directory explicitly.
 *
 * Workspace discovery mirrors app/mcp-entry.ts exactly, through the same
 * derivation adapters/shared/paths.ts applies:
 *   DSH_PROOF_ROOT             workspace root the log publishes for (default cwd)
 *   DSH_PROOF_TRUST_DIR        trust root (default $DSH_HOME/proof)
 *   DSH_PROOF_EVIDENCE_STORE   'host' (default) or 'workspace'
 *   DSH_PROOF_EVIDENCE_DIR     workspace-mode store segment (default '.proof')
 *   DSH_PROOF_OPERATOR_KEY_DIR operator key directory (default <trustRoot>/ptl-operator-key)
 *
 * Exit codes: 0 ok · 1 verification failure or nothing to publish · 2 usage.
 *
 * Discipline (same as src/app/*): imports only src/core/*, the shared path
 * derivation, node-ports and node: builtins — nothing from @deepseek-ai/*.
 *
 * @module dsh-proof/app/ptl-entry
 */

import { deriveProofPaths } from '../adapters/shared/paths.ts'
import { checkpointSignedData, parseAnchor, walkChain } from '../core/trust.ts'
import type { WalkedCheckpoint } from '../core/trust.ts'
import {
  appendPtlEntry, loadPtl, ptlLeafHash, savePtlHead, sthSignedData, verifyInclusion,
  verifyConsistency, verifyTreeHead,
} from '../core/transparency.ts'
import type { PtlEntry, SignedTreeHead } from '../core/transparency.ts'
import { NodeEd25519Signer, NodeFsPort } from '../node-ports.ts'

const USAGE = [
  'usage: dsh-proof-ptl append --log <dir> [--operator-key <keydir>]',
  '       dsh-proof-ptl head --log <dir>',
  '       dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key <keydir>]',
  '',
  'operator key resolution: --operator-key <keydir>, then $DSH_PROOF_OPERATOR_KEY_DIR,',
  'then <trustRoot>/ptl-operator-key (never <logDir>/operator-key by default —',
  'a key next to the data it notarises is self-referential; legacy logs must',
  'pass their <logDir>/operator-key explicitly)',
].join('\n')

interface CliArgs {
  readonly command: 'append' | 'head' | 'verify'
  readonly log?: string
  readonly bundle?: string
  readonly operatorKeyDir?: string
}

/**
 * Handwritten argv parsing, zero dependencies (same style as the MCP entry):
 * one subcommand, then long options. `--log`/`--bundle`/`--operator-key`
 * take a value. Returns the error string for anything it refuses to guess
 * at.
 */
function parseArgs(argv: readonly string[]): { args: CliArgs } | { error: string } {
  const [command, ...rest] = argv
  if (command !== 'append' && command !== 'head' && command !== 'verify') {
    return { error: `unknown subcommand: ${JSON.stringify(command ?? '')}` }
  }
  let log: string | undefined
  let bundle: string | undefined
  let operatorKeyDir: string | undefined
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]
    if (flag === '--log' || flag === '--bundle' || flag === '--operator-key') {
      const value = rest[i + 1]
      if (value === undefined || value.startsWith('--')) {
        return { error: `${flag} requires a value` }
      }
      i += 1
      if (flag === '--log') log = value
      else if (flag === '--bundle') bundle = value
      else operatorKeyDir = value
    } else {
      return { error: `unknown option: ${JSON.stringify(flag)}` }
    }
  }
  if (log === undefined || log.length === 0) return { error: '--log <dir> is required' }
  if (command !== 'verify' && bundle !== undefined) {
    return { error: `--bundle only applies to verify` }
  }
  if (command === 'head' && operatorKeyDir !== undefined) {
    return { error: `--operator-key only applies to append and verify` }
  }
  return {
    args: {
      command,
      log,
      ...(bundle !== undefined ? { bundle } : {}),
      ...(operatorKeyDir !== undefined ? { operatorKeyDir } : {}),
    },
  }
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
 * Where the operator key lives: the explicit `--operator-key` value, then
 * `$DSH_PROOF_OPERATOR_KEY_DIR`, then `<trustRoot>/ptl-operator-key`.
 * Never `<logDir>/operator-key` by default (v0.22, H-07c): that placement
 * is self-referential — whoever can rewrite the log can replace the key
 * and re-sign the rewrite, so every default check the CLI makes would be
 * vouched for by the very party being checked. The log directory is
 * DELIBERATELY not an input to the default.
 */
function resolveOperatorKeyDir(explicit: string | undefined): string {
  if (explicit !== undefined && explicit.length > 0) return explicit
  const fromEnv = envString('DSH_PROOF_OPERATOR_KEY_DIR')
  if (fromEnv !== undefined) return fromEnv
  return `${workspacePaths().trustRoot}/ptl-operator-key`
}

/**
 * The log operator's key for a verify pass, or `undefined` when there is
 * nothing to check with. The key is loaded ONLY when its directory already
 * exists: `NodeEd25519Signer.load` GENERATES a fresh key on first use, and a
 * verify pass must never mint an identity as a side effect. A key the
 * verifier just made could never verify anyone else's head anyway; no key
 * in hand is a missing capability, never an accusation — the same refusal
 * discipline core/trust applies to anchor and checkpoint signatures.
 */
async function resolveOperatorForVerify(fs: NodeFsPort, keyDir: string): Promise<NodeEd25519Signer | undefined> {
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
 * Extract the workspace's latest publishable checkpoint and publish it.
 *
 * Selection rule (v0.22, H-06 — now genuinely identical to the engine's
 * `latestSignedCheckpoint`, where the doc used to claim it): walk the
 * evidence log (`core/trust.walkChain`), keep well-formed checkpoints (one
 * whose self-reported `count` the walk itself refutes is a lying checkpoint,
 * and a lying checkpoint is never worth publishing even when it is signed)
 * that carry a non-empty `sig` and `keyId`, then:
 *
 * - With an out-of-band anchor on record naming a key: only the LAST
 *   checkpoint signed by that very key is publishable — never a
 *   positionally-later checkpoint under some foreign keyId an attacker
 *   appended. The anchor is the trust root of the publication; nothing on
 *   the chain is entitled to stand in for it.
 * - Without a usable anchor: a checkpoint is publishable only when this
 *   host holds the engine key (`<trustRoot>/keys`) that can VERIFY its
 *   signature — and the verification must pass.
 * - Neither: loud refusal. A publication without any trust root would
 *   notarise whoever last wrote to the workspace log, which is exactly the
 *   laundering the PTL exists to prevent.
 *
 * Whenever the local engine key matches the selected checkpoint's keyId,
 * the checkpoint signature itself is verified before the entry enters the
 * tree — a checkpoint whose `sig` does not verify under the key it names is
 * refused, not published.
 */
async function runAppend(fs: NodeFsPort, logDir: string, operatorKeyDir: string): Promise<number> {
  const paths = workspacePaths()
  const lines = await fs.readLines(paths.logPath)
  const walk = walkChain(lines)
  const malformed = new Set(walk.malformedCheckpoints)
  const signed = walk.checkpoints.filter(
    cp => cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null && cp.keyId.length > 0 && !malformed.has(cp.index),
  )
  if (signed.length === 0) {
    return fail('no signed checkpoint to publish — run proof_baseline/proof_verify first（checkpoint 由引擎签名）')
  }
  const anchorRaw = await fs.readFile(paths.anchorPath)
  const anchor = parseAnchor(anchorRaw)
  // The local engine key, loaded ONLY when it already exists: a verify-side
  // selection must never mint a key. Missing key is a missing capability.
  const engineKeyDir = `${paths.trustRoot}/keys`
  const engineSigner = (await fs.stat(engineKeyDir)) === undefined ? undefined : await NodeEd25519Signer.load(engineKeyDir)

  let chosen: WalkedCheckpoint | undefined
  if (anchor !== undefined && anchor.keyId !== '') {
    chosen = signed.findLast(cp => cp.keyId === anchor.keyId)
    if (chosen === undefined) {
      return fail(
        `no checkpoint signed by the anchored key ${JSON.stringify(anchor.keyId)} on this chain`
        + ' — the anchor is the publication trust root, and no later checkpoint under another key may stand in for it'
        + ' (a foreign-keyId checkpoint appended to the workspace log is exactly the forgery this rule refuses)',
      )
    }
  } else if (engineSigner !== undefined) {
    chosen = signed.findLast(cp => cp.keyId === engineSigner.keyId)
    if (chosen === undefined) {
      return fail(
        `no anchor on record and no checkpoint signed by the local engine key (${engineSigner.keyId})`
        + ' — without an anchor, publication is only possible for checkpoints this host can verify',
      )
    }
  } else {
    return fail(
      'refusing to publish: no trust root — the workspace has no anchor on record and no engine key'
      + ` under ${engineKeyDir} to verify checkpoint signatures with. Establish a trust root first:`
      + ' checkpoint under a host-held key with an anchor path configured (proof_baseline does this),'
      + ' or point DSH_PROOF_TRUST_DIR to the trust root holding the workspace key',
    )
  }

  // Verify the checkpoint's own signature whenever the named key is at
  // hand: the log is a notary, but the notary must not notarise a forgery it
  // was perfectly able to catch.
  if (engineSigner !== undefined && chosen.keyId === engineSigner.keyId && chosen.sig !== null) {
    let holds: boolean
    try {
      holds = await engineSigner.verify(checkpointSignedData(chosen.payload), chosen.sig)
    } catch {
      holds = false
    }
    if (!holds) {
      return fail(
        `checkpoint signature does not verify under the local engine key (${chosen.keyId})`
        + ' — refusing to publish a forged checkpoint',
      )
    }
  }

  // The published leaf is the checkpoint itself, re-committed under the
  // workspace identity the log indexes by: count/head/at from the signed
  // payload, keyId/sig copied verbatim so a third party can re-verify the
  // checkpoint signature against the engine's key without the workspace.
  const entry: PtlEntry = {
    v: 1,
    workspaceKey: paths.workspaceKey,
    keyId: chosen.keyId as string,
    count: chosen.payload.count,
    head: chosen.payload.head,
    at: chosen.payload.at,
    sig: chosen.sig as string,
  }

  const { sequence, duplicate } = await appendPtlEntry(fs, logDir, entry)
  // Every append closes with a freshly signed tree head — publishing an
  // entry without a head over it would leave the log's newest leaf outside
  // every auditable commitment. Per core/transparency, an STH's `logId` IS
  // the operator's keyId (the public identity of whoever runs the log), and
  // the operator key lives OUTSIDE the log directory (see
  // resolveOperatorKeyDir) so no rewrite of the log can rotate the very
  // identity that vouches for it.
  const { log } = await loadPtl(fs, logDir)
  const operator = await NodeEd25519Signer.load(operatorKeyDir)
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
 * A log with entries but no head on record says so explicitly: "currently
 * promises nothing" is a state worth naming, not a silent pass.
 */
async function runSelfVerify(fs: NodeFsPort, logDir: string, operatorKeyDir: string): Promise<number> {
  const { log, sth, headOvercommits } = await loadPtl(fs, logDir)
  const notes: string[] = []
  if (headOvercommits && sth !== undefined) {
    notes.push(`sth.json promises ${sth.treeSize} entries but the log holds ${log.size} — head and log are disconnected`)
  } else if (sth === undefined && log.size > 0) {
    notes.push(`no signed head on record (sth.json missing or unreadable) while the log holds ${log.size} entries`)
  }
  const rootMatch = sth !== undefined && sth.treeSize === log.size && log.merkleRoot() === sth.root

  let headSignature: boolean | undefined
  const operator = await resolveOperatorForVerify(fs, operatorKeyDir)
  if (operator !== undefined && sth !== undefined) {
    headSignature = await headSignatureHolds(sth, operator)
  } else if (sth !== undefined) {
    notes.push('operator key absent — head signature not verified')
  }

  const ok = rootMatch && headSignature !== false
  process.stdout.write(`${JSON.stringify({
    ok,
    treeSize: sth?.treeSize ?? log.size,
    checks: {
      rootMatch,
      ...(headSignature !== undefined ? { headSignature } : {}),
    },
    ...(notes.length > 0 ? { notes } : {}),
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
 *      newer (signed) head refutes. A bundle that claims publication while
 *      the log holds NO current head fails here: "published then, promised
 *      nothing now" is not a state an honest log can be in. A current head
 *      that promises more entries than the file holds fails here too —
 *      adjudicated as false, never as a producer-side RangeError.
 *   ④ logIdMatch  — the operator identity the bundle pinned and the
 *      identity on the current head must agree; a silent operator flip
 *      mid-log would let a rewritten history wear a fresh signature.
 *   ⑤ publishedHeadSig — the bundle's OWN claim of publication is a signed
 *      statement ("this operator signed this head at this time"), and that
 *      signature is verified with the operator key. Without the key the
 *      check is reported not-checked and FAILS the verification: a
 *      publication proof nobody verified is exactly the "uncertain = fail"
 *      case, and passing it silently would be the old hole with new paint.
 *   ⑥ headSignature — the current STH's own signature, when an operator key
 *      is at hand.
 * The bundle-side structural validation of the record happened when the
 * bundle was verified; here every value is read defensively anyway, because
 * the bundle is still producer-controlled input.
 */
async function runBundleVerify(
  fs: NodeFsPort, logDir: string, bundlePath: string, operatorKeyDir: string,
): Promise<number> {
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

  const { log, sth, headOvercommits } = await loadPtl(fs, logDir)
  const notes: string[] = []

  // ① the leaf the bundle claims, at the position it claims.
  const sequence = typeof t.sequence === 'number' && Number.isSafeInteger(t.sequence) ? t.sequence : -1
  const entry = sequence >= 0 && sequence < log.size ? log.entries[sequence] : undefined
  const leafMatch = entry !== undefined && typeof t.leafHash === 'string' && ptlLeafHash(entry) === t.leafHash

  // The publication head the bundle pins, narrowed once: ②③④ adjudicate
  // against it, and a record without a usable one can prove neither
  // inclusion nor non-rewrite.
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
  if (published !== undefined) {
    if (sth === undefined) {
      // (H-07b) The bundle claims a publication, and the log currently
      // promises nothing: there is no head to reconcile the claim against,
      // and that absence is a failure, not a pass.
      consistency = false
      notes.push('no current signed head on record (sth.json missing or unreadable) — a claimed publication cannot be reconciled with the present')
    } else if (published.treeSize === sth.treeSize && published.root === sth.root) {
      consistency = undefined // the log has not moved: nothing to reconcile
    } else if (published.treeSize > sth.treeSize) {
      consistency = false // the current log is SHORTER than what was published — a rewind
      notes.push(`the current head (size ${sth.treeSize}) is shorter than the published one (size ${published.treeSize}) — the log was rewound after publication`)
    } else if (headOvercommits) {
      // (M-63) The current head promises more entries than the file holds:
      // adjudicated, never delegated to a producer-side RangeError.
      consistency = false
      notes.push(`sth.json promises ${sth.treeSize} entries but the log holds ${log.size} — head and log are disconnected`)
    } else {
      consistency = verifyConsistency(
        published.treeSize, published.root, sth.treeSize, sth.root,
        log.consistencyProof(published.treeSize, sth.treeSize),
      )
    }
  }

  // ④ operator identity agreement between the pinned head and the current one.
  let logIdMatch: boolean | undefined
  if (published !== undefined && sth !== undefined
    && typeof rawPublished?.logId === 'string' && typeof sth.logId === 'string') {
    logIdMatch = rawPublished.logId === sth.logId
    if (!logIdMatch) {
      notes.push(`the pinned head names operator ${JSON.stringify(rawPublished.logId)} but the current head names ${JSON.stringify(sth.logId)} — the log changed hands or was re-keyed`)
    }
  }

  // ⑤ the bundle's own publication claim: the pinned head's signature.
  const operator = await resolveOperatorForVerify(fs, operatorKeyDir)
  let publishedHeadSig: boolean | 'not-checked (operator key absent)'
  if (operator === undefined) {
    publishedHeadSig = 'not-checked (operator key absent)'
    notes.push('operator key absent — the publication signature was NOT verified')
  } else if (
    published === undefined
    || typeof rawPublished?.logId !== 'string' || rawPublished.logId.length === 0
    || typeof rawPublished?.at !== 'string' || rawPublished.at.length === 0
    || typeof rawPublished?.sig !== 'string' || rawPublished.sig.length === 0
  ) {
    publishedHeadSig = false
    notes.push('the pinned published head is not a complete signed tree head — its signature cannot be adjudicated')
  } else {
    publishedHeadSig = await headSignatureHolds(rawPublished as SignedTreeHead, operator)
  }

  // ⑥ the current head's own signature.
  let headSignature: boolean | undefined
  if (operator !== undefined && sth !== undefined) {
    headSignature = await headSignatureHolds(sth, operator)
  }

  const ok = leafMatch && inclusion && consistency !== false
    && (logIdMatch === undefined || logIdMatch)
    && headSignature !== false
    && publishedHeadSig === true
  process.stdout.write(`${JSON.stringify({
    ok,
    checks: {
      leafMatch,
      inclusion,
      ...(consistency !== undefined ? { consistency } : {}),
      ...(logIdMatch !== undefined ? { logIdMatch } : {}),
      publishedHeadSig,
      ...(headSignature !== undefined ? { headSignature } : {}),
    },
    sequence,
    treeSize: sth?.treeSize ?? log.size,
    ...(notes.length > 0 ? { notes } : {}),
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
  const { command, log, bundle, operatorKeyDir } = parsed.args
  const fs = new NodeFsPort()
  if (log === undefined) {
    process.stderr.write(`--log <dir> is required\n${USAGE}\n`)
    return 2
  }
  // The operator key directory is resolved once and threaded everywhere a
  // key is needed: append signs with it, verify adjudicates with it, and
  // neither falls back to <logDir>/operator-key unless the caller passed
  // that directory explicitly (see resolveOperatorKeyDir).
  const keyDir = resolveOperatorKeyDir(operatorKeyDir)
  try {
    if (command === 'append') return await runAppend(fs, log, keyDir)
    if (command === 'head') return await runHead(fs, log)
    if (bundle === undefined) return await runSelfVerify(fs, log, keyDir)
    return await runBundleVerify(fs, log, bundle, keyDir)
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
