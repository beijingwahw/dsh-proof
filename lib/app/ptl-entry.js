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
 *       anchor-gated AND signature-verified (v0.23, X-H-11): with an anchor
 *       on record only checkpoints signed by the ANCHORED key are
 *       candidates, without one only checkpoints under the local engine
 *       key ($TRUST_DIR/keys) — and whichever branch runs, the chosen
 *       checkpoint's signature must actually VERIFY under key material
 *       this host holds. A keyId string match alone proves nothing (a
 *       forged checkpoint can claim any keyId it likes), and a candidate
 *       key with no local key material is a loud refusal naming what to
 *       provide — never a best-effort publish of unverifiable bytes. The
 *       operator key is resolved BEFORE the log is touched, so a key
 *       problem cannot leave a published-but-headless entry behind.
 *   dsh-proof-ptl head --log <dir>
 *       Print the current STH, or {"empty":true}.
 *   dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key <keydir>]
 *       No --bundle: self-check (recomputed merkle root === STH root, tree
 *       sizes agree, the STH signature adjudicated — and a head that cannot
 *       be adjudicated, because no operator key is at hand, FAILS the check:
 *       uncertain = fail, same as the bundle face; malformed lines in the
 *       entries file are counted, surfaced and fail the check too).
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
import { deriveProofPaths } from "../adapters/shared/paths.js";
import { checkpointSignedData, parseAnchorEx, walkChain } from "../core/trust.js";
import { appendPtlEntry, loadPtl, preflightPtlHead, ptlLeafHash, savePtlHead, selectPublishable, sthSignedData, verifyInclusion, verifyConsistency, verifyTreeHead, } from "../core/transparency.js";
import { NodeEd25519Signer, NodeFsPort } from "../node-ports.js";
const USAGE = [
    'usage: dsh-proof-ptl append --log <dir> [--operator-key <keydir>]',
    '       dsh-proof-ptl head --log <dir>',
    '       dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key <keydir>]',
    '',
    'operator key resolution: --operator-key <keydir>, then $DSH_PROOF_OPERATOR_KEY_DIR,',
    'then <trustRoot>/ptl-operator-key (never <logDir>/operator-key by default —',
    'a key next to the data it notarises is self-referential; legacy logs must',
    'pass their <logDir>/operator-key explicitly)',
].join('\n');
/**
 * Handwritten argv parsing, zero dependencies (same style as the MCP entry):
 * one subcommand, then long options. `--log`/`--bundle`/`--operator-key`
 * take a value. Returns the error string for anything it refuses to guess
 * at.
 */
function parseArgs(argv) {
    const [command, ...rest] = argv;
    if (command !== 'append' && command !== 'head' && command !== 'verify') {
        return { error: `unknown subcommand: ${JSON.stringify(command ?? '')}` };
    }
    let log;
    let bundle;
    let operatorKeyDir;
    const seen = new Set();
    for (let i = 0; i < rest.length; i++) {
        const flag = rest[i];
        if (flag === '--log' || flag === '--bundle' || flag === '--operator-key') {
            const value = rest[i + 1];
            if (value === undefined || value.startsWith('--')) {
                return { error: `${flag} requires a value` };
            }
            // V4-L12 (v0.24): a repeated flag is a usage error, not a silent
            // last-wins. Two --log values used to leave the FIRST log directory
            // quietly unread and the second one published to — a typo'd wrapper
            // script pointed the publish wherever the duplicate named, and no
            // output ever said so. Loud beats forgiving on a command whose whole
            // job is to commit public state.
            if (seen.has(flag)) {
                return { error: `duplicate flag: ${flag} given more than once — pass each flag once (repeats used to silently keep only the LAST value)` };
            }
            seen.add(flag);
            i += 1;
            if (flag === '--log')
                log = value;
            else if (flag === '--bundle')
                bundle = value;
            else
                operatorKeyDir = value;
        }
        else {
            return { error: `unknown option: ${JSON.stringify(flag)}` };
        }
    }
    if (log === undefined || log.length === 0)
        return { error: '--log <dir> is required' };
    if (command !== 'verify' && bundle !== undefined) {
        return { error: `--bundle only applies to verify` };
    }
    if (command === 'head' && operatorKeyDir !== undefined) {
        return { error: `--operator-key only applies to append and verify` };
    }
    return {
        args: {
            command,
            log,
            ...(bundle !== undefined ? { bundle } : {}),
            ...(operatorKeyDir !== undefined ? { operatorKeyDir } : {}),
        },
    };
}
function envString(name) {
    const value = process.env[name];
    return typeof value === 'string' && value.length > 0 ? value : undefined;
}
/** One clean line on stderr — the CLI's whole error vocabulary. No stacks. */
function fail(message) {
    process.stderr.write(`${message}\n`);
    return 1;
}
/** The workspace the log publishes for, derived exactly as mcp-entry derives it. */
function workspacePaths() {
    return deriveProofPaths({
        root: envString('DSH_PROOF_ROOT'),
        trustRoot: envString('DSH_PROOF_TRUST_DIR'),
        evidenceStore: envString('DSH_PROOF_EVIDENCE_STORE'),
        evidenceDir: envString('DSH_PROOF_EVIDENCE_DIR'),
    });
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
function resolveOperatorKeyDir(explicit) {
    if (explicit !== undefined && explicit.length > 0)
        return explicit;
    const fromEnv = envString('DSH_PROOF_OPERATOR_KEY_DIR');
    if (fromEnv !== undefined)
        return fromEnv;
    return `${workspacePaths().trustRoot}/ptl-operator-key`;
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
async function resolveOperatorForVerify(fs, keyDir) {
    if ((await fs.stat(keyDir)) === undefined)
        return undefined;
    return NodeEd25519Signer.load(keyDir);
}
/** Verify an STH under an operator key: adjudicate exactly what the signature covers. */
async function headSignatureHolds(sth, operator) {
    return verifyTreeHead(sth, (data, sig) => operator.verify(data, sig));
}
// ---------------------------------------------------------------------------
// append
// ---------------------------------------------------------------------------
/**
 * Extract the workspace's latest publishable checkpoint and publish it.
 *
 * Selection rule (v0.23, X-H-11 — one uniform predicate: the chosen
 * checkpoint must VERIFY): walk the evidence log (`core/trust.walkChain`),
 * keep well-formed checkpoints (one whose self-reported `count` the walk
 * itself refutes is a lying checkpoint, and a lying checkpoint is never
 * worth publishing even when it is signed) that carry a non-empty `sig` and
 * `keyId`, exclude every checkpoint whose self-declared `head` the walk
 * contradicts at its physical position (`headLiared`, v0.24 Y-H-01 — the
 * publish predicate is verified AND honestly positioned, the rule
 * core/evidence documents and no face implemented until now), then:
 *
 * - With an out-of-band anchor on record naming a key: the candidates are
 *   the checkpoints signed by that very key — never a positionally-later
 *   checkpoint under some foreign keyId an attacker appended. The anchor is
 *   the trust root of the publication; nothing on the chain is entitled to
 *   stand in for it. An anchor document that cannot be parsed, or one in a
 *   state no honest writer produces (empty keyId, stripped signature,
 *   impossible count — H-09's disarm family), is a LOUD refusal, never a
 *   silent fall-through to the no-anchor branch (v0.23, W9-M4): a damaged
 *   anchor is tampering until proven otherwise.
 * - Without a usable anchor: the candidates are the checkpoints under the
 *   local engine key (`<trustRoot>/keys`).
 * - In EITHER branch the chosen candidate's signature must verify under key
 *   material this host actually holds. The candidates are scanned newest
 *   first and the first VERIFIABLE one wins, so one appended
 *   garbage-signature twin at the tail (a positional-last veto) cannot
 *   brick publication while an earlier verifiable checkpoint exists
 *   (v0.23, W9-M5); when none verifies, the refusal lists every rejected
 *   candidate. An anchored key with no local key material is a loud
 *   refusal naming exactly what to provide — publishing bytes nobody can
 *   verify is the notarising of forgeries.
 *
 * Order of operations (v0.23, W9-M6 + v0.24 V4-M5): every read-side refusal
 * happens first, then the operator key is loaded, then the STORED head is
 * preflighted (rotation/unreadable/unparseable refusals fire before the log
 * is touched — V4-M5), and only then is the log mutated. A key-directory
 * typo, a locked key, or a log whose stored head this operator cannot
 * honestly extend used to leave an appended entry with no head over it — the
 * half-published state the engine face promises never to produce; now the
 * CLI cannot produce it either. And the leaf's workspace identity must agree with the identity the CHECKPOINT SIGNATURE
 * covers (`payload.workspaceKey`, v0.23 W9-M5): a chain copied into a
 * foreign workspace is refused instead of laundered into the log under the
 * new workspace's key.
 */
async function runAppend(fs, logDir, operatorKeyDir) {
    const paths = workspacePaths();
    const lines = await fs.readLines(paths.logPath);
    const walk = walkChain(lines);
    const malformed = new Set(walk.malformedCheckpoints);
    const signed = walk.checkpoints.filter(cp => cp.sig !== null && cp.sig.length > 0 && cp.keyId !== null && cp.keyId.length > 0 && !malformed.has(cp.index));
    if (signed.length === 0) {
        return fail('no signed checkpoint to publish — run proof_baseline/proof_verify first（checkpoint 由引擎签名）');
    }
    // Y-H-01 (v0.24): the publish predicate is verified AND !headLiared. A
    // checkpoint whose self-declared `head` the walk contradicts at its
    // physical position is a POSITION forgery even when its signature is
    // genuine — a real signature replayed onto, or transplanted to, a chain
    // position it was never computed for (the walk's `expectedHead` is
    // derived, not self-declared, so this is the one lie the signer's own key
    // cannot cover). Such candidates never enter the selection pool: before
    // this filter, a transplanted tail wearing a genuinely-verified signature
    // won the newest-first scan and was notarised into the public log.
    const honest = signed.filter(cp => !cp.headLiared);
    if (honest.length === 0) {
        return fail('refusing to publish: every signed checkpoint on this chain swears a chain head its own position contradicts'
            + ` (head-liars at log lines ${signed.filter(cp => cp.headLiared).map(cp => cp.index).join(', ')})`
            + ' — a genuine signature over a lying position is a forgery of position, not a publishable checkpoint;'
            + ' re-establish the baseline so an honestly-positioned checkpoint exists');
    }
    // W9-M4 (v0.23): the anchor is adjudicated through parseAnchorEx — a file
    // that exists but cannot be consulted (unparseable) or that sits in a
    // state no honest writer produces (invalid/disarmed) is a refusal, not
    // "as good as no anchor": silently switching selection semantics on a
    // damaged trust root is exactly the disarm the anchor exists to prevent.
    // (A read that fails on a file that exists is likewise refused — W9-M10.)
    const anchorRaw = await fs.readFile(paths.anchorPath);
    if (anchorRaw === undefined && (await fs.stat(paths.anchorPath)) !== undefined) {
        return fail(`cannot read the anchor file ${paths.anchorPath} (the file exists but the read failed)`
            + ' — refusing to publish against an unreadable trust root; retry, or restore the anchor from a known-good copy');
    }
    const anchorOutcome = parseAnchorEx(anchorRaw);
    if (anchorOutcome?.problem !== undefined) {
        return fail(anchorOutcome.problem === 'unparseable'
            ? `the anchor on record is not a parseable anchor document (${paths.anchorPath})`
                + ' — publication is refused instead of silently proceeding as if no anchor existed (the out-of-band defence cannot be consulted; restore or repair the anchor file first)'
            : `the anchor on record is DISARMED (${paths.anchorPath}: empty keyId, a stripped signature, or an impossible count — a shape no honest writer produces)`
                + ' — publication is refused instead of silently proceeding as if no anchor existed (a disarmed anchor is tampering until proven otherwise; restore it from a known-good copy)');
    }
    const anchor = anchorOutcome?.anchor;
    // The local engine key, loaded ONLY when it already exists: a verify-side
    // selection must never mint a key. Missing key is a missing capability.
    const engineKeyDir = `${paths.trustRoot}/keys`;
    const engineSigner = (await fs.stat(engineKeyDir)) === undefined ? undefined : await NodeEd25519Signer.load(engineKeyDir);
    // -- candidate set + the key material that will verify the choice --------
    let candidates;
    let verifier;
    if (anchor !== undefined) {
        candidates = honest.filter(cp => cp.keyId === anchor.keyId);
        if (candidates.length === 0) {
            return fail(`no checkpoint signed by the anchored key ${JSON.stringify(anchor.keyId)} on this chain`
                + ' — the anchor is the publication trust root, and no later checkpoint under another key may stand in for it'
                + ' (a foreign-keyId checkpoint appended to the workspace log is exactly the forgery this rule refuses)');
        }
        if (engineSigner !== undefined && engineSigner.keyId === anchor.keyId) {
            verifier = engineSigner;
        }
        if (verifier === undefined) {
            // X-H-11 (v0.23): the anchor names a key this host holds no material
            // for. A keyId string match proves nothing — the checkpoints could all
            // be forgeries claiming the anchored identity — so publication under
            // an unverifiable anchor is refused, naming the remedy.
            return fail(`refusing to publish: the anchor names key ${JSON.stringify(anchor.keyId)} but this host holds no key material that can verify it`
                + ` (no matching key under ${engineKeyDir}) — a checkpoint whose signature cannot be verified is not publishable, whatever keyId it claims`
                + ' (X-H-11: keyId matching without verification is the forgery shape). Provide the anchor/engine key material —'
                + ' point DSH_PROOF_TRUST_DIR at the trust root holding the workspace key, or run on the host that anchors this workspace');
        }
    }
    else if (engineSigner !== undefined) {
        candidates = honest.filter(cp => cp.keyId === engineSigner.keyId);
        if (candidates.length === 0) {
            return fail(`no anchor on record and no checkpoint signed by the local engine key (${engineSigner.keyId})`
                + ' — without an anchor, publication is only possible for checkpoints this host can verify');
        }
        verifier = engineSigner;
    }
    else {
        return fail('refusing to publish: no trust root — the workspace has no anchor on record and no engine key'
            + ` under ${engineKeyDir} to verify checkpoint signatures with. Establish a trust root first:`
            + ' checkpoint under a host-held key with an anchor path configured (proof_baseline does this),'
            + ' or point DSH_PROOF_TRUST_DIR to the trust root holding the workspace key');
    }
    // -- the selection itself: newest-first, first signature that VERIFIES ---
    // W9-M5 (v0.23) + V4-M6 (v0.24): the scan-back rule now lives in
    // core/transparency as `selectPublishable` — the ONE predicate every
    // publisher face selects through. The engine face kept a positional
    // findLast twin of the CLI's inline loop through all of v0.23 (one
    // appended garbage twin = a publication veto it never suffered here);
    // sharing the export is the only shape in which the two faces cannot
    // drift apart again.
    const candidateVerifier = verifier;
    const { chosen, rejected } = await selectPublishable(candidates, cp => candidateVerifier.verify(checkpointSignedData(cp.payload), cp.sig));
    if (chosen === undefined) {
        return fail(`refusing to publish: every candidate checkpoint under the ${anchor !== undefined ? 'anchored' : 'local engine'} key (${verifier.keyId})`
            + ` failed signature verification — rejected: ${rejected.map(cp => `log line ${cp.index} (count ${cp.payload.count})`).join(', ')}.`
            + ' A checkpoint whose signature does not verify under the key it names is a forgery, and the log is a notary, not a laundering service');
    }
    // W9-M5 (v0.23): the published leaf is keyed by the workspace identity the
    // DERIVATION computes, and that identity must agree with the one the
    // checkpoint SIGNATURE covers (`payload.workspaceKey`). Without the
    // cross-check, copying workspace A's chain into workspace B and running
    // the CLI there would enter A's honestly-signed checkpoint into the log
    // under B's identity — a cross-workspace laundering no later reader could
    // see. (A checkpoint that predates the field signs `null` — nothing to
    // cross-check, and the derived identity is all there is.)
    const signedWorkspace = chosen.payload.workspaceKey;
    if (signedWorkspace !== null && signedWorkspace !== paths.workspaceKey) {
        return fail(`refusing to publish: the selected checkpoint is signed for workspace ${JSON.stringify(signedWorkspace)}`
            + ` but this workspace derives ${JSON.stringify(paths.workspaceKey)} — a chain copied into a foreign workspace is not this workspace's evidence`
            + ' (point DSH_PROOF_ROOT at the workspace the chain belongs to, or rebuild the baseline here)');
    }
    // W9-M6 (v0.23): the operator key is loaded and proven usable BEFORE the
    // log is mutated. After this point every failure mode of the head mint
    // (a typo'd key directory minting a wrong-identity key, a locked key
    // directory, a full disk) can still strike — but it strikes BEFORE any
    // entry is appended, so the CLI cannot leave the half-published state
    // (an entry on the public log with no signed head over it) the engine
    // face already refuses to produce.
    const operator = await NodeEd25519Signer.load(operatorKeyDir);
    // V4-M5 (v0.24): everything about the STORED head that would refuse the
    // coming head write is adjudicated here, before appendPtlEntry touches the
    // log. savePtlHead's own gates (logId rotation above all) fire at
    // head-write time — which is AFTER the entry has landed, the exact
    // half-published state (an entry on the public log with no signed head
    // over it) the fronting order promises never to produce. A stored head
    // that is unreadable, unparseable (Y-H-06), or signed by a DIFFERENT
    // operator identity now refuses the publish before a line is written; the
    // write-time checks stay as defence in depth.
    await preflightPtlHead(fs, logDir, operator.keyId);
    // The published leaf is the checkpoint itself, re-committed under the
    // workspace identity the log indexes by: count/head/at from the signed
    // payload, keyId/sig copied verbatim so a third party can re-verify the
    // checkpoint signature against the engine's key without the workspace.
    const entry = {
        v: 1,
        workspaceKey: paths.workspaceKey,
        keyId: chosen.keyId,
        count: chosen.payload.count,
        head: chosen.payload.head,
        at: chosen.payload.at,
        sig: chosen.sig,
    };
    const { sequence, duplicate } = await appendPtlEntry(fs, logDir, entry);
    // Every append closes with a freshly signed tree head — publishing an
    // entry without a head over it would leave the log's newest leaf outside
    // every auditable commitment. Per core/transparency, an STH's `logId` IS
    // the operator's keyId (the public identity of whoever runs the log), and
    // the operator key lives OUTSIDE the log directory (see
    // resolveOperatorKeyDir) so no rewrite of the log can rotate the very
    // identity that vouches for it.
    const { log } = await loadPtl(fs, logDir);
    const unsigned = {
        logId: operator.keyId,
        treeSize: log.size,
        root: log.merkleRoot(),
        at: new Date().toISOString(),
    };
    const sth = { ...unsigned, sig: await operator.sign(sthSignedData(unsigned)) };
    // X-H-10 (v0.23): the head already stored in the log directory is
    // attacker-controllable storage, and savePtlHead reasons from it as its
    // trust baseline — so the operator key in hand also adjudicates the
    // stored head's own signature before the new one is signed over it.
    await savePtlHead(fs, logDir, sth, {
        verifyExistingHead: async (existing) => operator.verify(sthSignedData(existing), existing.sig),
    });
    process.stdout.write(`${JSON.stringify({
        sequence,
        duplicate,
        leafHash: ptlLeafHash(entry),
        treeSize: sth.treeSize,
        root: sth.root,
        logId: sth.logId,
    })}\n`);
    return 0;
}
// ---------------------------------------------------------------------------
// head
// ---------------------------------------------------------------------------
async function runHead(fs, logDir) {
    const { sth } = await loadPtl(fs, logDir);
    process.stdout.write(`${JSON.stringify(sth ?? { empty: true })}\n`);
    return 0;
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
 *
 * v0.23 (W9-M6/M7 — the no-bundle face catches up with the bundle face's
 * "uncertain = fail" discipline):
 * - a head on record whose signature could not be adjudicated (no operator
 *   key at hand) FAILS the self-check instead of passing on `rootMatch`
 *   alone — a commitment nobody verified is exactly the uncertainty the
 *   bundle face already refuses to wave through;
 * - `badLines > 0` (malformed/whitespace lines loadPtl counted while
 *   loading) FAILS too and is surfaced in the output — physical damage the
 *   readable prefix cannot speak for used to be invisible whenever the
 *   damage did not move the root.
 */
async function runSelfVerify(fs, logDir, operatorKeyDir) {
    const { log, sth, badLines, headOvercommits } = await loadPtl(fs, logDir);
    const notes = [];
    if (headOvercommits && sth !== undefined) {
        notes.push(`sth.json promises ${sth.treeSize} entries but the log holds ${log.size} — head and log are disconnected`);
    }
    else if (sth === undefined && log.size > 0) {
        notes.push(`no signed head on record (sth.json missing or unreadable) while the log holds ${log.size} entries`);
    }
    else if (sth === undefined && log.size === 0) {
        // V4-L10 (v0.24): an empty log fails the self-check with a bare
        // rootMatch:false and no word of explanation — an operator pointing the
        // CLI at a fresh (or mis-typed, or not-yet-published) log directory got
        // a failure that read like tampering. Name the state: nothing has been
        // published here yet, so there is no commitment to check. The verdict
        // stays a failure — a self-check of nothing is not a pass.
        notes.push('the log holds no entries and no signed head is on record — nothing has been published to this log yet, so there is no commitment to check (verify cannot pass on an empty log; run append first)');
    }
    if (badLines > 0) {
        notes.push(`${badLines} malformed line(s) in ptl-entries.jsonl — the readable prefix still verifies, but the log file carries bytes the tree does not speak for`);
    }
    const rootMatch = sth !== undefined && sth.treeSize === log.size && log.merkleRoot() === sth.root;
    let headSignature;
    const operator = await resolveOperatorForVerify(fs, operatorKeyDir);
    if (operator !== undefined && sth !== undefined) {
        headSignature = await headSignatureHolds(sth, operator);
    }
    else if (sth !== undefined) {
        notes.push('operator key absent — head signature not verified (uncertain = fail)');
    }
    const ok = rootMatch && headSignature === true && badLines === 0;
    process.stdout.write(`${JSON.stringify({
        ok,
        treeSize: sth?.treeSize ?? log.size,
        checks: {
            rootMatch,
            ...(headSignature !== undefined ? { headSignature } : {}),
        },
        ...(badLines > 0 ? { badLines } : {}),
        ...(notes.length > 0 ? { notes } : {}),
    })}\n`);
    return ok ? 0 : 1;
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
async function runBundleVerify(fs, logDir, bundlePath, operatorKeyDir) {
    const bundleRaw = await fs.readFile(bundlePath);
    if (bundleRaw === undefined)
        return fail(`cannot read bundle: ${bundlePath}`);
    let bundle;
    try {
        bundle = JSON.parse(bundleRaw);
    }
    catch (error) {
        return fail(`bundle is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    const record = bundle?.manifest?.transparency;
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
        return fail('bundle manifest carries no transparency record (was it published with dsh-proof-ptl append?)');
    }
    const t = record;
    const { log, sth, badLines, headOvercommits } = await loadPtl(fs, logDir);
    const notes = [];
    if (badLines > 0) {
        notes.push(`${badLines} malformed line(s) in ptl-entries.jsonl — the audited prefix is readable, but the log file itself is not sound`);
    }
    // ① the leaf the bundle claims, at the position it claims.
    const sequence = typeof t.sequence === 'number' && Number.isSafeInteger(t.sequence) ? t.sequence : -1;
    const entry = sequence >= 0 && sequence < log.size ? log.entries[sequence] : undefined;
    const leafMatch = entry !== undefined && typeof t.leafHash === 'string' && ptlLeafHash(entry) === t.leafHash;
    // The publication head the bundle pins, narrowed once: ②③④ adjudicate
    // against it, and a record without a usable one can prove neither
    // inclusion nor non-rewrite.
    const rawPublished = t.publishedHead;
    const published = rawPublished !== null && typeof rawPublished === 'object'
        && typeof rawPublished.treeSize === 'number' && Number.isSafeInteger(rawPublished.treeSize) && rawPublished.treeSize >= 1
        && typeof rawPublished.root === 'string'
        ? { treeSize: rawPublished.treeSize, root: rawPublished.root }
        : undefined;
    // ② inclusion of that leaf in the PUBLISHED head's tree — the head the
    // bundle pins, not the current one (see the doc comment above).
    const inclusion = entry !== undefined && published !== undefined && Array.isArray(t.inclusionProof)
        && verifyInclusion(entry, sequence, published.treeSize, t.inclusionProof, published.root);
    // ③ non-rewrite: publication head vs current head.
    let consistency;
    if (published !== undefined) {
        if (sth === undefined) {
            // (H-07b) The bundle claims a publication, and the log currently
            // promises nothing: there is no head to reconcile the claim against,
            // and that absence is a failure, not a pass.
            consistency = false;
            notes.push('no current signed head on record (sth.json missing or unreadable) — a claimed publication cannot be reconciled with the present');
        }
        else if (published.treeSize === sth.treeSize && published.root === sth.root) {
            consistency = undefined; // the log has not moved: nothing to reconcile
        }
        else if (published.treeSize > sth.treeSize) {
            consistency = false; // the current log is SHORTER than what was published — a rewind
            notes.push(`the current head (size ${sth.treeSize}) is shorter than the published one (size ${published.treeSize}) — the log was rewound after publication`);
        }
        else if (headOvercommits) {
            // (M-63) The current head promises more entries than the file holds:
            // adjudicated, never delegated to a producer-side RangeError.
            consistency = false;
            notes.push(`sth.json promises ${sth.treeSize} entries but the log holds ${log.size} — head and log are disconnected`);
        }
        else {
            consistency = verifyConsistency(published.treeSize, published.root, sth.treeSize, sth.root, log.consistencyProof(published.treeSize, sth.treeSize));
        }
    }
    // ④ operator identity agreement between the pinned head and the current one.
    let logIdMatch;
    if (published !== undefined && sth !== undefined
        && typeof rawPublished?.logId === 'string' && typeof sth.logId === 'string') {
        logIdMatch = rawPublished.logId === sth.logId;
        if (!logIdMatch) {
            notes.push(`the pinned head names operator ${JSON.stringify(rawPublished.logId)} but the current head names ${JSON.stringify(sth.logId)} — the log changed hands or was re-keyed`);
        }
    }
    // ⑤ the bundle's own publication claim: the pinned head's signature.
    const operator = await resolveOperatorForVerify(fs, operatorKeyDir);
    let publishedHeadSig;
    if (operator === undefined) {
        publishedHeadSig = 'not-checked (operator key absent)';
        notes.push('operator key absent — the publication signature was NOT verified');
    }
    else if (published === undefined
        || typeof rawPublished?.logId !== 'string' || rawPublished.logId.length === 0
        || typeof rawPublished?.at !== 'string' || rawPublished.at.length === 0
        || typeof rawPublished?.sig !== 'string' || rawPublished.sig.length === 0) {
        publishedHeadSig = false;
        notes.push('the pinned published head is not a complete signed tree head — its signature cannot be adjudicated');
    }
    else {
        publishedHeadSig = await headSignatureHolds(rawPublished, operator);
    }
    // ⑥ the current head's own signature.
    let headSignature;
    if (operator !== undefined && sth !== undefined) {
        headSignature = await headSignatureHolds(sth, operator);
    }
    // W9-M7 (v0.23): physical damage (badLines) fails the audit — the checks
    // above speak for the readable prefix, and a log whose FILE carries bytes
    // the tree does not account for is not a sound publication record.
    const ok = leafMatch && inclusion && consistency !== false
        && (logIdMatch === undefined || logIdMatch)
        && headSignature !== false
        && publishedHeadSig === true
        && badLines === 0;
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
        ...(badLines > 0 ? { badLines } : {}),
        ...(notes.length > 0 ? { notes } : {}),
    })}\n`);
    return ok ? 0 : 1;
}
// ---------------------------------------------------------------------------
async function main() {
    const parsed = parseArgs(process.argv.slice(2));
    if ('error' in parsed) {
        process.stderr.write(`${parsed.error}\n${USAGE}\n`);
        return 2;
    }
    const { command, log, bundle, operatorKeyDir } = parsed.args;
    const fs = new NodeFsPort();
    if (log === undefined) {
        process.stderr.write(`--log <dir> is required\n${USAGE}\n`);
        return 2;
    }
    // The operator key directory is resolved once and threaded everywhere a
    // key is needed: append signs with it, verify adjudicates with it, and
    // neither falls back to <logDir>/operator-key unless the caller passed
    // that directory explicitly (see resolveOperatorKeyDir).
    const keyDir = resolveOperatorKeyDir(operatorKeyDir);
    try {
        if (command === 'append')
            return await runAppend(fs, log, keyDir);
        if (command === 'head')
            return await runHead(fs, log);
        if (bundle === undefined)
            return await runSelfVerify(fs, log, keyDir);
        return await runBundleVerify(fs, log, bundle, keyDir);
    }
    catch (error) {
        return fail(`ptl ${command} failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}
main().then((code) => {
    // exitCode, never process.exit(): a forced exit can discard stdio writes
    // still sitting in the Windows pipe buffer, and this CLI's whole contract
    // is one honest line of output. With no servers or timers alive, setting
    // the code lets the process drain and exit with it.
    process.exitCode = code;
}).catch((error) => {
    // A rejection here is a bug, not a verdict — still one clean line, never a stack.
    process.stderr.write(`[dsh-proof-ptl] fatal: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
});
//# sourceMappingURL=ptl-entry.js.map