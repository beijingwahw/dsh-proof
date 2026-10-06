# Agent Proof Protocol (APP) 1.1

**An open standard for machine-verifiable completion claims.**

| | |
|---|---|
| Status | Draft |
| Protocol name | `agent-proof-protocol` |
| Version | `APP/1.1` |
| Reference implementation | dsh-proof v0.18.0 |
| Supersedes | `APP/1.0` (dsh-proof v0.14.0) — tool-surface expansion only, see §6/§8 |
| Proof media type | `application/vnd.app.proof+json` |
| Bundle media type | `application/vnd.app.proof-bundle+json` |
| Constants module | `src/app/protocol.ts` (this repository) |

## Why this protocol exists

When an agent reports "I'm done", the statement is a self-report from the party with the most to gain from its being believed. APP turns that statement into evidence any third party can recompute. Every claim resolves to content-addressed records in an append-only, hash-chained log; the log is sealed at intervals by signatures the claimant cannot produce and mirrored to an anchor it cannot reach. A verifier never asks the agent whether the work is finished — it re-derives the answer from bytes. The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## §1 Concepts

- **Claim** — a typed statement of completion ("this behavior was added", "this refactor changed no API"). Not free text: its kind binds it to a set of evidence obligations evaluated by `evaluateContract` (`src/core/contract.ts`).
- **Evidence** — one observed run of one check: command, status, exit code, output digest and excerpt, workspace snapshot. Self-addressing: `evidenceId = sha256(canonicalJson(record without evidenceId))`, minted by `makeEvidence` (`src/core/evidence.ts`).
- **Verdict** — the *baseline differential* for one check: which way the comparison between its baseline record and its current record moved. Produced by `verdictOf` (`src/core/evidence.ts`).
- **Grade** — what a whole verification run concluded: `proven`, `regressed`, `stale`, `unproven` or `no-baseline` (§2). Decided by `decideGrade` inside `assembleProof` (`src/core/report.ts`).
- **Baseline** — a named view over the evidence log: the latest record per check at the moment work started, plus a Merkle root over their addresses (`buildBaseline`, `src/core/evidence.ts`). The baseline decides which later failures are *yours*.
- **Checkpoint** — a signed statement on the log committing to "chain head H, after N records" (`{count, head, workspaceKey, at}`, Ed25519-signed by a host-held key). Produced by `EvidenceStore.checkpoint()` (`src/core/evidence.ts`), payload defined in `src/core/trust.ts`.
- **Anchor** — the highest checkpoint ever written, mirrored to a file outside the agent-writable workspace, next to the signing key (`parseAnchor`, `src/core/trust.ts`). Its presence makes silent truncation of the log detectable as a rewind.

## §2 Vocabulary

### Verdicts (8)

A verdict names the direction of the baseline→current comparison, never an absolute state.

| verdict | baseline | current | meaning |
|---|---|---|---|
| `still-passing` | pass | pass | credit — held green |
| `still-failing` | fail | fail | pre-existing — **never charged to the session** |
| `regression` | pass | fail | blame — this session broke it |
| `fixed` | fail | pass | credit — this session repaired it |
| `new-failure` | absent | fail | blame, honestly unattributable to history |
| `new-check` | absent | pass (decisive) / never ran | first sight; credit only when it actually ran decisively |
| `not-run` | present | absent | evidence stale — nothing to compare |
| `indeterminate` | either side non-decisive | either | **neither credit nor blame** — the honest middle |

### Grades (5)

Pessimistic by construction; missing evidence is never papered over.

| grade | meaning |
|---|---|
| `proven` | baseline existed; everything affected re-ran decisive and green (or the posterior crossed the certify target); nothing regressed |
| `regressed` | at least one `regression` or `new-failure` |
| `stale` | verification incomplete — an affected check produced no decisive outcome; the move is "re-run", not "wait" |
| `unproven` | verification completed but nothing objective speaks for the claim (no checks discovered, or none affected) — or green evidence never executed the change |
| `no-baseline` | no baseline exists; nothing can be diffed yet |

### Check statuses (6)

Only `pass` and `fail` are **decisive** — they settle the check's question (`isDecisiveStatus`, `src/core/evidence.ts`). `error`, `timeout`, `aborted` and `skipped` all mean "ran, or was stopped, without producing a conclusion"; the verdict lattice treats them identically as unknown.

### Chain modes (3)

| mode | meaning |
|---|---|
| `legacy` | v1 envelopes only — readable, honest, but no `prev` linkage (pre-standard logs) |
| `unsigned` | v2 hash-chained envelopes, no signature-bearing checkpoint |
| `signed` | v2 chained, at least one checkpoint carries a valid-form signature |

### Claim kinds (5)

Every kind sits on the shared `zero-regressions` floor; each adds its own obligations (`src/core/contract.ts`).

| kind | binding obligations (beyond the floor) |
|---|---|
| `behavior-preserving` | `api-surface-unchanged` — the public export face must not move in either direction |
| `behavior-adding` | `new-paths-covered` — every changed source path is exercised by a passing check |
| `perf-budget` | `benchmark-evidence` + `within-budget` — a decisive benchmark measurement inside the stated `budgetMs` |
| `docs-only` | `docs-only-changes` + `jury-review` — the change set really is documents; checks are skipped, confidence is capped |
| `llm-jury` | `jury-delivered` + `jury-upholds` — an active jury deliberation on the exact claim text upholds it at ≥ 0.5 |

## §3 Content addressing

Every addressable value is addressed by the SHA-256 of its **canonical JSON** form (`src/core/hash.ts`):

- Object keys are sorted recursively.
- `undefined` properties are dropped entirely (never serialized as `null`).
- Numbers pass through JSON serialization; `-0` and `0` agree; non-finite values become `null`.
- Circular structures are rejected with a `TypeError` — not an exhausted stack.

The address of a value `v` is `sha256(canonicalJson(v))`. Evidence records are **self-addressing**: stripping `evidenceId` and re-hashing must reproduce it, which any reader can check from the record's own bytes. Sets of records collapse order-independently into a Merkle-style root (`merkleRoot`: digest of the sorted, newline-joined addresses).

Captured output is normalised before hashing (`normalizeOutput`), making the same outcome yield the same address on any machine: workspace and home paths substitute to `$WORKSPACE` / `$HOME` (root first, matched only at path boundaries), durations to `<duration>`, timestamps to `<timestamp>`, CRLF folds to LF, trailing whitespace and blank lines drop. The same failure on a different checkout, under a different home directory, is the *same evidence* — this is what cross-session dedupe, cross-machine comparison and third-party recomputation all rest on.

## §4 Tamper evidence

The evidence log is a JSONL file of envelopes. v2 envelopes carry `prev = sha256(previous physical line, of any kind)`, so editing, inserting or removing any line breaks the link into the next (`walkChain`, `src/core/trust.ts`). v1 envelopes (legacy) carry no `prev` and audit honestly as `legacy`.

A **checkpoint** is an envelope whose payload is `{count, head, workspaceKey, at}` and whose detached signature covers exactly `canonicalJson(payload)`, produced with Ed25519 by a host-held key the audited agent cannot read (`SignerPort`, `src/core/ports.ts`). **MUST:** a checkpoint's `count` MUST equal the number of evidence and marker records that precede it on the chain, and MUST be a safe integer. The chain walker rejects checkpoints whose `count` disagrees with the records it actually walked past (`src/core/trust.ts` — validation normative as of APP/1.0; the reference implementation hardened `walkChain` accordingly) — without it, a forged small `count` could inflate the apparent tail window and launder a truncation. The walker likewise MUST reject a checkpoint whose `head` does not match the chain digest at its position.

The highest checkpoint is mirrored **out of band** to an anchor file (`{v, keyId, count, head, sig, at, workspaceKey?}`) stored next to the signing key, outside the workspace. A log that ends below the anchor's `count` is a **rewind**; equal counts with different heads are an anchor mismatch; an anchor whose fields no longer match its own signature is forged. The baseline file's digest is recorded on the chain at save time, so wholesale substitution of the baseline is also detectable.

## §5 Exchange format

A **proof bundle** (media type `application/vnd.app.proof-bundle+json`) moves a verification between parties: manifest first, files after.

```json
{
  "protocol": "APP/1.1",
  "appFingerprint": "<sha256 hex>",
  "workspaceKey": "<stable workspace identity>",
  "createdAt": "<ISO timestamp>",
  "files": [
    { "path": "evidence.jsonl", "sha256": "<hex>", "bytes": 1234 },
    { "path": "baseline.json", "sha256": "<hex>", "bytes": 567 },
    { "path": "anchor.json",   "sha256": "<hex>", "bytes": 89 }
  ]
}
```

`files` MUST list `evidence.jsonl` (the chained log); `baseline.json` and `anchor.json` are optional but SHOULD be included when they exist. A manifest MAY additionally carry a `transparency` record `{logId, sequence, leafHash, publishedHead, inclusionProof}` pinning where the bundle's checkpoint was published in a transparency log (§9). The field is additive-optional per §8 — bundles built before it existed verify exactly as they always did — and a bundle verifier adjudicates only its *structure*; the log-level proofs (inclusion, consistency) are adjudicated against the log itself (§9). `appFingerprint` names the producing implementation's dialect (§8), so a consumer detects vocabulary drift before interpreting anything.

**Verifier obligations.** A verifying party trusts nothing from the producer. It MUST recompute every file digest in `files` and reject on any mismatch; walk the chain (§4) and reject breaks, corrupt lines, count/head-invalid checkpoints; re-verify each record's self-addressing; re-verify checkpoint signatures when it holds — or can obtain — the named key; resolve the anchor's monotonicity checks when the anchor is available; and re-derive the baseline digest recorded on the chain before believing the baseline file. A missing adjudication capability (no key, no anchor) is recorded as such, never rounded up to a forgery charge.

## §6 Verification API

APP/1.1's conformance surface is seven model-facing tools (reference: `src/app/mcp-server.ts`):

| tool | input (essentials) | output (essentials) |
|---|---|---|
| `proof_status` | — | baseline presence, discovered checks, latest evidence per check, chain mode and integrity. Read-only |
| `proof_baseline` | — | runs every discovered check, records evidence, saves the baseline view, checkpoints |
| `proof_verify` | `changed?: string[]`, `all?: boolean` | grade, per-check verdicts, regression attribution, evidence root |
| `proof_claim` | `claim`, optional contract params (`kind`, `budgetMs`, `review`, `entryPoints`) | `proven: true` only when the contract's obligations all hold; otherwise `blockers` is the to-do list |
| `proof_bundle` | — | assembles the §5 bundle: manifest (with `appFingerprint`) + files, digests recomputed at pack time |
| `proof_publish` | — | appends the workspace's latest *signed* checkpoint to the transparency log (§9) as one Merkle leaf and mints a fresh operator-signed tree head: `{sequence, duplicate, leafHash, treeSize, root, logId, at, inclusionProof, sth}`. Idempotent by leaf hash — republishing the same checkpoint answers `duplicate: true` and the tree does not grow. Requires a configured log and a signed checkpoint on the chain; failure is a clean tool error, never a half-published tree |
| `proof_log_verify` | `sequence?`, `leafHash?` (together or apart), `publishedTreeSize?` + `publishedRoot?` (paired) | audits the transparency log from its own bytes — nothing the caller asserts is trusted: recomputes the root; adjudicates the signed tree head (size, root, signature — a missing operator key is `not-checked`, never valid); inclusion of the entry at `sequence` (leaf hash recomputed, then verified against the recomputed root); consistency from a previously published `(treeSize, root)` to the current tree. `ok: false` with the problems named on any failure |

**APP/1.0 → APP/1.1 is a tool-surface expansion, nothing else.** The two transparency tools joined the conformance face; the vocabularies (§2), the content addressing (§3), the chain and checkpoint formats (§4) and the bundle format (§5) are byte-for-byte what APP/1.0 defined — an old bundle remains exactly as verifiable as the day it was minted. What did move is the dialect marking: `PROTOCOL_VERSION` is fingerprint material (§8), so every APP/1.1 manifest self-identifies as mutually unintelligible with every APP/1.0 one, and each side refuses the other instead of guessing. A deployment that runs no transparency log keeps a conforming APP/1.1 face: `proof_publish` / `proof_log_verify` answer a clean configuration error when no log is configured, and bundles without a `transparency` record verify as they always have.

**Out of scope for v1:** `proof_jury`, `proof_jury_submit`, `proof_endorse`, `proof_conjure` and `proof_conjure_run` exist in the reference implementation but are NOT part of APP/1.1 conformance. They depend on host-held seams an open protocol cannot assume — an isolated deliberation model (Class B testimony), a human approval gate (Class C endorsement), and a sandbox plus session context for conjured tests. Hosts MAY expose them as extensions.

## §7 Security considerations

**Threat model: the prover is the audited party.** The agent can read and write every byte in the workspace — including the entire evidence log — and it can use the protocol's own hashing functions to rewrite a perfectly self-consistent history. Three lines of defense close that hole:

1. **Hash chain** — rewriting or deleting any interior line breaks the link into the next.
2. **Signed checkpoints** — a full rewrite can re-derive every digest, but it cannot forge a signature over a checkpoint; `head` mismatches and unsigned-while-signed checkpoints fail audit.
3. **Out-of-band anchor** — even a complete re-forge (new chain, new self-consistent checkpoints is impossible without the key; but truncation alone) is bounded: a log that ends below the anchor's high-water mark is a rewind.

**Known honest limits**, stated rather than hidden:

- Records appended after the last checkpoint are chain-covered but not checkpoint-covered. That tail window is bounded by the checkpoint cadence and closed at every baseline/verify/claim boundary.
- When the anchor is unreadable (different machine, key retired), anchor checks are *skipped*, not failed — a missing capability is not an accusation; rewind cover is lost, chain and signature cover are not.
- v1 legacy envelopes carry no `prev`; a log that is entirely v1 is audited as `legacy` and protected only by per-record self-addressing. Interop with such logs is a compatibility stance, not a security claim.
- Output normalisation (§3) is for equality of *addressing*, not secrecy: masked durations and timestamps can collide by design; that is the cost of the same failure hashing to the same address everywhere.

## §8 Conformance

An APP/1.1 implementation MUST implement content addressing (§3), tamper evidence (§4) and the exchange format (§5) exactly as specified, and MUST expose the seven tools of §6. A transparency log (§9) is an optional deployment: the two transparency tools presuppose an operator-run log and MAY answer a clean configuration error when none is configured.

**Implementation fingerprint.** `appFingerprint()` (`src/app/protocol.ts`) is `sha256(canonicalJson(...))` over the five vocabularies plus one string per load-bearing rule — `addressing: 'sha256(canonicalJson(v))'`, `chain: 'prev=sha256(prevLine)'`, `signature: 'ed25519(canonicalJson(checkpointPayload))'`. It is the dialect's digest: any change to a vocabulary value or to one of these rules MUST produce a different fingerprint. Producers stamp it into every manifest; consumers MUST refuse to interpret a bundle whose fingerprint they cannot reproduce against their own constants, rather than guess at the dialect. The APP/1.0 → APP/1.1 bump is this rule applied honestly to the tool surface: the vocabularies and rule strings are untouched, but `PROTOCOL_VERSION` is itself fingerprint material, so the seven-tool expansion moved the fingerprint by construction — a consumer that could silently read a 1.1 manifest while believing it spoke 1.0 would never learn that two tools' semantics exist; the moved fingerprint makes the dialects refuse each other loudly instead.

**Backward compatibility.** Evolution of the canonical addressing rules MUST NOT change the address of any existing value. The sanctioned mechanism is additive optional fields that are *omitted* (never `null`) when absent — canonical JSON drops them, so historical records keep their digests, and old artifacts that predate a field skip (rather than fail) its checks. This is the standing precedent of the reference implementation: `Evidence.source`, `synthetic` and `coverage`, `WorkspaceSnapshot.dirtyDigests`, and the anchor's `workspaceKey` were all added this way, without moving a single existing address.

A vocabulary change (a new verdict, a renamed status) is not a compatible evolution: it changes the fingerprint and thereby names a new dialect, and bundles that carry it MUST say so in their manifest.

## §9 Transparency log

A checkpoint (§4) proves the workspace's chain was intact *at the moment the host signed it*. It says nothing about whether the history leading there was ever rewritten after the fact, or whether everyone was shown the same history. A **Proof Transparency Log (PTL)** closes that gap by applying the certificate-transparency (RFC 6962) / sigstore playbook to agent delivery evidence: the sequence of published checkpoints becomes an append-only Merkle log, and any third party holding only public data can verify three properties — that a given delivery's checkpoint really is in the log (**completeness**, via an inclusion proof), that sequence numbers only grow and timestamps never rewind (**ordering**), and that every older signed head is still derivable from every newer one, so the log never rewrote itself (**immutability**, via a consistency proof). Tampering or truncation is caught by a root mismatch, a failed consistency proof, or the head-rewind guard below.

### Entries and leaves

The unit of publication is one workspace's signed checkpoint, hosted **verbatim**:

```json
{ "v": 1, "workspaceKey": "…", "keyId": "…", "count": 42, "head": "…", "at": "…", "sig": "…" }
```

The log is a **dumb notary**: it appends bytes and signs tree heads; it does NOT verify the workspace signature it carries. `keyId` names whose key an auditor needs to adjudicate `sig` — with the workspace public key, the auditor re-derives that verdict independently; without it, the entry still proves ordered, unrewritten publication. The separation is deliberate: the log attests *that* these bytes were published, never *that* the bytes were honest — trust in the workspace chain and trust in the log are two independent adjudications.

The leaf hash is `SHA-256(0x00 || canonicalJson(entry))` — the RFC 6962 domain-separation prefix (leaves `0x00`, internal nodes `0x01 || left || right`) over **canonical** JSON (§3), so any implementation in any language recomputes the same leaf from the same entry; a leaf address is never an artifact of local serialization order. The tree is the RFC 6962 **ordered** tree hash — deliberately a different construction from the order-independent set root of §3, because a transparency log must react to entry order (swapping two published checkpoints is a different history and must move the root) while an evidence set must not.

### Signed tree heads

The log operator signs a **signed tree head (STH)** after every append:

```json
{ "logId": "…", "treeSize": 7, "root": "…", "at": "…", "sig": "…" }
```

`sig` is an Ed25519 signature over exactly `canonicalJson({logId, treeSize, root, at})`; `logId` is the operator's own `keyId` — the public identity of whoever runs the log, and how a verifier knows whose key adjudicates the head. The operator key is a **separate key** from the workspace chain signer (§4): one speaks for the host over its evidence log, the other speaks for the log operator over the public tree, and rotating one must never rotate the other. A new head MUST NOT rewind the published one — a smaller `treeSize`, the same size under a different `root`, or an earlier `at` are all refused: once an operator has signed a head, the only honest next head extends it.

### Publishing and auditing

A workspace publishes its latest signed checkpoint through the engine's `publishCheckpoint()`, the `proof_publish` tool (§6), or the standalone auditor CLI (`dsh-proof-ptl append | head | verify`). All three are mirrors, not re-derivations — the entry carries the checkpoint's own `{count, head, at, sig, keyId}`, and the same checkpoint always addresses to the same leaf, so appending is idempotent by leaf hash: a replayed checkpoint is the same event, not a new one, and re-publishing can never pad the tree.

A published bundle (§5) carries a `transparency` record pinning `{logId, sequence, leafHash, publishedHead, inclusionProof}`. The log-side audit runs four checks in order:

1. **leafMatch** — the entry at `sequence` hashes to the recorded `leafHash`: the checkpoint the verifier was shown is the one in the log;
2. **inclusion** — the audit path folds that leaf into the root of the head the bundle *pins* (`publishedHead`): RFC 6962 audit paths are size-specific, so a proof minted at publication size folds against the publication head, never today's;
3. **consistency** — the pinned head is still a provable prefix of the *current* head, chaining the publication statement to the present: this is the non-rewrite guarantee, since a rewritten or truncated history cannot produce a consistency proof to a root the operator already signed;
4. **headSignature** — the current STH verifies under the operator key.

Any failure names the broken check. A missing capability — no operator key at hand — is reported `not-checked`, never valid, and never an accusation: the same refusal discipline as §5. A log with no bundle pinned self-checks the same way minus the leaf: recomputed root vs. the signed head, sizes agreeing, signature adjudicated.

### Trust model and honest limits

v1 specifies a **single-operator, file-backed log**. What is cryptographically guaranteed: the log's own history cannot be rewritten undetectably — an interior edit moves the root, a truncation shrinks the tree, both fail the head signature or the consistency proof, and the operator cannot sign a second self-consistent history without tripping the rewind guard. What is explicitly NOT guaranteed: a **split-view** operator — one serving different trees to different verifiers — cannot be caught by any single log alone; detecting it requires multiple witnesses or gossip between auditors (the full certificate-transparency answer), which is **future work**, not a property of this version. And per the dumb-notary principle, the log does not verify the workspace signatures it hosts: a published checkpoint proves publication, and the workspace signature is adjudicated separately by whoever holds the workspace public key.

Reference implementation: `src/core/transparency.ts` (pure domain — RFC 6962 Merkle tree, inclusion and consistency proofs, verifiers written as the exact mirror of the generators, pinned against the RFC's own §2.1.3 worked example) and `src/app/ptl-entry.ts` (the standalone auditor CLI). A three-step audit walkthrough ships as `examples/ptl-workflow.md`.
