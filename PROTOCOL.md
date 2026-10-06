# Agent Proof Protocol (APP) 1.4

**An open standard for machine-verifiable completion claims.**

| | |
|---|---|
| Status | Draft |
| Protocol name | `agent-proof-protocol` |
| Version | `APP/1.4` |
| Reference implementation | dsh-proof v0.27.0 |
| Supersedes | `APP/1.3` (dsh-proof v0.20.0) — tool-surface expansion only, see §6/§8/§12 |
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

### Chain modes (4)

The first three are the wire vocabulary (`CHAIN_MODES`, fingerprint material per §8). The fourth is a verifier-reported value over the same axis, added in the reference implementation's v0.22 hardening pass: it arises only in bundle verification, when a chain carries signature-bearing checkpoints nobody adjudicated.

| mode | meaning |
|---|---|
| `legacy` | v1 envelopes only — readable, honest, but no `prev` linkage (pre-standard logs) |
| `unsigned` | v2 hash-chained envelopes, no signature-bearing checkpoint |
| `signed` | v2 chained, at least one checkpoint carries a signature; when a bundle verifier reports this mode, the signatures were actually adjudicated against a held key and every adjudication passed (§5) |
| `signed-unverified` | bundle verification only: the chain carries signature-bearing checkpoints the verifier could not adjudicate (it holds no key any of them name) — "signatures exist" and "signatures were verified" are different claims, and presence is never rounded up to proof |

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
  "protocol": "APP/1.4",
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

`files` MUST list `evidence.jsonl` (the chained log); `baseline.json` and `anchor.json` are optional but SHOULD be included when they exist. The layout is closed: a manifest that lists anything else, or lists one of the three more than once, does not verify. A manifest MAY additionally carry a `transparency` record `{logId, sequence, leafHash, publishedHead, inclusionProof}` pinning where the bundle's checkpoint was published in a transparency log (§9). The field is additive-optional per §8 — bundles built before it existed verify exactly as they always did — and a bundle verifier adjudicates only its *structure* (shapes, ranges, the sequence-inside-the-tree and logId-agreement bounds, the proof-length bound judgable from the manifest alone); the log-level proofs (inclusion, consistency) are adjudicated against the log itself (§9). `appFingerprint` names the producing implementation's dialect (§8), so a consumer detects vocabulary drift before interpreting anything.

**Verifier obligations.** A verifying party trusts nothing from the producer. It MUST recompute every file digest in `files` and reject on any mismatch; walk the chain (§4) and reject breaks, corrupt lines and count/head-invalid checkpoints — malformed checkpoints are named problems, not folded into a passing verdict; re-verify each record's self-addressing; re-verify checkpoint signatures when it holds — or can obtain — the named key; resolve the anchor's monotonicity checks when the anchor is available; and re-derive the baseline digest recorded on the chain before believing the baseline file. A missing adjudication capability (no key, no anchor) is recorded as such, never rounded up to a forgery charge.

**The verification result says what was and was not adjudicated.** The reference surface (`verifyBundle`, `src/app/bundle.ts`) carries three fields the v0.22 hardening made load-bearing: `malformedCheckpoints` (the line indexes of checkpoints whose self-reported `count` the walk refutes — mirrored into `problems`); `checkpointSignature` — `verified` (the verifier held the named key and every checkpoint under it verified), `invalid` (at least one failed, with a problem naming the line), or `unverified` (no key the signatures name was at hand — a missing capability, never an accusation, but the chain mode reports `signed-unverified` so nobody mistakes presence of signatures for proof of them); and `legacyProtocol` — present and `true` exactly when the accepted dialect is a known ancestor (e.g. `APP/1.3`) rather than the current one: the bundle verified clean, under an older dialect, and readers deserve to see that. v0.23 adds three more: `headLiars` (checkpoints — signature verified or not — whose declared `head` disagrees with the chain position the walk computed: a *replayed* real signature over a false head is `invalid`, not `verified`); tail records behind the last checkpoint are a `problem`, not a footnote (bytes the anchor's signature never covered must not ride it); and `verifyBundle` accepts an optional `anchorSigner` so the calling engine (not just a key-holding third party) can adjudicate signatures — the delegated-trust path no longer substitutes keyId *presence* for signature *verification*. A structurally intact log carrying zero evidence records is refused outright, and the PTL layer's `savePtlHead` extends a stored head only under `verifyExistingHead` — uncertain means refuse, on every face.

## §6 Verification API

APP/1.4's conformance surface is thirteen model-facing tools (reference: `src/app/mcp-server.ts`):

| tool | input (essentials) | output (essentials) |
|---|---|---|
| `proof_status` | — | baseline presence, discovered checks, latest evidence per check, chain mode and integrity. Read-only |
| `proof_baseline` | — | runs every discovered check, records evidence, saves the baseline view, checkpoints |
| `proof_verify` | `changed?: string[]`, `all?: boolean`, `economics?: {computePerMs, humanReviewPerItem?}` | grade, per-check verdicts, regression attribution, evidence root. With `economics` the run is priced: the ledger rides the boundary marker (a price is a chain fact, replayable via `proof_economics`) |
| `proof_claim` | `claim`, optional contract params (`kind`, `budgetMs`, `review`, `entryPoints`) | `proven: true` only when the contract's obligations all hold; otherwise `blockers` is the to-do list |
| `proof_bundle` | — | assembles the §5 bundle: manifest (with `appFingerprint`) + files, digests recomputed at pack time |
| `proof_publish` | — | appends the workspace's latest *signed* checkpoint to the transparency log (§9) as one Merkle leaf and mints a fresh operator-signed tree head: `{sequence, duplicate, leafHash, treeSize, root, logId, at, inclusionProof, sth}`. Idempotent by leaf hash — republishing the same checkpoint answers `duplicate: true` and the tree does not grow. Requires a configured log and a signed checkpoint on the chain; failure is a clean tool error, never a half-published tree |
| `proof_log_verify` | `sequence?`, `leafHash?` (together or apart), `publishedTreeSize?` + `publishedRoot?` (paired) | audits the transparency log from its own bytes — nothing the caller asserts is trusted: recomputes the root; adjudicates the signed tree head (size, root, signature — a missing operator key is `not-checked`, never valid); inclusion of the entry at `sequence` (leaf hash recomputed, then verified against the recomputed root); consistency from a previously published `(treeSize, root)` to the current tree. `ok: false` with the problems named on any failure |
| `proof_delegate` | `claim`, optional `acceptance` (verifiable acceptance criteria), `parentTaskId?` (nest under an existing task) | mints the child's **proof obligation** — the claim that must become true — as a chain record with a content-addressed identity (`obligationId`), guards the graph's acyclicity (a parent must already exist; `detectCycles` as defense in depth), and returns `{taskId, obligationId, obligation}` plus a ready-to-paste `instruction`: the worker handoff text naming the claim, the acceptance criteria, and the worker's half of the protocol (§10) |
| `proof_delegate_submit` | `taskId`, `bundle` (a §5 export), optional `claimedGrade` (one of the five grades), `byWorkspace?` | adjudicates the bundle from its own bytes — the §5 verifier obligations, zero trust in the submitter — and additionally demands a *trust root*: the bundle's evidence chain MUST carry a signed checkpoint, naming the obligation minter's anchor key when this chain has one (at least some well-formed signed checkpoint otherwise — a signature is the one thing an empty-log forger cannot self-supply). Unanchored evidence caps the derived grade at `unproven`, whatever the self-consistency of the bytes, with the pinned problem `bundle evidence not anchored`. The engine records `artifactVerified` plus the `bundleFingerprint` that anchors what was turned in, derives the default grade from the anchoring (anchored bundle carrying a baseline → `proven`; anchored without one → `no-baseline`; unanchored → `unproven` — finer grades MUST be declared explicitly, and a declaration above what the evidence derives is capped with the discrepancy recorded on the submission), and returns the `composed` verdict over the rebuilt DAG; a claimed `proven` the artifact cannot back is booked as **forgery** (§10) |
| `proof_task` | `taskId?`, optional `ownGrade` (one of the five grades) | without `taskId`, the whole-graph overview (every task, its parent, claim summary, submission state); with it, the recursive composed verdict of that task's subtree — grade, forged/regressed/unproven children, waivers, blockers, cycles (§10). `ownGrade` is a *declaration*, never a measurement: the engine derives this workspace's own grade from the chain's `proof/verified` markers, and a self-report that exceeds the derived grade is refused with the reason on the record — testimony never lifts what the chain did not earn |
| `proof_training_export` | optional `fidelity` (`full` \| `private`), `provenanceFilter` (`agent-only` \| `all`), `license`, `path` | distills the evidence chain into a labeled training dataset (`dsh-training/1`, §11) and returns the manifest (reward-table snapshot, sample-counts, Merkle `root`, `provenanceFilter`), the chain `anchor` `{count, head, keyId?}` of the export moment, and `sampleCount`. **The samples themselves never ride the response** — a caller that wants the dataset passes `path` and the engine writes the JSONL samples plus the manifest document to disk (`writtenTo` names where); unknown enum values are refused loudly, never silently defaulted (omitted `fidelity` exports the `private` tier — zero output text — by default) |
| `proof_economics` | `computePerMs` (required, > 0), `humanReviewPerItem?` (≥ 0) | **a pure query**: replays verbatim the economics ledger the most recent rate-carrying verification marker on the chain recorded (§12) — label, timestamp, ledger bytes, plus the echoed rate card. Nothing is recomputed and nothing is priced here: the arguments are validated loudly (a malformed card is told off now, not on the next run) but they change no chain fact; no ledger on the chain answers the honest absence with the exact remedy |
| `proof_sla_quote` | `grade` (one of the five, required), `coverageAmount` (finite > 0, required), `confidence?` ([0, 1]), `currency` (`USD` only — anything else is refused, never converted), `deductible?` (≥ 0), `minPremium?` (≥ 0) | an insurance-style SLA quote over a graded proof (§12): `proven` earns an offer (`premium = coverageAmount × (1 − confidence)`), `regressed` is honestly denied, `stale` / `unproven` / `no-baseline` route to manual underwriting. The full quote — pricing content, exclusions, terms version — is content-addressed (`quoteId`) and lands on the chain as an `economics/quote` marker, so a quoted premium cannot be silently rewritten after the fact |

**APP/1.0 → APP/1.1 is a tool-surface expansion, nothing else.** The two transparency tools joined the conformance face; the vocabularies (§2), the content addressing (§3), the chain and checkpoint formats (§4) and the bundle format (§5) are byte-for-byte what APP/1.0 defined — an old bundle remains exactly as verifiable as the day it was minted. What did move is the dialect marking: `PROTOCOL_VERSION` is fingerprint material (§8), so every APP/1.1 manifest self-identifies as mutually unintelligible with every APP/1.0 one, and each side refuses the other instead of guessing. A deployment that runs no transparency log keeps a conforming APP/1.1 face: `proof_publish` / `proof_log_verify` answer a clean configuration error when no log is configured, and bundles without a `transparency` record verify as they always have.

**APP/1.1 → APP/1.2 repeats the same move on the same terms.** The three delegation tools joined the conformance face (7 → 10); the vocabularies (§2), the content addressing (§3), the chain and checkpoint formats (§4) and the bundle format (§5) are untouched, and the fingerprint moved by construction — an APP/1.1 consumer refuses an APP/1.2 manifest instead of guessing at delegation semantics it never agreed to. The three tools carry a three-party role split, one line each: the **orchestrator** speaks `proof_delegate` and `proof_task`; the **worker** proves the obligation in its own workspace with `proof_baseline` / `proof_verify` (or `proof_claim`) / `proof_bundle` and hands the export back through `proof_delegate_submit`; a third-party **auditor** verifies the published checkpoint history with `proof_log_verify` (§9) and the submitted bundles from their own bytes (§5). The delegation semantics themselves — obligations, the composition lattice, forgery — are specified in §10.

**APP/1.2 → APP/1.3 repeats it a third time (10 → 11).** The training-export tool joined the conformance face; the vocabularies (§2), the content addressing (§3), the chain and checkpoint formats (§4), the bundle format (§5) and the delegation semantics (§10) are byte-for-byte untouched, and the version-only fingerprint shift makes every APP/1.3 manifest mutually unintelligible with every APP/1.2 one — a consumer never silently accepts a dialect whose training-export semantics it has not implemented. The dataset itself — sample kinds, the reward table, privacy tiers, the provenance filter, content addressing and the chain anchor — is specified in §11.

**APP/1.3 → APP/1.4 repeats it a fourth time (11 → 13).** The verification-economics pair joined the conformance face (`proof_economics`, `proof_sla_quote`, plus the `economics` parameter on `proof_verify`); the vocabularies (§2), the content addressing (§3), the chain and checkpoint formats (§4), the bundle format (§5), the delegation semantics (§10) and the training export (§11) are byte-for-byte untouched, and the version-only fingerprint shift makes every APP/1.4 manifest mutually unintelligible with every APP/1.3 one — a consumer never silently accepts a dialect whose pricing semantics it has not implemented. The economics themselves — the run ledger, the SLA doors, the exclusions, the injected rate card — are specified in §12.

**Out of scope for v1:** `proof_jury`, `proof_jury_submit`, `proof_endorse`, `proof_conjure` and `proof_conjure_run` exist in the reference implementation but are NOT part of APP/1.4 conformance. They depend on host-held seams an open protocol cannot assume — an isolated deliberation model (Class B testimony), a human approval gate (Class C endorsement), and a sandbox plus session context for conjured tests. Hosts MAY expose them as extensions.

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

An APP/1.4 implementation MUST implement content addressing (§3), tamper evidence (§4) and the exchange format (§5) exactly as specified, and MUST expose the thirteen tools of §6. A transparency log (§9) is an optional deployment: the two transparency tools presuppose an operator-run log and MAY answer a clean configuration error when none is configured. The three delegation tools of §10 are part of the conformance face; an implementation that mints obligations MUST compose verdicts by the §10 lattice exactly. The training-export tool of §11 is likewise part of the conformance face; an implementation that mints datasets MUST follow the §11 reward table and honesty rules exactly. The verification-economics tools of §12 are part of the conformance face; an implementation that prices runs MUST follow the §12 ledger semantics exactly — null for the unmeasured, never zero; null per dollar at zero cost, never Infinity — and MUST NOT embed a price: the rate card is injected by the deployer at every pricing call, never a constant of the implementation.

**Implementation fingerprint.** `appFingerprint()` (`src/app/protocol.ts`) is `sha256(canonicalJson(...))` over the five vocabularies plus one string per load-bearing rule — `addressing: 'sha256(canonicalJson(v))'`, `chain: 'prev=sha256(prevLine)'`, `signature: 'ed25519(canonicalJson(checkpointPayload))'`. It is the dialect's digest: any change to a vocabulary value or to one of these rules MUST produce a different fingerprint. Producers stamp it into every manifest; consumers MUST refuse to interpret a bundle whose fingerprint they cannot reproduce, rather than guess at the dialect.

**Fingerprint negotiation and the ancestor table.** Refusal has one sanctioned exception, added when the reference implementation's genealogy had minted five dialects and orphaned every bundle older than the current one: a consumer accepts a manifest whose `(protocol, appFingerprint)` pair coherently matches any **known ancestor dialect** of its own genealogy — `LEGACY_PROTOCOL_VERSIONS`, each fingerprint recomputed from the live constants with only the version swapped, never a stale literal. This is safe exactly because every bump in this genealogy changed *only* the version byte the fingerprint digests: the vocabularies, rule strings, chain and bundle formats are byte-identical across generations, so a verifier that recognises a fingerprint can interpret the payload byte-for-byte as the producer wrote it. Acceptance under an ancestor is flagged (`legacyProtocol` in the reference `verifyBundle` result) so the reader sees they verified an older dialect. Anything else — a future version, a foreign implementation, or a *current* version string wearing a fingerprint this genealogy never produced under it — is refused with both digests named, so the refusal says exactly what diverged. A future bump that touches a vocabulary or a rule moves the fingerprint of every dialect computed from the then-current constants, and those old bundles are refused again — automatically, which is the refusal this section demands. The APP/1.0 → APP/1.1 bump is this rule applied honestly to the tool surface: the vocabularies and rule strings are untouched, but `PROTOCOL_VERSION` is itself fingerprint material, so the seven-tool expansion moved the fingerprint by construction — a consumer that could silently read a 1.1 manifest while believing it spoke 1.0 would never learn that two tools' semantics exist; the moved fingerprint makes the dialects refuse each other loudly instead. The APP/1.1 → APP/1.2 bump applies the same rule for the same reason: nothing but the three delegation tools moved, and the version-only fingerprint shift makes every APP/1.2 manifest mutually unintelligible with every APP/1.1 one — a consumer never silently accepts a dialect whose delegation semantics it has not implemented. The APP/1.2 → APP/1.3 bump repeats it a third time: the single training-export tool moved nothing else, and the version-only shift keeps every APP/1.3 manifest mutually unintelligible with every earlier dialect — a consumer never silently accepts a dialect whose training-export semantics (§11) it has not implemented. The APP/1.3 → APP/1.4 bump repeats it a fourth time: the two economics tools (and `proof_verify`'s `economics` parameter) moved nothing else, and the version-only shift keeps every APP/1.4 manifest mutually unintelligible with every earlier dialect — a consumer never silently accepts a dialect whose pricing semantics (§12) it has not implemented.

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

A workspace publishes its latest signed checkpoint through the engine's `publishCheckpoint()`, the `proof_publish` tool (§6), or the standalone auditor CLI (`dsh-proof-ptl append | head | verify`). All three are mirrors, not re-derivations — the entry carries the checkpoint's own `{count, head, at, sig, keyId}`, and the same checkpoint always addresses to the same leaf, so appending is idempotent by leaf hash: a replayed checkpoint is the same event, not a new one, and re-publishing can never pad the tree. But mirroring is not blindness: all three publishing paths select their checkpoint exactly the way the engine does (the latest well-formed signature-bearing checkpoint — never merely the last line's claim), and whenever the publishing host holds the key the selected checkpoint names, the checkpoint signature itself is adjudicated *before* the entry enters the tree — a checkpoint whose `sig` does not verify under the key it names is refused, not published. The log remains a dumb notary over what it *carries*; the door in front of it no longer notarises whoever last wrote to the workspace log.

A published bundle (§5) carries a `transparency` record pinning `{logId, sequence, leafHash, publishedHead, inclusionProof}`. The log-side audit runs six checks in order:

1. **leafMatch** — the entry at `sequence` hashes to the recorded `leafHash`: the checkpoint the verifier was shown is the one in the log;
2. **inclusion** — the audit path folds that leaf into the root of the head the bundle *pins* (`publishedHead`): RFC 6962 audit paths are size-specific, so a proof minted at publication size folds against the publication head, never today's;
3. **consistency** — the pinned head is still a provable prefix of the *current* head, chaining the publication statement to the present: this is the non-rewrite guarantee, since a rewritten or truncated history cannot produce a consistency proof to a root the operator already signed;
4. **logIdMatch** — the operator identity the bundle pinned and the identity on the current head agree; a silent operator flip mid-log would let a rewritten history wear a fresh signature;
5. **publishedHeadSig** — the bundle's own claim of publication is a signed statement ("this operator signed this head at this time"), and that signature verifies under the operator key; without the key this check is reported `not-checked` and **fails** the verification — a publication proof nobody verified is exactly the uncertain-equals-fail case, not a pass;
6. **headSignature** — the current STH verifies under the operator key.

Any failure names the broken check. A missing operator key for check 6 is reported `not-checked`, never valid, and never an accusation: the same refusal discipline as §5 — while checks 1–5 are adjudicable from public data and a log that cannot support them fails honestly rather than passing silently. A log with no bundle pinned self-checks the same way minus the leaf: recomputed root vs. the signed head, sizes agreeing, signature adjudicated.

### Trust model and honest limits

v1 specifies a **single-operator, file-backed log**. What is cryptographically guaranteed: the log's own history cannot be rewritten undetectably — an interior edit moves the root, a truncation shrinks the tree, both fail the head signature or the consistency proof, and the operator cannot sign a second self-consistent history without tripping the rewind guard. What is explicitly NOT guaranteed: a **split-view** operator — one serving different trees to different verifiers — cannot be caught by any single log alone; detecting it requires multiple witnesses or gossip between auditors (the full certificate-transparency answer), which is **future work**, not a property of this version. And per the dumb-notary principle, the log does not verify the workspace signatures it hosts: a published checkpoint proves publication, and the workspace signature is adjudicated separately by whoever holds the workspace public key.

Reference implementation: `src/core/transparency.ts` (pure domain — RFC 6962 Merkle tree, inclusion and consistency proofs, verifiers written as the exact mirror of the generators, pinned against the RFC's own §2.1.3 worked example) and `src/app/ptl-entry.ts` (the standalone auditor CLI). A three-step audit walkthrough ships as `examples/ptl-workflow.md`.

## §10 Responsibility DAG

Everything before §10 proves things *inside one workspace*. Delegation in a multi-agent system is a handshake with no memory: a parent task sends work down, a child agent reports "done", and the parent's proof silently inherits a claim nobody verified. APP/1.2 gives that handshake a topology and a law: a **cross-agent responsibility DAG** in which a delegated task carries a **proof obligation**, a parent task's `proven` is *preconditioned on all its children being proven*, and every edge is a bundle any party can re-verify.

**Obligations.** `proof_delegate` mints a `TaskObligation`: WHAT the child must prove (the `claim`, plus optional verifiable `acceptance` criteria), for whom (`issuedByWorkspace`), when, under which parent (`parentTaskId`). Its identity is the content address of the whole record — `obligationId` is the first 16 hex of `sha256(canonicalJson(obligation))`, the same shape and reasoning as claim ids — so rewording a claim mints a new obligation, never a silent edit of an old one. Delegation edges only point backwards in time (a parent MUST already exist), and the engine runs `detectCycles` over the resulting graph as defense in depth: a cycle anywhere is refused before composition — a circular responsibility chain proves nothing and MUST NOT be folded as if it did.

**Edges are bundles.** The child proves the obligation **in its own workspace** — `proof_baseline`, the work, `proof_verify` / `proof_claim`, `proof_bundle` — and submits the §5 export back with `proof_delegate_submit`. The parent adjudicates the submission from its own bytes (the §5 verifier obligations; zero trust in the submitter): `artifactVerified` records the adjudication, and `bundleFingerprint` — the order-independent digest over the manifest's content-digest column — anchors exactly which bytes the submission stands behind. This is where the §5 exchange format earns its keep: the edge of the DAG is a self-contained proof artifact, not an opinion crossing a trust boundary.

**The composition lattice.** A parent's grade folds its children pessimistically, in strict priority order:

1. **Forgery or regression outranks everything.** A child that *claimed* `proven` whose artifact does not verify is **forgery**; a child whose effective grade is `regressed` (claimed, or composed from below) is broken work. Either makes the parent `regressed` — and **no waiver can buy it out**: a waiver excuses *missing* work, never broken or forged work (the same symmetry as v0.11's rule that an endorsement cannot buy broken work).
2. **Else any unwaived child that is missing work** — never submitted, or submitted `stale` / `unproven` / `no-baseline` — makes the parent `stale`: a process gap that blocks `proven` without claiming anything was broken.
3. **Else every child is proven or waived**, and the parent's grade is its **own** evidence, reported as-is even when it degrades; a pure delegator (no evidence of its own) is `proven` — there is nothing of its own to fail.

Composition is recursive over the whole subtree, memoised (a grandchild shared by two parents composes once and answers both identically — the diamond), and an obligation is discharged by a submitted bundle or a recorded waiver — never by a green subtree alone: a task issued an obligation but submitted nothing stays *unsubmitted* at its parent's level even over a green subtree, because nobody proved ITS claim.

**Honest grades across a trust boundary.** The engine cannot re-run the child's checks — they ran in another workspace, against another baseline — so `claimedGrade` is testimony, kept strictly separate from `artifactVerified`. Self-consistency alone proves nothing (a bundle built from whole cloth out of the protocol's own public functions verifies "clean"), so the default derivation is anchored, not two-valued: an anchored, clean bundle carrying a baseline reads `proven`; an anchored bundle without one defaults to `no-baseline`; and evidence with no verifiable root — no signed checkpoint naming the obligation minter's anchor key (or, from an anchor-less minter, any well-formed signed checkpoint) — caps at `unproven` no matter how clean the bytes, with the problem pinned on the submission. Every finer grade (`unproven`, `stale`, `regressed`) is a workspace-local judgment the submitter MUST declare explicitly — a declaration above what the evidence derives is capped with the discrepancy recorded, and a declared `proven` the artifact cannot back is forgery, booked exactly like an inflated `proven` (priority 1). Fine-grained honesty across the seam rests on explicit declaration plus zero-trust artifact verification plus a signature the forger cannot self-supply, nothing else.

**Waivers.** `waiveDelegation` records a named human's risk acceptance (`by` and `reason` mandatory — an anonymous or unexplained acceptance is not an acceptance, it is an erasure) — and the acceptance is *authorized*, not just named: `by` must resolve to the host that holds the obligation minter's anchor key. A waiver from anyone else is refused loudly and recorded: an unauthorized risk acceptance is an event every reader of the chain should see, not a silent pass. The engine only keeps the books; whether a waiver lifts anything is the lattice's judgment, and over forged or regressed work it is refused by semantics, recorded and visible.

**Honest limits.** The composed verdict names forged children, regressed children, unproven children and waivers — descriptive lists in a fixed order, the same story for every reader. What the engine cannot do is substitute for the child's workspace: the artifact verdict is bundle verification (structure, digests, chain), not a re-execution of the child's checks; the fine grade rests on the submitter's explicit declaration, priced honestly by the forgery rule.

Reference implementation: `src/core/obligations.ts` (pure domain — obligations, submissions, the composition lattice, cycle detection; deterministic, no clock, no I/O) and the four engine verbs `delegateTask` / `submitDelegation` / `taskVerdict` / `waiveDelegation` (`src/engine.ts`), with the three MCP tools (`src/app/mcp-server.ts`) as the protocol face.

## §11 Training export

Everything before §11 proves work *as it happens*. §11 reads the same log afterwards and answers a different question: what did proving it **teach**? An evidence log is, among other things, a chronicle of agent behaviour with machine-verified outcomes attached — every record says what ran, what it printed, how long it took, and (read against the baseline, §1) what that run *meant*. Those labels are not the model's opinion of itself: they are differential facts under hash-chain protection (§4). Distilled into a dataset they become RL/DPO training pairs whose labels no annotator graded and no model self-reported — ground truth an agent-behaviour dataset normally spends a human label budget to approximate, available as a by-product of doing the work honestly. APP/1.3 standardizes that distillation (`dsh-training/1`) so a dataset is exportable, verifiable and aggregable across workspaces instead of trapped in one deployment's log.

**Two sample kinds ride in one schema.**

- **`verification`** — one per decisive observation (§2: `pass` / `fail` only): the context (checkId, check kind, discovery source, the session's changed paths) plus the verdict and the scalar `reward` that verdict earns under the reward table below. RL-shaped.
- **`flip-pair`** — one per adjacent disagreement in a check's decisive subsequence (chain order; non-decisive records neither break adjacency nor mint a pair), in DPO's fixed direction: `rejected` is **always** the fail side, `chosen` **always** the pass side. Which way the flip ran in time is not lost — it lives in the two `recordedAt` stamps — but the preference statement itself never points anywhere but away from red.

**The reward table — a written convention, snapshotted into every manifest.**

| verdict | reward | rationale |
|---|---|---|
| `still-passing` | 1.0 | the session's work left a green assertion green |
| `fixed` | 1.0 | the session repaired what was broken |
| `new-check` | 0.5 | a pass with no baseline to compare against — neutral |
| `still-failing` | 0.5 | pre-existing is not the agent's fault; charging 0 would be as dishonest as crediting 1 |
| `regression` | 0.0 | the session broke what held |
| `new-failure` | 0.0 | the session shipped a check that never held |
| `not-run` | 0.0 | unreachable in samples by construction; present so the table is exhaustive law |
| `indeterminate` | *excluded* | **unknown is not zero** — a decisive run whose baseline produced no decisive answer is EXCLUDED from the dataset rather than labeled 0; a real pass punished like a regression is worse data than no data |

The table is pinned by tests, deliberately not a knob (a reward table that varies per export is a dataset whose labels cannot be compared), and **snapshotted into every manifest** — a dataset always states the law its numbers were minted under, even if the law later changes.

**Privacy tiers — `private` is the default.** Output prose can carry secrets; digests cannot (they are one-way content addresses). A `private` export carries **zero output characters** — structure, labels and digests only — so a dataset can leave the machine before anyone has read every line of it. `full` adds each record's normalized excerpt (§3), truncated to 200 characters. Any degradation runs toward silence, never leakage.

**Provenance filter — `agent-only` is the default.** A reward of 1.0 asserts *"the agent's edit kept the suite green"* — a causal claim. When the change set contains a path attributed `external` (a human was also editing the workspace — attribution is the deployer's change-set provenance, not a protocol construct), that sentence is false, so under `agent-only` **one external path voids the whole session's verification labels** — better an empty dataset than a mislabeled one. Flip-pairs survive the void: pass-then-fail within one chain is a temporal fact about the check, whatever hand moved the files. The manifest records the requested filter honestly, even — especially — when the filter emptied the dataset.

**Content addressing and the chain anchor.** Each sample's address is `sampleHash = sha256(canonicalJson(sample))[:16]`, and the manifest's `root` is the order-independent Merkle root (§3) over the samples' addresses — the same discipline as a baseline's root, so editing **one character of one sample** moves the root: a dataset cannot be quietly re-labeled after the fact, and two exports can be compared without trusting either exporter. The manifest (`schema`, `fidelity`, `workspaceKey`, `generatedAt`, `counts`, `rewardTable`, optional `license`, `provenanceFilter`, `root`) makes the dataset self-describing. Every export is additionally pinned to the chain state at the export moment by an **anchor** `{count, head, keyId?}` — the last signed checkpoint (§4), or the last well-formed checkpoint of an unsigned chain — so a consumer holding the log can re-derive the dataset and check it against the anchor, or know they are looking at a different chain. The samples themselves never ride a tool response (§6): a dataset can be huge, and the response carries the manifest, anchor and count, with `path` writing the JSONL to disk.

**Honest limits**, stated rather than hidden:

- The verdicts underneath the labels are machine-verified differentials, but the 1.0 / 0.5 / 0.0 **pricing is a declared convention, not ground truth** — a dataset consumer who disagrees with `still-failing = 0.5` must re-price, and the reward-table snapshot in the manifest tells them exactly what they are re-pricing.
- **Flip pairing is an adjacency heuristic**: "adjacent" means adjacent in the exported log's decisive subsequence, not a claim that nothing intervened in the world between the two observations.
- The **`private` tier removes output text, not context**: samples still carry workspace paths and output digests — a path can itself be sensitive, and a digest can confirm a guess. Dataset consumers owe the data care even at private fidelity.
- **Cross-deployment aggregation trust is unsolved**: merging datasets from multiple exporters raises "whose data is this, and was it poisoned?" — questions this version does not answer. Anchoring dataset provenance in the transparency log (§9) — anti data-laundering for training sets — is the future direction, not a property of APP/1.3.

Reference implementation: `src/core/training.ts` (pure domain — the schema, reward law, sample shapes, distillation; deterministic, no clock, no I/O) and the engine verb `exportTrainingData` (`src/engine.ts` — chain state in, `DistillInput` assembled, dataset and anchor out), with `proof_training_export` (`src/app/mcp-server.ts`) as the protocol face.

## §12 Verification economics

Everything before §12 made trust **recomputable**; §12 gives it a **unit cost**. The seed was planted in v0.9: the bayesian scheduler already ranked checks by expected information gain per millisecond — certainty per unit cost, as a scheduling decision. §12 restates the same measured facts as a statement any party can read: what one verification run consumed, what the spend bought, and what an insurer-style service level over a `proven` grade is worth. Two disciplines govern every number: **only the measurable is measured** (durations and counts come off records the engine already produced; what was not measured is not invented), and **prices are injected, never embedded** (the deployer supplies a `RateCard`; swap the card and the same evidence reprices — a hardcoded rate would be a lie with a decimal point).

**The run ledger.** A verification that runs with `economics: {rate}` returns — and records on the chain — a ledger restating the run as a statement of cost and purchase:

- `computeMs` — Σ `durationMs` over **every** record; a timed-out check burned the milliseconds all the same.
- `cost` — `computeMs × computePerMs + humanReviewItems × humanReviewPerItem` under the injected card, rounded to six decimal places (the money spec — floating-point dust never reaches a statement).
- `assertions` — the decisive records: each decisive check answer is one verified assertion (`pass`/`fail` settle the check's question; the non-decisive statuses never did). `skippedCount` rides along so the statement shows spend that bought no assertion rather than hiding it — sunk cost, visible.
- `costPerAssertion` — `cost / max(1, assertions)`.
- `confidencePurchased` — `posterior − prior`: the marginal confidence the verification actually bought. `null` when either side was never measured — never zero, because an unmeasured purchase must not be pretended away; a negative value is reported as-is (a run that *lost* confidence is a real outcome).
- `confidencePerDollar`, `natsPerDollar` — `null` whenever `cost ≤ 0`: a free run bought confidence, but it bought nothing *per dollar*, and `Infinity` on a financial statement is never an answer.
- `infoNats` — Σ `H(prior) − H(posterior)` per check factor, in nats, **signed**: a factor folding toward failure contributes negatively, because paying to learn the claim broke is still information gained — honest bookkeeping counts information, not news enjoyed.

**Input-domain discipline (reference implementation v0.22).** Every priced amount sits under a money ceiling (1e15) whose ×10⁶ rounding cannot overflow — an input above it is refused at the gate, never computed with, so no input can mint `Infinity` onto a statement or fold two different amounts onto one `quoteId`. The grade vocabulary is enforced at the same gate: a grade outside the five §2 values routes to manual underwriting, never to a branch it does not name. And a record whose `durationMs` is not a finite non-negative number books as *unknown* (counted in `rejectedDurationRecords`, contributing nothing to `computeMs`/`cost`) — a measurement that never happened is not zero, and it is not a number either.

The priced run is a **chain fact**: the ledger rides the `proof/verified` marker exactly as the wave plan and coverage summary do, and `proof_economics` replays those bytes verbatim — it never recomputes a price, never trusts a caller's summary, and answers the honest absence (no rate-carrying run on the chain) with the exact remedy. The contract paths each carry their own honest caliber: a `docs-only` verdict consumed no machine compute and no paid review, so its ledger prices an honest zero; an `llm-jury` verdict prices the testimony it consumed (`humanReviewItems` counts exactly the B/C witnesses the verdict rested on); the machine contract path reports the **final** confidence — the number after any κ fusion — as its posterior.

**The SLA pricer — three doors, no fourth.** `proof_sla_quote` turns a graded proof into an insurance-style offer (`dsh-proof/SLA-1`):

- `proven` + a measured confidence in [0, 1] → **offer**: `pUndetected = 1 − confidence`, `premium = max(minPremium ?? 0, coverageAmount × pUndetected)`. The deductible is claim-time excess, passed through verbatim — never added into the premium. **No second β**: the confidence supplied here already absorbed every false-pass discount on its way in (the organic 0.02 of the scheduler, the synthetic 0.15 of v0.12), so `1 − confidence` *is* the comprehensive probability a defect went undetected; multiplying another β in would discount the discount and quietly under-price the book.
- `regressed` → **denied**, in one honest sentence: the delivery failed verification — the claim already broke. Insuring it would be selling coverage for a known loss.
- `stale` / `unproven` / `no-baseline`, or a `proven` without a measured (or in-range) confidence → **manual underwriting**: evidence exists but this formula honestly cannot price it; a human underwriter takes over rather than a number being invented.

Every quote is **content-addressed over its own pricing content**: `quoteId` is the first 16 hex of the sha256 over `{vehicle, grade, confidenceAtIssue, decision (class + numbers, never the prose), exclusions, termsVersion}`. The same inputs mint the same bytes; changing the coverage by one cent mints a different quote; rewording a denial re-prices nothing. The rate card is deliberately **not** part of the address — repricing the deployment leaves the quote bytes alone, so a quote is a fact about the risk, not about the day's prices. The full quote lands on the chain as an `economics/quote` marker: a quoted premium cannot be silently rewritten after the fact.

**Exclusions — the honest edges, written into the policy.** Every quote carries five exclusion clauses verbatim, pinned by the tests (an exclusion nobody can quote is a promise nobody made):

1. Attribution keys on command strings — the same defect hidden behind a rewritten command line is not covered (§7's shell blind spot, restated as policy).
2. The transparency log witnesses one operator's view — a divergent fork view held by another operator is not covered (§9's split-view limit, restated as policy).
3. Evidence appended after the last signed checkpoint carries chain cover only — the tail window is not covered.
4. Human endorsements price accepted risk, not verified fact — the accepted-risk portion of an endorsement is not covered (§10's waivers, restated as policy).
5. Non-decisive outcomes (timeout, error, aborted, skipped) verified nothing — the surface they never answered is not covered.

**Honest limits**, stated rather than hidden:

- The rate card is the **deployer's injected cost basis, not a real bill**: `computePerMs` and `humanReviewPerItem` are declarations of what compute and review cost a deployment, and the ledger is only as honest as the card.
- `pUndetected` is a **model probability, not actuarial claims history**: it descends from the v0.9 posterior, with all of that model's admitted distortions (independence above all) — no loss data feeds it.
- The premium is an **illustrative, model-based quote, not a financial product**: no regulator, no reserve, no claims process stands behind `dsh-proof/SLA-1`; it is a written convention for pricing residual risk, in the same spirit and with the same limits as the §11 reward table.
- A negative `infoNats` means the money bought **bad news** — the claim's probability fell. That is still information, deliberately reported with its sign; the ledger counts learning, not comfort.

Reference implementation: `src/core/economics.ts` (pure domain — the ledger, the pricer, the exclusions; deterministic, no clock, no I/O, every amount at the six-decimal money spec) and the engine verbs (`VerifyOptions.economics` on `verify` / `verifyContract`, `slaQuote` — input defense first, the ledger on the `proof/verified` marker, the full quote on the `economics/quote` marker), with `proof_verify`'s `economics` parameter, `proof_economics` and `proof_sla_quote` (`src/app/mcp-server.ts`) as the protocol face. The rate card is a **query-time parameter, not a configuration key**: pricing rides the tool call so the same chain reprices under different cards without redeploying anything.
