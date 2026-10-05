# Agent Proof Protocol (APP) 1.0

**An open standard for machine-verifiable completion claims.**

| | |
|---|---|
| Status | Draft |
| Protocol name | `agent-proof-protocol` |
| Version | `APP/1.0` |
| Reference implementation | dsh-proof v0.14.0 |
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
  "protocol": "APP/1.0",
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

`files` MUST list `evidence.jsonl` (the chained log); `baseline.json` and `anchor.json` are optional but SHOULD be included when they exist. `appFingerprint` names the producing implementation's dialect (§8), so a consumer detects vocabulary drift before interpreting anything.

**Verifier obligations.** A verifying party trusts nothing from the producer. It MUST recompute every file digest in `files` and reject on any mismatch; walk the chain (§4) and reject breaks, corrupt lines, count/head-invalid checkpoints; re-verify each record's self-addressing; re-verify checkpoint signatures when it holds — or can obtain — the named key; resolve the anchor's monotonicity checks when the anchor is available; and re-derive the baseline digest recorded on the chain before believing the baseline file. A missing adjudication capability (no key, no anchor) is recorded as such, never rounded up to a forgery charge.

## §6 Verification API

APP/1.0's conformance surface is five model-facing tools (reference: `src/dsh/tools.ts`):

| tool | input (essentials) | output (essentials) |
|---|---|---|
| `proof_status` | — | baseline presence, discovered checks, latest evidence per check, chain mode and integrity. Read-only |
| `proof_baseline` | — | runs every discovered check, records evidence, saves the baseline view, checkpoints |
| `proof_verify` | `changed?: string[]`, `all?: boolean` | grade, per-check verdicts, regression attribution, evidence root |
| `proof_claim` | `claim`, optional contract params (`kind`, `budgetMs`, `review`, `entryPoints`) | `proven: true` only when the contract's obligations all hold; otherwise `blockers` is the to-do list |
| `proof_bundle` | — | assembles the §5 bundle: manifest (with `appFingerprint`) + files, digests recomputed at pack time |

**Out of scope for v1:** `proof_jury`, `proof_jury_submit`, `proof_endorse`, `proof_conjure` and `proof_conjure_run` exist in the reference implementation but are NOT part of APP/1.0 conformance. They depend on host-held seams an open protocol cannot assume — an isolated deliberation model (Class B testimony), a human approval gate (Class C endorsement), and a sandbox plus session context for conjured tests. Hosts MAY expose them as extensions.

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

An APP/1.0 implementation MUST implement content addressing (§3), tamper evidence (§4) and the exchange format (§5) exactly as specified, and MUST expose the five tools of §6.

**Implementation fingerprint.** `appFingerprint()` (`src/app/protocol.ts`) is `sha256(canonicalJson(...))` over the five vocabularies plus one string per load-bearing rule — `addressing: 'sha256(canonicalJson(v))'`, `chain: 'prev=sha256(prevLine)'`, `signature: 'ed25519(canonicalJson(checkpointPayload))'`. It is the dialect's digest: any change to a vocabulary value or to one of these rules MUST produce a different fingerprint. Producers stamp it into every manifest; consumers MUST refuse to interpret a bundle whose fingerprint they cannot reproduce against their own constants, rather than guess at the dialect.

**Backward compatibility.** Evolution of the canonical addressing rules MUST NOT change the address of any existing value. The sanctioned mechanism is additive optional fields that are *omitted* (never `null`) when absent — canonical JSON drops them, so historical records keep their digests, and old artifacts that predate a field skip (rather than fail) its checks. This is the standing precedent of the reference implementation: `Evidence.source`, `synthetic` and `coverage`, `WorkspaceSnapshot.dirtyDigests`, and the anchor's `workspaceKey` were all added this way, without moving a single existing address.

A vocabulary change (a new verdict, a renamed status) is not a compatible evolution: it changes the fingerprint and thereby names a new dialect, and bundles that carry it MUST say so in their manifest.
