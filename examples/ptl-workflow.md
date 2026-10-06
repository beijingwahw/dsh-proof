# Proof Transparency Log — the three-step audit workflow

A signed checkpoint proves an agent's evidence chain was intact *at the moment
the engine signed it*. A **Proof Transparency Log (PTL)** proves something
stronger and later: that the checkpoint you were shown is the same one
everyone else was shown, and that nobody — operator included — has quietly
truncated or rewritten the published history since.

Three roles, three steps:

- **Agent** — delivers work inside a dsh-proof-instrumented workspace.
- **Operator** — publishes signed checkpoints into an append-only merkle log
  and signs a tree head (STH) over it after every append.
- **Buyer / third-party auditor** — holds a bundle and (optionally) a copy of
  the log, and verifies everything locally.

## Step 1 — Agent delivers: verify, then checkpoint

The agent runs the normal proof loop (`proof_baseline` once, `proof_verify`
per delivery, `proof_claim` at the boundary). Every verification closes with
an **engine-signed checkpoint** appended to the workspace evidence chain — a
`{count, head, workspaceKey, at}` payload signed by the host-held Ed25519
key. The agent can rewrite every hash in the log; it cannot forge that
signature.

```
# inside the workspace (MCP tools, or the harness plugin)
proof_verify { changed: ["src/checkout.ts"] }   # -> grade, and a signed checkpoint
```

## Step 2 — Operator publishes: append into the transparency log

Whoever owns delivery (a CI job, a release engineer, a marketplace gate)
copies the workspace's latest signed checkpoint into the append-only log and
signs a fresh tree head. The log is a directory — typically **outside** every
workspace it publishes for:

```bash
DSH_PROOF_ROOT=/srv/workspaces/checkout-app \
dsh-proof-ptl append --log /srv/ptl/checkout-log
```

One line of JSON comes back — keep it with the release records:

```json
{"sequence":0,"duplicate":false,"leafHash":"3f9c…","treeSize":1,"root":"a41b…","logId":"e77d0c9a1b3f4e20"}
```

What happened:

- the workspace was located exactly the way the MCP server locates it
  (`DSH_PROOF_ROOT`, `DSH_PROOF_TRUST_DIR`, `DSH_PROOF_EVIDENCE_STORE`,
  `DSH_PROOF_EVIDENCE_DIR` — same derivation, same bytes);
- the **latest checkpoint carrying a non-empty signature** was appended as
  one leaf (republishing the same checkpoint is a no-op: `duplicate:true`);
- the operator key at `<log>/operator-key/` was created on first use and
  signed a new **STH** `{logId, treeSize, root, at, sig}` over the whole log;
- `dsh-proof-ptl head --log <dir>` prints the current STH at any time —
  publish that (release notes, contract annex) so third parties can pin it.

## Step 3 — Third party verifies: the log adjudicates the bundle

The buyer receives the delivery as an **APP/1.0 proof bundle** whose manifest
carries a `transparency` record (leaf hash, sequence, inclusion proof, and
the STH as it stood at publication). With the log directory (or a copy of
it), the buyer runs the audit locally — no trust in the operator's future
behaviour required:

```bash
dsh-proof-ptl verify --log /srv/ptl/checkout-log \
                     --bundle checkout-app.bundle.json \
                     --operator-key
```

```json
{"ok":true,"checks":{"leafMatch":true,"inclusion":true,"consistency":true,"headSignature":true},"sequence":0,"treeSize":2}
```

Four independent checks, in order:

1. **leafMatch** — the entry at `sequence` hashes to the recorded `leafHash`:
   the checkpoint the buyer was shown is the one in the log.
2. **inclusion** — a merkle path proves that entry is covered by the current
   signed tree head.
3. **consistency** — because the published STH an older bundle pinned is
   still a provable prefix of the current tree, the log has grown *append-only*.
   This is the "cannot rewrite history" guarantee, in one sentence: **a
   consistency proof is a set of tree nodes from which both the old root and
   the new root re-derive, so a truncated or edited history cannot reproduce
   the old signed root the buyer already holds.**
4. **headSignature** — the current STH itself is signed by the operator key
   (`<log>/operator-key/`, handed over or published with the log).

Any failure exits `1` with `"ok":false` and names the broken check; usage
errors exit `2`. Without `--bundle`, `dsh-proof-ptl verify --log <dir>`
self-checks the log (recomputed merkle root vs. STH root, sizes, head
signature) — run it in CI after every append.
