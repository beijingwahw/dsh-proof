# dsh-proof

**Evidence-driven completion proof & regression attribution** — a DeepSeek Harness plugin.

> Turn "I'm done" from a self-report into a recomputable evidence chain.
> Turn "I fixed it but broke something else" from a post-mortem into in-flight attribution.

```
$ proof_claim "fixed the login redirect bug and added a regression test"
✓ PROVEN — fixed the login redirect bug and added a regression test
evidence root: 9f2c1ab47d0e
PROVEN — 3 check(s) passing, 0 regression(s), 1 pre-existing failure(s) left untouched.
```

**Install**

```sh
dsh plugin --profile web add dsh-proof        # from a registry
dsh plugin --profile web add ./dsh-proof      # from a local checkout
```

📖 **[中文文档](./README.zh.md)** — full gap analysis, architecture and configuration reference.

---

## The gap

The DSH ecosystem has 5000+ plugins across 14 categories. None of those categories is **verification**.

Three of the most common complaints from agent users share a single root cause — the agent's beliefs are not bound to the repository's facts:

1. *"The agent said it was done, and the problem is still there."* A self-report cannot be falsified.
2. *"I fixed one thing and broke three others."* Without a baseline you cannot tell pre-existing breakage from newly-caused breakage.
3. *"I edited the file myself and the agent had no idea."* World-model drift; the model keeps reasoning on stale code.

Existing plugins each cover part of it: `dsh-completion-guard` uses checklists the model ticks itself, `dsh-rollback` undoes changes after the fact, Aegis is a prompt-level methodology. **None of them produce machine-measured evidence at runtime.** That is what `dsh-proof` does.

---

## Three pillars

**1 · Baseline.** Before work starts, discover the workspace's *objective* checks (npm scripts, pytest/mypy/ruff, `go test`, `cargo test`, `make test`, …) and run them. Each outcome is recorded as content-addressed evidence: `evidenceId = sha256(canonical(record))`.

**2 · Change-impact incremental verification.** Only re-run the checks this change set made stale, selected through a reverse-dependency closure (import graph) plus path coupling. Lockfiles, `tsconfig`, CI workflows and other global invalidators force a full run. Uncertainty *widens* the selection — over-running costs a minute, under-running hides a break.

**3 · Claim → evidence.** `proof_claim` is the only compliant way to state completion. It re-runs the affected checks and returns `proven: true` only when nothing regressed and coverage is complete.

### The headline distinction

| baseline | current | verdict | whose fault |
|---|---|---|---|
| pass | pass | `still-passing` | — |
| pass | fail | **`regression`** | **this session**, with suspect files |
| fail | fail | `still-failing` | pre-existing — **not charged to you** |
| fail | pass | `fixed` | this session fixed it |
| absent | pass | `new-check` | first sight; counts as passing only if it actually ran |
| absent | fail | `new-failure` | honestly unattributable |
| present | not run | `not-run` | evidence stale |
| either side skipped/timeout/aborted/error | — | `indeterminate` | **neither credit nor blame** — the honest middle |

Working in an already-red repository is the normal condition. `dsh-proof` does not require you to fix history before you can prove you broke nothing. The verdict lattice is three-valued: credit (`still-passing`, `fixed`, a decisively-run `new-check`), blame (`regression`, `still-failing`, `new-failure`), and neither (`indeterminate`, `not-run`, a `new-check` that never ran) — unknown never borrows certainty from either side, and `summary` carries a separate `indeterminate` count.

### Grades

`proven` · `regressed` · `stale` · `unproven` · `no-baseline`

Missing evidence is never papered over: a check that could not produce a decisive result makes the claim `stale`, not `proven`.

---

## Four model-facing tools

| tool | purpose |
|---|---|
| `proof_status` | baseline, discovered checks, latest evidence, evidence-log integrity |
| `proof_baseline` | establish/refresh the baseline (runs every discovered check) |
| `proof_verify` | incremental verification + grade + regression attribution |
| `proof_claim` | state a claim **and** prove it; `blockers` is the to-do list |

All four follow DSH's hard contract: `execute` returns one canonical JSON value, prose lives in `output.render`, and UI cards come from **pure** `presentCall` / `presentResult` / `presentationMeta` projections so a session-log replay reproduces the identical card.

## Runtime enforcement, not prompt hope

| extension point | mechanism |
|---|---|
| `tools/pre-execute` | with `requireBaseline: ask`, mutations require user approval until a baseline exists |
| `tools/pre-execute` | with `evidenceStore: workspace`, mutation tools touching the evidence store are routed through user approval |
| `tools/result` | observes every tool result; maintains the dirty set and file fingerprints |
| `agent/turn-stopping` | injects corrective context when a turn mutated the workspace without a proven claim, flags files changed outside the tool stream, and (with `requireBaseline: warn`) reminds the agent to establish a baseline first |
| `ctx.systemPrompt.section()` | publishes the `proof:policy` section so the model knows the rules exist |

## Trust model (v0.2): the adversary is the auditee

The agent under audit has file-write tools. It could rewrite `.proof/` wholesale and recompute every self-consistent address with the hashing functions this very package exports — self-addressing alone only catches naive tampering. v0.2 separates the prover from the verifier with four layers:

1. **Hash chain** — every line carries `prev = sha256(previous line)`; editing or removing any line breaks the link into the next.
2. **Signed checkpoints** — a checkpoint commits to `{count, head}` and is signed with a host-held Ed25519 key (`$DSH_HOME/proof/keys/`, never inside the workspace). The agent can forge a whole chain; it cannot forge a signature.
3. **Out-of-band anchor** — the highest checkpoint ever written is mirrored next to the key, outside the workspace. Truncating or rewinding the log is detected as `rewind`.
4. **Baseline digest in the chain** — `baseline.json` is plain JSON, so its sha256 is recorded as a chained marker at save time; later substitution trips `baselineTampered`.

By default (`evidenceStore: host`) the log itself lives under `$DSH_HOME/proof/workspaces/<key>/`, outside the agent's sandboxed writable area. `proof_status` surfaces the telemetry: `chainMode`, `checkpoints`, `chainIntact`, `rewindDetected`, `baselineTampered`, plus the v0.7 triage fields (`unverifiableCheckpoints`, `anchorForged`) and the checkpoint-window remainder (`tailRecords`).

## Change-set provenance (v0.3): content-anchored, attribution-aware

"What changed" and "who changed it" are now separate questions. The old change set was just `git status` — pre-baseline dirt, the user's IDE edits, and the agent's tool edits all charged to the session together. v0.3 rebuilds it:

1. **Content-anchored baseline** — establishing a baseline digests every dirty file (`dirtyDigests`). Baseline checks ran against the working tree *as it was*, so those bytes, not a commit, are the diff anchor. Dirt unchanged since the baseline is excluded; a dirty file *reverted* to HEAD still counts as changed (`git diff HEAD` cannot see that); clean-at-baseline files resolve through `git diff <baselineHead>` plus untracked files.
2. **Provenance** — the session-level tool-touch set classifies every changed file as `agent` / `external` / `explicit` / `unknown`.
3. **Attribution split** — `attributedTo` only charges the session; external edits land in `externalSuspects`. A regression the *user* caused in their IDE is still reported honestly, but its rationale reads "changed outside the agent's tool stream — not charged to this session".

The method is surfaced as `attributionMethod` (`baseline-content` / `git-head` / `dirty-fallback` / `explicit`) so degradation is visible, and `proof_verify` renders an "EXTERNAL edits" section with the files not charged to the agent.

## LSP-fused impact (v0.4): dual-source confidence

Impact analysis upgrades from regex approximation to a fusion of two edge sources. The trick: `goToDefinition` placed *on the module specifier of an import statement* resolves to the file that specifier binds to — which both verifies the regex graph's approximate edges and discovers **workspace-internal imports regex cannot see** (tsconfig `paths` aliases, package-internal paths): real missed-breakage blind spots in monorepos.

Union semantics keep soundness absolute: verified and approximate edges are unioned; a missing language server, a failed query, or an exhausted budget simply leaves the edge approximate — *precision degrades, coverage never does*. Results are cached per (file, content version, position) with a hard per-build budget (`lspQueryBudget`, default 400), and the regime is surfaced as `impactPrecision`: `lsp-verified` / `approximate` / `forced`.

## Smart excerpting (v0.5): spend the budget where the failure lives

`headChars` used to be a dead knob — the value reached the engine but never the domain layer. v0.5 wires it into a real excerpt budget and upgrades how it is spent. Naive head truncation has a structural flaw: test output opens with a banner ("✓ 50 passing") while the assertion, the diff, and the stack trace live in the middle or at the end — truncation cut exactly what the model needs to fix the bug.

The default `balanced` strategy allocates in three segments: the **first salient failure line** (AssertionError / expected-received / Traceback / stack frames / ✖ / not ok / timed out …) is always kept when it fits within half the budget; a **line-aligned tail window** keeps stack traces intact (never cut mid-word); and `[... N chars omitted ...]` markers account for every dropped character (`outputTruncated` / `outputOmittedChars` ride on the evidence record). The hard clamp trims tail, never the salient middle. Everything is a pure function of (text, config), so content addressing is unaffected. Regression narratives and `proof_verify` failure details now quote the first *informative* line, not the first line. `excerptStrategy: head` preserves the legacy behaviour.

## Location-independent addressing (v0.6): one failure, one address, any machine

Compiler errors and stack traces carry absolute paths, so digests used to vary per machine and per checkout directory — the same test outcome never addressed identically twice across machines, and usernames (`/home/alice/...`) leaked into records that may be exported for audit. v0.6 canonicalises captured output before hashing: **root → `$WORKSPACE` (specific first)**, **home → `$HOME` (general after)** — a workspace under the home directory still collapses to `$WORKSPACE/...` while sibling paths become `$HOME/...`; Windows paths match in either slash style. With `normalizeHome` (default on), the same failure produces the *identical* `outputDigest` and `evidenceId` on any machine, under any checkout, for any user — the dedupe/comparison primitive a proof transparency log rests on — and no username ever enters an evidence field. Without canonical roots, behaviour is byte-for-byte legacy.

## Honesty hardening (v0.7): unknown never rounds up to "ok"

A deep-read pass closed every path that could round uncertainty into good news. The **verdict lattice** is three-valued: non-decisive statuses (`skipped` / `timeout` / `aborted` / `error`) yield `indeterminate` — neither credit nor blame, counted separately — and blame requires a decisive baseline pass, credit a decisive baseline fail. Audit **trust triage** is three-state: a signature this host cannot check (no signer, foreign keyId) is `unverifiableCheckpoints` — a missing capability, not a forgery charge — while the anchor's own signature is now verified (`anchorForged`). Engine honesty edges: when git is unavailable (`gitAvailable?()` reports `false`) the change set is marked `degraded` and the engine **forces the full check set**, surfacing `VerifyOutcome.degraded`; an aborted baseline never lands on disk (evidence still enters the chain under a `baseline/aborted` marker); signer load failures degrade loudly via a `trust/signer-unavailable` chain marker; the evidence log writes through a **single-flight queue** so concurrent appends cannot fork the chain. Soundness closure: monorepo subpackage checks run in their own `cwd`, dynamic and multi-line imports produce impact edges, porcelain `-z` renames parse both paths, Windows drive-letter paths enter the path domain, and multi-byte output survives chunk boundaries.

## Architecture

```
src/core/*      pure domain — zero @deepseek-ai/* imports, all I/O through ports
src/engine.ts   ProofEngine — the imperative façade hosts call
src/dsh/*       thin Cordis adapter — tools, hooks, prompt section
src/vendor/     contract snapshot pinned to dsh v0.2.1-alpha.1
```

The domain core is framework-free on purpose: it is fully unit-testable offline, and it survives DSH's preview-phase breaking changes. At runtime `@deepseek-ai/dsh-tools` and `@deepseek-ai/cordis` resolve from the user's dsh installation as peer dependencies.

## Verifying it

```sh
npm install
npm run typecheck     # tsc --noEmit
npm test              # 159 tests, node:test
npm run build
npm run bundle:check  # packaging contract self-check
```

The suite includes a **real-shell integration test** (`test/07-integration.test.ts`): it builds a throwaway project, actually runs `npm run --silent test`, breaks something, and asserts the pipeline reports `regressed` with the offending file attributed.

## Configuration

Every tunable is a `cordis.yml` field — no hardcoded knobs. See [README.zh.md § 八](./README.zh.md#八配置) for the full catalogue and the `checks` schema.

```yaml
- insert:
    - id: dsh-proof
      name: dsh-proof
      config:
        requireBaseline: warn      # off | warn | ask
        impactGraph: true
        driftDetection: true
        enforceOnTurnEnd: true
```

## Honest limits

- Check discovery is heuristic. For monorepos or custom build systems, declare `checks` explicitly with `paths` so incremental verification stays precise.
- The dependency graph is approximate and errs toward over-inclusion. Dynamic `import()` calls, multi-line ESM imports and Python dotted imports produce edges since v0.7; reflection and string-built paths still cannot be resolved.
- Checkpoint cadence leaves a window (v0.2): records after the last signed checkpoint are chain-covered but not checkpoint-covered. The window is bounded by `checkpointEvery`, closed at every baseline/verify/claim boundary, and *visible* — `proof_status` reports `tailRecords`, the count of records since the last checkpoint. The anchor protects against the audited agent, not against a fully compromised host.
- On machines without the signing key, signed checkpoints cannot be adjudicated locally: the audit reports them as `unverifiableCheckpoints` (a missing capability, not a forgery charge — the audit does not fail on it; anchor count/head comparison still bounds rewind).
- `proven` permits pre-existing red checks — they are reported prominently but not charged to the session. Deliberate, not a hole.
- It orchestrates and attributes your existing objective checks; it does not write tests.
- DSH is a developer preview and its plugin contract changes. This plugin pins a minimal contract snapshot and declares peers rather than bundling, but upstream shifts still need re-alignment.

## License

MIT
