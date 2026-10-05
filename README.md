# dsh-proof

**Evidence-driven completion proof & regression attribution** — a DeepSeek Harness plugin.

> Turn "I'm done" from a self-report into a recomputable evidence chain.
> Turn "I fixed it but broke something else" from a post-mortem into in-flight attribution.

```
$ proof_claim "fixed the login redirect bug and added a regression test"
✓ PROVEN — fixed the login redirect bug and added a regression test
evidence root: 9f2c1ab47d0e
PROVEN (p≈0.97) — "fixed the login redirect bug and added a regression test" is backed by evidence root 9f2c1ab47d0e: 3 check(s) passing, 0 regression(s), 1 pre-existing failure(s) left untouched.
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

**3 · Claim → evidence.** `proof_claim` is the only compliant way to state completion. It re-runs the affected checks and returns `proven: true` only when nothing regressed and the claim is certified — posterior ≥ `certifyTarget` under the default bayesian scheduler, full coverage in `set` mode.

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

Missing evidence is never papered over. Under the default `bayesian` scheduler (v0.9) the boundary is a confidence target: the claim is `proven` once its posterior crosses `certifyTarget` (narrative: `PROVEN (p≈0.97)`), `stale` below it — skipped checks carry their remaining uncertainty into the posterior instead of being hidden; with `scheduler: 'set'` a check that could not produce a decisive result makes the claim `stale`, not `proven`.

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

## Completeness closure (v0.8): books that balance, storage that endures

The v0.7 pass closed paths where *unknown* rounded up to "ok"; v0.8 closes paths where the **facts themselves** were wrong — miscounted, mangled by crashes and restarts, or mistranslated by the adapter layer. **Excerpt truth-in-budgeting**: the budget now bounds the assembled `text` itself — the omission marker and joining newlines count against it — uniformly for both strategies, and a new `keptOriginalChars` field closes the books exactly (`omittedChars + keptOriginalChars === normalized.length`; reconcile against it, never against `text.length`, which the marker inflates). Picked salient failure lines are never cut in half; overrun sacrifices the earliest tail line, then the head window's tail, and only a pathological budget degrades to head semantics. **Storage endurance**: appends are idempotent *across processes* — the first log scan re-indexes every address already on disk, so replaying a check against a fresh store after a restart is a true no-op instead of a duplicate record. A crash mid-write leaves a torn final line that used to fail audit forever; it is now atomically rewritten away with the repair recorded on-chain as `log/recovered-partial-tail`, while corruption of a whole line mid-log is deliberately **not** repaired — that is the signature of tampering, and audit keeps reporting it. Explicit `checks` and auto-discovery dedupe by command (explicit wins; the same command runs once), `canonicalJson` rejects circular structures with a clear `TypeError`, and Windows drive-letter case drift (`c:\ws\...` vs `C:/ws/...`) folds into `$WORKSPACE` (backslash roots keep legacy digests). **Windows shim resolution**: `npm`/`pnpm`/`yarn` ship as `.cmd` shims that Node's spawn refuses to execute — pnpm simply could not be a check command on Windows. The shims are *parsed* (npm's generation template is stable) and reduced to a direct `spawn(node, [script])` — no shell, no injection surface; non-standard shims produce a clean error instead of mojibake. **Death-cause honesty**: `CommandResult.killedBySignal` carries the fact that an external signal killed the child (always absent on win32 — Windows does not propagate signals across processes), and a signal death is recorded as `error` with the signal named — no longer silently mis-filed as `timeout`. **Adapter races and honesty**: concurrent writes use unique temp names plus rename retries (Windows EPERM contention), startup probes the on-disk baseline so the first prompt never claims "no baseline" when one exists, turn-stopping observers flush before drift detection reads state, mutation classification has a single source of truth (unknown tools default to mutation — conservatively charged to the agent), and the `source` content key no longer leaks code-snippet text into the touched set where it misattributed edits. The scheduling core (runner) gained its first direct unit tests: concurrency clamping, budget skips, abort propagation, out-of-order completion, signal deaths, spawn errors, excerpt pass-through.

## Bayesian verification scheduling (v0.9): certify at 0.97, don't run everything

"Which checks to run" stops being set algebra and becomes an information-gain decision — predictive test selection (Google 2015–2021, Facebook 2019) applied to agent assertions for the first time. The evidence log is, among other things, a labelled historical dataset (checkId × status × duration); the new pure module `src/core/bayes.ts` learns each check's flakiness and cost from it and models every check as a noisy sensor for one binary proposition ("the workspace is healthy"): the prior π = clamp(1 − ρ·s, 0.05, 0.999) combines a Laplace-smoothed failure tendency ρ = (failures+1)/(runs+5) (a never-run check starts skeptical at ρ = 0.2, a 200-run all-green veteran decays to ≈ 0.005; flips pair decisive observations only) with a change-impact strength ladder (direct hit or LSP-confirmed edge 1.0, closure distance 1/(1+d), bare prefix 0.7, wildcard/no-evidence 0.5); α = P(false fail | healthy) is learned from flips and clamped to [0.01, 0.3]; β = P(false pass | broken) is fixed at 0.02 — unlearnable without breakage ground truth, an admitted guess. `rankByInformationGain` then prices every candidate run by expected reduction of the claim's binary entropy per millisecond (VOI ≥ 0 provably — the Bayesian update is a martingale), with deterministic greedy ordering and lexicographic tie-breaks. The engine dispatches **waves** of `concurrency` checks, folds each wave's real outcomes into the running posterior, and stops early on one of three conditions — the claim posterior crosses `certifyTarget` (default 0.97), a first decisive failure lands (the assertion is dead; attribution is already sufficient), or the budget drains — leaving the rest as auditable planned skips carrying their priors (`skippedByPlan` rides the `proof/verified` marker). Graded trust replaces the binary grade: `proven` now means "posterior ≥ target", displayed as `PROVEN (p≈0.97)` or `STALE (p≈0.61, target 0.97)`, with `confidenceBasis` naming how the number was earned (`full-coverage` — still below 1, the flake residual is honest; `certified-subset`; `degraded`), and `proof_verify` surfaces `confidence` / `confidenceBasis` / `certifiedSkips` / `stoppedEarly` / `waves`. Soundness is preserved: the candidate pool is still the impact closure (global invalidators and uncertain graphs still widen it to every check), `all: true` and degraded git facts still bypass the waves for a forced whole-batch run, and `scheduler: 'set'` is the kill-switch restoring v0.8 behaviour bit-for-bit. Honest limits: the claim posterior is a product of per-check factors — independence is the model's largest known distortion (checks sharing changed files fail correlated), so the number is a ranking signal, not a calibrated probability.

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
npm test              # 229 tests, node:test
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
        scheduler: bayesian        # bayesian = VOI-ranked waves + graded trust (default) | set = legacy whole-batch
        certifyTarget: 0.97        # claim posterior that certifies `proven` without running everything
        impactGraph: true
        driftDetection: true
        enforceOnTurnEnd: true
```

## Honest limits

- Check discovery is heuristic. For monorepos or custom build systems, declare `checks` explicitly with `paths` so incremental verification stays precise.
- The dependency graph is approximate and errs toward over-inclusion. Dynamic `import()` calls, multi-line ESM imports and Python dotted imports produce edges since v0.7; reflection and string-built paths still cannot be resolved.
- The claim posterior (v0.9) is a product of per-check health factors: independence is the model's largest known distortion — checks sharing changed files fail correlated — so `confidence` is a ranking signal, not a calibrated probability. β (false-pass) is fixed at 0.02, an admitted guess; the checks a certified-subset run skips stay on the books as planned skips carrying their priors, and priors are only as good as the evidence log.
- Checkpoint cadence leaves a window (v0.2): records after the last signed checkpoint are chain-covered but not checkpoint-covered. The window is bounded by `checkpointEvery`, closed at every baseline/verify/claim boundary, and *visible* — `proof_status` reports `tailRecords`, the count of records since the last checkpoint. The anchor protects against the audited agent, not against a fully compromised host.
- On machines without the signing key, signed checkpoints cannot be adjudicated locally: the audit reports them as `unverifiableCheckpoints` (a missing capability, not a forgery charge — the audit does not fail on it; anchor count/head comparison still bounds rewind).
- `proven` permits pre-existing red checks — they are reported prominently but not charged to the session. Deliberate, not a hole.
- It orchestrates and attributes your existing objective checks; it does not write tests.
- DSH is a developer preview and its plugin contract changes. This plugin pins a minimal contract snapshot and declares peers rather than bundling, but upstream shifts still need re-alignment.

## License

MIT
