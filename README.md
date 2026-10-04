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
| absent | fail | `new-failure` | honestly unattributable |

Working in an already-red repository is the normal condition. `dsh-proof` does not require you to fix history before you can prove you broke nothing.

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
| `tools/result` | observes every tool result; maintains the dirty set and file fingerprints |
| `agent/turn-stopping` | injects corrective context when a turn mutated the workspace without a proven claim, and flags files changed outside the tool stream |
| `ctx.systemPrompt.section()` | publishes the `proof:policy` section so the model knows the rules exist |

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
npm test              # 61 tests, node:test
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
- The dependency graph is approximate and errs toward over-inclusion. Dynamic imports and string-built paths cannot be resolved.
- `proven` permits pre-existing red checks — they are reported prominently but not charged to the session. Deliberate, not a hole.
- It orchestrates and attributes your existing objective checks; it does not write tests.
- DSH is a developer preview and its plugin contract changes. This plugin pins a minimal contract snapshot and declares peers rather than bundling, but upstream shifts still need re-alignment.

## License

MIT
