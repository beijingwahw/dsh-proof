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

## Nine model-facing tools

| tool | purpose |
|---|---|
| `proof_status` | baseline, discovered checks, latest evidence, evidence-log integrity |
| `proof_baseline` | establish/refresh the baseline (runs every discovered check) |
| `proof_verify` | incremental verification + grade + regression attribution |
| `proof_claim` | state a claim **and** prove it; `blockers` is the to-do list; v0.10 adds contract params (`kind` + `budgetMs` / `review` / `entryPoints`) binding the claim to typed evidence obligations |
| `proof_jury` | **Class B evidence, step 1**: request an LLM jury deliberation — returns the frozen deliberation prompt (rubric + claim + context, byte-deterministic) and records the request on-chain, verbatim prompt included |
| `proof_jury_submit` | **Class B evidence, step 2**: record the verdict (`verdict` / `probability` / verbatim `reasoning`) as permanent evidence with the frozen prompt, declared model identity and independence tier; the claimId must match the pending request; gen auto-increments = appeal |
| `proof_endorse` | **Class C evidence**: a named human endorses/rejects a claim — the call itself triggers the host approval prompt; endorse = risk acceptance (unlocks the grade gap, never inflates the number), reject = collapse |
| `proof_conjure` | **Synthetic evidence, step 1**: request a conjured verification for an assertion no organic check covers — the plugin freezes the request (claim + paths) on-chain (`synthetic/requested`) and scaffolds a deterministic test template into `.proof-synthetic/` |
| `proof_conjure_run` | **Synthetic evidence, step 2**: the plugin verifies the on-chain request, digests the sandbox script verbatim, screens its capabilities (refusal = `skipped`, never executed, nothing on chain) and runs it through the plugin's own port; the `scriptDigest`, sandbox tier, screening verdict and authorship ride the content-addressed evidence, closed by a `synthetic/run` marker |

All nine follow DSH's hard contract: `execute` returns one canonical JSON value, prose lives in `output.render`, and UI cards come from **pure** `presentCall` / `presentResult` / `presentationMeta` projections so a session-log replay reproduces the identical card.

## Runtime enforcement, not prompt hope

| extension point | mechanism |
|---|---|
| `tools/pre-execute` | with `requireBaseline: ask`, mutations require user approval until a baseline exists |
| `tools/pre-execute` | with `evidenceStore: workspace`, mutation tools touching the evidence store are routed through user approval |
| `tools/pre-execute` | `proof_endorse` always routes through `ask` — Class C evidence is a human's conscious decision, never the model's say-so |
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

## Typed assertion contracts (v0.10): the claim binds its own evidence obligations

The claim text used to be free prose: the engine could prove "no affected check regressed", never what the sentence *ought* to prove. "I refactored X", "I added feature Y" and "nothing got slower" carry completely different proof obligations, and one generic no-regressions gate cannot tell them apart. v0.10 upgrades `proof_claim` with an optional **contract kind** that binds the assertion to a fixed set of decidable evidence obligations — stable obligation ids, and an unmet one says exactly what is missing and how to fix it:

| kind | use for | obligations (fixed order) |
|---|---|---|
| `behavior-preserving` | refactors / optimisation | `zero-regressions` + `api-surface-unchanged` |
| `behavior-adding` | new features / modules | `zero-regressions` + `new-paths-covered` |
| `perf-budget` | performance claims | `zero-regressions` + `benchmark-evidence` + `within-budget` |
| `docs-only` | documentation-only changes | `docs-only-changes` + `jury-review` |

`api-surface-unchanged` diffs the public API surface in **both directions** (added and removed must both be empty): entry points come from `package.json` (`main`, `exports["."]`, `types`) or the `apiEntryPoints` config, are expanded through a bounded relative-import closure (depth ≤ 10, ≤ 500 files, truncation marked on-chain), and each file's exports are extracted per line in five forms — named declarations (including multi-declarator and destructuring lists), brace lists with aliases kept verbatim, `export default` → `#default`, `export *` → `#*` (plus the `ns` of `export * as ns`), and TS `export =` → `#=` — as sorted `file#symbol` strings riding the baseline as a non-addressing `apiSurface` attachment. Extraction deliberately **over-reports**: a missed export is a missed breaking change (a wrong pass), while a phantom export only makes an honest claim work harder (a wrong fail). `new-paths-covered` demands every changed source file be covered by a check that passed decisively this run — new behaviour must ride tested paths. A `perf-budget` claim force-runs **every** benchmark check (kind `benchmark`, from `bench` / `benchmark` / `perf:bench` scripts or explicit config) regardless of impact analysis, and its `durationMs` must stay within the claim's `budgetMs`. A `docs-only` claim runs **no checks at all** — `docs-only-changes` (docs extensions only; `requirements*.txt`-style traps guarded by the global-invalidator set) plus a `jury-review` self-attestation — and when everything holds the grade is `proven` with confidence structurally capped at `juryConfidenceCap` (default 0.8, basis `jury-only`, narrative `PROVEN (p≈0.80, jury evidence — self-attestation is capped)`): jury evidence never impersonates an experiment, and the verdict lands on the chain as a `claim/jury` marker. Contract runs go whole-batch — no bayesian planned skips, since an obligation must not rest on a check the plan skipped — and **a proven run carrying any unmet obligation is downgraded to `stale`** (confidence keeps what the run measured; the obligations say what is missing). Backwards compatibility: a claim without a `kind` behaves exactly as in v0.9, and a pre-v0.10 baseline without a surface fails `api-surface-unchanged` honestly, telling you to re-run `proof_baseline`.

## Graded evidence classes (v0.11): testimony re-enters the proof system

Machine measurement covers only half the world — the other half (readability improved, error messages friendlier, the migration guide accurate) had no exit but capped self-attestation. v0.11 brings **testimony** back as first-class evidence, giving each class the strongest honesty mechanism it can carry: **Class A** is machine measurement (recomputable — re-run the command, compare digests); **Class B** is an LLM jury (auditable — the *complete deliberation packet* lands on the tamper-evident chain: the verbatim prompt with the full `jury-rubric/v1` rubric, the declared model identity, the independence tier, and the entire verbatim output, so any third party can replay the frozen prompt against the same or a different model and compare; a verdict that will not replay is detectable); **Class C** is a named human endorsement (accountable — `proof_endorse` always routes through the host approval seam, and approver / approvedAt / scope ride the chain).

The jury protocol is a request/submit pair: `proof_jury` deterministically assembles and freezes the deliberation prompt (header, versioned rubric, claim, context, output instruction — pure concatenation, byte-stable forever, request recorded on-chain with the verbatim prompt) and `proof_jury_submit` validates the verdict shape, binds it to the pending request's claimId, and appends the full packet at `gen + 1` — **appeals supersede rather than erase**: the chain is append-only, readers resolve to the highest generation per (claimId, kind), so the disputed record stays visible as the appeal's foil, and B/C channels resolve independently. Claims are identified by `claimIdOf` (first 16 hex of the claim's sha256) — rewording a claim is a new claim needing new testimony. The rubric orders one structured JSON ruling `{verdict: uphold|reject|abstain, probability, reasoning}`, demands judgement only from the given materials, and tells the juror its output becomes permanent, public, replayable Class B evidence.

**Explicit trust weights, two maths each in its place.** `classBTrust` (0.7) and `classCTrust` (0.9) are declared policy constants, never learned — there is no labelled dataset of "this witness was right". For **pure-jury paths** (the new engine-level `llm-jury` contract kind: obligations `jury-delivered` + `jury-upholds` — an active on-chain B verdict upholding at probability ≥ 0.5 — zero commands run), confidence is Π `attestationFactor` with factor = p^w, a **log-odds discount**: w ∈ [0,1] and p ∈ [0,1] ⇒ p^w ∈ [p,1], so testimony can only *weaken* a claim, never amplify it — the right direction of skepticism for self-interested proof systems (abstain is exactly factor 1; NaN/out-of-range probabilities degrade to abstain so they can never poison the product). When a **machine certification already exists**, a witness speaking about the whole claim enters as the **reliability mixture** `fused = (1−w)·c + w·p`: pulled toward the asserted probability with strength exactly w, never overshooting it — a jury asserting 0.99 at w = 0.7 carries a 0.94 machine certification across the 0.97 target (the rescue), asserting 0.1 crashes it. **Class C endorsement is risk acceptance, not certainty transfer**: the approval seam is binary, human correctness is modelled as the constant `humanProbability` = 0.95, and 0.95^0.9 ≈ 0.955 can mathematically never cross a 0.97 target — so endorsement leaves the number untouched and unlocks the *grade* instead (stale-by-target-gap + zero regressions + every obligation met → `proven`; the human took the residual the machines could not cross). Endorsement cannot pay for missing work: unmet obligations or regressions do not unlock. The symmetric lock: an explicit reject — human or jury — collapses the number ((1−0.95)^0.9) and demotes a `proven` grade the number no longer supports. `ConfidenceBasis` grows `attested` (machine + B/C fusion, or pure C) and extends `jury-only` to pure-B paths (narrative: `PROVEN (p≈0.97, machine + B/C attested)`). Plain `verify()` never reads attestations at all — v0.9 pure-machine semantics stay byte-locked. Honest limits: v0.11's actual independence tier is the weakest (`same-session`), the model identity is the submitter's declaration (`session-model (unverified)`) verified only by replay audit, the jury's probability is a subjective judgement, and both 0.95 and the mixture are modelling choices, not derived posteriors.

## PTC evidence synthesis (v0.12): conjured verification for the unchecked

Some assertions land where no existing check looks — the change touched a path no discovered suite covers, and `new-paths-covered` used to be a dead end ("add a check whose paths cover them", which the agent cannot do: check discovery only reads build metadata and host config). v0.12 opens the third path: **the plugin itself constructs a verification for exactly that gap**. The agent's role changes from "the audited" to *a co-conspirator in constructing the evidence* — but the chain lets it influence only the test's truth value (how strict an assertion to write), never the execution result.

The protocol is a two-tool pair. `proof_conjure(claim, paths)` freezes the request *before any script exists*: the claim and its paths land on-chain as a `synthetic/requested` marker (with a null `scriptDigest` — locking the request first is what makes a later script swap visible), and a deterministic scaffold is written into the sandbox (`syntheticDir`, default `.proof-synthetic/`). The scaffold's header warns in the file itself that this exact text becomes the `scriptDigest` of a piece of evidence — deleting an assertion mints a new address, and the old pass stops applying. The agent fills in a property test / minimal repro; `proof_conjure_run(claim, entry)` then checks the chain for the matching request, digests the script on disk verbatim, runs a deny-list capability screen (refusal returns the findings with status `skipped` — no execution, nothing lands on chain), and executes through **the plugin's own command port**. Three structural answers make the evidence unforgeable: the script source is sha256'd into `SyntheticEvidenceMeta` and participates in the `evidenceId` content address (two scripts, same output → two different pieces of evidence); execution never touches the agent's tool surface; and the request→run pair closes with markers, so a script swapped between the two calls runs under its own digest, visibly.

**The math prices the interested party.** A synthetic check's false-pass β rises from 0.02 to `syntheticFalsePass` (default 0.15, 7.5×) — the cheapest false pass here is not a mechanical accident but an omission (write the empty assertion, skip the input that breaks the code), because the test's author is a party to the claim it tests. Same history, same pass: an organic check lifts the posterior to ≈ 0.9960, a conjured one to ≈ 0.9706 (pinned end-to-end). α and π still learn from history like any check — the discount prices *whose hand wrote the assertions*; a failing conjured check damns like any other. The default deliberately lives outside `BAYES_CONSTANTS` (the never-retuned laws): it is an overridable modelling guess. Executed conjured specs join `verify()` / `verifyContract` as ordinary specs, `behavior-adding` accepts them as coverage through a tier ladder (run-organic > run-synthetic > latest-organic > latest-synthetic — fresh beats stale, independent beats self-authored; detail: "covered by synthetic evidence (discounted)"), and when every decisive record this run was conjured, `confidenceBasis` becomes `synthetic` (priority: jury-only > attested > synthetic > certified-subset > full-coverage > degraded) with a narrative that says it out loud: `PROVEN (p≈0.97, synthetic evidence — conjured tests, discounted)`. The sandbox regime is honestly labelled `'screened-subprocess'` — static screening is **not** a sandbox (computed specifiers and `eval`/`createRequire` aliases are invisible to text); the real boundary is the sandbox cwd, the run timeout (`syntheticTimeoutMs`), the output cap, and a future host `ptc-runtime` tier whose probe point is already reserved.

## Coverage-aware proof (v0.13): ran, green, and it actually executed the change

`proven` used to mean "every affected check re-ran and none regressed" — with a blind spot no reader could see in the report: a check's `paths` matching the change says *selection* believed the check owned the file; it says nothing about whether the check's process ever *executed* the changed code. A suite can be green while no test imports the touched module; a typecheck was green before the edit. "All green" is a statement about the checks, not about the change. v0.13 upgrades `proven` to **ran + green + executed-the-change**, with the third dimension's evidence produced by the checked processes themselves — **zero instrumentation**: verification injects `NODE_V8_COVERAGE` into every check subprocess (a Node runtime flag delivered through the environment; npm/.cmd shims propagate it into nested node test processes), and each process writes its raw V8 coverage profile on exit. The new pure module `src/core/coverage.ts` parses those profiles — a file with any function range at `count > 0` was *executed*, present-but-all-zero is *loaded-not-executed* (bucketed, reserved), everything outside the workspace root and under any `node_modules` segment is dropped, and Windows drive-letter / percent-encoded `file://` forms are normalized — coverage the checked code cannot fake from inside, because the profile is written by the same V8 instance that executed it, at process exit.

Every decisively-passing evidence record attaches its own `coverage` split against the change set (`changedExecuted` / `changedUncovered`) — and like v0.12's `scriptDigest`, **the attachment participates in the `evidenceId` content address**: a record cannot claim to have exercised a change it never ran. Collection completes *before the first append*, so the chain never holds a plain record and its enriched twin; the staging tree (`${storeDir}/coverage/<nonce>` — the nonce is physical staging, never hash material) is removed after collection via a new optional `FsPort.removeDir`. The gate's demotion is deliberately a different word from `stale`: **`stale` is a process verdict** (verification did not finish; re-running rescues it) while the coverage **`unproven` is an evidence verdict** (the process finished, everything was green — and the green evidence never executed the change; re-running cannot help, what is missing is a check that actually reaches it). `regressed` and `stale` are never overwritten; the gate is pinned after the machine grade and before obligation/attestation fusion, so a claim coverage knocked to `unproven` cannot be endorsement-unlocked — missing work is not residual risk. Uncovered changes are named (first 3 files) with the remedy attached: `proof_conjure` can synthesize a test that executes them — v0.12's synthesis is the *prescription* for v0.13's blind spots, and fittingly the gate caught one of its own historical conjure fixtures being green while never touching the change on day one. Three modes (`coverage` config, default `observe`): `observe` gates only when data exists and shows `basis: 'none'` honestly when it does not (fake command ports and non-Node toolchains degrade visibly instead of failing a new way); `require` treats missing data itself as disqualifying (`no-coverage-data`) — strict deployments, not for non-node ecosystems; `off` injects nothing and gates nothing, byte-identical to v0.12. Narratives say it out loud — `PROVEN (p≈0.97, change-executed)` / `UNPROVEN (p≈0.97) — … — unexecuted change (src/feature.mjs) — proof_conjure can synthesize a test that executes them` — and baselines never inject: a baseline is a measurement, not a claim.

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
npm test              # 388 tests, node:test
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
        apiEntryPoints: []         # API-surface entry points; [] = derive from package.json main/exports/types
        juryConfidenceCap: 0.8     # confidence ceiling for docs-only jury self-attestation
        classBTrust: 0.7           # Class B (LLM jury) trust weight: log-odds exponent / mixture strength
        classCTrust: 0.9           # Class C (human) trust weight: endorse discounts gently, reject collapses
        syntheticDir: .proof-synthetic # sandbox where conjured-test scaffolds and scripts live (pinned out of discovery)
        syntheticFalsePass: 0.15    # β priced into agent-authored (synthetic) checks; organic default is 0.02
        syntheticTimeoutMs: 60000   # cooperative timeout for one conjured-test execution
        coverage: observe           # coverage-aware proof gating: observe = gate only when V8 data exists (default) | require = no data is disqualifying | off = no injection, no gating
        impactGraph: true
        driftDetection: true
        enforceOnTurnEnd: true
```

## Honest limits

- Check discovery is heuristic. For monorepos or custom build systems, declare `checks` explicitly with `paths` so incremental verification stays precise.
- The dependency graph is approximate and errs toward over-inclusion. Dynamic `import()` calls, multi-line ESM imports and Python dotted imports produce edges since v0.7; reflection and string-built paths still cannot be resolved.
- The claim posterior (v0.9) is a product of per-check health factors: independence is the model's largest known distortion — checks sharing changed files fail correlated — so `confidence` is a ranking signal, not a calibrated probability. β (false-pass) is fixed at 0.02, an admitted guess; the checks a certified-subset run skips stay on the books as planned skips carrying their priors, and priors are only as good as the evidence log.
- The API surface (v0.10) is a line-regex extraction that deliberately over-reports: runtime-computed exports (dynamically built export names, string-assembled re-exports) are invisible to it, and a missed export would be a missed breaking change — so when in doubt it reports, and a phantom export only makes an honest claim work harder. Set `apiEntryPoints` when `package.json` does not point at the real entries.
- The docs-only jury (v0.10) is self-attestation, not experiment: `review` is the author's own note, confidence is capped at `juryConfidenceCap` (default 0.80) with basis `jury-only` — the number is a ceiling, never a measurement.
- `perf-budget`'s `durationMs` (v0.10) is a wall-clock measurement subject to machine noise (load, frequency scaling, contention) and not comparable across machines; leave headroom in `budgetMs` and expect boundary jitter.
- Class B testimony's independence is at its weakest tier in v0.11: the tooling records `same-session` (deliberated inside the authoring agent's own context — the most contamination-prone tier, named honestly on the chain), and the model identity is the submitter's declaration (`session-model (unverified)`) — the plugin cannot verify who answered; what catches impersonation is third-party replay of the frozen prompt, not the declaration. The trust weights are declared constants, not learned.
- The jury's `probability` (v0.11) is a subjective probability, not a measurement: the rubric demands "the number your own reasoning actually supports", but an LLM's self-reported figure carries no calibration guarantee — read p = 0.99 vs 0.9 as wording strength. All the testimony arithmetic consumes this subjective number; it does not make it objective.
- `humanProbability` = 0.95 (v0.11) is a modelling choice: the Class C approval seam is binary and elicits no number, so human correctness enters as a constant — deliberately below 1, because a human who could never be wrong would make every endorsed claim unfalsifiable.
- The reliability mixture (v0.11) is a scoring-rule choice, not a derived posterior: `fused = (1−w)·c + w·p` models "the witness is reliable with probability w, else noise" because a witness speaking about the whole claim is not one more independent factor in the product; which maths applies (p^w discount vs mixture vs risk-acceptance unlock) is decided by whether the machines already spoke, never by which number looks better.
- Static screening is not a sandbox (v0.12): the conjured-script screen is a text-level deny-list — computed specifiers (`import(buildName())`), alias channels (`createRequire` / `eval` / `new Function`) and case-mangled specifiers are invisible to it, because text cannot see runtime values. What actually bounds a runaway script is the sandbox cwd restriction, the run timeout (`syntheticTimeoutMs`), the output cap and a future host `ptc-runtime` tier; the screen only makes the *easy* exfiltration attempts fail loudly, before execution. The regime label says `'screened-subprocess'`, honestly.
- The synthetic β = 0.15 (v0.12) is an admitted guess that is unlearnable by construction: a false-pass rate needs breakage ground truth to learn, and a self-serving test (empty assertion, skipped breaking input) produces no breakage signal to learn from — it is forever green in the log. Like the organic 0.02 it is a priced stance, not a measurement; it deliberately lives in the overridable `syntheticFalsePass` rather than the never-retuned `BAYES_CONSTANTS`.
- Synthetic coverage is always weaker than its organic peer (v0.12): the same pass lifts the posterior less (end-to-end: synthetic ≈ 0.9706 < organic ≈ 0.9960), the obligation tier ladder yields to organic at every tier, and an all-synthetic run renames the basis. Read conjured coverage as "the claim's author ran and passed their own check", never as independent confirmation — the β, the ladder and the basis all encode that one sentence.
- Execution coverage is file-granular (v0.13): "executed" means the file has at least one function range at `count > 0` — it does not distinguish the changed lines from the untouched function next door, so a test touching only unchanged code in the same file counts the same as one executing the change. Line/symbol-level verdicts (baseline content blobs or LSP symbol maps) are an evolution, not this version; read `change-executed` as "this file ran", never "this line ran".
- Non-node ecosystems have no coverage data (v0.13): `NODE_V8_COVERAGE` is a Node runtime flag — pytest, `go test`, `cargo test` inherit the variable but write no V8 profile, so the dimension reads `basis: 'none'` for them. `observe` never gates such workspaces; `require` makes every claim `unproven`. That is a deployment decision, not a defect: pure-node toolchains can run `require`, mixed or non-node stacks should stay on `observe` (or `off`).
- The loaded-not-executed bucket is parsed but unused (v0.13): V8 reports carry a third fact — files imported yet never run — which v1 buckets and reserves but does not consume for stronger verdicts (sharper suspect ranking, a more precise `new-paths-covered`). Recorded here as an honest edge of what the gate currently says.
- Checkpoint cadence leaves a window (v0.2): records after the last signed checkpoint are chain-covered but not checkpoint-covered. The window is bounded by `checkpointEvery`, closed at every baseline/verify/claim boundary, and *visible* — `proof_status` reports `tailRecords`, the count of records since the last checkpoint. The anchor protects against the audited agent, not against a fully compromised host.
- On machines without the signing key, signed checkpoints cannot be adjudicated locally: the audit reports them as `unverifiableCheckpoints` (a missing capability, not a forgery charge — the audit does not fail on it; anchor count/head comparison still bounds rewind).
- `proven` permits pre-existing red checks — they are reported prominently but not charged to the session. Deliberate, not a hole.
- It orchestrates and attributes your existing objective checks. v0.12's evidence synthesis does not change that boundary: the agent drafts the assertions, and the plugin only scaffolds, screens, executes — and prices the result below every independent check.
- DSH is a developer preview and its plugin contract changes. This plugin pins a minimal contract snapshot and declares peers rather than bundling, but upstream shifts still need re-alignment.

## License

MIT
