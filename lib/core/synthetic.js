/**
 * Synthetic evidence (ο) — the pure domain of PTC evidence synthesis.
 *
 * Some assertions a session wants to prove have no existing check: the change
 * touched a path no discovered suite covers, or the claim is about a property
 * nobody ever tested. This module lets the *plugin* construct a verification
 * for exactly that gap: a property-test / minimal-repro script the agent
 * drafts from a scaffold, the host screens for forbidden capabilities, the
 * screened script runs in a sandbox, and the run's evidence enters the chain
 * with a `synthetic` marker — weighted below every discovered check.
 *
 * The standing tension this module is built around: the agent is a
 * *co-conspirator in constructing the evidence* — it writes the test that
 * proves its own claim — but the evidence chain must not let it *forge* one.
 * Three structural answers, all visible in the API below:
 *
 * 1. **The script is content-addressed into its own evidence.** The record
 *    carries `scriptDigest` (sha256 of the verbatim source) and the digest
 *    participates in `evidenceId`, so "the test that passed" and "the source
 *    that ran" cannot quietly diverge — weakening an assertion mints a new
 *    address, and the old pass cannot be re-used for the new script.
 * 2. **The capability screen is deny-list, not trust-list.** The script may
 *    only reach the outside world through modules the screener never named.
 *    Static screening is admitted to be *not* a sandbox (see `screenScript`);
 *    the real boundary is the sandbox cwd, the run timeout, the output cap
 *    and the host's ptc-runtime profile. The screen exists to make the easy
 *    exfiltration attempts fail loudly and *before* execution.
 * 3. **The math discounts self-graded homework.** `core/bayes.ts` prices a
 *    synthetic check's false-pass at 0.15, not 0.02 (see the long comment at
 *    the use site) — a passing synthetic check lifts the posterior less than
 *    a passing independent suite, without forbidding the agent from ever
 *    proving anything itself.
 *
 * ## Determinism
 *
 * Everything here is a pure function of its inputs: no clock (the request's
 * `requestedAt` is injected by the caller), no randomness, no filesystem, no
 * imports at all beyond `checkId` (pure identity) and a type. When a digest
 * of a script is needed — `SyntheticEvidenceMeta.scriptDigest` — callers use
 * `sha256` from `./hash.ts`, the project's one sanctioned digest source.
 * Findings and labels are sorted so identical inputs yield byte-identical
 * outputs, the content-addressing discipline demands.
 *
 * @module dsh-proof/core/synthetic
 */
import { checkId } from "./checks.js";
/**
 * Default sandbox directory (workspace-relative) where synthetic scripts and
 * their fixtures live before the runner executes them. The directory is added
 * to `DEFAULT_IGNORE_DIRS` (see `core/checks.ts`) so the sandbox never enters
 * the dependency graph and never triggers check discovery — the sandbox is an
 * *output* of verification, not a source input that could invalidate it.
 */
export const SYNTHETIC_DIR_DEFAULT = '.proof-synthetic';
// ---------------------------------------------------------------------------
// The scaffold
// ---------------------------------------------------------------------------
/**
 * The scaffold the agent fills in (ESM `.mjs`, top-level await allowed).
 *
 * Design constraints the template encodes:
 *
 * - **Deterministic assertion loop** — no clock, no randomness in the oracle:
 *   the same source must print the same output every run, forever, or the
 *   content-addressed evidence record is not reproducible.
 * - **Fixed last-line protocol** — `SYNTHETIC: PASS` or
 *   `SYNTHETIC: FAIL: <reason>`. The host's output excerpt and the runner's
 *   exit-code convention (`process.exitCode = 1` on failure) both key on it,
 *   so a scaffolded script can never "pass" by printing nothing.
 * - **The chain warning rides in the file itself** — the first thing the
 *   model reads after instantiation is that this exact text becomes the
 *   `scriptDigest` of a piece of evidence. Deleting an assertion is not a
 *   private edit; it mints a new address and the old pass stops applying.
 *
 * The template itself passes `screenScript` (module names appear in the
 * warning prose *unquoted*, and the screener only matches quoted specifiers)
 * — a scaffold plus filled business assertions starts from a clean screen,
 * so any finding on a submitted script came from the author's additions.
 */
export const SYNTHETIC_TEMPLATE = [
    '// SYNTHETIC EVIDENCE SCAFFOLD — read this header before editing.',
    '//',
    '// This script will become *synthetic evidence*: its exact source text is',
    '// hashed (sha256, verbatim) into the scriptDigest of the evidence record',
    '// that carries its result, and any verifier can re-run these exact bytes.',
    '// Everything you write here is on the record — an assertion you delete or',
    '// weaken is visible forever as a different digest, and the pass that the',
    '// old script earned stops applying to the new one.',
    '//',
    '// The capability screen rejects, before this file is ever executed:',
    '//   - any static or dynamic import of the process/network/worker modules',
    '//     named by FORBIDDEN_CAPABILITIES, in any of their node: spellings;',
    '//   - any require form of the same;',
    '//   - any use of the zero-import outbound globals (fetch, WebSocket) —',
    '//     reaching them needs no import at all, so none is accepted as cover;',
    '//   - any read of the environment-variable bag hanging off the process',
    '//     global — tests never need environment secrets.',
    '// fs IS allowed: read fixtures freely (writes are allowed but keep the',
    '// sandbox reproducible). The static screen is not a sandbox — the real',
    '// boundary is the sandbox cwd, the run timeout, the output cap and the',
    "// host's ptc-runtime profile.",
    '',
    '// ---- deterministic assertion loop (leave intact) -------------------------',
    'const failures = []',
    'let checks = 0',
    'function assert(condition, label) {',
    '  checks += 1',
    '  if (condition !== true) failures.push(label)',
    '}',
    '',
    '// ---- BUSINESS ASSERTIONS — replace this whole region ---------------------',
    '// Exercise exactly the paths named by the request and assert the claim\'s',
    '// behavior on deterministic inputs. Import the code under test normally.',
    '//',
    '// Shape of a property test:',
    '//   import { parse } from "../src/parse.mjs"',
    '//   const CASES = [',
    '//     ["a,b", ["a", "b"]],',
    '//     [" a , b ", ["a", "b"]],',
    '//   ]',
    '//   for (const [input, expected] of CASES) {',
    '//     const got = parse(input)',
    '//     assert(JSON.stringify(got) === JSON.stringify(expected),',
    '//       `parse(${JSON.stringify(input)}) -> ${JSON.stringify(got)}`)',
    '//   }',
    '',
    '// ---- harness tail (do not edit below this line) --------------------------',
    'if (failures.length === 0) {',
    "  console.log('SYNTHETIC: PASS')",
    '} else {',
    '  process.exitCode = 1',
    "  console.log(`SYNTHETIC: FAIL: ${failures.length}/${checks} assertion(s) failed: ${failures.join('; ')}`)",
    '}',
    '',
].join('\n');
/**
 * Sandbox-relative script name: `synthetic-<claimId>-<seq>.mjs`.
 *
 * The `seq` is collision insurance only — two scripts for the same claim
 * (a re-write after a FAIL, or several properties proven separately) must not
 * overwrite each other on disk — and deliberately carries *no* identity
 * semantics: the evidence identity is the script *content* (scriptDigest)
 * plus the command, never the sequence number, so re-running "the same test,
 * regenerated" dedupes only if the bytes really are the same.
 */
export function sandboxEntryFor(claimId, seq) {
    return `synthetic-${claimId}-${seq}.mjs`;
}
// ---------------------------------------------------------------------------
// Capability screening
// ---------------------------------------------------------------------------
/**
 * Modules a synthetic script may never reach, under any of their spellings:
 * process spawning (`child_process`), the environment bag (`process` /
 * `node:process` — an `import { env } from 'node:process'` would otherwise
 * bypass the whole `process.env` read check, and env reads are the classic
 * exfiltration channel), the network (`net`/`http`/`https`/`dgram`, and as
 * of H-31 also `dns`/`tls` — a DNS lookup or a raw TLS socket is an outbound
 * channel exactly like http, and dns tunnelling is the classic covert one),
 * parallel kernels that would escape the sandbox's cwd and timeout
 * (`worker_threads`, `cluster` — fork() is child_process with a friendlier
 * name). The list is a locked contract with the engine and tool wiring —
 * additions are a breaking change to what hosts must enforce at the
 * ptc-runtime tier, not a casual edit.
 *
 * W15-M3 (v0.23) added the eval-grade execution seams that walk in through a
 * CLEAN literal specifier: `node:vm` (`vm.runInThisContext` is `eval` with a
 * function name — it used to pass all four import regexes AND the global
 * screen) and `node:module` (the `createRequire` door; the escape itself is a
 * documented residual, but the module NAME is statically sealable, so the
 * door is). `node:inspector` stays out for now: it is an execution seam, but
 * a strictly weaker one than vm, and the contract cost of list growth is
 * real — additions belong to deliberate versioned changes like this one.
 *
 * `'node:process'` is listed for the contract's sake (the engine's conjure
 * instruction and the tool prose render this list verbatim, and both
 * spellings must be named to the model); matching itself reduces through the
 * `node:` strip in `forbiddenModuleOf`, where the single `'process'` entry
 * answers for both. `vm`/`module` follow the same convention.
 */
export const FORBIDDEN_CAPABILITIES = [
    'child_process', 'net', 'http', 'https', 'dgram', 'worker_threads', 'cluster',
    'dns', 'tls',
    'process', 'node:process',
    'vm', 'node:vm',
    'module', 'node:module',
];
/**
 * H-31: zero-import outbound GLOBALS a synthetic script may never touch.
 * Node ≥ 18 ships `fetch` (and ≥ 22 `WebSocket`) on the global object — no
 * `import` text for the module screen to see — so a script with a clean
 * import section could still POST the workspace to any address. W15-M2: the
 * screen flags every statically decidable call shape of every name here —
 * direct `fetch(…)`, computed member `globalThis['fetch'](…)`, optional call
 * `fetch?.(…)`, indirect `(0, fetch)(…)` and the alias declaration
 * `const f = fetch` (see `screenScript`). V7-M3 extends the same net to the
 * statically decidable VALUE shapes — the tagged template `` fetch`url` ``
 * (a call), the destructuring rename `const { fetch: f } = globalThis`, the
 * bare assignment alias `f = fetch` and `Reflect.apply(fetch, …)`; passing
 * the global bare to an arbitrary higher-order callee stays a documented
 * residual (not statically decidable). A local helper that happens to be
 * named `fetch` is over-reported, the deny-list's documented safe direction
 * (refuse the inert script, never run the live one).
 */
export const FORBIDDEN_GLOBALS = ['fetch', 'WebSocket'];
// Static `… from '<specifier>'` — covers `import … from`, multi-line import
// lists (the from-clause closes the statement) and `export … from` re-exports
// (a re-export pulls the module in exactly like an import). M11: the quote
// class includes the backtick — a template literal WITHOUT interpolation is
// a statically decidable specifier (`import(\`node:child_process\`)` used to
// sail past the screen), and interpolated templates remain in the
// computed-specifier limit below.
const RE_FROM_CLAUSE = /(?:^|[^\w$])from\s*(['"`])([^'"`\n]*)\1/g;
// Bare side-effect import: `import '<specifier>'`.
const RE_BARE_IMPORT = /\bimport\s*(['"`])([^'"`\n]*)\1/g;
// Dynamic import with a *literal* specifier: `await import('<specifier>')`.
// Computed specifiers (`import(name + suffix)`) are beyond static screening —
// see the limits note on `screenScript`.
const RE_DYNAMIC_IMPORT = /\bimport\s*\(\s*(['"`])([^'"`\n]*)\1/g;
// `require('<specifier>')`, the CommonJS spelling an .mjs could still reach
// through a transitive dependency.
const RE_REQUIRE = /\brequire\s*\(\s*(['"`])([^'"`\n]*)\1/g;
// `process.env` in its member and computed-member spellings. A synthetic test
// reads fixtures from the sandbox, never secrets from the environment — and
// an environment read is the classic covert channel for exfiltration prompts.
//
// Known residual (M11, deliberately left uncaught): `process?.env` and
// destructuring forms (`const { env } = process`) do not match either pattern.
// Extending the regexes toward them (optional chains, any binding shape)
// risks flagging innocent member/computed access that merely resembles an env
// read — false positives teach authors to route around the screen — so the
// optional-chain and deconstruction spellings stay documented residuals,
// bounded by the same sandbox cwd/timeout/output-cap regime as the other
// static-screen limits. (The `process`/`node:process` deny-list entries close
// the module-import route to the same bag.)
const RE_PROCESS_ENV = [/\bprocess\s*\.\s*env\b/, /\bprocess\s*\[\s*(['"])env\1\s*\]/];
// H-31: the zero-import outbound globals (see FORBIDDEN_GLOBALS) are screened
// by their call forms, built from the names at screening time — no import
// text is required to reach them (Node ships them on the global object), so
// the import regexes above are structurally blind to this channel.
/**
 * M11: decode the escape forms a specifier can hide behind before the
 * deny-list sees it — `\u0070`, `\x70` and `\u{70}` all write `p`, so
 * `'child_\u0070rocess'` is `'child_process'` and must screen as one. Only
 * the *identifier-relevant* escapes are decoded (hex/unicode); everything
 * else passes through verbatim, and a trailing lone backslash is kept — the
 * goal is matching what the runtime would resolve, not validating syntax.
 */
function unescapeSpecifier(specifier) {
    return specifier.replace(/\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))/g, (_, braced, u4, x2) => {
        const code = braced !== undefined ? Number.parseInt(braced, 16)
            : u4 !== undefined ? Number.parseInt(u4, 16)
                : Number.parseInt(x2 ?? '0', 16);
        return code > 0 && code <= 0x10_FFFF ? String.fromCodePoint(code) : _;
    });
}
/**
 * Normalize a module specifier to the name the deny-list speaks: strip the
 * `node:` prefix and any deep path, so `node:net`, `net` and a (hypothetical)
 * `net/…` deep import all reduce to `net` — while `./network.mjs` reduces to
 * `.` and stays allowed. Boundary precision matters both ways: missing a
 * spelling of a forbidden module is a hole; flagging an innocent local
 * fixture whose name merely *contains* a forbidden one is noise that teaches
 * authors to route around the screener.
 */
function forbiddenModuleOf(specifier) {
    const bare = specifier.replace(/^node:/, '');
    const root = bare.split('/')[0] ?? bare;
    return FORBIDDEN_CAPABILITIES.includes(root) ? root : undefined;
}
/**
 * Deny-list capability screen over a script's verbatim source. Returns every
 * finding; the script may only execute when the list is empty. Findings are
 * deduplicated and sorted, so the same source always screens to the same
 * verdict — screening output is recorded next to the run (see
 * `SyntheticEvidenceMeta.screened`), and it must address identically.
 *
 * What it catches: static imports (including multi-line lists and re-export
 * `from`-clauses), bare side-effect imports, literal-specifier dynamic
 * imports and `require` calls of any `FORBIDDEN_CAPABILITIES` module — with
 * or without the `node:` prefix — plus `process.env` reads in member and
 * computed-member form, and (H-31) the zero-import outbound globals named by
 * `FORBIDDEN_GLOBALS` in every statically decidable call shape (W15-M2:
 * direct, computed-member, optional-call, indirect-call and alias-binding)
 * and value shape (V7-M3: tagged-template, destructuring-alias,
 * assignment-alias and Reflect.apply — a global used as a VALUE at a
 * nameable site is as live as a call).
 * M11: all four import shapes accept backtick-quoted specifiers (an
 * uninterpolated template literal is statically decidable), and specifiers
 * are `\u`/`\x`-unescaped before the deny-list sees them, so
 * `'child_\u0070rocess'` screens as `'child_process'`. The scan runs over
 * the *raw text, comments included*: a commented-out forbidden import is
 * flagged rather than missed. That is deliberate over-reporting — this is a
 * deny-list, and for a screener the safe direction is refusing an inert
 * script, never running a live one.
 *
 * Admitted limits of static screening (this is a *screen*, not a sandbox):
 * computed specifiers (`import(buildName())`), runtime aliases that need no
 * literal (`eval`/`new Function` — the eval-tier escapes themselves),
 * case-mangled specifiers that would simply fail at runtime, and a global
 * passed BARE as an argument to an arbitrary callee
 * (`queueMicrotask(fetch, url)` — whether the callee invokes its argument is
 * not a static fact) are not caught — text cannot see runtime values. (W15-M3 closed the two module DOORS to
 * eval-tier power: `node:vm` and `node:module` are denied by name, so the
 * escapes now need an actual computed specifier, not a clean import.) The
 * enforcement that actually bounds a runaway script is the sandbox cwd
 * restriction, the run timeout, the output cap and the host's ptc-runtime
 * profile; the screen's job is only to make the *easy* variants fail loudly,
 * before execution.
 *
 * `fs` is deliberately allowed in both directions: a property test that
 * cannot read its fixture cannot test anything. The directory it may read is
 * the sandbox the host mounted — that boundary is enforced by cwd, not here.
 */
export function screenScript(source) {
    const findings = new Set();
    const checkImports = (regex, how) => {
        for (const match of source.matchAll(regex)) {
            // M11: the deny-list judges the specifier the runtime would resolve —
            // escapes decoded — while the finding quotes the raw text as written,
            // so the evidence shows exactly what the author typed.
            const raw = match[2] ?? '';
            const forbidden = forbiddenModuleOf(unescapeSpecifier(raw));
            if (forbidden !== undefined) {
                findings.add(`${how} of forbidden module '${forbidden}' (from '${raw}')`);
            }
        }
    };
    checkImports(RE_FROM_CLAUSE, 'static import');
    checkImports(RE_DYNAMIC_IMPORT, 'dynamic import');
    checkImports(RE_REQUIRE, 'require');
    // A bare side-effect import (`import 'child_process'`) has no from-clause
    // and no call paren — only this pattern sees it. It cannot double-report
    // the from-clause form (a binding name sits between the keyword and the
    // specifier), and the findings Set would collapse a duplicate anyway.
    checkImports(RE_BARE_IMPORT, 'static import');
    for (const pattern of RE_PROCESS_ENV) {
        if (pattern.test(source))
            findings.add('read of process.env (synthetic tests never need environment secrets)');
    }
    // H-31: the globals need no import, so this is the only line of defence the
    // static screen can offer them — the easiest exfiltration channel used to
    // be the one the screen could not even see. W15-M2: the direct call form
    // (`fetch(…)`, `globalThis.fetch(…)` — the `\b` does not care what precedes
    // the dot) is joined by every OTHER statically decidable shape the direct
    // regex missed; each is built from the name at screening time so the list
    // and the patterns cannot drift:
    //   computed member  `globalThis['fetch'](…)` / `x["WebSocket"](…)`
    //   optional call    `fetch?.(…)`
    //   indirect call    `(0, fetch)(…)`
    //   alias binding    `const f = fetch` / `const W = globalThis.WebSocket`
    // V7-M3 (the value-reference family): a global used as a VALUE — not
    // called at a recognizable site — is statically decidable in four more
    // shapes, and each used to pass the screen clean while remaining live:
    //   tagged template  `` fetch`https://…/${data}` `` — a tag call; the
    //                    template's raw strings reach the network stack whole
    //   destructuring    `const { fetch: f } = globalThis` — renames the global
    //                    away from every name-anchored pattern
    //   assignment       `let f; f = fetch` — the alias without a declaration
    //                    keyword on the same line the alias-binding form needs
    //   Reflect.apply    `Reflect.apply(fetch, undefined, [url])` — the
    //                    call-everything primitive, statically nameable
    // An alias declaration is flagged on its own: the binding hand is
    // statically visible even though the eventual call site is not. Over-
    // reporting (a local helper genuinely named `fetch` bound then called)
    // stays the deny-list's documented safe direction.
    //
    // Admitted non-decidable boundary (text cannot see runtime values):
    // passing the global BARE as an argument to an arbitrary higher-order
    // callee (`queueMicrotask(fetch, url)`) is NOT flagged — whether that
    // callee invokes its argument is not a static fact, so flagging every
    // bare identifier occurrence would be noise rather than a screen; the
    // aliases an intermediate variable washes out (`const g = globalThis;
    // g.fetch(…)`) likewise. Those shapes stay bounded by the sandbox cwd,
    // run timeout, output cap and ptc-runtime profile, exactly like the
    // computed-specifier and eval-tier residuals recorded on `screenScript`.
    for (const globalName of FORBIDDEN_GLOBALS) {
        const shapes = [
            [new RegExp(`\\b${globalName}\\s*\\(`), 'call form'],
            [new RegExp(`\\[\\s*(['"\`])${globalName}\\1\\s*\\]`), 'computed-member form'],
            [new RegExp(`\\b${globalName}\\s*\\?\\.\\s*\\(`), 'optional-call form'],
            [new RegExp(`\\(\\s*0\\s*,\\s*${globalName}\\s*\\)\\s*\\(`), 'indirect-call form'],
            [new RegExp(`\\b(?:const|let|var)\\s+[\\w$]+\\s*=\\s*(?:globalThis\\s*\\.\\s*)?${globalName}\\b`), 'alias-binding form'],
            // V7-M3 — the value-reference family (see the block comment above).
            [new RegExp(`\\b${globalName}\\s*\``), 'tagged-template form'],
            [new RegExp(`\\b(?:const|let|var)\\s*\\{[^}]*\\b${globalName}\\s*:\\s*[\\w$]+[^}]*\\}`), 'destructuring-alias form'],
            [new RegExp(`\\b[\\w$]+\\s*=(?!=)\\s*(?:globalThis\\s*\\.\\s*)?${globalName}\\b`), 'assignment-alias form'],
            [new RegExp(`\\bReflect\\s*\\.\\s*apply\\s*\\(\\s*(?:globalThis\\s*\\.\\s*)?${globalName}\\b`), 'reflect-apply form'],
        ];
        for (const [pattern, how] of shapes) {
            if (pattern.test(source)) {
                findings.add(`use of global '${globalName}' in ${how} (zero-import outbound capability — synthetic tests never need the network)`);
            }
        }
    }
    const sorted = [...findings].sort();
    return { ok: sorted.length === 0, findings: sorted };
}
/** Collapse a claim to a deterministic single-line excerpt for labels. */
function claimExcerpt(claim, max = 60) {
    const flat = claim.replace(/\s+/g, ' ').trim();
    return flat.length <= max ? flat : `${flat.slice(0, max - 3)}...`;
}
/**
 * The check spec a synthetic request becomes — an ordinary `CheckSpec` the
 * runner, store and scheduler treat like any other, except for `source:
 * 'synthetic'`, which is where the discounting lives (bayes β, contract
 * detail, report wording all key on it — never on a special record shape).
 *
 * Identity is `checkId('synthetic', ['node', entry], sandboxDir)`: the
 * *command and sandbox* make the id, the script *content* makes the evidence
 * (via `scriptDigest`). Two different scripts for one claim share a checkId
 * but never share evidence — re-writing the test after a FAIL is visible as
 * a new evidenceId under the same check, exactly like any re-run.
 */
export function syntheticSpec(request, sandboxDir, timeoutMs) {
    return {
        id: checkId('synthetic', ['node', request.entry], sandboxDir),
        label: `synthetic check (${request.claimId}): "${claimExcerpt(request.claim)}"`,
        command: ['node', request.entry],
        kind: 'test',
        source: 'synthetic',
        paths: [...request.paths],
        cwd: sandboxDir,
        timeoutMs,
    };
}
//# sourceMappingURL=synthetic.js.map