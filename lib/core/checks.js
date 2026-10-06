/**
 * Objective check discovery.
 *
 * A "check" is a claim the *workspace itself* can answer: run this command and
 * look at the exit code. The agent never gets to define what counts as passing
 * — that is the whole point. Discovery reads the project's own build metadata
 * and turns it into `CheckSpec`s; explicit user configuration always wins.
 *
 * @module dsh-proof/core/checks
 */
import { sha256 } from "./hash.js";
const DEFAULT_SCRIPT_KINDS = {
    test: 'test',
    'test:unit': 'test',
    'test:int': 'test',
    'test:e2e': 'test',
    'test:ci': 'test',
    check: 'other',
    verify: 'other',
    build: 'build',
    compile: 'build',
    typecheck: 'typecheck',
    'type-check': 'typecheck',
    tsc: 'typecheck',
    lint: 'lint',
    'lint:check': 'lint',
    'lint:ci': 'lint',
    stylelint: 'lint',
    eslint: 'lint',
    // ε/B6-L4: perf keys are deliberately NOT in the default name map. A script
    // merely NAMED `bench`/`benchmark`/`perf:bench` is usually a long-running
    // local helper, and name-key discovery promoted it to a must-pass
    // `benchmark` check under the default 120s timeout — a red check the
    // project never opted into. Perf-budget claims get their benchmark evidence
    // through an explicit `checks` entry with `kind: 'benchmark'` (or a
    // `scriptKinds` override), which is opt-in by construction.
};
const DEFAULT_IGNORE_DIRS = [
    'node_modules', '.git', 'dist', 'build', 'out', 'target', 'coverage',
    '.next', '.nuxt', '.output', '.cache', '.venv', 'venv', '__pycache__',
    '.pytest_cache', '.mypy_cache', '.ruff_cache', 'vendor', '.turbo', '.proof',
    'tmp', '.openclaw',
    // ο: the synthetic-evidence sandbox (SYNTHETIC_DIR_DEFAULT in
    // core/synthetic.ts). The literal is duplicated under this provenance note
    // rather than imported — core/synthetic.ts imports `checkId` from here, and
    // a back-import would make the pair a cycle whose entry order decides
    // whether this array initializer hits the const's TDZ. Mirrors the
    // SOURCE_EXT precedent in core/contract.ts; test/19 pins the two equal.
    '.proof-synthetic',
];
/** Discover every objective check the workspace declares. */
export async function discoverChecks(fs, root, options = {}) {
    const timeoutMs = options.timeoutMs ?? 120_000;
    // W14-L10: `??` only gates null/undefined, so an explicit NaN rode the spec
    // into the runner as a real timeout (the same hole H-33 sealed at the
    // excerpt layer). Refuse loudly: a non-finite timeout is a broken delivery,
    // never a request for the default.
    if (!Number.isFinite(timeoutMs)) {
        throw new TypeError(`DiscoverOptions.timeoutMs must be a finite number of milliseconds (got ${timeoutMs})`);
    }
    const scriptKinds = { ...DEFAULT_SCRIPT_KINDS, ...(options.scriptKinds ?? {}) };
    const found = [];
    const push = (spec) => {
        const resolved = spec.timeoutMs ?? timeoutMs;
        // Same gate for the per-entry spelling: `timeoutMs: NaN` in an explicit
        // checks entry must not silently pass through the `??`.
        if (!Number.isFinite(resolved)) {
            throw new TypeError(`check "${spec.label}" timeoutMs must be a finite number of milliseconds (got ${resolved})`);
        }
        found.push({
            ...spec,
            id: checkId(spec.source, spec.command, spec.cwd),
            timeoutMs: resolved,
        });
    };
    const explicit = options.checks ?? [];
    for (const entry of explicit) {
        const argv = toArray(entry.command);
        push({
            label: entry.label ?? argv.join(' '),
            command: argv,
            kind: entry.kind ?? 'other',
            source: 'config',
            paths: entry.paths ?? ['*'],
            ...(entry.timeoutMs !== undefined ? { timeoutMs: entry.timeoutMs } : {}),
        });
    }
    if (explicit.some(e => e.exclusive))
        return dedupe(found);
    // ---- Node / JS / TS -------------------------------------------------
    const pkgRaw = await fs.readFile(join(root, 'package.json'));
    if (pkgRaw !== undefined) {
        const pkg = parseJson(pkgRaw);
        if (pkg) {
            const scripts = (pkg.scripts ?? {});
            const workspaces = await expandWorkspacePatterns(fs, root, collectWorkspaceDirs(pkg));
            for (const [name, value] of Object.entries(scripts)) {
                if (typeof value !== 'string')
                    continue;
                const kind = scriptKinds[name];
                if (!kind)
                    continue;
                // npm folds `pre<script>`/`post<script>` into the run of `<script>`
                // itself — but only when that base script exists. Names that merely
                // *start with* the letters (prettier, postcss, prepare) are ordinary
                // scripts and must survive discovery.
                if (isHookScript(name, scripts))
                    continue;
                const argv = packageScriptArgv(pkg, name, value);
                push({
                    label: `npm script "${name}"`,
                    command: argv,
                    kind,
                    source: 'package.json',
                    paths: workspacePaths(root, workspaces),
                    // The argv pins *how npm is told to run*; the digest pins *what
                    // actually runs*. It rides the spec (never the id, never the
                    // evidence payload) so a baseline can later prove the same script
                    // body answered — see CheckSpec.scriptDigest.
                    scriptDigest: sha256(value),
                });
            }
            // Recursive discovery for pnpm/npm workspace members. The argv is
            // deliberately identical to the root's (`npm run` is the one invocation
            // that resolves `node_modules/.bin` under every manager); what separates
            // a subpackage check from the root's is `cwd` — it executes in the
            // member directory, gets its own id, and only expires on its own paths.
            for (const dir of workspaces) {
                const childRaw = await fs.readFile(join(root, dir, 'package.json'));
                const child = childRaw === undefined ? undefined : parseJson(childRaw);
                if (!child)
                    continue;
                const childScripts = (child.scripts ?? {});
                for (const [name, value] of Object.entries(childScripts)) {
                    if (typeof value !== 'string')
                        continue;
                    const kind = scriptKinds[name];
                    if (!kind)
                        continue;
                    if (isHookScript(name, childScripts))
                        continue;
                    push({
                        label: `npm script "${name}" (${dir})`,
                        command: packageScriptArgv(child, name, value),
                        kind,
                        source: 'package.json',
                        paths: [`${dir}/**`],
                        cwd: dir,
                        scriptDigest: sha256(value),
                    });
                }
            }
        }
    }
    // ---- Python ---------------------------------------------------------
    const pyRaw = await fs.readFile(join(root, 'pyproject.toml'));
    // pytest is discoverable through either file; a bare pytest.ini must not be
    // invisible just because the project never grew a pyproject.toml. The source
    // stays 'pyproject.toml' so already-minted pytest ids keep addressing.
    const hasPytestConfig = (pyRaw !== undefined && /(^|\n)\s*\[tool\.pytest/.test(pyRaw))
        || (await fs.readFile(join(root, 'pytest.ini'))) !== undefined;
    if (hasPytestConfig) {
        push({ label: 'pytest', command: pythonRunner(root, ['pytest', '-q']), kind: 'test', source: 'pyproject.toml', paths: ['*'] });
    }
    if (pyRaw !== undefined) {
        if (/(^|\n)\s*\[tool\.mypy/.test(pyRaw)) {
            push({ label: 'mypy', command: pythonRunner(root, ['mypy', '.']), kind: 'typecheck', source: 'pyproject.toml', paths: ['*'] });
        }
        if (/(^|\n)\s*\[tool\.ruff/.test(pyRaw)) {
            push({ label: 'ruff check', command: pythonRunner(root, ['ruff', 'check', '.']), kind: 'lint', source: 'pyproject.toml', paths: ['*'] });
        }
    }
    if ((await fs.readFile(join(root, 'tox.ini'))) !== undefined) {
        push({ label: 'tox', command: pythonRunner(root, ['tox', '-q']), kind: 'test', source: 'tox.ini', paths: ['*'] });
    }
    // ---- Go -------------------------------------------------------------
    if ((await fs.readFile(join(root, 'go.mod'))) !== undefined) {
        push({ label: 'go build', command: ['go', 'build', './...'], kind: 'build', source: 'go.mod', paths: ['*'] });
        push({ label: 'go vet', command: ['go', 'vet', './...'], kind: 'lint', source: 'go.mod', paths: ['*'] });
        push({ label: 'go test', command: ['go', 'test', './...'], kind: 'test', source: 'go.mod', paths: ['*'] });
    }
    // ---- Rust -----------------------------------------------------------
    const cargoRaw = await fs.readFile(join(root, 'Cargo.toml'));
    if (cargoRaw !== undefined) {
        push({ label: 'cargo check', command: ['cargo', 'check', '--all-targets'], kind: 'build', source: 'Cargo.toml', paths: ['*'] });
        push({ label: 'cargo test', command: ['cargo', 'test'], kind: 'test', source: 'Cargo.toml', paths: ['*'] });
        if (/(^|\n)\s*clippy/.test(cargoRaw) || (await fs.readFile(join(root, 'clippy.toml'))) !== undefined) {
            push({ label: 'cargo clippy', command: ['cargo', 'clippy', '--all-targets', '--', '-D', 'warnings'], kind: 'lint', source: 'Cargo.toml', paths: ['*'] });
        }
    }
    // ---- Make -----------------------------------------------------------
    const makeRaw = await fs.readFile(join(root, 'Makefile'));
    if (makeRaw !== undefined) {
        for (const target of parseMakeTargets(makeRaw)) {
            const kind = target === 'test' || target === 'check' ? 'test'
                : target === 'build' || target === 'all' ? 'build'
                    : target === 'lint' ? 'lint' : 'other';
            push({ label: `make ${target}`, command: ['make', target], kind, source: 'Makefile', paths: ['*'] });
        }
    }
    // ---- PHP ------------------------------------------------------------
    const composerRaw = await fs.readFile(join(root, 'composer.json'));
    if (composerRaw !== undefined) {
        const composer = parseJson(composerRaw);
        const scripts = (composer?.scripts ?? {});
        for (const name of ['test', 'phpunit', 'phpstan', 'psalm']) {
            if (typeof scripts[name] === 'string') {
                push({ label: `composer ${name}`, command: ['composer', name], kind: name === 'test' || name === 'phpunit' ? 'test' : 'typecheck', source: 'composer.json', paths: ['*'] });
            }
        }
    }
    return dedupe(found);
}
/** Stable check identity: the discovery source plus the exact command. */
export function checkId(source, command, cwd) {
    // `cwd` joins the hash material only when present, so ids minted before the
    // field existed (every root-dir check) stay byte-identical and the baselines
    // addressing them keep verifying. Monorepo siblings share argv but not cwd,
    // which is exactly what separates their identities.
    //
    // B6-L1 (collision note): the id truncates sha256 to 12 hex chars = 48
    // bits. Two *different* (source, command, cwd) triples colliding is the
    // birthday bound ~n²/2⁴⁹ (n=10⁴ checks in one workspace ⇒ ~3·10⁻⁷) and an
    // adversary needs ~2⁴⁸ chosen invocations; behavioural dedupe (below) keys
    // on (command, cwd), so a same-id/different-command collision would surface
    // as two specs sharing one id — a wrong-fail, not a silent merge. Widening
    // to 16 hex would change every existing id and orphan every baseline: it is
    // a versioned protocol change, not a casual fix — this comment is the
    // standing decision record.
    const material = cwd === undefined ? command.join('\u0000') : `${command.join('\u0000')}\u0000${cwd}`;
    return `${source}:${sha256(material).slice(0, 12)}`;
}
// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
/**
 * B6-L3: minimal shell-words split for config `command` strings — quotes
 * group, whitespace separates. The old `split(/\s+/)` shredded
 * `pytest -k "foo bar"` into `["pytest","-k","\"foo","bar\""]`, and the quote
 * fragments rode into argv, the label and the checkId material. Single and
 * double quotes both group; an unterminated quote keeps the rest of the
 * string as one token rather than inventing a split the author never wrote.
 * Behaviour for quote-free strings is byte-identical to the old splitter, so
 * every existing id stays put.
 *
 * W14-L8, the two documented deviations from full POSIX shell grammar:
 *
 * - **Single quotes have no escapes** (POSIX semantics, fixed): inside `'…'`
 *   every character is literal, backslash included, and only a bare `'`
 *   closes. The old reader unescaped `\'` there, which POSIX never does.
 * - **Double quotes escape only `\"`** (unchanged): the common shell reading;
 *   `\\` inside double quotes stays a literal backslash.
 * - **Outside quotes a backslash is LITERAL** (chosen, not POSIX): POSIX
 *   makes `\x` the literal `x` and `a\ b` ONE word, which would silently
 *   shred the Windows paths config authors legitimately write
 *   (`C:\ws\bin\tool` → `C:wsbintool` under POSIX rules). Keeping the
 *   backslash verbatim and splitting on real whitespace is deterministic,
 *   survives Windows spellings, and mis-splits only the rare escaped-space
 *   argv — a wrong-fail the config author sees immediately, never a silent
 *   identity change.
 */
function toArray(command) {
    if (typeof command !== 'string')
        return [...command];
    const out = [];
    let current = '';
    let quote;
    let started = false;
    const push = () => {
        if (started) {
            out.push(current);
            current = '';
            started = false;
        }
    };
    for (let i = 0; i < command.length; i += 1) {
        const ch = command[i];
        if (quote === "'") {
            // POSIX: no escape exists inside single quotes — the backslash is
            // content, only a bare quote closes.
            if (ch === "'") {
                quote = undefined;
                continue;
            }
            current += ch;
            continue;
        }
        if (quote === '"') {
            if (ch === '"') {
                quote = undefined;
                continue;
            }
            if (ch === '\\' && i + 1 < command.length && command[i + 1] === '"') {
                current += '"';
                i += 1;
                continue;
            }
            current += ch;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            started = true;
            continue;
        }
        if (/\s/.test(ch)) {
            push();
            continue;
        }
        current += ch;
        started = true;
    }
    push();
    return out;
}
function join(root, ...parts) {
    return `${root.replace(/\/+$/, '')}/${parts.filter(Boolean).join('/')}`;
}
function parseJson(raw) {
    try {
        const value = JSON.parse(raw);
        return typeof value === 'object' && value !== null ? value : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * Workspace member patterns as declared: literals (`apps/web`) and globs
 * (`packages/*`, `packages/**`) alike. Expansion against the real filesystem
 * happens in `expandWorkspacePatterns`; keeping them raw here is what lets
 * single-level globs reach their subpackages at all.
 */
function collectWorkspaceDirs(pkg) {
    const out = new Set();
    const add = (pattern) => {
        if (typeof pattern !== 'string')
            return;
        const normalized = pattern.replace(/\/+$/, '');
        if (normalized.length > 0)
            out.add(normalized);
    };
    if (Array.isArray(pkg.workspaces))
        pkg.workspaces.forEach(add);
    else if (pkg.workspaces && typeof pkg.workspaces === 'object') {
        const w = pkg.workspaces;
        if (Array.isArray(w.packages))
            w.packages.forEach(add);
    }
    return [...out];
}
/**
 * Resolve workspace patterns to concrete member directories. Single-level
 * globs (`packages/*`, `packages/**`) are expanded by listing the parent
 * directory and keeping every child that owns a package.json — without this,
 * the most common monorepo layout silently discovers nothing. Deeper or
 * unrecognised globs degrade to their literal prefix, which the caller's
 * package.json probe then filters. Missing directories yield nothing: there
 * are no members to lose.
 */
async function expandWorkspacePatterns(fs, root, patterns) {
    const out = new Set();
    for (const pattern of patterns) {
        if (!/[*?]/.test(pattern)) {
            out.add(pattern);
            continue;
        }
        const segments = pattern.split('/');
        const globIndex = segments.findIndex(s => /[*?]/.test(s));
        const deeper = globIndex >= 0 && segments.slice(globIndex + 1).some(s => /[*?]/.test(s));
        if (globIndex < 0 || deeper) {
            out.add(pattern.replace(/\/?\*.*$/, '').replace(/\/+$/, ''));
            continue;
        }
        const parent = segments.slice(0, globIndex).join('/');
        const names = await fs.readDir(join(root, parent));
        if (names === undefined)
            continue;
        for (const name of names) {
            const dir = parent === '' ? name : `${parent}/${name}`;
            // Only package.json-owning children are workspace members.
            if ((await fs.readFile(join(root, dir, 'package.json'))) !== undefined)
                out.add(dir);
        }
    }
    return [...out];
}
/**
 * npm hook semantics: `name` is a lifecycle hook only when stripping its
 * `pre`/`post` prefix leaves a script the same package actually declares.
 * A bare `pre`/`post` prefix (prettier, postcss, prepare) is just a name.
 */
function isHookScript(name, scripts) {
    for (const prefix of ['pre', 'post']) {
        if (!name.startsWith(prefix))
            continue;
        const base = name.slice(prefix.length);
        if (base.length > 0 && typeof scripts[base] === 'string')
            return true;
    }
    return false;
}
function workspacePaths(root, dirs) {
    if (dirs.length === 0)
        return ['*'];
    return ['*', ...dirs.map(d => `${d}/**`)];
}
/** How npm runs a script without a `run` prefix, pinned to the local binary. */
function packageScriptArgv(pkg, name, _value) {
    const hasPnpmLock = false; // argv stays package-manager agnostic on purpose.
    void hasPnpmLock;
    void pkg;
    void name;
    // `npm run <name>` is the only invocation that resolves `node_modules/.bin`
    // consistently across npm/pnpm/yarn, and it is what the project documents.
    return ['npm', 'run', '--silent', name];
}
function pythonRunner(root, argv) {
    void root;
    return argv;
}
function parseMakeTargets(makefile) {
    const targets = [];
    for (const line of makefile.split('\n')) {
        const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)/.exec(line);
        if (!m)
            continue;
        const name = m[1];
        if (name === undefined)
            continue;
        if (name === 'all' || name === 'test' || name === 'check' || name === 'build' || name === 'lint' || name === 'verify') {
            targets.push(name);
        }
    }
    return [...new Set(targets)];
}
/**
 * One invocation, one check. Deduping by id alone is not enough: ids embed
 * the discovery source, so a user-configured check and an auto-discovered
 * check running the *same command in the same directory* mint two ids for
 * one script — which the runner would then execute twice. The key here is
 * behavioural: `(command, cwd)`. Config entries are pushed before discovery,
 * so first-wins means explicit user intent overrides machine inference;
 * same-invocation discoveries are dropped, while different commands and
 * different cwds (monorepo siblings sharing argv) are untouched. (Identity
 * dedupe comes free: specs with the same id share source, command and cwd,
 * hence the same key.)
 */
function dedupe(specs) {
    const seen = new Map();
    for (const spec of specs) {
        const key = `${spec.command.join('\u0000')}\u0000${spec.cwd ?? ''}`;
        if (!seen.has(key))
            seen.set(key, spec);
    }
    return [...seen.values()];
}
export { DEFAULT_IGNORE_DIRS, DEFAULT_SCRIPT_KINDS };
//# sourceMappingURL=checks.js.map