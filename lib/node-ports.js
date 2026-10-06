/**
 * Real Node implementations of the core ports.
 *
 * Kept out of `core/` on purpose: the domain layer must not know it is running
 * on Node, and these adapters are the only place allowed to spawn processes or
 * touch `node:fs`.
 *
 * @module dsh-proof/node-ports
 */
import { spawn } from 'node:child_process';
import { existsSync, promises as fsp, readFileSync, statSync } from 'node:fs';
import * as path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
export class SystemClock {
    now() { return Date.now(); }
}
/**
 * Windows: `npm`, `pnpm`, `yarn` & co. ship as `.cmd` shims, which
 * `spawn(shell: false)` cannot execute (ENOENT for a bare name, EINVAL once
 * the name carries its `.cmd` extension). Rather than enabling a shell (an
 * injection surface this port refuses to open), the shims are *parsed*:
 * npm-generated `.cmd` files follow a stable template that ends in exactly
 * one invocation of `node <target> %*` (or `<target.exe> %*`), and that tail
 * can be rewritten into a pure argv vector — no string interpolation, still
 * no shell. The well-known `npm` fast path is kept ahead of the generic
 * parse: it needs no file read at all.
 */
function resolveWindowsArgv(argv, env, cwd) {
    const command = argv[0];
    if (command === undefined)
        return [...argv];
    const lower = command.toLowerCase();
    if (lower === 'npm' || lower === 'npm.cmd') {
        const cli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
        if (existsSync(cli))
            return [process.execPath, cli, ...argv.slice(1)];
    }
    const shimPath = findCmdShim(command, env, cwd);
    if (shimPath !== undefined) {
        const resolution = resolveCmdShim(shimPath);
        if (resolution !== undefined) {
            if ('script' in resolution)
                return [resolution.node, resolution.script, ...argv.slice(1)];
            return [resolution.exe, ...argv.slice(1)];
        }
    }
    return [...argv];
}
/**
 * npm-template invocation tails this parser is willing to rewrite. Both
 * template generations forward `%*` after exactly one quoted target relative
 * to the shim's own directory (`%dp0%` / `%~dp0`):
 *   current:  `... || title %COMSPEC% & "%_prog%"  "%dp0%\..\pkg\target" %*`
 *   legacy:   `"%~dp0\node.exe"  "%~dp0\..\pkg\target" %*` / `node  "..." %*`
 */
const SHIM_NODE_TAIL = /(?:"%_prog%"|"%~dp0\\node\.exe"|\bnode(?:\.exe)?)\s+"(?:%dp0%|%~dp0)\\([^"%]+)"\s+%\*\s*$/;
const SHIM_DIRECT_TAIL = /"(?:%dp0%|%~dp0)\\([^"%]+)"\s+%\*\s*$/;
function isRegularFile(p) {
    try {
        return statSync(p).isFile();
    }
    catch {
        return false;
    }
}
/**
 * Parses an npm-generated `.cmd` shim into a spawnable argv head — the
 * world's fix for "user configured `pnpm test` and spawn said ENOENT"
 * without ever opening a shell.
 *
 * Conservative by contract: ANY ambiguity — two different targets, an
 * unresolved `%VAR%` inside the target, a directly-invoked script that would
 * itself need a shell or interpreter — returns `undefined`, and the caller
 * lets the raw spawn fail with its clean spawnError instead. Never guess.
 */
export function resolveCmdShim(cmdPath) {
    let text;
    try {
        text = readFileSync(cmdPath, 'utf8').replace(/^\uFEFF/, '');
    }
    catch {
        return undefined;
    }
    const shimDir = path.dirname(cmdPath);
    const scripts = new Set();
    const exes = new Set();
    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (line.length === 0)
            continue;
        const nodeMatch = SHIM_NODE_TAIL.exec(line);
        if (nodeMatch !== null) {
            const rel = nodeMatch[1];
            // `%` here would mean an unresolved environment variable — refuse.
            if (rel === undefined || rel.includes('%'))
                return undefined;
            scripts.add(path.resolve(shimDir, rel).toLowerCase());
            continue;
        }
        const directMatch = SHIM_DIRECT_TAIL.exec(line);
        if (directMatch !== null) {
            const rel = directMatch[1];
            if (rel === undefined || rel.includes('%'))
                return undefined;
            const target = path.resolve(shimDir, rel).toLowerCase();
            // A directly-invoked script (`.js`, `.ps1`, extensionless) would itself
            // need a shell or an interpreter choice we cannot vouch for — refuse.
            if (!/\.(exe|com)$/.test(target))
                return undefined;
            exes.add(target);
        }
    }
    // Exactly one target, one shape — everything else is ambiguity.
    if (scripts.size > 1 || exes.size > 1 || (scripts.size > 0 && exes.size > 0))
        return undefined;
    if (scripts.size === 1) {
        const script = [...scripts][0];
        if (script === undefined || !isRegularFile(script))
            return undefined;
        // The template prefers a node.exe living next to the shim (portable
        // installs); fall back to the running runtime, exactly like `_prog=node`.
        const shimLocalNode = path.join(shimDir, 'node.exe');
        return { node: isRegularFile(shimLocalNode) ? shimLocalNode : process.execPath, script };
    }
    if (exes.size === 1) {
        const exe = [...exes][0];
        return exe !== undefined && isRegularFile(exe) ? { exe } : undefined;
    }
    return undefined;
}
/**
 * Case-robust PATH lookup — Windows hands the variable over as `Path` as
 * often as `PATH`, and a caller overlay may spell it yet another way. The
 * last definition wins: that is the caller's intent over the inheritance.
 */
function pathEnvValue(env) {
    let value;
    for (const key of Object.keys(env)) {
        if (key.toUpperCase() === 'PATH')
            value = env[key];
    }
    return value;
}
/**
 * Locates the `.cmd` shim cmd.exe would run for `command`, mirroring its
 * resolution closely enough to never hijack a directly-spawnable executable:
 * the spawn cwd first, then PATH directories in order; inside a directory
 * `.com`/`.exe`/`.bat` beat `.cmd` (PATHEXT order), and finding one means
 * plain spawn already handles the command — no rewrite, stay out of it.
 */
function findCmdShim(command, env, cwd) {
    const isCmdName = command.toLowerCase().endsWith('.cmd');
    if (/[\\/]/.test(command)) {
        if (!isCmdName)
            return undefined;
        const direct = path.resolve(cwd, command);
        return isRegularFile(direct) ? direct : undefined;
    }
    const cmdName = isCmdName ? command : `${command}.cmd`;
    const rivals = isCmdName ? [] : ['.com', '.exe', '.bat'];
    const dirs = [cwd, ...(pathEnvValue(env)?.split(';') ?? [])];
    for (const dir of dirs) {
        if (dir.trim().length === 0)
            continue;
        const base = path.resolve(dir);
        if (rivals.some((ext) => isRegularFile(path.join(base, command + ext))))
            return undefined;
        const candidate = path.join(base, cmdName);
        if (isRegularFile(candidate))
            return candidate;
    }
    return undefined;
}
/**
 * H-18: how long the port keeps waiting for `close` (exit + stdio EOF) after
 * it already knows the child is gone — the window in which a grandchild still
 * holding an inherited pipe must either let go or be declared "the pipes are
 * stuck". Also the grace added to the kill deadline for the absolute
 * settle-or-error backstop. Injectable so the deadline behaviour is testable
 * in real time instead of sleeping five seconds per case.
 */
export const PROCESS_TREE_GRACE_MS = 5_000;
/** Spawns argv vectors without a shell — no quoting games, no injection surface. */
export class NodeCommandPort {
    settleGraceMs;
    constructor(settleGraceMs = PROCESS_TREE_GRACE_MS) {
        this.settleGraceMs = settleGraceMs;
    }
    async run(argv, options) {
        // An already-aborted signal never fires its 'abort' listener, so checking
        // after spawn would let the child run until the timeout killed it.
        if (options.signal?.aborted) {
            return { exitCode: null, output: '', durationMs: 0, aborted: true };
        }
        // W15-L8(b): the timeout budget must be a finite positive number before
        // it reaches a timer. `Math.max(1, NaN)` is NaN and `setTimeout(NaN)`
        // fires in ~0ms; Node silently clamps anything above 2^31-1 to 1ms too —
        // so NaN, ±Infinity, zero and negatives each became an INSTANT kill
        // booked as `timedOut` ("ran too slow") when nothing ever ran, and a
        // caller asking for an enormous budget got the same 1ms death. A budget
        // that is not a finite positive number is a caller bug: refuse to spawn
        // and name it (the runner books the spawnError as a plain `error`
        // outcome — loud, honest, and NOT misattributed to slowness). A finite
        // positive budget beyond Node's timer domain is clamped to it, which is
        // the closest a timer can come to "effectively unlimited" without the
        // silent 1ms coercion.
        const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
            ? Math.min(options.timeoutMs, 2_147_483_647)
            : undefined;
        if (timeoutMs === undefined) {
            return {
                exitCode: null,
                output: '',
                durationMs: 0,
                aborted: false,
                spawnError: `invalid timeoutMs ${String(options.timeoutMs)} — refusing to spawn with a budget that could only misreport the death cause`,
            };
        }
        // Child environment, computed once so the Windows shim resolver sees the
        // same PATH the child will: inherited environment first, deterministic
        // color/CI defaults on top of it, caller overlay last — hosts stay free
        // to override when they must, everything else gets deterministic output.
        // B8-L2: an inherited NODE_V8_COVERAGE (the host process itself being
        // instrumented) is stripped — without this every check child and every
        // git child would keep writing V8 profiles into the HOST's coverage tree,
        // polluting the host report and perturbing the audited code. The runner's
        // deliberate per-run injection arrives via `options.env`, and the
        // overlay-last order keeps it authoritative.
        const inherited = { ...process.env };
        delete inherited.NODE_V8_COVERAGE;
        const env = {
            ...inherited, CI: '1', FORCE_COLOR: '0', NO_COLOR: '1', ...(options.env ?? {}),
        };
        // B8-L2 platform fact, verified on node 24/win32: Node core propagates
        // NODE_V8_COVERAGE into spawned node children EVEN WHEN the passed env
        // block omits it (NODE_OPTIONS-family behaviour; control variables do
        // not leak — the env block is honoured). When the host instrumented
        // itself but this run injects no coverage of its own, the host's flag is
        // unset for the duration of the synchronous spawn — the only window Node
        // reads it in — so the child cannot inherit it through that channel
        // either. An explicit overlay (the runner's per-run staging directory)
        // wins over the propagation, so the deliberate injection is unaffected.
        const hostCoverageLeak = options.env?.NODE_V8_COVERAGE === undefined
            ? process.env.NODE_V8_COVERAGE
            : undefined;
        const [command, ...args] = process.platform === 'win32'
            ? resolveWindowsArgv(argv, env, options.cwd)
            : [...argv];
        const started = Date.now();
        return new Promise((resolve) => {
            if (command === undefined) {
                resolve({ exitCode: null, output: '', durationMs: 0, aborted: false, spawnError: 'empty command' });
                return;
            }
            const maxChars = options.maxOutputChars ?? 64_000;
            let output = '';
            let aborted = false;
            let timedOut = false;
            let settled = false;
            // H-18(b): the child's own death facts, captured at 'exit' so a forced
            // settle (pipes stuck open) can still report them honestly.
            let exitSeen;
            // One decoder per stream: a multi-byte UTF-8 character straddling a
            // chunk boundary must survive the join instead of becoming U+FFFD —
            // captured evidence has to be byte-faithful for digests to be stable.
            const stdoutDecoder = new StringDecoder('utf8');
            const stderrDecoder = new StringDecoder('utf8');
            let child;
            try {
                if (hostCoverageLeak !== undefined)
                    delete process.env.NODE_V8_COVERAGE;
                child = spawn(command, args, {
                    cwd: options.cwd,
                    env,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    shell: false,
                    // H-18: on POSIX the child becomes its own process-group leader so
                    // a timeout/abort kill can take down the WHOLE tree — a grandchild
                    // holding an inherited stdio pipe is exactly why `close` (exit +
                    // stdio EOF) would otherwise never fire after the direct child
                    // dies, leaving this CommandResult forever pending and the whole
                    // verification batch hung. Windows is deliberately untouched:
                    // libuv spawns children into a job object there, and controlled
                    // experiments (D1 cross-validation + this suite's tree-kill test)
                    // show BOTH a kill of the direct child and its voluntary exit take
                    // the entire tree with them — `detached` would only detach the
                    // child from that guarantee without adding anything.
                    ...(process.platform !== 'win32' ? { detached: true } : {}),
                });
            }
            catch (error) {
                // Some argv heads (an explicit `.cmd`/`.bat` path, a null byte)
                // make spawn() itself throw synchronously — surface that as the
                // same clean spawnError instead of a rejected promise. No timer
                // or listener has been registered yet, so resolve directly.
                resolve({
                    exitCode: null,
                    output: '',
                    durationMs: Date.now() - started,
                    aborted: false,
                    spawnError: `spawn failed: ${error instanceof Error ? error.message : String(error)}`,
                });
                return;
            }
            finally {
                // B8-L2: restore the host's own instrumentation flag the instant the
                // synchronous spawn (or its synchronous failure) is past — the host
                // process keeps its own coverage configuration untouched.
                if (hostCoverageLeak !== undefined)
                    process.env.NODE_V8_COVERAGE = hostCoverageLeak;
            }
            // H-18(b): settle safety nets. `close` = exit + stdio EOF; a descendant
            // holding an inherited pipe can keep EOF away long after (on POSIX,
            // forever). These timers force the promise to settle with the facts the
            // port already holds instead of hanging the caller's batch. All are
            // cleared by `finish` on the normal path — including (W15-L9) the
            // SIGKILL escalation timers a kill registers, so a settled result never
            // leaves a live group-kill aimed at a possibly-recycled pid behind.
            const settleTimers = [];
            const finish = (exitCode, spawnError, killedBySignal, timedOut) => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                for (const t of settleTimers)
                    clearTimeout(t);
                options.signal.removeEventListener('abort', onAbort);
                // Flush decoders: a tail partial sequence (killed process) surfaces
                // as replacement characters instead of silently vanishing bytes.
                output += stdoutDecoder.end() + stderrDecoder.end();
                // B7-L1: truncation is stated IN the captured output, not merely
                // implied by the cap — a reader holding a clean-looking head must be
                // able to tell there was more (the failure line was typically at the
                // tail we dropped). The marker rides the tail and is digested like
                // any other content.
                const captured = output.length > maxChars
                    ? `${output.slice(0, maxChars)}\n[dsh-proof] output truncated: kept ${maxChars} of ${output.length} chars`
                    : output;
                resolve({
                    exitCode,
                    output: captured,
                    durationMs: Date.now() - started,
                    aborted,
                    ...(spawnError !== undefined ? { spawnError } : {}),
                    // Signal deaths NOT caused by this port's own abort/timeout — the
                    // fact that separates an external kill from a timeout at the port
                    // boundary. Since libuv 1.44 this port's own kills propagate the
                    // signal on Windows too; only a third party's TerminateProcess
                    // (exit code, no signal) stays unattributable, and there it stays
                    // unset rather than inventing one.
                    ...(!aborted && killedBySignal !== undefined ? { killedBySignal } : {}),
                    // "We killed it for exceeding the budget" — the honest death
                    // cause, kept orthogonal to the legacy spawnError text above.
                    ...(timedOut === true ? { timedOut: true } : {}),
                });
            };
            // H-18(b): the exit facts survive a missing `close`. When the deadline
            // fires the child is already gone on POSIX-shaped platforms — only the
            // pipes were stuck — so its own exit code/signal are the honest answer,
            // annotated with why the port settled without `close`.
            const forceSettle = (reason) => {
                if (exitSeen !== undefined) {
                    if (timedOut && exitSeen.code === null) {
                        finish(null, `timed out after ${timeoutMs}ms (${reason})`, undefined, true);
                        return;
                    }
                    finish(exitSeen.code, `${reason}; descendants may still hold the pipes`, exitSeen.signal ?? undefined, timedOut || undefined);
                    return;
                }
                // Not even `exit` arrived: the kill window (timeout + escalation)
                // elapsed without the child dying. Best-effort error shape carrying
                // whatever first-class facts the port holds.
                finish(null, `${reason}: no exit within the deadline`, undefined, timedOut || undefined);
            };
            const onAbort = () => {
                aborted = true;
                const escalation = killChild(child);
                if (escalation !== undefined)
                    settleTimers.push(escalation);
            };
            options.signal.addEventListener('abort', onAbort, { once: true });
            const timer = setTimeout(() => {
                timedOut = true;
                const escalation = killChild(child);
                if (escalation !== undefined)
                    settleTimers.push(escalation);
            }, timeoutMs);
            // H-18(b) absolute backstop: even `exit` refusing to arrive (kill
            // escalation failing, platform weirdness) must not hang the batch
            // forever. Fires after the full kill window (budget + grace + the
            // SIGTERM→SIGKILL escalation) and settles with the no-exit shape above.
            // W15-L8b: the sum is clamped to Node's timer domain — a clamped
            // near-2^31 budget plus grace would otherwise overflow back into the
            // silent 1ms coercion the entry clamp exists to prevent.
            settleTimers.push(setTimeout(() => forceSettle('kill deadline exceeded'), Math.min(timeoutMs + this.settleGraceMs + 2_500, 2_147_483_647)));
            // Always feed the decoders (their buffered partial bytes must not
            // desync), only stop appending once the capture cap is far exceeded.
            child.stdout?.on('data', (chunk) => {
                const text = stdoutDecoder.write(chunk);
                if (output.length < maxChars * 2)
                    output += text;
            });
            child.stderr?.on('data', (chunk) => {
                const text = stderrDecoder.write(chunk);
                if (output.length < maxChars * 2)
                    output += text;
            });
            child.on('error', (error) => {
                finish(null, `spawn failed: ${error.code ?? error.message}`);
            });
            child.on('exit', (code, signal) => {
                if (exitSeen !== undefined)
                    return;
                exitSeen = { code, signal };
                // Grace window for `close` to follow `exit` (it is milliseconds in
                // the normal case): beyond it, somebody still holds the pipes.
                settleTimers.push(setTimeout(() => forceSettle('stdio still open after child exit'), this.settleGraceMs));
            });
            child.on('close', (code, signal) => {
                if (timedOut && code === null) {
                    // The spawnError text stays (consumers match on it), but the
                    // first-class `timedOut` fact is what the runner reads now.
                    finish(null, `timed out after ${timeoutMs}ms`, undefined, true);
                    return;
                }
                // H-18(d)/B7-M1: a child that trapped our SIGTERM and exited BY CODE
                // (graceful services, jest worker pools — common on POSIX) must not
                // launder the timeout into a decisive exit-code result: "we killed it
                // for exceeding the budget" is true whatever shape the corpse took,
                // so `timedOut` rides along and the runner reads it before the code.
                finish(code, undefined, signal ?? undefined, timedOut || undefined);
            });
        });
    }
}
function killChild(child) {
    // H-18: take the whole process tree down, not just the direct child.
    // POSIX: the child was spawned detached (group leader), so a negative pid
    // signals the entire group — grandchildren included — which is what
    // releases the stdio pipes `close` is waiting on. Windows: libuv's job
    // object already kills the tree together with the child (verified by
    // controlled experiment — kill AND voluntary exit both take grandchildren
    // down on win32), so the plain child kill is the whole answer there.
    const groupKill = (signal) => {
        if (process.platform !== 'win32' && child.pid !== undefined) {
            try {
                process.kill(-child.pid, signal);
                return;
            }
            catch { /* group already gone — fall through to the direct kill */ }
        }
        try {
            child.kill(signal);
        }
        catch { /* already gone */ }
    };
    try {
        groupKill('SIGTERM');
        // W15-L9: the SIGTERM→SIGKILL escalation timer is RETURNED so the caller
        // can register it in the same settle list `finish` clears. Left to its
        // own devices it fires two seconds after every timeout kill, long after
        // the CommandResult settled — and if the dead child's pid/pgid was
        // recycled inside that window, the group SIGKILL lands on an innocent
        // process group. unref keeps the process lifetime honest either way.
        return setTimeout(() => { groupKill('SIGKILL'); }, 2_000).unref();
    }
    catch {
        /* already gone */
        return undefined;
    }
}
/**
 * Distinguishes concurrent temp files inside ONE process: `${pid}` alone let
 * two concurrent writers of the same target path (two verifications
 * refreshing the same anchor) share a temp name and clobber each other's
 * partial write between the write and the rename.
 */
let tempFileCounter = 0;
function nextTempName(target) {
    return `${target}.${process.pid}.${tempFileCounter++}.tmp`;
}
/**
 * Windows concurrency wart on atomic writes: MoveFileEx replacing an
 * existing destination can fail EPERM/EBUSY/EACCES for the instants another
 * writer (another verification refreshing the same anchor) holds it. Unique
 * temp names removed the write-write collision; this bounded retry closes
 * the rename-rename one. Non-transient codes surface immediately, and the
 * orphan temp file is cleaned up on the way out so failed writes leave no
 * residue next to the target.
 */
async function renameReplacing(from, to) {
    const transientCodes = new Set(['EPERM', 'EBUSY', 'EACCES']);
    for (let attempt = 0;; attempt++) {
        try {
            await fsp.rename(from, to);
            return;
        }
        catch (error) {
            const code = error.code;
            if (!transientCodes.has(code ?? '') || attempt >= 9) {
                try {
                    await fsp.unlink(from);
                }
                catch { /* nothing more to give back */ }
                throw error;
            }
            await new Promise((r) => setTimeout(r, 5 * (attempt + 1)));
        }
    }
}
export class NodeFsPort {
    async readFile(filePath) {
        try {
            return await fsp.readFile(filePath, 'utf8');
        }
        catch {
            return undefined;
        }
    }
    async readDir(dirPath) {
        try {
            return await fsp.readdir(dirPath);
        }
        catch {
            return undefined;
        }
    }
    async stat(filePath) {
        try {
            const st = await fsp.lstat(filePath);
            return {
                kind: st.isFile() ? 'file' : st.isDirectory() ? 'dir' : 'other',
                size: st.size,
                mtimeMs: st.mtimeMs,
            };
        }
        catch {
            return undefined;
        }
    }
    async walk(root, options = {}) {
        const ignore = new Set(options.ignoreDirs ?? []);
        const limit = options.limit ?? 20_000;
        const out = [];
        const visit = async (dir, prefix) => {
            if (out.length >= limit)
                return;
            let entries;
            try {
                entries = await fsp.readdir(dir, { withFileTypes: true });
            }
            catch {
                return;
            }
            for (const entry of entries) {
                if (out.length >= limit)
                    return;
                if (entry.name.startsWith('.') && entry.name !== '.')
                    continue;
                const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
                if (entry.isDirectory()) {
                    if (ignore.has(entry.name))
                        continue;
                    await visit(path.join(dir, entry.name), rel);
                }
                else if (entry.isFile()) {
                    out.push(rel);
                }
            }
        };
        await visit(root, '');
        // M8: the walk stops the moment it holds `limit` files, so reaching the
        // cap means the listing is a prefix, never a census — even a workspace of
        // exactly `limit` files cannot be distinguished from a bigger one without
        // walking past the cap, so the honest answer at the cap is `truncated`.
        // Consumers must treat the file list as incomplete (judge the graph
        // uncertain), not as "the whole workspace".
        const truncated = out.length >= limit;
        return { files: out.sort(), truncated };
    }
    async appendLine(filePath, line) {
        await fsp.mkdir(path.dirname(filePath), { recursive: true });
        // M-31: the log path must be a regular file before the host appends to
        // it. In workspace evidence mode the log lives in an agent-writable
        // directory; a symlink planted there used to redirect every host-side
        // append (agent-influenced JSON payloads) through to ANY file the host
        // can write. `writeFile` already refuses transitively (temp+rename
        // replaces the link itself); this makes appendLine symmetric with it.
        // An absent path is fine (first line); anything that exists and is not a
        // regular file — symlink, junction, directory — is refused loudly.
        let existing;
        try {
            existing = await fsp.lstat(filePath);
        }
        catch (error) {
            if (error.code !== 'ENOENT')
                throw error;
        }
        if (existing !== undefined && !existing.isFile()) {
            throw new Error(`appendLine refuses '${filePath}': not a regular file (${existing.isSymbolicLink() ? 'symlink' : existing.isDirectory() ? 'directory' : 'special file'}) — the evidence log must not be a redirect`);
        }
        await fsp.appendFile(filePath, `${line}\n`, 'utf8');
    }
    async readLines(filePath) {
        try {
            const raw = await fsp.readFile(filePath, 'utf8');
            return raw.split('\n').filter(l => l.trim().length > 0);
        }
        catch {
            return [];
        }
    }
    async writeFile(filePath, contents) {
        await fsp.mkdir(path.dirname(filePath), { recursive: true });
        const tmp = nextTempName(filePath);
        await fsp.writeFile(tmp, contents, 'utf8');
        await renameReplacing(tmp, filePath);
    }
    async mkdirp(dirPath) {
        await fsp.mkdir(dirPath, { recursive: true });
    }
    /**
     * υ: recursive best-effort directory removal for transient artifacts (the
     * V8-coverage scratch tree a verification collects and then throws away).
     * Failure is swallowed on purpose: what lives under these paths is
     * regenerable staging, and a cleanup error must never fail a verification
     * that already produced its proof. `force` rides along so a read-only
     * leftover file or a Windows file-lock wart degrades to "still there until
     * the next run overwrites it" instead of an exception.
     */
    async removeDir(dirPath) {
        try {
            await fsp.rm(dirPath, { recursive: true, force: true });
        }
        catch {
            /* staging area; the next run recreates it regardless */
        }
    }
}
/**
 * Ed25519 checkpoint signer whose key lives in a host-side directory the
 * agent's sandboxed tools cannot write to (default DSH_HOME, never the
 * workspace). The private key is created with owner-only permissions on
 * first use and never leaves the directory.
 *
 * The trust asymmetry this buys: the model can recompute every hash in the
 * evidence log, but only this key can produce the checkpoint signatures the
 * audit chain accepts.
 */
export class NodeEd25519Signer {
    keyId;
    privateKeyPem;
    publicKeyPem;
    constructor(privateKeyPem, publicKeyPem) {
        this.privateKeyPem = privateKeyPem;
        this.publicKeyPem = publicKeyPem;
        this.keyId = createHash('sha256').update(publicKeyPem, 'utf8').digest('hex').slice(0, 16);
    }
    /** Load the key from `dir`, creating it on first use. */
    static async load(dir) {
        await fsp.mkdir(dir, { recursive: true });
        const privateKeyPath = path.join(dir, 'proof-signing-key.pem');
        const publicKeyPath = path.join(dir, 'proof-signing-key.pub.pem');
        let privatePem;
        try {
            privatePem = await fsp.readFile(privateKeyPath, 'utf8');
        }
        catch (error) {
            // H11: only a key that provably does not exist may be created. Any
            // other read failure (EPERM/EBUSY from an AV scan or indexer lock,
            // EISDIR, a transient network blip) must REJECT: generating a fresh
            // pair here would silently rotate the key — every existing checkpoint
            // signature stops verifying and nothing on record says why. Callers
            // already have a loud degradation path for a load that throws (the
            // chain continues unsigned, marked signer-unavailable).
            if (error.code !== 'ENOENT')
                throw error;
            const { privateKey, publicKey } = generateKeyPairSync('ed25519');
            privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
            const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
            // Write the private half first (atomic temp+rename, owner-only) so a
            // crash never leaves a public half without its private counterpart.
            // M-83: the public half is now atomic too — a torn first write used to
            // leave a half PEM whose sha256 drifted the keyId and made verify()
            // throw (read as `false`) for every historical checkpoint until an
            // operator deleted the file by hand.
            const privateTmp = nextTempName(privateKeyPath);
            await fsp.writeFile(privateTmp, privatePem, { mode: 0o600 });
            await renameReplacing(privateTmp, privateKeyPath);
            const publicTmp = nextTempName(publicKeyPath);
            await fsp.writeFile(publicTmp, publicPem, { mode: 0o644 });
            await renameReplacing(publicTmp, publicKeyPath);
        }
        let publicPem;
        try {
            publicPem = await fsp.readFile(publicKeyPath, 'utf8');
        }
        catch {
            // Key exists but the public half is missing: derive it from the private key.
            publicPem = createPublicKey(createPrivateKey(privatePem)).export({ type: 'spki', format: 'pem' });
            const publicTmp = nextTempName(publicKeyPath);
            await fsp.writeFile(publicTmp, publicPem, { mode: 0o644 });
            await renameReplacing(publicTmp, publicKeyPath);
        }
        // M-83: the private half is the authority — verify the public file
        // actually matches it. A torn write or an on-disk swap used to be
        // adopted silently, drifting keyId (a torn half) or pinning verification
        // to a stranger's key (a swap). Mismatch repairs the public half
        // atomically from the private key (keyId stays stable, every historical
        // checkpoint keeps verifying) and says so loudly: the trust directory is
        // host-side operational surface, stderr is the always-available channel.
        const derivedPublicPem = createPublicKey(createPrivateKey(privatePem))
            .export({ type: 'spki', format: 'pem' });
        if (publicPem !== derivedPublicPem) {
            process.stderr.write(`dsh-proof: signer public key at ${publicKeyPath} does not match the private key — repaired from the private half (torn write or tamper?)\n`);
            const repairTmp = nextTempName(publicKeyPath);
            await fsp.writeFile(repairTmp, derivedPublicPem, { mode: 0o644 });
            await renameReplacing(repairTmp, publicKeyPath);
            publicPem = derivedPublicPem;
        }
        // Belt and braces: one sign+verify round-trip through the loaded pair
        // before the signer is handed out, so a key that cannot even self-verify
        // fails HERE, loudly, instead of poisoning every later checkpoint.
        const selfTest = Buffer.from('dsh-proof signer self-test', 'utf8');
        const selfSignature = edSign(null, selfTest, createPrivateKey(privatePem));
        if (!edVerify(null, selfTest, createPublicKey(publicPem), selfSignature)) {
            throw new Error(`ed25519 key pair in ${dir} failed its sign+verify self-test`);
        }
        return new NodeEd25519Signer(privatePem, publicPem);
    }
    async sign(data) {
        const key = createPrivateKey(this.privateKeyPem);
        return edSign(null, Buffer.from(data, 'utf8'), key).toString('base64');
    }
    async verify(data, signature) {
        try {
            const key = createPublicKey(this.publicKeyPem);
            return edVerify(null, Buffer.from(data, 'utf8'), key, Buffer.from(signature, 'base64'));
        }
        catch {
            return false;
        }
    }
}
/**
 * Parses `git status --porcelain -z` output into the set of paths it mentions.
 *
 * The `-z` stream is a sequence of NUL-terminated fields. Each entry begins
 * with a status field `XY <path>` (two status letters, a space, the path);
 * when the status contains `R` (rename) or `C` (copy) the ORIGINAL path
 * follows as a second bare field with no prefix — both halves are workspace
 * facts, so both are collected. Paths are emitted verbatim (`-z` performs no
 * C-quoting, so `sp ace.ts` arrives unquoted).
 *
 * Tolerant by design: a field without a status prefix (truncated or garbage
 * stream) is kept verbatim rather than dropped — dirtiness must never be
 * under-reported.
 */
export function parsePorcelainZ(output) {
    const fields = output.split('\0');
    const paths = [];
    for (let i = 0; i < fields.length; i++) {
        const field = fields[i];
        if (field === undefined || field.length === 0)
            continue;
        if (field.length >= 3 && field.charCodeAt(2) === 0x20 /* space */) {
            // Status field: 'XY <new-path>', possibly followed by the old path.
            const newPath = field.slice(3);
            if (newPath.length > 0)
                paths.push(newPath);
            const status = field.slice(0, 2);
            if (status.includes('R') || status.includes('C')) {
                const oldPath = fields[++i];
                if (oldPath !== undefined && oldPath.length > 0)
                    paths.push(oldPath);
            }
        }
        else {
            paths.push(field);
        }
    }
    return paths.sort();
}
/** Git-backed workspace facts. Degrades to "unknown" outside a work tree. */
export class GitWorkspace {
    root;
    commands;
    /**
     * Cached availability probe — with a B8-L4 twist: only a DEFINITIVE answer
     * (git ran and said "true", or ran and exited non-zero) is remembered for
     * the process lifetime. A probe that produced no answer at all (timeout
     * while an AV scanner warms up git.exe, a spawn failure) may have been
     * transient, so exactly one in-session re-probe is allowed before the
     * failure is believed — "the probe could not run" is not "there is no git".
     */
    gitAvailablePromise;
    gitAvailableDefinitive = false;
    gitProbeAttempts = 0;
    constructor(root, commands = new NodeCommandPort(), clock = new SystemClock()) {
        this.root = root;
        this.commands = commands;
        void clock;
    }
    /**
     * Whether git can answer questions about this workspace at all — the binary
     * is present AND the root sits inside a work tree (E3). Probed and
     * remembered as described on the fields above: definitive answers never
     * re-probe; answer-less probes get one retry.
     *
     * `--is-inside-work-tree` exits non-zero outside any repository, but exits
     * ZERO with "false" inside a bare one — so the output is checked too, not
     * just the exit code, or a bare repo would pass as verifiable.
     */
    gitAvailable() {
        if (this.gitAvailablePromise !== undefined
            && (this.gitAvailableDefinitive || this.gitProbeAttempts >= 2)) {
            return this.gitAvailablePromise;
        }
        this.gitProbeAttempts += 1;
        this.gitAvailablePromise = this.commands
            .run(['git', 'rev-parse', '--is-inside-work-tree'], {
            cwd: this.root, timeoutMs: 5_000, signal: AbortSignal.timeout(5_000),
        })
            .then((result) => {
            if (result.exitCode !== null && result.spawnError === undefined) {
                this.gitAvailableDefinitive = true;
                return result.exitCode === 0 && result.output.trim() === 'true';
            }
            // A probe that cannot even run is not an availability proof — and not
            // proof of absence either: answer false now, retry once later.
            return false;
        }, () => false);
        return this.gitAvailablePromise;
    }
    async gitHead() {
        const result = await this.commands.run(['git', 'rev-parse', 'HEAD'], {
            cwd: this.root, timeoutMs: 5_000, signal: AbortSignal.timeout(5_000),
        });
        // B8-L1/M-82: "no answer" (timeout kill, caller abort, spawn failure) is
        // a query FAILURE, not "no commit" — folding it into null let a transient
        // HEAD failure silently narrow every later change set (changedSince is
        // skipped on a null head, and nothing said the head was merely unknown).
        // Throwing lands in the engine's existing git-blind degradation
        // (gitHeadMissing -> forced full run). Only an ANSWERED non-zero exit —
        // an unborn branch, a non-repo — is the legitimate null: "no commit" is
        // a fact, not a failure.
        if (result.exitCode === null || result.spawnError !== undefined) {
            const detail = result.spawnError !== undefined
                ? result.spawnError
                : `killed or timed out${result.aborted ? ' (aborted by the caller)' : ''}`;
            throw new Error(`git rev-parse HEAD produced no answer (${detail})`);
        }
        return result.exitCode === 0 ? result.output.trim() || null : null;
    }
    /**
     * H6: a failed git query is not an empty answer. `git status` returning
     * 128 (index.lock contention, a mid-crash repository) and a query killed
     * by its own timeout used to coerce into `[]` — indistinguishable from
     * "clean", which let committed changes vanish from change sets and old
     * evidence pass as fresh. Now the failure THROWS, naming the subcommand
     * and the exit code, and callers degrade loudly (the change-set resolution
     * marks itself degraded and forces a full run). `gitHead` keeps its
     * `string | null` contract — "no commit" is a legitimate answer there —
     * and `gitAvailable` keeps probing softly: "no git installed" is an
     * environment fact, not a query failure.
     */
    requireGitOk(result, subcommand) {
        if (result.exitCode === null || result.spawnError !== undefined) {
            // Killed by the query's own timeout, aborted by the caller, or never
            // spawned — none of these is an answer, let alone "clean".
            const detail = result.spawnError !== undefined
                ? result.spawnError
                : `killed or timed out${result.aborted ? ' (aborted by the caller)' : ''}`;
            throw new Error(`git ${subcommand} produced no answer (${detail})`);
        }
        if (result.exitCode !== 0) {
            throw new Error(`git ${subcommand} failed with exit code ${result.exitCode}: ${result.output.trim().slice(0, 200)}`);
        }
    }
    async gitDirty() {
        const result = await this.commands.run(['git', 'status', '--porcelain', '-z'], {
            cwd: this.root, timeoutMs: 10_000, signal: AbortSignal.timeout(10_000),
        });
        this.requireGitOk(result, 'status --porcelain -z');
        // Both ends of a rename/copy are workspace facts — see parsePorcelainZ.
        return parsePorcelainZ(result.output);
    }
    /**
     * Files modified since `ref`, relative to root — the session's change set.
     *
     * `git diff --name-only -z` emits a plain NUL-separated path list: every
     * path terminated by NUL, no status prefixes, no rename pairing, no
     * quoting — so `split('\0')` + dropping empty strings is the exact inverse.
     * A failed query rejects (see `requireGitOk`): never a silent empty set.
     */
    async changedSince(ref) {
        // B8-L5: the trailing `--` ends the revision list — a ref that begins
        // with '-' (it comes from baseline material) must never be parsed as a
        // git OPTION (`--output=<file>` writes files).
        const result = await this.commands.run(['git', 'diff', '--name-only', '-z', ref, '--'], {
            cwd: this.root, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
        });
        this.requireGitOk(result, `diff --name-only -z ${ref} --`);
        return result.output.split('\0').filter(Boolean).sort();
    }
    /**
     * Untracked files (honouring .gitignore), relative to root.
     *
     * `git ls-files --others --exclude-standard -z` also emits a plain
     * NUL-separated path list (no prefixes, no quoting), so `split('\0')` +
     * dropping empty strings parses it exactly. A failed query rejects (see
     * `requireGitOk`): never a silent empty set.
     */
    async untracked() {
        const result = await this.commands.run(['git', 'ls-files', '--others', '--exclude-standard', '-z'], {
            cwd: this.root, timeoutMs: 15_000, signal: AbortSignal.timeout(15_000),
        });
        this.requireGitOk(result, 'ls-files --others --exclude-standard -z');
        return result.output.split('\0').filter(Boolean).sort();
    }
}
//# sourceMappingURL=node-ports.js.map