/**
 * `dsh-proof` — Evidence-Driven Completion Proof & Regression Attribution.
 *
 * A DeepSeek Harness plugin that turns "I'm done" from a self-report into a
 * recomputable evidence chain, and "I fixed it but broke something else" from a
 * post-mortem into in-flight attribution.
 *
 * Architecture (three layers, one thesis):
 *
 *   src/core/*      pure domain — checks, evidence, impact, verdicts, reports
 *                   zero `@deepseek-ai/*` imports, all I/O through ports
 *   src/engine.ts   ProofEngine — the imperative façade hosts call
 *   src/dsh/*       thin Cordis adapter — tools, hooks, prompt section
 *
 * @module dsh-proof
 */
import { homedir } from 'node:os';
import * as nodePath from 'node:path';
import { ProofEngine } from "./engine.js";
import { createProofTools } from "./dsh/tools.js";
import { WorkspaceWatch, driftNarrative, isMutationToolName, shellCommandMentionsPath, sweepToolInputStrings, } from "./dsh/observe.js";
import { absoluteInside, deriveProofPaths, foldHostPath, guardedTargets, isAbsoluteHostPath, touchesEvidencePath, workspaceKeyPair, } from "./adapters/shared/paths.js";
import { buildPolicySection } from "./dsh/prompt.js";
import { createLspResolver } from "./dsh/lsp-impact.js";
import { attachTeamBridge, createTeamBridge } from "./dsh/agent-team.js";
// v0.25.1 (U4-H1): the raw `_readMarkers` primitive is no longer imported
// anywhere outside core/evidence.ts — the underscore escape hatch is retired
// and every trust read here goes through the engine's own store face.
import { NodeFsPort } from "./node-ports.js";
export const name = 'dsh-proof';
export const inject = ['tools'];
// The Schemastery schema AND the `Config` type, exactly as DSH's contract asks.
export { Config } from "./config.js";
export function apply(ctx, config) {
    const host = ctx;
    const root = process.env.DSH_PROOF_ROOT
        ?? hostWorkspaceRoot(ctx);
    // -- trust root: keys and anchors live with the host, never in the workspace.
    const trustRoot = (config.trustDir && config.trustDir.length > 0 ? config.trustDir : undefined)
        ?? process.env.DSH_PROOF_TRUST_DIR
        ?? nodePath.join(dshHome(), 'proof');
    // Y-H-14 (v0.24): the workspace identity comes from the ONE shared
    // derivation (paths.ts deriveProofPaths — normalised root spelling, legacy
    // on-disk fallback probe, containment warn), the same rule mcp-entry.ts and
    // the adapter hooks use. Pre-v0.24 this face minted a RAW sha256(root) —
    // the legacy key unconditionally — so a Windows-flavoured root spelled this
    // face's engine store and anchors under one key while the MCP server and
    // the hooks derived another: one workspace, two stores, neither
    // authoritative. X-H-15 rides along for free: a RELATIVE trust root now
    // fails loudly here too (deriveProofPaths asserts), instead of resolving
    // against the agent-writable CWD.
    const derivedPaths = deriveProofPaths({
        root,
        trustRoot,
        evidenceStore: config.evidenceStore,
        evidenceDir: config.evidenceDir,
    });
    const workspaceKey = derivedPaths.workspaceKey;
    const evidenceDir = config.evidenceStore === 'workspace'
        ? config.evidenceDir
        : nodePath.join(trustRoot, 'workspaces', workspaceKey);
    // Shared filesystem port: the engine, the LSP resolver and the watcher all
    // see the same files (and the resolver's cache keys off the same stats).
    const sharedFs = new NodeFsPort();
    const lspResolver = config.lspImpact === false
        ? undefined
        : createLspResolver(host.lsp, root, sharedFs, { budget: config.lspQueryBudget });
    const engine = new ProofEngine({
        root,
        evidenceDir,
        trustDir: trustRoot,
        workspaceKey,
        checkpointEvery: config.checkpointEvery,
        fs: sharedFs,
        ...(lspResolver !== undefined ? { resolver: lspResolver } : {}),
        excerptStrategy: config.excerptStrategy,
        ...(config.normalizeHome ? { homeDir: homedir() } : {}),
        autoDiscover: config.autoDiscover,
        checks: config.checks.map(c => ({
            ...(c.label !== undefined ? { label: c.label } : {}),
            command: c.command,
            ...(c.kind !== undefined ? { kind: c.kind } : {}),
            ...(c.paths !== undefined ? { paths: c.paths } : {}),
            ...(c.timeoutMs !== undefined ? { timeoutMs: c.timeoutMs } : {}),
            ...(c.exclusive !== undefined ? { exclusive: c.exclusive } : {}),
        })),
        checkTimeoutMs: config.checkTimeoutMs,
        verifyBudgetMs: config.verifyBudgetMs,
        concurrency: config.concurrency,
        impactGraph: config.impactGraph,
        impactGraphLimit: config.impactGraphLimit,
        // M14: the LSP round-trip cap was in the config and the engine option but
        // never travelled between them — a graph build silently ran on the engine
        // default (400) whatever the deployment asked for.
        lspQueryBudget: config.lspQueryBudget,
        headChars: config.headChars,
        scheduler: config.scheduler,
        certifyTarget: config.certifyTarget,
        ...(config.apiEntryPoints !== undefined && config.apiEntryPoints.length > 0
            ? { apiEntryPoints: config.apiEntryPoints }
            : {}),
        juryConfidenceCap: config.juryConfidenceCap,
        classBTrust: config.classBTrust,
        classCTrust: config.classCTrust,
        syntheticDir: config.syntheticDir,
        syntheticFalsePass: config.syntheticFalsePass,
        syntheticTimeoutMs: config.syntheticTimeoutMs,
        coverage: config.coverage,
        // M14: the engine's degradation-warning channel (E2 discipline — trust
        // downgrades must be visible, not just recorded): verbose mirrors the
        // plugin's own flag, and the logger lands on the host context's logger
        // when it has one (the vendor snapshot documents none) and the console
        // otherwise.
        verbose: config.verbose,
        logger: hostLogger(ctx),
    });
    const watch = new WorkspaceWatch(engineFs(engine), root);
    /** True once a `proof_claim` ran during the current turn. */
    let claimedThisTurn = false;
    let mutating = false;
    /** Set when `warn` passes a baseline-less mutation; consumed by turn end. */
    let pendingBaselineNotice = false;
    // λ: the physical evidence-log location, derived with the same rule
    // ProofEngine applies to its own private copy (the engine exports neither
    // the path nor its derivation, and EvidenceStore exposes no marker
    // read-back). The Class B/C tools read attestation markers back through the
    // engine's fs port with it — keep in lockstep with engine.ts's constructor.
    const evidenceLogPath = `${isAbsoluteHostPath(evidenceDir)
        ? evidenceDir.replace(/[\/]+$/, '')
        : `${root.replace(/[\/]+$/, '')}/${evidenceDir}`}/evidence.jsonl`;
    const log = (...args) => { if (config.verbose)
        console.log('[dsh-proof]', ...args); };
    // -- model-facing tools -------------------------------------------------
    // H9b: `shellUsed` rides the same route as `touched` — the entry closes over
    // its watch instance, so every verify/claim call the tools make carries the
    // session's shell fact alongside the session's touched set.
    for (const tool of createProofTools(engine, () => watch.sessionTouchedPaths(), evidenceLogPath, () => watch.sessionShellUsed())) {
        host.tools.register(tool);
        log(`registered tool ${tool.name}`);
    }
    // -- evidence-store guard: the log must not be agent-writable ------------
    // X-H-16 (v0.23): the guard is registered in BOTH store modes. v0.22 fixed
    // only the adapter face (gates.ts' host branch) — on this, the DSH plugin
    // face, the guard stayed wrapped in the `workspace` branch, so under the
    // DEFAULT deployment (host mode) an absolute path straight into
    // `<trustRoot>/workspaces/<key>` and every store-naming command string
    // passed with nothing asked. Workspace mode keeps its relative-space `ask`
    // below; host mode adds the structured deny the gates' host branch already
    // answers with.
    //
    // Y-H-12 (v0.24): the workspace-mode structural guard compares through
    // paths.ts `touchesEvidencePath` — the ONE fold, the same rule the adapter
    // gates run. Pre-v0.24 this face chained observe.ts's `toWorkspaceRelative`
    // + a local collapseSegments + its own lowercasing (the H10 case fold):
    // no `\\?\` device-prefix strip, no drive-relative projection
    // (`C:.proof/…` resolves by the OS straight into the store while comparing
    // as a relative stranger), no per-segment Win32 trailing-dot fold — the
    // exact spellings X-H-12's lockstep rule promised would move in the same
    // batch on both faces, and only the adapter face moved. The fold's
    // documented price is unchanged: on a genuinely case-sensitive filesystem
    // a sibling `.PROOF` directory also matches — one extra approval beats one
    // rewritten log. The derivation is pure (no identity probe): the key is
    // never read on this path.
    const workspaceGuardPaths = deriveProofPaths({ root, evidenceStore: 'workspace', evidenceDir: config.evidenceDir }, { pure: true });
    const touchesEvidence = (candidate) => touchesEvidencePath(candidate, workspaceGuardPaths);
    // X-H-16: host mode denies ABSOLUTE candidates into the host-side store —
    // `${trustRoot}/workspaces/<key>` for BOTH identity spellings, the same
    // storeDir set the adapter gates' host branch sweeps. The fold comparison
    // is paths.ts `absoluteInside`, which runs BOTH sides through G4's exported
    // `foldHostPath` — the ONE fold (device prefixes, drive-relative forms,
    // separators, case, trailing-dot deformation, `..` collapse) this face and
    // the adapter face are contractually in lockstep on; this file folds
    // nothing of its own here. A workspace-relative path cannot reach a store
    // that lives outside the workspace; an absolute one is exactly the H-26
    // write this branch exists to refuse.
    const trustFolded = foldHostPath(trustRoot);
    const identityPair = workspaceKeyPair(root);
    const identityKeys = identityPair.normalized === identityPair.legacy
        ? [identityPair.normalized]
        : [identityPair.normalized, identityPair.legacy];
    const hostStoreDirs = identityKeys.map(key => `${trustFolded}/workspaces/${key}`);
    // V5-M1/Y-H-11 (v0.24): the value-sweep target set is the ONE shared
    // constructor — paths.ts `guardedTargets`, the same list the adapter gates
    // sweep. Pre-v0.24 this face hand-rolled its own list and the two forked in
    // exactly the places the audit drove commands through: this face listed the
    // bare store DIRECTORY and the signing-key file names the adapter face
    // missed; that face listed the root-anchored store spellings this face
    // missed; neither listed the `~`/`$DSH_HOME` spellings of the default
    // trust root (`rm -rf ~/.dsh/proof` erased keys, anchors, stores and
    // session ledgers on BOTH faces measured). X-H-13 (v0.23) still holds: the
    // BARE artifact file names (`evidence.jsonl`, …) are deliberately NOT
    // sweep targets — the sweep reads every string value of every call, and a
    // bare name would deny any string that so much as names such a file under
    // ANY directory. The signing-key pair stays bare: no legitimate workspace
    // file carries those names, so a mention of either is worth refusing
    // wherever it points.
    const shellGuardTargets = guardedTargets(root, {
        evidenceStore: config.evidenceStore,
        evidenceDir: config.evidenceDir,
        trustRoot,
    });
    host.on('tools/pre-execute', async (exec, next) => {
        // X-H-13 (v0.23): VALUE SWEEP. The old guard read one command string out
        // of three key spellings and only on mutation-class names —
        // `{commandLine: …}`, `{code: …}`, mixed argv and read-only-listed names
        // carrying store-writing commands all passed measured. The sweep now
        // collects EVERY string value of EVERY call (see
        // `sweepToolInputStrings`: no key is enumerated, no name exempt — the
        // read-only roster included, a NAME is not a capability) and refuses the
        // call when any of them mentions a guarded target. A string that names
        // the store cannot be path-checked structurally or parsed for intent, so
        // any mention is refused — 宁误拦: the price is denying a genuinely
        // read-only call that names the store (a grep for `evidence.jsonl`, a
        // Read of the log), which costs one refused call with the reason below;
        // the plugin's own proof_* tools read the log through the engine's fs
        // port, never through host tool calls, so verification itself is not in
        // this blast radius.
        for (const value of sweepToolInputStrings(exec.arguments)) {
            if (shellCommandMentionsPath(value, shellGuardTargets)) {
                return {
                    kind: 'deny',
                    reason: 'dsh-proof: this call names the verification evidence store or its trust files in a '
                        + 'string argument, which must not be modified by the agent it is meant to audit — '
                        + 'string values cannot be path-checked structurally or parsed for intent, so any '
                        + 'store-naming value is refused rather than guessed at.',
                };
            }
        }
        if (!isMutationToolName(exec.name))
            return next();
        // contentKeys: the guard prefers over-detection — a `move {source:
        // '.proof/evidence.jsonl', dest: …}` carries the log out through the
        // very key the watcher excludes as content-noise. A false positive here
        // costs one approval prompt; a false negative costs the log. (The value
        // sweep above already denies most of these; this structured layer stays
        // for the shapes the sweep's bounds cannot see into.)
        const paths = WorkspaceWatch.pathsIn(exec.arguments, { contentKeys: true });
        if (config.evidenceStore === 'workspace') {
            if (!paths.some(touchesEvidence))
                return next();
            return {
                kind: 'ask',
                reason: 'dsh-proof: this call writes into the verification evidence store, which must not be modified by the agent it is meant to audit.',
                displayReason: {
                    en: 'dsh-proof: block writes to the evidence log?',
                    'zh-CN': 'dsh-proof：拒绝写入证据日志？',
                },
            };
        }
        // X-H-16: host mode — an absolute path into the trust-side store is the
        // one spelling that reaches it, and it is denied outright (the store
        // lives outside the workspace precisely so the agent it audits cannot
        // edit it; there is nothing here a user approval could legitimize).
        if (paths.some(candidate => hostStoreDirs.some(dir => absoluteInside(candidate, dir)))) {
            return {
                kind: 'deny',
                reason: 'dsh-proof: this call writes into the host-side verification evidence store by '
                    + 'absolute path — the store lives outside the workspace precisely so the agent it '
                    + 'audits cannot edit it. Evidence changes go through a human, never through your own tools.',
            };
        }
        return next();
    });
    // -- policy gate: no baseline, no unreviewed mutation --------------------
    if (config.requireBaseline !== 'off') {
        host.on('tools/pre-execute', async (exec, next) => {
            if (!isMutationToolName(exec.name))
                return next();
            try {
                const baseline = await engine.baseline();
                if (baseline !== undefined)
                    return next();
            }
            catch {
                return next();
            }
            const message = `dsh-proof: no verification baseline exists yet, and \`${exec.name}\` mutates the workspace. `
                + 'Establish one first with proof_baseline so later failures can be attributed correctly.';
            if (config.requireBaseline === 'ask') {
                return {
                    kind: 'ask',
                    reason: message,
                    displayReason: {
                        en: 'dsh-proof: run proof_baseline before mutating the workspace?',
                        'zh-CN': 'dsh-proof：改动工作区之前先建立验证基线？',
                    },
                };
            }
            // 'warn' owes the model a corrective notice, not a silent pass: flag the
            // gap now and inject it at turn end, where the model can still act on it.
            pendingBaselineNotice = true;
            log(`warn-gated ${exec.name}`);
            return next();
        });
    }
    // -- Class C human-endorsement seam (λ) ----------------------------------
    // proof_endorse records a named human's decision as evidence, and the
    // human's consciousness IS the evidence — the tool must never run on the
    // model's say-so alone. Routing it through `ask` hands the call to the
    // host's approval seam: the model calls, the host prompts, a human decides,
    // and only an approval lets execute append the attestation. Registered
    // after the evidence-store guard and the baseline gate, not between them:
    // the three hooks match on disjoint tool names so their order carries no
    // behavior, and keeping the established gates' registration order intact
    // means hosts (and tests) that index this pipeline keep their reading.
    host.on('tools/pre-execute', async (exec, next) => {
        if (exec.name !== 'proof_endorse')
            return next();
        const parsed = (exec.arguments ?? {});
        const claim = parsed.claim;
        const head = typeof claim === 'string' ? claim.slice(0, 80) : '(no claim text)';
        // M-70: the DIRECTION the record will carry is an agent parameter the
        // approval must make visible — an endorse has unlock power a reject does
        // not, so a human approving "recording" while the agent swapped the
        // decision is approving the wrong act. Shown exactly like the approver:
        // declared by the agent, seen by the human.
        const decision = parsed.decision === 'endorse' || parsed.decision === 'reject'
            ? parsed.decision
            : '(no usable decision — the tool will refuse)';
        // M5: the approver is agent-declared free text that the chain will record
        // as the responsible human — the human at the approval seam must SEE the
        // name they are about to vouch for, or Class C's named accountability can
        // be counterfeited wholesale (the human approves a claim; the chain logs a
        // name the agent invented). v0.16 makes it visible; whether to keep
        // trusting the self-report is a later batch's call.
        const approver = typeof parsed.approver === 'string' && parsed.approver.trim().length > 0
            ? parsed.approver
            : 'host-approver (default)';
        return {
            kind: 'ask',
            reason: `dsh-proof: a human must consciously endorse/reject this claim — approve to record Class C evidence? `
                + `claim: "${head}" decision (as declared by the agent): ${decision} `
                + `approver (as declared by the agent): ${approver}`,
            displayReason: {
                en: `dsh-proof: a human must consciously endorse/reject this claim — approve to record Class C evidence? `
                    + `decision (as declared by the agent): ${decision} `
                    + `approver (as declared by the agent): ${approver}`,
                'zh-CN': `dsh-proof：需要人类有意识地背书/否决此主张——批准以记录 Class C 证据？`
                    + `方向（由 agent 自报）：${decision === 'endorse' ? 'endorse（背书）' : decision === 'reject' ? 'reject（否决）' : decision} `
                    + `审批人（由 agent 自报）：${approver}`,
            },
        };
    });
    // -- observation: what actually moved -----------------------------------
    // Each event is still fire-and-forget (a tool result must never be delayed
    // by bookkeeping), but the latest observation's promise is kept: the turn
    // can stop right behind the last tool result, and drift/enforcement computed
    // from a half-written observation would read yesterday's state. The promise
    // is also RETURNED from the listener: hosts are free to ignore it (the void
    // contract is unchanged), while embedders and tests that need the
    // observation settled before touching the workspace get a deterministic
    // handle instead of racing the fingerprint read against their own writes.
    let pendingObserve = Promise.resolve();
    host.on('tools/result', (exec, result) => {
        pendingObserve = (async () => {
            try {
                await watch.observe(exec, result);
                if (isMutationToolName(exec.name))
                    mutating = true;
                if (exec.name === 'proof_claim')
                    claimedThisTurn = true;
            }
            catch (error) {
                log('observe failed', error);
            }
        })();
        return pendingObserve;
    });
    // -- drift + unproven-claim enforcement ---------------------------------
    // The hook must also exist when only `warn` is active: that mode defers its
    // baseline notice to here.
    if (config.driftDetection || config.enforceOnTurnEnd || config.requireBaseline === 'warn') {
        host.on('agent/turn-stopping', async (payload) => {
            try {
                // The last tool result of a turn can still be mid-observation when
                // this hook fires; drift computed before it lands reads stale
                // fingerprints/touched state. Wait for it — defensively: an observation
                // that rejects must be swallowed here too, since a failed fingerprint
                // can never be allowed to wedge the turn's wind-down.
                await pendingObserve.catch(() => undefined);
                const notices = [];
                if (config.driftDetection) {
                    const drift = await watch.detectDrift();
                    // M2 (H9② narrative half): once a shell ran this session, "changed
                    // outside your tool calls" is an accusation the watcher cannot back
                    // — the shell's edits are invisible to path extraction by
                    // construction. The narrative demotes to the honest wording.
                    const narrative = driftNarrative(drift, { shellUsed: watch.sessionShellUsed() });
                    if (narrative !== undefined)
                        notices.push(narrative);
                    if (drift.drifted.length > 0)
                        await watch.snapshot(drift.drifted);
                }
                if (pendingBaselineNotice) {
                    pendingBaselineNotice = false;
                    notices.push('⚠️ dsh-proof: this turn mutated the workspace, but it has no completion-proof baseline. '
                        + 'Run proof_baseline to establish one so later failures can be attributed to your changes.');
                }
                if (config.enforceOnTurnEnd && mutating && !claimedThisTurn) {
                    notices.push('⚠️ dsh-proof: this turn mutated the workspace but made no proven completion claim. '
                        + 'Before telling the user it is done, call proof_claim with the exact claim. '
                        + 'A prose assertion is not evidence.');
                }
                if (notices.length > 0) {
                    payload.agent.inject({
                        role: 'user',
                        content: [{ type: 'text', text: notices.join('\n\n') }],
                        source: { kind: 'plugin', plugin: name },
                    });
                }
            }
            catch (error) {
                log('turn-stopping hook failed', error);
            }
            finally {
                claimedThisTurn = false;
                mutating = false;
                watch.windowStart();
            }
        });
    }
    // -- experimental agent-team bridge (v0.19) -----------------------------
    // Strictly opt-in (config.agentTeamBridge, default false): the host's
    // agent-team API is unreleased, so the event vocabulary is duck-typed at
    // runtime. A recognized delegation event is mirrored onto the chain as a
    // signed obligation and the worker's handoff instruction rides the event's
    // payload back to the child context. When no seam is spoken here, the
    // bridge goes idle with ONE stderr line — proof_delegate via the MCP/engine
    // face stays the first-class path, and a host without team events sees no
    // behavior change at all.
    if (config.agentTeamBridge === true) {
        const stderrLine = (line) => { console.error(line); };
        const bridge = createTeamBridge({
            delegate: input => engine.delegateTask(input),
            instructionOf: teamHandoffInstruction,
            stderr: stderrLine,
            // H-12: the bridge's namespace facts (host id ↔ engine id, lost parent
            // edges) land on the chain as observation markers — stderr is ephemeral,
            // a re-linkable mapping is evidence.
            mark: (label, payload) => engine.storeView.mark(label, payload),
            // W7-M9: the persisted mapping is read back through the same verified
            // read the λ tools use (suspect lines excluded), so a restarted bridge
            // re-adopts its predecessor's hostId→engineId edges instead of
            // forgetting them and re-minting the children as roots.
            // v0.25.1 (U4-H1): the read goes through the store's own public
            // `markersWith` — ONE physical read owned by the store that wrote the
            // markers, not a hand-wired fsView.readLines + raw parse pass
            // re-deriving view semantics beside the door (the retired `_readMarkers`
            // escape hatch; test/32 claim 1b now pins it gone from src/).
            mappings: async () => {
                try {
                    return (await engine.storeView.markersWith('agent-team/delegated', { excludeSuspect: true }))
                        .map(marker => marker.payload)
                        .filter((payload) => typeof payload.hostTaskId === 'string' && payload.hostTaskId.length > 0
                        && typeof payload.engineTaskId === 'string' && payload.engineTaskId.length > 0)
                        .map(payload => ({ hostTaskId: payload.hostTaskId, engineTaskId: payload.engineTaskId }));
                }
                catch {
                    return [];
                }
            },
        });
        const attached = attachTeamBridge(ctx, bridge, stderrLine);
        log(`agent-team bridge ${attached ? 'attached' : 'idle: no delegation seam'} (experimental)`);
    }
    // -- system-prompt section ----------------------------------------------
    let disposeSection;
    if (config.promptSection && host.systemPrompt) {
        const register = () => {
            disposeSection = host.systemPrompt.section({
                id: config.promptScope,
                title: 'Completion proof',
                order: 60,
                scope: config.promptScope,
                content: () => {
                    const specs = engine.cachedChecks();
                    return buildPolicySection({
                        discovered: specs,
                        hasBaseline: engine.hasBaselineSync(),
                        requireBaseline: config.requireBaseline,
                    });
                },
            });
        };
        // The section reads engine state lazily; register immediately and refresh
        // discovery in the background so the first prompt is not empty. The same
        // prewarm probes the baseline: without it, a plugin loaded over a
        // workspace that already has a baseline on disk keeps saying "no baseline
        // yet" — `content()` re-evaluates on every render, so once `baselineSeen`
        // flips, the next frame tells the truth.
        register();
        void engine.loadChecks().catch(() => undefined);
        void engine.baseline().catch(() => undefined);
    }
    // -- teardown -----------------------------------------------------------
    host.effect(() => () => {
        disposeSection?.();
        disposeSection = undefined;
        log('unloaded');
    });
    log(`loaded (root=${root}, requireBaseline=${config.requireBaseline}, evidence=${config.evidenceStore}, trust=${trustRoot})`);
}
// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
/**
 * v0.19: the worker's handoff instruction the agent-team bridge injects into
 * a delegated subtask's context. Worded after the MCP `proof_delegate` face's
 * own handoff (src/app/mcp-server.ts `handoffInstruction`) — same protocol
 * steps, same precondition sentence — so a worker reached through the bridge
 * and one reached through proof_direct MCP are told exactly the same thing.
 * Exported for the wiring tests, which pin its textual elements.
 */
export function teamHandoffInstruction(taskId, obligationId, claim) {
    return [
        `DELEGATED OBLIGATION ${taskId} (obligation ${obligationId})`,
        '',
        'You are the worker agent for a delegated obligation on the agent-proof-protocol',
        'responsibility DAG. Make the claim below true IN YOUR OWN WORKSPACE, then prove',
        'it and submit the proof back to the orchestrator that delegated it.',
        '',
        'CLAIM (what must become true):',
        `  ${claim}`,
        '',
        'YOUR PART OF THE PROTOCOL, in order:',
        "  1. proof_baseline  — anchor your workspace's starting state before you change anything.",
        '  2. Do the work that makes the claim true.',
        '  3. proof_verify (or proof_claim carrying the claim text) — the affected checks must',
        '     re-run, and your session must grade "proven" with zero regressions before you',
        '     may submit.',
        '  4. proof_bundle    — export the tamper-evident APP bundle of your evidence chain. This',
        '     tool lives on the MCP tool face (dsh-proof-mcp), not the nine DSH proof_* tools; if',
        '     your session cannot call it, ask the orchestrator to bundle your workspace.',
        `  5. Submit it back with proof_delegate_submit { taskId: ${JSON.stringify(taskId)}, bundle: <the bundle proof_bundle returned> } —`,
        '     also an MCP-face tool; hand the bundle to the orchestrator for it to submit when',
        '     your own tool face cannot reach it.',
        '',
        'Your "proven" is the precondition of the parent task\'s "proven": until your bundle',
        'verifies, everything above you in the task graph stays stale — and a forged or',
        'regressed submission is attributed to you by taskId, never silently absorbed.',
    ].join('\n');
}
/** The harness home directory: keys and anchors live under `<home>/proof`. */
function dshHome() {
    const fromEnv = process.env.DSH_HOME;
    if (typeof fromEnv === 'string' && fromEnv.length > 0)
        return fromEnv;
    return nodePath.join(homedir(), '.dsh');
}
/**
 * Resolve the workspace root. `ctx` does not expose a portable workspace path
 * across DSH versions, so this walks the documented surfaces and falls back to
 * the process working directory — which is what the harness sets for the
 * session workspace anyway.
 */
function hostWorkspaceRoot(ctx) {
    const candidate = ctx.workspace?.root;
    if (typeof candidate === 'string' && candidate.length > 0)
        return candidate;
    return process.cwd();
}
/** The engine's FsPort, reused by the watcher so both see the same filesystem. */
function engineFs(engine) {
    return engine.fsView;
}
/**
 * M14: the engine's line logger for degradation warnings (E2/H5/H6 visibility).
 * The host-context surface this adapter is written against (see
 * `src/vendor/dsh-tools.ts`, the pinned snapshot) documents no `logger`
 * capability, so the console is the default — but if the running context does
 * expose one, it wins: same rule as every other capability probe here
 * (`host.lsp`, `host.systemPrompt`), structural read over assumption.
 */
function hostLogger(ctx) {
    const candidate = ctx.logger;
    if (typeof candidate === 'function') {
        return (message) => { candidate.call(ctx, message); };
    }
    return (message) => { console.log(message); };
}
/**
 * H-02/X-H-13: the Ed25519 signing-key pair's file names — MOVED (Y-H-11,
 * v0.24) to paths.ts `SIGNING_KEY_FILE_NAMES` so both guard faces refuse the
 * same names; see there. This face and the adapter gates both consume the
 * shared export through `guardedTargets` now.
 */
export { ProofEngine };
//# sourceMappingURL=index.js.map