/**
 * Regression attribution: turning "something is broken" into "this change
 * broke this check, and here is the file that owns it".
 *
 * A regression is charged to the current session only when the check passed at
 * baseline and fails now. Anything already red at baseline is pre-existing and
 * is reported as such — otherwise an agent "fixing" one thing inherits every
 * historical failure and learns to lie about the rest.
 *
 * @module dsh-proof/core/regression
 */
import { isDecisiveStatus, verdictOf } from "./evidence.js";
import { attributeChange, isGlobalInvalidator, matchesAny } from "./impact.js";
import { firstInformativeLine } from "./excerpt.js";
// W15-L12: the certify-target display default is IMPORTED from the config
// module, not re-typed here — the day the config default moves, this
// narrative moves with it instead of silently disagreeing.
import { DEFAULT_CERTIFY_TARGET } from "../config.js";
/**
 * Attribute every check in the batch. `attributedTo` is the changed-file subset
 * that lands inside the check's impact set; `suspects` additionally ranks those
 * files by how narrowly they map to this check.
 */
export function attributeChecks(input) {
    const table = attributeChange(input.checks, input.changed, input.graph);
    const changed = new Set(input.changed);
    const provenance = input.provenance;
    const isExternal = (file) => provenance?.get(file) === 'external';
    return input.checks.map((spec) => {
        const baseline = input.baselineById.get(spec.id);
        const current = input.currentById.get(spec.id);
        const verdict = verdictOf(baseline, current);
        // Files that (transitively) reach this check's impact set.
        const suspects = new Set();
        for (const [file, owners] of table) {
            if (owners.includes(spec.id))
                suspects.add(file);
        }
        for (const file of input.changed) {
            if (spec.paths.includes('*') || matchesAny(file, spec.paths))
                suspects.add(file);
        }
        // Blame only what the session (or an explicit assertion) owns; edits that
        // arrived outside the agent's tool stream are reported, not charged.
        const attributedTo = [...suspects].filter(f => changed.has(f) && !isExternal(f)).sort();
        const externalSuspects = [...suspects].filter(f => changed.has(f) && isExternal(f)).sort();
        return {
            checkId: spec.id,
            label: spec.label,
            kind: spec.kind,
            verdict,
            ...(baseline !== undefined ? { baseline } : {}),
            ...(current !== undefined ? { current } : {}),
            attributedTo,
            ...(externalSuspects.length > 0 ? { externalSuspects } : {}),
            suspects: rankSuspects([...suspects], spec),
            rationale: rationaleFor(verdict, spec, baseline, current, attributedTo, externalSuspects),
        };
    });
}
function rankSuspects(files, spec) {
    return [...files].sort((a, b) => {
        const score = (f) => {
            // Ranking only — never correctness. Reuse the one true list of global
            // invalidators instead of a second regex: the old local `.*lock.*`
            // pattern scored `deadlock.ts` and `blockchain.md` as lockfiles.
            if (isGlobalInvalidator(f))
                return 0;
            if (spec.paths.some(p => p !== '*' && matchesAny(f, [p])))
                return 1;
            return 2;
        };
        const d = score(a) - score(b);
        return d !== 0 ? d : a.length - b.length;
    });
}
function rationaleFor(verdict, spec, baseline, current, attributedTo = [], externalSuspects = []) {
    const b = baseline?.status ?? 'absent';
    const c = current?.status ?? 'absent';
    switch (verdict) {
        case 'regression':
            if (attributedTo.length === 0 && externalSuspects.length > 0) {
                return `"${spec.label}" passed at baseline (${b}) and now fails (${c}), but every suspect file changed outside the agent's tool stream — external edit, present but not charged to this session.`;
            }
            if (externalSuspects.length > 0) {
                return `"${spec.label}" passed at baseline (${b}) and now fails (${c}) — charged to this session (suspects also include external edits: ${externalSuspects.slice(0, 3).join(', ')}).`;
            }
            return `"${spec.label}" passed at baseline (${b}) and now fails (${c}) — charged to this session.`;
        case 'still-failing':
            return `"${spec.label}" was already failing at baseline (${b}) and still fails (${c}) — pre-existing, not caused here.`;
        case 'still-passing':
            return `"${spec.label}" passed at baseline and still passes.`;
        case 'fixed':
            return `"${spec.label}" failed at baseline (${b}) and now passes (${c}) — this work fixed it.`;
        case 'new-failure':
            return `"${spec.label}" has no baseline and fails (${c}) — cannot distinguish new breakage from pre-existing.`;
        case 'new-check':
            return `"${spec.label}" is newly discovered${c === 'absent' ? ' and not yet run' : ` and passes (${c})`}.`;
        case 'not-run':
            return `"${spec.label}" was not re-run; its evidence is stale relative to this change set.`;
        case 'indeterminate':
            // Two distinct ignorances, one honest verdict each: a baseline that
            // never settled the question, or a current run that could not.
            if (!isDecisiveStatus(baseline?.status)) {
                return `"${spec.label}" had no decisive result at baseline (${b}) — neither credit nor blame can be derived from an unknown.`;
            }
            return `"${spec.label}" produced no decisive result this run (${c}) — the question stays open; no credit, no blame.`;
    }
}
/**
 * Human-readable regression lines ready for `agent.inject()`. Short on purpose:
 * this is corrective context, not a report.
 */
export function regressionNarrative(checks) {
    const out = [];
    for (const check of checks) {
        if (check.verdict !== 'regression' && check.verdict !== 'new-failure')
            continue;
        const externalOnly = check.verdict === 'regression' && check.attributedTo.length === 0
            && (check.externalSuspects?.length ?? 0) > 0;
        const owners = check.suspects.length > 0
            ? ` Suspect files: ${check.suspects.slice(0, 5).join(', ')}.`
            : '';
        const detail = check.current?.outputHead
            ? ` Last output: ${firstInformativeLine(check.current.outputHead)}`
            : '';
        out.push(`${externalOnly ? '↗' : '✖'} ${check.label}: ${check.rationale}${owners}${detail}`);
    }
    return out;
}
/**
 * Plain-language summary of what is and is not proven. The certify-target
 * fallback for the display is the config module's own default (see the
 * import above). Callers that know the run's actual target pass it; the
 * plain `ProofReport` carries only the posterior, not the threshold it was
 * certified against.
 */
export function proofNarrative(report, certifyTarget = DEFAULT_CERTIFY_TARGET) {
    const s = report.summary;
    const parts = [
        `${report.grade.toUpperCase()}`,
        `${s.passing} passing`,
        `${s.failing} failing`,
    ];
    if (s.regressions > 0)
        parts.push(`${s.regressions} regression(s)`);
    if (s.fixed > 0)
        parts.push(`${s.fixed} fixed`);
    if (s.preExisting > 0)
        parts.push(`${s.preExisting} pre-existing failure(s)`);
    if (s.indeterminate > 0)
        parts.push(`${s.indeterminate} indeterminate`);
    if (report.unverified.length > 0)
        parts.push(`${report.unverified.length} stale/unrun`);
    // β graded trust: with a posterior on the report the grade line becomes a
    // trust statement — `PROVEN (p≈0.97)` / `STALE (p≈0.61, target 0.97)`. The
    // counts keep their exact legacy form; only the head grows a tail. Whether
    // the target was met is read off `confidenceBasis` first (the report's own
    // record of certification) with the numeric comparison as fallback, so a
    // deployment with a non-default target still reads correctly.
    const graded = report;
    // υ: execution coverage — what the checks actually EXECUTED, not what their
    // paths matched. The report's optional `coverage` summary is mounted by
    // `applyCoverageGate` (core/report.ts). Both branches below demand basis
    // 'v8': at basis 'none' nothing was measured, and naming files "unexecuted"
    // without a measurement would be exactly the dishonesty this dimension
    // exists to remove.
    const coverage = graded.coverage;
    const coverageTail = coverage !== undefined
        && coverage.basis === 'v8'
        && coverage.uncovered.length === 0
        ? ', change-executed'
        : '';
    if (coverage !== undefined && coverage.basis === 'v8' && coverage.uncovered.length > 0) {
        // Paths coverage said "a check owns this file"; execution coverage says
        // "and then no green check ever ran a line of it". That gap is the claim
        // this whole dimension exists to catch, so the narrative names the files
        // and points at the remedy the toolset already has. W15-L11: the naming
        // is decoupled from the grade — a `stale` or `regressed` run with
        // uncovered changes used to fall between this branch and the
        // change-executed tail, and "the change was never executed" vanished
        // from the story precisely when the report was already bad enough to
        // need it most.
        const named = coverage.uncovered.slice(0, 3).join(', ');
        parts.push(`unexecuted change (${named}) — proof_conjure can synthesize a test that executes them`);
    }
    // ζ jury path first: a docs-only verdict never reads like a measurement. The
    // proven line states the number AND its regime — jury evidence, capped — so
    // nobody mistakes self-attestation for check coverage; the failing line names
    // the actual reason (obligations unmet), not a probability that no longer
    // means anything.
    if (graded.confidenceBasis === 'jury-only') {
        const p = (graded.confidence ?? 0).toFixed(2);
        const head = report.grade === 'proven'
            ? `${report.grade.toUpperCase()} (p≈${p}, jury evidence — self-attestation is capped)`
            : `${report.grade.toUpperCase()} (jury obligations unmet)`;
        return [head, ...parts.slice(1)].join(' — ');
    }
    // κ attested: machine evidence fused with B/C witnesses — same head shape
    // as the machine line, with the regime named so nobody mistakes a witnessed
    // number for a purely measured one.
    if (graded.confidenceBasis === 'attested') {
        const p = (graded.confidence ?? 0).toFixed(2);
        const head = `${report.grade.toUpperCase()} (p≈${p}, machine + B/C attested)`;
        return [head, ...parts.slice(1)].join(' — ');
    }
    // π synthetic: every decisive check was conjured by the claim's author —
    // the number is real but each factor paid the raised synthetic β, and the
    // head says so. Same shape for every grade: the discount is a property of
    // the evidence, not of the verdict.
    if (graded.confidenceBasis === 'synthetic') {
        const p = (graded.confidence ?? 0).toFixed(2);
        const head = `${report.grade.toUpperCase()} (p≈${p}, synthetic evidence — conjured tests, discounted)`;
        return [head, ...parts.slice(1)].join(' — ');
    }
    if (graded.confidence !== undefined) {
        const p = graded.confidence.toFixed(2);
        const met = graded.confidenceBasis === 'certified-subset' || graded.confidence >= certifyTarget;
        // υ: a change the checks verifiably executed earns its head a tail —
        // `PROVEN (p≈0.97, change-executed)` — the one-word difference between
        // "the suites are green" and "the suites are green AND ran this code".
        const head = met
            ? `${report.grade.toUpperCase()} (p≈${p}${coverageTail})`
            : `${report.grade.toUpperCase()} (p≈${p}, target ${certifyTarget.toFixed(2)}${coverageTail})`;
        return [head, ...parts.slice(1)].join(' — ');
    }
    return parts.join(' · ');
}
//# sourceMappingURL=regression.js.map