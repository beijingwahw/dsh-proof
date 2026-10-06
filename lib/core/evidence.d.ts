/**
 * The evidence layer: content-addressed records over an append-only log.
 *
 * Design mirrors DSH's own session-log rule — "everything the model saw must be
 * reconstructable from the log". Here the invariant is stricter: *every claim
 * the model makes must be recomputable from the evidence log*. The log is
 * append-only; a `baseline` or `proof` is just a named view over it.
 *
 * Since v0.2 the log is also tamper-evident against its own writer: every
 * line carries `prev = sha256(previous line)` (a hash chain), checkpoints
 * are signed by a host-held key (see `core/trust.ts`), the highest
 * checkpoint is mirrored to an anchor file outside the workspace, and the
 * baseline file's digest is recorded in the chain when it is saved.
 *
 * @module dsh-proof/core/evidence
 */
import type { CheckKind, CheckSource, CheckSpec, Clock, FsPort, SignerPort, WorkspacePort } from './ports.ts';
import type { NormalizeOptions } from './hash.ts';
import { type ExcerptOptions } from './excerpt.ts';
import type { SyntheticEvidenceMeta } from './synthetic.ts';
export type CheckStatus = 'pass' | 'fail' | 'error' | 'timeout' | 'aborted' | 'skipped';
/** One observed run of one check. Addressed by its own canonical digest. */
export interface Evidence {
    readonly evidenceId: string;
    readonly checkId: string;
    readonly label: string;
    readonly kind: CheckKind;
    readonly command: readonly string[];
    /**
     * Which discovery source minted the addressed check (ο). Participates in
     * the content address, so the record says — without consulting any live
     * spec pool — whether it came from `package.json`, `config`, or was
     * `synthetic` (agent-constructed; see `core/synthetic.ts`). Downstream
     * verdicts key on this instead of re-deriving provenance: an evidence log
     * must stay interpretable from its own bytes.
     */
    readonly source?: CheckSource;
    readonly status: CheckStatus;
    readonly exitCode: number | null;
    readonly durationMs: number;
    /** sha256 of `normalizeOutput(output)` — content addressing without storing the noise. */
    readonly outputDigest: string;
    /** Excerpt of the normalised output under the configured budget (v0.5). */
    readonly outputHead: string;
    /** True when the excerpt dropped content (`[... N chars omitted ...]` markers account for it). */
    readonly outputTruncated?: boolean;
    /** How many normalised characters are not in the excerpt. */
    readonly outputOmittedChars?: number;
    /**
     * ο: present only on synthetic-check records — the verbatim script digest,
     * sandbox tier, screen findings and authorship. Participates in the content
     * address, so the record *self-certifies what ran*: two runs with the same
     * observable outcome but different scripts are two different pieces of
     * evidence, and neither can borrow the other's pass.
     */
    readonly synthetic?: SyntheticEvidenceMeta;
    /**
     * τ: what of the change set *this record's own run* actually executed —
     * the executed/uncovered split of the V8 coverage the check's process left
     * behind (see `core/coverage.ts`). Like `synthetic`, it participates in the
     * content address: a record cannot claim to have exercised a change it
     * never ran, and two records with the same green output but different
     * execution footprints are two different pieces of evidence. Absent on
     * pre-τ records and on runs without instrumentation.
     */
    readonly coverage?: {
        readonly changedExecuted: readonly string[];
        readonly changedUncovered: readonly string[];
    };
    readonly recordedAt: string;
    /** Workspace state when the evidence was produced. */
    readonly workspace: WorkspaceSnapshot;
}
export interface WorkspaceSnapshot {
    readonly head: string | null;
    readonly dirty: readonly string[];
    /** Digest of the dirty-file set, so "the same dirt" compares equal. */
    readonly dirtDigest: string;
    /**
     * sha256 of each dirty file's *content* at snapshot time. Baseline checks
     * ran against the working tree as it was, so these digests — not the
     * commit — are the anchor change-set resolution diffs against (v0.3).
     */
    readonly dirtyDigests?: Readonly<Record<string, string>>;
    /**
     * M-34: the git queries behind this snapshot FAILED — `head: null` and
     * `dirty: []` mean "unobservable", not "clean tree, no commits". The old
     * behaviour content-addressed that blind guess as if it were a fact; the
     * flag rides the snapshot (and therefore the record's address) so every
     * consumer can tell a clean tree from a blinded one. Absent on honest
     * snapshots, so every existing address is untouched.
     */
    readonly gitDegraded?: boolean;
}
/** A named, ordered collection of evidence records. */
export interface Baseline {
    readonly baselineId: string;
    readonly createdAt: string;
    readonly workspace: WorkspaceSnapshot;
    /** checkId -> evidence, in discovery order. */
    readonly checks: readonly Evidence[];
    /** Merkle root over the evidence addresses — the baseline's fingerprint. */
    readonly root: string;
}
/**
 * Verdict about one check, derived purely from a baseline and fresh evidence.
 *
 * The lattice is three-valued. Every verdict is either *credit*
 * (`still-passing`, `fixed`, a decisively-run `new-check`), *blame*
 * (`regression`, `still-failing`, `new-failure`) or *neither*
 * (`indeterminate`, `not-run`, a `new-check` that never ran). `indeterminate`
 * is the honest middle: at least one side of the comparison produced no
 * decisive result (`skipped`, `timeout`, `aborted`, `error`), so the check
 * deserves neither credit nor blame. Blame requires a decisive baseline pass;
 * credit requires a decisive baseline fail — anything less is unknown, and
 * unknown is never silently rounded up to "ok".
 */
export type CheckVerdict = 'still-passing' | 'still-failing' | 'regression' | 'fixed' | 'new-failure' | 'new-check' | 'not-run' | 'indeterminate';
export interface CheckReport {
    readonly checkId: string;
    readonly label: string;
    readonly kind: CheckKind;
    readonly verdict: CheckVerdict;
    readonly baseline?: Evidence;
    readonly current?: Evidence;
    /** Files changed in this session that fall inside this check's impact set. */
    readonly attributedTo: readonly string[];
    /** Suspect files that changed *outside* the agent's tool stream (v0.3). */
    readonly externalSuspects?: readonly string[];
}
export type ProofGrade = 'proven' | 'unproven' | 'regressed' | 'no-baseline' | 'stale';
export interface ProofReport {
    readonly grade: ProofGrade;
    readonly root: string;
    readonly baselineRoot: string | null;
    readonly baselineCreatedAt: string | null;
    readonly generatedAt: string;
    readonly workspace: WorkspaceSnapshot;
    /** Only the checks the change set actually touches. */
    readonly checks: readonly CheckReport[];
    /** Everything discovered, whether or not it was run. */
    readonly discovered: number;
    /** Checks whose evidence is missing after an incremental run. */
    readonly unverified: readonly string[];
    /**
     * H5②: baseline checks whose definitions vanished from discovery (the
     * pool was edited). Optional so pre-v0.16 reports and the jury assemblers
     * stay byte-compatible; `assembleProof` always emits it.
     */
    readonly vanished?: readonly string[];
    readonly summary: {
        readonly passing: number;
        readonly failing: number;
        readonly regressions: number;
        readonly fixed: number;
        readonly preExisting: number;
        readonly newChecks: number;
        /** Checks where at least one side of the comparison was non-decisive — neither credit nor blame. */
        readonly indeterminate: number;
    };
    /** Regressions in plain language, ready to inject into the agent's context. */
    readonly regressions: readonly string[];
}
export interface RunOutcome {
    readonly status: CheckStatus;
    readonly exitCode: number | null;
    readonly durationMs: number;
    readonly output: string;
}
/**
 * Turn one observed run into an addressable evidence record.
 *
 * ο: the trailing `synthetic` parameter is the self-certifying metadata for
 * agent-constructed checks (script digest, sandbox tier, screen findings,
 * authorship). It rides into the content address like every other field —
 * the point is exactly that a record cannot claim a script it did not run.
 * Optional and last, so every pre-ο call site is untouched.
 *
 * τ: the trailing `coverage` parameter (after `synthetic`, same pattern)
 * carries the executed/uncovered split of the change set for this run, when
 * the check ran under V8 coverage instrumentation. It too rides into the
 * address; every pre-τ call site is untouched.
 */
export declare function makeEvidence(spec: CheckSpec, outcome: RunOutcome, workspace: WorkspaceSnapshot, clock: Clock, excerpt?: ExcerptOptions, canonical?: NormalizeOptions, synthetic?: SyntheticEvidenceMeta, coverage?: Evidence['coverage']): Evidence;
export declare function snapshotWorkspace(workspace: WorkspacePort): Promise<WorkspaceSnapshot>;
export declare function snapshotWorkspace(head: string | null, dirty: readonly string[]): WorkspaceSnapshot;
export declare function buildBaseline(records: readonly Evidence[], workspace: WorkspaceSnapshot, clock: Clock): Baseline;
export declare const DEFAULT_LOG_RELPATH = ".proof/evidence.jsonl";
export declare const DEFAULT_BASELINE_RELPATH = ".proof/baseline.json";
/** Trust wiring for an EvidenceStore: signing, anchoring, checkpoint cadence. */
export interface StoreTrust {
    /** Lazily resolved host signer; `undefined` results in an unsigned chain. */
    readonly signer?: () => Promise<SignerPort | undefined>;
    /** Where the out-of-band anchor lives (outside the agent-writable area). */
    readonly anchorPath?: string;
    /** Stable identity of the workspace, committed into checkpoints. */
    readonly workspaceKey?: string;
    /** Append a checkpoint automatically after this many records. */
    readonly checkpointEvery?: number;
}
/** Everything `audit()` can tell you about the log's integrity. */
export interface AuditReport {
    readonly ok: boolean;
    /** Evidence records in the log. */
    readonly total: number;
    /** checkIds whose payload no longer addresses itself. */
    readonly corrupt: readonly string[];
    /**
     * M15: the anchor file EXISTS but could not be parsed as an anchor
     * (malformed JSON, wrong shape, wrong version). Pure visibility signal —
     * it deliberately does NOT fail `ok`, because an unreadable anchor is a
     * missing capability on the auditor's side, not a provable forgery in the
     * log; but a reader MUST be able to see that the out-of-band defence line
     * (rewind/monotonicity) was not checked. An absent anchor (no file) stays
     * silent as before: "never anchored" is a deployment fact, not a defect.
     * Optional so hand-built reports from older surfaces keep satisfying the
     * type; `audit()` always emits it.
     */
    readonly anchorUnreadable?: boolean;
    readonly chain: {
        readonly mode: 'signed' | 'unsigned' | 'legacy';
        readonly breaks: readonly number[];
        readonly checkpoints: number;
        /** Checkpoints whose signature this host's key actively refutes — a forgery charge. */
        readonly badCheckpoints: readonly number[];
        /**
         * Checkpoints that carry a signature this host cannot adjudicate: no
         * signer is configured (key lost / different machine), or the checkpoint
         * names a different keyId. A missing capability is not an accusation.
         */
        readonly unverifiableCheckpoints: readonly number[];
        /**
         * Checkpoints carrying no signature while a signer is active on this
         * audit host — a charge. The one shape moved OUT of the charge is the
         * keyless adoption era (see `unsignedEraCheckpoints`): a completely
         * naked line below the first verified checkpoint of the now-held key.
         */
        readonly unsignedCheckpoints: readonly number[];
        readonly headMismatches: readonly number[];
        /**
         * M-33/H-32 (v0.22): checkpoints the *writer itself* recorded as
         * un-signable at append time — a transient signing failure ("key
         * directory locked by a scanner"). Visible, deliberately NOT a failing
         * `ok` charge once a later checkpoint of the same key carries a verified
         * signature (the recovery witness): an honest blip must not red the audit
         * forever, or operators learn to ignore the red. Without the witness the
         * line is indistinguishable from a stripped signature and stays in
         * `unsignedCheckpoints`.
         */
        readonly sigErrorCheckpoints?: readonly number[];
        /**
         * H-27/H-32 (v0.22): checkpoints written unsigned because the store
         * REFUSED to sign — its pre-sign audit found the physical chain rewritten
         * or inflated and declined to lend the forged bytes the host key. A
         * refusal is the store accusing its own log; the accusation is always
         * visible here.
         *
         * Y-H-02 (v0.24): the charge is now GENERATIONALLY SLICED — a refusal
         * fails `ok` only while its generation is unrecovered, i.e. until a
         * later checkpoint of the same key verifies or this process re-anchors
         * over it (see `refusedToSignPardoned`). v0.23 billed every refusal
         * forever, so one honest race, one crash between `mark` and `checkpoint`,
         * or one attacker line (V1-M7) permanently capped every future grade at
         * stale through the X-H-09 consumers — the documented "re-anchor and
         * resume" recovery was a no-op that itself minted fresh refusal rows.
         */
        readonly refusedToSign?: readonly number[];
        /**
         * Y-H-02 (v0.24): the subset of {@link refusedToSign} whose generation
         * has recovered — a later same-key checkpoint with a verified signature
         * exists, or this process wrote a `baseline/*` re-anchor marker after the
         * refusal. The scar stays visible in `refusedToSign`; it no longer fails
         * `ok`. Always emitted (empty when clean) by `audit()`.
         */
        readonly refusedToSignPardoned?: readonly number[];
        /**
         * Y-H-02 (v0.24): the keyless ADOPTION era, made visible without being a
         * charge — completely naked checkpoints (no sig, no sigError, no keyId;
         * only writable while no signer was configured) sitting below the FIRST
         * verified checkpoint of the key this audit host now holds. Before the
         * slice these rows lived in `unsignedCheckpoints` forever, so adopting a
         * signer was a one-way door to a permanent red the documented re-anchor
         * could never heal. Naked lines ABOVE the boundary are not this era (an
         * attacker's appended fake; stripping an honest checkpoint's signature
         * leaves its `keyId` behind) and stay charged. Always emitted (empty
         * when clean) by `audit()`.
         */
        readonly unsignedEraCheckpoints?: readonly number[];
        /**
         * Checkpoints whose self-reported `count` the walk itself refutes — not a
         * non-negative safe integer, or not equal to the records actually walked
         * to that position (see `walkChain`). Signature-independent by design: a
         * checkpoint can be perfectly cryptographic for a key this host cannot
         * adjudicate and still be lying about its count. Optional in the type so
         * hand-built reports from older surfaces keep satisfying it; `audit()`
         * always emits it (empty when clean).
         */
        readonly malformedCheckpoints?: readonly number[];
        /**
         * Line indexes that are not valid v1/v2 envelopes at all (unparseable
         * JSON, wrong envelope shape) — the raw `walkChain` channel the `ok`
         * formula has always consumed but the report never surfaced, so callers
         * could see breaks and bad signatures but not WHICH lines were garbage.
         * Optional for the same hand-built-report compatibility reason;
         * `audit()` always emits it (empty when clean).
         */
        readonly corruptLines?: readonly number[];
        /** Records after the last checkpoint — chain-covered, not checkpoint-covered. */
        readonly tailRecords: number;
        /** The log ends before the best checkpoint the anchor remembers. */
        readonly rewind: boolean;
        readonly anchorMismatch: boolean;
        /** The anchor file failed its own signature check — its data was tampered with. */
        readonly anchorForged: boolean;
        /**
         * H-09 (v0.22): the anchor file parses but is in a state no honest writer
         * produces — empty `keyId`, count outside the safe non-negative integers,
         * empty/absent `sig` (the four-line disarm family). Unlike
         * `anchorUnreadable` (an auditor-side capability gap), an invalid anchor
         * is tampering until proven otherwise and FAILS `ok`: the old behaviour
         * silently disabled the rewind/mismatch line of defence instead.
         */
        readonly anchorInvalid?: boolean;
        /** The baseline file no longer matches the digest recorded in the chain. */
        readonly baselineTampered: boolean;
        /**
         * H-32/M-A1-5 (v0.22): line indexes of *protected* markers (attest/*,
         * baseline/*) whose self-declared chain position (`headRef`) contradicts
         * their physical predecessor — the shape a replayed, moved, or
         * out-of-band-appended marker has. Visible only: suspect is "cannot vouch
         * for this line", not a proven forgery, so it does not by itself fail
         * `ok`; consumers of protected markers (κ fusion, baseline digests) must
         * exclude them from trust decisions instead of reading last-wins.
         */
        readonly suspectMarkers?: readonly number[];
    };
}
/**
 * v0.18: the checkpoint a transparency-log publish mirrors — the payload the
 * signature covers, the key that signed it, the detached signature, and the
 * line index it lives at. Returned by `EvidenceStore.latestSignedCheckpoint`.
 */
export interface SignedCheckpointView {
    /** The exact bytes-level material the signature commits to ({count, head, workspaceKey, at}). */
    readonly payload: {
        readonly count: number;
        readonly head: string;
        readonly workspaceKey: string | null;
        readonly at: string;
    };
    /** The signing key's identity (which key the signature must verify under). */
    readonly keyId: string;
    /** Detached signature over `checkpointSignedData(payload)`. */
    readonly sig: string;
    /** Index of the checkpoint line within the evidence log. */
    readonly index: number;
}
/**
 * Marker labels whose payloads feed *trust decisions* (κ attestation fusion,
 * baseline integrity, identity adoption, SLA accounting, jury verdicts,
 * synthetic-check minting), so an injected or replayed line under them is
 * worth forging: every `attest/*` verdict, the `baseline/*` summary family,
 * the `delegation/*` DAG, and `proof/verified`. Writes under these labels
 * carry a `headRef` witness; readers can filter by it (see
 * {@link _readMarkers}).
 *
 * V1-M9 (v0.24): the list is the single source of truth matched against the
 * CONSUMERS that claim to rely on suspect filtering. v0.23 shipped four
 * consumers reading labels the list never covered, making their
 * `excludeSuspect` reads a dead channel — one out-of-band append per label
 * forged host-adoption edges (`agent-team/delegated`), SLA quotes
 * (`economics/quote`), jury verdicts (`claim/jury`) and synthetic-check
 * requests (`synthetic/requested`). Labels join this list exactly when a
 * consumer's trust decision reads them; informational labels stay out so
 * the witness bytes stay minimal.
 *
 * P5 (pattern-five termination): `synthetic/run` joins — the v0.24 leftover
 * of exactly that survey. The run marker is what lets a conjured offer join
 * verification (`syntheticSpecs` mints a spec only for a request whose
 * claimId+entry appears under `synthetic/run`), which is a trust decision:
 * an out-of-band twin under it promoted a never-executed script into the
 * live check pool unflagged, while its sibling `synthetic/requested` was
 * already protected. headRef compatibility follows the late-adopted-label
 * rule every V1-M9 label already lives under: writes go through
 * `markInternal`, so every fresh `synthetic/run` carries the witness
 * automatically (write-side uniformity — no call site changes); pre-adoption
 * logs carry none, read suspect, and are governed by the generational
 * fallback — an all-legacy label degrades and keeps reading, a mixed
 * generation excludes the headRef-less rows from the trusted pool exactly
 * like `synthetic/requested`'s rule. Accepted and documented, not silently
 * smoothed over: re-running the conjured check re-mints a witnessed marker.
 */
export declare function isProtectedMarkerLabel(label: unknown): boolean;
/**
 * X-H-08 (v0.23): the `baseline/*` labels that *change what the log believes
 * about the baseline document* — `baseline/saved` (a new file's digest became
 * the remembered truth) and `baseline/established` (the engine took a fresh
 * anchor, with its own tamper/degradation metadata). An out-of-band append
 * under either label re-defines the baseline the next session verifies
 * against, which is why the pre-sign audit refuses to lend the host key over
 * foreign ones (see `preSignAudit`; v0.25's U1-H1 widened that refusal roster
 * to the full `isProtectedMarkerLabel` list — this predicate now scopes only
 * the Y-H-02 re-anchor recovery witness and the read-time baseline
 * authorship demand). Informational `baseline/*` labels beyond these two
 * (none today) would need the same treatment before being added.
 */
export declare function isBaselineMarkerLabel(label: unknown): boolean;
/** One marker line, read back with its tamper-evidence metadata. */
export interface MarkerRecord {
    /** Index of the marker line within the log. */
    readonly index: number;
    readonly label: string;
    readonly payload: Record<string, unknown>;
    /**
     * True when a protected marker's `headRef` (the chain head the writer saw
     * at append time) does not match the digest of the line physically before
     * it — the shape of a marker that was replayed at another position, moved,
     * or appended out of band. NOT a proven forgery (a forger that re-chains
     * the whole log can forge a consistent `headRef` too — only signatures
     * close that); it means "this line cannot vouch for where it sits", and
     * trust decisions must skip it rather than read it last-wins.
     */
    readonly suspect: boolean;
}
/**
 * The one PUBLIC read that carries the H-32 position verdict over a caller's
 * own line snapshot (v0.25.1, U4-H1) — the formal replacement for the retired
 * `_readMarkers` export, not an escape hatch: importing it is a declared,
 * contract-pinned decision, not an accident of naming.
 *
 * WHO MAY USE IT: processes that hold NO engine and NO store. The adapter
 * faces (claude-code hooks, opencode plugin) re-derive `lastBaselineDigest`'s
 * trusted-first selection over their own `readFile` snapshot because their
 * runtime contract carries no fs port and no store wiring — for them this is
 * the only door. Every engine-holding consumer must instead read through
 * `EvidenceStore.markersWith` or `createVerifiedView().markers`: the same
 * single-pass core, plus the generational fallback and the epoch bound this
 * thin read deliberately does NOT re-implement (a hand-rolled fallback beside
 * the view's is exactly how two faces come to disagree about what exists).
 * test/32 claim 1b pins the importer set to the two adapter files.
 *
 * Pure over the given lines; blank lines are normalised away (V1-M8), so a
 * raw `split('\n')` and a `readLines` snapshot derive the same indexes and
 * the same verdicts. `options.label` filters to one label; suspect records
 * stay in the result (flagged) so a caller can apply its own trusted-first
 * degradation, `options.excludeSuspect: true` drops them instead.
 */
export declare function readChainMarkers(lines: readonly string[], options?: {
    readonly label?: string;
    readonly excludeSuspect?: boolean;
}): MarkerRecord[];
/** Content-addressed, append-only, hash-chained evidence store backed by a JSONL file. */
export declare class EvidenceStore {
    private readonly fs;
    private readonly logPath;
    private readonly baselinePath;
    private readonly clock;
    private readonly trust;
    private readonly cache;
    private tailReady;
    private tail;
    private recordsSoFar;
    private sinceCheckpoint;
    private signerPromise;
    /**
     * W1-M3 (v0.23): the failure of the most recent signer-provider attempt,
     * when that attempt REJECTED. The memoized promise settles `undefined` for
     * both "no signer yet" and "provider failed" (the M15 retry semantics
     * require the failure not be cached); this side channel carries WHICH of
     * the two it was, so `checkpointInternal` can record a transient provider
     * failure on the sigError channel instead of writing a naked unsigned
     * checkpoint. Consumed on first read — a later `undefined` resolution is a
     * fresh answer, not this failure.
     */
    private signerResolveError;
    /**
     * X-H-08 (v0.23), widened v0.25 (U1-H1): digests of every PROTECTED-marker
     * line THIS process wrote (via `mark`/`saveBaseline` — every protected label
     * flows through `markInternal`, so the set is closed over this process's own
     * writes by construction). v0.23 collected only the baseline family; the
     * laundering the pre-sign audit exists to stop was therefore open under
     * every OTHER protected label: a between-sessions append of a headRef-
     * correct `attest/*` / `delegation/*` / `proof/verified` / `claim/jury` /
     * `economics/quote` / `synthetic/*` line was absorbed by `ensureTail` and
     * then notarised by the host's own next checkpoint — the floor launders the
     * tail at the moment it is minted. Content addressing makes the set
     * replay-proof: an attacker re-appending one of these lines verbatim keeps
     * its digest but breaks the chain (its `prev` still points at its original
     * predecessor); altering anything to re-chain it changes the digest out of
     * the set. See `preSignAudit`.
     */
    private readonly selfProtectedMarkers;
    /**
     * Single-flight tail for every log-mutating operation. Two concurrent
     * `append`/`mark`/`checkpoint` calls both read the same `this.tail`, both
     * build envelopes chained to it, and the second line's `prev` then points at
     * a line that no longer exists — the chain is broken by *correct* code
     * racing itself. Serialising the write section (tail read → append → tail
     * update) makes the interleaving impossible; reads stay concurrent.
     */
    private tailQueue;
    constructor(fs: FsPort, logPath: string, baselinePath: string, clock: Clock, trust?: StoreTrust);
    static atWorkspace(fs: FsPort, logPath: string, clock: Clock): EvidenceStore;
    /**
     * V1-M8 (v0.24): the ONE internal log-read — node-ports `readLines`
     * semantics (blank lines removed), enforced rather than assumed. Every
     * store-internal consumer and the verified view derive their line arrays
     * from here, so no face of the store can grow a private array convention.
     */
    private logLines;
    /**
     * Load the chain state from disk exactly once — the one full scan the first
     * mutation pays for. The same pass also re-indexes every existing evidence
     * address into the dedupe cache (so append idempotency survives restarts,
     * not just the process lifetime) and repairs a torn *tail* line if the
     * previous process died mid-`appendLine`.
     */
    private ensureTail;
    private resolveSigner;
    /**
     * W1-M3 (v0.23): the adjudicated form of `resolveSigner`. A provider that
     * REJECTS is a transient signing-capability failure — the same social
     * reality as `sign()` throwing (M-33: an AV scan holding the key directory)
     * — and the checkpoint boundary must record it on the sigError channel
     * rather than writing a naked unsigned line that `unsignedCheckpoints`
     * charges forever (no keyId, hence no possible recovery witness: one
     * transient blip and the audit could never go green again, which is how
     * operators learn to ignore reds). Memoization semantics are M15's, bitten
     * open: only a SUCCESSFUL resolution is cached; a rejection or an empty
     * resolution is retried on the next boundary.
     */
    private resolveSignerEx;
    /**
     * Run `op` as the one and only log-mutating operation in flight. The queue
     * swallows the previous operation's rejection (it was already delivered to
     * its own caller) so one failed write cannot deadlock every later one;
     * `op`'s own outcome — result or rejection — reaches its caller untouched.
     */
    private enqueue;
    /**
     * Append one evidence record. Re-appending an existing address is a no-op —
     * in this process *and* across restarts: the first log scan re-indexes
     * every address already on disk, so replaying a log against a fresh store
     * instance cannot duplicate records.
     */
    append(evidence: Evidence): Promise<void>;
    private appendInternal;
    /** Append a free-form marker (session boundaries, decisions). */
    mark(label: string, data?: Record<string, unknown>): Promise<void>;
    private markInternal;
    /**
     * Append a signed checkpoint and refresh the out-of-band anchor.
     *
     * A checkpoint commits to "the chain head, after N records". Without the
     * host's key the writer of the log cannot produce a new one, and without the
     * anchor the log cannot be quietly rewound past the last checkpoint.
     */
    checkpoint(): Promise<void>;
    private checkpointInternal;
    /**
     * H-27: the pre-sign audit — walk the physical bytes and refuse to sign if
     * anything about them is not what this store wrote. Returns the joined
     * problems (the refusal reason), or `undefined` when the chain is fit to
     * sign. Deliberately narrow: only *tamper-shape* signals refuse. A past
     * unsigned checkpoint (transient signing failure) or an unverifiable
     * foreign one is NOT a reason to refuse — those have their own channels,
     * and refusing on them would make recovery from an honest blip impossible.
     *
     * X-H-08 (v0.23) adds the one *authorship* signal: a PROTECTED-marker line
     * sitting on the checkpoint-uncovered tail that THIS process never wrote
     * (see `selfProtectedMarkers`; v0.25 widened the roster from the baseline
     * family to every label trust decisions read). See the rule's full comment
     * inline below.
     */
    private preSignAudit;
    /**
     * H-27: record a refused boundary — the checkpoint lands unsigned with the
     * `SIG_REFUSED_PREFIX` banner (the store accusing its own log), plus a
     * marker naming the reasons, so both the audit and marker readers can see
     * WHY nothing was signed. The store's tail/counter state re-syncs to the
     * physical bytes (they moved behind the queue's back; pretending otherwise
     * would just chain the next honest append onto a lie).
     */
    private recordRefusedCheckpoint;
    /** Must only be called from inside a queued operation (would self-deadlock). */
    private maybeCheckpoint;
    private writeEnvelope;
    /**
     * Every evidence record ever appended, in log order.
     *
     * V1-L11 (v0.24): a row is admitted only when it still addresses itself
     * (`addressOf(payload minus id) === id`). Evidence rows have no suspect
     * regime of their own (the marker/twin asymmetry the survey named), so an
     * out-of-band twin — same id, doctored payload, chained correctly — used
     * to win `latest()` last-wins and poison priors/exports until some later
     * audit ran. The read-time check makes the honest row the only answer for
     * its id on every face. `audit()` still collects unaddressing rows into
     * its `corrupt` channel (the charge needs to SEE the bad row); this is the
     * read-trust half of the pair.
     */
    all(): Promise<Evidence[]>;
    /** Latest evidence for each check, in first-seen check order. */
    latest(): Promise<Map<string, Evidence>>;
    /**
     * Verify the log's integrity end to end: per-record self-addressing, hash
     * chain linkage, checkpoint signatures, anchor monotonicity, and the
     * baseline file digest recorded at save time.
     */
    audit(): Promise<AuditReport>;
    /**
     * The last *signature-bearing* checkpoint on the chain, selected with the
     * audit's own "best" semantics — the checkpoint a transparency-log publish
     * (v0.18) mirrors into a public, independently verifiable artifact.
     *
     * Selection, mirroring `audit`'s anchor answering rule exactly:
     *
     * - Candidates are well-formed checkpoints (a count the walk itself refutes
     *   is excluded — publishing a lying self-report is not "latest", it is
     *   laundering) that carry a non-empty `sig` AND a non-null `keyId` AND —
     *   Y-H-01 (v0.24) — do not lie about their position (`headLiared`). A
     *   legitimately-signed checkpoint transplanted or replayed at another
     *   position swears a head the walk does not corroborate; v0.23 selected
     *   it (the signature is honest over a payload lying about WHERE) and the
     *   engine/CLI publish paths notarised the transplant into the transparency
     *   log. The publish predicate `signature === 'verified' && !headLiared`
     *   is now enforced where the candidate is chosen.
     * - When the out-of-band anchor exists and names a key, the LAST checkpoint
     *   by that very key wins — never a positionally-later checkpoint under some
     *   foreign keyId an attacker appended. No checkpoint of the anchored key at
     *   all means `undefined`: the anchor is the out-of-band high-water mark of
     *   OUR key, and nothing on this chain is entitled to stand in for it.
     *   v0.22 (H-09): an anchor file that exists but is unparseable OR in the
     *   domain-invalid disarm state also means `undefined` — a store whose
     *   out-of-band mark cannot be consulted has nothing publishable, and the
     *   publish path must fail loudly rather than silently fall back to
     *   any-key selection on exactly the hosts an attacker has been at.
     * - Without an anchor (never anchored / audited anchor-less), the last
     *   signed well-formed non-liar checkpoint of any key is the honest answer.
     * - No signed checkpoint at all → `undefined` (an unsigned chain has nothing
     *   publishable; the caller reports that as a precondition, not a crash).
     *
     * Y-H-03/V1-L10 (v0.24): the selection is the shared single-pass core —
     * ONE physical read feeds the walk, the anchor adjudication and the
     * choice; `createVerifiedView().bestCheckpoint` and
     * `lastWellFormedCheckpoint` derive from the same function, so no face can
     * select by a different rule (or re-read the log between selection and
     * walk, the v0.23 double-snapshot that could silently default
     * `headLiared` to false).
     */
    latestSignedCheckpoint(): Promise<SignedCheckpointView | undefined>;
    /**
     * v0.22 (H-32/M-A1-5): every marker under one label, in log order, with
     * tamper-evidence metadata — the RAW read (suspect lines included, flagged;
     * `excludeSuspect: true` drops them). This is the marker read-back the
     * store owns; the POOLING decision (trusted vs the generational fallback)
     * belongs to {@link createVerifiedView}.markers, which derives from the
     * same single-pass core (Y-H-03, v0.24) — suspect adjudication cannot fork
     * between the two faces.
     */
    markersWith(label: string, options?: {
        readonly excludeSuspect?: boolean;
    }): Promise<MarkerRecord[]>;
    /**
     * @internal One physical snapshot of the log lines, normalised to the
     * readLines array contract (blank lines removed — V1-M8), for the verified
     * read layer ({@link createVerifiedView}) — so its `markers`/
     * `bestCheckpoint` judgements derive from bytes the store itself read, not
     * a second fs path the caller wires up. Not a general API: readers that
     * need raw lines should say what they trust via the view.
     */
    rawLines(): Promise<readonly string[]>;
    /**
     * @internal The store's own signer provider (trust wiring), so
     * {@link createVerifiedView} can adjudicate signatures by default when the
     * caller does not inject one. `undefined` when the store was built without
     * signing configured — the view then reports `unverifiable`, never guesses.
     */
    hostSigner(): (() => Promise<SignerPort | undefined>) | undefined;
    /**
     * @internal Y-H-03/V1-L10 (v0.24): the ONE checkpoint-selection core every
     * "best checkpoint" consumer derives from — ONE normalised physical read
     * feeds the walk, the anchor adjudication AND the selection, so the store's
     * public reads and {@link createVerifiedView}.bestCheckpoint cannot select
     * by different rules or against different bytes. `requireSigned` picks the
     * publish-shaped pool (sig + keyId, `latestSignedCheckpoint` /
     * `bestCheckpointCore`) or the training-anchor pool (any well-formed
     * checkpoint, `lastWellFormedCheckpoint`); both pools exclude malformed
     * counts and — Y-H-01 — head liars.
     *
     * P5: the read/walk/anchor trinity is shared verbatim with
     * {@link publishableCandidatesCore} (see `selectionSnapshot`) — the single
     * answer and the candidate sequence draw from one snapshot per call, so
     * the two faces cannot disagree about the bytes or the anchor state.
     */
    private selectFromWalk;
    /**
     * @internal The shared one-read selection snapshot: physical lines (the
     * readLines convention), the chain walk, and the adjudicated anchor — or
     * the loud `anchorUnusable` state (unparseable OR domain-invalid, the
     * H-09/W1-M7 shapes) under which nothing is publishable.
     */
    private selectionSnapshot;
    /**
     * @internal The view-facing form of the selection core: one read, the
     * selected publish candidate, and the conservative head-liar verdict. The
     * verdict comes from the SAME walk that produced the selection (V1-L10:
     * v0.23's second read could misalign against a concurrent truncation and
     * silently default `headLiared` to false — the wrong direction); when the
     * walk cannot corroborate a selection at all the answer defaults TRUE
     * (treated as lying), never the other way.
     */
    bestCheckpointCore(): Promise<{
        readonly best?: SignedCheckpointView;
        readonly headLiared: boolean;
    }>;
    /**
     * @internal P5: the view-facing candidate core behind
     * {@link createVerifiedView}.publishableCandidates — ONE physical snapshot
     * (the same `selectionSnapshot` the single selection draws from), every
     * structurally publishable checkpoint under the anchor-key rule, in
     * DESCENDING (newest-first) order. Structural means: well-formed count,
     * position corroborated (`headLiared` false — Y-H-01's exclusion, so no
     * consumer of the sequence can notarise a transplant by forgetting the
     * predicate), signature-bearing (`sig` + `keyId` present, so a key-holder
     * downstream CAN verify). The signature itself is deliberately NOT
     * adjudicated here — the sequence exists precisely so a consumer whose
     * adjudication of `candidates[0]` fails (refuted, or a key this host does
     * not hold) can walk down to the next candidate with its own verifier
     * (transparency's `selectPublishable` first-verifiable-wins). The
     * loud-undefined anchor states answer `[]`, the exact `latestSignedCheckpoint`
     * `undefined` rule — never a silent any-key pool.
     */
    publishableCandidatesCore(): Promise<readonly SignedCheckpointView[]>;
    /**
     * v0.22 (L-A1-10): the last well-formed checkpoint, selected with the
     * audit's own anchor-answering rule — when the out-of-band anchor exists
     * and names a key, ONLY that key's well-formed checkpoints are candidates
     * (and none of them existing returns `undefined`, the attack state where a
     * rewound chain has nothing anchored to say). Anchor-less chains keep the
     * any-key semantics. Consumers that used to fall back to "the last
     * well-formed checkpoint of any key" (training export anchors) should use
     * this so a rewritten chain cannot smuggle a foreign checkpoint into an
     * anchor-shaped decision.
     *
     * W1-M7 (v0.23): an anchor file that exists but cannot be consulted —
     * unparseable OR domain-invalid — is a loud `undefined`, exactly the
     * `latestSignedCheckpoint` rule, instead of a silent fall-back to the
     * any-key pool. No anchor file at all keeps the any-key semantics: "never
     * anchored" is a deployment fact.
     *
     * Y-H-01 (v0.24): head liars are excluded here too — a transplanted
     * checkpoint must not anchor a training export any more than a publish.
     */
    lastWellFormedCheckpoint(): Promise<{
        count: number;
        head: string;
        keyId: string | null;
        index: number;
    } | undefined>;
    saveBaseline(baseline: Baseline): Promise<void>;
    /**
     * H-23 (v0.22): loading a baseline is now an integrity decision, not a
     * shape check. The document must (1) canonically re-derive its own id —
     * every record still addresses itself, the merkle root over the recorded
     * addresses still matches, the id still covers the same material
     * `buildBaseline` hashed — and (2) still be the bytes the last non-suspect
     * `baseline/saved` marker remembers. A document that fails either returns
     * `undefined`: stripped non-addressing fields (`scriptDigests`,
     * `apiSurface`), doctored payloads under kept ids, and rebuilt-consistent
     * forgeries all read as "no baseline" to the consumer instead of as a
     * fresh truth to verify against. (`audit()` surfaces the same findings as
     * `baselineTampered`; this method is the load-path half the engine
     * consumes.)
     *
     * Y-H-09 (v0.24): the authorship check moved UP to this read. When this
     * host holds the signing key, the `baseline/saved` marker about to answer
     * for the chain must be self-authored by this process or vouched by a
     * verified same-key checkpoint at-or-after it — a pseudo-absorption (the
     * X-H-08 shape: out-of-band twin marker + doctored file, both perfectly
     * shaped) previously loaded as a fresh truth and only met its refusal at
     * the NEXT signing boundary, minting verdicts against the poisoned bytes
     * first (and never on a keyless deployment). It now loads as `undefined`
     * at the moment of reading. Keyless stores keep the v0.23 rule — without
     * a key nothing can vouch, and a capability gap is not an accusation.
     */
    loadBaseline(): Promise<Baseline | undefined>;
    /**
     * @internal Y-H-09 (v0.24): the line index of the LAST checkpoint of this
     * host's key whose signature actually verified (-1 when none) — the
     * vouching boundary baseline-marker authorship is judged against. Shared
     * by the read paths; `audit` derives the same number from its own
     * adjudication pass.
     */
    private lastVerifiedOwnIndex;
}
/** One marker as the verified read layer admits it. */
export interface VerifiedMarkerView {
    /** Index of the marker line within the log. */
    readonly index: number;
    readonly label: string;
    readonly payload: Record<string, unknown>;
    /**
     * The H-32 position test: the line's `headRef` does not match its physical
     * predecessor. In a non-degraded generation suspect markers are simply not
     * admitted (they stay visible via `audit().chain.suspectMarkers`); this
     * flag is therefore only meaningful on degraded-generation records.
     */
    readonly suspect: boolean;
    /**
     * X-H-06 (v0.23): present exactly when this record was admitted by the
     * generational fallback — EVERY marker under the label is suspect, the
     * shape of a log written before the headRef witness existed. The fallback
     * reads them anyway (last-wins, lastBaselineDigest's rule): an upgraded
     * deployment keeps exactly the history it had, instead of every protected
     * marker evaporating into `delegation/*` DAG loss and `task-1` aliasing.
     * Consumers that must refuse degraded trust can test for it.
     */
    readonly degraded?: true;
}
/** {@link VerifiedChainView.markers} result. */
export interface VerifiedMarkers {
    /**
     * The trusted pool in log order, filtered to the `[sinceLine, maxLine]`
     * window when either bound is given (`sinceLine`: index >= sinceLine, the
     * baseline-generation epoch floor; `maxLine`: index <= maxLine, its
     * symmetric ceiling — P5: a consumer anchoring on "the state as of line N"
     * (a checkpoint boundary, an incident marker) reads exactly the pool that
     * existed at N, without re-slicing the log itself).
     */
    readonly records: readonly VerifiedMarkerView[];
    /** True when the pool is a degraded (all-suspect legacy) generation. */
    readonly degraded: boolean;
    /** Last-wins trusted read — the last element of `records`, for lastBaselineDigest-shaped consumers. */
    readonly last: VerifiedMarkerView | undefined;
}
/** How the best checkpoint's signature fared under adjudication. */
export type BestCheckpointSignature = 
/** Selected and verified under the very key it names. */
'verified'
/** The key this checkpoint names actively refutes the signature — a forgery charge; publish paths must treat as none. */
 | 'refuted'
/** No signer available (or it names a foreign key): a missing capability — the checkpoint data is still returned so downstream holders of the key can verify (X-H-10). */
 | 'unverifiable'
/** No publishable candidate at all (also the loud-undefined anchor states of `latestSignedCheckpoint`). */
 | 'none';
/** {@link VerifiedChainView.bestCheckpoint} result. */
export interface BestCheckpoint {
    readonly signature: BestCheckpointSignature;
    /** The selected checkpoint (absent only for `none`). */
    readonly checkpoint?: SignedCheckpointView;
    /**
     * X-H-03 (v0.23): the selected checkpoint swears a head the walk does not
     * corroborate at its position (`payload.head !== expectedHead`) — the
     * replay/transplant shape. The signature can be perfectly honest over a
     * payload that is lying about WHERE; publish and delegation paths must
     * treat `signature === 'verified' && headLiared` as refuse, exactly as
     * `preSignAudit`'s own head-liars rule does before signing.
     */
    readonly headLiared?: boolean;
}
/** Options for {@link createVerifiedView}. */
export interface VerifiedViewOptions {
    /**
     * Resolves the signer signatures are adjudicated under. Defaults to the
     * store's own trust wiring (`hostSigner()`); inject one when the caller
     * holds a different (e.g. anchor) key than the store writes with.
     */
    readonly signerProvider?: () => Promise<SignerPort | undefined>;
}
/**
 * v0.23: the unified verified read layer — the ONLY surface trust decisions
 * should read markers and checkpoints through. Kills the "wired to a dead
 * channel" family at the root: instead of every consumer hand-rolling
 * its own parse + suspect + fallback (and each forgetting one of the three —
 * the survey's X-H-01/X-H-06/X-M-18 findings), the three judgements live
 * here, once:
 *
 * - `markers` — one physical read, one pass (the engine's per-marker
 *   `isSuspectMarker` rescans were O(n²)~O(n³)); suspect position
 *   adjudication; the generational fallback so legacy logs degrade instead
 *   of evaporating; an optional `sinceLine` epoch window (baseline-generation
 *   aware consumers pass the anchoring line's index) and its symmetric
 *   `maxLine` ceiling (P5: "the pool as of line N" reads — both bounds apply
 *   to the TRUSTED pool, so a suspect twin outside the window can never
 *   re-enter by window arithmetic).
 * - `bestCheckpoint` — `latestSignedCheckpoint`'s selection with the
 *   signature actually ADJUDICATED (`verified`/`refuted`/`unverifiable`)
 *   and the X-H-03 head-liar mirror. Y-H-01 (v0.24): the publish predicate
 *   `signature === 'verified' && headLiared !== true` is enforced by the
 *   SELECTION itself — a head liar is never a candidate, so no consumer can
 *   forget the second half of the predicate.
 * - `publishableCandidates` — P5: the candidate SEQUENCE behind
 *   `bestCheckpoint`. The single-selection shape is newest-first with a
 *   de-facto one-vote veto: when the newest structurally-publishable
 *   checkpoint fails ADJUDICATION (refuted signature, or a key this host
 *   does not hold), `bestCheckpoint` answers `refuted`/`unverifiable` and
 *   every consumer of the single answer refuses — even when an older,
 *   perfectly verifiable checkpoint sits right below it on the chain. The
 *   sequence face exposes that fallback: every well-formed, position-
 *   corroborated, signature-bearing candidate (the same pool
 *   `selectBestCheckpoint` draws from, under the same anchor-key rule), in
 *   DESCENDING order, signatures NOT adjudicated here — the consumer walks
 *   it newest-first with its own verifier (transparency's
 *   `selectPublishable` first-verifiable-wins semantics, living in the
 *   evidence layer). `bestCheckpoint` is exactly `candidates[0]` adjudicated
 *   — the two faces cannot disagree about which checkpoint is newest.
 *   API-contract warning (F6, v0.25): `candidates[0]` is the NEWEST
 *   structurally-publishable checkpoint, NOT a verdict — the pool checks
 *   structure only (well-formed count, non-liar position, sig + keyId
 *   present), never that the signature verifies. A consumer that publishes
 *   `candidates[0]` without adjudicating it publishes a possibly-refutable
 *   line; every in-repo consumer verifies before use.
 * - `audit` — passthrough, so verdict paths stop cherry-picking single
 *   channels (X-H-09's `audit.ok` consumption lands on this surface).
 *
 * v0.24 (Y-H-03): the store's own public reads (`markersWith`,
 * `latestSignedCheckpoint`, `lastWellFormedCheckpoint`, `audit`'s marker
 * channels) derive from the SAME module-private cores this view uses — one
 * rule, two entry points, zero forking surface.
 */
export interface VerifiedChainView {
    markers(label: string, options?: {
        readonly sinceLine?: number;
        readonly maxLine?: number;
    }): Promise<VerifiedMarkers>;
    bestCheckpoint(): Promise<BestCheckpoint>;
    publishableCandidates(): Promise<readonly SignedCheckpointView[]>;
    audit(): Promise<AuditReport>;
}
/**
 * Build the {@link VerifiedChainView} over a store. Pure read layer: it never
 * mutates the log, never resolves a signer for writing, and holds no state
 * between calls — every call takes its own physical snapshot (the M-32
 * one-read-many-derivations discipline, one judgement per snapshot).
 */
export declare function createVerifiedView(store: EvidenceStore, options?: VerifiedViewOptions): VerifiedChainView;
/**
 * Whether a status is a decisive answer (`pass`/`fail`). `skipped`, `timeout`,
 * `aborted` and `error` all mean the check ran without producing — or never
 * got the chance to produce — a verdict, and the knowledge lattice treats
 * them identically: unknown.
 */
export declare function isDecisiveStatus(status: CheckStatus | undefined): boolean;
/**
 * Baseline-differential verdict: the entire point of the plugin.
 *
 * `regression` is reserved for "it passed before *this work* and fails now" —
 * a failing check that was already failing at baseline is `still-failing` and
 * must never be charged to the current session. And since the knowledge
 * lattice is three-valued, neither direction of the comparison may borrow
 * certainty from the other: a check that was *skipped* at baseline (budget
 * exhausted before it ever ran) can neither prove a regression nor credit a
 * fix, so it lands on `indeterminate` — the old behaviour of rounding
 * "never ran" up to "ok" manufactured verdicts out of nothing.
 */
export declare function verdictOf(baseline: Evidence | undefined, current: Evidence | undefined): CheckVerdict;
export type { CheckStatus as EvidenceCheckStatus };
//# sourceMappingURL=evidence.d.ts.map