/**
 * MCP (Model Context Protocol) server — any harness, any agent.
 *
 * Exposes dsh-proof's verification face over stdio JSON-RPC 2.0 so agents that
 * are NOT running inside DeepSeek Harness can still baseline, verify and claim
 * against the same tamper-evident evidence chain. This module is deliberately
 * framework-free: `createMcpHandler` is a pure per-message dispatcher (no I/O,
 * directly unit-testable) and `runMcpServer` is the thin newline-delimited
 * stdio loop around it.
 *
 * APP/1.4 cross-agent contract: exactly thirteen tools — `MCP_TOOLS` below is
 * the frozen list every consumer agrees on. (APP/1.0 spoke five; the §6
 * transparency-log expansion took it to seven with `proof_publish` and
 * `proof_log_verify`; the v0.19 responsibility-DAG expansion took it to ten
 * with `proof_delegate`, `proof_delegate_submit` and `proof_task`; the v0.20
 * training-export expansion took it to eleven with `proof_training_export`;
 * the v0.21 verification-economics expansion takes it to thirteen with
 * `proof_economics` and `proof_sla_quote`. Each bump is what lets an older
 * consumer refuse the wider dialect instead of guessing at it.)
 *
 * Transport note: MCP stdio is newline-delimited JSON (one JSON-RPC 2.0
 * message per line), NOT LSP-style Content-Length framing. Protocol-level
 * problems (unknown method, unparseable line, malformed request, a request
 * before `initialize`, a line over the transport cap) answer as JSON-RPC
 * errors; a tool that ran but failed answers as a normal result with
 * `isError: true` — MCP tool-error semantics, never mapped onto the RPC
 * layer. JSON-RPC 2.0 batches (an array of messages) are processed element
 * by element and answered with an array, per the specification.
 *
 * @module dsh-proof/app/mcp-server
 */
import type { ProofEngine } from '../engine.ts';
export declare const MCP_TOOLS: readonly ["proof_status", "proof_baseline", "proof_verify", "proof_claim", "proof_bundle", "proof_publish", "proof_log_verify", "proof_delegate", "proof_delegate_submit", "proof_task", "proof_training_export", "proof_economics", "proof_sla_quote"];
/**
 * Dependencies the server needs beyond the engine itself. Every path is
 * derived by the entry with the same rules the engine applied to its own
 * private copies (the engine exports neither its log path nor its derivation),
 * so the caller and this module never disagree about where evidence lives.
 */
export interface McpEngineDeps {
    engine: ProofEngine;
    /** Physical evidence-log location (`<storeDir>/evidence.jsonl`). */
    evidenceLogPath: string;
    /** Physical baseline location (`<storeDir>/baseline.json`). */
    baselinePath: string;
    /** Physical anchor location (`<trustDir>/anchors/<workspaceKey>/anchor.json`). */
    anchorPath: string;
    /** Stable workspace identity the bundle manifest is keyed by. */
    workspaceKey: string;
    /**
     * v0.18: directory of the public transparency log (`proof_publish` /
     * `proof_log_verify`). Absent = both tools answer a clean configuration
     * error. The entry derives it from the environment (DSH_PROOF_PTL_DIR,
     * default `<trustRoot>/ptl`) — the same dir the engine publishes to.
     */
    ptlDir?: string;
    /** Reported as serverInfo.version (entry injects from env or the constant). */
    serverVersion: string;
    /**
     * v0.22: opt-out of the initialize-before-tools gate for embedders that
     * drive `createMcpHandler` directly (unit tests, in-process hosts). The
     * stdio server NEVER honours this flag (v0.24, V6-L/F9): `runMcpServer`
     * strips it before building the handler — over a real transport the
     * handshake is mandatory, and an environment variable or embedding mistake
     * that flipped the flag used to silently open the un-handshaked door.
     */
    allowUninitializedTools?: boolean;
    /**
     * v0.22: the host-side trust root, when the caller knows it — the PTL
     * operator key resolves under it first (`<trustRoot>/ptl-operator-key`,
     * the engine's and the CLI's default) before the log-dir spellings, so a
     * key that notarises a log is never loaded from inside the directory the
     * log's own writer can rewrite.
     */
    trustRoot?: string;
}
export interface McpServerOptions extends McpEngineDeps {
    /** Defaults to process.stdin; overridable for tests. */
    input?: NodeJS.ReadableStream;
    /** Defaults to process.stdout; overridable for tests. */
    output?: NodeJS.WritableStream;
}
export declare const MCP_SERVER_NAME = "agent-proof-protocol";
/**
 * v0.24 (V6-L10): the version this build reports as serverInfo.version when
 * DSH_PROOF_SERVER_VERSION is unset. The constant tracks the package version
 * — a v0.23 build answering "0.22.0" made every version-negotiating or
 * reconciliation-minded client misjudge the dialect it was speaking for no
 * reason. Bump it with package.json (an operator who needs to pin the string
 * still can, via DSH_PROOF_SERVER_VERSION).
 */
export declare const MCP_DEFAULT_VERSION = "0.27.0";
/**
 * One marker record as this face reads it back: the label, the envelope
 * timestamp, the payload verbatim, and (v0.24) the degraded flag when the
 * record was admitted by the generational fallback.
 */
export interface McpMarkerRecord {
    readonly label: string;
    readonly at: string | null;
    readonly payload: Record<string, unknown>;
    /**
     * X-H-06 (v0.24, V6-M2): present exactly when this record was admitted by
     * the generational fallback — EVERY marker under its label is suspect, the
     * shape of a log written before the headRef witness existed. The engine
     * reads such labels degraded rather than as empty; this face now does the
     * same (through the same view), so an upgraded deployment's old
     * `delegation/*` DAG and ledgers survive the read instead of evaporating
     * only on this face.
     */
    readonly degraded?: true;
}
/**
 * v0.23 (W8 / G2 contract): every marker payload on the evidence chain under
 * the given labels (exact match) or label prefixes, in log order — with the
 * H-32 SUSPECT lines excluded.
 *
 * This face's marker read-backs (`taskOverview`, `latestEconomicsMarker`)
 * used to walk the raw log lines themselves, matching labels and nothing
 * else — the exact shape of the jury-prompt injection the DSH face fixed by
 * filtering suspect markers in its own `markerPayloads`. A marker whose
 * `headRef` (the chain head the writer saw at append time) does not match
 * the digest of the line physically before it was replayed, moved or
 * injected, and must not be read as chain fact: an out-of-band
 * `delegation/created` twin or a forged `proof/verified` economics carrier
 * would otherwise ride the overview and the ledger replay as if the chain
 * had corroborated it.
 *
 * v0.24 (V6-M1): the witness is judged in the READLINES domain — blank lines
 * filtered, exactly what `fsView.readLines` (and the store's own reads)
 * produce. The writer stamps `headRef` with the digest of the last NON-BLANK
 * line (the store's tail), so the raw split this face used judged honest
 * markers against blank lines they never chained to: one stray blank line
 * silently dropped every honest marker after it here, while a crafted
 * `blank + headRef=sha256('')` pair made a forged carrier's witness PASS in
 * the raw view and fail everywhere else. Both directions are gone now that
 * all positions come from the one blank-filtered domain.
 *
 * v0.24 (V6-M2): suspect adjudication and the X-H-06 generational fallback
 * come from `createVerifiedView` over the engine's own store — the same
 * surface the engine's trust decisions read, so this face can no longer
 * disagree with the engine about which markers exist. On any chain this
 * build wrote, honest markers are never suspect and the fallback never
 * fires; a label whose ENTIRE population is suspect (a pre-witness legacy
 * log) reads degraded instead of empty — engine parity, not face divergence.
 *
 * Exported (not private) so the cross-face contract is greppable and
 * unit-pinnable: `markerPayloads` on this face mirrors the verified-read
 * rule the engine applies, suspect filtering and generational fallback
 * included.
 */
export declare function markerPayloads(deps: McpEngineDeps, labels: ReadonlySet<string>, options?: {
    readonly labelPrefixes?: readonly string[];
}): Promise<McpMarkerRecord[]>;
export declare function createMcpHandler(deps: McpEngineDeps): (message: unknown) => Promise<{
    response?: unknown;
}>;
/**
 * One buffered line of input, or the marker of a line that blew the cap.
 * An oversized line is reported, never delivered — the stdio contract is one
 * JSON-RPC message per line, and a client violating it by orders of magnitude
 * must not size this server's memory.
 */
type CappedLine = {
    text: string;
} | {
    oversized: true;
};
/**
 * Read newline-delimited text from a stream with a hard per-line byte cap.
 * Bytes of an over-cap line are DISCARDED as they arrive (only the first
 * cap-crossing chunk is inspected), so neither a giant single line nor a
 * giant unterminated tail can grow the buffer without bound.
 *
 * v0.23 (W8-F3): lines are split at the BYTE level (the buffer stays bytes;
 * 0x0A is searched in the byte stream; only complete lines are decoded).
 * The old shape decoded each chunk to UTF-8 as it arrived, so a multi-byte
 * character straddling a chunk boundary was decoded twice — one U+FFFD per
 * half — and a perfectly legal CJK/emoji JSON line was answered with a
 * parse error. Byte-level splitting makes the boundary invisible (a UTF-8
 * continuation byte is never 0x0A, so a newline can never sit inside a code
 * point) and makes `capBytes` exact byte semantics for free. Exported for
 * the transport unit tests that pin the boundary-crossing behaviour.
 *
 * v0.24 (V6-F5): input-side backpressure — see {@link INPUT_QUEUE_HIGH_WATER}.
 * A stream without `pause`/`resume` (not one this face is wired to, but the
 * parameter type allows it) simply keeps flowing; nothing is dropped either
 * way, the cap only bounds OUR buffer when the transport cooperates.
 */
export declare function readCappedLines(input: NodeJS.ReadableStream, capBytes: number): AsyncIterable<CappedLine>;
/**
 * Run the MCP server over newline-delimited JSON-RPC 2.0: one message per
 * line on stdin, one response per line on stdout. Resolves when the input
 * stream ends. Protocol-level failures (an unparseable line, a line over the
 * 4 MiB cap) are emitted as JSON-RPC error responses with id null, because
 * the offending line carried no readable id to echo. Writes respect
 * backpressure, and a dead output stream (EPIPE) ends the loop instead of
 * crashing the process.
 */
export declare function runMcpServer(options: McpServerOptions): Promise<void>;
export {};
//# sourceMappingURL=mcp-server.d.ts.map