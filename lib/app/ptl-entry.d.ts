#!/usr/bin/env node
/**
 * Proof Transparency Log CLI — the non-MCP auditor's path (v0.22.0).
 *
 * A transparency log turns "the agent's evidence chain looked fine when I
 * checked" into a publicly checkable commitment: the latest *signed*
 * checkpoint of a workspace's evidence chain is appended to an append-only
 * merkle log, and the log operator signs a tree head (STH) over the whole
 * log after every append. From then on, anyone holding a published STH can
 * prove — without trusting the operator's future honesty — that the log was
 * never truncated or rewritten (consistency proofs), and that a given
 * checkpoint really was published at a given position (inclusion proofs).
 *
 * Three subcommands, each one line of JSON on stdout (or a clean one-line
 * error on stderr — never a stack trace):
 *
 *   dsh-proof-ptl append --log <dir> [--operator-key <keydir>]
 *       Extract the latest publishable checkpoint from the current
 *       workspace's evidence chain and append it to the log at <dir>, then
 *       sign and save a fresh STH with the operator key. Selection is
 *       anchor-gated AND signature-verified (v0.23, X-H-11): with an anchor
 *       on record only checkpoints signed by the ANCHORED key are
 *       candidates, without one only checkpoints under the local engine
 *       key ($TRUST_DIR/keys) — and whichever branch runs, the chosen
 *       checkpoint's signature must actually VERIFY under key material
 *       this host holds. A keyId string match alone proves nothing (a
 *       forged checkpoint can claim any keyId it likes), and a candidate
 *       key with no local key material is a loud refusal naming what to
 *       provide — never a best-effort publish of unverifiable bytes. The
 *       operator key is resolved BEFORE the log is touched, so a key
 *       problem cannot leave a published-but-headless entry behind.
 *   dsh-proof-ptl head --log <dir>
 *       Print the current STH, or {"empty":true}.
 *   dsh-proof-ptl verify --log <dir> [--bundle <bundle.json>] [--operator-key <keydir>]
 *       No --bundle: self-check (recomputed merkle root === STH root, tree
 *       sizes agree, the STH signature adjudicated — and a head that cannot
 *       be adjudicated, because no operator key is at hand, FAILS the check:
 *       uncertain = fail, same as the bundle face; malformed lines in the
 *       entries file are counted, surfaced and fail the check too).
 *       With --bundle: audit the bundle's manifest.transparency record against
 *       the log — leaf match, inclusion, consistency (non-rewrite), the
 *       operator's signature over the bundle-PINNED published head, the
 *       current head's signature, and the operator identity (`logId`)
 *       agreement between the pinned head and the current one.
 *
 * The operator key NEVER lives in the log directory by default (v0.22): a
 * key sitting next to the data it notarises is self-referential — whoever
 * can rewrite the log can replace the key and re-sign the rewrite.
 * Resolution order: the --operator-key <keydir> flag, then
 * $DSH_PROOF_OPERATOR_KEY_DIR, then <trustRoot>/ptl-operator-key where
 * <trustRoot> is the workspace discovery's trust root below. Existing
 * pre-0.22 logs whose key still sits at <logDir>/operator-key must pass
 * that directory explicitly.
 *
 * Workspace discovery mirrors app/mcp-entry.ts exactly, through the same
 * derivation adapters/shared/paths.ts applies:
 *   DSH_PROOF_ROOT             workspace root the log publishes for (default cwd)
 *   DSH_PROOF_TRUST_DIR        trust root (default $DSH_HOME/proof)
 *   DSH_PROOF_EVIDENCE_STORE   'host' (default) or 'workspace'
 *   DSH_PROOF_EVIDENCE_DIR     workspace-mode store segment (default '.proof')
 *   DSH_PROOF_OPERATOR_KEY_DIR operator key directory (default <trustRoot>/ptl-operator-key)
 *
 * Exit codes: 0 ok · 1 verification failure or nothing to publish · 2 usage.
 *
 * Discipline (same as src/app/*): imports only src/core/*, the shared path
 * derivation, node-ports and node: builtins — nothing from @deepseek-ai/*.
 *
 * @module dsh-proof/app/ptl-entry
 */
export {};
//# sourceMappingURL=ptl-entry.d.ts.map