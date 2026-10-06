/**
 * TRANSPARENCY — RFC 6962 mathematics for the checkpoint log.
 *
 * The adversary here is time and the log's own operator: a proof system that
 * claims "append-only" must fail provably when history is rewritten, reordered,
 * or truncated. The tests below pin that with three independent anchors:
 *
 * 1. **Differential** — an independently written naive recursion for the RFC
 *    6962 Merkle root (slice-based, its own hashing code) must agree with the
 *    implementation for every tree shape n = 0..33 (every binary shape up to
 *    5 bits of size), and every proof must verify against the NAIVE roots,
 *    never against roots produced by the code under test.
 * 2. **Known answer** — RFC 6962 §2.1.3's own worked example, the 7-leaf tree
 *    with named nodes: audit path of d0 is [b, h, l], PROOF(3, D[7]) is
 *    [c, d, g, l], PROOF(4, D[7]) is [l], PROOF(6, D[7]) is [i, j, k] —
 *    verbatim, so the implementation is pinned to the RFC's node ordering,
 *    not merely to its own consistency.
 * 3. **Narrative** — the split-view detector: rewriting the middle of the log
 *    mints a second self-consistent history whose root the signed tree head
 *    cannot reconcile, and truncating the tail is refused by the head guard.
 *
 * The storage tests drive the same FsPort contract the Node port implements;
 * MemoryFs stands in, exactly as it does for the evidence store.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { Buffer } from 'node:buffer'

import { canonicalJson, sha256 } from '../src/core/hash.ts'
import {
  type PtlEntry, type SignedTreeHead, TransparencyLog,
  appendPtlEntry, loadPtl, ptlLeafHash, savePtlHead, sthSignedData,
  verifyConsistency, verifyInclusion, verifyTreeHead,
} from '../src/core/transparency.ts'
import { MemoryFs } from './helpers.ts'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Deterministic workspace-checkpoint entry: every field varies with `i`. */
function entry(i: number, over: Partial<PtlEntry> = {}): PtlEntry {
  return {
    v: 1,
    workspaceKey: 'ws-alpha',
    keyId: 'key-ws',
    count: 10 + i,
    head: sha256(`head-${i}`),
    at: new Date(1_700_000_000_000 + i * 60_000).toISOString(),
    sig: `ws-sig-${sha256(`sig-${i}`).slice(0, 32)}`,
    ...over,
  }
}

/**
 * Deterministic log-operator key: signs STHs for the tests. The signature
 * BINDS the keyId — two operators never produce the same bytes over the same
 * data, so "verified under the wrong key" is testable.
 */
class FakeOperator {
  readonly keyId: string
  constructor(keyId = 'log-operator') { this.keyId = keyId }
  async sign(data: string): Promise<string> { return `op:${this.keyId}:${sha256(data)}` }
  async verify(data: string, sig: string): Promise<boolean> { return sig === `op:${this.keyId}:${sha256(data)}` }
}

/** Mint a genuinely-signed STH over a log's current state. */
async function mintSth(log: TransparencyLog, at: string): Promise<SignedTreeHead> {
  const op = new FakeOperator()
  const payload = { logId: op.keyId, treeSize: log.size, root: log.merkleRoot(), at }
  return { ...payload, sig: await op.sign(sthSignedData(payload)) }
}

/**
 * v0.23 (X-H-10): the operator-side head verifier handed to savePtlHead.
 * FakeOperator is stateless and deterministic (the signature is a function
 * of keyId + data), so a fresh instance verifies every head the default
 * operator minted — exactly the "caller holds the operator key" contract.
 */
const holdsUnderDefaultOperator = async (sth: SignedTreeHead): Promise<boolean> =>
  new FakeOperator().verify(sthSignedData(sth), sth.sig)

/** Flip one hex character (position defaults to the first) — a minimal forgery. */
function flipHex(h: string, at = 0): string {
  return `${h.slice(0, at)}${h[at] === '0' ? '1' : '0'}${h.slice(at + 1)}`
}

// ---------------------------------------------------------------------------
// Independent naive RFC 6962 reference — written from the RFC text, sharing
// no code with src/core/transparency.ts (own k-split, own hashing, slices)
// ---------------------------------------------------------------------------

function naiveSplit(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

function naiveNode(left: string, right: string): string {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]))
    .digest('hex')
}

function naiveLeafHash(e: PtlEntry): string {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalJson(e), 'utf8')]))
    .digest('hex')
}

function naiveRoot(leafHashes: readonly string[]): string {
  if (leafHashes.length === 0) return createHash('sha256').digest('hex')
  if (leafHashes.length === 1) return leafHashes[0] as string
  const k = naiveSplit(leafHashes.length)
  return naiveNode(naiveRoot(leafHashes.slice(0, k)), naiveRoot(leafHashes.slice(k)))
}

/** Leaves varied per (n, i) so every tree size gets a fresh content set too. */
function variedLeaves(n: number): PtlEntry[] {
  return Array.from({ length: n }, (_, i) => entry(i, {
    head: sha256(`leaf:${n}:${i}`),
    sig: `sig-${sha256(`sig:${n}:${i}`).slice(0, 24)}`,
  }))
}

// ---------------------------------------------------------------------------
// Leaf hashing: canonical bytes, domain separation
// ---------------------------------------------------------------------------

test('ptlLeafHash is exactly SHA-256(0x00 || canonicalJson(entry)) — pinned byte for byte', () => {
  const e = entry(3)
  const manual = createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalJson(e), 'utf8')]))
    .digest('hex')
  assert.equal(ptlLeafHash(e), manual)
  // Domain separation: without the 0x00 prefix this would be a leaf/node forgery.
  assert.notEqual(ptlLeafHash(e), sha256(canonicalJson(e)))
})

test('the leaf hash is over CANONONICAL bytes: key insertion order cannot move it', () => {
  const ordered = entry(7)
  // Same seven fields, deliberately shuffled insertion order — a different
  // producer (another language, another serialiser) addresses the same leaf.
  const shuffled = {
    sig: ordered.sig, at: ordered.at, head: ordered.head, count: ordered.count,
    keyId: ordered.keyId, workspaceKey: ordered.workspaceKey, v: 1,
  } as PtlEntry
  assert.equal(ptlLeafHash(shuffled), ptlLeafHash(ordered))
  // And insertion-ordered stringify would NOT have agreed: canonicalJson sorts
  // keys, JSON.stringify(ordered) does not, so the naive bytes differ.
  assert.notEqual(JSON.stringify(ordered), canonicalJson(ordered))
  // The dedupe sees them as the same event, not a new sequence number.
  const log = new TransparencyLog([ordered])
  assert.deepEqual(log.append(shuffled), { sequence: 0, duplicate: true })
})

// ---------------------------------------------------------------------------
// Differential Merkle root (every binary shape to 5 bits of size)
// ---------------------------------------------------------------------------

test('differential Merkle root: the naive RFC recursion agrees for n = 0..33', () => {
  for (let n = 0; n <= 33; n += 1) {
    const leaves = variedLeaves(n)
    const log = new TransparencyLog(leaves)
    assert.equal(log.merkleRoot(), naiveRoot(leaves.map(naiveLeafHash)), `root mismatch at n=${n}`)
    assert.equal(log.size, n)
  }
})

test('the empty log root is SHA-256 of nothing, computed independently', () => {
  const log = new TransparencyLog([])
  assert.equal(log.size, 0)
  assert.equal(log.entries.length, 0)
  assert.equal(log.merkleRoot(), createHash('sha256').digest('hex'))
})

// ---------------------------------------------------------------------------
// RFC 6962 §2.1.3 — the worked 7-leaf example, verbatim
// ---------------------------------------------------------------------------

test('RFC 6962 §2.1.3 known answer: audit paths [b,h,l] [c,g,l] [f,j,k] [i,k]', () => {
  const leaves = variedLeaves(7)
  const log = new TransparencyLog(leaves)
  const L = (i: number): string => naiveLeafHash(leaves[i] as PtlEntry)
  // The RFC's named nodes, computed by the naive reference:
  const b = L(1), c = L(2), d = L(3), f = L(5)
  const g = naiveNode(L(0), L(1))
  const h = naiveNode(L(2), L(3))
  const i = naiveNode(L(4), L(5))
  const j = L(6) // d6 sits alone under j in the RFC's picture
  const k = naiveNode(g, h)
  const l = naiveNode(i, j)

  assert.deepEqual(log.inclusionProof(0, 7), [b, h, l], 'audit path for d0 is [b, h, l]')
  assert.deepEqual(log.inclusionProof(3, 7), [c, g, l], 'audit path for d3 is [c, g, l]')
  assert.deepEqual(log.inclusionProof(4, 7), [f, j, k], 'audit path for d4 is [f, j, k]')
  assert.deepEqual(log.inclusionProof(6, 7), [i, k], 'audit path for d6 is [i, k]')
  assert.equal(log.merkleRoot(), naiveNode(k, l))
})

test('RFC 6962 §2.1.3 known answer: PROOF(3,7)=[c,d,g,l] PROOF(4,7)=[l] PROOF(6,7)=[i,j,k]', () => {
  const leaves = variedLeaves(7)
  const log = new TransparencyLog(leaves)
  const L = (i: number): string => naiveLeafHash(leaves[i] as PtlEntry)
  const g = naiveNode(L(0), L(1))
  const h = naiveNode(L(2), L(3))
  const i = naiveNode(L(4), L(5))
  const k = naiveNode(g, h)
  const l = naiveNode(i, L(6))

  assert.deepEqual(log.consistencyProof(3, 7), [L(2), L(3), g, l], 'PROOF(3, D[7]) = [c, d, g, l]')
  assert.deepEqual(log.consistencyProof(4, 7), [l], 'PROOF(4, D[7]) = [l]')
  assert.deepEqual(log.consistencyProof(6, 7), [i, L(6), k], 'PROOF(6, D[7]) = [i, j, k]')

  // And each RFC proof verifies against the naive roots of the corresponding
  // prefixes — the external anchor for the verifier, not just the generator.
  const rootOf = (n: number): string => naiveRoot(leaves.slice(0, n).map(naiveLeafHash))
  assert.equal(verifyConsistency(3, rootOf(3), 7, rootOf(7), log.consistencyProof(3, 7)), true)
  assert.equal(verifyConsistency(4, rootOf(4), 7, rootOf(7), log.consistencyProof(4, 7)), true)
  assert.equal(verifyConsistency(6, rootOf(6), 7, rootOf(7), log.consistencyProof(6, 7)), true)
})

// ---------------------------------------------------------------------------
// Inclusion proofs — every index of every size, plus the forgery matrix
// ---------------------------------------------------------------------------

test('inclusion proofs verify for every index at every tree size 1..33 (against naive roots)', () => {
  const leaves = variedLeaves(33)
  const log = new TransparencyLog(leaves)
  const rootOf = (n: number): string => naiveRoot(leaves.slice(0, n).map(naiveLeafHash))
  for (let n = 1; n <= 33; n += 1) {
    for (let m = 0; m < n; m += 1) {
      const proof = log.inclusionProof(m, n)
      assert.equal(
        verifyInclusion(leaves[m] as PtlEntry, m, n, proof, rootOf(n)),
        true,
        `inclusion failed at (index=${m}, treeSize=${n})`,
      )
    }
  }
})

test('inclusion proofs prove against a HISTORICAL tree head (older STH, smaller tree)', () => {
  const leaves = variedLeaves(9)
  const log = new TransparencyLog(leaves)
  const root5 = naiveRoot(leaves.slice(0, 5).map(naiveLeafHash))
  for (let m = 0; m < 5; m += 1) {
    assert.equal(verifyInclusion(leaves[m] as PtlEntry, m, 5, log.inclusionProof(m, 5), root5), true)
  }
  // The proof for treeSize 5 does not verify against the tree of 9...
  assert.equal(verifyInclusion(leaves[0] as PtlEntry, 0, 5, log.inclusionProof(0, 5), naiveRoot(leaves.map(naiveLeafHash))), false)
  // ...and a leaf beyond the historical size has no proof in it at all.
  assert.throws(() => log.inclusionProof(5, 5), RangeError)
})

test('inclusion verification rejects every forgery shape and never throws', () => {
  const leaves = variedLeaves(12)
  const log = new TransparencyLog(leaves)
  const e = leaves[4] as PtlEntry
  const root = naiveRoot(leaves.map(naiveLeafHash))
  const proof = log.inclusionProof(4, 12)
  assert.equal(verifyInclusion(e, 4, 12, proof, root), true, 'sanity: the honest proof verifies')

  // Tampered leaf (one checkpoint field changed).
  assert.equal(verifyInclusion(entry(4, { count: 999 }), 4, 12, proof, root), false)
  // Tampered single proof element — every position.
  for (let j = 0; j < proof.length; j += 1) {
    const forged = proof.map((node, at) => (at === j ? flipHex(node) : node))
    assert.equal(verifyInclusion(e, 4, 12, forged, root), false, `forged element ${j} accepted`)
  }
  // Tampered root.
  assert.equal(verifyInclusion(e, 4, 12, proof, flipHex(root)), false)
  // Wrong proof length: truncated, extended, empty.
  assert.equal(verifyInclusion(e, 4, 12, proof.slice(0, -1), root), false)
  assert.equal(verifyInclusion(e, 4, 12, [...proof, proof[0]!], root), false)
  assert.equal(verifyInclusion(e, 4, 12, [], root), false)
  // Non-hex proof element.
  assert.equal(verifyInclusion(e, 4, 12, ['zz'.repeat(32), ...proof.slice(1)], root), false)
  // Out-of-range and non-integer inputs answer false, never throw.
  assert.equal(verifyInclusion(e, 12, 12, [], root), false)
  assert.equal(verifyInclusion(e, -1, 12, proof, root), false)
  assert.equal(verifyInclusion(e, 4, 0, proof, root), false)
  // A proof does not transfer to a different claimed tree shape: the 6-leaf
  // fold of (index 4) consumes 2 nodes, this 12-leaf proof carries 4.
  assert.equal(verifyInclusion(e, 4, 6, log.inclusionProof(4, 12), root), false)
  // Under a shape that consumes the proof identically (13), the fold is still
  // committed to exactly the root it reconstructs — a different 13-leaf root
  // is never satisfied. (The honest 12-root folding under shape 13 is not a
  // break: tree sizes are pinned by the SIGNED head, not by the proof.)
  assert.equal(
    verifyInclusion(e, 4, 13, log.inclusionProof(4, 12), naiveRoot(variedLeaves(13).map(naiveLeafHash))),
    false,
  )
  assert.equal(verifyInclusion(e, 1.5, 12, proof, root), false)
  assert.equal(verifyInclusion(e, 4, 2.5, proof, root), false)
  // A proof for a different leaf in the same tree does not transfer.
  assert.equal(verifyInclusion(leaves[5] as PtlEntry, 4, 12, proof, root), false)
})

test('the producer side throws RangeError on out-of-range arguments', () => {
  const log = new TransparencyLog(variedLeaves(6))
  assert.throws(() => log.inclusionProof(6), RangeError)
  assert.throws(() => log.inclusionProof(-1), RangeError)
  assert.throws(() => log.inclusionProof(0, 0), RangeError)
  assert.throws(() => log.inclusionProof(0, 7), RangeError)
  assert.throws(() => log.inclusionProof(3, 3), RangeError)
  assert.throws(() => log.consistencyProof(0, 5), RangeError, 'RFC domain is 0 < m')
  assert.throws(() => log.consistencyProof(3, 2), RangeError)
  assert.throws(() => log.consistencyProof(2, 7), RangeError)
  // Identity is allowed and empty — same tree twice.
  assert.deepEqual(log.consistencyProof(5, 5), [])
})

// ---------------------------------------------------------------------------
// Consistency proofs — sampled (a, b) windows against naive roots
// ---------------------------------------------------------------------------

const OLD_SIZES = [1, 2, 3, 5, 8, 13, 21] as const
const MAX_B = 33

test('consistency proofs verify for sampled (a, b) with a < b <= 33 (against naive roots)', () => {
  const leaves = variedLeaves(MAX_B)
  const log = new TransparencyLog(leaves)
  const hashes = leaves.map(naiveLeafHash)
  const rootOf = (n: number): string => naiveRoot(hashes.slice(0, n))
  for (const a of OLD_SIZES) {
    for (let b = a + 1; b <= MAX_B; b += 1) {
      const proof = log.consistencyProof(a, b)
      assert.ok(proof.length <= Math.ceil(Math.log2(b)) + 1, `proof for (${a},${b}) exceeds the RFC bound`)
      assert.equal(
        verifyConsistency(a, rootOf(a), b, rootOf(b), proof),
        true,
        `consistency failed for (${a}, ${b})`,
      )
    }
  }
})

test('the old root is derivable from the new tree: prefix inclusion + consistency pin the a-leaf view', () => {
  // "旧根可从新树导出": every leaf of the old prefix still proves into the NEW
  // tree, and the consistency proof binds that same prefix root to the new
  // root. Together: nothing in the first a leaves changed as the log grew.
  const leaves = variedLeaves(MAX_B)
  const log = new TransparencyLog(leaves)
  const hashes = leaves.map(naiveLeafHash)
  const rootOf = (n: number): string => naiveRoot(hashes.slice(0, n))
  for (const [a, b] of [[3, 12], [5, 20], [8, 33], [13, 29], [21, 33]] as const) {
    for (let m = 0; m < a; m += 1) {
      assert.equal(verifyInclusion(leaves[m] as PtlEntry, m, b, log.inclusionProof(m, b), rootOf(b)), true)
    }
    assert.equal(verifyConsistency(a, rootOf(a), b, rootOf(b), log.consistencyProof(a, b)), true, `(${a},${b})`)
  }
})

test('consistency verification rejects truncation, forgery, and mismatched windows', () => {
  const leaves = variedLeaves(MAX_B)
  const log = new TransparencyLog(leaves)
  const hashes = leaves.map(naiveLeafHash)
  const rootOf = (n: number): string => naiveRoot(hashes.slice(0, n))

  // A truncated log (new size below old size) is the forgery this function
  // exists to catch — answered false, never thrown, so auditors can batch it.
  assert.equal(verifyConsistency(9, rootOf(9), 7, rootOf(7), log.consistencyProof(7, 7)), false)
  assert.equal(verifyConsistency(9, rootOf(9), 7, rootOf(7), []), false)
  // Forged old root.
  assert.equal(verifyConsistency(5, flipHex(rootOf(5)), 12, rootOf(12), log.consistencyProof(5, 12)), false)
  // Forged new root.
  assert.equal(verifyConsistency(5, rootOf(5), 12, flipHex(rootOf(12)), log.consistencyProof(5, 12)), false)
  // Every single tampered proof element is caught (sampled windows).
  for (const [a, b] of [[3, 12], [5, 20], [8, 33], [13, 29]] as const) {
    const proof = log.consistencyProof(a, b)
    for (let j = 0; j < proof.length; j += 1) {
      const forged = proof.map((node, at) => (at === j ? flipHex(node) : node))
      assert.equal(verifyConsistency(a, rootOf(a), b, rootOf(b), forged), false, `forged element ${j} of (${a},${b})`)
    }
  }
  // A proof minted for a DIFFERENT old size does not verify this window
  // (sampled; where lengths differ it fails structurally, where they match it
  // folds to the wrong root — both must land on false).
  for (const [a, a2, b] of [[4, 5, 12], [6, 5, 20], [12, 13, 29]] as const) {
    assert.equal(
      verifyConsistency(a, rootOf(a), b, rootOf(b), log.consistencyProof(a2, b)),
      false,
      `proof for ${a2} accepted as proof for ${a}`,
    )
  }
  // Wrong length and non-hex nodes.
  const proof58 = log.consistencyProof(5, 8)
  assert.equal(verifyConsistency(5, rootOf(5), 8, rootOf(8), proof58.slice(0, -1)), false)
  assert.equal(verifyConsistency(5, rootOf(5), 8, rootOf(8), [...proof58, proof58[0]!]), false)
  assert.equal(verifyConsistency(5, rootOf(5), 8, rootOf(8), ['zz'.repeat(32)]), false)
  // Identity semantics: same size needs an empty proof AND equal roots.
  assert.equal(verifyConsistency(8, rootOf(8), 8, rootOf(8), []), true)
  assert.equal(verifyConsistency(8, rootOf(8), 8, flipHex(rootOf(8)), []), false)
  assert.equal(verifyConsistency(8, rootOf(8), 8, rootOf(8), proof58), false)
  // Non-integer sizes.
  assert.equal(verifyConsistency(2.5, rootOf(5), 8, rootOf(8), proof58), false)
})

// ---------------------------------------------------------------------------
// Signed tree heads
// ---------------------------------------------------------------------------

test('sthSignedData covers exactly the canonical payload bytes', () => {
  const payload = { logId: 'log-operator', treeSize: 9, root: sha256('r'), at: '2026-10-06T00:00:00.000Z' }
  // canonicalJson sorts keys, so the signed bytes are insertion-order-free.
  assert.equal(sthSignedData(payload), canonicalJson({ at: payload.at, logId: payload.logId, root: payload.root, treeSize: payload.treeSize }))
  assert.equal(sthSignedData(payload), `{"at":"${payload.at}","logId":"${payload.logId}","root":"${payload.root}","treeSize":9}`)
  // Every field moves the bytes.
  assert.notEqual(sthSignedData({ ...payload, treeSize: 10 }), sthSignedData(payload))
  assert.notEqual(sthSignedData({ ...payload, root: flipHex(payload.root) }), sthSignedData(payload))
  assert.notEqual(sthSignedData({ ...payload, at: '2026-10-07T00:00:00.000Z' }), sthSignedData(payload))
})

test('verifyTreeHead: a genuine operator signature verifies; every tampering fails', async () => {
  const leaves = variedLeaves(6)
  const log = new TransparencyLog(leaves)
  const op = new FakeOperator()
  const sth = await mintSth(log, '2026-10-06T01:00:00.000Z')

  assert.equal(sth.treeSize, 6)
  assert.equal(sth.root, naiveRoot(leaves.map(naiveLeafHash)), 'the signed root is the naive-recomputed root')
  assert.equal(await verifyTreeHead(sth, (d, s) => op.verify(d, s)), true)

  // Tampered fields: the signature no longer covers the payload on record.
  assert.equal(await verifyTreeHead({ ...sth, treeSize: 7 }, (d, s) => op.verify(d, s)), false)
  assert.equal(await verifyTreeHead({ ...sth, root: flipHex(sth.root) }, (d, s) => op.verify(d, s)), false)
  assert.equal(await verifyTreeHead({ ...sth, at: '2026-10-06T02:00:00.000Z' }, (d, s) => op.verify(d, s)), false)
  assert.equal(await verifyTreeHead({ ...sth, logId: 'other-log' }, (d, s) => op.verify(d, s)), false)
  assert.equal(await verifyTreeHead({ ...sth, sig: flipHex(sth.sig, 4) }, (d, s) => op.verify(d, s)), false)
  // A different operator's key does not verify someone else's head.
  const other = new FakeOperator('other-operator')
  assert.equal(await verifyTreeHead(sth, (d, s) => other.verify(d, s)), false)
})

// ---------------------------------------------------------------------------
// Dedupe by leaf hash
// ---------------------------------------------------------------------------

test('append is idempotent by leaf hash: a replayed checkpoint is not a new event', () => {
  const log = new TransparencyLog()
  const e = entry(0)
  assert.deepEqual(log.append(e), { sequence: 0, duplicate: false })
  const rootAfterOne = log.merkleRoot()
  assert.deepEqual(log.append(e), { sequence: 0, duplicate: true }, 'same bytes, same sequence')
  assert.equal(log.size, 1, 'the tree did not grow')
  assert.equal(log.merkleRoot(), rootAfterOne, 'the root did not move')

  // One changed character in any field is a different event.
  const e2 = entry(1, { head: flipHex(sha256('head-1')) })
  assert.deepEqual(log.append(e2), { sequence: 1, duplicate: false })
  assert.equal(log.size, 2)
  assert.notEqual(log.merkleRoot(), rootAfterOne)

  // A log built from a stored copy (with the duplicate) keeps first-wins order.
  const stored = new TransparencyLog([e, e2, e])
  assert.equal(stored.size, 3)
  assert.deepEqual(stored.append(e), { sequence: 0, duplicate: true })
  assert.deepEqual(log.entries[1], e2, 'entries expose sequence order')
})

// ---------------------------------------------------------------------------
// Storage: loadPtl / appendPtlEntry / savePtlHead
// ---------------------------------------------------------------------------

const DIR = '/ptl'
const ENTRIES_PATH = '/ptl/ptl-entries.jsonl'
const HEAD_PATH = '/ptl/sth.json'

test('loadPtl on an empty directory: empty log, no head, nothing bad', async () => {
  const fs = MemoryFs.of({})
  const { log, sth, badLines } = await loadPtl(fs, DIR)
  assert.equal(log.size, 0)
  assert.equal(log.merkleRoot(), createHash('sha256').digest('hex'))
  assert.equal(sth, undefined)
  assert.equal(badLines, 0)
})

test('appendPtlEntry → loadPtl round-trips entries and root through ptl-entries.jsonl', async () => {
  const fs = MemoryFs.of({})
  const e0 = entry(0), e1 = entry(1), e2 = entry(2)
  assert.deepEqual(await appendPtlEntry(fs, DIR, e0), { sequence: 0, duplicate: false })
  assert.deepEqual(await appendPtlEntry(fs, DIR, e1), { sequence: 1, duplicate: false })
  assert.deepEqual(await appendPtlEntry(fs, DIR, e2), { sequence: 2, duplicate: false })
  // The replay across process boundaries dedupes exactly like the in-memory log.
  assert.deepEqual(await appendPtlEntry(fs, DIR, e1), { sequence: 1, duplicate: true })

  const { log, sth, badLines } = await loadPtl(fs, DIR)
  assert.equal(log.size, 3, 'the duplicate appended no line')
  assert.deepEqual(log.entries, [e0, e1, e2])
  assert.equal(log.merkleRoot(), naiveRoot([e0, e1, e2].map(naiveLeafHash)))
  assert.equal(sth, undefined)
  assert.equal(badLines, 0)
  assert.equal(fs.files.get(ENTRIES_PATH)!.split('\n').filter(l => l.length > 0).length, 3)
})

test('loadPtl skips malformed lines and counts them; the readable prefix survives', async () => {
  const e0 = entry(0), e1 = entry(1)
  const lines = [
    canonicalJson(e0),
    'this line is not json at all',
    '{"v":2,"workspaceKey":"ws","keyId":"k","count":1,"head":"h","at":"t","sig":"s"}', // wrong version
    '{"v":1,"workspaceKey":123}', // wrong types, truncated shape
    canonicalJson(e1),
  ]
  const fs = MemoryFs.of({ [ENTRIES_PATH]: `${lines.join('\n')}\n` })
  const { log, sth, badLines } = await loadPtl(fs, DIR)
  assert.equal(badLines, 3)
  assert.equal(log.size, 2)
  assert.deepEqual(log.entries, [e0, e1])
  assert.equal(sth, undefined)
})

test('a missing or malformed sth.json loads as undefined, never throws', async () => {
  const good = { logId: 'log-operator', treeSize: 3, root: sha256('r'), at: '2026-10-06T00:00:00.000Z', sig: 'op:x' }
  for (const raw of ['{oops not json', '{"logId":5}', '{"logId":"l","treeSize":-1,"root":"r","at":"a","sig":"s"}', 'null', '"a string"']) {
    const fs = MemoryFs.of({ [HEAD_PATH]: raw })
    assert.equal((await loadPtl(fs, DIR)).sth, undefined, `malformed head ${JSON.stringify(raw)} must load undefined`)
  }
  const fs = MemoryFs.of({ [HEAD_PATH]: canonicalJson(good) })
  assert.deepEqual((await loadPtl(fs, DIR)).sth, good)
})

test('savePtlHead round-trips and advances; the identical head re-saves idempotently', async () => {
  const fs = MemoryFs.of({})
  const shared = variedLeaves(5) // one history: 3-leaf prefix, then 5-leaf extension
  // v0.22: the entries live on disk — an advancing head must prove its
  // prefix consistency against them, so the log has to be real.
  for (const e of shared) await appendPtlEntry(fs, DIR, e)
  const sthA = await mintSth(new TransparencyLog(shared.slice(0, 3)), '2026-10-06T01:00:00.000Z')
  // The FIRST head is a cold start: no prior commitment, no verification.
  await savePtlHead(fs, DIR, sthA)
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthA)
  // Same head again: allowed (idempotent re-assertion) — and v0.23 (X-H-10):
  // the stored head's signature is adjudicated first, and it holds.
  await savePtlHead(fs, DIR, sthA, { verifyExistingHead: holdsUnderDefaultOperator })
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthA)
  // Advance: bigger tree, later timestamp, consistent prefix.
  const sthB = await mintSth(new TransparencyLog(shared), '2026-10-06T02:00:00.000Z')
  await savePtlHead(fs, DIR, sthB, { verifyExistingHead: holdsUnderDefaultOperator })
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthB)
  assert.equal(
    verifyConsistency(sthA.treeSize, sthA.root, sthB.treeSize, sthB.root,
      new TransparencyLog(shared).consistencyProof(3, 5)),
    true,
    'the stored heads are mutually consistent',
  )
})

test('savePtlHead (v0.22): a LONGER head over a rewritten history is refused — longer is not enough, the prefix must prove', async () => {
  const fs = MemoryFs.of({})
  const honest = variedLeaves(3)
  for (const e of honest) await appendPtlEntry(fs, DIR, e)
  const sthA = await mintSth(new TransparencyLog(honest), '2026-10-06T01:00:00.000Z')
  await savePtlHead(fs, DIR, sthA)

  // The attacker rewrites the whole file into a longer, self-consistent,
  // ENTIRELY DIFFERENT history and asks the operator to sign its head.
  const rewritten = variedLeaves(6) // fresh content, same length arithmetic
  fs.mutate(ENTRIES_PATH, `${rewritten.map(e => canonicalJson(e)).join('\n')}\n`)
  const sthAttack = await mintSth(new TransparencyLog(rewritten), '2026-10-06T02:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, sthAttack, { verifyExistingHead: holdsUnderDefaultOperator }),
    /refusing to sign a head that does not extend the published history/,
    'M-60: size growth without a consistency proof from the OLD head is a rewrite, not an append',
  )
  assert.equal((await loadPtl(fs, DIR)).sth!.root, sthA.root, 'the published head is untouched')

  // Back on the honest history, its genuine extension still signs fine.
  fs.mutate(ENTRIES_PATH, `${honest.map(e => canonicalJson(e)).join('\n')}\n`)
  await appendPtlEntry(fs, DIR, entry(50))
  const grown = (await loadPtl(fs, DIR)).log
  const sthHonest = await mintSth(grown, '2026-10-06T03:00:00.000Z')
  await savePtlHead(fs, DIR, sthHonest, { verifyExistingHead: holdsUnderDefaultOperator })
  assert.equal((await loadPtl(fs, DIR)).sth!.treeSize, 4)
})

test('savePtlHead (v0.22): operator identity flips, unparseable timestamps, and heads beyond the log are refused loudly', async () => {
  const fs = MemoryFs.of({})
  const leaves = variedLeaves(2)
  for (const e of leaves) await appendPtlEntry(fs, DIR, e)
  const opA = await mintSth(new TransparencyLog(leaves), '2026-10-06T01:00:00.000Z')
  await savePtlHead(fs, DIR, opA)

  // A head signed by a DIFFERENT operator over a grown tree: the identity
  // that auditors pin must not flip mid-log (M-60/A2-M3).
  const opB = new FakeOperator('OTHER-OPERATOR')
  const unsigned = { logId: opB.keyId, treeSize: 2, root: new TransparencyLog(leaves).merkleRoot(), at: '2026-10-06T02:00:00.000Z' }
  const flipped: SignedTreeHead = { ...unsigned, sig: await opB.sign(sthSignedData(unsigned)) }
  await assert.rejects(() => savePtlHead(fs, DIR, flipped), /refusing to change the transparency log operator/)

  // An `at` that is not a parseable instant is refused outright (A2-L1): a
  // garbage stamp could wedge every later honest comparison. The head is
  // RE-SIGNED over the garbage stamp so it passes the X-H-10 signature gate
  // first — the timestamp refusal is what is under test, not the signature.
  const wedgeOp = new FakeOperator()
  const wedgeUnsigned = { logId: 'log-operator', treeSize: 2, root: new TransparencyLog(leaves).merkleRoot(), at: 'zzzz' }
  const wedged: SignedTreeHead = { ...wedgeUnsigned, sig: await wedgeOp.sign(sthSignedData(wedgeUnsigned)) }
  await assert.rejects(
    () => savePtlHead(fs, DIR, wedged, { verifyExistingHead: holdsUnderDefaultOperator }),
    /timestamp cannot be parsed/,
  )

  // A head promising more entries than the file holds is disconnected, and
  // the disconnect is adjudicated instead of surfacing as a RangeError later.
  const beyond = await mintSth(new TransparencyLog(variedLeaves(9)), '2026-10-06T02:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, beyond, { verifyExistingHead: holdsUnderDefaultOperator }),
    /refusing to sign a head over 9 entries while the log holds 2/,
  )

  assert.equal((await loadPtl(fs, DIR)).sth!.logId, opA.logId, 'nothing was clobbered')
})

test('savePtlHead refuses every rewind: smaller tree, same tree different root, earlier timestamp', async () => {
  const fs = MemoryFs.of({})
  const at1 = '2026-10-06T02:00:00.000Z'
  await savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(9)), at1))
  const holds = { verifyExistingHead: holdsUnderDefaultOperator }

  // (1) truncated tree: treeSize goes backwards.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(7)), '2026-10-06T03:00:00.000Z'), holds),
    /refusing to rewind the transparency head/,
  )
  // (2) rewritten tree: same size, different root.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(10).slice(0, 9)), '2026-10-06T03:00:00.000Z'), holds),
    /refusing to rewind the transparency head/,
  )
  // (3) timestamp regression — even with a LARGER tree, `at` may not go back.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(12)), '2026-10-06T01:00:00.000Z'), holds),
    /refusing to rewind the transparency head/,
  )
  // Nothing was clobbered by the refused writes.
  assert.equal((await loadPtl(fs, DIR)).sth!.treeSize, 9)
  assert.equal((await loadPtl(fs, DIR)).sth!.at, at1)
})

// ---------------------------------------------------------------------------
// The narrative flagship: THE SPLIT-VIEW DETECTOR
// ---------------------------------------------------------------------------

test('THE SPLIT-VIEW DETECTOR: a rewritten entry mints a second self-consistent history the signed head cannot reconcile', async () => {
  const fs = MemoryFs.of({})
  const original = variedLeaves(9)
  for (const e of original) await appendPtlEntry(fs, DIR, e)
  const published = await loadPtl(fs, DIR)
  const sth = await mintSth(published.log, '2026-10-06T04:00:00.000Z')
  await savePtlHead(fs, DIR, sth)

  // The world's view: entry #4 is committed by the signed root, provably.
  const honestProof = published.log.inclusionProof(4, 9)
  assert.equal(verifyInclusion(original[4] as PtlEntry, 4, 9, honestProof, sth.root), true)

  // --- the rewrite: the operator's own file is edited behind the log's back ---
  const tamperedEntry = { ...(original[4] as PtlEntry), sig: 'ws-sig-forged-0000' }
  const lines = fs.files.get(ENTRIES_PATH)!.split('\n').filter(l => l.length > 0)
  lines[4] = canonicalJson(tamperedEntry)
  fs.mutate(ENTRIES_PATH, `${lines.join('\n')}\n`)

  const after = await loadPtl(fs, DIR)
  const forgedRoot = after.log.merkleRoot()
  assert.notEqual(forgedRoot, sth.root, 'rewriting one middle entry moves the root — the head is now a lie detector')

  // Both views are INTERNALLY consistent — each is a real Merkle tree — but
  // neither reconciles with the other, and only one matches the signed head.
  assert.equal(verifyInclusion(original[4] as PtlEntry, 4, 9, honestProof, sth.root), true, 'the old view still proves itself')
  assert.equal(verifyInclusion(tamperedEntry, 4, 9, honestProof, sth.root), false, 'the forged leaf cannot wear the old proof')
  assert.equal(verifyInclusion(tamperedEntry, 4, 9, after.log.inclusionProof(4, 9), forgedRoot), true, 'the forged view proves itself — into a root nobody signed')
  assert.equal((await loadPtl(fs, DIR)).sth!.root, sth.root, 'the head file still carries the ORIGINAL commitment')

  // Same size, different roots: no consistency proof exists between the views.
  assert.equal(verifyConsistency(9, sth.root, 9, forgedRoot, []), false)
  // And the old 5-leaf prefix cannot be derived from the rewritten tree: the
  // consistency proof the attacker's own log issues folds to the wrong old root.
  const originalPrefixRoot = naiveRoot(original.slice(0, 5).map(naiveLeafHash))
  const forgedPrefixRoot = naiveRoot([...original.slice(0, 4), tamperedEntry].map(naiveLeafHash))
  assert.notEqual(originalPrefixRoot, forgedPrefixRoot)
  assert.equal(verifyConsistency(5, originalPrefixRoot, 9, forgedRoot, after.log.consistencyProof(5, 9)), false,
    'the signed prefix is not derivable from the rewritten tree — history did not append, it forked')
  assert.equal(verifyConsistency(5, forgedPrefixRoot, 9, forgedRoot, after.log.consistencyProof(5, 9)), true,
    'the attacker can only prove their fork to themselves')
})

test('THE SPLIT-VIEW DETECTOR: truncating the tail is refused by the head guard and by the math', async () => {
  const fs = MemoryFs.of({})
  const original = variedLeaves(9)
  for (const e of original) await appendPtlEntry(fs, DIR, e)
  const full = await loadPtl(fs, DIR)
  const sth = await mintSth(full.log, '2026-10-06T04:00:00.000Z')
  await savePtlHead(fs, DIR, sth)

  // Cut the last two lines off the log — the classic "unpublish" move.
  const lines = fs.files.get(ENTRIES_PATH)!.split('\n').filter(l => l.length > 0)
  fs.mutate(ENTRIES_PATH, `${lines.slice(0, 7).join('\n')}\n`)
  const truncated = await loadPtl(fs, DIR)
  assert.equal(truncated.log.size, 7)

  // The math: the 9-leaf signed past is not derivable from a 7-leaf present.
  const truncatedRoot = truncated.log.merkleRoot()
  assert.equal(verifyConsistency(9, sth.root, 7, truncatedRoot, []), false, 'a tree cannot shrink into its own past')
  assert.equal(verifyConsistency(7, truncatedRoot, 9, sth.root, truncated.log.consistencyProof(7, 7)), false)
  // The guard: the operator refuses to sign the truncated state, exactly as
  // it refuses a forged STH from elsewhere landing in the head file.
  const truncatedSth = await mintSth(truncated.log, '2026-10-06T05:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, truncatedSth, { verifyExistingHead: holdsUnderDefaultOperator }),
    /refusing to rewind the transparency head/,
  )
  assert.equal((await loadPtl(fs, DIR)).sth!.root, sth.root, 'the published head is untouched')
})

test('reordering two entries moves the root: the RFC tree is an ORDERED tree, not a set', async () => {
  const fs = MemoryFs.of({})
  const original = variedLeaves(6)
  for (const e of original) await appendPtlEntry(fs, DIR, e)
  const honest = (await loadPtl(fs, DIR)).log

  const lines = fs.files.get(ENTRIES_PATH)!.split('\n').filter(l => l.length > 0)
  const swap = lines[2] as string
  lines[2] = lines[3] as string
  lines[3] = swap
  fs.mutate(ENTRIES_PATH, `${lines.join('\n')}\n`)

  const reordered = (await loadPtl(fs, DIR)).log
  assert.equal(reordered.size, 6)
  assert.notEqual(reordered.merkleRoot(), honest.merkleRoot(), 'swapping two log lines is a different history')
  // Same multiset, different sequence: set-hash semantics would NOT have
  // caught this — the ordered RFC tree is what makes the log a ledger.
  assert.deepEqual([...reordered.entries].slice(0, 2), [...honest.entries].slice(0, 2))
})

// ---------------------------------------------------------------------------
// v0.22 storage disciplines — torn tails, honest corruption reports,
// in-process append serialisation
// ---------------------------------------------------------------------------

test('appendPtlEntry refuses to append behind a TORN tail, naming the repair (M-61)', async () => {
  const fs = MemoryFs.of({})
  await appendPtlEntry(fs, DIR, entry(0))
  // Crash mid-write: a valid prefix with no closing brace, no newline.
  fs.mutate(ENTRIES_PATH, `${canonicalJson(entry(1)).slice(0, 25)}`)
  await assert.rejects(
    () => appendPtlEntry(fs, DIR, entry(2)),
    /torn \(unterminated\) line.*Repair the tail/s,
    'the silent-publication-loss shape must refuse, not splice',
  )
  // The file is untouched by the refusal.
  assert.equal(fs.files.get(ENTRIES_PATH), canonicalJson(entry(1)).slice(0, 25))
  // After repairing the tail (here: dropping the partial line), appending works.
  fs.mutate(ENTRIES_PATH, `${canonicalJson(entry(0))}\n`)
  const appended = await appendPtlEntry(fs, DIR, entry(2))
  assert.deepEqual(appended, { sequence: 1, duplicate: false })
  const { log } = await loadPtl(fs, DIR)
  assert.deepEqual(log.entries, [entry(0), entry(2)], 'the new line landed as its own line, provable by inclusion')
})

test('loadPtl counts whitespace-only lines as bad, and flags a head that overcommits the file (M-63/L3)', async () => {
  const e0 = entry(0)
  const raw = `${canonicalJson(e0)}\n   \n\t\n${canonicalJson(entry(1))}\n`
  const fs = MemoryFs.of({ [ENTRIES_PATH]: raw })
  const { log, badLines, headOvercommits } = await loadPtl(fs, DIR)
  assert.equal(badLines, 2, 'a line reduced to whitespace is damaged, not absent')
  assert.equal(log.size, 2)
  assert.equal(headOvercommits, undefined, 'no head on record: nothing to overcommit')

  const sth = await mintSth(log, '2026-10-06T01:00:00.000Z')
  const fs2 = MemoryFs.of({
    [ENTRIES_PATH]: raw,
    [HEAD_PATH]: canonicalJson({ ...sth, treeSize: sth.treeSize + 8 }),
  })
  const loaded2 = await loadPtl(fs2, DIR)
  assert.equal(loaded2.headOvercommits, true, 'a head promising more entries than the file holds is stated, not saved for a later RangeError')
  assert.equal(loaded2.log.size, 2)
})

test('concurrent appendPtlEntry calls serialise: every entry lands, exactly once, in submit order (M-62)', async () => {
  const fs = MemoryFs.of({})
  const outcomes = await Promise.all(
    [entry(0), entry(1), entry(2), entry(3), entry(4)].map(e => appendPtlEntry(fs, DIR, e)),
  )
  assert.deepEqual(outcomes.map(o => o.sequence), [0, 1, 2, 3, 4], 'no interleaving lost or duplicated a sequence number')
  assert.deepEqual(outcomes.map(o => o.duplicate), [false, false, false, false, false])
  const { log, badLines } = await loadPtl(fs, DIR)
  assert.equal(log.size, 5)
  assert.equal(badLines, 0)
  assert.equal(log.merkleRoot(), naiveRoot([entry(0), entry(1), entry(2), entry(3), entry(4)].map(naiveLeafHash)))
  // And the whole file is newline-terminated — no torn line can survive the
  // atomic whole-file commit even under racing writers.
  assert.ok(fs.files.get(ENTRIES_PATH)!.endsWith('\n'))
})

// ---------------------------------------------------------------------------
// v0.23 fix batch — X-H-10 (the stored head's own signature) and W9-M8
// (read failure is not absence). The planted-head attack this batch closes:
// sth.json lives in the log directory, so a log-writer can plant ANY
// self-consistent head it likes; savePtlHead used to reason from it as its
// trust baseline without ever checking WHO signed it — the operator's next
// honest append minted a fresh, genuinely-signed head over the attacker's
// chosen history.
// ---------------------------------------------------------------------------

test('X-H-10: a planted head whose signature does not verify is refused — the operator never launders it', async () => {
  const fs = MemoryFs.of({})
  const honest = variedLeaves(3)
  for (const e of honest) await appendPtlEntry(fs, DIR, e)
  // The attacker rewrites the entries AND plants a head over the rewrite:
  // self-consistent root/size, garbage signature.
  const planted = variedLeaves(4)
  fs.mutate(ENTRIES_PATH, `${planted.map(e => canonicalJson(e)).join('\n')}\n`)
  const plantedLog = new TransparencyLog(planted)
  const plantedHead: SignedTreeHead = {
    logId: 'log-operator',
    treeSize: plantedLog.size,
    root: plantedLog.merkleRoot(),
    at: '2026-10-06T01:00:00.000Z',
    sig: 'GARBAGE-BASE64-PLANTED',
  }
  fs.mutate(HEAD_PATH, canonicalJson(plantedHead))

  // The honest operator's next head over the (attacker-controlled) disk
  // state: consistency with the planted head would "prove" fine — it was
  // minted from the same planted bytes — but the signature gate refuses.
  const grown = (await loadPtl(fs, DIR)).log
  const next = await mintSth(grown, '2026-10-06T02:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, next, { verifyExistingHead: holdsUnderDefaultOperator }),
    /stored tree head's signature does not verify/,
    'the planted baseline is refused before any consistency math launders it',
  )
  // The planted head is untouched — the refusal wrote nothing.
  assert.equal((await loadPtl(fs, DIR)).sth!.sig, 'GARBAGE-BASE64-PLANTED')
})

test('X-H-10 fail-closed: no verifier callback and a throwing verifier are both refusals, never passes', async () => {
  const fs = MemoryFs.of({})
  const leaves = variedLeaves(2)
  for (const e of leaves) await appendPtlEntry(fs, DIR, e)
  const sth = await mintSth(new TransparencyLog(leaves), '2026-10-06T01:00:00.000Z')
  await savePtlHead(fs, DIR, sth) // cold start: no callback needed

  const advance = await mintSth(new TransparencyLog([...leaves, entry(9)]), '2026-10-06T02:00:00.000Z')
  // No callback at all: "cannot verify" is a refusal (uncertain = fail), not
  // the old silent pass over an unchecked baseline.
  await assert.rejects(
    () => savePtlHead(fs, DIR, advance),
    /without verifying the stored head's signature.*uncertain = fail/s,
  )
  // A callback that throws (locked key material, transient I/O): refusal,
  // with the underlying reason carried through.
  await assert.rejects(
    () => savePtlHead(fs, DIR, advance, {
      verifyExistingHead: async () => { throw new Error('key directory locked by a scanner') },
    }),
    /key directory locked by a scanner/,
  )
  assert.equal((await loadPtl(fs, DIR)).sth!.treeSize, 2, 'nothing was clobbered')
})

test('X-H-10 boundary: a stored head over ZERO entries is an adjudicated refusal, never a producer-side RangeError', async () => {
  const fs = MemoryFs.of({})
  const leaves = variedLeaves(2)
  for (const e of leaves) await appendPtlEntry(fs, DIR, e)
  // A planted size-0 head — even one carrying a GENUINE operator signature
  // (the worst case: it passes the signature gate and then used to drive
  // consistencyProof(0, N) outside the RFC domain as a RangeError).
  const emptySth = await mintSth(new TransparencyLog([]), '2026-10-06T01:00:00.000Z')
  assert.equal(emptySth.treeSize, 0, 'fixture: the empty-tree head')
  fs.mutate(HEAD_PATH, canonicalJson(emptySth))
  const advance = await mintSth(new TransparencyLog(leaves), '2026-10-06T02:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, advance, { verifyExistingHead: holdsUnderDefaultOperator }),
    /refusing to extend a stored head over 0 entries/,
    'adjudicated as a refusal, not surfaced as RangeError: 0->2 outside the log',
  )
})

test('W9-M8: an entries file that exists but cannot be read refuses the append — the log is never rewritten to one line', async () => {
  // FsPort.readFile folds "absent" and "read failed" into the same
  // `undefined`. The old append turned a failed read (EBUSY/EPERM/AV lock)
  // into `${''}${line}` — the whole history replaced by the new line.
  class UnreadableEntries extends MemoryFs {
    override async readFile(path: string): Promise<string | undefined> {
      if (path === ENTRIES_PATH) return undefined // the read fails...
      return super.readFile(path) // ...while stat (inherited) still sees the file
    }
  }
  const fs = new UnreadableEntries()
  const e0 = entry(0)
  fs.files.set(ENTRIES_PATH, `${canonicalJson(e0)}\n`)
  await assert.rejects(
    () => appendPtlEntry(fs, DIR, entry(1)),
    /exists but could not be read.*never masquerade as an empty log/s,
    'a read failure must refuse, not rewrite from an empty snapshot',
  )
  assert.equal(fs.files.get(ENTRIES_PATH), `${canonicalJson(e0)}\n`, 'the history is untouched')
})

test('W9-M8: an sth.json that exists but cannot be read is not a cold start', async () => {
  class UnreadableHead extends MemoryFs {
    override async readFile(path: string): Promise<string | undefined> {
      if (path === HEAD_PATH) return undefined
      return super.readFile(path)
    }
  }
  const fs = new UnreadableHead()
  fs.files.set(HEAD_PATH, canonicalJson(await mintSth(new TransparencyLog(variedLeaves(2)), '2026-10-06T01:00:00.000Z')))
  for (const e of variedLeaves(2)) await appendPtlEntry(fs, DIR, e)
  const advance = await mintSth((await loadPtl(fs, DIR)).log, '2026-10-06T02:00:00.000Z')
  await assert.rejects(
    () => savePtlHead(fs, DIR, advance, { verifyExistingHead: holdsUnderDefaultOperator }),
    /exists but could not be read.*unknown prior commitment/s,
    'an unreadable prior commitment must not be signed over as if there were none',
  )
})
