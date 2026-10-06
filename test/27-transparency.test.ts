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
  const sthA = await mintSth(new TransparencyLog(shared.slice(0, 3)), '2026-10-06T01:00:00.000Z')
  await savePtlHead(fs, DIR, sthA)
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthA)
  // Same head again: allowed (idempotent re-assertion).
  await savePtlHead(fs, DIR, sthA)
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthA)
  // Advance: bigger tree, later timestamp.
  const sthB = await mintSth(new TransparencyLog(shared), '2026-10-06T02:00:00.000Z')
  await savePtlHead(fs, DIR, sthB)
  assert.deepEqual((await loadPtl(fs, DIR)).sth, sthB)
  assert.equal(
    verifyConsistency(sthA.treeSize, sthA.root, sthB.treeSize, sthB.root,
      new TransparencyLog(shared).consistencyProof(3, 5)),
    true,
    'the stored heads are mutually consistent',
  )
})

test('savePtlHead refuses every rewind: smaller tree, same tree different root, earlier timestamp', async () => {
  const fs = MemoryFs.of({})
  const at1 = '2026-10-06T02:00:00.000Z'
  await savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(9)), at1))

  // (1) truncated tree: treeSize goes backwards.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(7)), '2026-10-06T03:00:00.000Z')),
    /refusing to rewind the transparency head/,
  )
  // (2) rewritten tree: same size, different root.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(10).slice(0, 9)), '2026-10-06T03:00:00.000Z')),
    /refusing to rewind the transparency head/,
  )
  // (3) timestamp regression — even with a LARGER tree, `at` may not go back.
  await assert.rejects(
    async () => savePtlHead(fs, DIR, await mintSth(new TransparencyLog(variedLeaves(12)), '2026-10-06T01:00:00.000Z')),
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
  await assert.rejects(() => savePtlHead(fs, DIR, truncatedSth), /refusing to rewind the transparency head/)
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
