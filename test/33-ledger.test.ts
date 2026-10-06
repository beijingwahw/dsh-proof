/**
 * LEDGER-CONTRACT TESTS (v0.26.1) — 让终局账本本身获得契约保护。
 *
 * MISSION. Seven audit rounds produced FINDINGS-LEDGER.md (the consolidated
 * verdict for every finding) and residuals.json (the machine-readable
 * registry of everything deliberately left open). A ledger nobody checks is
 * itself an unfulfilled claim — the exact disease test/32 was built for.
 * This file pins the ledger's four contracts:
 *
 *   (a) FORMAT — every ledger row has exactly four columns; every status is
 *       one of the four declared values; every CLOSED / CLOSED-WITH-NOTES
 *       row cites a test file that EXISTS and a 「keyword」 that really
 *       appears in that file (the "closed means pinned" rule — an unpinned
 *       closure must be registered as RESIDUAL-DOCUMENTED instead, see
 *       U3-F2/U3-F6 for the precedent).
 *   (b) REGISTRY — every residuals.json entry carries non-empty id / title /
 *       boundary / backstop / evidence, ids are unique, and every id is
 *       referenced by the ledger (the two documents cannot drift apart).
 *   (c) DOC SYNC — README.md's "Honest limits" section must contain every
 *       keyword of every residual's title: a residual that is documented
 *       nowhere a reader looks is a residual nobody knows they have.
 *   (d) NO-SHRINKAGE — the count of H-level rows marked CLOSED or
 *       CLOSED-WITH-NOTES must stay >= the sum of the H-closure numbers the
 *       fix commits claimed: fdd06db "closes all 34 highs" + its 8 red-team
 *       holes (= 42), 15a42bc "closes 19 more highs" (= 19), 86f4778
 *       "closes all 17" (= 17) — 78 in total. If a finding is ever demoted
 *       from the closed family to RESIDUAL/SUPERSEDED without the commit
 *       record being revisited, this goes red.
 *
 * KEYWORD RULES (stability notes — do not loosen casually):
 *   - Evidence keywords are the strings inside 「…」 immediately after a
 *     test/NN-name.test.ts path. The FIRST path and the FIRST keyword of a
 *     row are checked as a pair, so multi-pin evidence cells must put the
 *     first keyword in the first cited file (the ledger follows this order
 *     by construction).
 *   - Residual-title keywords are the title's alphanumeric tokens of length
 *     >= 5, lowercased, matched as substrings of the Honest limits section.
 *     Tokens shorter than 5 (and pure version numbers like "v0") are noise
 *     and skipped; substring (not whole-word) matching keeps the rule stable
 *     against plural/inflection drift while remaining strict (EVERY keyword
 *     must appear).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ledgerPath = join(repoRoot, 'FINDINGS-LEDGER.md')
const residualsPath = join(repoRoot, 'residuals.json')
const readmePath = join(repoRoot, 'README.md')

const STATUSES = new Set(['CLOSED', 'CLOSED-WITH-NOTES', 'RESIDUAL-DOCUMENTED', 'SUPERSEDED'])
const CLOSED_FAMILY = new Set(['CLOSED', 'CLOSED-WITH-NOTES'])

/**
 * H-level row IDs, per the original audit numbering systems:
 *   v0.13 baseline "H1".."H12" (splits "H5a/H5b", "H9a/H9b/H9c");
 *   round-1 "H-01".."H-34"; red-team "N-1".."N-8";
 *   X round "X-H-01".."X-H-19"; Y round "Y-H-01".."Y-H-17";
 *   U round H-level adjudications: U1-F1, U2-F1, U2-F2, U4-H1..U4-H4
 *     (levels per the U1-U4 reports; U1-F2..F5, U2-F3/F4, U3-F1/F2 and the
 *     U4-M/L ids are M/L rows in the ledger).
 */
const H_ID = /^(?:H\d{1,2}[abc]?|H-\d{2}|N-\d|X-H-\d{2}|Y-H-\d{2}|U1-F1|U2-F[12]|U4-H\d)$/

/** Commit-claimed H closures (see header note (d)). */
const COMMIT_CLAIMED_H_CLOSURES = 42 + 19 + 17 // fdd06db (+red team) / 15a42bc / 86f4778

interface LedgerRow {
  readonly id: string
  readonly title: string
  readonly status: string
  readonly evidence: string
  readonly isH: boolean
  readonly line: number
  readonly columns: number
}

function parseLedger (text: string): LedgerRow[] {
  // A ledger table is one whose header row is `| ID | …标题… | …状态… | …证据… |`
  // (the stats table at the bottom uses a different header and is not a
  // findings table — its rows are summaries, not per-finding verdicts).
  const rows: LedgerRow[] = []
  const lines = text.split('\n')
  let inLedgerTable = false
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? ''
    if (!raw.startsWith('|')) { inLedgerTable = false; continue }
    const cells = raw.split('|').slice(1, -1).map(c => c.trim())
    if (cells.length === 0) continue
    const first = cells[0] ?? ''
    if (first === 'ID') {
      inLedgerTable = cells.length === 4 && (cells[2] ?? '').includes('状态')
      continue
    }
    if (/^[-: ]+$/.test(first)) continue
    if (!inLedgerTable) continue
    rows.push({
      id: first,
      title: cells[1] ?? '',
      status: cells[2] ?? '',
      evidence: cells[3] ?? '',
      isH: H_ID.test(first),
      line: i + 1,
      columns: cells.length,
    })
  }
  return rows
}

const ledgerText = readFileSync(ledgerPath, 'utf8')
const rows = parseLedger(ledgerText)
const residuals: Array<{ id: string, title: string, boundary: string, backstop: string, evidence: string }> =
  JSON.parse(readFileSync(residualsPath, 'utf8'))
const readmeText = readFileSync(readmePath, 'utf8')

function honestLimitsSection (readme: string): string {
  const start = readme.indexOf('## Honest limits')
  assert.ok(start >= 0, 'README.md must keep its "## Honest limits" section')
  const next = readme.indexOf('\n## ', start + 1)
  return readme.slice(start, next === -1 ? undefined : next).toLowerCase()
}

const section = honestLimitsSection(readmeText)

function titleKeywords (title: string): string[] {
  return title
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(t => t.length >= 5 && !/^\d+$/.test(t))
}

/** First test-file path + first 「keyword」 of an evidence cell, as a pair. */
function firstPin (evidence: string): { file: string | undefined, keyword: string | undefined } {
  const file = /test\/\d{2}-[a-z-]+\.test\.ts/.exec(evidence)?.[0]
  const keyword = /「([^」]+)」/.exec(evidence)?.[1]
  return { file, keyword }
}

// ---------------------------------------------------------------------------
// (a) format contract
// ---------------------------------------------------------------------------

test('ledger (a): every data row has exactly four columns and a declared status', () => {
  assert.ok(rows.length >= 100, `expected >= 100 ledger rows, parsed ${rows.length}`)
  for (const row of rows) {
    assert.equal(row.columns, 4, `line ${row.line} ("${row.id}"): ledger rows must have exactly four columns, found ${row.columns}`)
    assert.ok(STATUSES.has(row.status), `line ${row.line} ("${row.id}"): status "${row.status}" not in the four-value set`)
    assert.ok(row.title.length > 0 && row.evidence.length > 0, `line ${row.line} ("${row.id}"): title/evidence must be non-empty`)
  }
})

test('ledger (a): CLOSED-family rows cite an existing test file whose content carries the keyword', () => {
  for (const row of rows) {
    if (!CLOSED_FAMILY.has(row.status)) continue
    const { file, keyword } = firstPin(row.evidence)
    assert.ok(file !== undefined, `line ${row.line} ("${row.id}", ${row.status}): evidence must cite a test/NN-*.test.ts path`)
    assert.ok(keyword !== undefined, `line ${row.line} ("${row.id}", ${row.status}): evidence must carry a 「keyword」 pin`)
    const absolute = join(repoRoot, file as string)
    assert.ok(existsSync(absolute), `line ${row.line} ("${row.id}"): cited test file ${file} does not exist`)
    const content = readFileSync(absolute, 'utf8')
    assert.ok(
      (content as string).includes(keyword as string),
      `line ${row.line} ("${row.id}"): keyword "${keyword}" not found in ${file} — the pin must be real`,
    )
  }
})

test('ledger (a): H-level rows are individually tracked (one row per finding id)', () => {
  const hIds = rows.filter(r => r.isH).map(r => r.id)
  assert.equal(new Set(hIds).size, hIds.length, 'H-level ids must be unique (no merged H rows)')
  // The five H families the audits enumerated, fully present:
  for (const id of ['H1', 'H12', 'H-01', 'H-34', 'N-1', 'N-8', 'X-H-01', 'X-H-19', 'Y-H-01', 'Y-H-17', 'U1-F1', 'U4-H4']) {
    assert.ok(hIds.includes(id), `H-level row ${id} missing from the ledger`)
  }
})

// ---------------------------------------------------------------------------
// (b) registry contract
// ---------------------------------------------------------------------------

test('registry (b): every residual entry is complete, unique, and referenced by the ledger', () => {
  assert.ok(Array.isArray(residuals) && residuals.length > 0, 'residuals.json must be a non-empty array')
  const seen = new Set<string>()
  for (const entry of residuals) {
    for (const field of ['id', 'title', 'boundary', 'backstop', 'evidence'] as const) {
      assert.ok(typeof entry[field] === 'string' && (entry[field] as string).trim().length > 0,
        `residual ${entry.id ?? '<unknown>'}: field "${field}" must be a non-empty string`)
    }
    assert.ok(!seen.has(entry.id), `residual ${entry.id}: duplicate id`)
    seen.add(entry.id)
    assert.ok(ledgerText.includes(entry.id), `residual ${entry.id}: not referenced anywhere in FINDINGS-LEDGER.md`)
  }
})

test('registry (b): every H-level RESIDUAL-DOCUMENTED row is registered in residuals.json', () => {
  const registered = new Set(residuals.map(e => e.id))
  for (const row of rows) {
    if (!row.isH || row.status !== 'RESIDUAL-DOCUMENTED') continue
    assert.ok(registered.has(row.id),
      `H-level row ${row.id} is RESIDUAL-DOCUMENTED but residuals.json has no entry for it`)
  }
})

// ---------------------------------------------------------------------------
// (c) README doc-sync contract
// ---------------------------------------------------------------------------

test('doc-sync (c): the Honest limits section covers every residual title\'s keywords', () => {
  assert.ok(section.length > 2000, 'the Honest limits section looks implausibly short')
  for (const entry of residuals) {
    const keywords = titleKeywords(entry.title)
    assert.ok(keywords.length >= 2, `residual ${entry.id}: title should carry at least two substantive keywords`)
    const missing = keywords.filter(k => !section.includes(k))
    assert.deepEqual(missing, [],
      `residual ${entry.id}: README "Honest limits" does not cover keyword(s) [${missing.join(', ')}] ` +
      `— sync the doc (add the boundary entry) or retitle the residual honestly`)
  }
})

// ---------------------------------------------------------------------------
// (d) no-shrinkage statistics contract
// ---------------------------------------------------------------------------

test('statistics (d): H-level closed-family count >= the fix commits\' claimed closures combined', () => {
  const closedFamily = rows.filter(r => r.isH && CLOSED_FAMILY.has(r.status))
  assert.ok(
    closedFamily.length >= COMMIT_CLAIMED_H_CLOSURES,
    `the ledger closes ${closedFamily.length} H-level rows (CLOSED + CLOSED-WITH-NOTES) — ` +
    `the fix commits claimed ${COMMIT_CLAIMED_H_CLOSURES} (fdd06db 34+8, 15a42bc 19, 86f4778 17). ` +
    'If findings were demoted, the commit record must be revisited first — the ledger does not shrink silently.',
  )
})
