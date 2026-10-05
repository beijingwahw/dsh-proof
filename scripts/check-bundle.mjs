#!/usr/bin/env node
/**
 * Bundle manifest sanity check — catches the packaging mistakes that make
 * `dsh plugin add` silently install a plain dependency with no active layer.
 */
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const problems = []
const ok = (label) => console.log(`  ok  ${label}`)
const bad = (label, detail) => { problems.push(`${label}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ''}`) }

console.log('[check-bundle] dsh-proof')

const pkgPath = join(root, 'package.json')
if (!existsSync(pkgPath)) {
  bad('package.json exists')
  process.exit(1)
}
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))

// -- the bundle manifest ----------------------------------------------------
const patchRef = pkg.dsh?.bundle?.patch
if (!patchRef) {
  bad('dsh.bundle.patch', 'without it `dsh plugin add` installs a plain dependency and activates no layer')
} else {
  ok(`dsh.bundle.patch = ${patchRef}`)
}

// File-level checks only make sense when a patch path is declared:
// `join(root, '')` resolves to the repo root itself, and readFileSync on a
// directory would crash the script with EISDIR instead of reporting a problem.
if (!patchRef) {
  bad('patch file exists', 'no dsh.bundle.patch declared in package.json')
} else {
  const patchPath = join(root, patchRef)
  if (!existsSync(patchPath)) {
    bad('patch file exists', patchPath)
  } else {
    ok(`patch file present (${patchRef})`)
    const patch = readFileSync(patchPath, 'utf8')
    if (!/^\s*-\s*insert\s*:/m.test(patch)) bad('patch is an insert layer', 'expected a YAML array starting with `- insert:`')
    else ok('patch is an insert layer')
    // Escape regex metacharacters: a scoped name like @scope/pkg.name would
    // otherwise turn the dot into a wildcard (and worse).
    const namePattern = String(pkg.name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    if (!new RegExp(`name:\\s*['"]?${namePattern}['"]?`).test(patch)) {
      bad('patch rows reference the package by name', `expected name: ${pkg.name}`)
    } else {
      ok(`patch rows reference "${pkg.name}"`)
    }
    if (/(^|\n)\s*name:\s*['"]?\.?\//.test(patch)) {
      bad('patch uses package names, not relative paths', 'relative paths resolve against the profile and break installs')
    } else {
      ok('no relative module paths in the patch')
    }
  }
}

// -- entry points ----------------------------------------------------------
for (const [field, path] of [['main', pkg.main], ['types', pkg.types]]) {
  if (!path) { bad(`${field} declared`); continue }
  // Built output may not exist yet; the source that produces it must.
  const srcEquivalent = path.replace(/^lib\//, 'src/').replace(/\.js$/, '.ts').replace(/\.d\.ts$/, '.ts')
  if (existsSync(join(root, path))) ok(`${field} exists (${path})`)
  else if (existsSync(join(root, srcEquivalent))) ok(`${field} builds from ${srcEquivalent}`)
  else bad(`${field} resolvable`, path)
}

// -- install mechanics ------------------------------------------------------
if (!pkg.files?.includes('cordis.patch.yml')) bad('files includes cordis.patch.yml', 'npm pack would omit the layer')
else ok('files includes cordis.patch.yml')

if (!pkg.scripts?.prepare) {
  console.log('  note no `prepare` script — install from git will not build `lib/`')
} else {
  ok('prepare script present (git installs can build)')
}

const peers = Object.keys(pkg.peerDependencies ?? {})
for (const peer of ['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools']) {
  if (!peers.includes(peer)) bad(`peerDependency ${peer}`, 'runtime types resolve from the dsh installation')
  else ok(`peerDependency ${peer}`)
}

if (!pkg.engines?.node) bad('engines.node declared', "DSH requires ^22.19.0 || >=24.0.0")
else ok(`engines.node = ${pkg.engines.node}`)

console.log(problems.length === 0 ? '\n[check-bundle] PASS' : `\n[check-bundle] ${problems.length} problem(s)`)
process.exit(problems.length === 0 ? 0 : 1)
