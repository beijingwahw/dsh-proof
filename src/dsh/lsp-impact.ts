/**
 * LSP-backed impact resolution: turns the host's language servers into a
 * precise, alias-aware DefinitionResolverPort for the dependency graph.
 *
 * The trick that makes the closed four-operation LSP surface sufficient:
 * goToDefinition placed *on the module specifier of an import statement*
 * resolves to the file that specifier binds to — including tsconfig `paths`
 * aliases and package-internal imports that regex extraction cannot see.
 *
 * Cost control: every result is cached per (file, content version, position),
 * and a hard query budget degrades the remainder to the approximate graph.
 *
 * @module dsh-proof/dsh/lsp-impact
 */

import type { DefinitionResolverPort, FsPort } from '../core/ports.ts'
import type { LspLike, LspLocation } from '../vendor/dsh-tools.ts'

export interface LspResolverOptions {
  /** Maximum language-server round-trips (per resolver instance). */
  readonly budget?: number
}

/** Build a caching, budgeted resolver over the host's LSP seam, if present. */
export function createLspResolver(
  lsp: LspLike | undefined,
  root: string,
  fs: FsPort,
  options: LspResolverOptions = {},
): DefinitionResolverPort | undefined {
  if (lsp === undefined) return undefined
  return new CachingLspResolver(lsp, root, fs, options.budget ?? 400)
}

class CachingLspResolver implements DefinitionResolverPort {
  private readonly entries = new Map<string, { version: string; results: Map<string, string | null> }>()
  private queries = 0
  private readonly lsp: LspLike
  private readonly root: string
  private readonly fs: FsPort
  private readonly budget: number

  constructor(lsp: LspLike, root: string, fs: FsPort, budget: number) {
    this.lsp = lsp
    this.root = root
    this.fs = fs
    this.budget = budget
  }

  async resolveDefinition(file: string, line: number, character: number): Promise<string | null> {
    if (this.queries >= this.budget) return null
    const stat = await this.fs.stat(`${this.root}/${file}`).catch(() => undefined)
    const version = stat === undefined ? 'none' : `${stat.mtimeMs}:${stat.size}`
    let entry = this.entries.get(file)
    if (entry === undefined || entry.version !== version) {
      entry = { version, results: new Map() }
      this.entries.set(file, entry)
    }
    const positionKey = `${line}:${character}`
    const cached = entry.results.get(positionKey)
    if (cached !== undefined) return cached

    this.queries += 1
    const result = await this.lsp
      .query('goToDefinition', { file: `${this.root}/${file}`.replace(/\\/g, '/'), line, character })
      .catch(() => null)
    const target = result !== null && result.kind === 'locations'
      ? firstWorkspaceRelative(result.locations, this.root)
      : null
    entry.results.set(positionKey, target)
    return target
  }
}

function firstWorkspaceRelative(locations: readonly LspLocation[], root: string): string | null {
  for (const location of locations) {
    const rel = uriToRelative(location.uri, root)
    if (rel !== null) return rel
  }
  return null
}

/** Convert a `file://` URI to a workspace-relative path, or null when outside. */
export function uriToRelative(uri: string, root: string): string | null {
  if (!uri.startsWith('file:')) return null
  let path: string
  if (uri.startsWith('file:///')) {
    path = `/${decodeURIComponentSafe(uri.slice('file:///'.length))}`
  } else if (uri.startsWith('file://')) {
    path = decodeURIComponentSafe(uri.slice('file://'.length))
  } else {
    return null
  }
  // Windows drive letters arrive as file:///C:/... — normalize /C:/ back to C:/.
  if (/^\/[A-Za-z]:\//.test(path)) path = path.slice(1)
  path = path.replace(/\\/g, '/')
  const normalizedRoot = root.replace(/\\/g, '/').replace(/\/+$/, '')
  if (!path.startsWith(`${normalizedRoot}/`)) return null
  return path.slice(normalizedRoot.length + 1)
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
