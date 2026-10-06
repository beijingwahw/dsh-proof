/**
 * Structural snapshot of the OpenCode plugin context — the minimal surface
 * this adapter consumes, narrowed from `unknown` at every boundary.
 *
 * Why a snapshot instead of a dependency: OpenCode publishes no type package
 * for plugins and its plugin API is explicitly still evolving (the project
 * itself warns about breaking changes between releases). Same discipline as
 * `src/vendor/dsh-tools.ts` (the DSH contract snapshot), one notch more
 * defensive:
 *
 *   - DSH snapshot pins a version and types the *whole* consumed contract.
 *   - This snapshot types only the minimal shapes we hook, marks every field
 *     optional, and treats registration call signatures as guesses. Everything
 *     is re-verified with `typeof`/shape checks at RUNTIME by plugin.ts; a
 *     surface that does not match degrades to a no-op with one stderr line,
 *     never an exception in the host.
 *
 * Nothing here pretends to be a complete OpenCode API: it is the list of
 * things dsh-proof's adapter calls, and the runtime duck-typing in plugin.ts
 * is the actual authority. If OpenCode renames a field, the adapter goes idle
 * and says so on stderr — the MCP tools (the thirteen frozen APP/1.4 names,
 * `MCP_TOOLS` in src/app/mcp-server.ts) keep working regardless, because
 * they ride the MCP server, not this plugin surface.
 *
 * @module dsh-proof/adapters/opencode/vendor
 */
// ---------------------------------------------------------------------------
// Runtime narrowers — the only authority on what "a compatible OpenCode
// context" means. Failure is always `undefined`, never a throw.
// ---------------------------------------------------------------------------
/**
 * Safe object check for the plugin context. Accepts any non-null, non-array
 * object (functions are rejected too — a context is a record, not a callable).
 */
export function asPluginContext(value) {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        return undefined;
    return value;
}
/** A registrar seam exists only when the slot holds a function. */
export function asBefore(reg) {
    return typeof reg === 'function' ? reg : undefined;
}
/** A registrar seam exists only when the slot holds a function. */
export function asAfter(reg) {
    return typeof reg === 'function' ? reg : undefined;
}
/**
 * The workspace directory the adapter should verify: `ctx.project.directory`
 * when it is a non-empty string, else `ctx.directory`, else `undefined`
 * (the caller falls back to `process.cwd()`). Only non-empty strings are
 * accepted — anything else is "not present", not "present but weird".
 */
export function directoryOf(ctx) {
    const project = ctx.project;
    if (typeof project === 'object' && project !== null) {
        const directory = project.directory;
        if (typeof directory === 'string' && directory.length > 0)
            return directory;
    }
    const fallback = ctx.directory;
    if (typeof fallback === 'string' && fallback.length > 0)
        return fallback;
    return undefined;
}
//# sourceMappingURL=vendor.js.map