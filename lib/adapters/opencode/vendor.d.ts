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
/**
 * A callable that registers a `tool.execute.before` handler.
 *
 * OpenCode's before hook hands the plugin `(input, output)` and lets the
 * handler intercept the call; the interception RETURN shape is not stable
 * across releases, so plugin.ts returns `{ error: { message } }` (the most
 * commonly documented form) and additionally explains itself on stderr.
 * Whether the registrar returns an unregister function is unknown — treated
 * as opaque and inspected with `typeof` by the caller.
 */
export interface OpencodeToolExecuteBefore {
    (handler: (input: unknown, output: unknown) => unknown | Promise<unknown>): unknown;
}
/** A callable that registers a `tool.execute.after` handler (post-observation). */
export interface OpencodeToolExecuteAfter {
    (handler: (input: unknown, output: unknown) => unknown | Promise<unknown>): unknown;
}
/**
 * The OpenCode plugin context as this adapter consumes it.
 *
 * `chat.params` is the system-prompt seam (when present, a handler registered
 * through it may append to the assembled chat parameters, which is where the
 * policy section gets injected). `event` is reserved for a future turn-end
 * hook — OpenCode exposes no Stop-hook equivalent today, so v1 deliberately
 * registers nothing on it (see plugin.ts's drift-anchor note).
 */
export interface OpencodePluginContextLike {
    tool?: {
        execute?: {
            before?: unknown;
            after?: unknown;
        };
    };
    chat?: {
        params?: unknown;
    };
    event?: unknown;
    project?: {
        directory?: unknown;
    };
    directory?: unknown;
    [k: string]: unknown;
}
/**
 * Safe object check for the plugin context. Accepts any non-null, non-array
 * object (functions are rejected too — a context is a record, not a callable).
 */
export declare function asPluginContext(value: unknown): OpencodePluginContextLike | undefined;
/** A registrar seam exists only when the slot holds a function. */
export declare function asBefore(reg: unknown): OpencodeToolExecuteBefore | undefined;
/** A registrar seam exists only when the slot holds a function. */
export declare function asAfter(reg: unknown): OpencodeToolExecuteAfter | undefined;
/**
 * The workspace directory the adapter should verify: `ctx.project.directory`
 * when it is a non-empty string, else `ctx.directory`, else `undefined`
 * (the caller falls back to `process.cwd()`). Only non-empty strings are
 * accepted — anything else is "not present", not "present but weird".
 */
export declare function directoryOf(ctx: OpencodePluginContextLike): string | undefined;
//# sourceMappingURL=vendor.d.ts.map