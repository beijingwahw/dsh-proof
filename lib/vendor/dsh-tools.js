/**
 * Contract snapshot of `@deepseek-ai/dsh-tools`, pinned to **dsh v0.2.1-alpha.1**.
 *
 * Why a snapshot instead of a live dependency:
 *
 * 1. DSH is a developer preview and publishes breaking contract changes between
 *    releases ("一定会有破坏兼容性的变更" — DeepSeek's own warning). A plugin
 *    that compiles against whatever is newest today silently breaks tomorrow.
 * 2. At runtime the real `@deepseek-ai/dsh-tools` resolves from the user's dsh
 *    installation (it is a `peerDependency`), so this file contributes **types
 *    only** — no shipped runtime code, no duplicate registry.
 * 3. It keeps `npm run typecheck` and `npm test` runnable offline.
 *
 * Regenerate against upstream when bumping the pin:
 *   packages/core/tools/src/index.ts   (ToolDefinition, pipeline events)
 *   packages/core/tools/src/schema.ts  (defineTool, schema DSL)
 *   packages/llm/llm/src/types.ts      (ContentBlock, UserMessage)
 *
 * @module dsh-proof/vendor/dsh-tools
 */
export {};
//# sourceMappingURL=dsh-tools.js.map