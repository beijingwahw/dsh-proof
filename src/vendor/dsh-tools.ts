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

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/** The only content block this plugin produces. */
export interface TextBlock {
  type: 'text'
  text: string
  [key: string]: unknown
}

/**
 * DSH content blocks are merge-extensible (`ContentBlockMap`). Structural
 * widening keeps this snapshot forward-compatible with new block kinds.
 */
export type ContentBlock = TextBlock | { type: string; [key: string]: unknown }

export interface UserMessage {
  readonly role: 'user'
  readonly content: readonly ContentBlock[]
  readonly source?: unknown
  readonly [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Tool execution identity
// ---------------------------------------------------------------------------

export type ToolExecutionToken = symbol

export interface ToolExecution {
  readonly callId: string
  readonly rootCallId: string
  readonly name: string
  readonly arguments: unknown
  readonly agent?: unknown
  readonly token: ToolExecutionToken
  readonly signal: AbortSignal
}

export interface ToolRunContext extends ToolExecution {
  /** Attach durable context the NEXT model request sees. */
  deferContext(context: UserMessage): void
  /** Mark a successful final result as terminal for the current agent turn. */
  concludeTurn(): void
}

export interface ToolErrorInfo {
  name: string
  code: string
  reason?: string
}

export interface ToolFailure {
  message: string
  info?: ToolErrorInfo
}

export interface ToolExecutionSuccess {
  readonly isError: false
  readonly value: unknown
  readonly content: readonly ContentBlock[]
  readonly error?: never
  readonly meta?: unknown
  readonly additionalContexts?: readonly UserMessage[]
  readonly concludesTurn?: true
}

export interface ToolExecutionFailure {
  readonly isError: true
  readonly error: ToolFailure
  readonly value?: never
  readonly content: readonly ContentBlock[]
  readonly meta?: unknown
  readonly additionalContexts?: readonly UserMessage[]
  readonly concludesTurn?: never
}

export type ToolExecutionResult = ToolExecutionSuccess | ToolExecutionFailure

/** The completed outcome handed to `ToolDefinition.presentResult`. */
export interface ToolResult {
  content: readonly ContentBlock[]
  isError: boolean
  meta?: unknown
}

// ---------------------------------------------------------------------------
// Policy decisions
// ---------------------------------------------------------------------------

export type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; info?: ToolErrorInfo }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string; displayReason?: { readonly en: string; readonly [locale: string]: string } }

export type PostToolDecision =
  | { kind: 'accept'; content?: readonly ContentBlock[]; value?: never; additionalContexts?: readonly UserMessage[] }
  | { kind: 'accept'; value: unknown; content?: never; additionalContexts?: readonly UserMessage[] }
  | { kind: 'block'; feedback: readonly ContentBlock[]; additionalContexts?: readonly UserMessage[] }

export type ToolGuard = (execution: Readonly<ToolExecution>) => string | undefined

// ---------------------------------------------------------------------------
// Presentation (UI cards) — pure projections, replay-safe
// ---------------------------------------------------------------------------

export interface FileLocation {
  path: string
  line?: number
}

export type ToolCallView =
  | { card: 'generic'; title: string; kind?: string; rawInput?: unknown; content?: readonly ContentBlock[]; locations?: readonly FileLocation[] }
  | { card: 'terminal'; title: string; description?: string; cwd?: string }
  | { card: 'diff'; title: string; diffs: readonly { path: string; oldText: string | null; newText: string }[]; locations?: readonly FileLocation[] }

export type ToolResultView =
  | { card: 'generic'; title?: string; content?: readonly ContentBlock[]; locations?: readonly FileLocation[] }
  | { card: 'terminal'; output: string; exitCode?: number | null; locations?: readonly FileLocation[] }
  | { card: 'diff'; diffs: readonly { path: string; oldText: string | null; newText: string }[]; locations?: readonly FileLocation[] }

// ---------------------------------------------------------------------------
// Schema DSL (JSON-Schema subset used on the wire)
// ---------------------------------------------------------------------------

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export interface JsonSchemaNode {
  type?: string | string[]
  description?: string
  properties?: Record<string, JsonSchemaNode>
  required?: string[]
  items?: JsonSchemaNode
  additionalProperties?: boolean
  enum?: readonly (string | number | boolean | null)[]
  anyOf?: readonly JsonSchemaNode[]
  default?: unknown
  [key: string]: unknown
}

export interface ParameterField {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'null' | 'array' | 'object' | 'json' | 'oneOf'
  required?: boolean
  description?: string
  items?: ParameterField | ParameterField[]
  properties?: Record<string, ParameterField>
  additionalProperties?: boolean
  enum?: readonly (string | number | boolean | null)[]
  default?: unknown
  [key: string]: unknown
}

export type ParameterSchemaSpec = Record<string, ParameterField>

export interface ToolOutputDefinition {
  readonly schema: JsonSchemaNode
  readonly render: (args: unknown, value: unknown) => ContentBlock[]
  readonly presentationMeta?: (args: unknown, value: unknown) => JsonValue
}

export interface ToolDefinition {
  readonly name: string
  readonly description: string
  readonly parameters: Record<string, unknown>
  readonly output: ToolOutputDefinition
  execute(args: unknown, exec: ToolRunContext): Promise<unknown>
  projectContent?(exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): ContentBlock[] | undefined
  finalizeContent?(exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): ContentBlock[] | undefined
  timeoutMs?: number
  isConcurrencySafe?(args: unknown): boolean
  presentCall?(args: unknown): ToolCallView | undefined
  presentResult?(args: unknown, result: ToolResult): ToolResultView | undefined
}

// ---------------------------------------------------------------------------
// The registry service
// ---------------------------------------------------------------------------

export interface ToolRuntimeLike {
  register(definition: ToolDefinition): unknown
  guard(guard: ToolGuard): unknown
  restrict(filter: unknown): unknown
  get(name: string, scope?: unknown): ToolDefinition | undefined
  schemas(scope?: unknown): readonly Record<string, unknown>[]
}

// ---------------------------------------------------------------------------
// Event surface consumed by this plugin
// ---------------------------------------------------------------------------

export interface DshEvents {
  'tools/pre-execute': (exec: ToolExecution, next: () => Promise<PreToolDecision>) => Promise<PreToolDecision>
  'tools/post-execute': (exec: ToolExecution, result: Readonly<ToolExecutionResult>, next: () => Promise<PostToolDecision>) => Promise<PostToolDecision>
  'tools/result': (exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>) => void
}

// ---------------------------------------------------------------------------
// LSP seam (ctx.lsp) — closed four-operation surface, positions 0-based UTF-16
// ---------------------------------------------------------------------------

export interface LspQueryArgs {
  readonly file: string
  readonly line: number
  readonly character: number
}

export interface LspLocation {
  readonly uri: string
  readonly range: unknown
}

export type LspQueryResult =
  | { readonly kind: 'locations'; readonly locations: readonly LspLocation[]; readonly resolvedWorkspaceUri?: unknown }
  | { readonly kind: 'hover'; readonly hover: unknown }

export interface LspLike {
  query(
    operation: 'goToDefinition' | 'findReferences' | 'goToImplementation' | 'hover',
    args: LspQueryArgs,
    signal?: AbortSignal,
  ): Promise<LspQueryResult>
}
