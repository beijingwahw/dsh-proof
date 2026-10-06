/**
 * The `proof:policy` system-prompt section.
 *
 * Prompt text is deliberately short and imperative. The enforcement lives in
 * the tool pipeline; this section only tells the model the rules exist so it
 * does not have to discover them by failing.
 *
 * @module dsh-proof/dsh/prompt
 */
import type { CheckSpec } from '../core/ports.ts';
export interface PromptFacts {
    readonly discovered: readonly CheckSpec[];
    readonly hasBaseline: boolean;
    readonly requireBaseline: 'off' | 'warn' | 'ask';
}
export declare function buildPolicySection(facts: PromptFacts): string;
//# sourceMappingURL=prompt.d.ts.map