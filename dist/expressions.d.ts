export function extractExpressions(text: any): any[];
/** Return list of validation issues: { kind, message, detail? } */
export function validateExpression(expr: any, { triggers }?: {
    triggers?: any[];
}): {
    kind: string;
    message: string;
}[];
/** True if expression text matches any UNTRUSTED pattern or contains github.event / head_ref style inputs. */
export function isUntrustedExpression(expr: any, untrustedRes: any): boolean;
/** Collect env var names assigned from untrusted expressions in a scalar/map node (JSON-ish). */
export function taintFromEnvBlock(envJs: any, untrustedRes: any): Set<any>;
/** Whether a string references a tainted env var inside ${{ env.NAME }} or plain $NAME in scripts. */
export function referencesTaintedEnv(text: any, tainted: any): boolean;
/** Roots allowed at the start of a property access chain in an expression. */
export const EXPR_ROOTS: Set<string>;
export namespace EVENT_FIELDS {
    export let push: string[];
    export let pull_request: string[];
    export let pull_request_target: string[];
    export let issues: string[];
    export let issue_comment: string[];
    export let workflow_dispatch: string[];
    export let workflow_call: string[];
    export let workflow_run: string[];
    export let release: string[];
    export let schedule: any[];
    export let repository_dispatch: string[];
    export let push_tag: any[];
    export let create: string[];
    let _delete: string[];
    export { _delete as delete };
    export let fork: string[];
    export let watch: string[];
    export let discussion: string[];
    export let discussion_comment: string[];
    export let pull_request_review: string[];
    export let pull_request_review_comment: string[];
    export let check_run: string[];
    export let check_suite: string[];
    export let registry_package: string[];
    export let page_build: string[];
    let _public: string[];
    export { _public as public };
    export let status: string[];
}
