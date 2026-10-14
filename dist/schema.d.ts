export function validateWorkflowSchema(root: any, { isAction }?: {
    isAction?: boolean;
}): any[];
/** Flag unusual `with:` keys for well-known actions (typos in input names). */
export function validateActionInputs(uses: any, withNode: any): any[];
