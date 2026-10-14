/** Apply config (rule overrides, trusted owners, allowlist, ignore globs) to raw findings. */
export function applyConfig(raw: any, config?: {}, now?: number): {
    findings: any[];
    suppressed: any[];
};
export function scan({ cwd, paths, config: override, configPath, now }?: {
    cwd?: string;
    config?: {};
}): {
    files: any[];
    config: {
        failOn: string;
        trustedOwners: any[];
        rules: {};
        allow: any[];
        ignore: any[];
    };
    findings: any[];
    suppressed: any[];
};
export { validateWorkflowSchema } from "./schema.js";
export { scanText, findFiles } from "./scan.js";
export { RULES, SEVERITIES, UNTRUSTED } from "./rules.js";
export { validateExpression, extractExpressions } from "./expressions.js";
export { loadConfig, isAllowed } from "./config.js";
export { formatText, formatJson, formatSarif, formatMarkdown, exitCode } from "./format.js";
export { fixFiles, resolveSha, pinText } from "./fix.js";
