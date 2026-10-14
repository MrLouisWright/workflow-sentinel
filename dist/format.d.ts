export function exitCode(result: any, failOn?: string): 1 | 0;
export function formatText(result: any, { color, failOn, fixes }?: {
    color?: boolean;
    failOn?: string;
    fixes?: boolean;
}): string;
export function formatJson(result: any, meta?: {}): string;
export function formatMarkdown(result: any): string;
export function formatSarif(result: any, { version }?: {
    version?: string;
}): string;
