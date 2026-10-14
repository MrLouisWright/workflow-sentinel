export function resolveSha(action: any, ref: any, { token, fetchImpl, api }?: {
    token?: any;
    fetchImpl?: typeof fetch;
    api?: string;
}): Promise<string>;
/** Rewrite text given a resolver(action, ref) -> sha. Returns { text, changes[] }. */
export function pinText(text: any, resolve: any): Promise<{
    text: any;
    changes: ({
        line: number;
        action: any;
        ref: any;
        error: any;
        sha?: undefined;
    } | {
        line: number;
        action: any;
        ref: any;
        sha: any;
        error?: undefined;
    })[];
}>;
export function fixFiles(files: any, { cwd, resolver, dryRun, ...opts }?: {
    cwd?: string;
    dryRun?: boolean;
}): Promise<{
    file: any;
    changes: ({
        line: number;
        action: any;
        ref: any;
        error: any;
        sha?: undefined;
    } | {
        line: number;
        action: any;
        ref: any;
        sha: any;
        error?: undefined;
    })[];
}[]>;
