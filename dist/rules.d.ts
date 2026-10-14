export const SEVERITIES: string[];
export function sevRank(s: any): number;
export const RULES: {
    'unpinned-action': {
        severity: string;
        title: string;
        help: string;
    };
    'missing-permissions': {
        severity: string;
        title: string;
        help: string;
    };
    'broad-permissions': {
        severity: string;
        title: string;
        help: string;
    };
    'dangerous-checkout': {
        severity: string;
        title: string;
        help: string;
    };
    'script-injection': {
        severity: string;
        title: string;
        help: string;
    };
    'secrets-inherit': {
        severity: string;
        title: string;
        help: string;
    };
    'secrets-untrusted': {
        severity: string;
        title: string;
        help: string;
    };
    'persist-credentials': {
        severity: string;
        title: string;
        help: string;
    };
    'self-hosted-pr': {
        severity: string;
        title: string;
        help: string;
    };
    'curl-pipe-shell': {
        severity: string;
        title: string;
        help: string;
    };
    'deprecated-command': {
        severity: string;
        title: string;
        help: string;
    };
    'docker-no-digest': {
        severity: string;
        title: string;
        help: string;
    };
    'parse-error': {
        severity: string;
        title: string;
        help: string;
    };
    'cache-poisoning': {
        severity: string;
        title: string;
        help: string;
    };
    artipacked: {
        severity: string;
        title: string;
        help: string;
    };
    'invalid-expression': {
        severity: string;
        title: string;
        help: string;
    };
    'invalid-schema': {
        severity: string;
        title: string;
        help: string;
    };
};
export const UNTRUSTED: RegExp[];
