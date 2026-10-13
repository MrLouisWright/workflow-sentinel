export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type RuleId = 'unpinned-action' | 'missing-permissions' | 'broad-permissions' | 'dangerous-checkout' | 'script-injection' | 'secrets-inherit' | 'secrets-untrusted' | 'persist-credentials' | 'self-hosted-pr' | 'curl-pipe-shell' | 'deprecated-command' | 'docker-no-digest' | 'parse-error';
export interface Finding { rule: RuleId; severity: Severity; title: string; file: string; line: number; message: string; fix: string; target?: string; ref?: string; owner?: string; }
export interface AllowEntry { rule?: RuleId | '*'; file?: string; target?: string; reason?: string; expires?: string; }
export interface Config { failOn?: Severity | 'none'; trustedOwners?: string[]; rules?: Partial<Record<RuleId, Severity | 'off'>>; allow?: (string | AllowEntry)[]; ignore?: string[]; }
export interface Result { findings: Finding[]; suppressed: Finding[]; files: string[]; config: Config; }
export const RULES: Record<RuleId, { severity: Severity; title: string; help: string }>;
export const SEVERITIES: Severity[];
export const UNTRUSTED: RegExp[];
export function scanText(text: string, file: string): Finding[];
export function findFiles(root?: string): string[];
export function applyConfig(raw: Finding[], config?: Config, now?: number): { findings: Finding[]; suppressed: Finding[] };
export function scan(opts?: { cwd?: string; paths?: string[]; config?: Config; configPath?: string; now?: number }): Result;
export function loadConfig(dir?: string, explicit?: string): Config;
export function isAllowed(allow: (string | AllowEntry)[], f: Finding, now?: number): boolean;
export function formatText(r: Result, o?: { color?: boolean; failOn?: string; fixes?: boolean }): string;
export function formatJson(r: Result, meta?: object): string;
export function formatSarif(r: Result, o?: { version?: string }): string;
export function formatMarkdown(r: Result): string;
export function exitCode(r: { findings: Finding[] }, failOn?: string): 0 | 1;
export function resolveSha(action: string, ref: string, o?: { token?: string; fetchImpl?: typeof fetch; api?: string }): Promise<string>;
export function pinText(text: string, resolve: (action: string, ref: string) => Promise<string>): Promise<{ text: string; changes: { line: number; action: string; ref: string; sha?: string; error?: string }[] }>;
export function fixFiles(files: string[], o?: { cwd?: string; dryRun?: boolean; resolver?: (a: string, r: string) => Promise<string>; token?: string }): Promise<{ file: string; changes: any[] }[]>;
