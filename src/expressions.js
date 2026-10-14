/** GitHub Actions `${{ }}` expression parsing and validation (actionlint-style). */

const EXPR_RE = /\$\{\{([\s\S]*?)\}\}/g;

/** Roots allowed at the start of a property access chain in an expression. */
export const EXPR_ROOTS = new Set([
  'github', 'env', 'vars', 'secrets', 'strategy', 'matrix', 'inputs', 'needs', 'jobs', 'steps', 'runner',
]);

/** Built-in call-style functions in workflow expressions. */
const EXPR_FUNCS = new Set([
  'success', 'failure', 'cancelled', 'always', 'hashFiles', 'format', 'contains', 'startsWith', 'endsWith', 'join', 'toJSON', 'fromJSON',
]);

/** github.event.* payloads that exist for common webhook event names. */
export const EVENT_FIELDS = {
  push: ['after', 'before', 'commits', 'compare', 'created', 'deleted', 'forced', 'head_commit', 'pusher', 'ref', 'repository'],
  pull_request: ['action', 'number', 'pull_request', 'label', 'assignee', 'review', 'changes'],
  pull_request_target: ['action', 'number', 'pull_request', 'label', 'assignee', 'review', 'changes'],
  issues: ['action', 'issue', 'assignee', 'label', 'changes'],
  issue_comment: ['action', 'comment', 'issue', 'changes'],
  workflow_dispatch: ['inputs', 'ref', 'repository', 'workflow'],
  workflow_call: ['inputs', 'secrets'],
  workflow_run: ['action', 'workflow_run', 'workflow'],
  release: ['action', 'release'],
  schedule: [],
  repository_dispatch: ['action', 'client_payload'],
  push_tag: [],
  create: ['ref', 'ref_type', 'master_branch', 'description', 'pusher'],
  delete: ['ref', 'ref_type'],
  fork: ['forkee', 'repository'],
  watch: ['action', 'repository', 'sender'],
  discussion: ['action', 'discussion', 'answer', 'label'],
  discussion_comment: ['action', 'comment', 'discussion'],
  pull_request_review: ['action', 'review', 'pull_request'],
  pull_request_review_comment: ['action', 'comment', 'pull_request', 'changes'],
  check_run: ['action', 'check_run', 'check_suite', 'requested_action'],
  check_suite: ['action', 'check_suite'],
  registry_package: ['action', 'registry_package', 'repository'],
  page_build: ['build', 'id', 'pusher', 'status'],
  public: ['repository'],
  status: ['action', 'branches', 'commit', 'ref', 'repository', 'sender', 'sha', 'state'],
};

/** github.* top-level objects (subset of actionlint's context docs). */
const GITHUB_TOP = new Set([
  'action', 'action_path', 'action_ref', 'action_repository', 'action_status', 'actor', 'actor_id', 'api_url', 'base_ref', 'env', 'event',
  'event_name', 'event_path', 'graphql_url', 'head_ref', 'job', 'output', 'path', 'ref', 'ref_name', 'ref_protected', 'ref_type',
  'repository', 'repository_id', 'repository_owner', 'repository_owner_id', 'repositoryUrl', 'retention_days', 'run_id', 'run_number',
  'run_attempt', 'secret_source', 'server_url', 'sha', 'token', 'triggering_actor', 'workflow', 'workspace',
]);

/** Common typos → suggestion. */
const TYPO_ROOT = { events: 'event', secret: 'secrets', matix: 'matrix', environ: 'env', jobss: 'jobs', step: 'steps' };
const TYPO_GITHUB = { reposity: 'repository', repositry: 'repository', head_refs: 'head_ref', base_refs: 'base_ref' };

export function extractExpressions(text) {
  const out = [];
  if (!text || typeof text !== 'string') return out;
  for (const m of text.matchAll(EXPR_RE)) out.push({ expr: m[1].trim(), index: m.index, raw: m[0] });
  return out;
}

/** Return list of validation issues: { kind, message, detail? } */
export function validateExpression(expr, { triggers = [] } = {}) {
  const issues = [];
  if (!expr) return [{ kind: 'empty', message: 'Empty `${{ }}` expression' }];

  // Strip string literals for context scanning
  const stripped = expr.replace(/'([^'\\]|\\.)*'|"([^"\\]|\\.)*"/g, ' ');

  // Detect function calls like hashFiles('x')
  for (const m of stripped.matchAll(/\b([A-Za-z_][\w]*)\s*\(/g)) {
    const fn = m[1];
    if (!EXPR_FUNCS.has(fn) && !EXPR_ROOTS.has(fn)) issues.push({ kind: 'unknown-func', message: `Unknown function or context \`${fn}()\`` });
  }

  // Property chains: github.event.foo, env.X, matrix.os
  for (const m of stripped.matchAll(/\b([A-Za-z_][\w]*(?:\.[A-Za-z_*][\w*]*)*)/g)) {
    const chain = m[1];
    if (!chain.includes('.')) continue;
    const parts = chain.split('.');
    const root = parts[0];
    if (EXPR_FUNCS.has(root)) continue;

    if (TYPO_ROOT[root]) {
      issues.push({ kind: 'typo', message: `\`${root}\` is not a valid expression root; did you mean \`${TYPO_ROOT[root]}\`?` });
      continue;
    }
    if (!EXPR_ROOTS.has(root)) {
      if (/^[A-Z]/.test(root)) continue; // likely JS in github-script, skip
      issues.push({ kind: 'invalid-root', message: `\`${root}\` is not a recognized expression context (expected github, env, matrix, …)` });
      continue;
    }

    if (root === 'github') validateGithubChain(parts.slice(1), triggers, issues);
    else if (root === 'secrets' && parts[1] === 'GITHUB_TOKEN' && parts.length > 2) issues.push({ kind: 'invalid-context', message: 'secrets.GITHUB_TOKEN has no sub-properties' });
  }

  return issues;
}

function validateGithubChain(parts, triggers, issues) {
  if (!parts.length) return;
  const head = parts[0];
  if (TYPO_GITHUB[head]) {
    issues.push({ kind: 'typo', message: `Unknown \`github.${head}\`; did you mean \`github.${TYPO_GITHUB[head]}\`?` });
    return;
  }
  if (head === 'events') {
    issues.push({ kind: 'typo', message: 'Use `github.event` (singular), not `github.events`' });
    return;
  }
  if (head === 'event') {
    if (parts.length === 1) return;
    const evField = parts[1];
    if (evField === 'inputs' && !triggers.some((t) => t.startsWith('workflow_dispatch') || t === 'workflow_call')) {
      issues.push({ kind: 'invalid-context', message: '`github.event.inputs` is only set for workflow_dispatch and workflow_call triggers' });
    }
    if (evField === 'pull_request' && !triggers.some((t) => /pull_request/.test(t))) {
      issues.push({ kind: 'invalid-context', message: '`github.event.pull_request` is not available for this workflow\'s `on:` triggers' });
    }
    if (evField === 'issue' && !triggers.some((t) => /issue/.test(t))) {
      issues.push({ kind: 'invalid-context', message: '`github.event.issue` is not available for this workflow\'s `on:` triggers' });
    }
    if (EVENT_FIELDS[evField] && parts[2] && !EVENT_FIELDS[evField].includes(parts[2]) && evField !== 'pull_request') {
      // pull_request has nested object — only flag obvious junk on shallow keys
      if (parts.length === 3 && !['head', 'base', 'user', 'labels', 'milestone'].includes(parts[2])) {
        issues.push({ kind: 'unknown-field', message: `\`github.event.${evField}.${parts[2]}\` is not a usual field for the ${evField} payload` });
      }
    }
    return;
  }
  if (!GITHUB_TOP.has(head) && head !== 'event') {
    issues.push({ kind: 'unknown-github', message: `Unknown property \`github.${head}\`` });
  }
}

/** True if expression text matches any UNTRUSTED pattern or contains github.event / head_ref style inputs. */
export function isUntrustedExpression(expr, untrustedRes) {
  if (!expr) return false;
  for (const re of untrustedRes) if (re.test(expr)) return true;
  if (/github\.event\.(inputs|client_payload)\./.test(expr)) return true;
  if (/github\.(head_ref|event\.ref)\b/.test(expr)) return true;
  return false;
}

/** Collect env var names assigned from untrusted expressions in a scalar/map node (JSON-ish). */
export function taintFromEnvBlock(envJs, untrustedRes) {
  const tainted = new Set();
  if (!envJs || typeof envJs !== 'object') return tainted;
  for (const [k, v] of Object.entries(envJs)) {
    const s = String(v ?? '');
    for (const { expr } of extractExpressions(s)) {
      if (isUntrustedExpression(expr, untrustedRes)) tainted.add(k);
    }
  }
  return tainted;
}

/** Whether a string references a tainted env var inside ${{ env.NAME }} or plain $NAME in scripts. */
export function referencesTaintedEnv(text, tainted) {
  if (!text || !tainted.size) return false;
  const s = String(text);
  for (const name of tainted) {
    if (new RegExp(`\\benv\\.${name}\\b`).test(s)) return true;
    if (new RegExp(`\\$\\{\\{\\s*env\\.${name}\\s*\\}\\}`).test(s)) return true;
  }
  return false;
}
