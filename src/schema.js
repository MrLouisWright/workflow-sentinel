/** Workflow YAML key validation (actionlint-style schema checks). */
import { isMap, isScalar } from 'yaml';

const WORKFLOW_KEYS = new Set(['name', 'on', 'env', 'defaults', 'concurrency', 'permissions', 'jobs', 'run-name', true]);
const JOB_KEYS = new Set([
  'name', 'runs-on', 'needs', 'if', 'permissions', 'env', 'defaults', 'strategy', 'continue-on-error', 'timeout-minutes',
  'steps', 'uses', 'with', 'secrets', 'outputs', 'container', 'services',
]);
const STEP_KEYS = new Set([
  'id', 'if', 'name', 'uses', 'run', 'env', 'with', 'working-directory', 'continue-on-error', 'timeout-minutes', 'shell',
]);
const STRATEGY_KEYS = new Set(['matrix', 'fail-fast', 'max-parallel']);
const WITH_HINTS = {
  'actions/cache': new Set(['path', 'key', 'restore-keys', 'upload-chunk-size', 'enableCrossOsArchive', 'fail-on-cache-miss', 'lookup-only', 'save-always']),
  'actions/cache/restore': new Set(['path', 'key', 'restore-keys', 'fail-on-cache-miss', 'lookup-only']),
  'actions/upload-artifact': new Set(['name', 'path', 'if-no-files-found', 'retention-days', 'compression-level']),
  'actions/download-artifact': new Set(['name', 'path', 'pattern', 'merge-multiple', 'github-token']),
};

const KEY_TYPO = {
  job: 'jobs',
  'runs-onn': 'runs-on',
  'run-on': 'runs-on',
  step: 'steps',
  permission: 'permissions',
  secrete: 'secrets',
  secrets: 'secrets',
  'working_directory': 'working-directory',
  'timeout_minutes': 'timeout-minutes',
  'continue_on_error': 'continue-on-error',
};

function scalarKey(pair) {
  if (!pair?.key) return null;
  return isScalar(pair.key) ? pair.key.value : pair.key;
}

export function validateWorkflowSchema(root, { isAction = false } = {}) {
  const issues = [];
  if (!isMap(root)) return issues;
  for (const p of root.items) {
    const k = scalarKey(p);
    if (k === undefined || k === null) continue;
    if (!WORKFLOW_KEYS.has(k)) {
      const hint = KEY_TYPO[k];
      issues.push({
        key: k,
        message: hint ? `Unknown workflow key \`${k}\`; did you mean \`${hint}\`?` : `Unknown workflow key \`${k}\``,
      });
    }
  }
  if (isAction) return issues;
  const jobs = root.items.find((p) => scalarKey(p) === 'jobs')?.value;
  if (isMap(jobs)) {
    for (const jp of jobs.items) {
      if (!isMap(jp.value)) continue;
      const jobName = scalarKey(jp) ?? '?';
      for (const p of jp.value.items) {
        const k = scalarKey(p);
        if (k === undefined) continue;
        if (!JOB_KEYS.has(k)) {
          const hint = KEY_TYPO[k];
          issues.push({ key: k, job: jobName, message: hint ? `Job "${jobName}": unknown key \`${k}\`; did you mean \`${hint}\`?` : `Job "${jobName}": unknown key \`${k}\`` });
        }
        if (k === 'strategy' && isMap(p.value)) validateNestedKeys(p.value, STRATEGY_KEYS, `Job "${jobName}" strategy`, issues);
        if (k === 'steps' && p.value?.items) {
          p.value.items.forEach((st, i) => {
            if (!isMap(st)) return;
            for (const sp of st.items) {
              const sk = scalarKey(sp);
              if (sk === undefined) continue;
              if (!STEP_KEYS.has(sk)) {
                const hint = KEY_TYPO[sk];
                issues.push({
                  key: sk,
                  job: jobName,
                  step: i + 1,
                  message: hint
                    ? `Job "${jobName}" step ${i + 1}: unknown key \`${sk}\`; did you mean \`${hint}\`?`
                    : `Job "${jobName}" step ${i + 1}: unknown key \`${sk}\``,
                });
              }
            }
          });
        }
      }
    }
  }
  return issues;
}

function validateNestedKeys(node, allowed, where, issues) {
  if (!isMap(node)) return;
  for (const p of node.items) {
    const k = scalarKey(p);
    if (k !== undefined && !allowed.has(k)) issues.push({ message: `${where}: unknown key \`${k}\`` });
  }
}

/** Flag unusual `with:` keys for well-known actions (typos in input names). */
export function validateActionInputs(uses, withNode) {
  const issues = [];
  if (!uses || !withNode || !isMap(withNode)) return issues;
  const action = String(uses).replace(/@.*$/, '').toLowerCase();
  const known = WITH_HINTS[action];
  if (!known) return issues;
  for (const p of withNode.items) {
    const k = scalarKey(p);
    if (k && !known.has(k) && !k.includes('-')) {
      // only flag likely typos on simple keys
      const close = [...known].find((x) => levenshtein(x, k) === 1);
      if (close) issues.push({ message: `\`${action}\` input \`${k}\` is unknown; did you mean \`${close}\`?` });
    }
  }
  return issues;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return d[m][n];
}
