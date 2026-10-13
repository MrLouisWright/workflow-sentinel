// --fix: pin `uses: owner/repo[/path]@ref` to the commit SHA the ref currently points at, keeping the ref as a comment.
import fs from 'node:fs';
import path from 'node:path';

const USES_RE = /^(\s*-?\s*uses:\s*)(["']?)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[^@\s"']+)?)@([^\s"'#]+)\2([ \t]*#.*)?$/;

export async function resolveSha(action, ref, { token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN, fetchImpl = globalThis.fetch, api = 'https://api.github.com' } = {}) {
  const repo = action.split('/').slice(0, 2).join('/');
  const headers = { accept: 'application/vnd.github.sha', 'user-agent': 'workflow-sentinel', 'x-github-api-version': '2022-11-28' };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetchImpl(`${api}/repos/${repo}/commits/${encodeURIComponent(ref)}`, { headers });
  if (!res.ok) throw new Error(`cannot resolve ${repo}@${ref}: HTTP ${res.status}`);
  const sha = (await res.text()).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`unexpected response resolving ${repo}@${ref}`);
  return sha;
}

/** Rewrite text given a resolver(action, ref) -> sha. Returns { text, changes[] }. */
export async function pinText(text, resolve) {
  const lines = text.split('\n');
  const changes = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].replace(/\r$/, '').match(USES_RE);
    if (!m) continue;
    const [, pre, q, action, ref, comment] = m;
    if (/^[0-9a-f]{40}$/.test(ref) || action.startsWith('.') || /\$\{\{/.test(ref)) continue;
    let sha;
    try { sha = await resolve(action, ref); } catch (e) { changes.push({ line: i + 1, action, ref, error: e.message }); continue; }
    const cr = lines[i].endsWith('\r') ? '\r' : '';
    lines[i] = `${pre}${q}${action}@${sha}${q}${comment ? comment : ` # ${ref}`}${cr}`;
    changes.push({ line: i + 1, action, ref, sha });
  }
  return { text: lines.join('\n'), changes };
}

export async function fixFiles(files, { cwd = '.', resolver, dryRun = false, ...opts } = {}) {
  const cache = new Map();
  const resolve = resolver || ((a, r) => {
    const k = `${a.split('/').slice(0, 2).join('/')}@${r}`;
    if (!cache.has(k)) cache.set(k, resolveSha(a, r, opts));
    return cache.get(k);
  });
  const report = [];
  for (const f of files) {
    const abs = path.resolve(cwd, f);
    const before = fs.readFileSync(abs, 'utf8');
    const { text, changes } = await pinText(before, resolve);
    if (changes.length) report.push({ file: f, changes });
    if (!dryRun && text !== before) fs.writeFileSync(abs, text);
  }
  return report;
}
