import fs from 'node:fs';
import path from 'node:path';
import { parseDocument, LineCounter, isMap, isSeq, isScalar } from 'yaml';
import { RULES, UNTRUSTED } from './rules.js';

const SHA_RE = /^[0-9a-f]{40}$/;
const EXPR_RE = /\$\{\{([\s\S]*?)\}\}/g;
const PR_TRIGGERS = ['pull_request', 'pull_request_target', 'pull_request_review', 'pull_request_review_comment', 'issue_comment', 'workflow_run'];

export function findFiles(root = '.') {
  const out = [];
  const wf = path.join(root, '.github', 'workflows');
  if (fs.existsSync(wf)) for (const f of fs.readdirSync(wf).sort()) if (/\.ya?ml$/.test(f)) out.push(path.join(wf, f));
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.isDirectory()) { if (!/^(node_modules|\.git|dist|build|coverage|vendor)$/.test(e.name) && !(dir === path.join(root, '.github') && e.name === 'workflows')) walk(path.join(dir, e.name), depth + 1); }
      else if (/^action\.ya?ml$/.test(e.name)) out.push(path.join(dir, e.name));
    }
  };
  walk(root, 0);
  return [...new Set(out)];
}

/** Scan one file's text. Returns findings (unfiltered by config). */
export function scanText(text, file, opts = {}) {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, uniqueKeys: false, prettyErrors: false });
  const findings = [];
  const lines = text.split(/\r?\n/);
  if (doc.errors.length) {
    const e = doc.errors[0];
    return [mk('parse-error', file, e.linePos?.[0]?.line || 1, `YAML parse error: ${e.message.split('\n')[0]}`)];
  }
  const lineAt = (node) => (node?.range ? lc.linePos(node.range[0]).line : 1);
  const get = (node, key) => (isMap(node) ? node.items.find((p) => (isScalar(p.key) ? p.key.value : p.key) === key) : undefined);
  const val = (node, key) => get(node, key)?.value;
  const js = (node) => (node && node.toJSON ? node.toJSON() : node);
  const add = (rule, node, message, extra = {}) => {
    const line = typeof node === 'number' ? node : lineAt(node);
    if (suppressed(lines, line, rule)) return;
    findings.push(mk(rule, file, line, message, extra));
  };

  const root = doc.contents;
  if (!isMap(root)) return findings;
  const isAction = /(^|[\\/])action\.ya?ml$/.test(file) && !get(root, 'jobs');

  if (isAction) {
    const runs = val(root, 'runs');
    const using = js(val(runs, 'using'));
    if (using === 'docker') {
      const img = val(runs, 'image');
      const s = String(js(img) || '');
      if (s.startsWith('docker://') && !/@sha256:[0-9a-f]{64}/.test(s)) add('docker-no-digest', img, `Action image ${s} is not pinned to a digest`, { target: s });
    }
    const steps = val(runs, 'steps');
    if (isSeq(steps)) for (const st of steps.items) checkStep(st, { triggers: [], composite: true, job: null });
    return findings;
  }

  // ---- triggers ----
  const onNode = val(root, 'on') ?? val(root, true); // YAML 1.1 "on" may parse as boolean true
  const onJs = js(onNode);
  const triggers = typeof onJs === 'string' ? [onJs] : Array.isArray(onJs) ? onJs : onJs && typeof onJs === 'object' ? Object.keys(onJs) : [];
  const privileged = triggers.filter((t) => t === 'pull_request_target' || t === 'workflow_run');
  const prTriggered = triggers.some((t) => PR_TRIGGERS.includes(t));

  // ---- permissions ----
  const topPerm = get(root, 'permissions');
  const jobs = val(root, 'jobs');
  const permIssue = (p, where) => {
    const v = js(p.value);
    if (v === 'write-all') add('broad-permissions', p.value, `${where} uses \`permissions: write-all\``);
    else if (where === 'Workflow' && v && typeof v === 'object' && isMap(jobs) && jobs.items.length > 1) {
      const w = Object.entries(v).filter(([, x]) => x === 'write').map(([k]) => k);
      if (w.length) add('broad-permissions', p.value, `Top-level permissions grant write to ${w.join(', ')} for every job; move write scopes to the jobs that need them`, { severity: 'low' });
    }
  };
  if (topPerm) permIssue(topPerm, 'Workflow');
  if (isMap(jobs)) {
    const jobsWithout = [];
    for (const jp of jobs.items) {
      const jp_p = get(jp.value, 'permissions');
      if (jp_p) permIssue(jp_p, `Job "${jp.key.value}"`);
      else if (!get(jp.value, 'uses')) jobsWithout.push(jp);
    }
    if (!topPerm && jobsWithout.length)
      add('missing-permissions', onNode ? doc.contents.items[0].key : 1, `No top-level \`permissions:\`; ${jobsWithout.length === 1 ? `job "${jobsWithout[0].key.value}" runs` : `${jobsWithout.length} jobs run`} with the default GITHUB_TOKEN scopes`);
  }

  // ---- jobs ----
  if (isMap(jobs)) for (const jp of jobs.items) {
    const job = jp.value;
    const name = String(jp.key.value);
    const ctx = { triggers, privileged, job: name, untrustedCheckout: false };

    const runsOn = js(val(job, 'runs-on'));
    const labels = typeof runsOn === 'string' ? [runsOn] : Array.isArray(runsOn) ? runsOn : runsOn?.labels ? [].concat(runsOn.labels) : [];
    if (prTriggered && labels.some((l) => /self-hosted/i.test(String(l))))
      add('self-hosted-pr', val(job, 'runs-on'), `Job "${name}" runs on a self-hosted runner and the workflow is triggered by ${triggers.filter((t) => PR_TRIGGERS.includes(t)).join(', ')}`);

    // reusable workflow call
    const uses = val(job, 'uses');
    if (uses) checkUses(uses, ctx);
    const sec = val(job, 'secrets');
    if (sec && js(sec) === 'inherit') add('secrets-inherit', sec, `Job "${name}" passes all secrets to ${js(uses)} with \`secrets: inherit\``);

    for (const k of ['container']) {
      const c = val(job, k);
      const img = isMap(c) ? val(c, 'image') : c;
      if (img) dockerImage(img, `Job "${name}" container`);
    }
    const services = val(job, 'services');
    if (isMap(services)) for (const sp of services.items) {
      const img = isMap(sp.value) ? val(sp.value, 'image') : null;
      if (img) dockerImage(img, `Service "${sp.key.value}" in job "${name}"`);
    }

    const steps = val(job, 'steps');
    if (isSeq(steps)) {
      // first pass: does this job check out untrusted code?
      for (const st of steps.items) if (privileged.length && untrustedCheckout(st)) ctx.untrustedCheckout = true;
      for (const st of steps.items) checkStep(st, ctx);
      if (ctx.untrustedCheckout) {
        const secretRefs = [];
        for (const st of steps.items) { const t = js(st); if (/\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)/.test(JSON.stringify(t))) secretRefs.push(st); }
        if (secretRefs.length) add('secrets-untrusted', secretRefs[0], `Job "${name}" checks out PR code under ${privileged.join('/')} and also uses repository secrets in ${secretRefs.length} step(s)`);
      }
    }
  }
  return findings;

  // ---- helpers (hoisted) ----
  function untrustedCheckout(st) {
    const u = String(js(val(st, 'uses')) || '');
    const w = js(val(st, 'with')) || {};
    const ref = String(w.ref ?? '') + ' ' + String(w.repository ?? '');
    const headRe = /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\/|github\.event\.pull_request\.merge_commit_sha|github\.event\.number|head\.repo\.full_name|workflow_run\.head_repository/;
    if (/^actions\/checkout@/i.test(u) && headRe.test(ref)) return true;
    const run = String(js(val(st, 'run')) || '');
    if (/\b(gh pr checkout|git (fetch|checkout|pull)\b[^\n]*(pull\/|head_ref|head\.ref|head\.sha|head_sha|head_branch))/.test(run)) return true;
    return false;
  }

  function checkUses(node, ctx) {
    const u = String(js(node) || '').trim();
    if (!u || u.startsWith('./') || u.startsWith('.\\')) return;
    if (u.startsWith('docker://')) { dockerImage(node, 'Step', true); return; }
    const at = u.lastIndexOf('@');
    const ref = at === -1 ? '' : u.slice(at + 1);
    const action = at === -1 ? u : u.slice(0, at);
    if (!SHA_RE.test(ref)) {
      const owner = action.split('/')[0];
      add('unpinned-action', node, `${u} is pinned to ${ref ? `"${ref}" (mutable ${/^v?\d+(\.\d+)*$/.test(ref) ? 'tag' : 'ref'})` : 'nothing'}, not a commit SHA`, { target: action, ref, owner, fix: `Pin it: \`uses: ${action}@<40-char-sha> # ${ref || 'latest'}\` (or run \`workflow-sentinel --fix\`). ${RULES['unpinned-action'].help.split('. ')[0]}.` });
    }
  }

  function dockerImage(node, where, isUses = false) {
    const s = String(js(node) || '');
    if (!s || /\$\{\{/.test(s)) return;
    if (!/@sha256:[0-9a-f]{64}/.test(s)) add('docker-no-digest', node, `${where} image ${s.replace(/^docker:\/\//, '')} is not pinned to a digest`, { target: s });
  }

  function checkStep(st, ctx) {
    if (!isMap(st)) return;
    const usesNode = val(st, 'uses');
    const u = String(js(usesNode) || '');
    if (usesNode) checkUses(usesNode, ctx);
    if (/^actions\/checkout@/i.test(u)) {
      const w = js(val(st, 'with')) || {};
      if (!(w['persist-credentials'] === false || w['persist-credentials'] === 'false'))
        add('persist-credentials', usesNode, `${u} without \`persist-credentials: false\`${ctx.job ? ` in job "${ctx.job}"` : ''}`, { fix: 'Add to the step: `with: { persist-credentials: false }` (keep it only if a later step must `git push`).' });
      if (ctx.privileged?.length && untrustedCheckout(st))
        add('dangerous-checkout', val(val(st, 'with'), 'ref') || usesNode, `Job "${ctx.job}" checks out the pull request head (${String(w.ref)}) in a ${ctx.privileged.join('/')} workflow`);
    } else if (ctx.privileged?.length && untrustedCheckout(st)) {
      add('dangerous-checkout', val(st, 'run'), `Job "${ctx.job}" fetches/checks out PR code in a run step of a ${ctx.privileged.join('/')} workflow`);
    }

    const scripts = [];
    const runNode = val(st, 'run');
    if (runNode) scripts.push(['run', runNode]);
    if (/^actions\/github-script@/i.test(u)) { const sn = val(val(st, 'with'), 'script'); if (sn) scripts.push(['script', sn]); }
    for (const [kind, n] of scripts) {
      const text = String(js(n) ?? '');
      const base = lineAt(n);
      const offset = isScalar(n) && (n.type === 'BLOCK_LITERAL' || n.type === 'BLOCK_FOLDED') ? 1 : 0;
      const lineOf = (idx) => base + offset + text.slice(0, idx).split('\n').length - 1;
      for (const m of text.matchAll(EXPR_RE)) {
        const expr = m[1].trim();
        const bad = UNTRUSTED.find((re) => re.test(expr));
        const isInput = ctx.composite && /\binputs\./.test(expr);
        const envName = expr.replace(/^.*\./, '').replace(/[^A-Za-z0-9]+/g, '_').toUpperCase() || 'VALUE';
        const fix = `Move it to an env var: \`env: { ${envName}: \${{ ${expr} }} }\` and reference ${kind === 'run' ? `"$${envName}"` : `process.env.${envName}`} in the script.`;
        if (bad) add('script-injection', lineOf(m.index), `\${{ ${expr} }} is interpolated into ${kind === 'run' ? 'a run: script' : 'github-script'}${ctx.job ? ` (job "${ctx.job}")` : ''}`, { fix, ...(ctx.privileged?.length ? { severity: 'critical' } : {}) });
        else if (isInput) add('script-injection', lineOf(m.index), `\${{ ${expr} }} (action input) is interpolated into a composite run: script; callers may pass untrusted data`, { severity: 'medium', fix });
        if (/\bsecrets\.[A-Za-z_]/.test(expr) && /\b(echo|printf|cat)\b[^\n]*$/.test(text.slice(text.lastIndexOf('\n', m.index) + 1, m.index)))
          add('secrets-untrusted', lineOf(m.index), `\${{ ${expr} }} is echoed in a script and may leak into logs or files`, { severity: 'medium' });
      }
      if (kind !== 'run') continue;
      const lns = text.split('\n');
      lns.forEach((l, i) => {
        const L = base + offset + i;
        if (/\b(curl|wget)\b[^|#]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b/.test(l) || /\b(ba)?sh\s+(-c\s+)?["']?\$\((curl|wget)\b/.test(l) || /\b(bash|sh)\s+<\(\s*(curl|wget)/.test(l))
          add('curl-pipe-shell', L, `Remote script piped to a shell: ${l.trim().slice(0, 100)}`);
        const dm = l.match(/::(set-output|save-state|set-env|add-path)\b/);
        if (dm) add('deprecated-command', L, `Deprecated \`::${dm[1]}\` workflow command`, /set-env|add-path/.test(dm[1]) ? { severity: 'high' } : {});
      });
    }
  }
}

function suppressed(lines, line, rule) {
  const re = /#\s*workflow-sentinel-(?:ignore|disable)(?:\s+([\w,\s-]+))?/;
  for (const l of [lines[line - 1], lines[line - 2]]) {
    const m = l && l.match(re);
    if (m && (!m[1] || m[1].split(/[\s,]+/).filter(Boolean).includes(rule))) {
      if (l === lines[line - 2] && !/^\s*#/.test(l)) continue; // previous line must be a comment-only line
      return true;
    }
  }
  return false;
}

function mk(rule, file, line, message, extra = {}) {
  const { severity, ...rest } = extra;
  return { rule, severity: severity || RULES[rule].severity, title: RULES[rule].title, file, line, message, fix: RULES[rule].help, ...rest };
}
