import { RULES, SEVERITIES, sevRank } from './rules.js';

export function exitCode(result, failOn = 'high') {
  if (failOn === 'none') return 0;
  return result.findings.some((f) => sevRank(f.severity) >= sevRank(failOn)) ? 1 : 0;
}

const counts = (fs) => Object.fromEntries(SEVERITIES.slice().reverse().map((s) => [s, fs.filter((f) => f.severity === s).length]));

export function formatText(result, { color = false, failOn = 'high', fixes = true } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const sc = { critical: '35;1', high: '31;1', medium: '33;1', low: '36', info: '2' };
  const out = [`${c('1', 'workflow-sentinel')} — ${result.files.length} file(s) scanned`];
  let cur = null;
  const byLoc = result.findings.slice().sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || sevRank(b.severity) - sevRank(a.severity));
  for (const f of byLoc) {
    if (f.file !== cur) { cur = f.file; out.push('', c('4', f.file)); }
    out.push(`  ${String(f.line).padStart(4)}  ${c(sc[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.message} ${c('2', `[${f.rule}]`)}`);
    if (fixes) out.push(`        ${c('32', '↳ fix:')} ${f.fix}`);
  }
  if (!result.findings.length) out.push(c('32', '✔ No workflow hardening issues found.'));
  const n = counts(result.findings);
  out.push('', Object.entries(n).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') + (result.findings.length ? '' : '0 findings') + (result.suppressed?.length ? ` · ${result.suppressed.length} allowlisted` : ''));
  const fail = exitCode(result, failOn);
  out.push(fail ? c('31;1', `✖ Failing (fail-on: ${failOn}).`) : c('32', `Passing (fail-on: ${failOn}).`));
  return out.join('\n') + '\n';
}

export function formatJson(result, meta = {}) {
  return JSON.stringify({ tool: 'workflow-sentinel', ...meta, summary: counts(result.findings), files: result.files, findings: result.findings, suppressed: result.suppressed }, null, 2) + '\n';
}

export function formatMarkdown(result) {
  const icon = { critical: '🟣', high: '🔴', medium: '🟠', low: '🔵', info: '⚪' };
  const out = ['## workflow-sentinel', ''];
  if (!result.findings.length) out.push(`✅ No workflow hardening issues in ${result.files.length} file(s).`);
  else {
    out.push(Object.entries(counts(result.findings)).filter(([, v]) => v).map(([k, v]) => `${icon[k]} ${v} ${k}`).join(' · '), '', '| Severity | Location | Issue | Fix |', '|---|---|---|---|');
    const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
    for (const f of result.findings) out.push(`| ${icon[f.severity]} ${f.severity} | \`${f.file}:${f.line}\` | ${esc(f.message)} (\`${f.rule}\`) | ${esc(f.fix)} |`);
  }
  return out.join('\n') + '\n';
}

export function formatSarif(result, { version = '0.0.0' } = {}) {
  const lvl = (s) => (sevRank(s) >= 3 ? 'error' : sevRank(s) === 2 ? 'warning' : 'note');
  const secSev = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'workflow-sentinel', version, informationUri: 'https://github.com/MrLouisWright/workflow-sentinel',
        rules: Object.entries(RULES).map(([id, r]) => ({ id, name: id, shortDescription: { text: r.title }, help: { text: r.help }, defaultConfiguration: { level: lvl(r.severity) }, properties: { 'security-severity': secSev[r.severity], tags: ['security', 'github-actions'] } })) } },
      results: result.findings.map((f) => ({
        ruleId: f.rule, level: lvl(f.severity), message: { text: `${f.message}. Fix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        partialFingerprints: { workflowSentinel: `${f.rule}:${f.file}:${f.target || f.message}` },
        properties: { severity: f.severity },
      })),
    }],
  }, null, 2) + '\n';
}
