#!/usr/bin/env node
import fs from 'node:fs';
import { scan, fixFiles, formatText, formatJson, formatSarif, formatMarkdown, exitCode, SEVERITIES } from '../src/index.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const HELP = `workflow-sentinel ${pkg.version} — harden GitHub Actions workflows

Usage: workflow-sentinel [paths...] [options]

Scans .github/workflows/*.yml and action.yml files (default: current directory).

Options:
  --fail-on <sev>        critical | high | medium | low | info | none (default: high)
  --config <file>        Config file (default: .workflow-sentinel.json or package.json "workflow-sentinel")
  --trusted-owner <o>    Don't require SHA pins for this owner or owner/repo (repeatable, e.g. actions)
  --fix                  Pin actions to commit SHAs via the GitHub API (uses GH_TOKEN/GITHUB_TOKEN)
  --fix-dry-run          Show what --fix would change without writing
  --json [file]          JSON report to file, or stdout
  --sarif <file>         SARIF 2.1.0 report
  --markdown <file>      Markdown report
  --no-fixes             Hide fix suggestions in text output
  --no-color             Disable colours
  -h, --help | -v, --version

Exit codes: 0 pass, 1 findings at or above --fail-on, 2 usage or runtime error.
`;

function parseArgs(argv) {
  const o = { paths: [], trusted: [], color: (process.stdout.isTTY && !process.env.NO_COLOR) || !!process.env.FORCE_COLOR, fixes: true };
  const need = (i) => { const v = argv[i + 1]; if (v === undefined || v.startsWith('--')) throw new Error(`${argv[i]} needs a value`); return v; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      case '--fail-on': o.failOn = need(i); i++; if (![...SEVERITIES, 'none'].includes(o.failOn)) throw new Error(`Invalid --fail-on ${o.failOn}`); break;
      case '--config': o.config = need(i); i++; break;
      case '--trusted-owner': o.trusted.push(need(i)); i++; break;
      case '--fix': o.fix = true; break;
      case '--fix-dry-run': o.fix = true; o.dryRun = true; break;
      case '--json': { const n = argv[i + 1]; if (n && !n.startsWith('--')) { o.json = n; i++; } else o.json = '-'; break; }
      case '--sarif': o.sarif = need(i); i++; break;
      case '--markdown': o.markdown = need(i); i++; break;
      case '--no-fixes': o.fixes = false; break;
      case '--no-color': o.color = false; break;
      default: if (a.startsWith('-')) throw new Error(`Unknown option ${a}`); o.paths.push(a);
    }
  }
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`workflow-sentinel: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(pkg.version + '\n'); return 0; }
  for (const p of o.paths) if (!fs.existsSync(p)) throw new Error(`No such file or directory: ${p}`);
  let res = scan({ paths: o.paths, configPath: o.config });
  if (o.trusted.length) res = scan({ paths: o.paths, configPath: o.config, config: { trustedOwners: [...(res.config.trustedOwners || []), ...o.trusted] } });
  if (!res.files.length) throw new Error('No workflow or action files found');
  if (o.fix) {
    const files = [...new Set(res.findings.filter((f) => f.rule === 'unpinned-action').map((f) => f.file))];
    const rep = await fixFiles(files, { dryRun: o.dryRun });
    let errs = 0;
    for (const r of rep) for (const c of r.changes) {
      if (c.error) { errs++; process.stderr.write(`  ! ${r.file}:${c.line} ${c.action}@${c.ref}: ${c.error}\n`); }
      else process.stdout.write(`  ${o.dryRun ? 'would pin' : 'pinned'} ${r.file}:${c.line} ${c.action}@${c.ref} → ${c.sha}\n`);
    }
    if (!o.dryRun) res = scan({ paths: o.paths, configPath: o.config, config: o.trusted.length ? { trustedOwners: [...(res.config.trustedOwners || []), ...o.trusted] } : {} });
    if (errs) process.stderr.write(`workflow-sentinel: ${errs} action(s) could not be resolved\n`);
  }
  const failOn = o.failOn || res.config.failOn || 'high';
  const code = exitCode(res, failOn);
  const meta = { version: pkg.version, failOn, exitCode: code };
  if (o.sarif) fs.writeFileSync(o.sarif, formatSarif(res, { version: pkg.version }));
  if (o.markdown) fs.writeFileSync(o.markdown, formatMarkdown(res));
  if (o.json && o.json !== '-') fs.writeFileSync(o.json, formatJson(res, meta));
  if (o.json === '-') process.stdout.write(formatJson(res, meta));
  else process.stdout.write(formatText(res, { color: o.color, failOn, fixes: o.fixes }));
  return code;
}

main().then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`workflow-sentinel: ${e.message}\n`); process.exitCode = 2; });
