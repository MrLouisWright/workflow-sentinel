import fs from 'node:fs';
import path from 'node:path';
import { scanText, findFiles } from './scan.js';
import { loadConfig, isAllowed, ownerTrusted } from './config.js';
import { sevRank } from './rules.js';

export { scanText, findFiles } from './scan.js';
export { RULES, SEVERITIES, UNTRUSTED } from './rules.js';
export { loadConfig, isAllowed } from './config.js';
export { formatText, formatJson, formatSarif, formatMarkdown, exitCode } from './format.js';
export { fixFiles, resolveSha, pinText } from './fix.js';

/** Apply config (rule overrides, trusted owners, allowlist, ignore globs) to raw findings. */
export function applyConfig(raw, config = {}, now = Date.now()) {
  const findings = [], suppressed = [];
  for (const f0 of raw) {
    const o = config.rules?.[f0.rule];
    if (o === 'off') continue;
    const f = o ? { ...f0, severity: o } : f0;
    if (ownerTrusted(config.trustedOwners, f) || isAllowed(config.allow, f, now)) suppressed.push(f); else findings.push(f);
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { findings, suppressed };
}

export function scan({ cwd = '.', paths, config: override = {}, configPath, now } = {}) {
  const config = { ...loadConfig(cwd, configPath), ...override };
  const files = [];
  if (paths && paths.length) {
    for (const p of paths) {
      const abs = path.resolve(cwd, p);
      if (fs.statSync(abs).isDirectory()) files.push(...findFiles(abs)); else files.push(abs);
    }
  } else files.push(...findFiles(path.resolve(cwd)));
  const ignore = (config.ignore || []).map((g) => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\0').replace(/\*/g, '[^/]*').replace(/\0/g, '.*') + '$'));
  const raw = [];
  const scanned = [];
  for (const abs of files) {
    const rel = path.relative(path.resolve(cwd), abs).split(path.sep).join('/');
    if (ignore.some((r) => r.test(rel))) continue;
    scanned.push(rel);
    raw.push(...scanText(fs.readFileSync(abs, 'utf8'), rel));
  }
  return { ...applyConfig(raw, config, now), files: scanned, config };
}
