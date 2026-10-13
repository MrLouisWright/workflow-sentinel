import fs from 'node:fs';
import path from 'node:path';
import { RULES, SEVERITIES } from './rules.js';

export const CONFIG_FILES = ['.workflow-sentinel.json', '.workflow-sentinelrc.json', '.workflow-sentinelrc'];
export const DEFAULTS = { failOn: 'high', trustedOwners: [], rules: {}, allow: [], ignore: [] };

export function loadConfig(dir = '.', explicit) {
  let cfg = {};
  const f = explicit || CONFIG_FILES.map((c) => path.join(dir, c)).find((p) => fs.existsSync(p));
  if (f) cfg = JSON.parse(fs.readFileSync(f, 'utf8'));
  else if (fs.existsSync(path.join(dir, 'package.json'))) { try { cfg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))['workflow-sentinel'] || {}; } catch { /* ignore */ } }
  for (const [k, v] of Object.entries(cfg.rules || {})) {
    if (!RULES[k]) throw new Error(`Unknown rule in config: ${k}`);
    if (v !== 'off' && !SEVERITIES.includes(v)) throw new Error(`Invalid level for ${k}: ${v}`);
  }
  return { ...DEFAULTS, ...cfg };
}

const globRe = (g) => new RegExp('^' + String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*').replace(/\?/g, '.') + '$');
const norm = (p) => p.split(path.sep).join('/').replace(/^\.\//, '');

/**
 * allow: [{ rule?, file?, target?, reason?, expires? }] or "rule" / "rule:target-glob"
 * target matches the action ("actions/checkout"), image, or nothing.
 */
export function isAllowed(allow, f, now = Date.now()) {
  for (let a of allow || []) {
    if (typeof a === 'string') { const [rule, target] = a.split(/:(.*)/s); a = { rule, target }; }
    if (a.expires && Date.parse(a.expires) < now) continue;
    if (a.rule && a.rule !== '*' && a.rule !== f.rule) continue;
    if (a.file && !globRe(norm(a.file)).test(norm(f.file))) continue;
    if (a.target && !(f.target && globRe(a.target).test(f.target))) continue;
    return true;
  }
  return false;
}

export function ownerTrusted(trusted, f) {
  if (f.rule !== 'unpinned-action' || !f.target) return false;
  return (trusted || []).some((t) => { const g = t.includes('/') ? t : `${t}/*`; return globRe(g).test(f.target) || globRe(g).test(f.target.split('/').slice(0, 2).join('/')); });
}
