/** Taint-style checks: cache poisoning, artipacked, env propagation (zizmor-aligned). */
import { extractExpressions, isUntrustedExpression, referencesTaintedEnv } from './expressions.js';

const CACHE_ACTIONS = /^actions\/cache(?:\/|$|@)/i;
const UPLOAD_ARTIFACT = /^actions\/upload-artifact@/i;
const DOWNLOAD_ARTIFACT = /^actions\/download-artifact@/i;
const CHECKOUT = /^actions\/checkout@/i;

export function cacheKeyFields(withJs) {
  if (!withJs || typeof withJs !== 'object') return [];
  const out = [];
  if (withJs.key != null) out.push(['key', String(withJs.key)]);
  if (withJs.path != null) out.push(['path', String(withJs.path)]);
  const rk = withJs['restore-keys'];
  if (rk != null) {
    if (Array.isArray(rk)) rk.forEach((v, i) => out.push([`restore-keys[${i}]`, String(v)]));
    else out.push(['restore-keys', String(rk)]);
  }
  return out;
}

/** Returns finding messages for cache poisoning on a cache/restore step. */
export function checkCachePoisoning(uses, withJs, taintedEnv, untrustedRes) {
  const u = String(uses || '');
  if (!CACHE_ACTIONS.test(u)) return [];
  const hits = [];
  for (const [field, val] of cacheKeyFields(withJs)) {
    let bad = false;
    for (const { expr } of extractExpressions(val)) {
      if (isUntrustedExpression(expr, untrustedRes)) bad = true;
    }
    if (!bad && referencesTaintedEnv(val, taintedEnv)) bad = true;
    if (bad) hits.push({ field, value: val.slice(0, 80) });
  }
  return hits;
}

/** artipacked: credentials or PR output packaged into artifacts. */
export function checkArtipacked(ctx) {
  const findings = [];
  const { checkoutPersisted, hasUploadArtifact, hasDownloadArtifact, privileged, untrustedCheckout, uploadPaths } = ctx;

  if (hasUploadArtifact && checkoutPersisted === true) {
    findings.push({
      kind: 'checkout-upload',
      message: 'This job uploads artifacts after actions/checkout without `persist-credentials: false`; `.git/config` may contain the GITHUB_TOKEN',
    });
  }
  if (hasUploadArtifact && uploadPaths?.some((p) => /(?:^|[\s,])\.\s*$|\/\.git\b|\*\*/.test(p))) {
    findings.push({
      kind: 'broad-upload',
      message: 'upload-artifact uses a broad path (`.` or `**` or `.git`); narrow paths so tokens and checkout metadata are not archived',
    });
  }
  if (hasDownloadArtifact && privileged?.length && untrustedCheckout) {
    findings.push({
      kind: 'download-untrusted',
      message: `download-artifact runs in a ${privileged.join('/')} workflow that checks out untrusted code; verify artifact provenance before use`,
    });
  }
  return findings;
}

export { CACHE_ACTIONS, UPLOAD_ARTIFACT, DOWNLOAD_ARTIFACT, CHECKOUT };
