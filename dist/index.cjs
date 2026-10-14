var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.js
var index_exports = {};
__export(index_exports, {
  RULES: () => RULES,
  SEVERITIES: () => SEVERITIES,
  UNTRUSTED: () => UNTRUSTED,
  applyConfig: () => applyConfig,
  exitCode: () => exitCode,
  extractExpressions: () => extractExpressions,
  findFiles: () => findFiles,
  fixFiles: () => fixFiles,
  formatJson: () => formatJson,
  formatMarkdown: () => formatMarkdown,
  formatSarif: () => formatSarif,
  formatText: () => formatText,
  isAllowed: () => isAllowed,
  loadConfig: () => loadConfig,
  pinText: () => pinText,
  resolveSha: () => resolveSha,
  scan: () => scan,
  scanText: () => scanText,
  validateExpression: () => validateExpression,
  validateWorkflowSchema: () => validateWorkflowSchema
});
module.exports = __toCommonJS(index_exports);
var import_node_fs4 = __toESM(require("node:fs"), 1);
var import_node_path4 = __toESM(require("node:path"), 1);

// src/scan.js
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);
var import_yaml2 = require("yaml");

// src/rules.js
var SEVERITIES = ["info", "low", "medium", "high", "critical"];
var sevRank = (s) => SEVERITIES.indexOf(s);
var RULES = {
  "unpinned-action": {
    severity: "high",
    title: "Action not pinned to a full commit SHA",
    help: "Tags and branches are mutable; a compromised upstream can retag. Pin to a 40-char commit SHA and keep the tag as a comment (run with --fix to do this automatically)."
  },
  "missing-permissions": {
    severity: "medium",
    title: "No explicit permissions",
    help: "Without a `permissions:` block the GITHUB_TOKEN gets the repository default, which may be read/write. Add `permissions: { contents: read }` at the top level and widen per job only where needed."
  },
  "broad-permissions": {
    severity: "high",
    title: "Overly broad permissions",
    help: "Avoid `write-all` (and top-level write scopes). Grant the minimum scopes per job, e.g. `permissions: { contents: read }`."
  },
  "dangerous-checkout": {
    severity: "critical",
    title: "Privileged trigger checks out untrusted PR code",
    help: '`pull_request_target`/`workflow_run` run with secrets and a write token; checking out the PR head lets attackers run code with those privileges ("pwn request"). Use `pull_request` instead, or never build/run the checked-out code and split privileged steps into a separate workflow.'
  },
  "script-injection": {
    severity: "high",
    title: "Untrusted input interpolated into a script",
    help: 'Attacker-controlled `${{ }}` values are pasted into the shell before it runs. Pass them through an environment variable instead: `env: { TITLE: ${{ github.event.issue.title }} }` then use "$TITLE".'
  },
  "secrets-inherit": {
    severity: "medium",
    title: "Reusable workflow called with `secrets: inherit`",
    help: "Pass only the secrets the called workflow needs: `secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`."
  },
  "secrets-untrusted": {
    severity: "high",
    title: "Secrets exposed to untrusted code or output",
    help: "Do not expose secrets to jobs that run PR-controlled code, and never echo secrets. Move secret-using steps to a job that does not check out untrusted code."
  },
  "persist-credentials": {
    severity: "medium",
    title: "actions/checkout persists credentials",
    help: "actions/checkout leaves the GITHUB_TOKEN in .git/config for later steps (and artifacts). Add `with: { persist-credentials: false }` unless a later step needs to push."
  },
  "self-hosted-pr": {
    severity: "high",
    title: "Self-hosted runner on a pull-request trigger",
    help: "Pull requests from forks can run arbitrary code on persistent self-hosted runners. Use GitHub-hosted runners for PR workflows, or ephemeral, isolated runners with fork-PR approval required."
  },
  "curl-pipe-shell": {
    severity: "medium",
    title: "Remote script piped into a shell",
    help: "Download to a file, verify a checksum or signature, then execute \u2014 or use a pinned action/package instead of `curl | bash`."
  },
  "deprecated-command": {
    severity: "medium",
    title: "Deprecated workflow command",
    help: 'Replace `::set-output` with `echo "name=value" >> "$GITHUB_OUTPUT"`, `::save-state` with `$GITHUB_STATE`, `::set-env` with `$GITHUB_ENV`, `::add-path` with `$GITHUB_PATH`.'
  },
  "docker-no-digest": {
    severity: "medium",
    title: "Docker image without a digest",
    help: "Image tags are mutable. Pin to a digest: `image@sha256:<digest>` (get it with `docker buildx imagetools inspect <image>`)."
  },
  "parse-error": { severity: "high", title: "Workflow could not be parsed", help: "Fix the YAML syntax." },
  "cache-poisoning": {
    severity: "high",
    title: "Untrusted input in cache key or path",
    help: "Cache keys must not include PR titles, branch names, or other attacker-controlled values (directly or via env). Use a fixed prefix plus `github.sha` or `github.run_id`, or restrict cache restore to trusted branches only."
  },
  "artipacked": {
    severity: "medium",
    title: "Artifact step may package credentials or untrusted output",
    help: "Set `persist-credentials: false` on actions/checkout before upload-artifact, use narrow `path:` values, and do not download artifacts from untrusted PR workflows into privileged jobs."
  },
  "invalid-expression": {
    severity: "medium",
    title: "Invalid or mistyped workflow expression",
    help: "Fix the `${{ }}` expression: use valid contexts (`github`, `env`, `matrix`, \u2026), match `github.event.*` to your workflow triggers, and fix typos (e.g. `github.events` \u2192 `github.event`)."
  },
  "invalid-schema": {
    severity: "low",
    title: "Unknown workflow YAML key",
    help: "Remove or rename the key to match the GitHub Actions workflow schema (see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)."
  }
};
var UNTRUSTED = [
  /github\.event\.issue\.(title|body)/,
  /github\.event\.pull_request\.(title|body)/,
  /github\.event\.pull_request\.head\.(ref|label|repo\.default_branch|repo\.description|repo\.homepage)/,
  /github\.event\.comment\.body/,
  /github\.event\.review\.body/,
  /github\.event\.review_comment\.body/,
  /github\.event\.discussion\.(title|body)/,
  /github\.event\.pages\.[^ }]*\.page_name/,
  /github\.event\.commits\.[^ }]*\.(message|author\.(email|name))/,
  /github\.event\.head_commit\.(message|author\.(email|name))/,
  /github\.event\.workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name))|head_repository\.description)/,
  /github\.event\.release\.(name|body|tag_name)/,
  /github\.event\.ref/,
  /github\.head_ref/,
  /github\.event\.(inputs|client_payload)\./,
  /github\.event\.check_suite\.head_branch/,
  /github\.event\.check_run\.(name|output)/
];

// src/expressions.js
var EXPR_RE = /\$\{\{([\s\S]*?)\}\}/g;
var EXPR_ROOTS = /* @__PURE__ */ new Set([
  "github",
  "env",
  "vars",
  "secrets",
  "strategy",
  "matrix",
  "inputs",
  "needs",
  "jobs",
  "steps",
  "runner"
]);
var EXPR_FUNCS = /* @__PURE__ */ new Set([
  "success",
  "failure",
  "cancelled",
  "always",
  "hashFiles",
  "format",
  "contains",
  "startsWith",
  "endsWith",
  "join",
  "toJSON",
  "fromJSON"
]);
var EVENT_FIELDS = {
  push: ["after", "before", "commits", "compare", "created", "deleted", "forced", "head_commit", "pusher", "ref", "repository"],
  pull_request: ["action", "number", "pull_request", "label", "assignee", "review", "changes"],
  pull_request_target: ["action", "number", "pull_request", "label", "assignee", "review", "changes"],
  issues: ["action", "issue", "assignee", "label", "changes"],
  issue_comment: ["action", "comment", "issue", "changes"],
  workflow_dispatch: ["inputs", "ref", "repository", "workflow"],
  workflow_call: ["inputs", "secrets"],
  workflow_run: ["action", "workflow_run", "workflow"],
  release: ["action", "release"],
  schedule: [],
  repository_dispatch: ["action", "client_payload"],
  push_tag: [],
  create: ["ref", "ref_type", "master_branch", "description", "pusher"],
  delete: ["ref", "ref_type"],
  fork: ["forkee", "repository"],
  watch: ["action", "repository", "sender"],
  discussion: ["action", "discussion", "answer", "label"],
  discussion_comment: ["action", "comment", "discussion"],
  pull_request_review: ["action", "review", "pull_request"],
  pull_request_review_comment: ["action", "comment", "pull_request", "changes"],
  check_run: ["action", "check_run", "check_suite", "requested_action"],
  check_suite: ["action", "check_suite"],
  registry_package: ["action", "registry_package", "repository"],
  page_build: ["build", "id", "pusher", "status"],
  public: ["repository"],
  status: ["action", "branches", "commit", "ref", "repository", "sender", "sha", "state"]
};
var GITHUB_TOP = /* @__PURE__ */ new Set([
  "action",
  "action_path",
  "action_ref",
  "action_repository",
  "action_status",
  "actor",
  "actor_id",
  "api_url",
  "base_ref",
  "env",
  "event",
  "event_name",
  "event_path",
  "graphql_url",
  "head_ref",
  "job",
  "output",
  "path",
  "ref",
  "ref_name",
  "ref_protected",
  "ref_type",
  "repository",
  "repository_id",
  "repository_owner",
  "repository_owner_id",
  "repositoryUrl",
  "retention_days",
  "run_id",
  "run_number",
  "run_attempt",
  "secret_source",
  "server_url",
  "sha",
  "token",
  "triggering_actor",
  "workflow",
  "workspace"
]);
var TYPO_ROOT = { events: "event", secret: "secrets", matix: "matrix", environ: "env", jobss: "jobs", step: "steps" };
var TYPO_GITHUB = { reposity: "repository", repositry: "repository", head_refs: "head_ref", base_refs: "base_ref" };
function extractExpressions(text) {
  const out = [];
  if (!text || typeof text !== "string") return out;
  for (const m of text.matchAll(EXPR_RE)) out.push({ expr: m[1].trim(), index: m.index, raw: m[0] });
  return out;
}
function validateExpression(expr, { triggers = [] } = {}) {
  const issues = [];
  if (!expr) return [{ kind: "empty", message: "Empty `${{ }}` expression" }];
  const stripped = expr.replace(/'([^'\\]|\\.)*'|"([^"\\]|\\.)*"/g, " ");
  for (const m of stripped.matchAll(/\b([A-Za-z_][\w]*)\s*\(/g)) {
    const fn = m[1];
    if (!EXPR_FUNCS.has(fn) && !EXPR_ROOTS.has(fn)) issues.push({ kind: "unknown-func", message: `Unknown function or context \`${fn}()\`` });
  }
  for (const m of stripped.matchAll(/\b([A-Za-z_][\w]*(?:\.[A-Za-z_*][\w*]*)*)/g)) {
    const chain = m[1];
    if (!chain.includes(".")) continue;
    const parts = chain.split(".");
    const root = parts[0];
    if (EXPR_FUNCS.has(root)) continue;
    if (TYPO_ROOT[root]) {
      issues.push({ kind: "typo", message: `\`${root}\` is not a valid expression root; did you mean \`${TYPO_ROOT[root]}\`?` });
      continue;
    }
    if (!EXPR_ROOTS.has(root)) {
      if (/^[A-Z]/.test(root)) continue;
      issues.push({ kind: "invalid-root", message: `\`${root}\` is not a recognized expression context (expected github, env, matrix, \u2026)` });
      continue;
    }
    if (root === "github") validateGithubChain(parts.slice(1), triggers, issues);
    else if (root === "secrets" && parts[1] === "GITHUB_TOKEN" && parts.length > 2) issues.push({ kind: "invalid-context", message: "secrets.GITHUB_TOKEN has no sub-properties" });
  }
  return issues;
}
function validateGithubChain(parts, triggers, issues) {
  if (!parts.length) return;
  const head = parts[0];
  if (TYPO_GITHUB[head]) {
    issues.push({ kind: "typo", message: `Unknown \`github.${head}\`; did you mean \`github.${TYPO_GITHUB[head]}\`?` });
    return;
  }
  if (head === "events") {
    issues.push({ kind: "typo", message: "Use `github.event` (singular), not `github.events`" });
    return;
  }
  if (head === "event") {
    if (parts.length === 1) return;
    const evField = parts[1];
    if (evField === "inputs" && !triggers.some((t) => t.startsWith("workflow_dispatch") || t === "workflow_call")) {
      issues.push({ kind: "invalid-context", message: "`github.event.inputs` is only set for workflow_dispatch and workflow_call triggers" });
    }
    if (evField === "pull_request" && !triggers.some((t) => /pull_request/.test(t))) {
      issues.push({ kind: "invalid-context", message: "`github.event.pull_request` is not available for this workflow's `on:` triggers" });
    }
    if (evField === "issue" && !triggers.some((t) => /issue/.test(t))) {
      issues.push({ kind: "invalid-context", message: "`github.event.issue` is not available for this workflow's `on:` triggers" });
    }
    if (EVENT_FIELDS[evField] && parts[2] && !EVENT_FIELDS[evField].includes(parts[2]) && evField !== "pull_request") {
      if (parts.length === 3 && !["head", "base", "user", "labels", "milestone"].includes(parts[2])) {
        issues.push({ kind: "unknown-field", message: `\`github.event.${evField}.${parts[2]}\` is not a usual field for the ${evField} payload` });
      }
    }
    return;
  }
  if (!GITHUB_TOP.has(head) && head !== "event") {
    issues.push({ kind: "unknown-github", message: `Unknown property \`github.${head}\`` });
  }
}
function isUntrustedExpression(expr, untrustedRes) {
  if (!expr) return false;
  for (const re of untrustedRes) if (re.test(expr)) return true;
  if (/github\.event\.(inputs|client_payload)\./.test(expr)) return true;
  if (/github\.(head_ref|event\.ref)\b/.test(expr)) return true;
  return false;
}
function taintFromEnvBlock(envJs, untrustedRes) {
  const tainted = /* @__PURE__ */ new Set();
  if (!envJs || typeof envJs !== "object") return tainted;
  for (const [k, v] of Object.entries(envJs)) {
    const s = String(v ?? "");
    for (const { expr } of extractExpressions(s)) {
      if (isUntrustedExpression(expr, untrustedRes)) tainted.add(k);
    }
  }
  return tainted;
}
function referencesTaintedEnv(text, tainted) {
  if (!text || !tainted.size) return false;
  const s = String(text);
  for (const name of tainted) {
    if (new RegExp(`\\benv\\.${name}\\b`).test(s)) return true;
    if (new RegExp(`\\$\\{\\{\\s*env\\.${name}\\s*\\}\\}`).test(s)) return true;
  }
  return false;
}

// src/schema.js
var import_yaml = require("yaml");
var WORKFLOW_KEYS = /* @__PURE__ */ new Set(["name", "on", "env", "defaults", "concurrency", "permissions", "jobs", "run-name", true]);
var JOB_KEYS = /* @__PURE__ */ new Set([
  "name",
  "runs-on",
  "needs",
  "if",
  "permissions",
  "env",
  "defaults",
  "strategy",
  "continue-on-error",
  "timeout-minutes",
  "steps",
  "uses",
  "with",
  "secrets",
  "outputs",
  "container",
  "services"
]);
var STEP_KEYS = /* @__PURE__ */ new Set([
  "id",
  "if",
  "name",
  "uses",
  "run",
  "env",
  "with",
  "working-directory",
  "continue-on-error",
  "timeout-minutes",
  "shell"
]);
var STRATEGY_KEYS = /* @__PURE__ */ new Set(["matrix", "fail-fast", "max-parallel"]);
var WITH_HINTS = {
  "actions/cache": /* @__PURE__ */ new Set(["path", "key", "restore-keys", "upload-chunk-size", "enableCrossOsArchive", "fail-on-cache-miss", "lookup-only", "save-always"]),
  "actions/cache/restore": /* @__PURE__ */ new Set(["path", "key", "restore-keys", "fail-on-cache-miss", "lookup-only"]),
  "actions/upload-artifact": /* @__PURE__ */ new Set(["name", "path", "if-no-files-found", "retention-days", "compression-level"]),
  "actions/download-artifact": /* @__PURE__ */ new Set(["name", "path", "pattern", "merge-multiple", "github-token"])
};
var KEY_TYPO = {
  job: "jobs",
  "runs-onn": "runs-on",
  "run-on": "runs-on",
  step: "steps",
  permission: "permissions",
  secrete: "secrets",
  secrets: "secrets",
  "working_directory": "working-directory",
  "timeout_minutes": "timeout-minutes",
  "continue_on_error": "continue-on-error"
};
function scalarKey(pair) {
  if (!pair?.key) return null;
  return (0, import_yaml.isScalar)(pair.key) ? pair.key.value : pair.key;
}
function validateWorkflowSchema(root, { isAction = false } = {}) {
  const issues = [];
  if (!(0, import_yaml.isMap)(root)) return issues;
  for (const p of root.items) {
    const k = scalarKey(p);
    if (k === void 0 || k === null) continue;
    if (!WORKFLOW_KEYS.has(k)) {
      const hint = KEY_TYPO[k];
      issues.push({
        key: k,
        message: hint ? `Unknown workflow key \`${k}\`; did you mean \`${hint}\`?` : `Unknown workflow key \`${k}\``
      });
    }
  }
  if (isAction) return issues;
  const jobs = root.items.find((p) => scalarKey(p) === "jobs")?.value;
  if ((0, import_yaml.isMap)(jobs)) {
    for (const jp of jobs.items) {
      if (!(0, import_yaml.isMap)(jp.value)) continue;
      const jobName = scalarKey(jp) ?? "?";
      for (const p of jp.value.items) {
        const k = scalarKey(p);
        if (k === void 0) continue;
        if (!JOB_KEYS.has(k)) {
          const hint = KEY_TYPO[k];
          issues.push({ key: k, job: jobName, message: hint ? `Job "${jobName}": unknown key \`${k}\`; did you mean \`${hint}\`?` : `Job "${jobName}": unknown key \`${k}\`` });
        }
        if (k === "strategy" && (0, import_yaml.isMap)(p.value)) validateNestedKeys(p.value, STRATEGY_KEYS, `Job "${jobName}" strategy`, issues);
        if (k === "steps" && p.value?.items) {
          p.value.items.forEach((st, i) => {
            if (!(0, import_yaml.isMap)(st)) return;
            for (const sp of st.items) {
              const sk = scalarKey(sp);
              if (sk === void 0) continue;
              if (!STEP_KEYS.has(sk)) {
                const hint = KEY_TYPO[sk];
                issues.push({
                  key: sk,
                  job: jobName,
                  step: i + 1,
                  message: hint ? `Job "${jobName}" step ${i + 1}: unknown key \`${sk}\`; did you mean \`${hint}\`?` : `Job "${jobName}" step ${i + 1}: unknown key \`${sk}\``
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
  if (!(0, import_yaml.isMap)(node)) return;
  for (const p of node.items) {
    const k = scalarKey(p);
    if (k !== void 0 && !allowed.has(k)) issues.push({ message: `${where}: unknown key \`${k}\`` });
  }
}
function validateActionInputs(uses, withNode) {
  const issues = [];
  if (!uses || !withNode || !(0, import_yaml.isMap)(withNode)) return issues;
  const action = String(uses).replace(/@.*$/, "").toLowerCase();
  const known = WITH_HINTS[action];
  if (!known) return issues;
  for (const p of withNode.items) {
    const k = scalarKey(p);
    if (k && !known.has(k) && !k.includes("-")) {
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

// src/taint.js
var CACHE_ACTIONS = /^actions\/cache(?:\/|$|@)/i;
var UPLOAD_ARTIFACT = /^actions\/upload-artifact@/i;
var DOWNLOAD_ARTIFACT = /^actions\/download-artifact@/i;
var CHECKOUT = /^actions\/checkout@/i;
function cacheKeyFields(withJs) {
  if (!withJs || typeof withJs !== "object") return [];
  const out = [];
  if (withJs.key != null) out.push(["key", String(withJs.key)]);
  if (withJs.path != null) out.push(["path", String(withJs.path)]);
  const rk = withJs["restore-keys"];
  if (rk != null) {
    if (Array.isArray(rk)) rk.forEach((v, i) => out.push([`restore-keys[${i}]`, String(v)]));
    else out.push(["restore-keys", String(rk)]);
  }
  return out;
}
function checkCachePoisoning(uses, withJs, taintedEnv, untrustedRes) {
  const u = String(uses || "");
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
function checkArtipacked(ctx) {
  const findings = [];
  const { checkoutPersisted, hasUploadArtifact, hasDownloadArtifact, privileged, untrustedCheckout, uploadPaths } = ctx;
  if (hasUploadArtifact && checkoutPersisted === true) {
    findings.push({
      kind: "checkout-upload",
      message: "This job uploads artifacts after actions/checkout without `persist-credentials: false`; `.git/config` may contain the GITHUB_TOKEN"
    });
  }
  if (hasUploadArtifact && uploadPaths?.some((p) => /(?:^|[\s,])\.\s*$|\/\.git\b|\*\*/.test(p))) {
    findings.push({
      kind: "broad-upload",
      message: "upload-artifact uses a broad path (`.` or `**` or `.git`); narrow paths so tokens and checkout metadata are not archived"
    });
  }
  if (hasDownloadArtifact && privileged?.length && untrustedCheckout) {
    findings.push({
      kind: "download-untrusted",
      message: `download-artifact runs in a ${privileged.join("/")} workflow that checks out untrusted code; verify artifact provenance before use`
    });
  }
  return findings;
}

// src/scan.js
var SHA_RE = /^[0-9a-f]{40}$/;
var EXPR_RE2 = /\$\{\{([\s\S]*?)\}\}/g;
var PR_TRIGGERS = ["pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment", "issue_comment", "workflow_run"];
function findFiles(root = ".") {
  const out = [];
  const wf = import_node_path.default.join(root, ".github", "workflows");
  if (import_node_fs.default.existsSync(wf)) {
    for (const f of import_node_fs.default.readdirSync(wf).sort()) if (/\.ya?ml$/.test(f)) out.push(import_node_path.default.join(wf, f));
  }
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let ents;
    try {
      ents = import_node_fs.default.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      if (e.isDirectory()) {
        if (!/^(node_modules|\.git|dist|build|coverage|vendor)$/.test(e.name) && !(dir === import_node_path.default.join(root, ".github") && e.name === "workflows")) walk(import_node_path.default.join(dir, e.name), depth + 1);
      } else if (/^action\.ya?ml$/.test(e.name)) out.push(import_node_path.default.join(dir, e.name));
    }
  };
  walk(root, 0);
  return [...new Set(out)];
}
function scanText(text, file, opts = {}) {
  const lc = new import_yaml2.LineCounter();
  const doc = (0, import_yaml2.parseDocument)(text, { lineCounter: lc, uniqueKeys: false, prettyErrors: false });
  const findings = [];
  const lines = text.split(/\r?\n/);
  if (doc.errors.length) {
    const e = doc.errors[0];
    return [mk("parse-error", file, e.linePos?.[0]?.line || 1, `YAML parse error: ${e.message.split("\n")[0]}`)];
  }
  const lineAt = (node) => node?.range ? lc.linePos(node.range[0]).line : 1;
  const get = (node, key) => (0, import_yaml2.isMap)(node) ? node.items.find((p) => ((0, import_yaml2.isScalar)(p.key) ? p.key.value : p.key) === key) : void 0;
  const val = (node, key) => get(node, key)?.value;
  const js = (node) => node && node.toJSON ? node.toJSON() : node;
  const add = (rule, node, message, extra = {}) => {
    const line = typeof node === "number" ? node : lineAt(node);
    if (suppressed(lines, line, rule)) return;
    findings.push(mk(rule, file, line, message, extra));
  };
  const root = doc.contents;
  if (!(0, import_yaml2.isMap)(root)) return findings;
  const isAction = /(^|[\\/])action\.ya?ml$/.test(file) && !get(root, "jobs");
  if (isAction) {
    const runs = val(root, "runs");
    const using = js(val(runs, "using"));
    if (using === "docker") {
      const img = val(runs, "image");
      const s = String(js(img) || "");
      if (s.startsWith("docker://") && !/@sha256:[0-9a-f]{64}/.test(s)) add("docker-no-digest", img, `Action image ${s} is not pinned to a digest`, { target: s });
    }
    const steps = val(runs, "steps");
    if ((0, import_yaml2.isSeq)(steps)) {
      const compositeCtx = { triggers: [], composite: true, job: null, taintedEnv: /* @__PURE__ */ new Set(), arti: null };
      for (const st of steps.items) checkStep(st, compositeCtx);
    }
    return findings;
  }
  const onNode = val(root, "on") ?? val(root, true);
  const onJs = js(onNode);
  const triggers = typeof onJs === "string" ? [onJs] : Array.isArray(onJs) ? onJs : onJs && typeof onJs === "object" ? Object.keys(onJs) : [];
  const privileged = triggers.filter((t) => t === "pull_request_target" || t === "workflow_run");
  const prTriggered = triggers.some((t) => PR_TRIGGERS.includes(t));
  for (const si of validateWorkflowSchema(root)) add("invalid-schema", root, si.message);
  scanExpressionsInNode(val(root, "env"), "Workflow env", triggers);
  scanExpressionsInNode(val(root, "run-name"), "run-name", triggers);
  const topPerm = get(root, "permissions");
  const jobs = val(root, "jobs");
  const permIssue = (p, where) => {
    const v = js(p.value);
    if (v === "write-all") add("broad-permissions", p.value, `${where} uses \`permissions: write-all\``);
    else if (where === "Workflow" && v && typeof v === "object" && (0, import_yaml2.isMap)(jobs) && jobs.items.length > 1) {
      const w = Object.entries(v).filter(([, x]) => x === "write").map(([k]) => k);
      if (w.length) add("broad-permissions", p.value, `Top-level permissions grant write to ${w.join(", ")} for every job; move write scopes to the jobs that need them`, { severity: "low" });
    }
  };
  if (topPerm) permIssue(topPerm, "Workflow");
  if ((0, import_yaml2.isMap)(jobs)) {
    const jobsWithout = [];
    for (const jp of jobs.items) {
      const jp_p = get(jp.value, "permissions");
      if (jp_p) permIssue(jp_p, `Job "${jp.key.value}"`);
      else if (!get(jp.value, "uses")) jobsWithout.push(jp);
    }
    if (!topPerm && jobsWithout.length)
      add("missing-permissions", onNode ? doc.contents.items[0].key : 1, `No top-level \`permissions:\`; ${jobsWithout.length === 1 ? `job "${jobsWithout[0].key.value}" runs` : `${jobsWithout.length} jobs run`} with the default GITHUB_TOKEN scopes`);
  }
  if ((0, import_yaml2.isMap)(jobs)) for (const jp of jobs.items) {
    const job = jp.value;
    const name = String(jp.key.value);
    const taintedEnv = taintFromEnvBlock(js(val(job, "env")), UNTRUSTED);
    const arti = { checkoutPersisted: null, hasUploadArtifact: false, hasDownloadArtifact: false, uploadPaths: [], privileged, untrustedCheckout: false };
    const ctx = { triggers, privileged, job: name, untrustedCheckout: false, taintedEnv, arti };
    scanExpressionsInNode(val(job, "env"), `Job "${name}" env`, triggers);
    const runsOn = js(val(job, "runs-on"));
    const labels = typeof runsOn === "string" ? [runsOn] : Array.isArray(runsOn) ? runsOn : runsOn?.labels ? [].concat(runsOn.labels) : [];
    if (prTriggered && labels.some((l) => /self-hosted/i.test(String(l))))
      add("self-hosted-pr", val(job, "runs-on"), `Job "${name}" runs on a self-hosted runner and the workflow is triggered by ${triggers.filter((t) => PR_TRIGGERS.includes(t)).join(", ")}`);
    const uses = val(job, "uses");
    if (uses) checkUses(uses, ctx);
    const sec = val(job, "secrets");
    if (sec && js(sec) === "inherit") add("secrets-inherit", sec, `Job "${name}" passes all secrets to ${js(uses)} with \`secrets: inherit\``);
    for (const k of ["container"]) {
      const c = val(job, k);
      const img = (0, import_yaml2.isMap)(c) ? val(c, "image") : c;
      if (img) dockerImage(img, `Job "${name}" container`);
    }
    const services = val(job, "services");
    if ((0, import_yaml2.isMap)(services)) for (const sp of services.items) {
      const img = (0, import_yaml2.isMap)(sp.value) ? val(sp.value, "image") : null;
      if (img) dockerImage(img, `Service "${sp.key.value}" in job "${name}"`);
    }
    const steps = val(job, "steps");
    if ((0, import_yaml2.isSeq)(steps)) {
      for (const st of steps.items) if (privileged.length && untrustedCheckout(st)) ctx.untrustedCheckout = true;
      for (const st of steps.items) checkStep(st, ctx);
      arti.untrustedCheckout = ctx.untrustedCheckout;
      for (const af of checkArtipacked(arti)) add("artipacked", steps.items[0], af.message);
      if (ctx.untrustedCheckout) {
        const secretRefs = [];
        for (const st of steps.items) {
          const t = js(st);
          if (/\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)/.test(JSON.stringify(t))) secretRefs.push(st);
        }
        if (secretRefs.length) add("secrets-untrusted", secretRefs[0], `Job "${name}" checks out PR code under ${privileged.join("/")} and also uses repository secrets in ${secretRefs.length} step(s)`);
      }
    }
  }
  return findings;
  function untrustedCheckout(st) {
    const u = String(js(val(st, "uses")) || "");
    const w = js(val(st, "with")) || {};
    const ref = String(w.ref ?? "") + " " + String(w.repository ?? "");
    const headRe = /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\/|github\.event\.pull_request\.merge_commit_sha|github\.event\.number|head\.repo\.full_name|workflow_run\.head_repository/;
    if (/^actions\/checkout@/i.test(u) && headRe.test(ref)) return true;
    const run = String(js(val(st, "run")) || "");
    if (/\b(gh pr checkout|git (fetch|checkout|pull)\b[^\n]*(pull\/|head_ref|head\.ref|head\.sha|head_sha|head_branch))/.test(run)) return true;
    return false;
  }
  function checkUses(node, ctx) {
    const u = String(js(node) || "").trim();
    if (!u || u.startsWith("./") || u.startsWith(".\\")) return;
    if (u.startsWith("docker://")) {
      dockerImage(node, "Step", true);
      return;
    }
    const at = u.lastIndexOf("@");
    const ref = at === -1 ? "" : u.slice(at + 1);
    const action = at === -1 ? u : u.slice(0, at);
    if (!SHA_RE.test(ref)) {
      const owner = action.split("/")[0];
      add("unpinned-action", node, `${u} is pinned to ${ref ? `"${ref}" (mutable ${/^v?\d+(\.\d+)*$/.test(ref) ? "tag" : "ref"})` : "nothing"}, not a commit SHA`, { target: action, ref, owner, fix: `Pin it: \`uses: ${action}@<40-char-sha> # ${ref || "latest"}\` (or run \`workflow-sentinel --fix\`). ${RULES["unpinned-action"].help.split(". ")[0]}.` });
    }
  }
  function dockerImage(node, where, isUses = false) {
    const s = String(js(node) || "");
    if (!s || /\$\{\{/.test(s)) return;
    if (!/@sha256:[0-9a-f]{64}/.test(s)) add("docker-no-digest", node, `${where} image ${s.replace(/^docker:\/\//, "")} is not pinned to a digest`, { target: s });
  }
  function scanExpressionsInNode(node, where, trigs) {
    if (!node) return;
    const text2 = String(js(node) ?? "");
    const base = lineAt(node);
    for (const { expr, index } of extractExpressions(text2)) {
      for (const iss of validateExpression(expr, { triggers: trigs })) {
        const line = base + text2.slice(0, index).split("\n").length - 1;
        add("invalid-expression", line, `${where}: ${iss.message} (\`${expr.slice(0, 60)}\`)`);
      }
    }
  }
  function mergeTaintFromStepEnv(st, ctx) {
    const envNode = val(st, "env");
    if (!envNode || !ctx.taintedEnv) return;
    for (const n of taintFromEnvBlock(js(envNode), UNTRUSTED)) ctx.taintedEnv.add(n);
    scanExpressionsInNode(envNode, ctx.job ? `Job "${ctx.job}" step env` : "Step env", ctx.triggers);
  }
  function checkStep(st, ctx) {
    if (!(0, import_yaml2.isMap)(st)) return;
    mergeTaintFromStepEnv(st, ctx);
    const usesNode = val(st, "uses");
    const u = String(js(usesNode) || "");
    const withNode = val(st, "with");
    const withJs = js(withNode) || {};
    if (usesNode) {
      checkUses(usesNode, ctx);
      for (const ai of validateActionInputs(u, withNode)) add("invalid-schema", withNode || usesNode, ai.message);
    }
    if (withNode) scanExpressionsInNode(withNode, ctx.job ? `Job "${ctx.job}" with` : "Step with", ctx.triggers);
    if (ctx.taintedEnv && CACHE_ACTIONS.test(u)) {
      for (const hit of checkCachePoisoning(u, withJs, ctx.taintedEnv, UNTRUSTED))
        add(
          "cache-poisoning",
          val(withNode, hit.field === "key" ? "key" : hit.field.startsWith("restore") ? "restore-keys" : "path") || withNode || usesNode,
          `Cache ${hit.field} includes untrusted input${ctx.job ? ` (job "${ctx.job}")` : ""}: ${hit.value}`
        );
    }
    if (ctx.arti && UPLOAD_ARTIFACT.test(u)) {
      ctx.arti.hasUploadArtifact = true;
      const paths = withJs.path;
      if (paths != null) ctx.arti.uploadPaths.push(...(Array.isArray(paths) ? paths : [paths]).map(String));
    }
    if (ctx.arti && DOWNLOAD_ARTIFACT.test(u)) ctx.arti.hasDownloadArtifact = true;
    if (CHECKOUT.test(u)) {
      const w = js(val(st, "with")) || {};
      const persisted = !(w["persist-credentials"] === false || w["persist-credentials"] === "false");
      if (ctx.arti && persisted) ctx.arti.checkoutPersisted = true;
      if (!(w["persist-credentials"] === false || w["persist-credentials"] === "false"))
        add("persist-credentials", usesNode, `${u} without \`persist-credentials: false\`${ctx.job ? ` in job "${ctx.job}"` : ""}`, { fix: "Add to the step: `with: { persist-credentials: false }` (keep it only if a later step must `git push`)." });
      if (ctx.privileged?.length && untrustedCheckout(st))
        add("dangerous-checkout", val(val(st, "with"), "ref") || usesNode, `Job "${ctx.job}" checks out the pull request head (${String(w.ref)}) in a ${ctx.privileged.join("/")} workflow`);
    } else if (ctx.privileged?.length && untrustedCheckout(st)) {
      add("dangerous-checkout", val(st, "run"), `Job "${ctx.job}" fetches/checks out PR code in a run step of a ${ctx.privileged.join("/")} workflow`);
    }
    const scripts = [];
    const runNode = val(st, "run");
    if (runNode) scripts.push(["run", runNode]);
    if (/^actions\/github-script@/i.test(u)) {
      const sn = val(val(st, "with"), "script");
      if (sn) scripts.push(["script", sn]);
    }
    for (const [kind, n] of scripts) {
      const text2 = String(js(n) ?? "");
      const base = lineAt(n);
      const offset = (0, import_yaml2.isScalar)(n) && (n.type === "BLOCK_LITERAL" || n.type === "BLOCK_FOLDED") ? 1 : 0;
      const lineOf = (idx) => base + offset + text2.slice(0, idx).split("\n").length - 1;
      for (const m of text2.matchAll(EXPR_RE2)) {
        const expr = m[1].trim();
        for (const iss of validateExpression(expr, { triggers: ctx.triggers })) {
          add("invalid-expression", lineOf(m.index), `${iss.message} in ${kind === "run" ? "run:" : "github-script"}${ctx.job ? ` (job "${ctx.job}")` : ""} (\`${expr.slice(0, 60)}\`)`);
        }
        const bad = UNTRUSTED.find((re) => re.test(expr));
        const isInput = ctx.composite && /\binputs\./.test(expr);
        const envName = expr.replace(/^.*\./, "").replace(/[^A-Za-z0-9]+/g, "_").toUpperCase() || "VALUE";
        const fix = `Move it to an env var: \`env: { ${envName}: \${{ ${expr} }} }\` and reference ${kind === "run" ? `"$${envName}"` : `process.env.${envName}`} in the script.`;
        if (bad) add("script-injection", lineOf(m.index), `\${{ ${expr} }} is interpolated into ${kind === "run" ? "a run: script" : "github-script"}${ctx.job ? ` (job "${ctx.job}")` : ""}`, { fix, ...ctx.privileged?.length ? { severity: "critical" } : {} });
        else if (isInput) add("script-injection", lineOf(m.index), `\${{ ${expr} }} (action input) is interpolated into a composite run: script; callers may pass untrusted data`, { severity: "medium", fix });
        if (/\bsecrets\.[A-Za-z_]/.test(expr) && /\b(echo|printf|cat)\b[^\n]*$/.test(text2.slice(text2.lastIndexOf("\n", m.index) + 1, m.index)))
          add("secrets-untrusted", lineOf(m.index), `\${{ ${expr} }} is echoed in a script and may leak into logs or files`, { severity: "medium" });
      }
      if (kind !== "run") continue;
      const lns = text2.split("\n");
      lns.forEach((l, i) => {
        const L = base + offset + i;
        if (/\b(curl|wget)\b[^|#]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b/.test(l) || /\b(ba)?sh\s+(-c\s+)?["']?\$\((curl|wget)\b/.test(l) || /\b(bash|sh)\s+<\(\s*(curl|wget)/.test(l))
          add("curl-pipe-shell", L, `Remote script piped to a shell: ${l.trim().slice(0, 100)}`);
        const dm = l.match(/::(set-output|save-state|set-env|add-path)\b/);
        if (dm) add("deprecated-command", L, `Deprecated \`::${dm[1]}\` workflow command`, /set-env|add-path/.test(dm[1]) ? { severity: "high" } : {});
      });
    }
  }
}
function suppressed(lines, line, rule) {
  const re = /#\s*workflow-sentinel-(?:ignore|disable)(?:\s+([\w,\s-]+))?/;
  for (const l of [lines[line - 1], lines[line - 2]]) {
    const m = l && l.match(re);
    if (m && (!m[1] || m[1].split(/[\s,]+/).filter(Boolean).includes(rule))) {
      if (l === lines[line - 2] && !/^\s*#/.test(l)) continue;
      return true;
    }
  }
  return false;
}
function mk(rule, file, line, message, extra = {}) {
  const { severity, ...rest } = extra;
  return { rule, severity: severity || RULES[rule].severity, title: RULES[rule].title, file, line, message, fix: RULES[rule].help, ...rest };
}

// src/config.js
var import_node_fs2 = __toESM(require("node:fs"), 1);
var import_node_path2 = __toESM(require("node:path"), 1);
var CONFIG_FILES = [".workflow-sentinel.json", ".workflow-sentinelrc.json", ".workflow-sentinelrc"];
var DEFAULTS = { failOn: "high", trustedOwners: [], rules: {}, allow: [], ignore: [] };
function loadConfig(dir = ".", explicit) {
  let cfg = {};
  const f = explicit || CONFIG_FILES.map((c) => import_node_path2.default.join(dir, c)).find((p) => import_node_fs2.default.existsSync(p));
  if (f) cfg = JSON.parse(import_node_fs2.default.readFileSync(f, "utf8"));
  else if (import_node_fs2.default.existsSync(import_node_path2.default.join(dir, "package.json"))) {
    try {
      cfg = JSON.parse(import_node_fs2.default.readFileSync(import_node_path2.default.join(dir, "package.json"), "utf8"))["workflow-sentinel"] || {};
    } catch {
    }
  }
  for (const [k, v] of Object.entries(cfg.rules || {})) {
    if (!RULES[k]) throw new Error(`Unknown rule in config: ${k}`);
    if (v !== "off" && !SEVERITIES.includes(v)) throw new Error(`Invalid level for ${k}: ${v}`);
  }
  return { ...DEFAULTS, ...cfg };
}
var globRe = (g) => new RegExp("^" + String(g).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\0").replace(/\*/g, "[^/]*").replace(/\u0000/g, ".*").replace(/\?/g, ".") + "$");
var norm = (p) => p.split(import_node_path2.default.sep).join("/").replace(/^\.\//, "");
function isAllowed(allow, f, now = Date.now()) {
  for (let a of allow || []) {
    if (typeof a === "string") {
      const [rule, target] = a.split(/:(.*)/s);
      a = { rule, target };
    }
    if (a.expires && Date.parse(a.expires) < now) continue;
    if (a.rule && a.rule !== "*" && a.rule !== f.rule) continue;
    if (a.file && !globRe(norm(a.file)).test(norm(f.file))) continue;
    if (a.target && !(f.target && globRe(a.target).test(f.target))) continue;
    return true;
  }
  return false;
}
function ownerTrusted(trusted, f) {
  if (f.rule !== "unpinned-action" || !f.target) return false;
  return (trusted || []).some((t) => {
    const g = t.includes("/") ? t : `${t}/*`;
    return globRe(g).test(f.target) || globRe(g).test(f.target.split("/").slice(0, 2).join("/"));
  });
}

// src/format.js
function exitCode(result, failOn = "high") {
  if (failOn === "none") return 0;
  return result.findings.some((f) => sevRank(f.severity) >= sevRank(failOn)) ? 1 : 0;
}
var counts = (fs5) => Object.fromEntries(SEVERITIES.slice().reverse().map((s) => [s, fs5.filter((f) => f.severity === s).length]));
function formatText(result, { color = false, failOn = "high", fixes = true } = {}) {
  const c = (code, s) => color ? `\x1B[${code}m${s}\x1B[0m` : s;
  const sc = { critical: "35;1", high: "31;1", medium: "33;1", low: "36", info: "2" };
  const out = [`${c("1", "workflow-sentinel")} \u2014 ${result.files.length} file(s) scanned`];
  let cur = null;
  const byLoc = result.findings.slice().sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || sevRank(b.severity) - sevRank(a.severity));
  for (const f of byLoc) {
    if (f.file !== cur) {
      cur = f.file;
      out.push("", c("4", f.file));
    }
    out.push(`  ${String(f.line).padStart(4)}  ${c(sc[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.message} ${c("2", `[${f.rule}]`)}`);
    if (fixes) out.push(`        ${c("32", "\u21B3 fix:")} ${f.fix}`);
  }
  if (!result.findings.length) out.push(c("32", "\u2714 No workflow hardening issues found."));
  const n = counts(result.findings);
  out.push("", Object.entries(n).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(", ") + (result.findings.length ? "" : "0 findings") + (result.suppressed?.length ? ` \xB7 ${result.suppressed.length} allowlisted` : ""));
  const fail = exitCode(result, failOn);
  out.push(fail ? c("31;1", `\u2716 Failing (fail-on: ${failOn}).`) : c("32", `Passing (fail-on: ${failOn}).`));
  return out.join("\n") + "\n";
}
function formatJson(result, meta = {}) {
  return JSON.stringify({ tool: "workflow-sentinel", ...meta, summary: counts(result.findings), files: result.files, findings: result.findings, suppressed: result.suppressed }, null, 2) + "\n";
}
function formatMarkdown(result) {
  const icon = { critical: "\u{1F7E3}", high: "\u{1F534}", medium: "\u{1F7E0}", low: "\u{1F535}", info: "\u26AA" };
  const out = ["## workflow-sentinel", ""];
  if (!result.findings.length) out.push(`\u2705 No workflow hardening issues in ${result.files.length} file(s).`);
  else {
    out.push(Object.entries(counts(result.findings)).filter(([, v]) => v).map(([k, v]) => `${icon[k]} ${v} ${k}`).join(" \xB7 "), "", "| Severity | Location | Issue | Fix |", "|---|---|---|---|");
    const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
    for (const f of result.findings) out.push(`| ${icon[f.severity]} ${f.severity} | \`${f.file}:${f.line}\` | ${esc(f.message)} (\`${f.rule}\`) | ${esc(f.fix)} |`);
  }
  return out.join("\n") + "\n";
}
function formatSarif(result, { version = "0.0.0" } = {}) {
  const lvl = (s) => sevRank(s) >= 3 ? "error" : sevRank(s) === 2 ? "warning" : "note";
  const secSev = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "workflow-sentinel",
        version,
        informationUri: "https://github.com/MrLouisWright/workflow-sentinel",
        rules: Object.entries(RULES).map(([id, r]) => ({ id, name: id, shortDescription: { text: r.title }, help: { text: r.help }, defaultConfiguration: { level: lvl(r.severity) }, properties: { "security-severity": secSev[r.severity], tags: ["security", "github-actions"] } }))
      } },
      results: result.findings.map((f) => ({
        ruleId: f.rule,
        level: lvl(f.severity),
        message: { text: `${f.message}. Fix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        partialFingerprints: { workflowSentinel: `${f.rule}:${f.file}:${f.target || f.message}` },
        properties: { severity: f.severity }
      }))
    }]
  }, null, 2) + "\n";
}

// src/fix.js
var import_node_fs3 = __toESM(require("node:fs"), 1);
var import_node_path3 = __toESM(require("node:path"), 1);
var USES_RE = /^(\s*-?\s*uses:\s*)(["']?)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[^@\s"']+)?)@([^\s"'#]+)\2([ \t]*#.*)?$/;
async function resolveSha(action, ref, { token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN, fetchImpl = globalThis.fetch, api = "https://api.github.com" } = {}) {
  const repo = action.split("/").slice(0, 2).join("/");
  const headers = { accept: "application/vnd.github.sha", "user-agent": "workflow-sentinel", "x-github-api-version": "2022-11-28" };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetchImpl(`${api}/repos/${repo}/commits/${encodeURIComponent(ref)}`, { headers });
  if (!res.ok) throw new Error(`cannot resolve ${repo}@${ref}: HTTP ${res.status}`);
  const sha = (await res.text()).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`unexpected response resolving ${repo}@${ref}`);
  return sha;
}
async function pinText(text, resolve) {
  const lines = text.split("\n");
  const changes = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].replace(/\r$/, "").match(USES_RE);
    if (!m) continue;
    const [, pre, q, action, ref, comment] = m;
    if (/^[0-9a-f]{40}$/.test(ref) || action.startsWith(".") || /\$\{\{/.test(ref)) continue;
    let sha;
    try {
      sha = await resolve(action, ref);
    } catch (e) {
      changes.push({ line: i + 1, action, ref, error: e.message });
      continue;
    }
    const cr = lines[i].endsWith("\r") ? "\r" : "";
    const tagComment = comment?.trim() || `# ${ref}`;
    lines[i] = `${pre}${q}${action}@${sha}${q}${tagComment.startsWith("#") ? ` ${tagComment}` : ` # ${tagComment}`}${cr}`;
    changes.push({ line: i + 1, action, ref, sha });
  }
  return { text: lines.join("\n"), changes };
}
async function fixFiles(files, { cwd = ".", resolver, dryRun = false, ...opts } = {}) {
  const cache = /* @__PURE__ */ new Map();
  const resolve = resolver || ((a, r) => {
    const k = `${a.split("/").slice(0, 2).join("/")}@${r}`;
    if (!cache.has(k)) cache.set(k, resolveSha(a, r, opts));
    return cache.get(k);
  });
  const report = [];
  for (const f of files) {
    const abs = import_node_path3.default.resolve(cwd, f);
    const before = import_node_fs3.default.readFileSync(abs, "utf8");
    const { text, changes } = await pinText(before, resolve);
    if (changes.length) report.push({ file: f, changes });
    if (!dryRun && text !== before) import_node_fs3.default.writeFileSync(abs, text);
  }
  return report;
}

// src/index.js
function applyConfig(raw, config = {}, now = Date.now()) {
  const findings = [], suppressed2 = [];
  for (const f0 of raw) {
    const o = config.rules?.[f0.rule];
    if (o === "off") continue;
    const f = o ? { ...f0, severity: o } : f0;
    if (ownerTrusted(config.trustedOwners, f) || isAllowed(config.allow, f, now)) suppressed2.push(f);
    else findings.push(f);
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { findings, suppressed: suppressed2 };
}
function scan({ cwd = ".", paths, config: override = {}, configPath, now } = {}) {
  const config = { ...loadConfig(cwd, configPath), ...override };
  const files = [];
  if (paths && paths.length) {
    for (const p of paths) {
      const abs = import_node_path4.default.resolve(cwd, p);
      if (import_node_fs4.default.statSync(abs).isDirectory()) files.push(...findFiles(abs));
      else files.push(abs);
    }
  } else files.push(...findFiles(import_node_path4.default.resolve(cwd)));
  const ignore = (config.ignore || []).map((g) => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\0").replace(/\*/g, "[^/]*").replace(/\0/g, ".*") + "$"));
  const raw = [];
  const scanned = [];
  for (const abs of files) {
    const rel = import_node_path4.default.relative(import_node_path4.default.resolve(cwd), abs).split(import_node_path4.default.sep).join("/");
    if (ignore.some((r) => r.test(rel))) continue;
    scanned.push(rel);
    raw.push(...scanText(import_node_fs4.default.readFileSync(abs, "utf8"), rel));
  }
  return { ...applyConfig(raw, config, now), files: scanned, config };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  RULES,
  SEVERITIES,
  UNTRUSTED,
  applyConfig,
  exitCode,
  extractExpressions,
  findFiles,
  fixFiles,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  isAllowed,
  loadConfig,
  pinText,
  resolveSha,
  scan,
  scanText,
  validateExpression,
  validateWorkflowSchema
});
//# sourceMappingURL=index.cjs.map
