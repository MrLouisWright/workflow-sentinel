// Rule catalogue: id -> default severity, title, help.
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const sevRank = (s) => SEVERITIES.indexOf(s);

export const RULES = {
  'unpinned-action': { severity: 'high', title: 'Action not pinned to a full commit SHA',
    help: 'Tags and branches are mutable; a compromised upstream can retag. Pin to a 40-char commit SHA and keep the tag as a comment (run with --fix to do this automatically).' },
  'missing-permissions': { severity: 'medium', title: 'No explicit permissions',
    help: 'Without a `permissions:` block the GITHUB_TOKEN gets the repository default, which may be read/write. Add `permissions: { contents: read }` at the top level and widen per job only where needed.' },
  'broad-permissions': { severity: 'high', title: 'Overly broad permissions',
    help: 'Avoid `write-all` (and top-level write scopes). Grant the minimum scopes per job, e.g. `permissions: { contents: read }`.' },
  'dangerous-checkout': { severity: 'critical', title: 'Privileged trigger checks out untrusted PR code',
    help: '`pull_request_target`/`workflow_run` run with secrets and a write token; checking out the PR head lets attackers run code with those privileges ("pwn request"). Use `pull_request` instead, or never build/run the checked-out code and split privileged steps into a separate workflow.' },
  'script-injection': { severity: 'high', title: 'Untrusted input interpolated into a script',
    help: 'Attacker-controlled `${{ }}` values are pasted into the shell before it runs. Pass them through an environment variable instead: `env: { TITLE: ${{ github.event.issue.title }} }` then use "$TITLE".' },
  'secrets-inherit': { severity: 'medium', title: 'Reusable workflow called with `secrets: inherit`',
    help: 'Pass only the secrets the called workflow needs: `secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`.' },
  'secrets-untrusted': { severity: 'high', title: 'Secrets exposed to untrusted code or output',
    help: 'Do not expose secrets to jobs that run PR-controlled code, and never echo secrets. Move secret-using steps to a job that does not check out untrusted code.' },
  'persist-credentials': { severity: 'medium', title: 'actions/checkout persists credentials',
    help: 'actions/checkout leaves the GITHUB_TOKEN in .git/config for later steps (and artifacts). Add `with: { persist-credentials: false }` unless a later step needs to push.' },
  'self-hosted-pr': { severity: 'high', title: 'Self-hosted runner on a pull-request trigger',
    help: 'Pull requests from forks can run arbitrary code on persistent self-hosted runners. Use GitHub-hosted runners for PR workflows, or ephemeral, isolated runners with fork-PR approval required.' },
  'curl-pipe-shell': { severity: 'medium', title: 'Remote script piped into a shell',
    help: 'Download to a file, verify a checksum or signature, then execute — or use a pinned action/package instead of `curl | bash`.' },
  'deprecated-command': { severity: 'medium', title: 'Deprecated workflow command',
    help: 'Replace `::set-output` with `echo "name=value" >> "$GITHUB_OUTPUT"`, `::save-state` with `$GITHUB_STATE`, `::set-env` with `$GITHUB_ENV`, `::add-path` with `$GITHUB_PATH`.' },
  'docker-no-digest': { severity: 'medium', title: 'Docker image without a digest',
    help: 'Image tags are mutable. Pin to a digest: `image@sha256:<digest>` (get it with `docker buildx imagetools inspect <image>`).' },
  'parse-error': { severity: 'high', title: 'Workflow could not be parsed', help: 'Fix the YAML syntax.' },
};

// Expressions an attacker can control (fork PRs, issues, comments, branch names, commit messages...).
export const UNTRUSTED = [
  /github\.event\.issue\.(title|body)/, /github\.event\.pull_request\.(title|body)/,
  /github\.event\.pull_request\.head\.(ref|label|repo\.default_branch|repo\.description|repo\.homepage)/,
  /github\.event\.comment\.body/, /github\.event\.review\.body/, /github\.event\.review_comment\.body/,
  /github\.event\.discussion\.(title|body)/, /github\.event\.pages\.[^ }]*\.page_name/,
  /github\.event\.commits\.[^ }]*\.(message|author\.(email|name))/, /github\.event\.head_commit\.(message|author\.(email|name))/,
  /github\.event\.workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name))|head_repository\.description)/,
  /github\.event\.release\.(name|body|tag_name)/, /github\.event\.ref/, /github\.head_ref/,
  /github\.event\.(inputs|client_payload)\./, /github\.event\.check_suite\.head_branch/, /github\.event\.check_run\.(name|output)/,
];
