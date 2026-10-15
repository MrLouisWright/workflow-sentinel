# workflow-sentinel

[![npm version](https://img.shields.io/npm/v/workflow-sentinel)](https://www.npmjs.com/package/workflow-sentinel)
[![CI](https://github.com/MrLouisWright/workflow-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/workflow-sentinel/actions/workflows/ci.yml)
[![Node](https://img.shields.io/node/v/workflow-sentinel)](https://www.npmjs.com/package/workflow-sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Catch insecure GitHub Actions workflows before they're merged.

`workflow-sentinel` reads your `.github/workflows/*.yml` and `action.yml` files and flags the patterns behind most real-world Actions compromises: mutable action tags, over-privileged tokens, `pull_request_target` "pwn requests", script injection, leaked secrets and more. Every finding includes a file and line number, a severity and a **concrete fix**. `--fix` pins your actions to commit SHAs for you.

CLI, library and GitHub Action. Node.js 18+, one small runtime dependency (`yaml`).

## Rules

| Rule | Severity | What it catches |
|---|---|---|
| `dangerous-checkout` | critical | `pull_request_target` / `workflow_run` that checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}`, `github.head_ref`, `refs/pull/…`, `gh pr checkout`) |
| `unpinned-action` | high | `uses:` with a tag or branch instead of a 40-char commit SHA (steps, reusable workflows, composite actions) |
| `broad-permissions` | high | `permissions: write-all` at workflow or job level. Top-level write scopes shared by several jobs are reported as low |
| `script-injection` | high (critical under `pull_request_target`) | `${{ github.event.issue.title }}`, `…pull_request.body`, `github.head_ref`, comment bodies, commit messages and similar values pasted into `run:` or `actions/github-script`. `${{ inputs.* }}` in composite actions is reported as medium |
| `secrets-untrusted` | high | Secrets used in a job that runs checked-out PR code. Echoing `${{ secrets.* }}` is reported as medium |
| `self-hosted-pr` | high | `runs-on: self-hosted` in a workflow triggered by pull requests or comments |
| `missing-permissions` | medium | No top-level `permissions:` and jobs without their own |
| `persist-credentials` | medium | `actions/checkout` without `persist-credentials: false` |
| `secrets-inherit` | medium | Reusable workflow called with `secrets: inherit` |
| `curl-pipe-shell` | medium | `curl … \| bash`, `wget -O- … \| sh`, `bash <(curl …)`, `sh -c "$(curl …)"` |
| `deprecated-command` | medium (high for `set-env`/`add-path`) | `::set-output`, `::save-state`, `::set-env`, `::add-path` |
| `docker-no-digest` | medium | `docker://` actions, `container:`, `services:` and Docker `action.yml` images without `@sha256:` |
| `cache-poisoning` | high | Untrusted `github.event.*` / branch names in `actions/cache` keys or paths (including via tainted `env`) |
| `artipacked` | medium | `upload-artifact` after checkout without `persist-credentials: false`, broad artifact paths, risky `download-artifact` in privileged workflows |
| `invalid-expression` | medium | Mistyped `${{ }}` contexts (`github.events`), properties unavailable for your `on:` triggers, unknown functions |
| `invalid-schema` | low | Unknown workflow/job/step keys (e.g. `job:` instead of `jobs:`), likely typos in action inputs |

## Install and run

```bash
npx workflow-sentinel                      # scan the current repository
npx workflow-sentinel .github/workflows/release.yml --fail-on medium
npx workflow-sentinel --trusted-owner actions --trusted-owner github
GH_TOKEN=... npx workflow-sentinel --fix   # pin every action to its current commit SHA (# v4 comment for Dependabot)
```

### Sample output

```text
workflow-sentinel — 3 file(s) scanned

.github/workflows/ci.yml
     1  MEDIUM   No top-level `permissions:`; job "test" runs with the default GITHUB_TOKEN scopes [missing-permissions]
        ↳ fix: Without a `permissions:` block the GITHUB_TOKEN gets the repository default, which may be read/write. Add `permissions: { contents: read }` at the top level and widen per job only where needed.
     9  HIGH     actions/checkout@v4 is pinned to "v4" (mutable tag), not a commit SHA [unpinned-action]
        ↳ fix: Pin it: `uses: actions/checkout@<40-char-sha> # v4` (or run `workflow-sentinel --fix`). Tags and branches are mutable; a compromised upstream can retag.
     9  MEDIUM   actions/checkout@v4 without `persist-credentials: false` in job "test" [persist-credentials]
        ↳ fix: Add to the step: `with: { persist-credentials: false }` (keep it only if a later step must `git push`).
...
9 high, 5 medium
✖ Failing (fail-on: high).
```

### Options

| Option | Description |
|---|---|
| `[paths…]` | Files or directories to scan (default: `.github/workflows` plus every `action.yml` under the current directory, skipping `node_modules`, `dist` and similar folders) |
| `--fail-on <sev>` | `critical`, `high` (default), `medium`, `low`, `info` or `none` |
| `--config <file>` | Config file path |
| `--trusted-owner <o>` | Allow tags for an owner (`actions`) or a repo (`github/codeql-action`). Repeatable |
| `--fix` / `--fix-dry-run` | Resolve each tag or branch to its commit SHA through the GitHub API (`GH_TOKEN` or `GITHUB_TOKEN`) and rewrite `uses:` as `owner/repo@<sha> # v4` (Dependabot-compatible SHA comments) |
| `--json [file]`, `--sarif <file>`, `--markdown <file>` | Reports |
| `--no-fixes`, `--no-color` | Text output tweaks |

**Exit codes:** `0` passed · `1` findings at or above `--fail-on` · `2` usage, config or runtime error.

## Configuration

Put the config in `.workflow-sentinel.json` (or a `"workflow-sentinel"` key in `package.json`):

```json
{
  "failOn": "high",
  "trustedOwners": ["actions", "github/codeql-action"],
  "rules": { "persist-credentials": "low", "curl-pipe-shell": "off" },
  "ignore": [".github/workflows/legacy-*.yml"],
  "allow": [
    "unpinned-action:my-org/*",
    { "rule": "persist-credentials", "file": ".github/workflows/release.yml", "reason": "pushes tags" },
    { "rule": "self-hosted-pr", "expires": "2026-12-31", "reason": "migrating runners" }
  ]
}
```

- **`rules`** sets a severity per rule, or `off`.
- **`allow`** matches on any combination of `rule`, `file` (glob) and `target` (an action like `actions/*`, or an image). `"rule:target"` is a shorthand. An entry stops applying after its `expires` date.
- **Inline:** add `# workflow-sentinel-ignore [rule …]` at the end of a line, or on its own line just above it.

Suppressed findings are counted in the summary and listed under `suppressed` in the JSON.

## GitHub Action

```yaml
name: Workflow security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  workflow-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with: { persist-credentials: false }
      - uses: MrLouisWright/workflow-sentinel@v1
        with:
          fail-on: high
          sarif: workflow-sentinel.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: workflow-sentinel.sarif }
```

Inputs: `paths`, `fail-on`, `config`, `trusted-owners` (space-separated), `sarif`, `json`, `job-summary` (default `true`) and `args`.

## Library

ESM and CommonJS (`require`) are both supported. TypeScript declarations are generated from source at build time.

```js
import { scan, scanText, formatSarif } from 'workflow-sentinel';
const { findings } = scan({ cwd: '.', config: { trustedOwners: ['actions'] } });
```

```js
const { scanText, validateExpression } = require('workflow-sentinel');
```

Tests live in [`test/`](test/) and run on every push in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (including import + `require` checks). Releases publish to npm with [`--provenance`](.github/workflows/release.yml).

## Limitations

This is a static, pattern-based linter. It doesn't follow data across jobs or into the scripts your workflows call, and it can't know which of your self-hosted runners are ephemeral. Treat a clean result as a good baseline, not a guarantee.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Credit (optional)

Free to use under MIT, no attribution required. If workflow-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with workflow-sentinel by Louis Wright</a>
```

```markdown
[![Built with workflow-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-workflow--sentinel-blue)](https://louiswright.co.uk)
```

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
