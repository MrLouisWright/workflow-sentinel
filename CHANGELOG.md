# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-13

### Added
- Scans `.github/workflows/*.yml|yaml` and every `action.yml|yaml` (composite and Docker actions) with line-accurate findings.
- Rules: `unpinned-action`, `missing-permissions`, `broad-permissions`, `dangerous-checkout` (pull_request_target / workflow_run pwn requests), `script-injection` (run: and github-script, composite inputs), `secrets-inherit`, `secrets-untrusted`, `persist-credentials`, `self-hosted-pr`, `curl-pipe-shell`, `deprecated-command`, `docker-no-digest`, `parse-error`.
- Five severities (critical/high/medium/low/info), `--fail-on`, exit codes 0/1/2; every finding carries a concrete fix.
- Config file with trusted owners, per-rule overrides, allowlist (rule/file/target globs, reason, expiry) and ignore globs; inline `# workflow-sentinel-ignore [rule]` comments.
- `--fix` / `--fix-dry-run`: pin actions and reusable workflows to commit SHAs via the GitHub API, keeping the tag as a comment.
- Text, JSON, SARIF 2.1.0 (with security-severity) and Markdown output.
- Composite GitHub Action with job summary; programmatic API with TypeScript types. One runtime dependency (`yaml`).
