import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const BIN = path.resolve('bin/workflow-sentinel.js');
const cli = (args, cwd) => spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '' } });
function repo(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-'));
  for (const [p, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, p)), { recursive: true }); fs.writeFileSync(path.join(d, p), t); }
  return d;
}
const BAD = `on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo "\${{ github.event.pull_request.title }}"\n`;

test('help / version / bad args', () => {
  assert.match(cli(['--help']).stdout, /--fail-on/);
  assert.match(cli(['--version']).stdout, /^\d+\.\d+\.\d+/);
  assert.equal(cli(['--nope']).status, 2);
  assert.equal(cli(['--fail-on', 'extreme']).status, 2);
  assert.equal(cli(['does-not-exist']).status, 2);
});

test('scans .github/workflows and nested action.yml; exit codes and fail-on', () => {
  const d = repo({ '.github/workflows/ci.yml': BAD, 'actions/x/action.yml': 'name: x\nruns:\n  using: composite\n  steps:\n    - uses: foo/bar@main\n', 'node_modules/y/action.yml': 'runs: { using: composite, steps: [ { uses: z/z@v1 } ] }' });
  let r = cli([], d);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /2 file\(s\) scanned/);
  assert.match(r.stdout, /ci\.yml/);
  assert.match(r.stdout, /actions\/x\/action\.yml/);
  assert.match(r.stdout, /↳ fix:/);
  assert.doesNotMatch(r.stdout, /node_modules/);
  assert.equal(cli(['--fail-on', 'critical'], d).status, 0);
  assert.equal(cli(['--fail-on', 'none'], d).status, 0);
  r = cli(['--fail-on', 'critical', '--no-fixes'], d);
  assert.doesNotMatch(r.stdout, /↳ fix:/);
});

test('reports: json stdout, json/sarif/markdown files', () => {
  const d = repo({ '.github/workflows/ci.yml': BAD });
  const j = JSON.parse(cli(['--json'], d).stdout);
  assert.equal(j.exitCode, 1);
  assert.ok(j.summary.high >= 2);
  assert.ok(j.findings.every((f) => f.fix && f.file && f.line));
  cli(['--sarif', 's.sarif', '--markdown', 'r.md', '--json', 'r.json'], d);
  const s = JSON.parse(fs.readFileSync(path.join(d, 's.sarif'), 'utf8'));
  assert.equal(s.version, '2.1.0');
  assert.ok(s.runs[0].results.length >= 4);
  assert.ok(s.runs[0].tool.driver.rules.find((x) => x.id === 'dangerous-checkout').properties['security-severity']);
  assert.match(fs.readFileSync(path.join(d, 'r.md'), 'utf8'), /\| Severity \| Location/);
  assert.ok(JSON.parse(fs.readFileSync(path.join(d, 'r.json'), 'utf8')).findings.length);
});

test('config file: trusted owners, overrides, allowlist, ignore, failOn', () => {
  const d = repo({ '.github/workflows/ci.yml': BAD, '.github/workflows/legacy.yml': BAD });
  fs.writeFileSync(path.join(d, '.workflow-sentinel.json'), JSON.stringify({
    failOn: 'critical', trustedOwners: ['actions'], ignore: ['.github/workflows/legacy.yml'],
    rules: { 'missing-permissions': 'off' }, allow: [{ rule: 'persist-credentials', reason: 'needs push' }],
  }));
  const j = JSON.parse(cli(['--json'], d).stdout);
  assert.deepEqual(j.files, ['.github/workflows/ci.yml']);
  assert.deepEqual(j.findings.map((f) => f.rule), ['script-injection']);
  assert.equal(j.exitCode, 0);
  assert.equal(j.suppressed.length, 2);
  fs.writeFileSync(path.join(d, '.workflow-sentinel.json'), JSON.stringify({ rules: { bogus: 'high' } }));
  assert.equal(cli([], d).status, 2);
});

test('--trusted-owner flag and explicit file paths', () => {
  const d = repo({ 'w.yml': 'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/cache@v4\n' });
  assert.equal(cli(['w.yml'], d).status, 1);
  assert.equal(cli(['w.yml', '--trusted-owner', 'actions'], d).status, 0);
});

test('no files → exit 2', () => {
  assert.equal(cli([], repo({ 'README.md': 'x' })).status, 2);
});
