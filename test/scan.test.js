import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText, applyConfig, isAllowed } from '../src/index.js';

const SHA = 'a'.repeat(40);
const rules = (fs) => fs.map((f) => f.rule);
const only = (fs, r) => fs.filter((f) => f.rule === r);
const scan = (t, file = '.github/workflows/x.yml') => scanText(t, file);

const CLEAN = `name: ok
on: [push]
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA} # v4
        with:
          persist-credentials: false
      - uses: ./local-action
      - run: echo "hello \${{ github.sha }}"
`;

test('clean workflow has no findings', () => {
  assert.deepEqual(scan(CLEAN), []);
});

test('unpinned actions: tags, branches, missing ref; SHA and local are fine', () => {
  const f = scan(`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - uses: someone/thing@main
      - uses: "org/repo/sub/path@v1.2.3"
      - uses: org/pinned@${SHA}
      - uses: ./x
  b:
    uses: org/wf/.github/workflows/r.yml@v1
`);
  const u = only(f, 'unpinned-action');
  assert.deepEqual(u.map((x) => x.target), ['actions/setup-node', 'someone/thing', 'org/repo/sub/path', 'org/wf/.github/workflows/r.yml']);
  assert.deepEqual(u.map((x) => x.line), [7, 8, 9, 13]);
  assert.match(u[0].fix, /actions\/setup-node@<40-char-sha> # v4/);
  assert.match(u[1].message, /mutable ref/);
});

test('trusted owners and allowlist suppress', () => {
  const f = scan(`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - uses: github/codeql-action/upload-sarif@v3
      - uses: someone/thing@main
`);
  const r = applyConfig(f, { trustedOwners: ['actions', 'github/codeql-action'] });
  assert.deepEqual(r.findings.map((x) => x.target), ['someone/thing']);
  assert.equal(r.suppressed.length, 2);
  const r2 = applyConfig(f, { allow: ['unpinned-action:someone/*', { rule: 'unpinned-action', target: 'actions/*', expires: '2000-01-01' }] });
  assert.deepEqual(r2.findings.map((x) => x.target).sort(), ['actions/setup-node', 'github/codeql-action/upload-sarif']);
  const r3 = applyConfig(f, { rules: { 'unpinned-action': 'low' } });
  assert.ok(r3.findings.every((x) => x.severity === 'low'));
  assert.equal(applyConfig(f, { rules: { 'unpinned-action': 'off' } }).findings.length, 0);
  assert.ok(isAllowed([{ file: '.github/workflows/*.yml' }], { rule: 'x', file: '.github/workflows/a.yml' }));
  assert.ok(!isAllowed([{ file: 'other/*.yml' }], { rule: 'x', file: '.github/workflows/a.yml' }));
});

test('permissions: missing, write-all, top-level write', () => {
  const base = (p) => `on: push\n${p}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n`;
  assert.deepEqual(rules(scan(base(''))), ['missing-permissions']);
  assert.deepEqual(rules(scan(base('permissions: write-all\n'))), ['broad-permissions']);
  const w = scan(base('permissions:\n  contents: write\n  pull-requests: read\n'));
  assert.equal(w[0].rule, 'broad-permissions');
  assert.equal(w[0].severity, 'low');
  assert.match(w[0].message, /contents/);
  assert.deepEqual(scan(`on: push\npermissions:\n  contents: write\njobs:\n  only:\n    runs-on: x\n    steps:\n      - run: true\n`), [], 'single job: top-level write is fine');
  // job-level permissions everywhere → fine
  assert.deepEqual(scan(`on: push\njobs:\n  a:\n    runs-on: x\n    permissions:\n      contents: read\n    steps:\n      - run: true\n`), []);
  const jw = scan(`on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    permissions: write-all\n    steps:\n      - run: true\n`);
  assert.equal(jw[0].rule, 'broad-permissions');
  assert.match(jw[0].message, /Job "a"/);
});

test('pull_request_target pwn request + secrets', () => {
  const f = scan(`on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          ref: \${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: npm ci && npm test
        env:
          NPM_TOKEN: \${{ secrets.NPM_TOKEN }}
`);
  assert.deepEqual(rules(f).sort(), ['dangerous-checkout', 'secrets-untrusted']);
  assert.equal(only(f, 'dangerous-checkout')[0].severity, 'critical');
  assert.equal(only(f, 'dangerous-checkout')[0].line, 12);
});

test('workflow_run + gh pr checkout; pull_request_target without head checkout is fine', () => {
  const f = scan(`on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: { contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout \${{ github.event.workflow_run.pull_requests[0].number }}
`);
  assert.ok(rules(f).includes('dangerous-checkout'));
  const ok = scan(`on: pull_request_target
permissions: { pull-requests: write }
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@${SHA}
`);
  assert.deepEqual(ok, []);
});

test('script injection in run and github-script, with line numbers', () => {
  const f = scan(`on: issues
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "ok"
          echo "\${{ github.event.issue.title }}"
          echo "\${{ github.sha }} \${{ github.head_ref }}"
      - run: echo "\${{ github.event.comment.body }}"
      - uses: actions/github-script@${SHA}
        with:
          script: |
            console.log("\${{ github.event.pull_request.body }}")
      - env:
          SAFE: \${{ github.event.issue.title }}
        run: echo "$SAFE"
`);
  const si = only(f, 'script-injection');
  assert.deepEqual(si.map((x) => x.line), [9, 10, 11, 15]);
  assert.match(si[0].fix, /env: \{ TITLE: \$\{\{ github\.event\.issue\.title \}\} \}/);
  assert.match(si[3].fix, /process\.env\.BODY/);
  assert.ok(si.every((x) => x.severity === 'high'));
});

test('script injection is critical under pull_request_target', () => {
  const f = scan(`on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \${{ github.event.pull_request.title }}\n`);
  assert.equal(only(f, 'script-injection')[0].severity, 'critical');
});

test('secrets: inherit and echoed secrets', () => {
  const f = scan(`on: push
permissions: {}
jobs:
  call:
    uses: org/repo/.github/workflows/x.yml@${SHA}
    secrets: inherit
  leak:
    runs-on: x
    steps:
      - run: echo "\${{ secrets.API_KEY }}" > key.txt
`);
  assert.equal(only(f, 'secrets-inherit')[0].line, 6);
  assert.equal(only(f, 'secrets-untrusted')[0].severity, 'medium');
});

test('persist-credentials: missing, true, "false" string accepted', () => {
  const mk = (w) => `on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@${SHA}\n${w}`;
  assert.deepEqual(rules(scan(mk(''))), ['persist-credentials']);
  assert.deepEqual(rules(scan(mk('        with:\n          persist-credentials: true\n'))), ['persist-credentials']);
  assert.deepEqual(rules(scan(mk("        with:\n          persist-credentials: 'false'\n"))), []);
});

test('self-hosted runners on PR triggers only', () => {
  const mk = (on, ro) => `on: ${on}\npermissions: {}\njobs:\n  a:\n    runs-on: ${ro}\n    steps:\n      - run: true\n`;
  assert.deepEqual(rules(scan(mk('pull_request', '[self-hosted, linux]'))), ['self-hosted-pr']);
  assert.deepEqual(rules(scan(mk('[push, pull_request_target]', 'self-hosted'))), ['self-hosted-pr']);
  assert.deepEqual(rules(scan(mk('push', 'self-hosted'))), []);
  assert.deepEqual(rules(scan(mk('pull_request', '{ group: big, labels: [self-hosted] }'))), ['self-hosted-pr']);
});

test('curl | bash variants and deprecated commands', () => {
  const f = scan(`on: push
permissions: {}
jobs:
  a:
    runs-on: x
    steps:
      - run: |
          curl -fsSL https://x.sh/install | bash
          wget -qO- https://y | sudo -E sh
          bash <(curl -s https://z)
          sh -c "$(curl -fsSL https://w)"
          curl -o file https://safe && sha256sum -c sums
          echo "::set-output name=x::1"
          echo "::save-state name=y::2"
          echo "::set-env name=Z::3"
`);
  assert.deepEqual(only(f, 'curl-pipe-shell').map((x) => x.line), [8, 9, 10, 11]);
  const d = only(f, 'deprecated-command');
  assert.deepEqual(d.map((x) => x.line), [13, 14, 15]);
  assert.equal(d[2].severity, 'high');
});

test('docker images without digest: step, container, services, action.yml', () => {
  const D = 'sha256:' + 'b'.repeat(64);
  const f = scan(`on: push
permissions: {}
jobs:
  a:
    runs-on: x
    container: node:20
    services:
      db:
        image: postgres:16
      cache:
        image: redis@${D}
    steps:
      - uses: docker://alpine:3.20
      - uses: docker://alpine@${D}
  b:
    runs-on: x
    container:
      image: \${{ matrix.image }}
    steps:
      - run: true
`);
  assert.deepEqual(only(f, 'docker-no-digest').map((x) => x.line), [6, 9, 13]);
  const a = scanText(`name: x\nruns:\n  using: docker\n  image: docker://ghcr.io/o/i:1\n`, 'action.yml');
  assert.deepEqual(rules(a), ['docker-no-digest']);
  assert.deepEqual(scanText(`name: x\nruns:\n  using: docker\n  image: Dockerfile\n`, 'action.yml'), []);
});

test('composite action.yml: unpinned uses and inputs in run', () => {
  const f = scanText(`name: x
inputs:
  who: { description: d }
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - shell: bash
      run: echo "hi \${{ inputs.who }}"
    - shell: bash
      env: { WHO: "\${{ inputs.who }}" }
      run: echo "$WHO"
`, 'sub/action.yml');
  assert.deepEqual(rules(f).sort(), ['script-injection', 'unpinned-action']);
  assert.equal(only(f, 'script-injection')[0].severity, 'medium');
  assert.equal(only(f, 'script-injection')[0].line, 9);
});

test('inline suppression comments', () => {
  const f = scan(`on: push
permissions: {}
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/setup-node@v4 # workflow-sentinel-ignore unpinned-action
      # workflow-sentinel-ignore
      - uses: other/thing@v1
      - uses: third/thing@v1 # workflow-sentinel-ignore persist-credentials
`);
  assert.deepEqual(only(f, 'unpinned-action').map((x) => x.target), ['third/thing']);
});

test('YAML errors and odd shapes do not throw', () => {
  assert.equal(scan('on: [push\njobs: {')[0].rule, 'parse-error');
  assert.deepEqual(scan(''), []);
  assert.deepEqual(scan('- just\n- a list\n'), []);
  assert.doesNotThrow(() => scan('on: push\njobs:\n  a:\n    steps: nope\n'));
  assert.doesNotThrow(() => scan('on: push\njobs:\n  a: null\n'));
});

test('every finding has a fix suggestion and severity', () => {
  const t = `on: pull_request_target\njobs:\n  a:\n    runs-on: self-hosted\n    container: node\n    steps:\n      - uses: actions/checkout@v4\n        with: { ref: "\${{ github.head_ref }}" }\n      - run: curl x | sh; echo \${{ github.event.issue.body }}; echo "::set-output name=a::b"\n`;
  const f = scan(t);
  assert.ok(f.length >= 7);
  for (const x of f) { assert.ok(x.fix && x.fix.length > 20, x.rule); assert.ok(x.severity); assert.ok(x.line >= 1); }
});
