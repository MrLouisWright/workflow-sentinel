import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pinText, resolveSha, fixFiles, scanText } from '../src/index.js';

const S1 = '1'.repeat(40), S2 = '2'.repeat(40);
const resolver = async (a, r) => { if (a.startsWith('missing/')) throw new Error('HTTP 404'); return a.startsWith('actions/checkout') ? S1 : S2; };

test('pinText pins tags, keeps comments, quotes, CRLF and skips SHAs/local/expressions', async () => {
  const src = [
    '    steps:',
    '      - uses: actions/checkout@v4',
    "      - uses: 'org/x/sub@v1' # keep me",
    `      - uses: org/y@${S2}`,
    '      - uses: ./local',
    '      - uses: org/z@${{ matrix.ref }}',
    '      - uses: missing/repo@v9',
    '    uses: org/wf/.github/workflows/r.yml@main\r',
  ].join('\n');
  const { text, changes } = await pinText(src, resolver);
  const L = text.split('\n');
  assert.equal(L[1], `      - uses: actions/checkout@${S1} # v4`);
  assert.equal(L[2], `      - uses: 'org/x/sub@${S2}' # keep me`);
  assert.equal(L[3], `      - uses: org/y@${S2}`);
  assert.equal(L[4], '      - uses: ./local');
  assert.equal(L[5], '      - uses: org/z@${{ matrix.ref }}');
  assert.equal(L[6], '      - uses: missing/repo@v9');
  assert.equal(L[7], `    uses: org/wf/.github/workflows/r.yml@${S2} # main\r`);
  assert.equal(changes.filter((c) => c.error).length, 1);
  assert.equal(changes.filter((c) => c.sha).length, 3);
});

test('resolveSha hits the commits API with the sha media type and token', async () => {
  let seen;
  const fetchImpl = async (url, { headers }) => { seen = { url, headers }; return { ok: true, status: 200, text: async () => S1 + '\n' }; };
  assert.equal(await resolveSha('actions/cache/save', 'v4', { token: 'T', fetchImpl }), S1);
  assert.equal(seen.url, 'https://api.github.com/repos/actions/cache/commits/v4');
  assert.equal(seen.headers.accept, 'application/vnd.github.sha');
  assert.equal(seen.headers.authorization, 'Bearer T');
  await assert.rejects(resolveSha('a/b', 'v1', { fetchImpl: async () => ({ ok: false, status: 404 }) }), /404/);
  await assert.rejects(resolveSha('a/b', 'v1', { fetchImpl: async () => ({ ok: true, text: async () => '<html>' }) }), /unexpected/);
});

test('fixFiles writes, dedupes lookups, and the result scans clean for pinning', async () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-fix-'));
  const f = path.join(d, 'w.yml');
  fs.writeFileSync(f, 'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: org/a@v1\n      - uses: org/a@v1\n');
  let calls = 0;
  const rep = await fixFiles([f], { resolver: async () => { calls++; return S2; } });
  assert.equal(rep[0].changes.length, 2);
  assert.equal(scanText(fs.readFileSync(f, 'utf8'), 'w.yml').filter((x) => x.rule === 'unpinned-action').length, 0);
  const before = fs.readFileSync(f, 'utf8');
  await fixFiles([f], { resolver: async () => S1, dryRun: true });
  assert.equal(fs.readFileSync(f, 'utf8'), before);
});
