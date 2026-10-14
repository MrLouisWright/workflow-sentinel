import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');

test('ESM import from package entry', async () => {
  const mod = await import(path.join(root, 'src/index.js'));
  assert.equal(typeof mod.scanText, 'function');
  assert.equal(typeof mod.validateExpression, 'function');
});

test('CJS require from dist after build', () => {
  const build = spawnSync(process.execPath, [path.join(root, 'scripts/build.mjs')], { cwd: root, encoding: 'utf8' });
  assert.equal(build.status, 0, build.stderr || build.stdout);
  const require = createRequire(path.join(root, 'package.json'));
  const mod = require('workflow-sentinel');
  assert.equal(typeof mod.scanText, 'function');
  assert.equal(typeof mod.fixFiles, 'function');
  const findings = mod.scanText('on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/x@v1\n', 'w.yml');
  assert.ok(findings.some((f) => f.rule === 'unpinned-action'));
});
