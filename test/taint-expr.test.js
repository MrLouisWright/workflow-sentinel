import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText, validateExpression } from '../src/index.js';

const SHA = 'a'.repeat(40);
const only = (fs, r) => fs.filter((f) => f.rule === r);

test('cache poisoning: direct and env-tainted cache keys', () => {
  const direct = scanText(`on: pull_request
permissions: { contents: read }
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@${SHA}
        with:
          path: node_modules
          key: \${{ github.head_ref }}-npm
`, 'w.yml');
  assert.equal(only(direct, 'cache-poisoning').length, 1);
  assert.match(only(direct, 'cache-poisoning')[0].message, /head_ref/);

  const tainted = scanText(`on: pull_request
permissions: { contents: read }
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - env:
          BR: \${{ github.event.pull_request.head.ref }}
        run: echo setup
      - uses: actions/cache/restore@${SHA}
        with:
          path: ~/.npm
          key: \${{ env.BR }}-cache
`, 'w.yml');
  assert.equal(only(tainted, 'cache-poisoning').length, 1);
  assert.match(only(tainted, 'cache-poisoning')[0].message, /env\.BR/);
});

test('artipacked: upload after checkout without persist-credentials false', () => {
  const f = scanText(`on: push
permissions: { contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
      - uses: actions/upload-artifact@${SHA}
        with:
          name: out
          path: dist/
`, 'w.yml');
  assert.ok(only(f, 'artipacked').some((x) => /persist-credentials/.test(x.message)));
  const ok = scanText(`on: push
permissions: { contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          persist-credentials: false
      - uses: actions/upload-artifact@${SHA}
        with:
          path: dist/
`, 'w.yml');
  assert.deepEqual(only(ok, 'artipacked'), []);
});

test('invalid expression and schema typos', () => {
  const f = scanText(`name: CI
on: push
permissions: { contents: read }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.events.pull_request.title }}"
`, 'w.yml');
  assert.ok(only(f, 'invalid-expression').some((x) => /github\.event/.test(x.message)));

  const badKey = scanText(`on: push
job:
  x:
    runs-on: x
    steps:
      - run: true
`, 'w.yml');
  assert.ok(only(badKey, 'invalid-schema').some((x) => /jobs/.test(x.message)));
});

test('validateExpression flags wrong trigger context', () => {
  const iss = validateExpression('github.event.pull_request.number', { triggers: ['push'] });
  assert.ok(iss.some((x) => /not available/.test(x.message)));
});
