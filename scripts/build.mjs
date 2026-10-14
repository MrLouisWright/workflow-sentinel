import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import { execSync } from 'node:child_process';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
fs.mkdirSync(dist, { recursive: true });

await esbuild.build({
  entryPoints: [path.join(root, 'src/index.js')],
  outfile: path.join(dist, 'index.cjs'),
  format: 'cjs',
  platform: 'node',
  target: 'node18',
  bundle: true,
  external: ['yaml'],
  sourcemap: true,
});

execSync('npx tsc -p tsconfig.json', { cwd: root, stdio: 'inherit' });

// Re-export bin unchanged; types land in dist/
console.log('build: dist/index.cjs + dist/*.d.ts');
