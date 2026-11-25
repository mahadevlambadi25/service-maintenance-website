import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseEnv } from '@neon/env';
import neonConfig from '../neon.ts';
import { ENV, loadLocalEnvFiles, ROOT_DIR } from '../src/config.js';

function collectJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectJsFiles(full));
    } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.mjs'))) {
      out.push(full);
    }
  }
  return out;
}

loadLocalEnvFiles();

const srcFiles = collectJsFiles(path.join(ROOT_DIR, 'src'));
for (const file of srcFiles) {
  execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
}

const requiredPublicAssets = [
  'public/css/tokens.css',
  'public/css/main.css',
  'public/css/admin.css',
  'public/js/app.js',
  'public/js/admin.js',
  'public/assets/brand-mark.svg',
];
for (const rel of requiredPublicAssets) {
  const full = path.join(ROOT_DIR, rel);
  if (!fs.existsSync(full)) {
    throw new Error(`Missing required frontend asset: ${rel}`);
  }
}

let neonSummary = 'sqlite-fallback (DATABASE_URL not set)';
if (process.env.DATABASE_URL || ENV.DATABASE_URL) {
  const neonEnv = parseEnv(neonConfig, ['DATABASE_URL', 'DATABASE_URL_UNPOOLED']);
  if (!neonEnv?.postgres?.databaseUrl || !neonEnv?.postgres?.databaseUrlUnpooled) {
    throw new Error('Neon env validation failed: DATABASE_URL and DATABASE_URL_UNPOOLED are required.');
  }
  neonSummary = `neon-postgres (branch=${process.env.NEON_BRANCH || 'unknown'})`;
}

console.log(`Build verified: ${srcFiles.length} source files syntax-checked, ${requiredPublicAssets.length} public assets verified, DB target=${neonSummary}`);
