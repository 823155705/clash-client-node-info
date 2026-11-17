#!/usr/bin/env node
/**
 * Zero-dependency build & consistency verification script for xream & Kelee Node Suite v3.0.0
 *
 * Usage:
 *   node scripts/build.js          # Generate 3 root artifacts from src/xream-node-core.js
 *   node scripts/build.js --check  # Verify generated artifacts match src/xream-node-core.js & SHA-256 isolation
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');
const CORE_PATH = path.join(ROOT_DIR, 'src', 'xream-node-core.js');

const TARGETS = [
  {
    file: 'xream-node-info.js',
    banner: 'v3.0.0 · Universal Multi-Client',
    variant: 'universal',
    hostHint: 'auto',
  },
  {
    file: 'xream-clash-node-info.js',
    banner: 'v3.0.0 · Clash-Client FG-Interactive',
    variant: 'clash-fg',
    hostHint: 'auto',
  },
  {
    file: 'xream-clash-node-bg.js',
    banner: 'v3.0.0 · Clash-Client BG-Tunnel-Event',
    variant: 'clash-bg',
    hostHint: 'auto',
  },
];

function sha256Hex(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function renderArtifact(coreSource, target) {
  const bannerToken = '(v3.0.0 · Core Source)';
  const variantToken = "const BUILD_VARIANT = 'core-source';";
  const hostHintToken = "const DEFAULT_HOST_HINT = 'auto';";

  if (!coreSource.includes(bannerToken)) {
    throw new Error(`Missing banner token ${bannerToken} in src/xream-node-core.js`);
  }
  if (!coreSource.includes(variantToken)) {
    throw new Error(`Missing variant token ${variantToken} in src/xream-node-core.js`);
  }
  if (!coreSource.includes(hostHintToken)) {
    throw new Error(`Missing hostHint token ${hostHintToken} in src/xream-node-core.js`);
  }

  return coreSource
    .replace(bannerToken, `(${target.banner})`)
    .replace(variantToken, `const BUILD_VARIANT = '${target.variant}';`)
    .replace(hostHintToken, `const DEFAULT_HOST_HINT = '${target.hostHint}';`);
}

function main() {
  const checkOnly = process.argv.includes('--check');

  if (!fs.existsSync(CORE_PATH)) {
    console.error(`[build] ERROR: Core source not found at ${CORE_PATH}`);
    process.exit(1);
  }

  const coreSource = fs.readFileSync(CORE_PATH, 'utf8');
  const builtRecords = TARGETS.map((target) => {
    const outPath = path.join(ROOT_DIR, target.file);
    const content = renderArtifact(coreSource, target);
    const hash = sha256Hex(content);
    return { target, outPath, content, hash };
  });

  // Assert SHA-256 anti-quarantine isolation across artifacts
  const clashFg = builtRecords.find((r) => r.target.file === 'xream-clash-node-info.js');
  const clashBg = builtRecords.find((r) => r.target.file === 'xream-clash-node-bg.js');
  if (!clashFg || !clashBg || clashFg.hash === clashBg.hash) {
    console.error('[build] ERROR: FG and BG Clash artifacts MUST have distinct SHA-256 hashes!');
    process.exit(1);
  }

  const uniqueHashes = new Set(builtRecords.map((r) => r.hash));
  if (uniqueHashes.size !== builtRecords.length) {
    console.error('[build] ERROR: Duplicate SHA-256 hash detected among generated artifacts!');
    process.exit(1);
  }

  if (checkOnly) {
    let hasError = false;
    for (const rec of builtRecords) {
      if (!fs.existsSync(rec.outPath)) {
        console.error(`[build --check] MISSING: ${rec.target.file}`);
        hasError = true;
        continue;
      }
      const diskContent = fs.readFileSync(rec.outPath, 'utf8');
      const diskHash = sha256Hex(diskContent);
      if (diskContent !== rec.content) {
        console.error(
          `[build --check] MISMATCH: ${rec.target.file} (disk sha256=${diskHash.slice(0, 12)} != expected=${rec.hash.slice(0, 12)})`
        );
        hasError = true;
      } else {
        console.log(
          `[build --check] OK  ${rec.target.file.padEnd(26)} sha256=${rec.hash.slice(0, 16)}... (${Buffer.byteLength(rec.content, 'utf8')} B)`
        );
      }
    }
    if (hasError) {
      console.error('[build --check] FAILED: Run `node scripts/build.js` to synchronize artifacts.');
      process.exit(1);
    }
    console.log('[build --check] All 3 artifacts are up-to-date and SHA-256 isolated.');
    process.exit(0);
  }

  for (const rec of builtRecords) {
    fs.writeFileSync(rec.outPath, rec.content, 'utf8');
    const lines = rec.content.split('\n').length;
    const bytes = Buffer.byteLength(rec.content, 'utf8');
    console.log(
      `[build] WROTE ${rec.target.file.padEnd(26)} ${String(lines).padStart(5)} lines | ${String(bytes).padStart(7)} B | sha256=${rec.hash.slice(0, 16)}...`
    );
  }
  console.log('[build] Build completed successfully (FG/BG SHA-256 isolation verified).');
}

main();
