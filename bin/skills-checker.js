#!/usr/bin/env node
/**
 * skills-checker bin shim (ESM)
 *
 * Locates the platform-specific Rust binary under bin/<platform>-<arch>/
 * and forwards all arguments to it. Zero dependencies.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const platform = process.platform; // win32 | darwin | linux
const arch = process.arch; // x64 | arm64
const isWindows = platform === 'win32';

const exeName = isWindows ? 'skills-checker.exe' : 'skills-checker';
const binDir = path.join(__dirname, `${platform}-${arch}`);
const binPath = path.join(binDir, exeName);

if (!fs.existsSync(binPath)) {
  console.error(
    `[skills-checker] Binary not found for ${platform}-${arch}: ${binPath}\n` +
      `  Options:\n` +
      `    1) Build it locally:  npm run build:bin  (requires Rust toolchain)\n` +
      `    2) Download it:       set SKILLS_CHECKER_BIN_URL then run: npm rebuild skills-checker\n` +
      `    3) Install a per-platform prebuilt package (if published).`
  );
  process.exit(2);
}

const result = spawnSync(binPath, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: true,
});

if (result.error) {
  console.error(`[skills-checker] Failed to execute binary: ${result.error.message}`);
  process.exit(2);
}
process.exit(result.status === null ? 1 : result.status);
