#!/usr/bin/env node
/**
 * postinstall hook (ESM): verify (and optionally download) the platform binary.
 *
 * - If bin/<platform>-<arch>/skills-checker(.exe) exists -> done.
 * - If SKILLS_CHECKER_BIN_URL is set (e.g. pointing to a GitHub Release
 *   asset for this platform) -> download it (pure Node https, no deps).
 * - Otherwise print actionable instructions and exit 0 (do NOT break
 *   `npm install`; the bin shim will give a friendly error on use).
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const platform = process.platform;
const arch = process.arch;
const isWindows = platform === 'win32';
const exeName = isWindows ? 'skills-checker.exe' : 'skills-checker';
const destDir = path.join(__dirname, '..', 'bin', `${platform}-${arch}`);
const dest = path.join(destDir, exeName);

function log(msg) {
  console.log(`[skills-checker] ${msg}`);
}

function download(url) {
  return new Promise((resolve, reject) => {
    log(`Downloading binary from ${url}`);
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        download(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      fs.mkdirSync(destDir, { recursive: true });
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', reject);
    });
    req.on('error', reject);
  });
}

function chmodExecutable() {
  if (isWindows) return;
  try {
    fs.chmodSync(dest, 0o755);
  } catch (_) {
    /* ignore */
  }
}

async function main() {
  if (fs.existsSync(dest)) {
    log(`binary ready: ${dest}`);
    return;
  }

  const url = process.env.SKILLS_CHECKER_BIN_URL;
  if (url) {
    try {
      await download(url);
      chmodExecutable();
      // sanity check
      const r = spawnSync(dest, ['--version'], { encoding: 'utf8' });
      log(r.stdout ? `downloaded, version: ${r.stdout.trim()}` : 'downloaded.');
      return;
    } catch (err) {
      log(`download failed: ${err.message}`);
    }
  }

  log(
    `no prebuilt binary for ${platform}-${arch} found.\n` +
      `  -> Build locally:   npm run build:bin   (requires Rust toolchain)\n` +
      `  -> Auto download:   set SKILLS_CHECKER_BIN_URL=https://.../skills-checker${isWindows ? '.exe' : ''} and run: npm rebuild skills-checker\n` +
      `  -> Use a prebuilt per-platform package (if published).`
  );
}

main().catch((err) => {
  log(`unexpected error: ${err.message}`);
});
