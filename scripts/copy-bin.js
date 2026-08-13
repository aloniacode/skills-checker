#!/usr/bin/env node
/**
 * Copy the release binary into bin/<platform>-<arch>/ layout. (ESM)
 *
 * Usage:
 *   node scripts/copy-bin.js                 # local: target/release, auto platform/arch
 *   node scripts/copy-bin.js --target <triple>   # CI: target/<triple>/release (cross builds)
 *   node scripts/copy-bin.js --from <dir>    # copy from an explicit directory
 *   node scripts/copy-bin.js --if-missing    # skip when the target already exists
 *
 * Rust target triple -> npm platform-arch mapping:
 *   x86_64-pc-windows-msvc  -> win32-x64
 *   x86_64-unknown-linux-gnu-> linux-x64
 *   aarch64-unknown-linux-gnu -> linux-arm64
 *   x86_64-apple-darwin     -> darwin-x64
 *   aarch64-apple-darwin    -> darwin-arm64
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TRIPLE_MAP = {
  'x86_64-pc-windows-msvc': ['win32', 'x64'],
  'x86_64-unknown-linux-gnu': ['linux', 'x64'],
  'aarch64-unknown-linux-gnu': ['linux', 'arm64'],
  'x86_64-apple-darwin': ['darwin', 'x64'],
  'aarch64-apple-darwin': ['darwin', 'arm64'],
};

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { ifMissing: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--if-missing') opts.ifMissing = true;
    else if (args[i] === '--target') opts.target = args[++i];
    else if (args[i] === '--from') opts.from = args[++i];
  }
  return opts;
}

function detectPlatformArch() {
  const map = {
    win32: { x64: ['win32', 'x64'], arm64: ['win32', 'arm64'] },
    linux: { x64: ['linux', 'x64'], arm64: ['linux', 'arm64'] },
    darwin: { x64: ['darwin', 'x64'], arm64: ['darwin', 'arm64'] },
  };
  const entry = (map[process.platform] || {})[process.arch];
  if (!entry) {
    console.error(`[copy-bin] Unsupported local platform: ${process.platform}-${process.arch}`);
    process.exit(2);
  }
  return entry;
}

function main() {
  const opts = parseArgs();
  const root = path.join(__dirname, '..');

  let platform, arch, srcDir;
  if (opts.target) {
    const entry = TRIPLE_MAP[opts.target];
    if (!entry) {
      console.error(`[copy-bin] Unsupported target triple: ${opts.target}`);
      process.exit(2);
    }
    [platform, arch] = entry;
    srcDir = path.join(root, 'target', opts.target, 'release');
  } else if (opts.from) {
    [platform, arch] = detectPlatformArch();
    srcDir = path.resolve(opts.from);
  } else {
    [platform, arch] = detectPlatformArch();
    srcDir = path.join(root, 'target', 'release');
  }

  const exeName = platform === 'win32' ? 'skills-checker.exe' : 'skills-checker';
  const src = path.join(srcDir, exeName);
  const destDir = path.join(root, 'bin', `${platform}-${arch}`);
  const dest = path.join(destDir, exeName);

  // --if-missing：目标已存在则直接跳过（CI 发布 job 中 bin/ 已由
  // merge-artifacts 填充，此时没有本地 target/release，不应报错）
  if (opts.ifMissing && fs.existsSync(dest)) {
    console.log(`[copy-bin] ${platform}-${arch} already exists, skipped.`);
    return;
  }

  if (!fs.existsSync(src)) {
    console.error(`[copy-bin] Source binary not found: ${src}\n  Run "cargo build --release" first.`);
    process.exit(2);
  }

  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, dest);
  if (platform !== 'win32') {
    try {
      fs.chmodSync(dest, 0o755);
    } catch (_) {
      /* chmod may be a no-op on some systems */
    }
  }
  console.log(`[copy-bin] ${src} -> ${dest}`);
}

main();
