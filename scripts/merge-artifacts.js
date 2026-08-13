#!/usr/bin/env node
/**
 * CI-only (ESM): merge per-platform artifacts downloaded by actions/download-artifact
 * into a single bin/<platform>-<arch>/ layout for npm publish.
 *
 * Expected input layout (download-artifact@v4 with path: bin):
 *   bin/bin-<target>/<platform>-<arch>/skills-checker(.exe)
 *   bin/bin-<target>/skills-checker.js           (shim copy, discarded)
 * Produces (artifact dirs removed):
 *   bin/<platform>-<arch>/skills-checker(.exe)
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const binDir = path.join(root, 'bin');

if (!fs.existsSync(binDir)) {
  console.error('[merge-artifacts] bin/ dir not found — did artifacts download?');
  process.exit(2);
}

let merged = 0;
for (const entry of fs.readdirSync(binDir)) {
  const artifactDir = path.join(binDir, entry);
  if (!fs.statSync(artifactDir).isDirectory()) continue;
  // 只处理 CI 下载的 artifact 目录（bin-<target>），跳过本地已有的平台目录
  if (!entry.startsWith('bin-')) continue;
  for (const plat of fs.readdirSync(artifactDir)) {
    const from = path.join(artifactDir, plat);
    if (!fs.statSync(from).isDirectory()) continue;
    const to = path.join(binDir, plat);
    fs.cpSync(from, to, { recursive: true });
    merged++;
    console.log(`[merge-artifacts] ${from} -> ${to}`);
  }
  // 合并后删除整个 artifact 目录（含 shim 副本与嵌套残留）；清理失败仅告警不中断
  try {
    fs.rmSync(artifactDir, { recursive: true, force: true });
    console.log(`[merge-artifacts] removed ${artifactDir}`);
  } catch (err) {
    console.warn(`[merge-artifacts] warn: failed to remove ${artifactDir}: ${err.message}`);
  }
}

if (merged === 0) {
  console.error('[merge-artifacts] no platform dirs found under bin/');
  process.exit(2);
}
console.log(`[merge-artifacts] done, ${merged} platform(s) merged.`);
