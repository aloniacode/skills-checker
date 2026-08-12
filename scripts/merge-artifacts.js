#!/usr/bin/env node
/**
 * CI-only (ESM): merge per-platform artifacts downloaded by actions/download-artifact
 * into a single bin/<platform>-<arch>/ layout for npm publish.
 *
 * Expected input layout (download-artifact@v4 with path: bin):
 *   bin/<artifact-name>/<platform>-<arch>/skills-checker(.exe)
 * Produces:
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
  for (const plat of fs.readdirSync(artifactDir)) {
    const from = path.join(artifactDir, plat);
    if (!fs.statSync(from).isDirectory()) continue;
    const to = path.join(binDir, plat);
    fs.cpSync(from, to, { recursive: true });
    merged++;
    console.log(`[merge-artifacts] ${from} -> ${to}`);
  }
}

if (merged === 0) {
  console.error('[merge-artifacts] no platform dirs found under bin/');
  process.exit(2);
}
console.log(`[merge-artifacts] done, ${merged} platform(s) merged.`);
