#!/usr/bin/env node
// Builds dist/zauthentificator-<version>.zip from the CONTENTS of extension/ (manifest.json at the
// zip root, ready for "Load unpacked" after unzipping) with the system `zip` CLI, then prints the
// zip path and its sha256.
//
//   node scripts/build-zip.mjs [--ext <extension dir>] [--out <output dir>]

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error(`build-zip: ${message}`);
  process.exitCode = 1;
}

function parseArgs(argv) {
  const opts = { ext: path.join(REPO_ROOT, 'extension'), out: path.join(REPO_ROOT, 'dist') };
  for (let i = 0; i < argv.length; i += 2) {
    const value = argv[i + 1];
    if (argv[i] === '--ext' && value) opts.ext = path.resolve(value);
    else if (argv[i] === '--out' && value) opts.out = path.resolve(value);
    else return null;
  }
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (!opts) return fail('usage: build-zip.mjs [--ext <extension dir>] [--out <output dir>]');

  const manifestPath = path.join(opts.ext, 'manifest.json');
  if (!fs.existsSync(manifestPath)) return fail(`${path.relative(process.cwd(), manifestPath)} not found`);
  let version;
  try {
    ({ version } = JSON.parse(fs.readFileSync(manifestPath, 'utf8')));
  } catch (err) {
    return fail(`manifest.json unreadable: ${err.message}`);
  }
  if (typeof version !== 'string' || !/^\d+(\.\d+){0,3}$/.test(version)) {
    return fail(`manifest version ${JSON.stringify(version)} is not 1-4 dot-separated integers`);
  }

  fs.mkdirSync(opts.out, { recursive: true });
  const zipPath = path.join(opts.out, `zauthentificator-${version}.zip`);
  fs.rmSync(zipPath, { force: true }); // zip -r would otherwise update an existing archive in place

  const zip = spawnSync('zip', ['-q', '-r', '-X', zipPath, '.', '-x', '*.DS_Store'], {
    cwd: opts.ext,
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  if (zip.error) return fail(`cannot run zip: ${zip.error.message}`);
  if (zip.status !== 0) return fail(`zip exited with status ${zip.status}`);

  const list = spawnSync('unzip', ['-Z1', zipPath], { encoding: 'utf8' });
  if (list.error || list.status !== 0) return fail(`cannot list ${zipPath}: ${list.error?.message ?? list.stderr}`);
  const entries = list.stdout.split('\n').filter(Boolean);
  if (!entries.includes('manifest.json')) return fail('manifest.json is not at the zip root');
  if (entries.some((e) => e.endsWith('.DS_Store'))) return fail('.DS_Store leaked into the zip');

  const sha256 = createHash('sha256').update(fs.readFileSync(zipPath)).digest('hex');
  const shown = path.relative(process.cwd(), zipPath);
  console.log(shown.startsWith('..') ? zipPath : shown);
  console.log(`sha256 ${sha256}`);
}

main(process.argv.slice(2));
