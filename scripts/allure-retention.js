#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const RESULTS_DIR = path.join(ROOT, 'allure-results');
const HISTORY_DIR = path.join(ROOT, 'allure-results-history');
const KEEP_RUNS = Number(process.env.ALLURE_KEEP_RUNS || '2');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function dirHasArtifacts(dirPath) {
  if (!fs.existsSync(dirPath)) return false;
  const entries = fs.readdirSync(dirPath);
  return entries.length > 0;
}

function makeRunName() {
  const now = new Date();
  const pad = (n) => String(n).padStart(1, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `run-${stamp}`;
}

function archivePreviousResults() {
  if (!dirHasArtifacts(RESULTS_DIR)) {
    return;
  }

  ensureDir(HISTORY_DIR);
  const archiveDir = path.join(HISTORY_DIR, makeRunName());

  fs.cpSync(RESULTS_DIR, archiveDir, { recursive: true });
  console.log(`[allure-retention] Archived previous results to ${path.relative(ROOT, archiveDir)}`);
}

function pruneHistory() {
  if (!fs.existsSync(HISTORY_DIR)) return;

  const runDirs = fs
    .readdirSync(HISTORY_DIR)
    .map((name) => ({
      name,
      fullPath: path.join(HISTORY_DIR, name),
    }))
    .filter((entry) => fs.existsSync(entry.fullPath) && fs.statSync(entry.fullPath).isDirectory())
    .sort((a, b) => fs.statSync(b.fullPath).mtimeMs - fs.statSync(a.fullPath).mtimeMs);

  const toDelete = runDirs.slice(Math.max(KEEP_RUNS, 0));
  for (const entry of toDelete) {
    fs.rmSync(entry.fullPath, { recursive: true, force: true });
    console.log(`[allure-retention] Removed old archive ${path.relative(ROOT, entry.fullPath)}`);
  }
}

function cleanResultsDir() {
  fs.rmSync(RESULTS_DIR, { recursive: true, force: true });
  ensureDir(RESULTS_DIR);
  console.log('[allure-retention] Prepared clean allure-results directory');
}

function main() {
  archivePreviousResults();
  pruneHistory();
  cleanResultsDir();
}

main();
