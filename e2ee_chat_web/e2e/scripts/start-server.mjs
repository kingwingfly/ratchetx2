#!/usr/bin/env node
// Starts a local `wrangler dev` instance backed by `e2ee_chat_worker/wrangler.test.toml` and
// serving the built `e2ee_chat_web/dist` assets, with ephemeral `--persist-to` storage cleaned up
// on exit.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');
const workerDir = path.join(repoRoot, 'e2ee_chat_worker');
const webDistDir = path.join(repoRoot, 'e2ee_chat_web', 'dist');
const wranglerConfig = path.join(workerDir, 'wrangler.test.toml');
const workerEntry = path.join(workerDir, 'build', 'worker', 'shim.mjs');
const wranglerBin = path.join(workerDir, 'node_modules', '.bin', 'wrangler');

if (!fs.existsSync(workerEntry)) {
  console.error(
    `Missing built worker at ${workerEntry}. Run \`worker-build --dev\` in e2ee_chat_worker first.`,
  );
  process.exit(1);
}
if (!fs.existsSync(path.join(webDistDir, 'index.html'))) {
  console.error(
    `Missing built web client at ${webDistDir}. Run \`trunk build\` in e2ee_chat_web first.`,
  );
  process.exit(1);
}
if (!fs.existsSync(wranglerBin)) {
  console.error(
    `Missing wrangler binary at ${wranglerBin}. Run \`npm ci\` in e2ee_chat_worker first.`,
  );
  process.exit(1);
}

const port = process.env.E2E_PORT || '8788';
const persistDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2ee-chat-e2e-'));

const child = spawn(
  wranglerBin,
  [
    'dev',
    '--local',
    '--config',
    wranglerConfig,
    '--assets',
    webDistDir,
    '--ip',
    '127.0.0.1',
    '--port',
    port,
    '--persist-to',
    persistDir,
    '--show-interactive-dev-session=false',
  ],
  {
    cwd: workerDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      WRANGLER_SEND_METRICS: 'false',
    },
  },
);

let cleaned = false;
function cleanup() {
  if (cleaned) return;
  cleaned = true;
  try {
    fs.rmSync(persistDir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup of temp persistence directory.
  }
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    child.kill(signal);
  });
}

child.on('exit', (code, signal) => {
  cleanup();
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 0);
  }
});

child.on('error', (err) => {
  console.error('Failed to spawn wrangler dev:', err);
  cleanup();
  process.exit(1);
});
