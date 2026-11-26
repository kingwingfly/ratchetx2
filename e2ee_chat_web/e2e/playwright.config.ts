import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.E2E_PORT || '8788');
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  expect: {
    timeout: 20_000,
  },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL,
    trace: 'on-first-retry',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      testIgnore: /bfcache\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
      },
    },
    {
      // Dedicated project launching full Chromium (`--headless=new` via `channel: 'chromium'`)
      // without Playwright's default `--disable-back-forward-cache` flag so `pageshow`
      // `persisted === true` bfcache restoration is genuinely exercised (`chromium_headless_shell`
      // disables bfcache with `BackForwardCacheDisabledForDelegate`).
      name: 'chromium-bfcache',
      testMatch: /bfcache\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chromium',
        launchOptions: {
          ignoreDefaultArgs: ['--disable-back-forward-cache'],
        },
      },
    },
  ],
  webServer: {
    command: 'node ./scripts/start-server.mjs',
    url: `${baseURL}/auth`,
    reuseExistingServer: process.env.E2E_REUSE_SERVER === '1',
    timeout: 60_000,
    env: {
      ...process.env,
      E2E_PORT: String(port),
    },
  },
});
