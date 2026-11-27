import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, type Page } from '@playwright/test';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');
export const TEST_SERVER_PASSWORD = 'test-server-password';
export const TEST_PASSPHRASE = 'correct horse battery staple';
export const ROLLBACK_ANCHOR_KEY = 'e2ee-chat.vault.anchor.v3';
export const LEGACY_ROLLBACK_ANCHOR_KEY = 'e2ee-chat.vault.anchor.v1';

export function fixturePath(name: string): string {
  return path.join(FIXTURES_DIR, name);
}

/**
 * Create a fresh vault on the current page and wait until it is unlocked.
 * If `signIn` is true (default), also completes server sign-in so prekeys publish cleanly.
 */
export async function createVault(
  page: Page,
  name: string,
  passphrase = TEST_PASSPHRASE,
  opts: { signIn?: boolean; path?: string } = {},
): Promise<void> {
  const { signIn: doSignIn = true, path: initialPath = '/' } = opts;
  await page.goto(initialPath);
  const dialog = page.locator('dialog.modal');
  await expect(dialog.getByRole('heading', { name: 'Create your vault' })).toBeVisible();
  await dialog.locator('#name').fill(name);
  await dialog.locator('#password').fill(passphrase);
  await dialog.locator('#repeat').fill(passphrase);
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Lock the vault' })).toBeVisible();
  if (doSignIn) {
    await ensureSignedIn(page);
  } else {
    // First-boot PublishV2 hits 403 SignInRequired on the test server and auto-opens SignInDialog.
    // Dismiss it deterministically so the modal never intercepts subsequent sidebar clicks.
    const signInHeading = dialog.getByRole('heading', { name: 'Sign in to this server' });
    await expect(signInHeading).toBeVisible();
    await dialog.getByRole('button', { name: 'Not now', exact: true }).click();
    await expect(signInHeading).toBeHidden();
  }
}

/**
 * Ensure the browser has signed in to the test server (`wrangler.test.toml` `PASSWORD`).
 * Waits for the auto-opened `SignInDialog` triggered by post-create `PublishV2`.
 */
export async function ensureSignedIn(
  page: Page,
  password = TEST_SERVER_PASSWORD,
): Promise<void> {
  const alreadySignedIn = await page.evaluate(async () => {
    const res = await fetch('/auth', { credentials: 'same-origin' });
    if (!res.ok) return false;
    const data = await res.json();
    return Boolean(data && typeof data.subject === 'string');
  });
  if (alreadySignedIn) {
    return;
  }

  const dialog = page.locator('dialog.modal');
  const signInHeading = dialog.getByRole('heading', { name: 'Sign in to this server' });
  await expect(signInHeading).toBeVisible();
  await dialog.locator('#server-password').fill(password);
  await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(signInHeading).toBeHidden();

  // Wait for the post-sign-in `PublishV2` to commit on the Worker DO (not merely `button.sync`'s
  // `synced` label, which can already be set by the pre-sign-in 403 sync round).
  await expect(page.locator('.activity')).toContainText(/published .*prekeys/i);
}

/** Lock the vault via the sidebar Lock button and wait for the Unlock screen. */
export async function lockVault(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Lock the vault' }).click();
  await expect(page.locator('dialog.modal').getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
}

/** Unlock a locked vault with `passphrase`. */
export async function unlockVault(page: Page, passphrase = TEST_PASSPHRASE): Promise<void> {
  const dialog = page.locator('dialog.modal');
  await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await dialog.locator('#password').fill(passphrase);
  await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Lock the vault' })).toBeVisible();
}

/** Open "Your identity" and return both the raw identity key and the invitation link. */
export async function readIdentityInfo(page: Page): Promise<{ key: string; inviteLink: string }> {
  await page.getByRole('button', { name: 'Your identity' }).click();
  const dialog = page.locator('dialog.modal');
  await expect(dialog.getByRole('heading', { name: 'Your identity' })).toBeVisible();
  const keyBoxes = dialog.locator('.copyable .key');
  await expect(keyBoxes).toHaveCount(2);
  const key = (await keyBoxes.nth(0).textContent())?.trim() ?? '';
  const inviteLink = (await keyBoxes.nth(1).textContent())?.trim() ?? '';
  expect(key.length).toBeGreaterThan(20);
  expect(inviteLink).toContain('#chat=');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(dialog).not.toHaveAttribute('open', '');
  return { key, inviteLink };
}

/**
 * Establish a verified, accepted E2E-encrypted chat between `alicePage` and `bobPage`.
 * Alice initiates using Bob's invitation link; Bob accepts the incoming request.
 */
export async function establishChat(
  alicePage: Page,
  bobPage: Page,
  aliceName = 'Alice',
  bobName = 'Bob',
): Promise<void> {
  await createVault(alicePage, aliceName);
  await createVault(bobPage, bobName);

  const bobIdentity = await readIdentityInfo(bobPage);

  // Alice starts a chat with Bob via New Chat dialog using Bob's identity key.
  await alicePage.locator('.sidebar').getByRole('button', { name: 'New chat' }).click();
  const aliceDialog = alicePage.locator('dialog.modal');
  await expect(aliceDialog.getByRole('heading', { name: 'New chat' })).toBeVisible();
  await aliceDialog.locator('#peer-key').fill(bobIdentity.key);
  await aliceDialog.locator('#peer-name').fill(bobName);
  await aliceDialog.getByRole('button', { name: 'Start', exact: true }).click();

  await expect(alicePage.locator('.pane')).toBeVisible();
  await expect(alicePage.locator('.pane-title strong')).toHaveText(bobName);
  await expect(alicePage.locator('.banner.awaiting-acceptance')).toBeVisible();
  await expect(alicePage.locator('.banner.awaiting-acceptance')).toContainText(
    `Waiting for ${bobName} to accept your chat request`,
  );
  await expect(alicePage.locator('.chat-item .chat-sub').first()).toHaveText(
    'waiting for acceptance',
  );
  await expect(alicePage.locator('.composer textarea')).toHaveAttribute(
    'placeholder',
    'Write a message (delivers once accepted)',
  );

  // Bob receives Alice's chat request over the live Worker DO + WebSocket notification.
  const bobChatItem = bobPage.locator('.chat-item').first();
  await expect(bobChatItem).toBeVisible();
  await bobChatItem.click();
  await expect(bobPage.locator('.pane')).toBeVisible();

  const acceptPrompt = bobPage.getByRole('button', { name: /accept or delete/i });
  await expect(acceptPrompt).toBeVisible();
  await acceptPrompt.click();

  const bobDialog = bobPage.locator('dialog.modal');
  await expect(bobDialog.getByRole('heading', { name: 'Chat request' })).toBeVisible();
  await bobDialog.getByRole('button', { name: 'Accept', exact: true }).click();
  await expect(bobDialog).not.toHaveAttribute('open', '');

  // Acceptance clears Alice's awaiting-acceptance notice automatically via live WS sync.
  await expect(alicePage.locator('.banner.awaiting-acceptance')).toBeHidden();
  await expect(alicePage.locator('.composer textarea')).toHaveAttribute(
    'placeholder',
    'Write a message',
  );

  // Both composers should now be enabled and ready to exchange messages/files.
  await expect(alicePage.locator('.composer textarea')).toBeEnabled();
  await expect(bobPage.locator('.composer textarea')).toBeEnabled();
}

/** Send a text message from the open chat pane. */
export async function sendTextMessage(page: Page, text: string): Promise<void> {
  const textarea = page.locator('.composer textarea');
  await expect(textarea).toBeEnabled();
  await textarea.fill(text);
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(page.locator('.messages .bubble', { hasText: text })).toBeVisible();
}

/** Attach and send one or more files from the open chat pane. */
export async function sendFiles(
  page: Page,
  files: string | string[] | { name: string; mimeType: string; buffer: Buffer }[],
): Promise<void> {
  const input = page.locator('.composer input[type="file"]');
  await input.setInputFiles(files);
}
