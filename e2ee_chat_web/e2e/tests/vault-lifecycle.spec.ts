import { expect, test } from '@playwright/test';
import {
  ROLLBACK_ANCHOR_KEY,
  TEST_PASSPHRASE,
  createVault,
  lockVault,
  unlockVault,
} from './helpers.ts';

test.describe('vault lifecycle', () => {
  test('first-boot create, lock, wrong passphrase rejection, and unlock', async ({ page }) => {
    await createVault(page, 'Alice', TEST_PASSPHRASE, { signIn: false });

    const anchor = await page.evaluate((key) => localStorage.getItem(key), ROLLBACK_ANCHOR_KEY);
    expect(anchor).toMatch(/^v1:1:\d+:[0-9a-f]{64}$/);

    await lockVault(page);

    const dialog = page.locator('dialog.modal');
    await dialog.locator('#password').fill('wrong passphrase 123');
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    await unlockVault(page, TEST_PASSPHRASE);
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Alice');
  });

  test('same-version rollback anchor rejection (stale revision & salt swap) and 2-step ConfirmGuard reset', async ({
    page,
  }) => {
    await createVault(page, 'Bob', TEST_PASSPHRASE, { signIn: false });
    await lockVault(page);

    const originalAnchor = await page.evaluate(
      (key) => localStorage.getItem(key),
      ROLLBACK_ANCHOR_KEY,
    );
    expect(originalAnchor).not.toBeNull();
    const parts = originalAnchor!.split(':');
    expect(parts).toHaveLength(4);
    const [prefix, migrated, revStr, saltHash] = parts;
    const rev = Number(revStr);
    expect(Number.isInteger(rev) && rev >= 1).toBe(true);

    const dialog = page.locator('dialog.modal');

    // 1. Stale revision rollback: external anchor is ahead of the IDB header revision.
    await page.evaluate(
      ({ key, value }) => localStorage.setItem(key, value),
      { key: ROLLBACK_ANCHOR_KEY, value: `${prefix}:${migrated}:${rev + 10}:${saltHash}` },
    );
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toContainText(/rollback/i);
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    // 2. Salt swap rollback: anchor salt fingerprint differs from the IDB header salt.
    const swappedSalt = saltHash.startsWith('0') ? `f${saltHash.slice(1)}` : `0${saltHash.slice(1)}`;
    await page.evaluate(
      ({ key, value }) => localStorage.setItem(key, value),
      { key: ROLLBACK_ANCHOR_KEY, value: `${prefix}:${migrated}:${rev}:${swappedSalt}` },
    );
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toContainText(/salt|rollback|replacement/i);
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    // 3. UnlockVault::reset 2-step ConfirmGuard clears IDB + localStorage anchor so fresh vault succeeds.
    const resetButton = dialog.getByRole('button', { name: 'Forgot it: start over', exact: true });
    await resetButton.click();

    const confirmButton = dialog.getByRole('button', {
      name: 'Delete it all, for good?',
      exact: true,
    });
    await expect(confirmButton).toBeVisible();

    // First click must only arm ConfirmGuard without wiping localStorage or IDB yet.
    const anchorBeforeConfirm = await page.evaluate(
      (key) => localStorage.getItem(key),
      ROLLBACK_ANCHOR_KEY,
    );
    expect(anchorBeforeConfirm).not.toBeNull();

    // Second click confirms destruction, clears IDB + rollback anchor, and reloads to CreateVault.
    await confirmButton.click();
    await expect(dialog.getByRole('heading', { name: 'Create your vault' })).toBeVisible();

    const clearedState = await page.evaluate(async (anchorKey) => {
      const anchor = localStorage.getItem(anchorKey);
      const recordKeys = await new Promise<IDBValidKey[]>((resolve, reject) => {
        const req = indexedDB.open('e2ee-chat');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains('records')) {
            db.close();
            resolve([]);
            return;
          }
          const tx = db.transaction('records', 'readonly');
          const keysReq = tx.objectStore('records').getAllKeys();
          keysReq.onerror = () => {
            db.close();
            reject(keysReq.error);
          };
          keysReq.onsuccess = () => {
            const keys = keysReq.result;
            db.close();
            resolve(keys);
          };
        };
      });
      return { anchor, recordKeys };
    }, ROLLBACK_ANCHOR_KEY);
    expect(clearedState.anchor).toBeNull();
    expect(clearedState.recordKeys).toEqual([]);

    // Fresh vault creation with a new passphrase must succeed cleanly.
    const freshPassphrase = 'fresh vault passphrase 2026';
    await dialog.locator('#name').fill('Bob Fresh');
    await dialog.locator('#password').fill(freshPassphrase);
    await dialog.locator('#repeat').fill(freshPassphrase);
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Lock the vault' })).toBeVisible();
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Bob Fresh');
  });
});
