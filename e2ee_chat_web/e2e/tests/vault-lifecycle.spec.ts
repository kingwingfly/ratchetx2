import { expect, test } from '@playwright/test';
import {
  LEGACY_ROLLBACK_ANCHOR_KEY,
  ROLLBACK_ANCHOR_KEY,
  TEST_PASSPHRASE,
  createVault,
  lockVault,
  unlockVault,
} from './helpers.ts';

test.describe('vault lifecycle', () => {
  test('first-boot create, opaque IDB keys, lock, wrong passphrase rejection, and unlock', async ({
    page,
  }) => {
    await createVault(page, 'Alice', TEST_PASSPHRASE, { signIn: false });

    const anchor = await page.evaluate((key) => localStorage.getItem(key), ROLLBACK_ANCHOR_KEY);
    expect(anchor).toMatch(/^v3:\d+:[0-9a-f]{32}$/);

    // Verify all raw IndexedDB keys are either literal `"vault"`/`"state"` or 64-hex HMAC keys.
    const rawKeys = await page.evaluate(async () => {
      return new Promise<string[]>((resolve, reject) => {
        const req = indexedDB.open('e2ee-chat');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('records', 'readonly');
          const keysReq = tx.objectStore('records').getAllKeys();
          keysReq.onerror = () => {
            db.close();
            reject(keysReq.error);
          };
          keysReq.onsuccess = () => {
            const keys = keysReq.result.map(String);
            db.close();
            resolve(keys);
          };
        };
      });
    });
    expect(rawKeys).toContain('vault');
    expect(rawKeys).toContain('state');
    for (const k of rawKeys) {
      if (k !== 'vault' && k !== 'state') {
        expect(k, `raw IDB key "${k}" must be opaque 64-hex`).toMatch(/^[0-9a-f]{64}$/);
      }
    }

    await lockVault(page);

    const dialog = page.locator('dialog.modal');
    await dialog.locator('#password').fill('wrong passphrase 123');
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    await unlockVault(page, TEST_PASSPHRASE);
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Alice');
  });

  test('v3 rollback anchor rejection (stale revision & vault_id swap) and 2-step ConfirmGuard reset', async ({
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
    expect(parts).toHaveLength(3);
    const [prefix, revStr, vaultIdHex] = parts;
    expect(prefix).toBe('v3');
    const rev = Number(revStr);
    expect(Number.isInteger(rev) && rev >= 1).toBe(true);
    expect(vaultIdHex).toMatch(/^[0-9a-f]{32}$/);

    const dialog = page.locator('dialog.modal');

    // 1. Stale revision rollback: external anchor is ahead of the IDB header revision.
    await page.evaluate(
      ({ key, value }) => localStorage.setItem(key, value),
      { key: ROLLBACK_ANCHOR_KEY, value: `${prefix}:${rev + 10}:${vaultIdHex}` },
    );
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toContainText(/rollback/i);
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    // 2. vault_id swap rollback: anchor vault_id differs from the IDB header vault_id.
    const swappedId = vaultIdHex.startsWith('0')
      ? `f${vaultIdHex.slice(1)}`
      : `0${vaultIdHex.slice(1)}`;
    await page.evaluate(
      ({ key, value }) => localStorage.setItem(key, value),
      { key: ROLLBACK_ANCHOR_KEY, value: `${prefix}:${rev}:${swappedId}` },
    );
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toContainText(/vault_id|rollback|replacement/i);
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

  test('incompatible v2 vault header triggers pre-KDF IncompatibleVault screen and 2-step reset', async ({
    page,
  }) => {
    // Load a static same-origin asset first so zero app IndexedDB handles are open while seeding
    // a real legacy v2 IndexedDB database with an absurd Argon2 memory header (u32::MAX) + v1 anchor.
    await page.goto('/media-worker.js');
    await page.evaluate(async (legacyAnchorKey) => {
      await new Promise<void>((resolve, reject) => {
        const del = indexedDB.deleteDatabase('e2ee-chat');
        del.onerror = () => reject(del.error);
        del.onblocked = () => reject(new Error('deleteDatabase blocked'));
        del.onsuccess = () => resolve();
      });
      await new Promise<void>((resolve, reject) => {
        const open = indexedDB.open('e2ee-chat', 2);
        open.onerror = () => reject(open.error);
        open.onupgradeneeded = () => {
          const db = open.result;
          if (!db.objectStoreNames.contains('records')) {
            db.createObjectStore('records');
          }
        };
        open.onsuccess = () => {
          const db = open.result;
          const tx = db.transaction('records', 'readwrite');
          // Protobuf VaultHeader: salt(tag 1, 16B), memory=u32::MAX(tag 2),
          // iterations=3(tag 3), parallelism=1(tag 4), version=2(tag 5), revision=1(tag 6).
          const header = new Uint8Array([
            0x0a, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            0x10, 0xff, 0xff, 0xff, 0xff, 0x0f,
            0x18, 0x03,
            0x20, 0x01,
            0x28, 0x02,
            0x30, 0x01,
          ]);
          tx.objectStore('records').put(header, 'vault');
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => {
            db.close();
            reject(tx.error);
          };
        };
      });
      localStorage.setItem(legacyAnchorKey, `v1:1:5:${'ab'.repeat(32)}`);
    }, LEGACY_ROLLBACK_ANCHOR_KEY);

    await page.goto('/');
    const dialog = page.locator('dialog.modal');
    await expect(dialog.getByRole('heading', { name: 'Incompatible vault format' })).toBeVisible();
    await expect(dialog).toContainText('format version 2');
    await expect(dialog.locator('#password')).toHaveCount(0);

    // 1st click arms ConfirmGuard without deleting legacy vault or anchor yet.
    const resetBtn = dialog.getByRole('button', { name: 'Reset vault and start over', exact: true });
    await resetBtn.click();
    const confirmBtn = dialog.getByRole('button', {
      name: 'Delete old vault, for good?',
      exact: true,
    });
    await expect(confirmBtn).toBeVisible();
    const legacyStillThere = await page.evaluate(
      (k) => localStorage.getItem(k),
      LEGACY_ROLLBACK_ANCHOR_KEY,
    );
    expect(legacyStillThere).not.toBeNull();

    // 2nd click destroys IDB + legacy & v3 anchors and returns cleanly to CreateVault.
    await confirmBtn.click();
    await expect(dialog.getByRole('heading', { name: 'Create your vault' })).toBeVisible();
    const legacyAfter = await page.evaluate(
      (k) => localStorage.getItem(k),
      LEGACY_ROLLBACK_ANCHOR_KEY,
    );
    expect(legacyAfter).toBeNull();
  });
});
