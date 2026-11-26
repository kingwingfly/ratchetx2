import { expect, test, type Page } from '@playwright/test';
import {
  LEGACY_ROLLBACK_ANCHOR_KEY,
  ROLLBACK_ANCHOR_KEY,
  TEST_PASSPHRASE,
  createVault,
  establishChat,
  fixturePath,
  lockVault,
  sendFiles,
  sendTextMessage,
  unlockVault,
} from './helpers.ts';

const EXPECTED_WORKER_MANIFEST_KEYS = [
  'vault_kdf',
  'pdf',
  'audio',
  'search',
  'diagram',
  'markdown',
  'code_web',
  'code_systems',
  'code_apps',
  'code_scripts',
] as const;

const LEGACY_IDB_PREFIXES = ['history:', 'file:', 'chunk:', 'outbox:', 'upload:', 'deferred'];

async function inspectVaultIdb(page: Page): Promise<{ version: number; keys: string[] }> {
  return page.evaluate(async () => {
    return new Promise<{ version: number; keys: string[] }>((resolve, reject) => {
      const req = indexedDB.open('e2ee-chat');
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        const db = req.result;
        const version = db.version;
        const tx = db.transaction('records', 'readonly');
        const keysReq = tx.objectStore('records').getAllKeys();
        keysReq.onerror = () => {
          db.close();
          reject(keysReq.error);
        };
        keysReq.onsuccess = () => {
          const keys = keysReq.result.map(String);
          db.close();
          resolve({ version, keys });
        };
      };
    });
  });
}

function assertOpaqueV3IdbKeys(
  idb: { version: number; keys: string[] },
  opts: { requireOpaqueRecords?: boolean } = {},
): void {
  expect(idb.version).toBe(3);
  expect(idb.keys).toContain('vault');
  expect(idb.keys).toContain('state');
  const opaqueKeys: string[] = [];
  for (const key of idb.keys) {
    if (key === 'vault' || key === 'state') continue;
    for (const prefix of LEGACY_IDB_PREFIXES) {
      expect(key, `cleartext legacy IDB key "${key}" leaked`).not.toContain(prefix);
    }
    expect(key, `raw IDB key "${key}" must be opaque 64-hex`).toMatch(/^[0-9a-f]{64}$/);
    opaqueKeys.push(key);
  }
  if (opts.requireOpaqueRecords) {
    expect(opaqueKeys.length).toBeGreaterThan(0);
  }
}

test.describe('vault lifecycle', () => {
  test('first-boot create, opaque IDB keys, lock, wrong passphrase rejection, and unlock', async ({
    page,
  }) => {
    await createVault(page, 'Alice', TEST_PASSPHRASE, { signIn: false });

    const anchor = await page.evaluate((key) => localStorage.getItem(key), ROLLBACK_ANCHOR_KEY);
    expect(anchor).toMatch(/^v3:\d+:[0-9a-f]{32}$/);

    // Verify IndexedDB (`e2ee-chat` v3) keys are only `"vault"`, `"state"`, or 64-hex HMAC keys.
    assertOpaqueV3IdbKeys(await inspectVaultIdb(page));

    await lockVault(page);

    const dialog = page.locator('dialog.modal');
    await dialog.locator('#password').fill('wrong passphrase 123');
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(dialog.locator('.error')).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

    await unlockVault(page, TEST_PASSPHRASE);
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Alice');
  });

  test('real browser IndexedDB (v3) contains only "vault", "state", and 64-hex opaque keys after message and file exchange', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    try {
      await establishChat(alicePage, bobPage, 'Alice IDB', 'Bob IDB');

      const messageText = 'Opaque IndexedDB v3 audit message';
      await sendTextMessage(alicePage, messageText);
      await expect(bobPage.locator('.messages .bubble', { hasText: messageText })).toBeVisible();

      await sendFiles(alicePage, [fixturePath('sample.rs'), fixturePath('pixel.png')]);
      await expect(alicePage.locator('.uploads .upload')).toHaveCount(0);
      await expect(bobPage.locator('.messages .file-card', { hasText: 'sample.rs' })).toBeVisible();
      await expect(bobPage.locator('.messages .inline-media button.thumb').first()).toBeVisible();

      assertOpaqueV3IdbKeys(await inspectVaultIdb(alicePage), { requireOpaqueRecords: true });
      assertOpaqueV3IdbKeys(await inspectVaultIdb(bobPage), { requireOpaqueRecords: true });
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });

  test('vault_kdf worker manifest wiring, cancelable KDF UX during create & unlock, and real derivation', async ({
    page,
  }) => {
    await page.goto('/');
    const dialog = page.locator('dialog.modal');
    await expect(dialog.getByRole('heading', { name: 'Create your vault' })).toBeVisible();

    // 1. Verify `<meta name="e2ee-worker-manifest">` contains all 10 expected hashed worker keys.
    const manifest = await page.evaluate(() => {
      const meta = document.querySelector('meta[name="e2ee-worker-manifest"]');
      return meta ? (JSON.parse(meta.getAttribute('content') || '{}') as Record<string, string>) : null;
    });
    expect(manifest).not.toBeNull();
    expect(Object.keys(manifest!).sort()).toEqual([...EXPECTED_WORKER_MANIFEST_KEYS].sort());
    for (const key of EXPECTED_WORKER_MANIFEST_KEYS) {
      const prefix = key === 'vault_kdf' ? 'vault_kdf' : `preview_${key}`;
      expect(manifest![key], `manifest.${key}`).toMatch(
        new RegExp(`^/assets/${prefix}-[0-9a-f]+_loader\\.js$`),
      );
    }

    // 2. Cancel during Create: pause the `vault_kdf` worker script fetch deterministically so we
    //    can assert the accessible KDF spinner, status text, disabled inputs, and working Cancel
    //    button regardless of host CPU speed.
    let releaseCreateRoute: (() => void) | null = null;
    const createRouteGate = new Promise<void>((resolve) => {
      releaseCreateRoute = resolve;
    });
    let sawCreateKdfRequest = false;
    const holdCreateRoute = async (route: import('@playwright/test').Route) => {
      sawCreateKdfRequest = true;
      await createRouteGate;
      // Clicking Cancel invokes `worker.terminate()`, which already aborts this intercepted fetch.
      await route.continue().catch(() => {});
    };
    await page.route('**/assets/vault_kdf-*_loader.js', holdCreateRoute);

    await dialog.locator('#name').fill('Alice KDF');
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.locator('#repeat').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();

    await expect(dialog.locator('.error.working')).toBeVisible();
    await expect(dialog.locator('.error.working .kdf-spinner')).toBeVisible();
    await expect(dialog.locator('.error.working')).toContainText('Deriving encryption key…');
    await expect(dialog.locator('#password')).toBeDisabled();
    const cancelBtn = dialog.getByRole('button', { name: 'Cancel', exact: true });
    await expect(cancelBtn).toBeVisible();
    await expect.poll(() => sawCreateKdfRequest).toBe(true);

    // Click Cancel: terminates ephemeral worker immediately and returns to editable form cleanly.
    await cancelBtn.click();
    await expect(dialog.locator('#password')).toBeEnabled();
    await expect(dialog.locator('.error.working')).toHaveCount(0);
    await expect(dialog.getByRole('heading', { name: 'Create your vault' })).toBeVisible();
    await page.unroute('**/assets/vault_kdf-*_loader.js', holdCreateRoute);
    releaseCreateRoute!();

    // Confirm zero vault was written to IndexedDB after cancelled Create.
    const anchorAfterCancel = await page.evaluate(
      (key) => localStorage.getItem(key),
      ROLLBACK_ANCHOR_KEY,
    );
    expect(anchorAfterCancel).toBeNull();

    // 3. Complete real vault creation via the ephemeral `vault_kdf` worker.
    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.locator('#repeat').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Lock the vault' })).toBeVisible();
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Alice KDF');

    // Dismiss auto-opened SignInDialog cleanly before locking.
    const signInHeading = dialog.getByRole('heading', { name: 'Sign in to this server' });
    await expect(signInHeading).toBeVisible();
    await dialog.getByRole('button', { name: 'Not now', exact: true }).click();
    await expect(signInHeading).toBeHidden();

    // 4. Lock vault and verify Cancel during Unlock.
    await lockVault(page);

    let releaseUnlockRoute: (() => void) | null = null;
    const unlockRouteGate = new Promise<void>((resolve) => {
      releaseUnlockRoute = resolve;
    });
    let sawUnlockKdfRequest = false;
    const holdUnlockRoute = async (route: import('@playwright/test').Route) => {
      sawUnlockKdfRequest = true;
      await unlockRouteGate;
      await route.continue().catch(() => {});
    };
    await page.route('**/assets/vault_kdf-*_loader.js', holdUnlockRoute);

    await dialog.locator('#password').fill(TEST_PASSPHRASE);
    await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();

    await expect(dialog.locator('.error.working')).toBeVisible();
    await expect(dialog.locator('.error.working .kdf-spinner')).toBeVisible();
    await expect(dialog.locator('.error.working')).toContainText('Deriving encryption key…');
    await expect(dialog.locator('#password')).toBeDisabled();
    const unlockCancelBtn = dialog.getByRole('button', { name: 'Cancel', exact: true });
    await expect(unlockCancelBtn).toBeVisible();
    await expect.poll(() => sawUnlockKdfRequest).toBe(true);

    await unlockCancelBtn.click();
    await expect(dialog.locator('#password')).toBeEnabled();
    await expect(dialog.locator('.error.working')).toHaveCount(0);
    await expect(dialog.getByRole('button', { name: 'Forgot it: start over', exact: true })).toBeVisible();
    await page.unroute('**/assets/vault_kdf-*_loader.js', holdUnlockRoute);
    releaseUnlockRoute!();

    // 5. Complete real Unlock via the ephemeral `vault_kdf` worker.
    await unlockVault(page, TEST_PASSPHRASE);
    await expect(page.locator('.sidebar-foot .whoami strong')).toHaveText('Alice KDF');
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
