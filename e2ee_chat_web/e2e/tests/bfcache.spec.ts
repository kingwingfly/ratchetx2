import { expect, test } from '@playwright/test';
import {
  TEST_PASSPHRASE,
  establishChat,
  lockVault,
  sendTextMessage,
  unlockVault,
} from './helpers.ts';

test.describe('bfcache restoration and synchronous pagehide scrub (chromium-bfcache)', () => {
  test('pageshow persisted === true triggers clean reload via glue.rs lifecycle handler', async ({
    page,
  }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Page.enable');
    const notRestoredEvents: unknown[] = [];
    cdp.on('Page.backForwardCacheNotUsed', (evt) => {
      notRestoredEvents.push(evt);
    });

    // Load the app: `Engine::start()` acquires the exclusive `"e2ee-chat"` Web Lock and installs
    // `glue.rs`'s `pagehide` (synchronous teardown + Web Lock release) and `pageshow`
    // (`persisted => reload`) handlers. Waiting for `Create your vault` proves startup & lock
    // acquisition completed cleanly without an open WebSocket or open IndexedDB write transaction
    // blocking Chromium bfcache.
    await page.goto('/');
    const createHeading = page.locator('dialog.modal').getByRole('heading', {
      name: 'Create your vault',
    });
    await expect(createHeading).toBeVisible();

    // Record a JS-heap marker and append every `pagehide`/`pageshow` transition into
    // `sessionStorage` so we capture the full sequence:
    //   1. `pagehide` (`persisted: true`) on navigation away -> enters bfcache
    //   2. `pageshow` (`persisted: true`) on `goBack()` -> restored from bfcache
    //   3. `pagehide` (`persisted: false`) as `glue.rs` triggers `window.location.reload()`
    //   4. Fresh document load with `__e2eDocInstance === undefined`
    await page.evaluate(() => {
      sessionStorage.setItem('e2e_bfcache_events', '[]');
      (window as unknown as Record<string, string>).__e2eDocInstance = 'pre-bfcache';
      const pushEvent = (type: string, persisted: boolean) => {
        const list = JSON.parse(sessionStorage.getItem('e2e_bfcache_events') || '[]');
        list.push({ type, persisted });
        sessionStorage.setItem('e2e_bfcache_events', JSON.stringify(list));
      };
      window.addEventListener('pagehide', (event) => pushEvent('pagehide', event.persisted));
      window.addEventListener('pageshow', (event) => pushEvent('pageshow', event.persisted));
    });

    // Navigate away to a real server endpoint (avoiding `page.route` CDP interception) so Chromium
    // snapshots the previous document into bfcache.
    await page.goto('/auth');
    await expect(page.locator('body')).toContainText('{}');

    // Go back: Chromium restores `/` from bfcache -> `pageshow` (`persisted === true`) fires ->
    // `glue.rs` invokes `window.location.reload()` -> fresh document loads cleanly.
    await page.goBack();
    await expect(createHeading).toBeVisible();

    // Wait for `window.location.reload()` triggered by `pageshow` (`persisted === true`) to finish
    // replacing the pre-bfcache document instance.
    await expect
      .poll(() =>
        page.evaluate(
          () => (window as unknown as Record<string, string | undefined>).__e2eDocInstance,
        ),
      )
      .toBeUndefined();
    await expect(createHeading).toBeVisible();

    const events = await page.evaluate(
      () =>
        JSON.parse(sessionStorage.getItem('e2e_bfcache_events') || '[]') as Array<{
          type: string;
          persisted: boolean;
        }>,
    );

    expect(events, `notRestored: ${JSON.stringify(notRestoredEvents)}`).toEqual(
      expect.arrayContaining([
        { type: 'pagehide', persisted: true },
        { type: 'pageshow', persisted: true },
        { type: 'pagehide', persisted: false },
      ]),
    );
  });

  test('synchronous pagehide scrubs unlocked DOM, messages, contacts, and unread document.title', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    try {
      const secretText = 'CLASSIFIED-PAGEHIDE-SCRUB-PAYLOAD-9876';
      await establishChat(alicePage, bobPage, 'Alice Scrub', 'Bob Scrub');

      // Send a message while Alice has Bob open so Alice's DOM holds both the peer name and secret
      // text, and also trigger an unread badge in Bob's title after Bob closes back to the chat list.
      await sendTextMessage(alicePage, secretText);
      await expect(bobPage.locator('.messages .bubble', { hasText: secretText })).toBeVisible();

      // Close Bob's chat pane, then send another message from Alice so Bob's `document.title`
      // includes an unread counter (`(1) ratchetx2 chat`) before navigating away.
      await bobPage.getByRole('button', { name: 'Close the chat' }).click();
      await expect(bobPage.locator('.pane.welcome')).toBeVisible();
      const unreadSecret = 'UNREAD-TITLE-SCRUB-SECRET-4321';
      await sendTextMessage(alicePage, unreadSecret);
      await expect.poll(() => bobPage.title()).toMatch(/^\(\d+\) /);

      // Register a `pagehide` observer AFTER app boot so `glue.rs`'s synchronous `pagehide`
      // handler runs FIRST in listener order, letting us inspect the exact DOM and `document.title`
      // state synchronously at `pagehide` time (what bfcache snapshots!).
      const installObserver = () => {
        window.addEventListener('pagehide', (event) => {
          const snapshot = {
            persisted: event.persisted,
            title: document.title,
            bodyText: document.body.innerText,
            mainCount: document.querySelectorAll('.main').length,
            bubbleCount: document.querySelectorAll('.messages .bubble').length,
            chatItemCount: document.querySelectorAll('.chat-item').length,
            modalText: document.querySelector('dialog.modal')?.textContent ?? '',
          };
          sessionStorage.setItem('e2e_pagehide_scrub', JSON.stringify(snapshot));
        });
      };
      await alicePage.evaluate(installObserver);
      await bobPage.evaluate(installObserver);

      // Navigate both unlocked pages away to `/auth`.
      await alicePage.goto('/auth');
      await expect(alicePage.locator('body')).toContainText('"subject"');
      await bobPage.goto('/auth');
      await expect(bobPage.locator('body')).toContainText('"subject"');

      const readSnapshot = async (p: typeof alicePage) =>
        p.evaluate(
          () =>
            JSON.parse(sessionStorage.getItem('e2e_pagehide_scrub') || 'null') as {
              persisted: boolean;
              title: string;
              bodyText: string;
              mainCount: number;
              bubbleCount: number;
              chatItemCount: number;
              modalText: string;
            } | null,
        );

      const aliceSnap = await readSnapshot(alicePage);
      expect(aliceSnap).not.toBeNull();
      expect(aliceSnap!.title).toBe('E2EE Chat');
      expect(aliceSnap!.mainCount).toBe(0);
      expect(aliceSnap!.bubbleCount).toBe(0);
      expect(aliceSnap!.chatItemCount).toBe(0);
      expect(aliceSnap!.bodyText).not.toContain(secretText);
      expect(aliceSnap!.bodyText).not.toContain(unreadSecret);
      expect(aliceSnap!.bodyText).not.toContain('Bob Scrub');
      expect(aliceSnap!.bodyText).not.toContain('Alice Scrub');
      expect(aliceSnap!.modalText).toContain('Unlock your vault');

      const bobSnap = await readSnapshot(bobPage);
      expect(bobSnap).not.toBeNull();
      expect(bobSnap!.title).toBe('E2EE Chat');
      expect(bobSnap!.mainCount).toBe(0);
      expect(bobSnap!.bubbleCount).toBe(0);
      expect(bobSnap!.chatItemCount).toBe(0);
      expect(bobSnap!.bodyText).not.toContain(secretText);
      expect(bobSnap!.bodyText).not.toContain(unreadSecret);
      expect(bobSnap!.bodyText).not.toContain('Alice Scrub');
      expect(bobSnap!.bodyText).not.toContain('Bob Scrub');
      expect(bobSnap!.modalText).toContain('Unlock your vault');

      // Navigating back must land cleanly on the locked vault modal (never displaying plaintext).
      await alicePage.goBack();
      await expect(
        alicePage.locator('dialog.modal').getByRole('heading', { name: 'Unlock your vault' }),
      ).toBeVisible();
      await expect(alicePage.locator('.messages .bubble')).toHaveCount(0);
      await expect(alicePage).toHaveTitle('E2EE Chat');
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });

  test('manual Lock while a chat is open scrubs state and reloads without calling history.back()', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    try {
      const secretText = 'MANUAL-LOCK-OPEN-CHAT-SECRET-5555';
      await establishChat(alicePage, bobPage, 'Alice Lock', 'Bob Lock');
      await sendTextMessage(alicePage, secretText);
      await expect(bobPage.locator('.messages .bubble', { hasText: secretText })).toBeVisible();

      // Confirm Alice currently has Bob's chat open with a pushed chat-level history entry.
      const preLockState = await alicePage.evaluate(() => String(window.history.state ?? ''));
      expect(preLockState).toMatch(/^ratchetx2-chat:/);

      // Spy on `window.history.back()` and `popstate` across the manual Lock reload.
      await alicePage.evaluate(() => {
        sessionStorage.setItem('e2e_lock_back_calls', '0');
        sessionStorage.setItem('e2e_lock_popstate_calls', '0');
        (window as unknown as Record<string, string>).__e2ePreLockInstance = 'before-lock';
        const origBack = window.history.back.bind(window.history);
        window.history.back = () => {
          const n = Number(sessionStorage.getItem('e2e_lock_back_calls') || '0') + 1;
          sessionStorage.setItem('e2e_lock_back_calls', String(n));
          return origBack();
        };
        window.addEventListener('popstate', () => {
          const n = Number(sessionStorage.getItem('e2e_lock_popstate_calls') || '0') + 1;
          sessionStorage.setItem('e2e_lock_popstate_calls', String(n));
        });
      });

      // Click "Lock the vault" while Bob's chat is open.
      await lockVault(alicePage);

      // Wait for the fresh reload to replace the pre-lock document instance cleanly.
      await expect
        .poll(() =>
          alicePage.evaluate(
            () => (window as unknown as Record<string, string | undefined>).__e2ePreLockInstance,
          ),
        )
        .toBeUndefined();
      await expect(
        alicePage.locator('dialog.modal').getByRole('heading', { name: 'Unlock your vault' }),
      ).toBeVisible();
      await expect(alicePage.locator('.messages .bubble')).toHaveCount(0);
      await expect(alicePage).toHaveTitle('E2EE Chat');

      const counts = await alicePage.evaluate(() => ({
        backCalls: Number(sessionStorage.getItem('e2e_lock_back_calls') || '0'),
        popstateCalls: Number(sessionStorage.getItem('e2e_lock_popstate_calls') || '0'),
      }));
      expect(counts.backCalls).toBe(0);
      expect(counts.popstateCalls).toBe(0);

      // Unlocking afterwards restores Bob's chat cleanly.
      await unlockVault(alicePage, TEST_PASSPHRASE);
      await expect(alicePage.locator('.chat-item', { hasText: 'Bob Lock' })).toBeVisible();
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });
});
