import { expect, test } from '@playwright/test';

test.describe('bfcache restoration (chromium-bfcache)', () => {
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
    // `glue.rs`'s `pagehide` (synchronous Web Lock release) and `pageshow` (`persisted => reload`)
    // handlers. Waiting for `Create your vault` proves startup & lock acquisition completed cleanly
    // without an open WebSocket or open IndexedDB write transaction blocking Chromium bfcache.
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
});
