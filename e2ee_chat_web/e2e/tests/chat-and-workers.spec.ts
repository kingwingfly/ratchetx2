import { expect, test } from '@playwright/test';
import {
  establishChat,
  fixturePath,
  sendFiles,
  sendTextMessage,
} from './helpers.ts';

test.describe('chat handshake, encrypted exchange, and compiled preview workers', () => {
  test('Alice and Bob exchange handshake, messages, and attachments exercising all compiled preview workers', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    const pageErrors: string[] = [];
    alicePage.on('pageerror', (err) => pageErrors.push(`alice: ${err.message}`));
    bobPage.on('pageerror', (err) => pageErrors.push(`bob: ${err.message}`));

    try {
      await establishChat(alicePage, bobPage, 'Alice', 'Bob');

      // 1. Bidirectional encrypted text exchange over live wrangler dev DO + WS.
      const aliceMsg = 'Hello Bob over real PQ ratchet!';
      await sendTextMessage(alicePage, aliceMsg);
      await expect(bobPage.locator('.messages .bubble', { hasText: aliceMsg })).toBeVisible();

      const bobMsg = 'Hi Alice, encrypted reply received!';
      await sendTextMessage(bobPage, bobMsg);
      await expect(alicePage.locator('.messages .bubble', { hasText: bobMsg })).toBeVisible();

      // 2. Send attachments covering all compiled preview workers:
      //    - preview_code_systems (sample.rs) + preview_search
      //    - preview_code_web (sample.ts)
      //    - preview_code_scripts (sample.py)
      //    - preview_code_apps (sample.java)
      //    - preview_diagram (diagram.md)
      //    - preview_pdf (sample-15pages.pdf)
      //    - preview_audio (sample.wav)
      await sendFiles(alicePage, [
        fixturePath('sample.rs'),
        fixturePath('sample.ts'),
        fixturePath('sample.py'),
        fixturePath('sample.java'),
        fixturePath('diagram.md'),
        fixturePath('sample-15pages.pdf'),
        fixturePath('sample.wav'),
      ]);

      const viewer = bobPage.locator('dialog.viewer');
      const closeViewer = async () => {
        await viewer.getByRole('button', { name: 'Close', exact: true }).click();
        await expect(viewer).not.toHaveAttribute('open', '');
      };

      // (a) preview_code_systems + preview_search
      const rsCard = bobPage.locator('.messages .file-card', { hasText: 'sample.rs' });
      await expect(rsCard).toBeVisible();
      await rsCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const rsCode = viewer.locator('pre.code code[data-lang="rust"]');
      await expect(rsCode).toBeVisible();
      await expect(rsCode.locator('span[class^="hl-"]').first()).toBeVisible();
      await expect(viewer.locator('pre.code')).not.toHaveAttribute('data-error');

      // Exercise `preview_search` worker in the open code viewer.
      const searchInput = viewer.locator('.search input[type="search"]');
      await expect(searchInput).toBeVisible();
      await searchInput.fill('SEARCH_MARKER_RUST');
      await expect(viewer.locator('.search-count')).toHaveText('1 / 1');
      await closeViewer();

      // (b) preview_code_web
      const tsCard = bobPage.locator('.messages .file-card', { hasText: 'sample.ts' });
      await expect(tsCard).toBeVisible();
      await tsCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const tsCode = viewer.locator('pre.code code[data-lang="typescript"]');
      await expect(tsCode).toBeVisible();
      await expect(tsCode.locator('span[class^="hl-"]').first()).toBeVisible();
      await expect(viewer.locator('pre.code')).not.toHaveAttribute('data-error');
      await closeViewer();

      // (c) preview_code_scripts
      const pyCard = bobPage.locator('.messages .file-card', { hasText: 'sample.py' });
      await expect(pyCard).toBeVisible();
      await pyCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const pyCode = viewer.locator('pre.code code[data-lang="python"]');
      await expect(pyCode).toBeVisible();
      await expect(pyCode.locator('span[class^="hl-"]').first()).toBeVisible();
      await expect(viewer.locator('pre.code')).not.toHaveAttribute('data-error');
      await closeViewer();

      // (d) preview_code_apps
      const javaCard = bobPage.locator('.messages .file-card', { hasText: 'sample.java' });
      await expect(javaCard).toBeVisible();
      await javaCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const javaCode = viewer.locator('pre.code code[data-lang="java"]');
      await expect(javaCode).toBeVisible();
      await expect(javaCode.locator('span[class^="hl-"]').first()).toBeVisible();
      await expect(viewer.locator('pre.code')).not.toHaveAttribute('data-error');
      await closeViewer();

      // (e) preview_diagram (Mermaid fenced block inside Markdown)
      const mdCard = bobPage.locator('.messages .file-card', { hasText: 'diagram.md' });
      await expect(mdCard).toBeVisible();
      await mdCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const diagramImg = viewer.locator('img.diagram');
      await expect(diagramImg).toBeVisible();
      const diagramSrc = await diagramImg.getAttribute('src');
      expect(diagramSrc).toMatch(/^data:image\/svg\+xml;base64,/);
      const decodedSvg = Buffer.from(
        diagramSrc!.replace(/^data:image\/svg\+xml;base64,/, ''),
        'base64',
      ).toString('utf8');
      expect(decodedSvg).toContain('<svg');
      await closeViewer();

      // (f) preview_pdf
      const pdfCard = bobPage.locator('.messages .file-card', { hasText: 'sample-15pages.pdf' });
      await expect(pdfCard).toBeVisible();
      await pdfCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      await expect(viewer.locator('.pdf .pdf-page')).toHaveCount(15);
      const drawnCanvas = viewer.locator('.pdf canvas[data-drawn="yes"]').first();
      await expect(drawnCanvas).toBeVisible();
      const dims = await drawnCanvas.evaluate((c: HTMLCanvasElement) => ({
        w: c.width,
        h: c.height,
      }));
      expect(dims.w).toBeGreaterThan(0);
      expect(dims.h).toBeGreaterThan(0);
      await closeViewer();

      // (g) preview_audio (inline audio clip opens AudioView and displays worker-extracted tags)
      const wavClipButton = bobPage.locator('.messages .inline-media .clip-name', {
        hasText: 'sample.wav',
      });
      await expect(wavClipButton).toBeVisible();
      await wavClipButton.click();
      await expect(viewer).toHaveAttribute('open', '');
      await expect(viewer.locator('.track-text strong')).toHaveText('Fixture Tone');
      await expect(viewer.locator('.track-text .artist')).toHaveText('E2EE Test');
      await closeViewer();

      expect(pageErrors).toEqual([]);
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });

  test('preview worker crash recovers cleanly on subsequent call without hanging FIFO queue', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      // Intercept Bob's `preview_code_systems_loader.js`: fail the first start with an uncaught
      // error to trigger `worker.onerror`, then allow the real compiled worker to load on retry.
      let loaderRequests = 0;
      await bobPage.route('**/preview_code_systems_loader.js', async (route) => {
        loaderRequests += 1;
        if (loaderRequests === 1) {
          await route.fulfill({
            status: 200,
            contentType: 'application/javascript; charset=utf-8',
            body: 'throw new Error("e2e simulated preview worker crash");',
          });
        } else {
          await route.continue();
        }
      });

      await establishChat(alicePage, bobPage, 'AliceCrash', 'BobCrash');
      await sendFiles(alicePage, fixturePath('sample.rs'));

      const rsCard = bobPage.locator('.messages .file-card', { hasText: 'sample.rs' });
      await expect(rsCard).toBeVisible();

      const viewer = bobPage.locator('dialog.viewer');

      // 1st open: crashed worker fails cleanly (surfaces `data-error`) without hanging UI.
      await rsCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      await expect(viewer.locator('pre.code')).toHaveAttribute('data-error', /preview failed/i);
      expect(loaderRequests).toBe(1);
      await viewer.getByRole('button', { name: 'Close', exact: true }).click();
      await expect(viewer).not.toHaveAttribute('open', '');

      // 2nd open: fresh worker spawns, FIFO queue is not stuck, syntax highlighting succeeds.
      await rsCard.click();
      await expect(viewer).toHaveAttribute('open', '');
      const rsCode = viewer.locator('pre.code code[data-lang="rust"]');
      await expect(rsCode).toBeVisible();
      await expect(rsCode.locator('span[class^="hl-"]').first()).toBeVisible();
      await expect(viewer.locator('pre.code')).not.toHaveAttribute('data-error');
      expect(loaderRequests).toBeGreaterThanOrEqual(2);
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });
});
