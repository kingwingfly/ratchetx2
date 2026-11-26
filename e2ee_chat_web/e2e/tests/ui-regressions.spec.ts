import { expect, test } from '@playwright/test';
import {
  establishChat,
  fixturePath,
  sendFiles,
  sendTextMessage,
} from './helpers.ts';

test.describe('UI lifecycle regressions (PdfView, InlineMedia, FileBrowser)', () => {
  test('PdfView caps active canvases <= 9 across scrolling and zeroes canvases on close', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      await establishChat(alicePage, bobPage, 'AlicePdf', 'BobPdf');
      await sendFiles(alicePage, fixturePath('sample-15pages.pdf'));

      const pdfCard = bobPage.locator('.messages .file-card', { hasText: 'sample-15pages.pdf' });
      await expect(pdfCard).toBeVisible();
      await pdfCard.click();

      const viewer = bobPage.locator('dialog.viewer');
      await expect(viewer).toHaveAttribute('open', '');
      await expect(viewer.locator('.pdf .pdf-page')).toHaveCount(15);

      const inspectCanvases = async () =>
        bobPage.evaluate(() => {
          const canvases = Array.from(
            document.querySelectorAll<HTMLCanvasElement>('.viewer .pdf canvas'),
          );
          const nonZero = canvases.filter((c) => c.width > 0 && c.height > 0);
          return { total: canvases.length, nonZero: nonZero.length };
        });

      // Top of PDF: page 0 draws, active canvases <= 9.
      await expect(viewer.locator('.pdf canvas[data-page="0"][data-drawn="yes"]')).toBeVisible();
      let stats = await inspectCanvases();
      expect(stats.total).toBeGreaterThan(0);
      expect(stats.total).toBeLessThanOrEqual(9);
      expect(stats.nonZero).toBeLessThanOrEqual(9);

      // Middle of PDF: scroll page 7 into view, assert page 7 draws and active canvases <= 9.
      await viewer.locator('.pdf .pdf-page[data-page="7"]').scrollIntoViewIfNeeded();
      await expect(viewer.locator('.pdf canvas[data-page="7"][data-drawn="yes"]')).toBeVisible();
      stats = await inspectCanvases();
      expect(stats.total).toBeLessThanOrEqual(9);
      expect(stats.nonZero).toBeLessThanOrEqual(9);

      // Bottom of PDF: scroll page 14 into view, assert page 14 draws and active canvases <= 9.
      await viewer.locator('.pdf .pdf-page[data-page="14"]').scrollIntoViewIfNeeded();
      await expect(viewer.locator('.pdf canvas[data-page="14"][data-drawn="yes"]')).toBeVisible();
      stats = await inspectCanvases();
      expect(stats.total).toBeLessThanOrEqual(9);
      expect(stats.nonZero).toBeLessThanOrEqual(9);

      // Capture live canvas references before closing to verify `on_cleanup` zeroes width & height.
      const capturedCount = await bobPage.evaluate(() => {
        const canvases = Array.from(
          document.querySelectorAll<HTMLCanvasElement>('.viewer .pdf canvas'),
        );
        (window as unknown as { __pdfCanvases: HTMLCanvasElement[] }).__pdfCanvases = canvases;
        return canvases.length;
      });
      expect(capturedCount).toBeGreaterThan(0);

      await viewer.getByRole('button', { name: 'Close', exact: true }).click();
      await expect(viewer).not.toHaveAttribute('open', '');
      await expect(viewer.locator('.pdf canvas')).toHaveCount(0);

      const postClose = await bobPage.evaluate(() => {
        const canvases =
          (window as unknown as { __pdfCanvases: HTMLCanvasElement[] }).__pdfCanvases ?? [];
        return canvases.map((c) => ({ width: c.width, height: c.height }));
      });
      for (const dim of postClose) {
        expect(dim).toEqual({ width: 0, height: 0 });
      }
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });

  test('InlineMedia lazy-loads on scroll, falls back to .file-card on corrupt media, and releases URL on unmount', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      await establishChat(alicePage, bobPage, 'AliceMedia', 'BobMedia');

      // 1. Send image first, then enough text messages to push it well above the fold, then
      //    corrupt WAV and valid WAV at the bottom.
      await sendFiles(alicePage, fixturePath('pixel.png'));
      await expect(bobPage.locator('.messages .inline-media button.thumb').first()).toBeVisible();

      for (let i = 1; i <= 18; i++) {
        await sendTextMessage(
          alicePage,
          `Filler line ${i}: ensuring earlier media scrolls cleanly out of the viewport.\nSecond line ${i}.`,
        );
      }
      await expect(bobPage.locator('.messages .bubble', { hasText: 'Filler line 18:' })).toBeVisible();

      // 2. Corrupt WAV: `media_mime` sniffs audio/wav -> mounts <audio> -> Chromium fires on:error ->
      //    InlineMedia falls back cleanly to `.file-card`.
      await sendFiles(alicePage, fixturePath('corrupt.wav'));
      const corruptFallback = bobPage.locator('.messages .inline-media button.file-card', {
        hasText: 'corrupt.wav',
      });
      await expect(corruptFallback).toBeVisible();
      await expect(
        bobPage.locator('.messages .inline-media', { hasText: 'corrupt.wav' }).locator('audio'),
      ).toHaveCount(0);

      // 3. Valid WAV at the bottom for unmount blob-URL release check.
      await sendFiles(alicePage, fixturePath('sample.wav'));
      const wavAudio = bobPage
        .locator('.messages .inline-media', { hasText: 'sample.wav' })
        .locator('audio');
      await expect(wavAudio).toBeVisible();

      // 4. Close and reopen the chat on Bob so history reloads from IndexedDB with
      //    `LocalFile { data: None }`, exercising true `when_shown` IntersectionObserver lazy load.
      await bobPage.getByRole('button', { name: 'Close the chat', exact: true }).click();
      await expect(bobPage.locator('.messages')).toHaveCount(0);

      await bobPage.locator('.chat-item').first().click();
      await expect(bobPage.locator('.messages')).toBeVisible();
      await expect(bobPage.locator('.messages .bubble', { hasText: 'Filler line 18:' })).toBeVisible();

      // Verify `pixel.png` is off-screen at the top and has NOT loaded its `<img>` yet.
      const pixelThumb = bobPage.locator('.messages .inline-media button.thumb').first();
      await expect(pixelThumb).toHaveCount(1);
      await expect(pixelThumb.locator('img')).toHaveCount(0);

      // Spy on `URL.revokeObjectURL` and capture the live `<audio>` element & src before unmounting.
      const trackedAudioSrc = await bobPage.evaluate(() => {
        const revoked: string[] = [];
        const origRevoke = URL.revokeObjectURL.bind(URL);
        URL.revokeObjectURL = (url: string) => {
          revoked.push(url);
          return origRevoke(url);
        };
        const audio = document.querySelector<HTMLAudioElement>('.messages .inline-media audio');
        const src = audio?.getAttribute('src') ?? '';
        (window as unknown as Record<string, unknown>).__mediaReleaseCheck = { revoked, audio };
        return src;
      });
      expect(trackedAudioSrc).toMatch(/^blob:/);

      // Scroll to top of `.messages` to bring `pixel.png` into view -> triggers lazy load.
      await bobPage.locator('.messages').evaluate((el) => {
        el.scrollTop = 0;
      });
      const pixelImg = pixelThumb.locator('img');
      await expect(pixelImg).toBeVisible();
      await expect
        .poll(() => pixelImg.evaluate((img: HTMLImageElement) => img.naturalWidth))
        .toBe(4);

      // 5. Close chat (unmount `InlineMedia`): verify `stop_media` cleared `src` and `release`
      //    revoked the audio blob URL.
      await bobPage.getByRole('button', { name: 'Close the chat', exact: true }).click();
      await expect(bobPage.locator('.messages')).toHaveCount(0);

      const releaseOutcome = await bobPage.evaluate(() => {
        const state = (
          window as unknown as {
            __mediaReleaseCheck: { revoked: string[]; audio: HTMLAudioElement | null };
          }
        ).__mediaReleaseCheck;
        return {
          revoked: state.revoked,
          audioHasSrc: state.audio?.hasAttribute('src') ?? false,
        };
      });
      expect(releaseOutcome.audioHasSrc).toBe(false);
      expect(releaseOutcome.revoked).toContain(trackedAudioSrc);
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });

  test('FileBrowser renders .file-grid on Media vs .file-list elsewhere and persists 2-step DeleteFromServer across shelf switches', async ({
    browser,
  }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      await establishChat(alicePage, bobPage, 'AliceFiles', 'BobFiles');

      // Send small files across Media, Code, and Archives shelves.
      await sendFiles(alicePage, [
        fixturePath('pixel.png'),
        fixturePath('sample.rs'),
        fixturePath('sample.zip'),
      ]);

      // Send a deterministic > 1 MiB (> INLINE_FILE_MAX) Markdown document so it uploads as a
      // remote server attachment (`Body::Remote`, `deletable = true`) via real R2 + Attachment DO.
      const largeDocHeader = '# Large Remote Attachment\n\n';
      const largeDocBody = '0123456789abcdef\n'.repeat(65_000); // ~1.105 MiB
      const largeDocBuffer = Buffer.from(largeDocHeader + largeDocBody, 'utf8');
      expect(largeDocBuffer.byteLength).toBeGreaterThan(1 << 20);

      await sendFiles(alicePage, [
        {
          name: 'large-report.md',
          mimeType: 'text/markdown',
          buffer: largeDocBuffer,
        },
      ]);

      // Wait until Alice's upload completes and Bob receives all four files.
      await expect(alicePage.locator('.uploads .upload')).toHaveCount(0);
      await expect(bobPage.locator('.messages .file-card', { hasText: 'large-report.md' })).toBeVisible();
      await expect(bobPage.locator('.messages .file-card', { hasText: 'sample.rs' })).toBeVisible();
      await expect(bobPage.locator('.messages .file-card', { hasText: 'sample.zip' })).toBeVisible();

      // Open FileBrowser on Bob's chat.
      await bobPage.getByRole('button', { name: 'Files of this chat', exact: true }).click();
      const modal = bobPage.locator('dialog.modal .files');
      await expect(modal).toBeVisible();
      await expect(modal.getByRole('heading', { name: 'Files', exact: true })).toBeVisible();

      // Default shelf (`All`) renders `.file-list` (not `.file-grid`).
      await expect(modal.locator('.file-list')).toBeVisible();
      await expect(modal.locator('.file-grid')).toHaveCount(0);

      // `Media` shelf renders `.file-grid` (not `.file-list`).
      await modal.locator('.shelves button', { hasText: /^Media / }).click();
      await expect(modal.locator('.file-grid')).toBeVisible();
      await expect(modal.locator('.file-list')).toHaveCount(0);

      // `Code` shelf renders `.file-list`.
      await modal.locator('.shelves button', { hasText: /^Code / }).click();
      await expect(modal.locator('.file-list')).toBeVisible();
      await expect(modal.locator('.file-grid')).toHaveCount(0);
      await expect(modal.locator('.file-row', { hasText: 'sample.rs' })).toBeVisible();

      // `Archives` shelf renders `.file-list`.
      await modal.locator('.shelves button', { hasText: /^Archives / }).click();
      await expect(modal.locator('.file-list')).toBeVisible();
      await expect(modal.locator('.file-row', { hasText: 'sample.zip' })).toBeVisible();

      // `Documents` shelf renders `.file-list` with `large-report.md` and `DeleteFromServer`.
      await modal.locator('.shelves button', { hasText: /^Documents / }).click();
      await expect(modal.locator('.file-list')).toBeVisible();
      const remoteEntry = modal.locator('.file-entry', { hasText: 'large-report.md' });
      await expect(remoteEntry).toBeVisible();
      const deleteBtn = remoteEntry.locator('button.delete-remote');
      await expect(deleteBtn).toBeVisible();
      await expect(deleteBtn).toHaveAttribute('aria-label', 'Delete from the server');

      // 1st click arms 2-step ConfirmGuard without deleting yet.
      await deleteBtn.click();
      await expect(deleteBtn).toHaveClass(/\basked\b/);
      await expect(deleteBtn).toHaveAttribute('aria-label', /^Delete it from the server, for you and /);

      // 2nd click confirms real server deletion.
      await deleteBtn.click();
      await expect(remoteEntry.locator('button.delete-remote')).toHaveCount(0);
      await expect(remoteEntry).toContainText('no longer on the server');

      // Switch shelves (`Media` -> `All` -> `Documents`) and verify deleted state persists.
      await modal.locator('.shelves button', { hasText: /^Media / }).click();
      await expect(modal.locator('.file-grid')).toBeVisible();

      await modal.locator('.shelves button', { hasText: /^All / }).click();
      const allRemoteEntry = modal.locator('.file-entry', { hasText: 'large-report.md' });
      await expect(allRemoteEntry).toContainText('no longer on the server');
      await expect(allRemoteEntry.locator('button.delete-remote')).toHaveCount(0);

      await modal.locator('.shelves button', { hasText: /^Documents / }).click();
      await expect(remoteEntry).toContainText('no longer on the server');
      await expect(remoteEntry.locator('button.delete-remote')).toHaveCount(0);
    } finally {
      await aliceCtx.close();
      await bobCtx.close();
    }
  });
});
