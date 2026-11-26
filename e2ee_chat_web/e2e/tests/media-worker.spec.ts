import fs from 'node:fs';
import { expect, test } from '@playwright/test';
import { fixturePath } from './helpers.ts';

const EXPECTED_SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; sandbox",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
};

function assertSecurityHeaders(headers: Record<string, string>): void {
  for (const [name, expected] of Object.entries(EXPECTED_SECURITY_HEADERS)) {
    expect(headers[name], `header ${name}`).toBe(expected);
  }
}

test.describe('media-worker.js service worker', () => {
  test('enforces method/destination guards, streams Range/suffix/200/416, and propagates AbortController aborts', async ({
    context,
    page,
  }) => {
    await page.goto('/');

    // Wait for `media-worker.js` to register, activate, and claim this client.
    const swReady = await page.evaluate(async () => {
      const reg = await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        await new Promise<void>((resolve) => {
          navigator.serviceWorker.addEventListener('controllerchange', () => resolve(), {
            once: true,
          });
        });
      }
      return {
        scriptURL: reg.active?.scriptURL ?? '',
        controlled: Boolean(navigator.serviceWorker.controller),
      };
    });
    expect(swReady.scriptURL).toMatch(/\/media-worker\.js$/);
    expect(swReady.controlled).toBe(true);

    // 1. Real HTTP requests through the active Service Worker:
    //    - POST /media/<tok> -> 405 Method Not Allowed + SECURITY_HEADERS
    //    - Non-media fetch destination GET /media/<tok> -> 403 Forbidden + SECURITY_HEADERS
    const guardResponses = await page.evaluate(async () => {
      const read = async (res: Response) => ({
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
      });
      const postRes = await fetch('/media/e2e-guard', { method: 'POST' });
      const getFetchRes = await fetch('/media/e2e-guard', { method: 'GET' });
      return {
        post: await read(postRes),
        getFetch: await read(getFetchRes),
      };
    });
    expect(guardResponses.post.status).toBe(405);
    assertSecurityHeaders(guardResponses.post.headers);
    expect(guardResponses.getFetch.status).toBe(403);
    assertSecurityHeaders(guardResponses.getFetch.headers);

    //    - Navigation (`mode: 'navigate'`) to /media/<tok> -> 403 Forbidden + SECURITY_HEADERS
    const navPage = await context.newPage();
    const navRespPromise = navPage.waitForResponse((res) =>
      res.url().endsWith('/media/e2e-guard'),
    );
    await navPage.goto('/media/e2e-guard').catch(() => null);
    const navResp = await navRespPromise;
    expect(navResp.status()).toBe(403);
    assertSecurityHeaders(navResp.headers());
    await navPage.close();

    // 2. Real `<audio src="/media/...">` request through the active Service Worker -> 206/200 +
    //    SECURITY_HEADERS + playable metadata loaded via real MessageChannel handshake.
    const wavBytes = Array.from(fs.readFileSync(fixturePath('sample.wav')));
    await page.evaluate((wavArr) => {
      const wav = new Uint8Array(wavArr);
      const stream40 = new Uint8Array(40);
      for (let i = 0; i < 40; i++) stream40[i] = (i * 7 + 3) & 0xff;
      const CHUNK = 16;

      const state = {
        abortedTokens: [] as string[],
        receivedMessages: [] as Array<Record<string, unknown>>,
      };
      (window as unknown as Record<string, unknown>).__mediaSwTest = state;

      navigator.serviceWorker.startMessages?.();
      navigator.serviceWorker.addEventListener('message', (event: MessageEvent) => {
        const msg = event.data as Record<string, unknown> | null;
        const port = event.ports?.[0];
        if (!msg || typeof msg.media !== 'string' || !port) return;
        const token = msg.media;

        if (token === 'e2e-wav-live') {
          const start = typeof msg.start === 'number' ? msg.start : 0;
          const end =
            typeof msg.end === 'number' ? Math.min(msg.end, wav.length - 1) : wav.length - 1;
          const slice = wav.slice(start, end + 1);
          port.postMessage(
            { size: wav.length, start, mime: 'audio/wav', bytes: slice.buffer },
            [slice.buffer],
          );
          return;
        }

        if (token === 'e2e-stream-40') {
          state.receivedMessages.push({ ...msg });
          if (msg.invalid) {
            port.postMessage({ error: 416, size: stream40.length });
            return;
          }
          if (msg.whole) {
            const slice = stream40.slice(0, CHUNK);
            port.postMessage(
              { size: stream40.length, start: 0, mime: 'audio/wav', bytes: slice.buffer },
              [slice.buffer],
            );
            return;
          }
          if (typeof msg.suffix === 'number') {
            const len = Math.min(msg.suffix, stream40.length);
            const start = stream40.length - len;
            const slice = stream40.slice(start);
            port.postMessage(
              { size: stream40.length, start, mime: 'audio/wav', bytes: slice.buffer },
              [slice.buffer],
            );
            return;
          }
          if (typeof msg.start === 'number') {
            if (msg.start >= stream40.length) {
              port.postMessage({ error: 416, size: stream40.length });
              return;
            }
            const chunkEnd = Math.min(msg.start + CHUNK, stream40.length);
            const reqEnd =
              typeof msg.end === 'number' ? Math.min(msg.end + 1, chunkEnd) : chunkEnd;
            const slice = stream40.slice(msg.start, reqEnd);
            port.postMessage(
              { size: stream40.length, start: msg.start, mime: 'audio/wav', bytes: slice.buffer },
              [slice.buffer],
            );
          }
          return;
        }

        if (token === 'e2e-hang-range') {
          // Withhold reply until the Service Worker aborts and posts `{ aborted: true }`.
          port.onmessage = (abortEvent: MessageEvent) => {
            if (abortEvent.data && abortEvent.data.aborted === true) {
              state.abortedTokens.push(token);
            }
          };
          return;
        }

        if (token === 'e2e-hang-stream') {
          if (msg.whole) {
            const slice = stream40.slice(0, CHUNK);
            port.postMessage(
              { size: stream40.length, start: 0, mime: 'audio/wav', bytes: slice.buffer },
              [slice.buffer],
            );
          } else {
            port.onmessage = (abortEvent: MessageEvent) => {
              if (abortEvent.data && abortEvent.data.aborted === true) {
                state.abortedTokens.push(token);
              }
            };
          }
        }
      });
    }, wavBytes);

    const mediaResponsePromise = page.waitForResponse((res) =>
      res.url().endsWith('/media/e2e-wav-live'),
    );
    const audioDuration = await page.evaluate(
      () =>
        new Promise<number>((resolve, reject) => {
          const audio = document.createElement('audio');
          audio.preload = 'metadata';
          audio.addEventListener('loadedmetadata', () => {
            const dur = audio.duration;
            audio.removeAttribute('src');
            audio.load();
            audio.remove();
            resolve(dur);
          });
          audio.addEventListener('error', () => reject(new Error('audio failed to load')));
          audio.src = '/media/e2e-wav-live';
          document.body.appendChild(audio);
        }),
    );
    const liveResp = await mediaResponsePromise;
    expect(audioDuration).toBeGreaterThan(0);
    expect([200, 206]).toContain(liveResp.status());
    assertSecurityHeaders(liveResp.headers());
    expect(liveResp.headers()['accept-ranges']).toBe('bytes');
    expect(liveResp.headers()['content-type']).toBe('audio/wav');
    if (liveResp.status() === 206) {
      expect(liveResp.headers()['content-range']).toMatch(/^bytes \d+-\d+\/\d+$/);
    }

    // 3. Exercise exact Range, suffix Range, invalid 416, non-Range multi-chunk 200, and
    //    AbortController.abort() cleanup directly inside the live `media-worker.js` Service Worker
    //    communicating with the real controlled page via `self.clients.get(clientId)`.
    const sw = context
      .serviceWorkers()
      .find((worker) => worker.url().endsWith('/media-worker.js'));
    expect(sw, 'active media-worker.js ServiceWorker').toBeDefined();

    const swResults = await sw!.evaluate(async () => {
      const clients = await (self as unknown as { clients: { matchAll: () => Promise<Array<{ id: string }>> } }).clients.matchAll();
      const clientId = clients[0]?.id;
      if (!clientId) throw new Error('no controlled client found');

      type ServeFn = (req: Request, clientId: string, token: string) => Promise<Response>;
      const serveFn = (globalThis as unknown as { serve: ServeFn }).serve;

      const makeReq = (
        token: string,
        opts: { method?: string; range?: string; destination?: string; signal?: AbortSignal } = {},
      ) => {
        const headers = new Headers();
        if (opts.range !== undefined) headers.set('Range', opts.range);
        const req = {
          method: opts.method ?? 'GET',
          mode: 'cors',
          destination: opts.destination ?? 'audio',
          headers,
          signal: opts.signal,
          url: `${self.location.origin}/media/${token}`,
        };
        return req as unknown as Request;
      };

      const readResp = async (resp: Response) => ({
        status: resp.status,
        headers: Object.fromEntries(resp.headers.entries()),
        bytes: Array.from(new Uint8Array(await resp.arrayBuffer())),
      });

      // (a) Forward Range: bytes=0-15 -> 206 + Content-Range + SECURITY_HEADERS
      const range0_15 = await readResp(
        await serveFn(makeReq('e2e-stream-40', { range: 'bytes=0-15' }), clientId, 'e2e-stream-40'),
      );

      // (b) Suffix Range: bytes=-8 -> 206 + Content-Range: bytes 32-39/40
      const suffix8 = await readResp(
        await serveFn(makeReq('e2e-stream-40', { range: 'bytes=-8' }), clientId, 'e2e-stream-40'),
      );

      // (c) Invalid Range: bytes=20-10 -> 416 + Content-Range: bytes */40
      const invalidRange = await readResp(
        await serveFn(
          makeReq('e2e-stream-40', { range: 'bytes=20-10' }),
          clientId,
          'e2e-stream-40',
        ),
      );

      // (d) Non-Range GET -> 200 OK multi-chunk streaming (16 + 16 + 8 = 40 bytes)
      const whole200 = await readResp(
        await serveFn(makeReq('e2e-stream-40'), clientId, 'e2e-stream-40'),
      );

      // (e) AbortController.abort() while Range reply is in flight -> 499 + `{ aborted: true }`
      const rangeAbort = new AbortController();
      const rangeAbortPromise = serveFn(
        makeReq('e2e-hang-range', { range: 'bytes=0-15', signal: rangeAbort.signal }),
        clientId,
        'e2e-hang-range',
      );
      // Yield a macrotask so `page.postMessage` delivers port2 before aborting.
      await new Promise((r) => setTimeout(r, 20));
      rangeAbort.abort();
      const abortedRangeResp = await readResp(await rangeAbortPromise);

      // (f) AbortController.abort() mid multi-chunk 200 stream -> stream errors + `{ aborted: true }`
      const streamAbort = new AbortController();
      const streamResp = await serveFn(
        makeReq('e2e-hang-stream', { signal: streamAbort.signal }),
        clientId,
        'e2e-hang-stream',
      );
      const reader = streamResp.body!.getReader();
      const firstChunk = await reader.read();
      const secondReadPromise = reader.read();
      await new Promise((r) => setTimeout(r, 20));
      streamAbort.abort();
      let streamAbortedError = '';
      try {
        await secondReadPromise;
      } catch (err) {
        streamAbortedError = err instanceof Error ? err.name : String(err);
      }

      return {
        range0_15,
        suffix8,
        invalidRange,
        whole200,
        abortedRangeStatus: abortedRangeResp.status,
        streamFirstChunkLen: firstChunk.value?.byteLength ?? 0,
        streamAbortedError,
      };
    });

    const expected40 = Array.from({ length: 40 }, (_, i) => (i * 7 + 3) & 0xff);

    expect(swResults.range0_15.status).toBe(206);
    assertSecurityHeaders(swResults.range0_15.headers);
    expect(swResults.range0_15.headers['content-range']).toBe('bytes 0-15/40');
    expect(swResults.range0_15.headers['content-length']).toBe('16');
    expect(swResults.range0_15.bytes).toEqual(expected40.slice(0, 16));

    expect(swResults.suffix8.status).toBe(206);
    assertSecurityHeaders(swResults.suffix8.headers);
    expect(swResults.suffix8.headers['content-range']).toBe('bytes 32-39/40');
    expect(swResults.suffix8.headers['content-length']).toBe('8');
    expect(swResults.suffix8.bytes).toEqual(expected40.slice(32, 40));

    expect(swResults.invalidRange.status).toBe(416);
    assertSecurityHeaders(swResults.invalidRange.headers);
    expect(swResults.invalidRange.headers['content-range']).toBe('bytes */40');

    expect(swResults.whole200.status).toBe(200);
    assertSecurityHeaders(swResults.whole200.headers);
    expect(swResults.whole200.headers['content-length']).toBe('40');
    expect(swResults.whole200.bytes).toEqual(expected40);

    expect(swResults.abortedRangeStatus).toBe(499);
    expect(swResults.streamFirstChunkLen).toBe(16);
    expect(swResults.streamAbortedError).toBe('AbortError');

    // Confirm both aborts propagated `{ aborted: true }` to the page's MessagePort!
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            (window as unknown as { __mediaSwTest: { abortedTokens: string[] } }).__mediaSwTest
              .abortedTokens,
        ),
      )
      .toEqual(expect.arrayContaining(['e2e-hang-range', 'e2e-hang-stream']));
  });
});
