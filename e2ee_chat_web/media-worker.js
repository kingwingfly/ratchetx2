// Streams attachments to the page's players as they are fetched. A player's request for
// `/media/<token>` goes to the page that opened the stream, which fetches and decrypts the chunk
// the asked range starts in, and only it, so a video or audio plays, and seeks, while it
// downloads. The keys stay in the page: this only passes the plaintext of a range through, in
// memory.

// How long a page may take for a range, as it waits for a chunk still being uploaded, in
// milliseconds.
const PATIENCE = 120_000;

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; sandbox",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
};

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith('/media/')) {
    event.respondWith(serve(event.request, event.clientId, url.pathname.slice('/media/'.length)));
  }
});

function fetchRange(page, msg, signal) {
  if (signal && signal.aborted) {
    return Promise.resolve({ aborted: true });
  }
  const channel = new MessageChannel();
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      channel.port1.onmessage = null;
      channel.port1.close();
      resolve(result);
    };
    const onAbort = () => finish({ aborted: true });
    const timer = setTimeout(() => finish({ error: 504 }), PATIENCE);
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }
    channel.port1.onmessage = (message) => finish(message.data);
    try {
      page.postMessage(msg, [channel.port2]);
    } catch {
      finish({ error: 404 });
    }
  });
}

function errorResponse(status, size) {
  const headers = { ...SECURITY_HEADERS };
  if (status === 416 && size !== undefined) {
    headers['Content-Range'] = `bytes */${size}`;
  }
  return new Response(null, { status, headers });
}

function parseRange(header) {
  const forward = /^bytes=(\d+)-(\d*)$/.exec(header);
  if (forward) {
    const start = Number(forward[1]);
    const end = forward[2] ? Number(forward[2]) : undefined;
    if (
      Number.isSafeInteger(start) &&
      (end === undefined || (Number.isSafeInteger(end) && end >= start))
    ) {
      return { start, end };
    }
    return { invalid: true };
  }
  const suffix = /^bytes=-(\d+)$/.exec(header);
  if (suffix) {
    const length = Number(suffix[1]);
    if (Number.isSafeInteger(length) && length > 0) {
      return { suffix: length };
    }
  }
  return { invalid: true };
}

async function serve(request, clientId, token) {
  if (request.method !== 'GET') {
    return errorResponse(405);
  }
  if (
    request.mode === 'navigate' ||
    (request.destination && request.destination !== 'audio' && request.destination !== 'video')
  ) {
    return errorResponse(403);
  }
  const page = clientId && (await self.clients.get(clientId));
  if (!page) {
    return errorResponse(404);
  }
  const rangeHeader = request.headers.get('Range');
  if (rangeHeader !== null) {
    const spec = parseRange(rangeHeader);
    const reply = await fetchRange(page, { media: token, ...spec }, request.signal);
    if (reply.aborted) {
      return errorResponse(499);
    }
    const { size, start, mime, bytes, error } = reply;
    if (error !== undefined) {
      return errorResponse(error, size);
    }
    // As much of the range as the chunk holds: the player asks for the rest.
    return new Response(bytes, {
      status: 206,
      headers: {
        ...SECURITY_HEADERS,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(bytes.byteLength),
        'Content-Range': `bytes ${start}-${start + bytes.byteLength - 1}/${size}`,
        'Content-Type': mime,
      },
    });
  }

  // Non-Range GET: respond with RFC 9110 200 OK (including 0-byte streams) and stream chunks on
  // demand if multi-chunk, cancelling any pending MessagePort wait if the consumer aborts.
  const firstReply = await fetchRange(page, { media: token, whole: true }, request.signal);
  if (firstReply.aborted) {
    return errorResponse(499);
  }
  if (firstReply.error !== undefined) {
    return errorResponse(firstReply.error, firstReply.size);
  }
  const { size, mime, bytes } = firstReply;
  const headers = {
    ...SECURITY_HEADERS,
    'Accept-Ranges': 'bytes',
    'Content-Length': String(size),
    'Content-Type': mime,
  };
  if (size === 0 || bytes.byteLength >= size) {
    return new Response(bytes, { status: 200, headers });
  }
  if (request.signal && request.signal.aborted) {
    return errorResponse(499);
  }
  let offset = bytes.byteLength;
  let first = new Uint8Array(bytes);
  const streamAbort = new AbortController();
  const onRequestAbort = () => streamAbort.abort();
  const cleanupAbort = () => {
    if (request.signal) {
      request.signal.removeEventListener('abort', onRequestAbort);
    }
  };
  if (request.signal) {
    request.signal.addEventListener('abort', onRequestAbort, { once: true });
  }
  const body = new ReadableStream({
    async pull(controller) {
      if (streamAbort.signal.aborted) {
        cleanupAbort();
        controller.error(new DOMException('Aborted', 'AbortError'));
        return;
      }
      if (first !== null) {
        controller.enqueue(first);
        first = null;
        if (offset >= size) {
          cleanupAbort();
          controller.close();
        }
        return;
      }
      const next = await fetchRange(page, { media: token, start: offset }, streamAbort.signal);
      if (next.aborted || streamAbort.signal.aborted) {
        cleanupAbort();
        controller.error(new DOMException('Aborted', 'AbortError'));
        return;
      }
      if (next.error !== undefined || !next.bytes || next.bytes.byteLength === 0) {
        cleanupAbort();
        controller.error(new Error(`media stream failed (${next.error ?? 'empty'})`));
        return;
      }
      controller.enqueue(new Uint8Array(next.bytes));
      offset += next.bytes.byteLength;
      if (offset >= size) {
        cleanupAbort();
        controller.close();
      }
    },
    cancel() {
      cleanupAbort();
      streamAbort.abort();
    },
  });
  return new Response(body, { status: 200, headers });
}
