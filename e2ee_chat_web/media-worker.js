// Streams attachments to the page's players as they are fetched. A player's request for
// `/media/<token>` goes to the page that opened the stream, which fetches and decrypts the chunk
// the asked range starts in, and only it, so a video or audio plays, and seeks, while it
// downloads. The keys stay in the page: this only passes the plaintext of a range through, in
// memory.

// How long a page may take for a range, as it waits for a chunk still being uploaded, in
// milliseconds.
const PATIENCE = 120_000;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith('/media/')) {
    event.respondWith(serve(event.request, event.clientId, url.pathname.slice('/media/'.length)));
  }
});

async function serve(request, clientId, token) {
  const page = clientId && (await self.clients.get(clientId));
  if (!page) {
    return new Response(null, { status: 404 });
  }
  // `bytes=<start>-` or `bytes=<start>-<end>`; from the start if it asks for no range.
  const range = /^bytes=(\d+)-(\d*)$/.exec(request.headers.get('Range') || '');
  const start = range ? Number(range[1]) : 0;
  const end = range && range[2] ? Number(range[2]) : undefined;
  const channel = new MessageChannel();
  const answered = new Promise((resolve) => {
    channel.port1.onmessage = (message) => resolve(message.data);
    setTimeout(() => resolve({ error: 504 }), PATIENCE);
  });
  page.postMessage({ media: token, start, end }, [channel.port2]);
  const { size, mime, bytes, error } = await answered;
  channel.port1.close();
  if (error !== undefined) {
    return new Response(null, { status: error });
  }
  // As much of the range as the chunk holds: the player asks for the rest.
  return new Response(bytes, {
    status: 206,
    headers: {
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store',
      'Content-Length': String(bytes.byteLength),
      'Content-Range': `bytes ${start}-${start + bytes.byteLength - 1}/${size}`,
      'Content-Type': mime,
    },
  });
}
