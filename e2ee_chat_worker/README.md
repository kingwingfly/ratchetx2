The E2EE chat server as a [Cloudflare Worker](https://developers.cloudflare.com/workers/languages/rust/), with the [web client](../e2ee_chat_web) as its static assets.

- The handshake, mailbox and attachment services (the [protocol](../protocol) crate's servers) over the [Connect protocol](https://connectrpc.com/docs/protocol): `POST /handshake.v1.HandshakeService/<Method>`, `POST /mailbox.v1.MailboxService/<Method>` and `POST /attachment.v1.AttachmentService/<Method>`, with protobuf bodies. Any page may call them (CORS); requests that read or change an identity's data are signed by it.
- **D1** keeps the prekey bundles, one-time prekeys, initial messages, message queues and attachments (`migrations/`; apply new ones before running a new build). **R2** keeps message contents over 64 KiB, so rows stay small, and attachments' chunks, under `attachments/<id>/<index>`.
- **Notifications** over WebSockets: a client opens `/notifications?request=<SubscribeRequest>`, a subscription signed by its identity key, as unpadded base64url protobuf (`protocol::notify`). The socket goes to a **Durable Object** for that identity key, which keeps it with the hibernation API, so an idle socket costs no duration, and answers the client's `ping`s, one a minute, with `pong` without waking. A web client keeps its socket open only while its user is on the page; one that died without closing, as its device slept, goes without pings, and the object closes it when it next wakes, to notify. After each pushed message or initial message, the Worker tells the recipient's object, which sends a `Notification` frame on its sockets, once the response has gone.
- Every store operation is one D1 statement or batch, so it is atomic, as the [storage](../storage) traits require; `--features conformance` runs their conformance suites against D1 and R2.
- Daily, a cron trigger deletes messages, initial messages and attachments older than `RETENTION_DAYS` (30), with their R2 objects, since the protocol has no acknowledgements.
- The web client's files are served before the Worker runs, with the security headers of `e2ee_chat_web/_headers`.

The server only sees encrypted messages and public keys, but it does see who sends to whom, when, and how much.

# Run it locally

Needs the `wasm32-unknown-unknown` target, [trunk](https://trunkrs.dev) and [worker-build](https://crates.io/crates/worker-build) (`cargo install trunk worker-build`), Node.js for wrangler, and clang with its WebAssembly target and `llvm-ar`, for the grammars of the web client's code previews.

```sh
cd e2ee_chat_worker
npm install
npx wrangler d1 migrations apply e2ee-chat --local
npx wrangler dev
```

`wrangler dev` builds the web client, with its previews' workers, and the Worker, and serves both, with local D1 and R2, on <http://localhost:8787>. Open it in two browser profiles to chat with yourself. To work on the web client with hot reload, run `trunk serve` in `e2ee_chat_web` too: it proxies the Connect calls to `wrangler dev`.

# Deploy

```sh
npx wrangler login
npx wrangler d1 create e2ee-chat          # put its database_id in wrangler.toml
npx wrangler r2 bucket create e2ee-chat
npx wrangler d1 migrations apply e2ee-chat --remote
npx wrangler deploy
```

**Before a public deployment, add a password** to the expensive operations: starting uploads and uploading chunks (R2 storage), pushing messages and sending initial messages. Today anyone who can reach the Worker can use them, and storage, requests and Durable Object calls are billed. This is not built yet. A password shared by the server's users, which the clients send with those calls, identifies nobody and signs nothing, so it does not weaken deniability.

# Limits

The servers' default limits apply: 100 one-time prekeys per publish, 100 initial messages waiting per inbox, each with a first message of up to 4 KiB, messages up to 4 MiB - 64 KiB, attachments of up to 50 chunks of 2 MiB, and fetches of up to 100 messages or that many bytes, headers included, which D1 sums before any row leaves it. Request bodies over 4 MiB are refused as soon as they grow past it.

As the protocol has it, the mailbox takes pushes from anyone, and the handshake service initial messages: a queue is named by its sender's and recipient's identity keys, an initial message claims its sender's, and clients drop what does not decrypt. Put [rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) in front of a public deployment. While its notifications come, a web client polls every five minutes; otherwise every 3 to 30 seconds while its user is on the page, and every 30 minutes while they are away, with no socket open. Each poll is a request per chat, and each notification a request to a Durable Object; the TUI client always polls.

# Storage conformance

```sh
npx wrangler d1 migrations apply e2ee-chat --local --persist-to /tmp/conformance
WORKER_BUILD_ARGS="--features conformance" npx wrangler dev --persist-to /tmp/conformance
curl -X POST http://localhost:8787/conformance
```

The suites need empty tables, and a failure panics, which fails the request. Never deploy this feature.
