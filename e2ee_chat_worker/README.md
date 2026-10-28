The E2EE chat server as a [Cloudflare Worker](https://developers.cloudflare.com/workers/languages/rust/), with the [web client](../e2ee_chat_web) as its static assets.

- The handshake, mailbox and attachment services (the [protocol](../protocol) crate's servers) over the [Connect protocol](https://connectrpc.com/docs/protocol): `POST /handshake.v1.HandshakeService/<Method>`, `POST /mailbox.v1.MailboxService/<Method>` and `POST /attachment.v1.AttachmentService/<Method>`, with protobuf bodies. Any page may call them (CORS); requests that read or change an identity's data are signed by it.
- **Durable Objects** keep the server's state, each in its own SQLite database: an `Identity` per identity key, with its bundle and one-time prekeys, its inbox of initial messages, the queues of messages to it, one per sender, and its client's WebSockets; and an `Attachment` per attachment, with its chunks, the hashes of its two tokens and which chunks were put; it names no uploader. Each identity's data is its own object's, so the server grows with its users, rather than through one database. **R2** keeps message contents over 64 KiB, so rows stay small, under `messages/`, and attachments' chunks, under `attachments/<id>/<index>`.
- **Notifications** over WebSockets: a client opens `/notifications?request=<SubscribeRequest>`, a subscription signed by its identity key, as unpadded base64url protobuf (`protocol::notify`). The socket goes to its identity's object, which keeps it with the hibernation API, so an idle socket costs no duration, and answers the client's `ping`s, one a minute, with `pong` without waking. A web client keeps its socket open only while its user is on the page; one that died without closing, as its device slept, goes without pings, and the object closes it when it next notifies. As a message or an initial message arrives, the recipient's object, which keeps it, sends a `Notification` frame on its sockets at once.
- **Sign-in**: the server is only for those signed in to it. Every call that writes needs it: publishing keys, fetching a bundle, which takes one of its one-time prekeys, starting a chat, pushing a message, and starting an upload; others are refused with `permission_denied`. Anyone can make identity keys, so limits per key would stop nobody; the password is what keeps the server to those who have it. Fetching messages, taking one's own inbox, downloading, notifications, and what an attachment's tokens authorize stay open. A client signs in once, `POST /auth/password` with the server's password, the `PASSWORD` secret, as its body, and gets a cookie, `__Host-e2ee-chat`, which its calls carry until it expires after `SESSION_DAYS` (30). The cookie is signed with HMAC-SHA256 under another secret, `AUTH_KEY`, so that a cookie cannot help guess the password offline; it names who signed in, `password` for now, so that later sign-ins, e.g. with a blockchain account by SIWE, SIWS or SIWX (CAIP-122), can sign the same cookies, and storage bought could be counted against them. It is `HttpOnly`, `Secure` and `SameSite=Strict`: the page's scripts cannot read it, and no other site's requests carry it, so no other page can store files as the user. `GET /auth` says who a request is signed in as, as JSON, `{}` for nobody, and `POST /auth/sign-out` signs out. Both posts are refused when the browser says they come from another site (`Sec-Fetch-Site`), so that no other page's form signs its visitor in or out; a development proxy such as `trunk serve` is the page's own origin, so its calls pass. A wrong password is answered after a second. As the cookie is the server's own, a web client signs in only on its own server's page.
- Every store operation is one call of one object, which serves it whole, its statements with nothing in between, so it is atomic, as the [storage](../storage) traits require; `--features conformance` runs their conformance suites through the objects and R2.
- **Delivery**: a message goes once its recipient has it. Its push carries SHA-256 of its delivery token, which only the two peers can compute, and the recipient's next fetch, once it saved what it received, gives the tokens back: the Worker deletes those messages, with their R2 objects. Attachments stay, as recipients may download them again, until they expire or a peer deletes one. Each has two tokens: its upload token, random, which the uploader alone gets and forgets once the upload is done, puts its chunks; its delete token, which the peers derive from the attachment's key, deletes it, at any time, by the uploader or a recipient alike, so that a recipient who does not want a file stops its upload. Neither names who uploaded it, and the Worker keeps nobody's name with it. A chunk is put once, R2 writing it only if it has none, so the upload token cannot change what was downloaded, even with two puts at once. If R2 fails to delete what was delivered, the fetch still reads, and those messages expire. Deleting a chat tells the server nothing.
- Each object's alarm deletes, with their R2 objects, its messages never delivered and initial messages never taken once `RETENTION_DAYS` (30) old, and an attachment once `FILE_RETENTION_DAYS` (90) old; both may be fractions of a day. The bucket's [lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) may delete objects sooner: a message whose content is gone comes without it, and its recipient goes past it, as past a message lost; an attachment notes each chunk put, so one gone since is not found, rather than waited for as one still to be uploaded.
- Its responses carry its time in `Date`, exposed to other origins too, which clients sign the requests whose time it checks with (a subscription), as a device's clock may be off; the Worker sets it, as `wrangler dev` does not.
- The web client's files are served before the Worker runs, with the security headers of `e2ee_chat_web/_headers`.

The server only sees encrypted messages and public keys, but it does see who sends to whom, when, and how much.

# Run it locally

Needs the `wasm32-unknown-unknown` target, [trunk](https://trunkrs.dev) and [worker-build](https://crates.io/crates/worker-build) (`cargo install trunk worker-build`), Node.js for wrangler, and clang with its WebAssembly target and `llvm-ar`, for the grammars of the web client's code previews.

```sh
cd e2ee_chat_worker
npm install
printf 'PASSWORD="%s"\nAUTH_KEY="%s"\n' "a password" "$(openssl rand -base64 32)" > .dev.vars
npx wrangler dev
```

`.dev.vars` holds the secrets for `wrangler dev`, which warns if one is missing; git ignores it. The objects create their tables themselves.

`wrangler dev` builds the web client, with its previews' workers, and the Worker, and serves both, with local Durable Objects and R2, on <http://localhost:8787>. Open it in two browser profiles to chat with yourself. To work on the web client with hot reload, run `trunk serve` in `e2ee_chat_web` too: it proxies the Connect calls to `wrangler dev`.

# Deploy

```sh
npx wrangler login
npx wrangler r2 bucket create e2ee-chat
npx wrangler r2 bucket lifecycle add e2ee-chat messages messages/ --expire-days 30
npx wrangler r2 bucket lifecycle add e2ee-chat attachments attachments/ --expire-days 90
npx wrangler secret put PASSWORD          # what users sign in with
openssl rand -base64 32 | npx wrangler secret put AUTH_KEY
npx wrangler deploy
```

Without both secrets, nobody can sign in, so nobody can use the server. The lifecycle rules delete R2 objects that outlive their rows, as with an alarm that failed; keep their days at least `RETENTION_DAYS` for `messages/` and `FILE_RETENTION_DAYS` for `attachments/`, and longer than an upload takes, as a chunk expires from when it was put. Changing `AUTH_KEY` signs everyone out. The password is shared by the server's users and identifies nobody: it signs nothing the peers send, so deniability stays; but neither can it limit one user's share: put [rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) in front of a public deployment, by IP, on `/auth/password` too. Limits per user need users that cannot be made at will, e.g. invited or paying ones.

# Limits

The servers' default limits apply: 100 one-time prekeys per publish, 100 initial messages waiting per inbox, each with a first message of up to 4 KiB, messages up to 4 MiB - 64 KiB, attachments of up to 50 chunks of 2 MiB, and fetches of up to 100 messages or that many bytes, headers included, which the object sums before any row leaves it. Request bodies over 4 MiB are refused as soon as they grow past it.

As the protocol has it, the mailbox takes pushes from anyone, and the handshake service initial messages: a queue is named by its sender's and recipient's identity keys, an initial message claims its sender's, and clients drop what does not decrypt. Put [rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) in front of a public deployment. While its notifications come, a web client polls every five minutes; otherwise every 3 to 30 seconds while its user is on the page, and every 30 minutes while they are away, with no socket open. Each poll is a request per chat to the identity's object; the TUI client always polls.

# Storage conformance

```sh
WORKER_BUILD_ARGS="--features conformance" npx wrangler dev --persist-to /tmp/conformance
curl -X POST http://localhost:8787/conformance
```

The suites need empty objects, so a fresh `--persist-to`, and a failure panics, which fails the request. Never deploy this feature.
