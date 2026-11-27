The E2EE chat server as a [Cloudflare Worker](https://developers.cloudflare.com/workers/languages/rust/), with the [web client](../e2ee_chat_web) as its static assets.

- The Worker accepts protobuf Connect requests at `POST /<service>/<method>` with CORS enabled for `handshake.v2.HandshakeService` (8 RPCs), `mailbox.v2.MailboxService` (5 RPCs), and `attachment.v1.AttachmentService` (4 RPCs). The recipient signs unified mailbox reads (`FetchSigned`), monotonic prefix acknowledgments (`AckMessages`), write-token grant updates (`RegisterWriteToken` and `RevokeWriteToken`), and inbox reads/acknowledgments (`ListInitialMessages` and `AckInitialMessages`) with its identity key. `PQ_ENABLED = "false"` in `wrangler.toml` rolls back post-quantum negotiation at runtime while keeping signed v2 reads, classical fallback, and in-flight PQ draining active. [Protocol crate](../protocol) · [Connect protocol](https://connectrpc.com/docs/protocol)
- **Durable Objects** keep the server's state, each in its own SQLite database: an `IdentityV2` per identity key (`SCHEMA_V5`, fail-closed on version mismatch), keeping its capability manifest (with optional folded classical SPK signature), one-time classical/PQ prekeys, idempotent initial-message inbox, recipient-versioned write-token grants (`peer_grants` + `write_tokens`), a single unified sealed-sender-lite inline mailbox queue (`messages`, zero R2 dependency), and its pre-authenticated hibernating WebSockets; and an `AttachmentV2` per attachment, with its chunk count, the SHA-256 hashes of its upload and delete tokens, and which chunks were put. **R2** keeps **only** encrypted attachment chunks under opaque `v2/attachments/<id>/<index>` keys — zero message bodies and zero identity keys live in R2.
- **Notifications** use pre-authenticated hibernating WebSockets. Clients connect to `GET /notifications` offering `Sec-WebSocket-Protocol: e2ee-notify.v2, e2ee-sub.<base64url_nopad(SubscribeRequest)>`, where `SubscribeRequest` is audience-bound, identity-signed, timestamped, and carries a mandatory 16-byte CSPRNG `nonce`. The Worker validates `Origin`, `WS_RATE_LIMITER`, the sign-in cookie (when `PASSWORD` is configured), and the `SubscribeRequest` signature/audience/skew/nonce at ingress **before** routing to any `IdentityV2` DO, strips `Sec-WebSocket-Protocol` and internal headers (never logging offered subprotocol credentials), and forwards only verified headers. `IdentityV2` checks and records the `(identity, audience, timestamp, nonce)` replay key in `seen_subscribes` before returning `101` echoing only `Sec-WebSocket-Protocol: e2ee-notify.v2` (`403` pre-101 on replay, `429` on cap). Distinct same-millisecond reconnects carry fresh 128-bit nonces and never collide. The object answers minute-by-minute `ping` with `pong` during hibernation and emits sender-blind binary `Notification` hints (`message` or `initial_message`).
- **Sign-in & Rate Limiting**: writes require a signed `__Host-e2ee-chat` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), parsed with a 4 KiB header cap and strict duplicate-cookie rejection: `PublishV2`, `RefillPrekeys`, `ClaimBundle`, `SendInitialV2`, `PushV2`, `StartUpload`, `PutChunk`, and `GET /notifications` (when `PASSWORD` is configured). Signed reads/acks/grant management (`FetchSigned`, `AckMessages`, `RegisterWriteToken`, `RevokeWriteToken`, `ListInitialMessages`, `AckInitialMessages`), `GetServerInfo`, `GetManifest`, `GetChunk`, and `DeleteAttachment` do not require a sign-in cookie. Four GA `[[ratelimits]]` bindings protect ingress before DO routing:
  - `AUTH_RATE_LIMITER` (`20 / 60s`): `POST /auth/password` (`429` + `Retry-After: 60`, before body read, backed by isolate-local failure tracking and 1–5 s wrong-password backoff).
  - `WS_RATE_LIMITER` (`30 / 60s`): `GET /notifications` (`429` + `Retry-After: 60`, keyed by normalized IP + hashed cookie tag).
  - `HANDSHAKE_RATE_LIMITER` (`30 / 60s`): `ClaimBundle` and `SendInitialV2` (Connect `Code::Unavailable` / HTTP `503` JSON + `Retry-After: 60`).
  - `UPLOAD_RATE_LIMITER` (`30 / 60s`): `StartUpload` (Connect `Code::Unavailable` / HTTP `503` JSON + `Retry-After: 60`).
  - **Operational caveats**: Cloudflare `[[ratelimits]]` counters are **per-colo and eventually consistent**, so operators **MUST** use a high-entropy random `PASSWORD` (`>= 128` bits, e.g. `openssl rand -base64 24`, never a weak passphrase) and pair with [Cloudflare WAF Rate Limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) for global cross-colo enforcement. Cookie-tag rate-limit keys rotate whenever a client re-authenticates via `POST /auth/password` (because `Claims.expires` changes), so unconditional normalized IP (`/64` for IPv6) keys + `AUTH_RATE_LIMITER` + WAF remain the primary per-client defense. When `PASSWORD` is configured, `check_rate_limit` fails **closed** uniformly on missing/misconfigured bindings, runtime throws/rejections, or malformed outcomes (logging via `console_error!`), so monitor Worker error logs for rate-limiter binding health.
- **Delivery, Grants, & Isolation**: `PushV2` carries no sender identity key and requires a recipient-authorized 32-byte deniable `write_token` (hashed at the protocol boundary and verified in constant time against `write_tokens` before deduplication; unknown/revoked tokens return Connect `Code::Aborted` / HTTP `409`). Recipients register opaque `peer_slot_id` grants (`RegisterWriteToken`, capped at 4096 authorized peers and 4 grants/peer preserving pinned `active_token_hash`), revoke them with a monotonic version floor (`RevokeWriteToken`), and acknowledge unified mailbox prefixes via `AckMessages` or piggybacked `FetchSigned.ack_up_to_sequence`. All `PushV2` envelopes stay inline (`<= 64 KiB` envelope / `80 KiB` wire body), and all file attachments stream encrypted 2 MiB chunks through R2. A per-isolate `LargeBodyPermit` caps concurrent `PutChunk`, `GetChunk`, and `FetchSigned` calls at 4 (acquired before reading the body, returning Connect `Code::Unavailable` `503` + `Retry-After: 1`).
- **Retention**: `IdentityV2`'s alarm is purely synchronous local SQLite + WebSocket cleanup (zero R2 calls), expiring unread messages and initial messages after `RETENTION_DAYS` (30), deduplication tombstones and zeroed `dedup_counts` rows after 24 hours, empty revoked `peer_grants` tombstones after `MAX_CLOCK_SKEW` (5 minutes), subscription replay keys past their skew window, and expired WebSocket sessions. `AttachmentV2`'s alarm deletes chunks from R2 and wipes DO storage after `FILE_RETENTION_DAYS` (90), retrying hourly on transient R2 failure.
- Responses carry the server's time in `Date` and `x-e2ee-pq` (`"1"` or `"0"`), plus `nosniff`, `no-store`, and `no-referrer`. Static web client files are served before the Worker runs with the security headers of `e2ee_chat_web/_headers`.

The server only sees encrypted messages, opaque `peer_slot_id`s, and recipient identity keys on mailbox ops — it does not see sender identities on `PushV2` or `Notification` frames.

# Run it locally

Needs the `wasm32-unknown-unknown` target, [trunk](https://trunkrs.dev) and [worker-build](https://crates.io/crates/worker-build) (`cargo install trunk worker-build`), Node.js for wrangler, and clang with its WebAssembly target and `llvm-ar`, for the grammars of the web client's code previews.

```sh
cd e2ee_chat_worker
npm install
printf 'PASSWORD="%s"\nAUTH_KEY="%s"\n' "$(openssl rand -base64 24)" "$(openssl rand -base64 32)" > .dev.vars
npx wrangler dev
```

`.dev.vars` holds the secrets for `wrangler dev`, which warns if one is missing; git ignores it. The objects create their tables themselves.

`wrangler dev` builds the web client, with its previews' workers, and the Worker, and serves both, with local Durable Objects and R2, on <http://localhost:8787>. Open it in two browser profiles to chat with yourself. To work on the web client with hot reload, run `trunk serve` in `e2ee_chat_web` too: it proxies the Connect calls to `wrangler dev`.

# Deploy

`wrangler.toml` sets `workers_dev = false`: configure a custom domain under `routes` and matching `SERVER_ID` under `[vars]` before deploying.

```sh
npx wrangler login
npx wrangler r2 bucket create e2ee-chat
npx wrangler r2 bucket lifecycle add e2ee-chat attachments-v2 v2/attachments/ --expire-days 97
openssl rand -base64 24 | npx wrangler secret put PASSWORD
openssl rand -base64 32 | npx wrangler secret put AUTH_KEY
npx wrangler deploy
```

Without both secrets, nobody can sign in, so nobody can use the server. Keep the `v2/attachments/` R2 lifecycle rule at least `FILE_RETENTION_DAYS + 7` (97 days by default) so orphaned chunks from failed alarms are garbage-collected safely after DO expiry. Changing `AUTH_KEY` signs everyone out.

## Upgrading an existing pre-audit Worker script in place

The default `wrangler.toml` uses clean DO namespaces (`IdentityV2`, `AttachmentV2`) with `[[migrations]] tag = "v1"`, which deploys directly under a fresh Worker script name (or after deleting the old pre-audit Worker before attaching your custom-domain `routes`).

If you instead upgrade an **existing** deployed Worker script in place, perform a one-shot migration deploy by temporarily appending a `v2` migration tag (adjusting the tag if your existing script already has later tags):

```toml
[[migrations]]
tag = "v1"
new_sqlite_classes = ["Identity", "Attachment"]

[[migrations]]
tag = "v2"
new_sqlite_classes = ["IdentityV2", "AttachmentV2"]
deleted_classes = ["Identity", "Attachment"]
```

*(If upgrading from a very old deployment predating commit `05155959` that still had a `Notifier` Durable Object class, include `"Notifier"` in `deleted_classes` out of band.)* After that one-shot migration deploy succeeds, old `Identity` / `Attachment` state is deleted cleanly and subsequent deploys use only `IdentityV2` / `AttachmentV2`.

# Limits

The servers' default limits apply: 100 one-time prekeys per publish/refill, 100 initial messages waiting per inbox (first message up to 8 KiB), inline `PushV2` envelopes up to 64 KiB (`80 KiB` wire body), `FetchSigned` pages up to 100 messages or 1 MiB, up to 4096 authorized peers per recipient (4 grants/peer preserving the pinned active grant), up to 2000 messages / 64 MiB per peer and 256 MiB total per recipient, and attachments of up to 50 chunks of 2 MiB each. Request bodies over each procedure's limit are refused as soon as they grow past it.

# Storage conformance

```sh
worker-build --dev --features conformance
npx wrangler dev --config wrangler.test.toml --persist-to /tmp/conformance --no-bundle
curl -X POST -H "Authorization: Bearer $CONFORMANCE_TOKEN" http://localhost:8787/conformance
```

`POST /conformance` strictly requires a matching `CONFORMANCE_TOKEN` secret (`Authorization: Bearer <token>` or `X-Conformance-Token: <token>`) — a regular sign-in cookie is never accepted. The suites need empty objects, so use a fresh `--persist-to`; a failure panics and fails the request. Never deploy `--features conformance`.
