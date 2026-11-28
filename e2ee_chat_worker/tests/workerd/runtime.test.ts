import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import WorkerEntrypoint from "../../build/worker/shim.mjs";
import {
  AUDIENCE,
  MAX_SAFE_INTEGER,
  ORIGIN,
  connectPost,
  decodeAckMessagesResponse,
  decodeFetchSignedResponse,
  decodeGetChunkResponse,
  decodeGetServerInfoResponse,
  decodeNotification,
  decodePushV2Response,
  decodeRevokeWriteTokenResponse,
  decodeStartUploadResponse,
  encodeClaimBundleRequest,
  encodeDeleteAttachmentRequest,
  encodeGetChunkRequest,
  encodePushV2Request,
  encodePutChunkRequest,
  encodeSendInitialV2ClassicalRequest,
  encodeStartUploadRequest,
  hex,
  identityFromSeed,
  pbBytes,
  sha256,
  signAckInitialMessagesRequest,
  signAckMessagesRequest,
  signClassicalPublishV2Request,
  signFetchSignedRequest,
  signInCookie,
  signRegisterWriteTokenRequest,
  signRevokeWriteTokenRequest,
  signSubscribeRequestV2,
  utf8,
  wsSubprotocolHeader,
} from "./helpers";

function waitForMessage(ws: WebSocket, timeoutMs = 5000): Promise<string | ArrayBuffer | Blob> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for WS message")), timeoutMs);
    const onMessage = (event: MessageEvent) => {
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage);
      ws.removeEventListener("close", onClose);
      resolve(event.data as string | ArrayBuffer | Blob);
    };
    const onClose = (event: CloseEvent) => {
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage);
      ws.removeEventListener("close", onClose);
      reject(new Error(`WS closed unexpectedly (${event.code}: ${event.reason})`));
    };
    ws.addEventListener("message", onMessage);
    ws.addEventListener("close", onClose);
  });
}

async function binaryFrameBytes(frame: string | ArrayBuffer | Blob): Promise<Uint8Array> {
  if (frame instanceof ArrayBuffer) return new Uint8Array(frame);
  if (frame instanceof Blob) return new Uint8Array(await frame.arrayBuffer());
  throw new Error(`expected binary WebSocket frame, got string: ${frame}`);
}

function waitForClose(ws: WebSocket, timeoutMs = 5000): Promise<{ code: number; reason: string }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for WS close")), timeoutMs);
    const onClose = (event: CloseEvent) => {
      clearTimeout(timer);
      ws.removeEventListener("close", onClose);
      resolve({ code: event.code, reason: event.reason });
    };
    ws.addEventListener("close", onClose);
  });
}

async function publishClassicalIdentity(
  identity: ReturnType<typeof identityFromSeed>,
  cookie: string,
  seq = 1n,
  opks: Uint8Array[] = [],
): Promise<Response> {
  const spk = identityFromSeed((identity.publicKey[0] ^ 0x55) || 1).publicKey;
  const now = BigInt(Date.now());
  return connectPost(
    "/handshake.v2.HandshakeService/PublishV2",
    await signClassicalPublishV2Request({
      identity,
      audience: AUDIENCE,
      manifestSeq: seq,
      generation: seq,
      issuedAt: now,
      expiresAt: now + 3_600_000n,
      signedPrekey: spk,
      oneTimePrekeys: opks,
      timestampMs: now,
    }),
    cookie,
  );
}

describe("workerd runtime twins", () => {
  // -------------------------------------------------------------------------
  // 1. /auth/password login, hardened cookie parser, CSRF/Origin rejections
  // -------------------------------------------------------------------------
  it("enforces /auth/password login, hardened cookie helper (duplicate & >4096B), and CSRF/Origin rejections", async () => {
    const anon = await exports.default.fetch(`${ORIGIN}/auth`);
    expect(anon.status).toBe(200);
    expect(await anon.json()).toEqual({});
    expect(anon.headers.get("cache-control")).toBe("no-store");
    expect(anon.headers.get("x-content-type-options")).toBe("nosniff");
    expect(anon.headers.get("referrer-policy")).toBe("no-referrer");
    expect(anon.headers.get("x-e2ee-pq")).toBe("1");
    expect(anon.headers.get("date")).toBeTruthy();

    // Cross-site / cross-origin POSTs to /auth/password and /auth/sign-out are rejected.
    const crossSite = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: { "Sec-Fetch-Site": "cross-site" },
      body: env.PASSWORD,
    });
    expect(crossSite.status).toBe(403);
    expect(await crossSite.text()).toBe("not from this server's page");

    const sameSite = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: { "Sec-Fetch-Site": "same-site" },
      body: env.PASSWORD,
    });
    expect(sameSite.status).toBe(403);

    const badOrigin = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: { Origin: "https://evil.example" },
      body: env.PASSWORD,
    });
    expect(badOrigin.status).toBe(403);

    const badReferer = await exports.default.fetch(`${ORIGIN}/auth/sign-out`, {
      method: "POST",
      headers: { Referer: "https://evil.example/form" },
    });
    expect(badReferer.status).toBe(403);

    // Wrong password returns 403.
    const wrong = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: {
        Origin: ORIGIN,
        "CF-Connecting-IP": "198.51.100.77",
      },
      body: "not-the-password",
    });
    expect(wrong.status).toBe(403);
    expect(await wrong.text()).toBe("wrong password");

    // Valid password issues a signed __Host-e2ee-chat cookie with strict attributes.
    const login = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: {
        Origin: ORIGIN,
        "CF-Connecting-IP": "198.51.100.2",
      },
      body: env.PASSWORD,
    });
    expect(login.status).toBe(200);
    const setCookie = login.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(
      /^__Host-e2ee-chat=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+; Path=\/; Max-Age=\d+; HttpOnly; Secure; SameSite=Strict$/,
    );
    const claims = (await login.json()) as { subject: string; expires: number };
    expect(claims.subject).toBe("password");
    expect(claims.expires).toBeGreaterThan(Date.now());

    const cookiePair = setCookie!.split(";")[0];

    // Valid cookie authenticates GET /auth.
    const authed = await exports.default.fetch(`${ORIGIN}/auth`, {
      headers: { Cookie: cookiePair },
    });
    expect(authed.status).toBe(200);
    expect(await authed.json()).toEqual(claims);

    // Duplicate __Host-e2ee-chat cookies are rejected (prevents cookie-shadowing).
    const dupCookie = await exports.default.fetch(`${ORIGIN}/auth`, {
      headers: { Cookie: `${cookiePair}; ${cookiePair}` },
    });
    expect(await dupCookie.json()).toEqual({});

    // Oversized Cookie header (> 4096 bytes) is rejected.
    const hugeCookie = `${cookiePair}; pad=${"a".repeat(4100)}`;
    const oversizedAuth = await exports.default.fetch(`${ORIGIN}/auth`, {
      headers: { Cookie: hugeCookie },
    });
    expect(await oversizedAuth.json()).toEqual({});

    // Tampered cookie is rejected both on GET /auth and on write Connect RPCs.
    const tamperedCookie = `${cookiePair.slice(0, -1)}${cookiePair.endsWith("A") ? "B" : "A"}`;
    const badAuth = await exports.default.fetch(`${ORIGIN}/auth`, {
      headers: { Cookie: tamperedCookie },
    });
    expect(await badAuth.json()).toEqual({});

    const deleteHash = await sha256(utf8("delete-token-16b"));
    const unauthedUpload = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(1, deleteHash),
      tamperedCookie,
    );
    expect(unauthedUpload.status).toBe(403);
    expect(await unauthedUpload.json()).toMatchObject({ code: "permission_denied" });

    // POST /auth/sign-out clears the cookie with Max-Age=0 and hardened attributes.
    const signOut = await exports.default.fetch(`${ORIGIN}/auth/sign-out`, {
      method: "POST",
      headers: { "Sec-Fetch-Site": "same-origin", Cookie: cookiePair },
    });
    expect(signOut.status).toBe(200);
    expect(await signOut.json()).toEqual({});
    expect(signOut.headers.get("set-cookie")).toBe(
      "__Host-e2ee-chat=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
    );
  });

  // -------------------------------------------------------------------------
  // 2. Real R2 BUCKET (`v2/attachments/` opaque keys, only_if, AttachmentV2 alarm)
  // -------------------------------------------------------------------------
  it("uses opaque v2/attachments/ R2 keys, enforces only_if immutability, and cleans up on AttachmentV2 alarm", async () => {
    const cookie = await signInCookie(env.PASSWORD, "198.51.100.10");
    const deleteToken = new Uint8Array(16).fill(0x5a);
    const deleteHash = await sha256(deleteToken);

    const startRes = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(2, deleteHash),
      cookie,
      exports.default,
      { "CF-Connecting-IP": "198.51.100.10" },
    );
    expect(startRes.status).toBe(200);
    const { id, uploadToken, expires } = decodeStartUploadResponse(
      new Uint8Array(await startRes.arrayBuffer()),
    );
    expect(id.length).toBe(16);
    expect(uploadToken.length).toBe(16);
    expect(expires).toBeGreaterThan(BigInt(Date.now()));

    // Upload chunk 0 via Connect PutChunk and verify it exists under `v2/attachments/`.
    const chunk0V1 = utf8("chunk-0-original-ciphertext-bytes");
    const put0 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(id, uploadToken, 0, chunk0V1),
      cookie,
    );
    expect(put0.status).toBe(200);

    const key0 = `v2/attachments/${hex(id)}/0`;
    const key1 = `v2/attachments/${hex(id)}/1`;
    expect(await env.BUCKET.get(`attachments/${hex(id)}/0`)).toBeNull();
    const stored0 = await env.BUCKET.get(key0);
    expect(stored0).not.toBeNull();
    expect(new Uint8Array(await stored0!.arrayBuffer())).toEqual(chunk0V1);

    // Pre-seed chunk 1 directly in R2 to exercise `only_if(etag_does_not_match: "*")`.
    const chunk1Existing = utf8("chunk-1-preexisting-r2-bytes!!");
    const chunk1Overwrite = utf8("chunk-1-attempted-overwrite-data");
    await env.BUCKET.put(key1, chunk1Existing);

    const put1 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(id, uploadToken, 1, chunk1Overwrite),
      cookie,
    );
    expect(put1.status).toBe(200);

    const get1 = await connectPost(
      "/attachment.v1.AttachmentService/GetChunk",
      encodeGetChunkRequest(id, 1),
    );
    expect(get1.status).toBe(200);
    const decoded1 = decodeGetChunkResponse(new Uint8Array(await get1.arrayBuffer()));
    expect(decoded1.uploaded).toBe(true);
    expect(decoded1.data).toEqual(chunk1Existing);

    // Triggering the AttachmentV2 DO alarm deletes both R2 objects and wipes DO state.
    const attStub = env.ATTACHMENTS.get(env.ATTACHMENTS.idFromName(hex(id)));
    const scheduledAlarm = await runInDurableObject(attStub, (_inst, state) =>
      state.storage.getAlarm(),
    );
    expect(scheduledAlarm).not.toBeNull();

    const alarmRan = await runDurableObjectAlarm(attStub);
    expect(alarmRan).toBe(true);

    expect(await env.BUCKET.get(key0)).toBeNull();
    expect(await env.BUCKET.get(key1)).toBeNull();

    const afterAlarmGet = await connectPost(
      "/attachment.v1.AttachmentService/GetChunk",
      encodeGetChunkRequest(id, 0),
    );
    expect(afterAlarmGet.status).toBe(404);
    expect(await afterAlarmGet.json()).toMatchObject({ code: "not_found" });

    // Explicit DeleteAttachment with delete_token removes R2 chunk and DO state;
    // wrong token is refused with 401 unauthenticated.
    const start2 = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(1, deleteHash),
      cookie,
      exports.default,
      { "CF-Connecting-IP": "198.51.100.10" },
    );
    const att2 = decodeStartUploadResponse(new Uint8Array(await start2.arrayBuffer()));
    const put2 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(att2.id, att2.uploadToken, 0, utf8("explicit-delete-chunk")),
      cookie,
    );
    expect(put2.status).toBe(200);
    const key2 = `v2/attachments/${hex(att2.id)}/0`;
    expect(await env.BUCKET.get(key2)).not.toBeNull();

    const badDel = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att2.id, new Uint8Array(16).fill(0x00)),
    );
    expect(badDel.status).toBe(401);
    expect(await badDel.json()).toMatchObject({ code: "unauthenticated" });

    // R22-P2-8: `only_if_incomplete = true` preserves a completed 1-chunk attachment in DO + R2.
    const condComplete = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att2.id, att2.uploadToken, true),
    );
    expect(condComplete.status).toBe(200);
    expect(await env.BUCKET.get(key2)).not.toBeNull();

    const goodDel = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att2.id, deleteToken),
    );
    expect(goodDel.status).toBe(200);
    expect(await env.BUCKET.get(key2)).toBeNull();

    // R22-P2-8: `only_if_incomplete = true` deletes an incomplete 2-chunk attachment in DO + R2.
    const start3 = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(2, deleteHash),
      cookie,
      exports.default,
      { "CF-Connecting-IP": "198.51.100.10" },
    );
    const att3 = decodeStartUploadResponse(new Uint8Array(await start3.arrayBuffer()));
    const put3 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(att3.id, att3.uploadToken, 0, utf8("incomplete-chunk-zero")),
      cookie,
    );
    expect(put3.status).toBe(200);
    const key3 = `v2/attachments/${hex(att3.id)}/0`;
    expect(await env.BUCKET.get(key3)).not.toBeNull();
    const condIncomplete = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att3.id, att3.uploadToken, true),
    );
    expect(condIncomplete.status).toBe(200);
    expect(await env.BUCKET.get(key3)).toBeNull();
  });

  // -------------------------------------------------------------------------
  // 3. IdentityV2 SCHEMA_V5: unified mailbox, grants, zero mailbox R2,
  //    prefix ACK, alarm expiry/tombstones, eviction, transactionSync rollback,
  //    and MAX_SAFE_INTEGER guards
  // -------------------------------------------------------------------------
  it("enforces SCHEMA_V5 grants, unified inline mailbox (zero R2), prefix ACK, alarm cleanup, eviction, rollback, and MAX_SAFE_INTEGER", async () => {
    const cookie = await signInCookie(env.PASSWORD, "198.51.100.20");
    const bob = identityFromSeed(0x32);
    const spk = identityFromSeed(0x33).publicKey;
    const opk1 = identityFromSeed(0x34).publicKey;
    const opk2 = identityFromSeed(0x35).publicKey;
    const now = BigInt(Date.now());

    // Legacy v1 paths are cleanly gone (404, no deprecated header).
    const legacy = await connectPost("/mailbox.v1.MailboxService/Push", new Uint8Array(0), cookie);
    expect(legacy.status).toBe(404);
    expect(legacy.headers.get("x-e2ee-deprecated")).toBeNull();

    // Publish classical v2 manifest (seq = 1) + 2 OPKs.
    const pub1 = await connectPost(
      "/handshake.v2.HandshakeService/PublishV2",
      await signClassicalPublishV2Request({
        identity: bob,
        audience: AUDIENCE,
        manifestSeq: 1n,
        generation: 1n,
        issuedAt: now,
        expiresAt: now + 3_600_000n,
        signedPrekey: spk,
        oneTimePrekeys: [opk1, opk2],
        timestampMs: now,
      }),
      cookie,
    );
    expect(pub1.status).toBe(200);

    // Push with unregistered write_token -> Connect Code::Aborted (HTTP 409 JSON).
    const peerSlotA = new Uint8Array(32).fill(0xa1);
    const peerSlotB = new Uint8Array(32).fill(0xb1);
    const writeTokenA = new Uint8Array(32).fill(0xa2);
    const writeTokenB = new Uint8Array(32).fill(0xb2);
    const tokenHashA = await sha256(writeTokenA);
    const tokenHashB = await sha256(writeTokenB);
    const cid1 = new Uint8Array(16).fill(0x44);

    const rejectedPush = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        recipient: bob.publicKey,
        header: utf8("h0"),
        content: utf8("c0"),
        writeToken: writeTokenA,
        clientMessageId: cid1,
      }),
      cookie,
    );
    expect(rejectedPush.status).toBe(409);
    expect(await rejectedPush.json()).toMatchObject({ code: "aborted" });

    // Register write tokens for peer A and peer B (requires NO sign-in cookie).
    const regA = await connectPost(
      "/mailbox.v2.MailboxService/RegisterWriteToken",
      await signRegisterWriteTokenRequest({
        recipient: bob,
        audience: AUDIENCE,
        peerSlotId: peerSlotA,
        tokenHash: tokenHashA,
        grantVersion: 1n,
        pinActive: true,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(regA.status).toBe(200);
    const regB = await connectPost(
      "/mailbox.v2.MailboxService/RegisterWriteToken",
      await signRegisterWriteTokenRequest({
        recipient: bob,
        audience: AUDIENCE,
        peerSlotId: peerSlotB,
        tokenHash: tokenHashB,
        grantVersion: 1n,
        pinActive: true,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(regB.status).toBe(200);

    // Push > 64 KiB inline envelope (still <= 80 KiB wire body) -> 429 resource_exhausted (no R2!).
    const tooBigInline = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        recipient: bob.publicKey,
        header: utf8("hdr"),
        content: new Uint8Array(65 * 1024),
        writeToken: writeTokenA,
      }),
      cookie,
    );
    expect(tooBigInline.status).toBe(429);
    expect(await tooBigInline.json()).toMatchObject({ code: "resource_exhausted" });

    // Push > 80 KiB wire body -> rejected at Worker ingress before prost decode.
    const tooBigWire = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      new Uint8Array(81 * 1024),
      cookie,
    );
    expect(tooBigWire.status).toBe(429);
    expect(await tooBigWire.json()).toMatchObject({ code: "resource_exhausted" });

    // Push inline messages from peer A (seq 1, with cid1) and peer B (seq 2).
    const push1Body = encodePushV2Request({
      recipient: bob.publicKey,
      header: utf8("h1"),
      content: utf8("payload-from-a"),
      writeToken: writeTokenA,
      clientMessageId: cid1,
    });
    const push1 = await connectPost("/mailbox.v2.MailboxService/PushV2", push1Body, cookie);
    expect(push1.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push1.arrayBuffer()))).toBe(1n);

    // Idempotent retry returns seq 1 without duplicating.
    const push1Retry = await connectPost("/mailbox.v2.MailboxService/PushV2", push1Body, cookie);
    expect(push1Retry.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push1Retry.arrayBuffer()))).toBe(1n);

    const push2 = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        recipient: bob.publicKey,
        header: utf8("h2"),
        content: utf8("payload-from-b"),
        writeToken: writeTokenB,
      }),
      cookie,
    );
    expect(push2.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push2.arrayBuffer()))).toBe(2n);

    // Zero mailbox objects ever written to R2.
    const msgBucket = await env.BUCKET.list({ prefix: "messages/" });
    expect(msgBucket.objects.length).toBe(0);

    // Inspect IdentityV2 DO directly: SCHEMA_V5 version == 5 & transactionSync throw-rollback.
    const bobStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(hex(bob.publicKey)));
    const schemaAndRollback = await runInDurableObject(bobStub, (_inst, state) => {
      const schemaVersion = state.storage.sql
        .exec("SELECT schema_version FROM meta WHERE only = 0")
        .one().schema_version as number;
      let threw = false;
      try {
        state.storage.transactionSync(() => {
          state.storage.sql.exec(
            "INSERT INTO dedup_counts (token_hash, count) VALUES (?, ?)",
            new Uint8Array(32).fill(0xee),
            99,
          );
          throw new Error("intentional rollback");
        });
      } catch {
        threw = true;
      }
      const rolledBack = state.storage.sql
        .exec(
          "SELECT count(*) AS count FROM dedup_counts WHERE token_hash = ?",
          new Uint8Array(32).fill(0xee),
        )
        .one().count as number;
      return { schemaVersion, threw, rolledBack };
    });
    expect(schemaAndRollback).toEqual({
      schemaVersion: 5,
      threw: true,
      rolledBack: 0,
    });

    // Evict IdentityV2 DO and verify persisted rows survive cold restart.
    await evictDurableObject(bobStub);

    // Fetch page 1 (limit=1) -> seq 1 with tokenHashA and has_more=true.
    const fetch1 = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        audience: AUDIENCE,
        afterSequence: 0n,
        limit: 1,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(fetch1.status).toBe(200);
    const page1 = decodeFetchSignedResponse(new Uint8Array(await fetch1.arrayBuffer()));
    expect(page1.hasMore).toBe(true);
    expect(page1.messages.length).toBe(1);
    expect(page1.messages[0].sequence).toBe(1n);
    expect(page1.messages[0].tokenHash).toEqual(tokenHashA);
    expect(page1.messages[0].content).toEqual(utf8("payload-from-a"));

    // Piggybacked ACK of seq 1 while fetching after seq 1 -> returns seq 2, has_more=false.
    const fetch2 = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        audience: AUDIENCE,
        afterSequence: 1n,
        limit: 10,
        ackUpToSequence: 1n,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(fetch2.status).toBe(200);
    const page2 = decodeFetchSignedResponse(new Uint8Array(await fetch2.arrayBuffer()));
    expect(page2.hasMore).toBe(false);
    expect(page2.messages.length).toBe(1);
    expect(page2.messages[0].sequence).toBe(2n);
    expect(page2.messages[0].tokenHash).toEqual(tokenHashB);

    // Explicit AckMessages rejects > last_sequence (seq 3) and accepts seq 2.
    const futureAck = await connectPost(
      "/mailbox.v2.MailboxService/AckMessages",
      await signAckMessagesRequest({
        recipient: bob,
        audience: AUDIENCE,
        upToSequence: 3n,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(futureAck.status).toBe(400);
    expect(await futureAck.json()).toMatchObject({ code: "invalid_argument" });

    const goodAck = await connectPost(
      "/mailbox.v2.MailboxService/AckMessages",
      await signAckMessagesRequest({
        recipient: bob,
        audience: AUDIENCE,
        upToSequence: 2n,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(goodAck.status).toBe(200);
    expect(decodeAckMessagesResponse(new Uint8Array(await goodAck.arrayBuffer()))).toBe(1n);

    // Revoke peer A -> auth-before-dedup rejects cid1 retry with 409 aborted!
    const revokeA = await connectPost(
      "/mailbox.v2.MailboxService/RevokeWriteToken",
      await signRevokeWriteTokenRequest({
        recipient: bob,
        audience: AUDIENCE,
        peerSlotId: peerSlotA,
        minGrantVersion: 5n,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(revokeA.status).toBe(200);
    expect(decodeRevokeWriteTokenResponse(new Uint8Array(await revokeA.arrayBuffer()))).toBe(1);

    const revokedRetry = await connectPost("/mailbox.v2.MailboxService/PushV2", push1Body, cookie);
    expect(revokedRetry.status).toBe(409);
    expect(await revokedRetry.json()).toMatchObject({ code: "aborted" });

    // Backdate dedup & revoked peer_grants tombstone and fire IdentityV2 alarm ->
    // zeroed `dedup_counts` and empty expired `peer_grants` tombstones are pruned cleanly.
    await runInDurableObject(bobStub, async (_inst, state) => {
      state.storage.sql.exec("UPDATE mailbox_dedup SET expires_at = 1");
      state.storage.sql.exec("UPDATE peer_grants SET revoked_at = 1 WHERE revoked_at > 0");
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(bobStub)).toBe(true);
    const afterAlarm = await runInDurableObject(bobStub, (_inst, state) => ({
      dedup: state.storage.sql.exec("SELECT count(*) AS c FROM mailbox_dedup").one().c as number,
      dedupCounts: state.storage.sql.exec("SELECT count(*) AS c FROM dedup_counts").one()
        .c as number,
      revokedPeerA: state.storage.sql
        .exec("SELECT count(*) AS c FROM peer_grants WHERE peer_slot_id = ?", peerSlotA)
        .one().c as number,
    }));
    expect(afterAlarm).toEqual({ dedup: 0, dedupCounts: 0, revokedPeerA: 0 });

    // MAX_SAFE_INTEGER guards.
    const badAckInit = await connectPost(
      "/handshake.v2.HandshakeService/AckInitialMessages",
      await signAckInitialMessagesRequest({
        recipient: bob,
        audience: AUDIENCE,
        ids: [MAX_SAFE_INTEGER + 1n],
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(badAckInit.status).toBe(400);
    expect(await badAckInit.json()).toMatchObject({ code: "invalid_argument" });

    const badSeqPub = await connectPost(
      "/handshake.v2.HandshakeService/PublishV2",
      await signClassicalPublishV2Request({
        identity: bob,
        audience: AUDIENCE,
        manifestSeq: MAX_SAFE_INTEGER + 1n,
        generation: 2n,
        issuedAt: now,
        expiresAt: now + 3_600_000n,
        signedPrekey: spk,
        oneTimePrekeys: [],
        timestampMs: now + 2n,
      }),
      cookie,
    );
    expect(badSeqPub.status).toBe(400);
    expect(await badSeqPub.json()).toMatchObject({ code: "invalid_argument" });
  });

  // -------------------------------------------------------------------------
  // 4. Pre-Auth WebSocket (`Sec-WebSocket-Protocol`), zero victim DO wake on
  //    bad sig, same-ms distinct-nonce reconnect, replay 403 pre-101,
  //    sender-blind Notification, and hibernation
  // -------------------------------------------------------------------------
  it("enforces pre-auth WS Sec-WebSocket-Protocol, zero victim DO wake on bad sig, same-ms distinct-nonce reconnect, replay 403, and sender-blind notifications", async () => {
    const cookie = await signInCookie(env.PASSWORD, "198.51.100.30");
    const bob = identityFromSeed(0x41);
    const victim = identityFromSeed(0x4f);
    const wsUrl = `${ORIGIN}/notifications`;

    // Publish Bob + register write token for live notification push.
    expect((await publishClassicalIdentity(bob, cookie)).status).toBe(200);
    const writeToken = new Uint8Array(32).fill(0x77);
    const tokenHash = await sha256(writeToken);
    expect(
      (
        await connectPost(
          "/mailbox.v2.MailboxService/RegisterWriteToken",
          await signRegisterWriteTokenRequest({
            recipient: bob,
            audience: AUDIENCE,
            peerSlotId: new Uint8Array(32).fill(0x70),
            tokenHash,
            grantVersion: 1n,
            pinActive: true,
            timestampMs: BigInt(Date.now()),
          }),
        )
      ).status,
    ).toBe(200);

    // Non-WebSocket request returns 426.
    const noUpgrade = await exports.default.fetch(wsUrl, {
      headers: { Cookie: cookie, "CF-Connecting-IP": "198.51.100.30" },
    });
    expect(noUpgrade.status).toBe(426);

    // Unauthenticated upgrade is rejected with 403 when PASSWORD is configured.
    const unauthedWs = await exports.default.fetch(wsUrl, {
      headers: { Upgrade: "websocket", "CF-Connecting-IP": "198.51.100.30" },
    });
    expect(unauthedWs.status).toBe(403);

    // Cross-origin upgrade is rejected with 403 (CSWSH defense).
    const crossOriginWs = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: "https://evil.example",
        Cookie: cookie,
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(crossOriginWs.status).toBe(403);
    expect(await crossOriginWs.text()).toBe("cross-origin WebSocket refused");

    // Missing Sec-WebSocket-Protocol returns 400.
    const missingProto = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(missingProto.status).toBe(400);

    // Bad signature claiming victim's identity returns 403 pre-101 AND never wakes/allocates
    // victim's IdentityV2 DO (`seen_subscribes` / `meta` stay completely absent).
    const forgedSub = await signSubscribeRequestV2(victim, AUDIENCE, BigInt(Date.now()));
    const tamperedSub = new Uint8Array(forgedSub);
    tamperedSub[tamperedSub.length - 1] ^= 0xff; // corrupt nonce/signature
    const badSigRes = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(tamperedSub),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(badSigRes.status).toBe(403);
    const victimStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(hex(victim.publicKey)));
    const victimTables = await runInDurableObject(victimStub, (_inst, state) =>
      state.storage.sql
        .exec("SELECT count(*) AS count FROM sqlite_master WHERE type = 'table'")
        .one().count as number,
    );
    expect(victimTables).toBe(0);

    // Valid pre-auth upgrade: 101 echoing ONLY `e2ee-notify.v2` (never `e2ee-sub.*`).
    const sharedTs = BigInt(Date.now());
    const nonce1 = new Uint8Array(16).fill(0x11);
    const nonce2 = new Uint8Array(16).fill(0x22);
    const sub1 = await signSubscribeRequestV2(bob, AUDIENCE, sharedTs, nonce1);
    const upgrade1 = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(sub1),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(upgrade1.status).toBe(101);
    expect(upgrade1.headers.get("sec-websocket-protocol")).toBe("e2ee-notify.v2");
    const ws1 = upgrade1.webSocket!;
    expect(ws1).not.toBeNull();
    ws1.accept();

    // Non-canonical URL audience (instead of normalized authority) is rejected with 403 pre-101.
    const nonCanonicalSub = await signSubscribeRequestV2(bob, `${ORIGIN}/`, sharedTs, nonce2);
    const nonCanonicalRes = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(nonCanonicalSub),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(nonCanonicalRes.status).toBe(403);

    // Same-millisecond reconnect with a distinct 16-byte nonce succeeds cleanly!
    const sub2 = await signSubscribeRequestV2(bob, AUDIENCE, sharedTs, nonce2);
    const upgrade2 = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(sub2),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(upgrade2.status).toBe(101);
    expect(upgrade2.headers.get("sec-websocket-protocol")).toBe("e2ee-notify.v2");
    const ws2 = upgrade2.webSocket!;
    ws2.accept();
    ws2.close(1000, "done");

    // Exact replay of sub1 returns 403 pre-101!
    const replayRes = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(sub1),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(replayRes.status).toBe(403);
    expect(await replayRes.text()).toBe("replayed subscription");

    // Auto-response answers "ping" with "pong".
    const pongPromise = waitForMessage(ws1);
    ws1.send("ping");
    expect(await pongPromise).toBe("pong");

    // PushV2 delivers a sender-blind binary Notification { message: true } before & after hibernation.
    const notifPromise = waitForMessage(ws1);
    const pushRes = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        recipient: bob.publicKey,
        header: utf8("ws-h"),
        content: utf8("ws-c"),
        writeToken,
      }),
      cookie,
    );
    expect(pushRes.status).toBe(200);
    expect(decodeNotification(await binaryFrameBytes(await notifPromise))).toEqual({
      message: true,
    });

    const bobStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(hex(bob.publicKey)));
    await evictDurableObject(bobStub, { webSockets: "hibernate" });

    const hibernatedPong = waitForMessage(ws1);
    ws1.send("ping");
    expect(await hibernatedPong).toBe("pong");

    const hibernatedNotif = waitForMessage(ws1);
    const pushAfterHibernate = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        recipient: bob.publicKey,
        header: utf8("ws-h2"),
        content: utf8("ws-c2"),
        writeToken,
      }),
      cookie,
    );
    expect(pushAfterHibernate.status).toBe(200);
    expect(decodeNotification(await binaryFrameBytes(await hibernatedNotif))).toEqual({
      message: true,
    });

    // Unexpected post-auth frame closes socket with 1008.
    const closePromise = waitForClose(ws1);
    ws1.send("unexpected-post-auth-frame");
    const closed = await closePromise;
    expect(closed.code).toBe(1008);
    expect(closed.reason).toBe("unexpected message");

    // Sign-in cookie `session_expires` survives hibernation and alarm closes expired socket with 1008.
    const nonce3 = new Uint8Array(16).fill(0x33);
    const sub3 = await signSubscribeRequestV2(bob, AUDIENCE, BigInt(Date.now()), nonce3);
    const upgrade3 = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
        "Sec-WebSocket-Protocol": wsSubprotocolHeader(sub3),
        "CF-Connecting-IP": "198.51.100.30",
      },
    });
    expect(upgrade3.status).toBe(101);
    const wsExp = upgrade3.webSocket!;
    wsExp.accept();

    await evictDurableObject(bobStub, { webSockets: "hibernate" });

    const preservedExpires = await runInDurableObject(bobStub, async (_inst, state) => {
      const sockets = state.getWebSockets();
      expect(sockets.length).toBe(1);
      const serverWs = sockets[0];
      const att = serverWs.deserializeAttachment() as
        | Map<string, unknown>
        | Record<string, unknown>;
      const prev = att instanceof Map ? att.get("session_expires") : att.session_expires;
      const expiredAt = Date.now() - 1;
      if (att instanceof Map) {
        att.set("session_expires", expiredAt);
        serverWs.serializeAttachment(att);
      } else {
        serverWs.serializeAttachment({ ...att, session_expires: expiredAt });
      }
      await state.storage.setAlarm(Date.now() + 60_000);
      return Number(prev);
    });
    expect(preservedExpires).toBeGreaterThan(Date.now());

    const expClosePromise = waitForClose(wsExp);
    expect(await runDurableObjectAlarm(bobStub)).toBe(true);
    const expClosed = await expClosePromise;
    expect(expClosed.code).toBe(1008);
    expect(expClosed.reason).toBe("session expired");
  });

  // -------------------------------------------------------------------------
  // 5. All 4 GA `[[ratelimits]]` bindings
  // -------------------------------------------------------------------------
  it("enforces all 4 [[ratelimits]] bindings with exact HTTP status codes and Retry-After headers", async () => {
    // 5a. AUTH_RATE_LIMITER (20/60s) on POST /auth/password -> 429 + Retry-After: 60.
    // Using the valid password proves AUTH_RATE_LIMITER (not isolate FAILED_ATTEMPTS) fired.
    const authIp = "198.51.100.201";
    for (let i = 0; i < 20; i++) {
      const ok = await exports.default.fetch(`${ORIGIN}/auth/password`, {
        method: "POST",
        headers: { "Sec-Fetch-Site": "same-origin", "CF-Connecting-IP": authIp },
        body: env.PASSWORD,
      });
      expect(ok.status).toBe(200);
    }
    const authLimited = await exports.default.fetch(`${ORIGIN}/auth/password`, {
      method: "POST",
      headers: { "Sec-Fetch-Site": "same-origin", "CF-Connecting-IP": authIp },
      body: env.PASSWORD,
    });
    expect(authLimited.status).toBe(429);
    expect(authLimited.headers.get("retry-after")).toBe("60");

    // 5b. WS_RATE_LIMITER (30/60s) on GET /notifications -> 429 + Retry-After: 60.
    const wsIp = "198.51.100.202";
    for (let i = 0; i < 30; i++) {
      const res = await exports.default.fetch(`${ORIGIN}/notifications`, {
        headers: { Upgrade: "websocket", "CF-Connecting-IP": wsIp },
      });
      expect(res.status).toBe(403);
    }
    const wsLimited = await exports.default.fetch(`${ORIGIN}/notifications`, {
      headers: { Upgrade: "websocket", "CF-Connecting-IP": wsIp },
    });
    expect(wsLimited.status).toBe(429);
    expect(wsLimited.headers.get("retry-after")).toBe("60");

    // 5c. HANDSHAKE_RATE_LIMITER (30/60s) on ClaimBundle & SendInitialV2 ->
    //     Connect Code::Unavailable (HTTP 503 JSON + Retry-After: 60, NEVER resource_exhausted!).
    const hsIp = "198.51.100.203";
    const hsCookie = await signInCookie(env.PASSWORD, hsIp);
    const target = identityFromSeed(0x61);
    const sender = identityFromSeed(0x62);
    const claimBody = encodeClaimBundleRequest(target.publicKey, []);
    for (let i = 0; i < 30; i++) {
      const res = await connectPost(
        "/handshake.v2.HandshakeService/ClaimBundle",
        claimBody,
        hsCookie,
        exports.default,
        { "CF-Connecting-IP": hsIp },
      );
      expect(res.status).toBe(404);
    }
    const claimLimited = await connectPost(
      "/handshake.v2.HandshakeService/ClaimBundle",
      claimBody,
      hsCookie,
      exports.default,
      { "CF-Connecting-IP": hsIp },
    );
    expect(claimLimited.status).toBe(503);
    expect(claimLimited.headers.get("retry-after")).toBe("60");
    expect(await claimLimited.json()).toMatchObject({ code: "unavailable" });

    const initBody = encodeSendInitialV2ClassicalRequest({
      recipient: target.publicKey,
      sender: sender.publicKey,
      ephemeralKey: identityFromSeed(0x63).publicKey,
      signedPrekey: identityFromSeed(0x64).publicKey,
      header: utf8("ih"),
      content: utf8("ic"),
    });
    for (let i = 0; i < 30; i++) {
      const res = await connectPost(
        "/handshake.v2.HandshakeService/SendInitialV2",
        initBody,
        hsCookie,
        exports.default,
        { "CF-Connecting-IP": hsIp },
      );
      expect(res.status).toBe(404);
    }
    const initLimited = await connectPost(
      "/handshake.v2.HandshakeService/SendInitialV2",
      initBody,
      hsCookie,
      exports.default,
      { "CF-Connecting-IP": hsIp },
    );
    expect(initLimited.status).toBe(503);
    expect(initLimited.headers.get("retry-after")).toBe("60");
    expect(await initLimited.json()).toMatchObject({ code: "unavailable" });

    // 5d. UPLOAD_RATE_LIMITER (30/60s) on StartUpload ->
    //     Connect Code::Unavailable (HTTP 503 JSON + Retry-After: 60, NEVER resource_exhausted!).
    const upIp = "198.51.100.204";
    const upCookie = await signInCookie(env.PASSWORD, upIp);
    const deleteHash = await sha256(utf8("rl-delete-token-"));
    const startBody = encodeStartUploadRequest(1, deleteHash);
    for (let i = 0; i < 30; i++) {
      const res = await connectPost(
        "/attachment.v1.AttachmentService/StartUpload",
        startBody,
        upCookie,
        exports.default,
        { "CF-Connecting-IP": upIp },
      );
      expect(res.status).toBe(200);
    }
    const uploadLimited = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      startBody,
      upCookie,
      exports.default,
      { "CF-Connecting-IP": upIp },
    );
    expect(uploadLimited.status).toBe(503);
    expect(uploadLimited.headers.get("retry-after")).toBe("60");
    expect(await uploadLimited.json()).toMatchObject({ code: "unavailable" });
  });

  // -------------------------------------------------------------------------
  // 6. LargeBodyPermit (`503` Connect `Code::Unavailable` + `Retry-After: 1`)
  // -------------------------------------------------------------------------
  it("enforces LargeBodyPermit (max 4 concurrent PutChunk/GetChunk/FetchSigned) returning 503 unavailable + Retry-After: 1", async () => {
    const cookie = await signInCookie(env.PASSWORD, "198.51.100.205");
    const controllers: ReadableStreamDefaultController<Uint8Array>[] = [];
    const inFlight: Promise<Response>[] = [];

    // Hold 4 streaming PutChunk requests open inside `read_body` (each holds a LargeBodyPermit).
    for (let i = 0; i < 4; i++) {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controllers.push(controller);
          controller.enqueue(new Uint8Array([0x0a, 0x01]));
        },
      });
      inFlight.push(connectPost("/attachment.v1.AttachmentService/PutChunk", stream, cookie));
    }

    // Give the 4 fetches a microtask tick to acquire permits and block on `read_body`.
    await new Promise((resolve) => setTimeout(resolve, 25));

    // A 5th large-body op (GetChunk and FetchSigned) MUST fail immediately with 503 + Retry-After: 1.
    const busyGet = await connectPost(
      "/attachment.v1.AttachmentService/GetChunk",
      encodeGetChunkRequest(new Uint8Array(16).fill(0x99), 0),
    );
    expect(busyGet.status).toBe(503);
    expect(busyGet.headers.get("retry-after")).toBe("1");
    expect(await busyGet.json()).toMatchObject({ code: "unavailable" });

    const bob = identityFromSeed(0x71);
    const busyFetch = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        audience: AUDIENCE,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(busyFetch.status).toBe(503);
    expect(busyFetch.headers.get("retry-after")).toBe("1");
    expect(await busyFetch.json()).toMatchObject({ code: "unavailable" });

    // Close the 4 streams so RAII `LargeBodyPermit::drop` releases all slots.
    for (const controller of controllers) controller.close();
    const settled = await Promise.all(inFlight);
    for (const res of settled) {
      expect(res.status).toBe(400); // truncated protobuf body -> invalid_argument
    }

    // Subsequent FetchSigned succeeds cleanly once permits are released.
    const freeFetch = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        audience: AUDIENCE,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(freeFetch.status).toBe(200);
  });

  // -------------------------------------------------------------------------
  // 7. PQ_ENABLED="false" runtime gating
  // -------------------------------------------------------------------------
  it('serves signed GetManifest and advertises x-e2ee-pq: 0 when PQ_ENABLED="false"', async () => {
    const ctx = createExecutionContext();
    const pqOffEnv = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
      PQ_ENABLED: "false",
    });
    const worker = new WorkerEntrypoint(ctx, pqOffEnv);

    const infoRes = await worker.fetch(
      new Request(`${ORIGIN}/handshake.v2.HandshakeService/GetServerInfo`, {
        method: "POST",
        headers: {
          "content-type": "application/proto",
          "connect-protocol-version": "1",
        },
        body: new Uint8Array(0),
      }),
    );
    expect(infoRes.status).toBe(200);
    expect(infoRes.headers.get("x-e2ee-pq")).toBe("0");
    const info = decodeGetServerInfoResponse(new Uint8Array(await infoRes.arrayBuffer()));
    expect(info.pqEnabled).toBe(false);
    expect(info.supportedSuites).toEqual([]);
    expect(info.pqRatchetSupported).toBe(false);
    expect(info.serverId).toBe(AUDIENCE);

    const bob = identityFromSeed(0x51);
    const manifestRes = await worker.fetch(
      new Request(`${ORIGIN}/handshake.v2.HandshakeService/GetManifest`, {
        method: "POST",
        headers: {
          "content-type": "application/proto",
          "connect-protocol-version": "1",
        },
        body: pbBytes(1, bob.publicKey),
      }),
    );
    expect(manifestRes.status).toBe(200);
    expect(manifestRes.headers.get("x-e2ee-pq")).toBe("0");
    expect(new Uint8Array(await manifestRes.arrayBuffer()).length).toBe(0);

    await waitOnExecutionContext(ctx);
  });

  // -------------------------------------------------------------------------
  // 8. Fail-closed /notifications auth without PASSWORD, lazy R2 binding,
  //    and fail-closed rate limiter when PASSWORD is set
  // -------------------------------------------------------------------------
  it("fails closed on /notifications when PASSWORD is unset, tolerates missing ATTACHMENTS on core RPCs, and fails closed on missing rate limiter when PASSWORD is set", async () => {
    // 8a. Missing PASSWORD + no Access/Cookie still fails closed on GET /notifications (403)
    //     just like call_connect, and missing ATTACHMENTS R2 binding does NOT break core RPCs.
    {
      const ctx = createExecutionContext();
      const minimalEnv = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
        PASSWORD: undefined,
        BUCKET: undefined,
        ATTACHMENTS: undefined,
      });
      const worker = new WorkerEntrypoint(ctx, minimalEnv);

      const unauthedWs = await worker.fetch(
        new Request(`${ORIGIN}/notifications`, {
          headers: { Upgrade: "websocket", "CF-Connecting-IP": "198.51.100.210" },
        }),
      );
      expect(unauthedWs.status).toBe(403);

      const infoRes = await worker.fetch(
        new Request(`${ORIGIN}/handshake.v2.HandshakeService/GetServerInfo`, {
          method: "POST",
          headers: {
            "content-type": "application/proto",
            "connect-protocol-version": "1",
          },
          body: new Uint8Array(0),
        }),
      );
      expect(infoRes.status).toBe(200);
      await waitOnExecutionContext(ctx);
    }

    // 8b. Missing AUTH_RATE_LIMITER binding fails closed (429) when PASSWORD is configured.
    {
      const ctx = createExecutionContext();
      const missingRlEnv = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
        AUTH_RATE_LIMITER: undefined,
      });
      const worker = new WorkerEntrypoint(ctx, missingRlEnv);
      const res = await worker.fetch(
        new Request(`${ORIGIN}/auth/password`, {
          method: "POST",
          headers: {
            "Sec-Fetch-Site": "same-origin",
            "CF-Connecting-IP": "198.51.100.211",
          },
          body: env.PASSWORD,
        }),
      );
      expect(res.status).toBe(429);
      await waitOnExecutionContext(ctx);
    }

    // 8c. Throwing, rejecting, or malformed AUTH_RATE_LIMITER fails closed (429) when PASSWORD is set.
    for (const [idx, badLimiter] of [
      {
        limit() {
          throw new Error("boom sync");
        },
      },
      {
        limit() {
          return Promise.reject(new Error("boom async"));
        },
      },
      {
        limit() {
          return Promise.resolve({ success: "not-a-bool" });
        },
      },
    ].entries()) {
      const ctx = createExecutionContext();
      const badEnv = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
        AUTH_RATE_LIMITER: badLimiter,
      });
      const worker = new WorkerEntrypoint(ctx, badEnv);
      const res = await worker.fetch(
        new Request(`${ORIGIN}/auth/password`, {
          method: "POST",
          headers: {
            "Sec-Fetch-Site": "same-origin",
            "CF-Connecting-IP": `198.51.100.${212 + idx}`,
          },
          body: env.PASSWORD,
        }),
      );
      expect(res.status).toBe(429);
      await waitOnExecutionContext(ctx);
    }

    // 8d. StartUpload checks BUCKET R2 binding upfront and rejects cleanly without allocating DOs.
    {
      const cookie = await signInCookie(env.PASSWORD, "198.51.100.220");
      const ctx = createExecutionContext();
      let doIdFromNameCalls = 0;
      const spyAttachmentNs = {
        idFromName(name: string) {
          doIdFromNameCalls++;
          return env.ATTACHMENTS.idFromName(name);
        },
        get: env.ATTACHMENTS.get.bind(env.ATTACHMENTS),
      };
      const noR2Env = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
        BUCKET: undefined,
        ATTACHMENTS: spyAttachmentNs,
      });
      const worker = new WorkerEntrypoint(ctx, noR2Env);
      const deleteHash = await sha256(utf8("no-r2-delete-token"));
      const res = await worker.fetch(
        new Request(`${ORIGIN}/attachment.v1.AttachmentService/StartUpload`, {
          method: "POST",
          headers: {
            "content-type": "application/proto",
            "connect-protocol-version": "1",
            "CF-Connecting-IP": "198.51.100.220",
            Cookie: cookie,
          },
          body: encodeStartUploadRequest(1, deleteHash),
        }),
      );
      expect(res.status).toBeGreaterThanOrEqual(500);
      expect(doIdFromNameCalls).toBe(0);
      await waitOnExecutionContext(ctx);
    }
  });
});
