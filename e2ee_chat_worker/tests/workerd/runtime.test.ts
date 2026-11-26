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
  base64UrlEncode,
  connectPost,
  decodeFetchSignedResponse,
  decodeGetChunkResponse,
  decodeGetServerInfoResponse,
  decodeNotification,
  decodePushV2Response,
  decodeStartUploadResponse,
  encodeDeleteAttachmentRequest,
  encodeGetChunkRequest,
  encodePutChunkRequest,
  encodePushV2Request,
  encodeStartUploadRequest,
  hex,
  identityFromSeed,
  pbBytes,
  sha256,
  signAckInitialMessagesRequest,
  signClassicalPublishV2Request,
  signFetchSignedRequest,
  signInCookie,
  signSubscribeRequestV2,
  utf8,
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

describe("workerd runtime twins", () => {
  // -------------------------------------------------------------------------
  // 1. /auth/password login, cookie attributes, CSRF/Origin rejections
  // -------------------------------------------------------------------------
  it("enforces /auth/password login, hardened cookie attributes, and CSRF/Origin rejections", async () => {
    // Unauthenticated GET /auth returns {} with defensive metadata headers.
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
  // 2. Real R2 BUCKET (put, only_if, delete_multiple) + Attachment DO alarm
  // -------------------------------------------------------------------------
  it("enforces R2 put/only_if immutability and Attachment DO alarm delete_multiple cleanup", async () => {
    const cookie = await signInCookie();
    const deleteToken = new Uint8Array(16).fill(0x5a);
    const deleteHash = await sha256(deleteToken);

    const startRes = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(2, deleteHash),
      cookie,
    );
    expect(startRes.status).toBe(200);
    const { id, uploadToken, expires } = decodeStartUploadResponse(
      new Uint8Array(await startRes.arrayBuffer()),
    );
    expect(id.length).toBe(16);
    expect(uploadToken.length).toBe(16);
    expect(expires).toBeGreaterThan(BigInt(Date.now()));

    // Upload chunk 0 via Connect PutChunk and verify it exists in real R2 BUCKET.
    const chunk0V1 = utf8("chunk-0-original-ciphertext-bytes");
    const put0 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(id, uploadToken, 0, chunk0V1),
      cookie,
    );
    expect(put0.status).toBe(200);

    const key0 = `attachments/${hex(id)}/0`;
    const key1 = `attachments/${hex(id)}/1`;
    const stored0 = await env.BUCKET.get(key0);
    expect(stored0).not.toBeNull();
    expect(new Uint8Array(await stored0!.arrayBuffer())).toEqual(chunk0V1);

    // Pre-seed chunk 1 directly in R2 before PutChunk so `put().only_if(etag_does_not_match: "*")`
    // is genuinely exercised at the R2 conditional-write layer (without short-circuiting on `uploaded` bit).
    const chunk1Existing = utf8("chunk-1-preexisting-r2-bytes!!");
    const chunk1Overwrite = utf8("chunk-1-attempted-overwrite-data");
    await env.BUCKET.put(key1, chunk1Existing);

    const put1 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(id, uploadToken, 1, chunk1Overwrite),
      cookie,
    );
    expect(put1.status).toBe(200);

    // R2 `only_if` prevented overwriting the existing object, while DO noted chunk 1 as uploaded.
    const get1 = await connectPost(
      "/attachment.v1.AttachmentService/GetChunk",
      encodeGetChunkRequest(id, 1),
    );
    expect(get1.status).toBe(200);
    const decoded1 = decodeGetChunkResponse(new Uint8Array(await get1.arrayBuffer()));
    expect(decoded1.uploaded).toBe(true);
    expect(decoded1.data).toEqual(chunk1Existing);

    // Triggering the Attachment DO alarm runs `Attachment::delete()` -> `BUCKET.delete_multiple`
    // and `storage.deleteAll()`.
    const attStub = env.ATTACHMENTS.get(env.ATTACHMENTS.idFromName(hex(id)));
    const scheduledAlarm = await runInDurableObject(attStub, (_inst, state) =>
      state.storage.getAlarm(),
    );
    expect(scheduledAlarm).not.toBeNull();

    const alarmRan = await runDurableObjectAlarm(attStub);
    expect(alarmRan).toBe(true);

    // Both R2 objects are gone and GetChunk returns Connect not_found (404).
    expect(await env.BUCKET.get(key0)).toBeNull();
    expect(await env.BUCKET.get(key1)).toBeNull();

    const afterAlarmGet = await connectPost(
      "/attachment.v1.AttachmentService/GetChunk",
      encodeGetChunkRequest(id, 0),
    );
    expect(afterAlarmGet.status).toBe(404);
    expect(await afterAlarmGet.json()).toMatchObject({ code: "not_found" });

    // Explicit DeleteAttachment with delete_token removes both R2 chunks and DO state;
    // wrong token is refused with 401 unauthenticated.
    const start2 = await connectPost(
      "/attachment.v1.AttachmentService/StartUpload",
      encodeStartUploadRequest(1, deleteHash),
      cookie,
    );
    const att2 = decodeStartUploadResponse(new Uint8Array(await start2.arrayBuffer()));
    const put2 = await connectPost(
      "/attachment.v1.AttachmentService/PutChunk",
      encodePutChunkRequest(att2.id, att2.uploadToken, 0, utf8("explicit-delete-chunk")),
      cookie,
    );
    expect(put2.status).toBe(200);
    const key2 = `attachments/${hex(att2.id)}/0`;
    expect(await env.BUCKET.get(key2)).not.toBeNull();

    const badDel = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att2.id, new Uint8Array(16).fill(0x00)),
    );
    expect(badDel.status).toBe(401);
    expect(await badDel.json()).toMatchObject({ code: "unauthenticated" });

    const goodDel = await connectPost(
      "/attachment.v1.AttachmentService/DeleteAttachment",
      encodeDeleteAttachmentRequest(att2.id, deleteToken),
    );
    expect(goodDel.status).toBe(200);
    expect(await env.BUCKET.get(key2)).toBeNull();
  });

  // -------------------------------------------------------------------------
  // 3. Identity DO: DeleteDeliveredAtomic R2 cleanup & alarm retry,
  //    SQLite transactionSync persistence/rollback across requests & eviction,
  //    and MAX_SAFE_INTEGER guards
  // -------------------------------------------------------------------------
  it("handles DeleteDeliveredAtomic R2 cleanup, alarm pending_r2_deletes retry, and expired-R2 sweep", async () => {
    const cookie = await signInCookie();
    const alice = identityFromSeed(0x11);
    const bob = identityFromSeed(0x22);
    const deliveryToken = new Uint8Array(16).fill(0x33);
    const deliveryHash = await sha256(deliveryToken);
    const cid = new Uint8Array(16).fill(0x44);

    // Push a >64 KiB message so `Store::stage_content` stores the body in real R2 BUCKET.
    const largeContent = new Uint8Array(65 * 1024);
    for (let i = 0; i < largeContent.length; i++) largeContent[i] = i & 0xff;
    const header = utf8("r2-message-header");

    const pushBody = encodePushV2Request({
      sender: alice.publicKey,
      recipient: bob.publicKey,
      header,
      content: largeContent,
      deliveryHash,
      clientMessageId: cid,
    });
    const push1 = await connectPost("/mailbox.v2.MailboxService/PushV2", pushBody, cookie);
    expect(push1.status).toBe(200);
    const seq1 = decodePushV2Response(new Uint8Array(await push1.arrayBuffer()));
    expect(seq1).toBe(1n);

    // Retry with the same client_message_id deduplicates to seq 1 and deletes the duplicate R2 blob.
    const pushRetry = await connectPost("/mailbox.v2.MailboxService/PushV2", pushBody, cookie);
    expect(pushRetry.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await pushRetry.arrayBuffer()))).toBe(1n);

    const msgPrefix = `messages/${hex(alice.publicKey)}/${hex(bob.publicKey)}/`;
    const listedAfterPush = await env.BUCKET.list({ prefix: msgPrefix });
    expect(listedAfterPush.objects.length).toBe(1);
    const stagedObjectKey = listedAfterPush.objects[0].key;

    // FetchSigned reads the full 65 KiB payload back from R2.
    const now = BigInt(Date.now());
    const fetch1 = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        sender: alice.publicKey,
        audience: AUDIENCE,
        timestampMs: now,
      }),
    );
    expect(fetch1.status).toBe(200);
    const envelopes = decodeFetchSignedResponse(new Uint8Array(await fetch1.arrayBuffer()));
    expect(envelopes.length).toBe(1);
    expect(envelopes[0].sequence).toBe(1n);
    expect(envelopes[0].header).toEqual(header);
    expect(envelopes[0].content).toEqual(largeContent);

    // Deliver receipt via FetchSigned.delivered -> triggers DeleteDeliveredAtomic inside Identity DO.
    const fetchDel = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        sender: alice.publicKey,
        audience: AUDIENCE,
        delivered: [deliveryToken],
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(fetchDel.status).toBe(200);
    expect(decodeFetchSignedResponse(new Uint8Array(await fetchDel.arrayBuffer()))).toEqual([]);
    expect(await env.BUCKET.get(stagedObjectKey)).toBeNull();

    // Verify alarm retry of `pending_r2_deletes` AND alarm expiry of R2-backed messages.
    const bobStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(hex(bob.publicKey)));
    const orphanKey = `messages/${hex(alice.publicKey)}/${hex(bob.publicKey)}/queued-retry-blob`;
    await env.BUCKET.put(orphanKey, utf8("queued-for-alarm-retry"));

    // Also push a second >64 KiB message and backdate its `created_at` to force alarm expiry.
    const push2 = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        sender: alice.publicKey,
        recipient: bob.publicKey,
        header: utf8("expiring-r2-header"),
        content: largeContent,
      }),
      cookie,
    );
    expect(push2.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push2.arrayBuffer()))).toBe(2n);

    const listedBeforeAlarm = await env.BUCKET.list({ prefix: msgPrefix });
    expect(listedBeforeAlarm.objects.length).toBe(2); // orphanKey + seq 2 blob
    const expiringKey = listedBeforeAlarm.objects.find((o) => o.key !== orphanKey)!.key;

    await runInDurableObject(bobStub, async (_inst, state) => {
      state.storage.sql.exec(
        "INSERT INTO pending_r2_deletes (object, created_at) VALUES (?, ?)",
        orphanKey,
        Date.now(),
      );
      state.storage.sql.exec("UPDATE messages SET created_at = 0 WHERE sequence = 2");
      await state.storage.setAlarm(Date.now() + 60_000);
    });

    const ran = await runDurableObjectAlarm(bobStub);
    expect(ran).toBe(true);

    // Alarm drained both `pending_r2_deletes` and expired R2-backed `messages` (using json_each/unhex/RETURNING).
    expect(await env.BUCKET.get(orphanKey)).toBeNull();
    expect(await env.BUCKET.get(expiringKey)).toBeNull();

    const remainingRows = await runInDurableObject(bobStub, (_inst, state) => ({
      pendingDeletes: state.storage.sql
        .exec("SELECT count(*) AS count FROM pending_r2_deletes")
        .one().count as number,
      messages: state.storage.sql
        .exec("SELECT count(*) AS count FROM messages")
        .one().count as number,
      recipientBytes: state.storage.sql
        .exec("SELECT total_bytes FROM recipient_stats WHERE only = 0")
        .one().total_bytes as number,
    }));
    expect(remainingRows).toEqual({ pendingDeletes: 0, messages: 0, recipientBytes: 0 });
  });

  it("persists SQLite state across DO eviction, rolls back transactionSync throws, and enforces MAX_SAFE_INTEGER", async () => {
    const cookie = await signInCookie();
    const alice = identityFromSeed(0x31);
    const bob = identityFromSeed(0x32);
    const spk = identityFromSeed(0x33).publicKey;
    const opk1 = identityFromSeed(0x34).publicKey;
    const opk2 = identityFromSeed(0x35).publicKey;
    const now = BigInt(Date.now());

    // Publish a valid classical v2 manifest (seq = 1) + 2 OPKs.
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

    // Duplicate OPK publish is rejected and leaves existing manifest/OPKs intact.
    const dupPub = await connectPost(
      "/handshake.v2.HandshakeService/PublishV2",
      await signClassicalPublishV2Request({
        identity: bob,
        audience: AUDIENCE,
        manifestSeq: 2n,
        generation: 2n,
        issuedAt: now,
        expiresAt: now + 3_600_000n,
        signedPrekey: spk,
        oneTimePrekeys: [opk1, opk1],
        timestampMs: now + 1n,
      }),
      cookie,
    );
    expect(dupPub.status).toBe(400);
    expect(await dupPub.json()).toMatchObject({ code: "invalid_argument" });

    // Push a message, then verify real DO SQLite `transactionSync` throw-rollback semantics.
    const push1 = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        sender: alice.publicKey,
        recipient: bob.publicKey,
        header: utf8("persist-h1"),
        content: utf8("persist-c1"),
      }),
      cookie,
    );
    expect(push1.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push1.arrayBuffer()))).toBe(1n);

    const bobStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(hex(bob.publicKey)));
    const schemaAndRollback = await runInDurableObject(bobStub, (_inst, state) => {
      const schemaVersion = state.storage.sql
        .exec("SELECT schema_version FROM meta WHERE only = 0")
        .one().schema_version as number;
      let threw = false;
      try {
        state.storage.transactionSync(() => {
          state.storage.sql.exec(
            "INSERT INTO pending_r2_deletes (object, created_at) VALUES (?, ?)",
            "should-rollback",
            1234,
          );
          throw new Error("intentional rollback");
        });
      } catch {
        threw = true;
      }
      const rolledBackCount = state.storage.sql
        .exec("SELECT count(*) AS count FROM pending_r2_deletes WHERE object = ?", "should-rollback")
        .one().count as number;
      return { schemaVersion, threw, rolledBackCount };
    });
    expect(schemaAndRollback).toEqual({
      schemaVersion: 4,
      threw: true,
      rolledBackCount: 0,
    });

    // Evict the running Identity DO instance (clearing in-memory `schema_ready`) and confirm
    // persisted SQLite rows survive cold restart and sequences continue monotonically.
    await evictDurableObject(bobStub);

    const fetchAfterEvict = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        sender: alice.publicKey,
        audience: AUDIENCE,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(fetchAfterEvict.status).toBe(200);
    const msgs = decodeFetchSignedResponse(new Uint8Array(await fetchAfterEvict.arrayBuffer()));
    expect(msgs.length).toBe(1);
    expect(msgs[0].sequence).toBe(1n);
    expect(msgs[0].content).toEqual(utf8("persist-c1"));

    const push2 = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        sender: alice.publicKey,
        recipient: bob.publicKey,
        header: utf8("persist-h2"),
        content: utf8("persist-c2"),
      }),
      cookie,
    );
    expect(push2.status).toBe(200);
    expect(decodePushV2Response(new Uint8Array(await push2.arrayBuffer()))).toBe(2n);

    // MAX_SAFE_INTEGER guards:
    // 1. AckInitialMessages rejects IDs > MAX_SAFE_INTEGER with Connect invalid_argument (400).
    const badAck = await connectPost(
      "/handshake.v2.HandshakeService/AckInitialMessages",
      await signAckInitialMessagesRequest({
        recipient: bob,
        audience: AUDIENCE,
        ids: [MAX_SAFE_INTEGER + 1n],
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(badAck.status).toBe(400);
    expect(await badAck.json()).toMatchObject({ code: "invalid_argument" });

    // 2. PublishV2 rejects manifest_seq > MAX_SAFE_INTEGER with Connect invalid_argument (400).
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

    // 3. FetchSigned with `after > MAX_SAFE_INTEGER` short-circuits cleanly to empty list
    //    (never binding an unsafe integer into DO SQLite).
    const highAfter = await connectPost(
      "/mailbox.v2.MailboxService/FetchSigned",
      await signFetchSignedRequest({
        recipient: bob,
        sender: alice.publicKey,
        audience: AUDIENCE,
        after: MAX_SAFE_INTEGER + 1n,
        timestampMs: BigInt(Date.now()),
      }),
    );
    expect(highAfter.status).toBe(200);
    expect(decodeFetchSignedResponse(new Uint8Array(await highAfter.arrayBuffer()))).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // 4. Hibernating WebSocket (/notifications?identity=...)
  // -------------------------------------------------------------------------
  it("supports signed first-frame WebSocket subscribe, ping/pong, live notification, replay 1008, and unexpected-frame 1008", async () => {
    const cookie = await signInCookie();
    const bob = identityFromSeed(0x41);
    const alice = identityFromSeed(0x42);
    const bobHex = hex(bob.publicKey);
    const wsUrl = `${ORIGIN}/notifications?identity=${bobHex}`;

    // Legacy query-param subscription returns 410 Gone + x-e2ee-deprecated: v1.
    const legacyWs = await exports.default.fetch(`${ORIGIN}/notifications?request=legacy`, {
      headers: { Upgrade: "websocket", Cookie: cookie },
    });
    expect(legacyWs.status).toBe(410);
    expect(legacyWs.headers.get("x-e2ee-deprecated")).toBe("v1");

    // Non-WebSocket request returns 426.
    const noUpgrade = await exports.default.fetch(wsUrl, {
      headers: { Cookie: cookie },
    });
    expect(noUpgrade.status).toBe(426);

    // Unauthenticated upgrade is rejected with 403 when PASSWORD is configured.
    const unauthedWs = await exports.default.fetch(wsUrl, {
      headers: { Upgrade: "websocket" },
    });
    expect(unauthedWs.status).toBe(403);

    // Cross-origin upgrade is rejected with 403 (CSWSH defense).
    const crossOriginWs = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: "https://evil.example",
        Cookie: cookie,
      },
    });
    expect(crossOriginWs.status).toBe(403);
    expect(await crossOriginWs.text()).toBe("cross-origin WebSocket refused");

    // Open a valid WebSocket and authenticate with a signed first-frame SubscribeRequest (binary).
    const upgrade1 = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
      },
    });
    expect(upgrade1.status).toBe(101);
    const ws1 = upgrade1.webSocket;
    expect(ws1).not.toBeNull();
    ws1!.accept();

    const subTimestamp = BigInt(Date.now());
    const signedSubscribe = await signSubscribeRequestV2(bob, AUDIENCE, subTimestamp);
    const okPromise = waitForMessage(ws1!);
    ws1!.send(signedSubscribe);
    expect(await okPromise).toBe("ok");

    // Auto-response answers "ping" with "pong" during hibernation.
    const pongPromise = waitForMessage(ws1!);
    ws1!.send("ping");
    expect(await pongPromise).toBe("pong");

    // Pushing a message to Bob wakes the DO and pushes a binary Notification over the socket.
    const notifPromise = waitForMessage(ws1!);
    const pushRes = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        sender: alice.publicKey,
        recipient: bob.publicKey,
        header: utf8("ws-h"),
        content: utf8("ws-c"),
      }),
      cookie,
    );
    expect(pushRes.status).toBe(200);
    const notifBytes = await binaryFrameBytes(await notifPromise);
    expect(decodeNotification(notifBytes).messageFrom).toEqual(alice.publicKey);

    // Hibernate the Identity DO while keeping the authenticated WebSocket open, then verify
    // ping/pong auto-response and notification delivery survive hibernation.
    const bobStub = env.IDENTITIES.get(env.IDENTITIES.idFromName(bobHex));
    await evictDurableObject(bobStub, { webSockets: "hibernate" });
    const hibernatedPong = waitForMessage(ws1!);
    ws1!.send("ping");
    expect(await hibernatedPong).toBe("pong");

    const hibernatedNotif = waitForMessage(ws1!);
    const pushAfterHibernate = await connectPost(
      "/mailbox.v2.MailboxService/PushV2",
      encodePushV2Request({
        sender: alice.publicKey,
        recipient: bob.publicKey,
        header: utf8("ws-h2"),
        content: utf8("ws-c2"),
      }),
      cookie,
    );
    expect(pushAfterHibernate.status).toBe(200);
    expect(decodeNotification(await binaryFrameBytes(await hibernatedNotif)).messageFrom).toEqual(
      alice.publicKey,
    );

    // Replaying the exact same signed SubscribeRequest (same identity, audience, timestamp) on a
    // second connection MUST close with 1008 ("replayed subscription"), NOT 4010!
    const upgradeReplay = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
      },
    });
    expect(upgradeReplay.status).toBe(101);
    const wsReplay = upgradeReplay.webSocket!;
    wsReplay.accept();

    const replayClosePromise = waitForClose(wsReplay);
    wsReplay.send(signedSubscribe);
    const replayClose = await replayClosePromise;
    expect(replayClose.code).toBe(1008);
    expect(replayClose.code).not.toBe(4010);
    expect(replayClose.reason).toBe("replayed subscription");

    // Sending an unexpected post-auth frame closes the authenticated socket with 1008.
    const unexpectedClosePromise = waitForClose(ws1!);
    ws1!.send("unexpected-post-auth-frame");
    const unexpectedClose = await unexpectedClosePromise;
    expect(unexpectedClose.code).toBe(1008);
    expect(unexpectedClose.reason).toBe("unexpected message");

    // Base64url text first-frame subscribe also succeeds with a fresh timestamp.
    const upgradeText = await exports.default.fetch(wsUrl, {
      headers: {
        Upgrade: "websocket",
        Origin: ORIGIN,
        Cookie: cookie,
      },
    });
    expect(upgradeText.status).toBe(101);
    const wsText = upgradeText.webSocket!;
    wsText.accept();
    const textOk = waitForMessage(wsText);
    const freshSub = await signSubscribeRequestV2(bob, AUDIENCE, subTimestamp + 1n);
    wsText.send(base64UrlEncode(freshSub));
    expect(await textOk).toBe("ok");
    wsText.close(1000, "done");
  });

  // -------------------------------------------------------------------------
  // 5. PQ_ENABLED="false" runtime gating
  // -------------------------------------------------------------------------
  it('gates GetManifest and advertises x-e2ee-pq: 0 when PQ_ENABLED="false"', async () => {
    const ctx = createExecutionContext();
    const pqOffEnv = Object.assign(Object.create(Object.getPrototypeOf(env)), env, {
      PQ_ENABLED: "false",
    });
    const worker = new WorkerEntrypoint(ctx, pqOffEnv);

    // GetServerInfo reports pq_enabled=false, empty supported_suites, and x-e2ee-pq: 0.
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
    expect(info.legacyV1Enabled).toBe(false);
    expect(info.allowUnsignedFetch).toBe(false);

    // GetManifest is completely disabled when PQ_ENABLED="false" (HTTP 501 Connect unimplemented).
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
    expect(manifestRes.status).toBe(501);
    expect(manifestRes.headers.get("x-e2ee-pq")).toBe("0");
    expect(await manifestRes.json()).toEqual({
      code: "unimplemented",
      message: "post-quantum routes are disabled",
    });

    await waitOnExecutionContext(ctx);
  });
});
