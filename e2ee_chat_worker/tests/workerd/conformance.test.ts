import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { signInCookie } from "./helpers";

const CONFORMANCE_URL = "https://e2ee-chat.test/conformance";

describe("POST /conformance", () => {
  it("rejects missing, invalid tokens, and sign-in cookie alone with 403", async () => {
    const missing = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
    });
    expect(missing.status).toBe(403);
    expect(await missing.text()).toBe("unauthorized");
    expect(missing.headers.get("x-content-type-options")).toBe("nosniff");
    expect(missing.headers.get("cache-control")).toBe("no-store");
    expect(missing.headers.get("referrer-policy")).toBe("no-referrer");

    // Sign-in cookie alone MUST NOT bypass CONFORMANCE_TOKEN.
    const cookie = await signInCookie(env.PASSWORD, "198.51.100.90");
    const cookieOnly = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
      headers: {
        Cookie: cookie,
      },
    });
    expect(cookieOnly.status).toBe(403);
    expect(await cookieOnly.text()).toBe("unauthorized");

    const wrongBearer = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
      headers: {
        Authorization: "Bearer wrong-conformance-token",
      },
    });
    expect(wrongBearer.status).toBe(403);
    expect(await wrongBearer.text()).toBe("unauthorized");

    const wrongScheme = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
      headers: {
        Authorization: `Basic ${env.CONFORMANCE_TOKEN}`,
      },
    });
    expect(wrongScheme.status).toBe(403);
    expect(await wrongScheme.text()).toBe("unauthorized");

    const wrongHeader = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
      headers: {
        "X-Conformance-Token": "wrong-conformance-token",
      },
    });
    expect(wrongHeader.status).toBe(403);
    expect(await wrongHeader.text()).toBe("unauthorized");
  });

  it("runs attachment_store, pq_handshake_store, and idempotent_mailbox_store conformance suites with Bearer token", async () => {
    const response = await exports.default.fetch(CONFORMANCE_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.CONFORMANCE_TOKEN}`,
      },
    });
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("the storage conformance suites passed");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });
});
