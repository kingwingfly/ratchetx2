/// <reference types="@cloudflare/vitest-plugin/types" />

declare namespace Cloudflare {
  interface Env {
    BUCKET: R2Bucket;
    IDENTITIES: DurableObjectNamespace;
    ATTACHMENTS: DurableObjectNamespace;
    AUTH_RATE_LIMITER: RateLimit;
    WS_RATE_LIMITER: RateLimit;
    HANDSHAKE_RATE_LIMITER: RateLimit;
    UPLOAD_RATE_LIMITER: RateLimit;
    RETENTION_DAYS: string;
    FILE_RETENTION_DAYS: string;
    SESSION_DAYS: string;
    PQ_ENABLED: string;
    PASSWORD: string;
    AUTH_KEY: string;
    CONFORMANCE_TOKEN: string;
  }
}
