/// <reference types="@cloudflare/vitest-plugin/types" />

declare namespace Cloudflare {
  interface Env {
    BUCKET: R2Bucket;
    IDENTITIES: DurableObjectNamespace;
    ATTACHMENTS: DurableObjectNamespace;
    RETENTION_DAYS: string;
    FILE_RETENTION_DAYS: string;
    SESSION_DAYS: string;
    PQ_ENABLED: string;
    PASSWORD: string;
    AUTH_KEY: string;
    CONFORMANCE_TOKEN: string;
  }
}
