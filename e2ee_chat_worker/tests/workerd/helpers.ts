import { env, exports } from "cloudflare:workers";

export const ORIGIN = "https://e2ee-chat.test";
export const AUDIENCE = "e2ee-chat.test";
export const MAX_SAFE_INTEGER = 9007199254740991n;

// ---------------------------------------------------------------------------
// Byte & encoding utilities
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function decodeUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

async function sha512(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", data));
}

function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
}

function u32le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

function u64be(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

// ---------------------------------------------------------------------------
// Minimal zero-dependency protobuf binary codec
// ---------------------------------------------------------------------------

function encodeVarint(value: bigint): Uint8Array {
  if (value < 0n) throw new RangeError("negative varint");
  const bytes: number[] = [];
  let v = value;
  while (v >= 0x80n) {
    bytes.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  bytes.push(Number(v));
  return Uint8Array.from(bytes);
}

function encodeTag(fieldNumber: number, wireType: 0 | 2): Uint8Array {
  return encodeVarint(BigInt((fieldNumber << 3) | wireType));
}

export function pbVarint(fieldNumber: number, value: bigint | number | boolean): Uint8Array {
  const v = typeof value === "boolean" ? (value ? 1n : 0n) : BigInt(value);
  if (v === 0n) return new Uint8Array(0);
  return concatBytes(encodeTag(fieldNumber, 0), encodeVarint(v));
}

export function pbBytes(fieldNumber: number, bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) return new Uint8Array(0);
  return concatBytes(encodeTag(fieldNumber, 2), encodeVarint(BigInt(bytes.length)), bytes);
}

export function pbBytesAlways(fieldNumber: number, bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeTag(fieldNumber, 2), encodeVarint(BigInt(bytes.length)), bytes);
}

export function pbString(fieldNumber: number, value: string): Uint8Array {
  if (value.length === 0) return new Uint8Array(0);
  return pbBytes(fieldNumber, utf8(value));
}

interface PbField {
  fieldNumber: number;
  wireType: number;
  varint?: bigint;
  bytes?: Uint8Array;
}

function readVarint(buf: Uint8Array, pos: number): { value: bigint; next: number } {
  let value = 0n;
  let shift = 0n;
  let i = pos;
  while (i < buf.length) {
    const b = buf[i++];
    value |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value, next: i };
    shift += 7n;
  }
  throw new Error("truncated protobuf varint");
}

export function decodePbFields(buf: Uint8Array): PbField[] {
  const fields: PbField[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const tag = readVarint(buf, pos);
    pos = tag.next;
    const fieldNumber = Number(tag.value >> 3n);
    const wireType = Number(tag.value & 7n);
    if (wireType === 0) {
      const v = readVarint(buf, pos);
      pos = v.next;
      fields.push({ fieldNumber, wireType, varint: v.value });
    } else if (wireType === 2) {
      const len = readVarint(buf, pos);
      pos = len.next;
      const end = pos + Number(len.value);
      fields.push({ fieldNumber, wireType, bytes: buf.subarray(pos, end) });
      pos = end;
    } else if (wireType === 1) {
      pos += 8;
    } else if (wireType === 5) {
      pos += 4;
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
  }
  return fields;
}

function decodePackedVarints(bytes: Uint8Array): bigint[] {
  const out: bigint[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    const v = readVarint(bytes, pos);
    out.push(v.value);
    pos = v.next;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Pure-BigInt Curve25519 / Ed25519 / XEdDSA signer (matches `xeddsa/src/lib.rs`)
// ---------------------------------------------------------------------------

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a: bigint, m: bigint): bigint {
  return modPow(a, m - 2n, m);
}

const D = mod(-121665n * modInv(121666n, P), P);
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const BY = mod(4n * modInv(5n, P), P);

type ExtPoint = readonly [bigint, bigint, bigint, bigint];
const ID_POINT: ExtPoint = [0n, 1n, 1n, 0n];
const BASE_POINT: ExtPoint = [BX, BY, 1n, mod(BX * BY, P)];

function pointAdd(p1: ExtPoint, p2: ExtPoint): ExtPoint {
  const [X1, Y1, Z1, T1] = p1;
  const [X2, Y2, Z2, T2] = p2;
  const A = mod((Y1 - X1) * (Y2 - X2), P);
  const B = mod((Y1 + X1) * (Y2 + X2), P);
  const C = mod(T1 * 2n * D * T2, P);
  const D_ = mod(Z1 * 2n * Z2, P);
  const E = mod(B - A, P);
  const F = mod(D_ - C, P);
  const G = mod(D_ + C, P);
  const H = mod(B + A, P);
  return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
}

function scalarMulBase(scalar: bigint): ExtPoint {
  let acc: ExtPoint = ID_POINT;
  let base: ExtPoint = BASE_POINT;
  let k = mod(scalar, L);
  while (k > 0n) {
    if (k & 1n) acc = pointAdd(acc, base);
    base = pointAdd(base, base);
    k >>= 1n;
  }
  return acc;
}

function bytesToBigIntLe(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i]);
  }
  return out;
}

function encodeLe32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function toAffine(point: ExtPoint): { x: bigint; y: bigint } {
  const [X, Y, Z] = point;
  const zInv = modInv(Z, P);
  return { x: mod(X * zInv, P), y: mod(Y * zInv, P) };
}

function compressEdwards(point: ExtPoint): Uint8Array {
  const { x, y } = toAffine(point);
  const out = encodeLe32(y);
  if ((x & 1n) === 1n) out[31] |= 0x80;
  return out;
}

const HASH1_PREFIX = new Uint8Array(32).fill(0xff);
HASH1_PREFIX[0] = 0xfe;

export interface TestIdentity {
  /** Normalized sign-0 Ed25519 private scalar bytes (little-endian). */
  scalar: bigint;
  scalarBytes: Uint8Array;
  /** Compressed sign-0 Ed25519 verifying key bytes (32 bytes). */
  edwardsPubBytes: Uint8Array;
  /** Canonical Curve25519 Montgomery public key bytes (32 bytes). */
  publicKey: Uint8Array;
}

export function identityFromSeed(seedByte: number): TestIdentity {
  const raw = new Uint8Array(32).fill(seedByte);
  let k = mod(bytesToBigIntLe(raw), L);
  if (k === 0n) k = 1n;
  const { x, y } = toAffine(scalarMulBase(k));
  const a = (x & 1n) === 1n ? L - k : k;
  const edwardsPubBytes = encodeLe32(y);
  const u = mod((1n + y) * modInv(mod(1n - y, P), P), P);
  return {
    scalar: a,
    scalarBytes: encodeLe32(a),
    edwardsPubBytes,
    publicKey: encodeLe32(u),
  };
}

export async function xeddsaSign(
  identity: TestIdentity,
  message: Uint8Array,
  random64?: Uint8Array,
): Promise<Uint8Array> {
  const z = random64 ?? crypto.getRandomValues(new Uint8Array(64));
  const rDigest = await sha512(concatBytes(HASH1_PREFIX, identity.scalarBytes, message, z));
  const r = mod(bytesToBigIntLe(rDigest), L);
  if (r === 0n) throw new Error("negligible zero nonce");
  const capR = compressEdwards(scalarMulBase(r));
  const hDigest = await sha512(concatBytes(capR, identity.edwardsPubBytes, message));
  const h = mod(bytesToBigIntLe(hDigest), L);
  const s = mod(r + h * identity.scalar, L);
  return concatBytes(capR, encodeLe32(s));
}

// ---------------------------------------------------------------------------
// Protocol message encoders / signers / decoders
// ---------------------------------------------------------------------------

export async function signSubscribeRequestV2(
  identity: TestIdentity,
  audience: string,
  timestampMs: bigint,
): Promise<Uint8Array> {
  const audBytes = utf8(audience);
  const transcript = concatBytes(
    utf8("notify.v2/subscribe"),
    u32le(audBytes.length),
    audBytes,
    identity.publicKey,
    u64le(timestampMs),
  );
  const signature = await xeddsaSign(identity, transcript);
  return concatBytes(
    pbBytes(1, identity.publicKey),
    pbVarint(2, timestampMs),
    pbBytes(3, signature),
    pbString(4, audience),
  );
}

export function encodePushV2Request(params: {
  sender: Uint8Array;
  recipient: Uint8Array;
  header: Uint8Array;
  content: Uint8Array;
  deliveryHash?: Uint8Array;
  clientMessageId?: Uint8Array;
}): Uint8Array {
  const encryptedMessage = concatBytes(pbBytes(1, params.header), pbBytes(2, params.content));
  return concatBytes(
    pbBytes(1, params.sender),
    pbBytes(2, params.recipient),
    pbBytesAlways(3, encryptedMessage),
    params.deliveryHash ? pbBytes(5, params.deliveryHash) : new Uint8Array(0),
    params.clientMessageId ? pbBytes(6, params.clientMessageId) : new Uint8Array(0),
  );
}

export function decodePushV2Response(bytes: Uint8Array): bigint {
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.varint !== undefined) {
      return field.varint;
    }
  }
  return 0n;
}

export async function signFetchSignedRequest(params: {
  recipient: TestIdentity;
  sender: Uint8Array;
  audience: string;
  after?: bigint;
  limit?: number;
  maxSize?: number;
  delivered?: Uint8Array[];
  timestampMs: bigint;
}): Promise<Uint8Array> {
  const after = params.after ?? 0n;
  const limit = params.limit ?? 10;
  const maxSize = params.maxSize ?? 0;
  const delivered = params.delivered ?? [];
  const audBytes = utf8(params.audience);
  const transcript = concatBytes(
    utf8("ratchetx2.fetch.v2\0"),
    u32be(audBytes.length),
    audBytes,
    params.sender,
    params.recipient.publicKey,
    u64be(after),
    u32be(limit),
    u32be(maxSize),
    u32be(delivered.length),
    ...delivered,
    u64be(params.timestampMs),
  );
  const signature = await xeddsaSign(params.recipient, transcript);
  return concatBytes(
    pbString(1, params.audience),
    pbBytes(2, params.sender),
    pbBytes(3, params.recipient.publicKey),
    pbVarint(4, after),
    pbVarint(5, limit),
    pbVarint(6, maxSize),
    ...delivered.map((token) => pbBytes(7, token)),
    pbVarint(8, params.timestampMs),
    pbBytes(9, signature),
  );
}

export interface DecodedEnvelopeV2 {
  sequence: bigint;
  header?: Uint8Array;
  content?: Uint8Array;
}

export function decodeFetchSignedResponse(bytes: Uint8Array): DecodedEnvelopeV2[] {
  const out: DecodedEnvelopeV2[] = [];
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.bytes) {
      let sequence = 0n;
      let header: Uint8Array | undefined;
      let content: Uint8Array | undefined;
      for (const ef of decodePbFields(field.bytes)) {
        if (ef.fieldNumber === 1 && ef.varint !== undefined) sequence = ef.varint;
        if (ef.fieldNumber === 2 && ef.bytes) {
          for (const mf of decodePbFields(ef.bytes)) {
            if (mf.fieldNumber === 1 && mf.bytes) header = mf.bytes;
            if (mf.fieldNumber === 2 && mf.bytes) content = mf.bytes;
          }
        }
      }
      out.push({ sequence, header, content });
    }
  }
  return out;
}

export function encodeStartUploadRequest(chunks: number, deleteHash: Uint8Array): Uint8Array {
  return concatBytes(pbVarint(2, chunks), pbBytes(6, deleteHash));
}

export function decodeStartUploadResponse(bytes: Uint8Array): {
  id: Uint8Array;
  uploadToken: Uint8Array;
  expires: bigint;
} {
  let id = new Uint8Array(0);
  let uploadToken = new Uint8Array(0);
  let expires = 0n;
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.bytes) id = field.bytes;
    if (field.fieldNumber === 2 && field.bytes) uploadToken = field.bytes;
    if (field.fieldNumber === 3 && field.varint !== undefined) expires = field.varint;
  }
  return { id, uploadToken, expires };
}

export function encodePutChunkRequest(
  id: Uint8Array,
  uploadToken: Uint8Array,
  index: number,
  data: Uint8Array,
): Uint8Array {
  return concatBytes(
    pbBytes(1, id),
    pbBytes(2, uploadToken),
    pbVarint(3, index),
    pbBytes(4, data),
  );
}

export function encodeGetChunkRequest(id: Uint8Array, index: number): Uint8Array {
  return concatBytes(pbBytes(1, id), pbVarint(2, index));
}

export function decodeGetChunkResponse(bytes: Uint8Array): {
  data: Uint8Array;
  uploaded: boolean;
} {
  let data = new Uint8Array(0);
  let uploaded = false;
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.bytes) data = field.bytes;
    if (field.fieldNumber === 2 && field.varint !== undefined) uploaded = field.varint !== 0n;
  }
  return { data, uploaded };
}

export function encodeDeleteAttachmentRequest(id: Uint8Array, token: Uint8Array): Uint8Array {
  return concatBytes(pbBytes(1, id), pbBytes(2, token));
}

export async function signAckInitialMessagesRequest(params: {
  recipient: TestIdentity;
  audience: string;
  ids: bigint[];
  timestampMs: bigint;
}): Promise<Uint8Array> {
  const audBytes = utf8(params.audience);
  const transcript = concatBytes(
    utf8("ratchetx2.ack-initial.v2\0"),
    u32be(audBytes.length),
    audBytes,
    params.recipient.publicKey,
    u32be(params.ids.length),
    ...params.ids.map(u64be),
    u64be(params.timestampMs),
  );
  const signature = await xeddsaSign(params.recipient, transcript);
  return concatBytes(
    pbString(1, params.audience),
    pbBytes(2, params.recipient.publicKey),
    ...params.ids.map((id) => pbVarint(3, id)),
    pbVarint(4, params.timestampMs),
    pbBytes(5, signature),
  );
}

export async function signClassicalPublishV2Request(params: {
  identity: TestIdentity;
  audience: string;
  manifestSeq: bigint;
  generation: bigint;
  issuedAt: bigint;
  expiresAt: bigint;
  signedPrekey: Uint8Array;
  oneTimePrekeys: Uint8Array[];
  timestampMs: bigint;
}): Promise<Uint8Array> {
  const audBytes = utf8(params.audience);
  const manifestInput = concatBytes(
    utf8("ratchetx2.manifest.v2\0"),
    u32be(audBytes.length),
    audBytes,
    params.identity.publicKey,
    u64be(params.manifestSeq),
    u64be(params.generation),
    u64be(params.issuedAt),
    u64be(params.expiresAt),
    new Uint8Array([0, 0, 0]), // pq_enabled=false, strict_pq=false, pq_ratchet_supported=false
    u32be(0), // offered_suites count
    params.signedPrekey,
    u32be(0), // pq_last_resort count
  );
  const manifestSig = await xeddsaSign(params.identity, manifestInput);
  const manifestDigest = await sha256(manifestInput);
  const spkSig = await xeddsaSign(params.identity, params.signedPrekey);

  const publishInput = concatBytes(
    utf8("ratchetx2.publish.v2\0"),
    manifestDigest,
    new Uint8Array([1]),
    spkSig,
    u32be(params.oneTimePrekeys.length),
    ...params.oneTimePrekeys,
    u32be(0), // pq_last_resort count
    u32be(0), // pq_one_time_prekeys count
    u64be(params.timestampMs),
  );
  const publishSig = await xeddsaSign(params.identity, publishInput);

  const manifestProto = concatBytes(
    pbString(1, params.audience),
    pbBytes(2, params.identity.publicKey),
    pbVarint(3, params.manifestSeq),
    pbVarint(4, params.generation),
    pbVarint(5, params.issuedAt),
    pbVarint(6, params.expiresAt),
    pbBytes(11, params.signedPrekey),
    pbBytes(13, manifestSig),
  );

  return concatBytes(
    pbBytes(1, manifestProto),
    pbBytes(2, spkSig),
    ...params.oneTimePrekeys.map((k) => pbBytes(3, k)),
    pbVarint(6, params.timestampMs),
    pbBytes(7, publishSig),
  );
}

export function decodeGetServerInfoResponse(bytes: Uint8Array): {
  pqEnabled: boolean;
  supportedSuites: number[];
  pqRatchetSupported: boolean;
  serverId: string;
  legacyV1Enabled: boolean;
  allowUnsignedFetch: boolean;
} {
  let pqEnabled = false;
  const supportedSuites: number[] = [];
  let pqRatchetSupported = false;
  let serverId = "";
  let legacyV1Enabled = false;
  let allowUnsignedFetch = false;
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.varint !== undefined) pqEnabled = field.varint !== 0n;
    if (field.fieldNumber === 2) {
      if (field.wireType === 0 && field.varint !== undefined) {
        supportedSuites.push(Number(field.varint));
      } else if (field.wireType === 2 && field.bytes) {
        for (const v of decodePackedVarints(field.bytes)) supportedSuites.push(Number(v));
      }
    }
    if (field.fieldNumber === 3 && field.varint !== undefined) {
      pqRatchetSupported = field.varint !== 0n;
    }
    if (field.fieldNumber === 4 && field.bytes) serverId = decodeUtf8(field.bytes);
    if (field.fieldNumber === 5 && field.varint !== undefined) {
      legacyV1Enabled = field.varint !== 0n;
    }
    if (field.fieldNumber === 6 && field.varint !== undefined) {
      allowUnsignedFetch = field.varint !== 0n;
    }
  }
  return {
    pqEnabled,
    supportedSuites,
    pqRatchetSupported,
    serverId,
    legacyV1Enabled,
    allowUnsignedFetch,
  };
}

export function decodeNotification(bytes: Uint8Array): {
  messageFrom?: Uint8Array;
  initialMessage?: boolean;
} {
  for (const field of decodePbFields(bytes)) {
    if (field.fieldNumber === 1 && field.bytes) return { messageFrom: field.bytes };
    if (field.fieldNumber === 2 && field.varint !== undefined) {
      return { initialMessage: field.varint !== 0n };
    }
  }
  return {};
}

// ---------------------------------------------------------------------------
// HTTP & Connect helpers against the Worker under test
// ---------------------------------------------------------------------------

export async function signInCookie(password = env.PASSWORD): Promise<string> {
  const res = await exports.default.fetch(`${ORIGIN}/auth/password`, {
    method: "POST",
    headers: {
      "Sec-Fetch-Site": "same-origin",
      "CF-Connecting-IP": "198.51.100.1",
    },
    body: password,
  });
  if (res.status !== 200) {
    throw new Error(`sign-in failed with ${res.status}: ${await res.text()}`);
  }
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) throw new Error("missing set-cookie header");
  return setCookie.split(";")[0];
}

export async function connectPost(
  path: string,
  body: Uint8Array,
  cookie?: string,
  fetcher: { fetch: typeof exports.default.fetch } = exports.default,
): Promise<Response> {
  const headers = new Headers({
    "content-type": "application/proto",
    "connect-protocol-version": "1",
  });
  if (cookie) headers.set("cookie", cookie);
  return fetcher.fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers,
    body,
  });
}
