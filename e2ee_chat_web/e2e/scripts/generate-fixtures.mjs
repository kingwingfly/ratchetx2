#!/usr/bin/env node
// Generates small, deterministic binary fixtures committed under `e2ee_chat_web/e2e/fixtures/`.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Build a valid N-page PDF 1.4 with simple vector rectangles (fast for hayro). */
function buildPdf(pageCount) {
  const objects = [];
  // 1: Catalog, 2: Pages
  const pageRefs = [];
  for (let i = 0; i < pageCount; i++) {
    pageRefs.push(`${3 + i * 2} 0 R`);
  }
  objects.push(`1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`);
  objects.push(
    `2 0 obj\n<< /Type /Pages /Kids [${pageRefs.join(' ')}] /Count ${pageCount} >>\nendobj\n`,
  );
  for (let i = 0; i < pageCount; i++) {
    const pageObjId = 3 + i * 2;
    const contentObjId = pageObjId + 1;
    // Distinct color tint per page so every page renders non-empty pixels.
    const r = (0.15 + ((i * 5) % 10) * 0.07).toFixed(2);
    const g = (0.35 + ((i * 3) % 10) * 0.05).toFixed(2);
    const b = (0.55 + ((i * 7) % 10) * 0.04).toFixed(2);
    const stream = `q ${r} ${g} ${b} rg 72 72 468 648 re f Q\n`;
    objects.push(
      `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${contentObjId} 0 R >>\nendobj\n`,
    );
    objects.push(
      `${contentObjId} 0 obj\n<< /Length ${Buffer.byteLength(stream, 'ascii')} >>\nstream\n${stream}endstream\nendobj\n`,
    );
  }

  let out = '%PDF-1.4\n';
  const offsets = [0];
  for (const obj of objects) {
    offsets.push(Buffer.byteLength(out, 'ascii'));
    out += obj;
  }
  const xrefPos = Buffer.byteLength(out, 'ascii');
  out += `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i++) {
    out += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  return Buffer.from(out, 'ascii');
}

/** Build a tiny valid 4x4 RGBA PNG. */
function buildPng() {
  const width = 4;
  const height = 4;
  const raw = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    const row = y * (1 + width * 4);
    raw[row] = 0; // filter None
    for (let x = 0; x < width; x++) {
      const p = row + 1 + x * 4;
      raw[p] = 40 + x * 40;
      raw[p + 1] = 160;
      raw[p + 2] = 90 + y * 30;
      raw[p + 3] = 255;
    }
  }
  const chunk = (type, data) => {
    const typeBuf = Buffer.from(type, 'ascii');
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Build a valid playable PCM WAV with RIFF LIST/INFO tags readable by `lofty`. */
function buildWavWithTags() {
  const sampleRate = 8000;
  const numSamples = 2000; // 0.25 s
  const pcm = Buffer.alloc(numSamples * 2);
  for (let i = 0; i < numSamples; i++) {
    const sample = Math.round(Math.sin((2 * Math.PI * 440 * i) / sampleRate) * 6000);
    pcm.writeInt16LE(sample, i * 2);
  }
  const riffChunk = (id, payload) => {
    const hdr = Buffer.alloc(8);
    hdr.write(id, 0, 4, 'ascii');
    hdr.writeUInt32LE(payload.length, 4);
    const pad = payload.length % 2 === 1 ? Buffer.from([0]) : Buffer.alloc(0);
    return Buffer.concat([hdr, payload, pad]);
  };
  const fmt = Buffer.alloc(16);
  fmt.writeUInt16LE(1, 0); // PCM
  fmt.writeUInt16LE(1, 2); // mono
  fmt.writeUInt32LE(sampleRate, 4);
  fmt.writeUInt32LE(sampleRate * 2, 8);
  fmt.writeUInt16LE(2, 12);
  fmt.writeUInt16LE(16, 14);

  const infoField = (tag, text) => riffChunk(tag, Buffer.from(`${text}\0`, 'utf8'));
  const infoBody = Buffer.concat([
    Buffer.from('INFO', 'ascii'),
    infoField('INAM', 'Fixture Tone'),
    infoField('IART', 'E2EE Test'),
    infoField('IPRD', 'Smoke Suite'),
    infoField('ICRD', '2026'),
  ]);

  const body = Buffer.concat([
    Buffer.from('WAVE', 'ascii'),
    riffChunk('fmt ', fmt),
    riffChunk('data', pcm),
    riffChunk('LIST', infoBody),
  ]);
  const header = Buffer.alloc(8);
  header.write('RIFF', 0, 4, 'ascii');
  header.writeUInt32LE(body.length, 4);
  return Buffer.concat([header, body]);
}

/** Build a corrupt WAV that passes `RIFF....WAVE` sniffing yet triggers HTMLAudioElement error. */
function buildCorruptWav() {
  const body = Buffer.concat([
    Buffer.from('WAVE', 'ascii'),
    Buffer.from('fmt ', 'ascii'),
    Buffer.from([0x10, 0x00, 0x00, 0x00]),
    // Invalid format tag (0xFFFF), 0 channels, 0 sample rate.
    Buffer.from([
      0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00,
    ]),
    Buffer.from('data', 'ascii'),
    Buffer.from([0x10, 0x00, 0x00, 0x00]),
    Buffer.alloc(16, 0xde),
  ]);
  const header = Buffer.alloc(8);
  header.write('RIFF', 0, 4, 'ascii');
  header.writeUInt32LE(body.length, 4);
  return Buffer.concat([header, body]);
}

/** Build a minimal stored ZIP archive with a single file `hello.txt`. */
function buildZip() {
  const name = Buffer.from('hello.txt', 'utf8');
  const data = Buffer.from('hello from e2ee zip fixture\n', 'utf8');
  const crc = crc32(data);

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8); // stored
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);

  const localEntry = Buffer.concat([local, name, data]);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt32LE(0, 42); // local header offset

  const centralEntry = Buffer.concat([central, name]);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralEntry.length, 12);
  eocd.writeUInt32LE(localEntry.length, 16);

  return Buffer.concat([localEntry, centralEntry, eocd]);
}

fs.mkdirSync(FIXTURES_DIR, { recursive: true });
fs.writeFileSync(path.join(FIXTURES_DIR, 'sample-15pages.pdf'), buildPdf(15));
fs.writeFileSync(path.join(FIXTURES_DIR, 'pixel.png'), buildPng());
fs.writeFileSync(path.join(FIXTURES_DIR, 'sample.wav'), buildWavWithTags());
fs.writeFileSync(path.join(FIXTURES_DIR, 'corrupt.wav'), buildCorruptWav());
fs.writeFileSync(path.join(FIXTURES_DIR, 'sample.zip'), buildZip());
console.log('Generated deterministic fixtures in', FIXTURES_DIR);
