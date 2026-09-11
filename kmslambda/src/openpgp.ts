import crypto from 'crypto';

/**
 * Minimal OpenPGP v4 ECDSA transferable public key, aligned with kmspgp Pgp.java.
 * Packet layout must stay in sync with that encoder so fingerprints match.
 */

const ECDSA = 19;
const SHA256 = 8;
const SIG_CERTIFICATION = 0x10;
const PACKET_PUBLIC_KEY = 6;
const PACKET_USER_ID = 13;
const PACKET_SIGNATURE = 2;
const SUB_SIG_CREATION = 2;
const SUB_KEY_FLAGS = 27;
const SUB_SIGNER_USER_ID = 28;
const SUB_ISSUER_FINGERPRINT = 33;
const SECP256R1_OID = Buffer.from('2A8648CE3D030107', 'hex');

export interface OpenPgpPublicKey {
  armored: string;
  fingerprint: string;
  userId: string;
  keyCreationDate: string;
}

export async function exportCertifiedPublicKey(opts: {
  publicKeyPem: string;
  createdAt: Date;
  userId: string;
  signDigest: (digest: Buffer) => Promise<Buffer>;
}): Promise<OpenPgpPublicKey> {
  const createdAtSeconds = Math.floor(opts.createdAt.getTime() / 1000);
  const point = uncompressedPoint(opts.publicKeyPem);
  const keyBody = publicKeyPacketBody(createdAtSeconds, point);
  const fingerprint = keyFingerprint(keyBody);
  const userIdBytes = Buffer.from(opts.userId, 'utf8');

  const hashedSubs = Buffer.concat([
    subpacket(SUB_SIG_CREATION, uint32(createdAtSeconds)),
    subpacket(SUB_SIGNER_USER_ID, userIdBytes),
    subpacket(SUB_ISSUER_FINGERPRINT, Buffer.concat([Buffer.from([4]), fingerprint])),
    subpacket(SUB_KEY_FLAGS, Buffer.from([0x03])),
  ]);

  const hashedPrefix = Buffer.concat([
    Buffer.from([4, SIG_CERTIFICATION, ECDSA, SHA256]),
    uint16(hashedSubs.length),
    hashedSubs,
  ]);

  const hash = crypto.createHash('sha256');
  hash.update(Buffer.from([0x99]));
  hash.update(uint16(keyBody.length));
  hash.update(keyBody);
  hash.update(Buffer.from([0xb4]));
  hash.update(uint32(userIdBytes.length));
  hash.update(userIdBytes);
  hash.update(hashedPrefix);
  hash.update(Buffer.from([0x04, 0xff]));
  hash.update(uint32(hashedPrefix.length));
  const digest = hash.digest();

  const der = await opts.signDigest(digest);
  const { r, s } = parseEcdsaDer(der);
  const unhashed = Buffer.alloc(0);
  const sigBody = Buffer.concat([
    hashedPrefix,
    uint16(unhashed.length),
    unhashed,
    digest.subarray(0, 2),
    mpiFromBytes(r),
    mpiFromBytes(s),
  ]);

  const binary = Buffer.concat([
    oldPacket(PACKET_PUBLIC_KEY, keyBody),
    oldPacket(PACKET_USER_ID, userIdBytes),
    oldPacket(PACKET_SIGNATURE, sigBody),
  ]);

  return {
    armored: armor('PGP PUBLIC KEY BLOCK', binary),
    fingerprint: fingerprint.toString('hex').toUpperCase(),
    userId: opts.userId,
    keyCreationDate: opts.createdAt.toISOString(),
  };
}

function uncompressedPoint(pem: string): Buffer {
  const key = crypto.createPublicKey(pem);
  const jwk = key.export({ format: 'jwk' });
  const x = pad32(Buffer.from(jwk.x!, 'base64url'));
  const y = pad32(Buffer.from(jwk.y!, 'base64url'));
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function pad32(buf: Buffer): Buffer {
  if (buf.length === 32) return buf;
  if (buf.length > 32) return buf.subarray(buf.length - 32);
  return Buffer.concat([Buffer.alloc(32 - buf.length), buf]);
}

function publicKeyPacketBody(createdAtSeconds: number, point: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([4]),
    uint32(createdAtSeconds),
    Buffer.from([ECDSA, SECP256R1_OID.length]),
    SECP256R1_OID,
    mpiFromBytes(point),
  ]);
}

function keyFingerprint(keyBody: Buffer): Buffer {
  return crypto
    .createHash('sha1')
    .update(Buffer.from([0x99]))
    .update(uint16(keyBody.length))
    .update(keyBody)
    .digest();
}

function subpacket(type: number, body: Buffer): Buffer {
  const n = 1 + body.length;
  return Buffer.concat([subpacketLength(n), Buffer.from([type]), body]);
}

function subpacketLength(n: number): Buffer {
  if (n < 192) return Buffer.from([n]);
  if (n <= 8383) {
    const d = n - 192;
    return Buffer.from([192 + (d >> 8), d & 0xff]);
  }
  const b = Buffer.alloc(5);
  b[0] = 255;
  b.writeUInt32BE(n, 1);
  return b;
}

function oldPacket(tag: number, body: Buffer): Buffer {
  if (body.length <= 255) {
    return Buffer.concat([Buffer.from([0x80 | (tag << 2), body.length]), body]);
  }
  if (body.length <= 65535) {
    const hdr = Buffer.alloc(3);
    hdr[0] = 0x80 | (tag << 2) | 1;
    hdr.writeUInt16BE(body.length, 1);
    return Buffer.concat([hdr, body]);
  }
  const hdr = Buffer.alloc(5);
  hdr[0] = 0x80 | (tag << 2) | 2;
  hdr.writeUInt32BE(body.length, 1);
  return Buffer.concat([hdr, body]);
}

function mpiFromBytes(bytes: Buffer): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const value = bytes.subarray(start);
  let bitLen = value.length === 0 ? 0 : value.length * 8;
  if (value.length > 0) {
    let lead = value[0];
    while (bitLen > 0 && (lead & 0x80) === 0) {
      bitLen--;
      lead = (lead << 1) & 0xff;
    }
  }
  const out = Buffer.alloc(2 + value.length);
  out.writeUInt16BE(bitLen, 0);
  value.copy(out, 2);
  return out;
}

function parseEcdsaDer(der: Buffer): { r: Buffer; s: Buffer } {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('ECDSA signature is not a DER SEQUENCE');
  const seqLen = readDerLength(der, i);
  i = seqLen.next;
  const r = readDerInteger(der, i);
  i = r.next;
  const s = readDerInteger(der, i);
  return { r: r.value, s: s.value };
}

function readDerLength(buf: Buffer, i: number): { len: number; next: number } {
  const first = buf[i++];
  if (first < 0x80) return { len: first, next: i };
  const n = first & 0x7f;
  let len = 0;
  for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
  return { len, next: i };
}

function readDerInteger(buf: Buffer, i: number): { value: Buffer; next: number } {
  if (buf[i++] !== 0x02) throw new Error('ECDSA signature INTEGER expected');
  const len = readDerLength(buf, i);
  const raw = buf.subarray(len.next, len.next + len.len);
  return { value: raw, next: len.next + len.len };
}

function uint16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

function uint32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function armor(kind: string, data: Buffer): string {
  const b64 = data.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  const crc = crc24(data);
  const crcB64 = Buffer.from([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]).toString('base64');
  return [
    `-----BEGIN ${kind}-----`,
    'Version: kmspgp',
    '',
    ...lines,
    `=${crcB64}`,
    `-----END ${kind}-----`,
    '',
  ].join('\n');
}

function crc24(data: Buffer): number {
  let crc = 0xb704ce;
  for (const byte of data) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}
