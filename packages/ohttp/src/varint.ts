// QUIC variable-length integer encoding (RFC 9000 §16), which RFC 9292 (Binary HTTP) mandates for
// every length/count field. Top 2 bits of the first byte select the encoded width; the remaining bits
// (of the first byte and any following bytes) hold the value, big-endian.
//
//   00xxxxxx                                              -> 1 byte,  0..63
//   01xxxxxx xxxxxxxx                                     -> 2 bytes, 0..16383
//   10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx                   -> 4 bytes, 0..1073741823
//   11xxxxxx (x7 more bytes)                              -> 8 bytes, 0..4611686018427387903
//
// We use `number` (not `bigint`) throughout — every length we ever encode (HTTP method/path/header/
// body sizes) is far below `Number.MAX_SAFE_INTEGER`, and `number` keeps every call site in this
// package simpler. The 8-byte form's full range technically needs `bigint` to represent losslessly;
// encoding refuses any value that would round-trip incorrectly through `number`, rather than silently
// truncating.

const MAX_1 = 0x3f; // 2^6 - 1
const MAX_2 = 0x3fff; // 2^14 - 1
const MAX_4 = 0x3fffffff; // 2^30 - 1
const MAX_8_SAFE = Number.MAX_SAFE_INTEGER; // conservative cap; see module doc

export function encodeVarint(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`varint: value must be a non-negative integer, got ${value}`);
  }
  if (value <= MAX_1) {
    return new Uint8Array([value]);
  }
  if (value <= MAX_2) {
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, value | 0x4000);
    return out;
  }
  if (value <= MAX_4) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value | 0x80000000);
    return out;
  }
  if (value <= MAX_8_SAFE) {
    const out = new Uint8Array(8);
    const view = new DataView(out.buffer);
    // Split into high/low 32-bit halves — `setUint32` on the high half already carries the `11`
    // length-prefix bits since `value` here always fits under 2^62, far below the `0xC0000000`
    // prefix bit's position in the high word for any value we actually encode.
    const high = Math.floor(value / 0x100000000);
    const low = value >>> 0;
    view.setUint32(0, high | 0xc0000000);
    view.setUint32(4, low);
    return out;
  }
  throw new Error(`varint: value ${value} exceeds this codec's safe-integer encoding limit`);
}

/** Returns `{ value, bytesRead }`. Throws on truncated input. */
export function decodeVarint(bytes: Uint8Array, offset: number): { value: number; bytesRead: number } {
  if (offset >= bytes.length) throw new Error("varint: truncated (no length-prefix byte)");
  const first = bytes[offset]!;
  const prefix = first >> 6;
  const width = prefix === 0 ? 1 : prefix === 1 ? 2 : prefix === 2 ? 4 : 8;
  if (offset + width > bytes.length) throw new Error(`varint: truncated (need ${width} bytes)`);
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, width);
  if (width === 1) return { value: first & 0x3f, bytesRead: 1 };
  if (width === 2) return { value: view.getUint16(0) & 0x3fff, bytesRead: 2 };
  if (width === 4) return { value: view.getUint32(0) & 0x3fffffff, bytesRead: 4 };
  const high = view.getUint32(0) & 0x3fffffff;
  const low = view.getUint32(4);
  const value = high * 0x100000000 + low;
  if (!Number.isSafeInteger(value)) {
    throw new Error("varint: decoded 8-byte value exceeds Number.MAX_SAFE_INTEGER — not supported by this codec");
  }
  return { value, bytesRead: 8 };
}

/** Length-prefixed byte string: `varint(len) || bytes`. */
export function encodeVarintBytes(bytes: Uint8Array): Uint8Array {
  const lenBytes = encodeVarint(bytes.length);
  const out = new Uint8Array(lenBytes.length + bytes.length);
  out.set(lenBytes, 0);
  out.set(bytes, lenBytes.length);
  return out;
}

/** Returns `{ value, bytesRead }` for a length-prefixed byte string starting at `offset`. */
export function decodeVarintBytes(bytes: Uint8Array, offset: number): { value: Uint8Array; bytesRead: number } {
  const { value: len, bytesRead: lenSize } = decodeVarint(bytes, offset);
  const start = offset + lenSize;
  const end = start + len;
  if (end > bytes.length) throw new Error(`varint-prefixed bytes: truncated (need ${len} bytes)`);
  return { value: bytes.slice(start, end), bytesRead: lenSize + len };
}
