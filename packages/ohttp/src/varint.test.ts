import { describe, expect, it } from "vitest";
import { decodeVarint, decodeVarintBytes, encodeVarint, encodeVarintBytes } from "./varint.js";

describe("QUIC varint (RFC 9000 §16)", () => {
  it("encodes the boundary values with the RFC's exact prefix bits", () => {
    expect(Array.from(encodeVarint(0))).toEqual([0b00000000]);
    expect(Array.from(encodeVarint(63))).toEqual([0b00111111]);
    expect(encodeVarint(64).length).toBe(2);
    expect(encodeVarint(64)[0]! >> 6).toBe(0b01);
    expect(encodeVarint(16383).length).toBe(2);
    expect(encodeVarint(16384).length).toBe(4);
    expect(encodeVarint(16384)[0]! >> 6).toBe(0b10);
    expect(encodeVarint(1073741823).length).toBe(4);
    expect(encodeVarint(1073741824).length).toBe(8);
    expect(encodeVarint(1073741824)[0]! >> 6).toBe(0b11);
  });

  it("round-trips across all four width classes", () => {
    for (const v of [0, 1, 63, 64, 300, 16383, 16384, 100000, 1073741823, 1073741824, 5_000_000_000]) {
      const encoded = encodeVarint(v);
      const { value, bytesRead } = decodeVarint(encoded, 0);
      expect(value).toBe(v);
      expect(bytesRead).toBe(encoded.length);
    }
  });

  it("rejects negative or non-integer input", () => {
    expect(() => encodeVarint(-1)).toThrow();
    expect(() => encodeVarint(1.5)).toThrow();
  });

  it("throws on truncated input rather than reading out of bounds", () => {
    const twoByteEncoding = encodeVarint(1000);
    expect(() => decodeVarint(twoByteEncoding.slice(0, 1), 0)).toThrow();
  });

  it("length-prefixed byte strings round-trip, including empty", () => {
    for (const s of [new Uint8Array(0), new Uint8Array([1, 2, 3]), new Uint8Array(200).fill(7)]) {
      const encoded = encodeVarintBytes(s);
      const { value, bytesRead } = decodeVarintBytes(encoded, 0);
      expect(Array.from(value)).toEqual(Array.from(s));
      expect(bytesRead).toBe(encoded.length);
    }
  });

  it("decodes correctly at a non-zero offset inside a larger buffer", () => {
    const prefix = new Uint8Array([0xaa, 0xbb]);
    const encoded = encodeVarintBytes(new Uint8Array([9, 9, 9]));
    const buf = new Uint8Array(prefix.length + encoded.length);
    buf.set(prefix, 0);
    buf.set(encoded, prefix.length);
    const { value, bytesRead } = decodeVarintBytes(buf, prefix.length);
    expect(Array.from(value)).toEqual([9, 9, 9]);
    expect(bytesRead).toBe(encoded.length);
  });
});
