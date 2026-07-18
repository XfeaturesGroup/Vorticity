// Binary HTTP (RFC 9292) — "Known-Length" message framing only (§3.3, §3.5's request/response
// variants). OHTTP (RFC 9458) requires the inner request/response to be framed this way before HPKE
// sealing. We implement only what our own client+gateway actually need: a single request line
// (method/scheme/authority/path), a flat header list, and a body — no informational (1xx) responses,
// no chunked/indeterminate-length framing (we always know the full body upfront), no trailers (RFC
// 9292 §3.8 explicitly allows omitting an empty trailer section entirely, which is what we do). This
// is a conformant subset, not a shortcut: every field we DO emit follows the spec's exact byte layout.
import { decodeVarint, decodeVarintBytes, encodeVarint, encodeVarintBytes } from "./varint.js";

const FRAMING_INDICATOR_REQUEST = 0;
const FRAMING_INDICATOR_RESPONSE = 1;

const utf8 = new TextEncoder();
const utf8Decode = new TextDecoder();

export interface BhttpRequest {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  headers: [string, string][];
  body: Uint8Array;
}

export interface BhttpResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array;
}

function encodeHeaderSection(headers: [string, string][]): Uint8Array {
  const lines: Uint8Array[] = [];
  for (const [name, value] of headers) {
    const nameBytes = encodeVarintBytes(utf8.encode(name));
    const valueBytes = encodeVarintBytes(utf8.encode(value));
    const line = new Uint8Array(nameBytes.length + valueBytes.length);
    line.set(nameBytes, 0);
    line.set(valueBytes, nameBytes.length);
    lines.push(line);
  }
  const totalLen = lines.reduce((n, l) => n + l.length, 0);
  const out = new Uint8Array(encodeVarint(totalLen).length + totalLen);
  const lenPrefix = encodeVarint(totalLen);
  out.set(lenPrefix, 0);
  let offset = lenPrefix.length;
  for (const line of lines) {
    out.set(line, offset);
    offset += line.length;
  }
  return out;
}

function decodeHeaderSection(bytes: Uint8Array, offset: number): { headers: [string, string][]; bytesRead: number } {
  const { value: sectionLen, bytesRead: lenSize } = decodeVarint(bytes, offset);
  const sectionStart = offset + lenSize;
  const sectionEnd = sectionStart + sectionLen;
  if (sectionEnd > bytes.length) throw new Error("bhttp: truncated header field section");
  const headers: [string, string][] = [];
  let pos = sectionStart;
  while (pos < sectionEnd) {
    const name = decodeVarintBytes(bytes, pos);
    pos += name.bytesRead;
    const value = decodeVarintBytes(bytes, pos);
    pos += value.bytesRead;
    headers.push([utf8Decode.decode(name.value), utf8Decode.decode(value.value)]);
  }
  if (pos !== sectionEnd) throw new Error("bhttp: header field section length mismatch");
  return { headers, bytesRead: lenSize + sectionLen };
}

function encodeContent(body: Uint8Array): Uint8Array {
  const lenPrefix = encodeVarint(body.length);
  const out = new Uint8Array(lenPrefix.length + body.length);
  out.set(lenPrefix, 0);
  out.set(body, lenPrefix.length);
  return out;
}

function decodeContent(bytes: Uint8Array, offset: number): { body: Uint8Array; bytesRead: number } {
  const { value, bytesRead } = decodeVarintBytes(bytes, offset);
  return { body: value, bytesRead };
}

/** Empty trailer field section, encoded explicitly as length-0 (RFC 9292 §3.8 allows omitting this
 * entirely; we emit an explicit zero for a simpler, single-code-path decoder — a decoder that treats
 * "missing" as zero-length already accepts this form too, per the same section). */
function emptyTrailerSection(): Uint8Array {
  return encodeVarint(0);
}

export function encodeBhttpRequest(req: BhttpRequest): Uint8Array {
  const parts: Uint8Array[] = [
    encodeVarint(FRAMING_INDICATOR_REQUEST),
    encodeVarintBytes(utf8.encode(req.method)),
    encodeVarintBytes(utf8.encode(req.scheme)),
    encodeVarintBytes(utf8.encode(req.authority)),
    encodeVarintBytes(utf8.encode(req.path)),
    encodeHeaderSection(req.headers),
    encodeContent(req.body),
    emptyTrailerSection(),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function decodeBhttpRequest(bytes: Uint8Array): BhttpRequest {
  let offset = 0;
  const framing = decodeVarint(bytes, offset);
  offset += framing.bytesRead;
  if (framing.value !== FRAMING_INDICATOR_REQUEST) {
    throw new Error(`bhttp: expected request framing indicator 0, got ${framing.value}`);
  }
  const method = decodeVarintBytes(bytes, offset);
  offset += method.bytesRead;
  const scheme = decodeVarintBytes(bytes, offset);
  offset += scheme.bytesRead;
  const authority = decodeVarintBytes(bytes, offset);
  offset += authority.bytesRead;
  const path = decodeVarintBytes(bytes, offset);
  offset += path.bytesRead;
  const headerSection = decodeHeaderSection(bytes, offset);
  offset += headerSection.bytesRead;
  const content = decodeContent(bytes, offset);
  offset += content.bytesRead;
  // Trailer section: decode-and-discard if present; RFC 9292 §3.8 says a decoder MUST treat a
  // missing trailer section as empty, so we don't error if the buffer ends here.
  if (offset < bytes.length) {
    const trailer = decodeHeaderSection(bytes, offset);
    offset += trailer.bytesRead;
  }
  return {
    method: utf8Decode.decode(method.value),
    scheme: utf8Decode.decode(scheme.value),
    authority: utf8Decode.decode(authority.value),
    path: utf8Decode.decode(path.value),
    headers: headerSection.headers,
    body: content.body,
  };
}

export function encodeBhttpResponse(res: BhttpResponse): Uint8Array {
  const parts: Uint8Array[] = [
    encodeVarint(FRAMING_INDICATOR_RESPONSE),
    encodeVarint(res.status),
    encodeHeaderSection(res.headers),
    encodeContent(res.body),
    emptyTrailerSection(),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function decodeBhttpResponse(bytes: Uint8Array): BhttpResponse {
  let offset = 0;
  const framing = decodeVarint(bytes, offset);
  offset += framing.bytesRead;
  if (framing.value !== FRAMING_INDICATOR_RESPONSE) {
    throw new Error(`bhttp: expected response framing indicator 1, got ${framing.value}`);
  }
  const status = decodeVarint(bytes, offset);
  offset += status.bytesRead;
  // No informational (1xx) responses supported — a status in [100,199] here would mean this branch
  // needs extending (RFC 9292 §3.5's "Known-Length Informational Response" list), which our own
  // client/gateway never produce.
  if (status.value >= 100 && status.value < 200) {
    throw new Error(`bhttp: informational (1xx) responses are not supported by this decoder`);
  }
  const headerSection = decodeHeaderSection(bytes, offset);
  offset += headerSection.bytesRead;
  const content = decodeContent(bytes, offset);
  offset += content.bytesRead;
  if (offset < bytes.length) {
    const trailer = decodeHeaderSection(bytes, offset);
    offset += trailer.bytesRead;
  }
  return { status: status.value, headers: headerSection.headers, body: content.body };
}
