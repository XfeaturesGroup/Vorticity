// Traffic-analysis mitigations from docs/03-crypto-core.md §6 ("Sealed Sender++"), point 4:
// "Constant-size envelopes via length padding to power-of-two buckets; timestamps bucketed
// server-side." Point 3 (receipts padded/delayed/decoupled) and pairwise-queue transport (point 2)
// were already real as of the "R22: real transport" pass — this module closes the two pieces of
// point 4 that were still just prose: neither existed in code anywhere in this Worker until now
// (confirmed by grep across QueueDO.ts/GroupDO.ts/ConvLogDO.ts before writing this file — every one
// of them stored and returned a raw `Date.now()`, and `size_bucket` was accepted from the client
// but never actually checked against the real ciphertext length).
//
// WHY BUCKET AT WRITE TIME, NOT ONLY AT RESPONSE TIME (a real design decision, not the obvious
// default): docs/02's primary adversary A2 is the HOST ITSELF — "reads all D1/R2/DO state ... can
// log & correlate." Bucketing a timestamp only when it's returned in an HTTP/WS response would do
// nothing against that adversary, who can read the raw stored value directly out of DO SQLite —
// it would only raise cost for a weaker, secondary adversary (passive network observer, A1/A7).
// Coarsening BEFORE the value is ever written means even a full storage dump reveals only the
// bucket a message landed in, not its real submission instant — real protection against the
// adversary this project's own threat model names as primary, not just the wire-level one.
const TIMESTAMP_BUCKET_MS = 60_000; // 1 minute — a tunable default, not a protocol-mandated value

/** Rounds a Unix-ms timestamp DOWN to the current bucket boundary — never reveals sub-bucket timing. */
export function bucketTimestamp(ms: number, granularityMs: number = TIMESTAMP_BUCKET_MS): number {
  return Math.floor(ms / granularityMs) * granularityMs;
}

const MAX_SIZE_BUCKET = 24; // 2^24 = 16 MiB — well above any real message/media-metadata size here

/**
 * Validates a CLIENT-DECLARED size bucket against the REAL ciphertext length. `sizeBucket` is an
 * exponent: valid ciphertext must fit in `2^sizeBucket` bytes (the padding target), and — this is
 * the check that was previously missing everywhere in this codebase, not just here — must NOT be
 * smaller than the previous power-of-two boundary, or a lying/broken client could declare a bucket
 * far bigger than its real (unpadded) ciphertext, defeating the padding's whole purpose without
 * the server ever noticing. `size_bucket = 0` is a legal edge case (a ciphertext of exactly 1 byte,
 * `2^0`); real ciphertexts are never that small in practice (AEAD tags alone are 16 bytes), but
 * nothing here assumes otherwise.
 */
export function validateSizeBucket(byteLength: number, sizeBucket: number): boolean {
  if (!Number.isInteger(sizeBucket) || sizeBucket < 0 || sizeBucket > MAX_SIZE_BUCKET) return false;
  if (byteLength <= 0) return false;
  const upperBound = 2 ** sizeBucket;
  const lowerBound = sizeBucket === 0 ? 0 : 2 ** (sizeBucket - 1);
  return byteLength > lowerBound && byteLength <= upperBound;
}
