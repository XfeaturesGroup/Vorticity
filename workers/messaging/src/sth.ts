// Signed Tree Head (STH) for KeyTransparencyDO — RFC 6962 §3.5-shaped, adapted to our own log.
//
// THE GAP THIS CLOSES, stated precisely (see kt-sth-key.ts's header for the full context): a
// consistency proof (merkleConsistency.ts) authenticates that root_m's CONTENT is a genuine
// append-only prefix of root_n's content — but the raw Merkle math never independently authenticates
// the numeric SIZE label attached to a claimed root. Real Certificate Transparency deployments close
// exactly this gap with a Signed Tree Head: the log operator signs `(size, root, timestamp)` with a
// key everyone can verify against, turning "the log claims size N has root R" into a durable,
// non-repudiable, independently-checkable statement. This does NOT by itself make the log incapable
// of equivocating (a dishonest operator can still sign two DIFFERENT roots for the SAME size and hand
// one to each of two observers) — what it provides is DETECTABILITY: if that ever happens, whoever
// later compares both signed STHs holds cryptographic, non-repudiable proof of misbehavior, which is
// exactly the role gossip/monitoring plays in real CT (still not built here — see this pass's honest
// scope note in docs/06).
//
// Uses `node:crypto`'s Ed25519 (this Worker already opts into `nodejs_compat`, same precedent
// KeyTransparencyDO.ts's own `createHash` usage established) rather than vortic-core/WASM: this is a
// pure server-side signing operation with no client-side counterpart to keep in the same language,
// unlike alias_sig.rs (which needs the SAME sign/verify pair runnable from a browser). `node:crypto`'s
// Ed25519 needs no digest algorithm argument (`sign(null, message, key)` / `verify(null, ...)`) — the
// hash is built into the Ed25519 signature scheme itself.

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";

export interface SignedTreeHead {
  size: number;
  root: string; // 64-char lowercase hex
  timestamp: number; // unix ms
  signature: string; // base64
}

function sthMessage(size: number, root: string, timestamp: number): Buffer {
  return Buffer.from(`vortic-kt-sth-v1:${size}:${root}:${timestamp}`, "utf8");
}

export function signSth(privateKeyPem: string, size: number, root: string, timestamp: number): SignedTreeHead {
  const key: KeyObject = createPrivateKey(privateKeyPem);
  const signature = nodeSign(null, sthMessage(size, root, timestamp), key);
  return { size, root, timestamp, signature: signature.toString("base64") };
}

/**
 * Verifies an STH's signature against the given public key. Returns false (never throws) on any
 * malformed input — this function's whole point is to be safe to run against an untrusted STH a
 * caller fetched from somewhere (e.g. a future client-side verification path, or a gossip/monitor
 * comparing two independently-obtained STHs).
 */
export function verifySth(publicKeyPem: string, sth: SignedTreeHead): boolean {
  if (
    !Number.isInteger(sth.size) ||
    sth.size < 0 ||
    typeof sth.root !== "string" ||
    !/^[0-9a-f]{64}$/.test(sth.root) ||
    !Number.isInteger(sth.timestamp) ||
    typeof sth.signature !== "string"
  ) {
    return false;
  }
  try {
    const key = createPublicKey(publicKeyPem);
    const sigBytes = Buffer.from(sth.signature, "base64");
    return nodeVerify(null, sthMessage(sth.size, sth.root, sth.timestamp), key, sigBytes);
  } catch {
    return false;
  }
}
