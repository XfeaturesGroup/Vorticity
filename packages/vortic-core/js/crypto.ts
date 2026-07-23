// Real crypto surface for @vorticity/vortic-core — a thin, synchronous-after-init wrapper around
// the wasm-pack `--target web` bundle built from this crate's Rust (src/symmetric.rs + src/kem.rs).
//
// This exposes two things the chat transport needs:
//   1. An X25519 Diffie-Hellman handshake (`generateKeyPair` + `deriveSharedSecret`) so two peers can
//      agree on a per-conversation key over the wire — no more hardcoded demo key.
//   2. Keyed ChaCha20-Poly1305 (`encryptMessage`/`decryptMessage`), which now take the derived shared
//      secret as their first argument.
// All functions are synchronous but require `initCrypto()` to have resolved first (the WASM must be
// instantiated before any exported function can run). Callers gate on it once, on mount.
//
// The `?url` import is Vite's asset-URL form: it hands `init()` the resolved URL of the compiled
// `.wasm` so the browser fetches + instantiates it, rather than relying on wasm-bindgen's default
// relative-fetch (which resolves against the glue file's own URL and is fragile across a bundler's
// module graph). Vite already transpiles this workspace package from source (same as @vorticity/ui),
// so both the generated glue module and the `?url` asset resolve inside the app's Vite pipeline.
import init, {
  encrypt_message,
  decrypt_message,
  x25519_generate_keypair,
  x25519_derive_shared,
  oprf_blind,
  oprf_unblind,
  oprf_verify_dleq,
  blindsig_blind,
  blindsig_finalize,
  blindsig_verify,
  kem_generate_keypair,
  kem_public_key_from_keypair,
  identity_verifying_key,
  identity_sign_bundle,
  identity_verify_bundle,
  RatchetSession,
  MlsGroupSession,
  alias_lookup_key,
  alias_derive_record_key,
  pow_mint,
  pow_verify,
} from "../pkg/client/vortic_core.js";
import wasmUrl from "../pkg/client/vortic_core_bg.wasm?url";

let readyPromise: Promise<void> | null = null;

/// Instantiate the WASM module exactly once. Idempotent and concurrency-safe: every caller awaits
/// the same in-flight promise, so N components mounting at once trigger a single instantiation.
export function initCrypto(): Promise<void> {
  if (!readyPromise) {
    readyPromise = init({ module_or_path: wasmUrl }).then(() => undefined);
  }
  return readyPromise;
}

export interface X25519KeyPair {
  /// 32-byte X25519 secret — never leaves the device.
  privateKey: Uint8Array;
  /// 32-byte X25519 public key — sent to the peer in the `handshake` frame.
  publicKey: Uint8Array;
}

/// Generate a fresh ephemeral X25519 keypair. The 32-byte secret seed comes from the browser CSPRNG
/// (`crypto.getRandomValues`); the WASM derives the public key from it. Requires `initCrypto()`.
export function generateKeyPair(): X25519KeyPair {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const packed = x25519_generate_keypair(seed); // secret(32) || public(32)
  return {
    privateKey: packed.slice(0, 32),
    publicKey: packed.slice(32, 64),
  };
}

/// Derive the shared 32-byte ChaCha20-Poly1305 key from our secret and the peer's public key.
/// X25519 is symmetric, so both peers computing this over the swapped keys get the same result.
/// Requires `initCrypto()`.
export function deriveSharedSecret(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return x25519_derive_shared(myPrivateKey, theirPublicKey);
}

/// Encrypt a UTF-8 string under a 32-byte key; returns base64(nonce || ciphertext || tag). Throws if
/// `initCrypto()` has not resolved, the key is the wrong length, or on an internal encryption failure.
export function encryptMessage(key: Uint8Array, plaintext: string): string {
  return encrypt_message(key, plaintext);
}

/// Decrypt a base64 payload produced by `encryptMessage` under the same key. Throws on a wrong key,
/// tampering, a truncated/garbage payload, or non-UTF-8 plaintext — never returns partial data.
export function decryptMessage(key: Uint8Array, payloadB64: string): string {
  return decrypt_message(key, payloadB64);
}

// --- VOPRF (Ristretto255) client side: the enrollment airlock ---

export interface OprfBlind {
  /// 32-byte blinded point B = r·H(seed) — sent to the Enrollment Worker's /oprf/issue.
  blinded: Uint8Array;
  /// 32-byte blinding factor r — kept locally to unblind the Worker's response. Never sent.
  blindingFactor: Uint8Array;
}

/// Blind an identity seed for VOPRF evaluation. `entropy` must be 32 fresh random bytes; if omitted,
/// it is drawn from `crypto.getRandomValues`. Requires `initCrypto()`.
export function oprfBlind(seed: Uint8Array, entropy?: Uint8Array): OprfBlind {
  const e = entropy ?? crypto.getRandomValues(new Uint8Array(32));
  const packed = oprf_blind(seed, e); // blinded(32) || r(32)
  return { blinded: packed.slice(0, 32), blindingFactor: packed.slice(32, 64) };
}

/// Unblind the Worker's evaluated point into the final 32-byte OPRF token (`token = k·H(seed)`).
/// Requires `initCrypto()`.
export function oprfUnblind(evaluated: Uint8Array, blindingFactor: Uint8Array): Uint8Array {
  return oprf_unblind(evaluated, blindingFactor);
}

/// Verify the Worker's DLEQ proof — that it evaluated with the key committed in `publicKey`. `proof`
/// is the 128-byte `Z || K || c || s`. Returns true iff the evaluation is honest. Requires `initCrypto()`.
export function oprfVerifyDleq(blinded: Uint8Array, evaluated: Uint8Array, publicKey: Uint8Array, challenge: Uint8Array, response: Uint8Array): boolean {
  const proof = new Uint8Array(128);
  proof.set(evaluated, 0);
  proof.set(publicKey, 32);
  proof.set(challenge, 64);
  proof.set(response, 96);
  return oprf_verify_dleq(blinded, proof);
}

// --- RSA Blind Signatures (RFC 9474 "RSABSSA") client side: the Plane Bridge redemption token ---
// Replaces the VOPRF airlock above for enrollment<->messaging redemption (see
// packages/vortic-core/src/blind_sig.rs's module doc for why: a VOPRF evaluation cannot be verified
// by a third party without the OPRF secret or an equivalent shared secret, which the Messaging Plane
// must never hold). `oprfBlind`/`oprfUnblind`/`oprfVerifyDleq` above remain valid, tested VOPRF
// primitives — just no longer wired into this specific bridge.

/** RSA-3072 modulus size in bytes — fixes every blind_sig.rs byte length below. */
export const BLINDSIG_MODULUS_BYTES = 384;
/** RFC 9474 Randomized mode's fixed message-randomizer length. */
export const BLINDSIG_RANDOMIZER_BYTES = 32;

export interface BlindSigBlindResult {
  /// Opaque client-local state to keep until `blindSigFinalize` — never send this anywhere.
  blindingState: Uint8Array;
  /// The actual blinded message to POST to the issuer's /token/issue.
  blindedMessage: Uint8Array;
}

/// Blind `msg` for the issuer's RSA-3072 public key (PEM). Requires `initCrypto()`.
export function blindSigBlind(pkPem: string, msg: Uint8Array): BlindSigBlindResult {
  const blindingState = blindsig_blind(pkPem, msg);
  return { blindingState, blindedMessage: blindingState.slice(0, BLINDSIG_MODULUS_BYTES) };
}

/// The 32-byte message randomizer embedded in a blinding state (needed alongside `msg`/`sig` when
/// presenting the redemption token to Messaging's /membership/insert).
export function blindSigRandomizer(blindingState: Uint8Array): Uint8Array {
  return blindingState.slice(BLINDSIG_MODULUS_BYTES * 2, BLINDSIG_MODULUS_BYTES * 2 + BLINDSIG_RANDOMIZER_BYTES);
}

/// Finalize the issuer's blind signature into the real, verifiable signature over `msg`. Also
/// verifies the result internally (throws if the issuer signed dishonestly). Requires `initCrypto()`.
export function blindSigFinalize(pkPem: string, blindingState: Uint8Array, blindSig: Uint8Array, msg: Uint8Array): Uint8Array {
  return blindsig_finalize(pkPem, blindingState, blindSig, msg);
}

/// Verify a redemption token `(msg, msgRandomizer, sig)` against the issuer's public key. Requires
/// `initCrypto()`. (Messaging does the authoritative check server-side; this is available for a
/// client-side self-check before sending, e.g. in tests.)
export function blindSigVerify(pkPem: string, msg: Uint8Array, msgRandomizer: Uint8Array, sig: Uint8Array): boolean {
  return blindsig_verify(pkPem, msg, msgRandomizer, sig);
}

// --- Triple Ratchet (R24): PQXDH-style authenticated handshake + Double + Sparse-PQ Ratchet ---
// See packages/vortic-core/src/ratchet.rs's module doc for the full design. Everything below is a
// thin wrapper: all cryptographic state lives inside the WASM `RatchetSession` object; this module
// only adds the "fresh randomness on every call" convention JS call sites need to follow.

export { RatchetSession };

/// 96 bytes of fresh CSPRNG entropy — the `entropy` argument every `RatchetSession.encryptMessage`/
/// `decryptMessage` call requires. Most of it goes unused on any given call (only consumed if that
/// specific call happens to trigger a DH ratchet turn or a Sparse-PQ-Ratchet event) — see ratchet.rs's
/// `Entropy` doc comment — but which case applies isn't knowable in advance, so always draw fresh.
export function freshRatchetEntropy(): Uint8Array {
  const bytes = new Uint8Array(96);
  crypto.getRandomValues(bytes);
  return bytes;
}

/// A device's long-term hybrid (ML-KEM-768 + X25519) prekey keypair, deterministic from a 32-byte
/// seed the caller persists locally (e.g. IndexedDB) — never sent anywhere. Requires `initCrypto()`.
export function kemGenerateKeypair(seed: Uint8Array): Uint8Array {
  return kem_generate_keypair(seed);
}

/// The public half of a `kemGenerateKeypair` output — this is the prekey bundle to sign
/// (`identitySignBundle`) and publish. Requires `initCrypto()`.
export function kemPublicKeyFromKeypair(keypairBytes: Uint8Array): Uint8Array {
  return kem_public_key_from_keypair(keypairBytes);
}

/// The public verifying key for a long-term Ed25519 identity, deterministic from a 32-byte seed the
/// caller persists locally. Publish this once (e.g. alongside the prekey bundle) so peers can verify
/// signed bundles. Requires `initCrypto()`.
export function identityVerifyingKey(seed: Uint8Array): Uint8Array {
  return identity_verifying_key(seed);
}

/// Sign a hybrid prekey bundle (`kemPublicKeyFromKeypair`'s output) with the long-term identity
/// derived from `seed` — this signature is what makes a peer's `RatchetSession.handshakeInitiate`
/// call authenticated rather than bare DH. Requires `initCrypto()`.
export function identitySignBundle(seed: Uint8Array, hybridPublicBytes: Uint8Array): Uint8Array {
  return identity_sign_bundle(seed, hybridPublicBytes);
}

/// Verify a signed prekey bundle against a peer's published verifying key. Requires `initCrypto()`.
export function identityVerifyBundle(verifyingKey: Uint8Array, hybridPublicBytes: Uint8Array, sig: Uint8Array): boolean {
  return identity_verify_bundle(verifyingKey, hybridPublicBytes, sig);
}

// --- Public @alias discovery (docs/03 §8) + Hashcash PoW (docs/03 §8.3) ---
// "Alias contact establishment" pass (2026-07): closes the crate's own Phase-0 `todo!()` stubs in
// alias.rs/pow.rs. See those files' module docs for why the PoW miner lives in Rust/WASM rather
// than a TS loop over `crypto.subtle.digest` (async per-iteration overhead makes a real 20-26 bit
// mint impractically slow in plain JS).

/// `H("vortic-alias-v1" || nickname)` as lowercase hex — matches `AliasDO.ts`'s `LOOKUP_KEY_RE`
/// (`^[0-9a-f]{64}$`) exactly. Requires `initCrypto()`.
export function aliasLookupKeyHex(nickname: string): string {
  const bytes = alias_lookup_key(nickname);
  return Array.from(bytes as Uint8Array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/// The 32-byte symmetric key the alias record is AEAD-sealed under — derivable by anyone who
/// knows `nickname` (the owner, and anyone who later resolves it), by no one else. Requires
/// `initCrypto()`.
export function aliasDeriveRecordKey(nickname: string): Uint8Array {
  return alias_derive_record_key(nickname);
}

/// Mints a Hashcash stamp for `resource` at `minBits` difficulty. Runs a real synchronous loop
/// inside WASM (no async per-iteration overhead) — can still take several seconds at the top of
/// docs/03 §8.3's range (register: 24-26 bits), so callers should invoke this off the main thread
/// (see `apps/web/src/workers/powMiner.worker.ts`), not directly from a component. `epoch` must be
/// `Math.floor(Date.now() / 3_600_000)` to match `AliasDO.ts`'s acceptance window. Requires
/// `initCrypto()`.
export function powMint(resource: string, minBits: number, epoch: number, salt: string): string {
  return pow_mint(resource, minBits, epoch, salt);
}

/// Local sanity-check only (see pow.rs's module doc: the real server-side gate is `AliasDO.ts`'s
/// own independent, already-tested JS implementation, not this WASM call) — lets a caller confirm
/// a stamp it just mined actually clears the bar before spending a network round-trip on it.
/// Requires `initCrypto()`.
export function powVerify(stamp: string, expectedResource: string, minBits: number): boolean {
  return pow_verify(stamp, expectedResource, minBits);
}

// --- MLS groups (RFC 9420, X-Wing hybrid PQ ciphersuite) — see group.rs's module doc for the full
// design and docs/03 §5. Same opaque-handle convention as RatchetSession above: all group state
// lives inside the WASM object, exportState()/importState() are the persistence pair (MUST be
// sealed before touching disk — see group.rs's own doc comment on exportState, identical warning to
// RatchetSession's). Passthrough only, no thin wrapper needed beyond re-exporting the class itself
// (wasm-bindgen's generated methods are already the real API — see useGroupTransport.ts/lib/group.ts
// for the JS-side conventions built on top: base64 framing, sealed persistence, invite exchange).

export { MlsGroupSession };
