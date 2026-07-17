# 03 — Cryptographic Core

Concrete primitives, parameters, and protocol steps. Everything here compiles to a single Rust crate
(`vortic-core`) exposed to the TS frontend and the Workers backend via `wasm-bindgen`, so the *same audited
code* runs on client and (verification-only) on edge.

```
vortic-core (Rust → WASM)
├── kem/      ML-KEM-768 (fips203/ml-kem crate) + X25519  → hybrid
├── ratchet/  PQXDH handshake, Double+Sparse-PQ (Triple) ratchet
├── group/    MLS (mls-rs) wrapper, epoch mgmt
├── ring/     bLSAG linkable ring signatures (Ristretto255)
├── zk/       Semaphore v4 identity + Groth16 prove (client) / verify (edge)
├── blind_sig/ RSA Blind Signatures (RFC 9474 RSABSSA) — the enrollment<->messaging Plane Bridge (§2)
├── oprf/     VOPRF (ristretto255-SHA512) — still implemented/tested, no longer wired into §2's bridge
├── seal/     Sealed Sender++ envelope
├── alias/    Opt-in public @alias records (hashed key + AEAD value), ownership key
├── pow/      Hashcash / Argon2id proof-of-work stamps (anti-scrape / anti-spam)
├── backup/   Argon2id + AES-256-GCM, BIP39
└── util/     HKDF-SHA256, Poseidon, constant-time, zeroize
```

Primitive baseline: **AEAD** = AES-256-GCM (HW) / XChaCha20-Poly1305 (fallback). **Hash** = SHA-256/512 +
BLAKE3 for blobs, **Poseidon** inside circuits. **Sig** = Ed25519 (transport) / EdDSA-BabyJubJub (Semaphore).
**KDF** = HKDF-SHA256; **password KDF** = Argon2id (m=256 MiB, t=3, p=1). All secrets `zeroize`d.

---

## 1. Identity layers (deliberately separate)

| Layer | Keypair | Known to | Purpose |
|---|---|---|---|
| **Account** | OAuth (Xfeatures) | IdP only | Onboarding, anti-Sybil, recovery gate |
| **Enrollment credential** | blinded VOPRF token | nobody-linkably | "I'm an enrolled member" — unlinkable |
| **Membership** | Semaphore id `(trapdoor, nullifier)` → commitment | in Merkle set (anon) | ZK proof of membership |
| **Long-term device** | Ed25519 + X25519 + ML-KEM | peers only (via prekeys) | Ratchet handshake, device auth |
| **Ephemeral** | per-message ratchet keys | derived | FS/PCS |
| **Alias persona** *(opt-in)* | Ed25519 `alias_key` | public by choice | Owns one `@nickname`→intro-queue record; signs updates/revocation |

There is **no key that is a function of both the email and the handle.** That absence *is* the product.
Public aliases (§8) are an **opt-in** exception on the *discovery* axis only — never on the *linkage* axis: an
alias binds `@nickname → intro-queue`, still with zero stored path to email, PPID, handle, or the owner's real
conversation queues.

---

## 2. Anonymous enrollment (the airlock) — RSA Blind Signatures (RFC 9474 "RSABSSA")

Goal: turn "authenticated Xfeatures user" into "unlinkable proof of eligibility" without the server learning
which token belongs to which user, **and** in a form a THIRD party (the Messaging Plane) can verify without
holding any secret. Uses **RSA Blind Signatures** (RFC 9474, RSABSSA-SHA384-PSS-Randomized, RSA-3072).

**Why not VOPRF (the original design):** a VOPRF evaluation is not, by construction, third-party verifiable —
checking it requires the evaluator's own secret key `k` (or an equivalent shared secret). Any scheme where
Messaging "verifies" a VOPRF-issued token therefore smuggles a shared secret between the planes under a
different name, violating the hard invariant that Messaging may know only a **public** key about Enrollment.
RSA blind signatures solve this by construction: the issuer's signature is a real signature, verifiable by
anyone holding nothing but the issuer's public key. (Superseded 2026-07 — see
[06](06-roadmap-and-risks.md)'s Plane Bridge entry.)

```
Client                                    Enrollment Worker/Issuer (holds sk_issuer, PPID secret s)
  │  OAuth2 + PKCE → access_token            │
  │  fetch /userinfo → sub, email_verified   │
  │                                          │  PPID = HMAC-SHA256(s, sub)     ← one-way, no email stored
  │                                          │  if seen[PPID] and quota exceeded → reject (sybil guard)
  │  msg ← random identity message           │
  │  (blinded, state) = Blind(pk, msg) ──────►│  blindSig = BlindSign(sk, blinded)  ← never sees unblinded msg
  │  sig = Finalize(pk, state, blindSig, msg) ◄──────  (also self-verifies before returning)
  │  token = (msg, sig, msgRandomizer)        │  stores only PPID + counter (NOT msg, NOT sig)
```

- The issuer signs a value it **cannot see** (`msg` is blinded). `token = (msg, sig, msgRandomizer)` is a real
  RSASSA-PSS signature the client can later present; ANY party — including Messaging — verifies it with
  nothing but `pk_issuer` (`Verify(pk_issuer, msg, msgRandomizer, sig)`), no shared secret required.
- **PPID** (`HMAC(s, sub)`) is the *only* residue of the real identity, stored purely to rate-limit
  enrollments per account (checked once, in `/oauth/callback`'s upsert — `/token/issue` does not repeat this
  check; see docs/04 Flow 1). It is one-way and never associated with `msg`, `sig`, or any handle.
- Redemption of `token` authorizes exactly one action: **inserting a Semaphore commitment into the group tree**
  (Messaging Plane's `/membership/insert`, verified there against `pk_issuer` — see docs/04 Flow 1). After
  that, the token is spent (recorded by `token_null = H(msg)` in `issuer_token_null`, DB_MSG — **not**
  DB_ENROLL; see docs/04's D1 schema) and the messaging identity is live — with **zero stored link** back to
  `sub`, and zero secret shared between the planes.
- **Non-goal, accepted deliberately (not PQ):** RSABSSA is not post-quantum. This is an accepted tradeoff, not
  an oversight — the token is one-time-use and spent (nullified) immediately at redemption, so a
  harvest-now-decrypt-later adversary who later breaks RSA has nothing left to redeem: there is no ciphertext
  or long-lived secret protected by this signature to harvest. See docs/02's non-goal N6.

**Residual risk (must document):** timing/IP correlation between the OAuth call and the commitment insertion.
Mitigated by (a) client caches the token and inserts later, (b) OHTTP on the insertion path, (c) different
hostnames/Workers per plane, (d) the Gate nudging VPN/Tor. See [06](06-roadmap-and-risks.md).

---

## 3. ZK membership & session auth — Semaphore v4

Once a commitment is in the tree, the client proves membership **without revealing which leaf** to obtain a
session capability.

- **Identity:** Semaphore v4 EdDSA identity → `commitment = Poseidon(pk)`. Tree = **Lean Incremental Merkle
  Tree**, root maintained by a `MerkleTreeDO` (Durable Object, authoritative) and mirrored to D1.
- **Proof (Groth16):** public inputs `= (merkleRoot, nullifierHash, signalHash, externalNullifier)`; private
  `= (identity secret, merkle path)`. Proves: *"I know the secret behind some commitment under `merkleRoot`,
  and `nullifierHash` is its unique tag for `externalNullifier`."*
- **`externalNullifier = H(epoch)`** where epoch = e.g. `floor(unix / 3600)`. One anonymous session per member
  per epoch → **Sybil-resistant rate limiting with zero identity.** Reused nullifier ⇒ rejected.
- **Edge verification:** the Worker runs the **Groth16 verifier in WASM** and, on success, mints a short-lived
  **capability** (a MAC'd, audience-scoped token — *not* a ZK proof) valid for the epoch. **Subsequent messages
  authenticate with the cheap capability, never re-proving ZK.** This is the single most important performance
  decision — see the cost analysis below and in [06](06-roadmap-and-risks.md).

**Verifier cost reality (measured elsewhere):** snarkjs pure-WASM Groth16 verify ≈ **0.74–0.88 s CPU**. That is
acceptable *once per session* (Workers paid plan allows up to 5 min CPU/req; 30 s default) but **catastrophic
per message.** Optimization ladder: snarkjs-WASM (baseline) → hand-rolled **BN254/BLS12-381 pairing verifier in
Rust→WASM** (3 pairings only; target 10–50 ms) → optional off-hot-path verification with cached roots.

---

## 4. 1:1 messaging — hybrid PQC Triple Ratchet

**Handshake = PQXDH** (Signal's post-quantum X3DH): combine `X25519(DH) ‖ ML-KEM-768(KEM)` into the root key
via HKDF, so an attacker must break **both** ECDH *and* ML-KEM to recover the session. Prekey bundles published
to a `PrekeyDO`/D1 include: identity key, signed prekey, one-time prekeys, **and one-time ML-KEM
encapsulation keys** (Kyber prekeys), all rotated.

**Ratchet = Triple Ratchet (SPQR-style):**
- Symmetric-key ratchet (per-message keys) → **forward secrecy**.
- Classical DH ratchet (X25519) → **post-compromise security**.
- **Sparse Post-Quantum Ratchet**: chunked ML-KEM public keys / encapsulations amortized across message headers
  (a full ML-KEM key is too big per message), periodically re-mixing PQ entropy into the root → **PQ PCS**.

Result: FS + PCS + PQ, degrading gracefully — breaking classical *or* quantum alone never fully compromises.
Implementation: fork/bind `libsignal` PQXDH + our SPQR module, or port to `vortic-core`.

---

## 5. Groups — MLS (RFC 9420), not Sender Keys

For groups we use **MLS** (`mls-rs`, WASM) for logarithmic-cost **post-compromise security** as membership
churns — a member removed at epoch N cannot read epoch N+1, cryptographically.

- **Ciphersuite:** start `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; move to a **hybrid PQ ciphersuite**
  (X25519+ML-KEM DHKEM) as `mls-rs` PQ suites stabilize.
- **Delivery Service (DS):** MLS assumes an ordering/fan-out DS. Ours is a **`GroupDO`** (Durable Object) that
  orders `Commit`/`Application` messages **blindly** — it sees ciphertext + epoch, never plaintext or
  member identities.
- **Authentication Service (AS):** replaced by membership proofs — you join by presenting a valid enrollment
  credential + Semaphore proof, so the group roster is **anonymous credentials, not identities.**

### Anonymous authorship — linkable ring signatures
On top of MLS, a member can post as **"someone in this group"** using a **bLSAG linkable ring signature**
(Ristretto255) over the current member public-key set:
- **Anonymity:** verifiers learn a real member signed, not who.
- **Linkability tag** keyed by `H(group ‖ epoch)`: two posts by the same author in an epoch share a tag →
  **spam/abuse control and rate-limits without deanonymization.** Rotates each epoch to prevent long-term linkage.
Use case: whistleblower channels, anonymous polls, "confession" rooms inside a known membership.

---

## 6. Sealed Sender++ (fixing Signal's leak)

Signal's Sealed Sender is undone by delivery receipts + traffic analysis (deanon in ~5 msgs). Vorticity's
envelope:

1. **Sender field encrypted to recipient** (as Signal) — server sees no `from`.
2. **Pairwise queue transport** (§7): the envelope lands in a per-connection queue with a rotating opaque ID —
   no account identifier on the wire, so cross-conversation correlation has no join key.
3. **Receipts padded, delayed, decoupled:** delivery/read receipts are (a) fixed-size, (b) randomly delayed
   within a bucket, (c) sent as *independent* sealed messages on a *different* queue, breaking the tight
   request↔receipt timing that the attacks exploit.
4. **Constant-size envelopes** via length padding to power-of-two buckets; **timestamps bucketed** server-side.
5. **Optional cover traffic**: clients may emit decoy sealed messages to their own queues (paranoid mode).

---

## 7. Transport identity — pairwise unidirectional queues (SimpleX model)

- A connection between two parties uses **two** queues (A→B, B→A), each a **`QueueDO`** addressed by a
  **rotating opaque 128-bit queue ID** unrelated to any account.
- Server role per queue: *accept push, hold ciphertext ≤ TTL, deliver on subscribe, delete.* It cannot see who
  owns a queue, who the peer is, or how queues relate.
- **Queue IDs rotate** on a schedule / after N messages; old IDs are abandoned. No durable identifier ever
  touches the wire — beating Session/Threema's stable-ID model.

---

## 8. Public aliases & Proof-of-Work discovery (opt-in)

Aliases add mass-market contact discovery **without** a searchable identity directory. **Default: every profile
is undiscoverable.** A user may opt in by claiming a unique `@nickname`. The guarantee we keep: the host may
learn `@nickname → intro-queue`, but **never** `@nickname → email / PPID / handle / the owner's real queues`.
Aliases relax the *discovery* axis (opt-in), never the *identity-linkage* axis. The alias plane lives **entirely
in the Messaging Plane** — it has no binding to `DB_ENROLL`.

### 8.1 Record derivation (inert to a raw DB dump)
An alias record is keyed by a hash and its value is encrypted under a key derivable only from the nickname, so a
dump of `AliasDO`/D1 is useless without brute-forcing the nickname:
```
lookup_key = H("vortic-alias-v1" || nickname)                 // what the DO indexes on (no plaintext nick stored)
rec_key    = HKDF("vortic-alias-enc" || nickname)             // symmetric; derivable only if you know the nickname
record     = AEAD_enc(rec_key, { intro_queue_id, alias_pub, flags, pow_bits })
stored:      lookup_key  ->  record   (+ alias_pub, registered_epoch)
```
The DO holds `lookup_key → ciphertext`; it cannot read `intro_queue_id` without the nickname. **Residual (must
document):** human nicknames are low-entropy, so a host holding the DB can mount an *offline dictionary attack*
to recover nickname→intro-queue pairs. We accept this — aliases are public *by intent* — and mitigate with PoW
on the live path, a capability gate, and a high-entropy-nickname recommendation for sensitive personas. Crucially
the **identity-linkage guarantee is unaffected**: even a fully brute-forced record yields only an intro-queue, never
email/PPID/handle. That guarantee is cryptographic, not dictionary-dependent.

### 8.2 Ownership
`alias_key` (Ed25519) is generated at registration and is a **per-persona** key, unrelated to the account or the
messaging handle. Every mutating op (register, re-point the intro-queue, change `pow_bits`, revoke) carries a
signature under `alias_key`; the DO verifies it and still learns nothing about identity. `alias_key` is included in
the E2EE backup so ownership survives device loss. Bind it into **Key Transparency (K8)** so a malicious server
can't silently swap the key behind a `@nickname`.

### 8.3 Proof-of-Work stamps (Hashcash family)
Both **resolve** and **write-to-intro-queue** require a client-minted PoW stamp bound to the target and to a time
epoch, so stamps can't be precomputed indefinitely or replayed across targets:
```
stamp    = ver : alg : bits : epoch : resource : salt : counter
valid    ⇔  leading_zero_bits( Hpow(stamp) ) ≥ bits
resource =  lookup_key            (resolve)   |   intro_queue_id   (write to intro queue)
epoch    =  ⌊unix / 3600⌋         (server accepts ±1 epoch)
Hpow     =  SHA-256   (baseline: verify ≈ µs)   |   Argon2id   (hardened: memory-hard, botnet/GPU-resistant)
```
- **Verification is a single hash → negligible Worker CPU.** PoW is the *inverse* of ZK on cost: cheap to check,
  expensive to mint — exactly what the edge wants (contrast R1). Spent stamps are recorded per-epoch in
  `AliasDO`/`RateGateDO` to block replay.
- **Difficulty is adaptive & per-target:** resolve ≈ 18–22 bits (~0.1–1 s on a phone), write ≈ 20–24 bits
  (~1–4 s), one-time registration ≈ 24–26 bits. A high-value alias may raise its own `pow_bits`; the DO raises
  global bits under load. Under active attack, switch to **challenge-response** (server issues a fresh `salt`) to
  kill precomputation.
- **Economics:** harvesting the namespace costs ≈ `Σ_nick 2^bits` hashes *and* one enrolled account per actor;
  combined with encrypted records this makes bulk scraping/spam uneconomical. Honest limit: a botnet can still
  grind a *specific* known nickname — PoW raises cost, it is not a wall (see [06](06-roadmap-and-risks.md) R15–R16).

### 8.4 Two gates on every alias action
An action against the alias plane must satisfy **both**: (1) a valid **session capability** (⇒ the actor is an
enrolled Xfeatures member — itself account-costly and Sybil-limited), and (2) a valid **PoW stamp** bound to the
target. Spam and enumeration must therefore pay in *accounts* **and** in *CPU*. Reaching an alias only drops an
**approval-gated** sealed request into a disposable intro-queue — it never reveals the owner and never opens an
ongoing channel by itself (see [04](04-serverless-architecture.md) Flows 5–6).

## 9. Multi-device & sync — encrypted CRDT op-log

- Per-conversation state (messages, read markers, drafts, reactions, pins) is a **CRDT** (Yjs or Automerge).
- CRDT updates are **E2EE**, then appended as opaque blobs to a **`ConvLogDO`** which only assigns a
  monotonic sequence and fans out. **The server orders ciphertext; clients merge.** No server-side merge, no
  server-visible state — true offline-first multi-device without leaking to the host.
- New device onboarding = MLS/ratchet device addition + replay of the encrypted op-log; **no plaintext history
  ever leaves a device unencrypted.**

---

## 10. Media

Client encrypts each file with a random **content key** (AES-256-GCM), chunked (e.g., 1 MiB frames, per-frame
nonce) for streaming and integrity. Ciphertext uploaded to **R2 via presigned PUT** (multipart for large).
The **content key travels only inside the E2EE message.** R2 object = ciphertext blob, generic content-type,
size padded. Server can host and serve but never decrypt, thumbnail, or classify.

---

## 11. Backups — local-first, E2EE

- **Recovery phrase:** BIP39 (24 words) → seed → Argon2id-stretched → master backup key.
- **Local export:** full state (identity keys, ratchet state, message DB) encrypted with the master key
  (AES-256-GCM), exportable to file.
- **Optional cloud copy:** the *same ciphertext* blob may be stored in R2 keyed by an opaque backup ID; the
  server holds an unreadable blob. Restore = re-enroll (blinded) + phrase → decrypt.
- **Forward-secret backup option:** rotating backup keys so an old exfiltrated backup can't decrypt newer state.

---

## Crypto invariants (enforced/reviewed)

1. No primitive with a single point of failure — **always hybrid** on the confidentiality path.
2. Nonces never reused (per-key deterministic counters or 192-bit random for XChaCha).
3. All comparisons of secrets are **constant-time**; all key material `zeroize`d on drop.
4. The **edge only ever *verifies*** (Groth16, ring sigs, OPRF-DLEQ) and holds **no decryption keys**, ever.
5. Circuit + verifier keys are pinned, versioned, and reproducibly built; a trusted-setup ceremony (Groth16)
   or migration to a **transparent-setup system (PLONK/Halo2)** is tracked as a risk (see [06](06-roadmap-and-risks.md)).
6. Public aliases are **opt-in and default-off**; an alias record stores no identity and no plaintext nickname,
   and every alias action is gated by capability **and** PoW (§8). Non-participating profiles stay fully
   undiscoverable — the network's default remains "invisible."
