# Vorticity — Architecture & Engineering Dossier

> **Xfeatures — Vorticity**: a closed, metadata-hostile communications network. E2EE by default,
> post-quantum from day one, and engineered so that **Cloudflare (the host) cannot cryptographically
> link an Xfeatures Account (email) to a messenger identity, session, or message.**
>
> Part of **XfeaturesGroup**. Strictly proprietary.

This folder is the design authority for the rebuild. The legacy monolith (conventional social network,
email stored in D1, sessions bound to `user_id` — the anti-pattern Vorticity destroys) has been deleted;
the OAuth mechanics and binding shapes worth keeping were extracted first to
[docs/legacy-reference/](legacy-reference/). The real monorepo scaffold now lives at repo root — see
[../README.md](../README.md) for the layout (`apps/`, `packages/`, `workers/`).

## Reading order

| # | Doc | What it answers |
|---|-----|-----------------|
| 01 | [research-and-competitors.md](01-research-and-competitors.md) | Signal / Session / Matrix / Threema / SimpleX teardown. Where each leaks. How Vorticity wins. |
| 02 | [threat-model.md](02-threat-model.md) | Adversary tiers, trust boundaries, security goals & explicit non-goals. |
| 03 | [crypto-core.md](03-crypto-core.md) | Identity, hybrid PQC ratchet, MLS groups, Sealed Sender++, ring signatures, ZK membership, blinded enrollment, E2EE backup. |
| 04 | [serverless-architecture.md](04-serverless-architecture.md) | Workers / Durable Objects / D1 / R2 topology. All flows as Mermaid. Unlinkable D1 schema. |
| 05 | [features-and-killer-features.md](05-features-and-killer-features.md) | Must-haves + killer features. The **Pre-Session Security Gate** (env attestation) spec. |
| 06 | [roadmap-and-risks.md](06-roadmap-and-risks.md) | Phased roadmap + risk register. The ZKP↔Workers coupling risk, quantified. |
| 07 | [ui-design-system.md](07-ui-design-system.md) | What was inherited from Xfeatures HQ + Xfeatures Web, decisions where they disagreed, bugs fixed rather than propagated. |

## The 12 decisions that define Vorticity (TL;DR)

1. **Two-plane split.** An *Enrollment Plane* (sees OAuth/email, mints anonymous credentials) is
   cryptographically and operationally severed from a *Messaging Plane* (sees only opaque IDs + ciphertext).
   The only bridge is a **blind signature**, so the messaging identity is never revealed to the enroller.
2. **Unlinkability = blinded tokens + Semaphore ZK membership**, not trust. Enrollment stores a one-way
   **PPID** (`HMAC(secret, oauth_sub)`) *purely* for sybil/double-enroll defense — never linked to a handle.
3. **PQC by default, hybrid.** X3DH→**PQXDH** (ML-KEM-768 + X25519) handshake; **Triple Ratchet** style
   (Double Ratchet + Sparse PQ Ratchet) for 1:1. Classical break OR quantum break alone is survivable.
4. **Groups on MLS (RFC 9420)** for real post-compromise security at scale — not naive Sender Keys.
5. **Sealed Sender++**: we fix Signal's documented receipt/traffic-analysis deanonymization (deanon in
   as few as 5 messages) with padded, delayed, decoupled receipts + queue isolation.
6. **Ring signatures (linkable, LSAG)** for anonymous-author group posts with per-epoch spam control.
7. **SimpleX-style pairwise queues** as the transport: no user IDs on the wire, two unidirectional queues
   per connection, each a **Durable Object** addressed by a rotating opaque queue ID.
8. **`Cloudflare Pub/Sub is retired`** (private beta ended 2025-08-20). Real-time fan-out is **Durable
   Objects + WebSocket Hibernation** (+ `@cloudflare/actors`), not Pub/Sub. This is a hard correction to the brief.
9. **CRDT sync (Yjs/Automerge) over an encrypted op-log.** The server is a blind ordered sequencer
   (a per-conversation DO log of opaque ciphertext); clients do all merging. Server never sees state.
10. **Media = R2 presigned + client-side chunked AES-GCM.** Server stores ciphertext blobs with no
    content-type, no thumbnails it can read, no plaintext ever.
11. **OHTTP / Oblivious relay in front of the Messaging Plane** so the Worker never sees the client IP —
    because ZK hides *cryptographic* linkage, not *network* linkage. This is load-bearing, not cosmetic.
12. **Pre-Session Security Gate**: every new session runs a client environment attestation (VPN, DNS,
    WebRTC leak, clock skew, root/devtools, entropy…) and scores it. The VPN nudge is part of the
    anonymity model (see #11), not theater.

## Hard risk to internalize now

**ZK proofs break cryptographic linkability; they do nothing about network-level correlation.** If the
same Cloudflare account hosts both planes, a compelled/malicious platform can attempt IP+timing correlation
between an enrollment call and the first Merkle insertion. The mitigation stack is OHTTP + temporal
decoupling + the user's own VPN/Tor (hence the Gate). Verifier cost (~0.75–0.9 s CPU in snarkjs WASM)
forces us to **verify membership once per session to mint a capability**, never per message. Both points are
expanded in [06-roadmap-and-risks.md](06-roadmap-and-risks.md).

## Stack (strict)

- **Frontend:** TypeScript · React · Vite (UI kits inherited from *Xfeatures main site* + *Xfeatures HQ* — paths pending).
- **Edge:** Cloudflare Workers (paid) · Durable Objects (SQLite-backed, Hibernation) · D1 · R2.
- **Auth:** Xfeatures Account OAuth2 only — <https://account.xfeatures.net/docs/oauth2>.
- **Crypto in WASM:** Rust → `wasm-bindgen` (ML-KEM via kyberlib/ml-kem, MLS via mls-rs/OpenMLS, Groth16 verifier).
