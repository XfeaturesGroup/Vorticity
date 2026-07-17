# 02 — Threat Model

## Adversary tiers

| Tier | Capability | Assumed for Vorticity? |
|---|---|---|
| **A1 — Network observer** | Sees TLS metadata, IPs, sizes, timing on the wire | Yes |
| **A2 — The host (Cloudflare)** | Reads all D1/R2/DO state, sees Worker inputs incl. client IP, can log & correlate, can be legally compelled | **Yes — primary adversary** |
| **A3 — The identity provider (Xfeatures Account)** | Knows the real user (email), sees OAuth issuance | Yes — must not learn messenger activity |
| **A4 — Malicious peer / group member** | Valid account, tries to deanonymize others, spam, or forge | Yes |
| **A5 — Endpoint compromise (post-hoc)** | Steals device at time T, wants history before T | Yes (forward secrecy) |
| **A6 — Future quantum adversary** | Harvest-now-decrypt-later; breaks classical DH/ECC later | Yes (PQC) |
| **A7 — Global passive adversary + active mixnet attacker** | Nation-state traffic correlation across all links | **Partial** — see non-goals |

**Primary adversary is A2, the host itself.** Vorticity's central claim is *"even Cloudflare, with full
database and Worker access and a court order, cannot link email↔handle↔messages."* Every design decision is
graded against A2.

## Trust boundaries

```
 Real identity  │  Anonymity set  │  Ciphertext plane
────────────────┼─────────────────┼────────────────────
 Xfeatures       │  Blinded cred    │  Semaphore handle
 Account (A3)    │  + ZK proof      │  + pairwise queues
 knows email     │  (the airlock)   │  server sees opaque IDs only
        ▲                 ▲                    ▲
        └── OAuth only ───┘                    └── E2EE payload, sealed sender
```

- **The airlock is a blind signature.** Information must not flow left→right in a linkable form. The
  Enrollment Plane may know "email X enrolled" (PPID) but must never learn "email X → handle H".
- **The ciphertext plane is zero-knowledge to the host by construction**, not by policy.

## Security goals (what we guarantee)

| ID | Goal | Mechanism |
|---|---|---|
| G1 | Message confidentiality & integrity | E2EE: Triple Ratchet (1:1), MLS (groups) |
| G2 | Forward secrecy | Symmetric ratchet, MLS epoch keys |
| G3 | Post-compromise security | DH ratchet (1:1), MLS tree updates (groups) |
| G4 | Post-quantum confidentiality | Hybrid ML-KEM-768 + X25519 (PQXDH), SPQR |
| G5 | Email↔handle unlinkability vs host | Blinded enrollment + Semaphore ZK; no join key in D1 |
| G6 | Sender anonymity vs host | Sealed Sender++ + pairwise queues |
| G7 | Social-graph invisibility vs host | Pairwise unidirectional queues (no user IDs on wire) |
| G8 | Sybil resistance without identity | PPID double-enroll guard + per-epoch nullifiers |
| G9 | Anonymous authorship in groups | Linkable ring signatures |
| G10 | IP unlinkability vs host | OHTTP relay in front of Messaging Plane |
| G11 | Recoverable without linkage | Blinded re-enrollment + E2EE backup phrase |
| G12 | Media confidentiality | Client-side chunked AES-GCM before R2 |

## Explicit non-goals (state them, don't pretend)

- **N1 — Global traffic-analysis resistance (A7).** We are not Tor+mixnet. A global passive adversary that
  watches *both* the client's uplink and Cloudflare's edge can attempt end-to-end timing correlation. We
  *raise cost* (OHTTP, padding, batched/delayed receipts, cover traffic option) but do not claim defeat.
  This is the honest ceiling and must be stated to users.
- **N2 — Endpoint security.** A live-compromised device (keylogger, screen scraper, malware with our keys in
  memory) is game over for that device's data. We mitigate with local encryption at rest, screen-capture
  flags, and the Security Gate — we don't claim to beat local malware.
- **N3 — Metadata against the IdP (A3) for the fact of enrollment.** Xfeatures Account necessarily knows
  "this email created a Vorticity credential at time T." It must never learn anything past the airlock.
- **N4 — Availability against the host.** Cloudflare can deny service (take us down). We defend
  confidentiality/anonymity, not censorship-resistance of availability. (A future P2P/relay-diversification
  track can address this — see roadmap.)
- **N5 — Deniability guarantees beyond ratchet-level.** Full cryptographic deniability (OTR-style) is a
  stretch goal, not a v1 promise.
- **N6 — The enrollment<->messaging Plane Bridge (RSABSSA) is not post-quantum.** RSA Blind Signatures
  (RFC 9474, see [03](03-crypto-core.md) §2) replaced VOPRF for the redemption-token bridge because a VOPRF
  evaluation cannot be verified by a third party without a shared secret — RSABSSA can, with only a public
  key, which is what the plane-isolation invariant actually requires. RSA-3072 is not quantum-resistant; a
  future quantum adversary (A6) that breaks RSA could forge a redemption signature. This is an accepted
  tradeoff, not an oversight: the token is single-use and immediately nullified at redemption
  (`issuer_token_null`, DB_MSG) — there is no ciphertext or long-lived secret this signature protects, so
  harvest-now-decrypt-later has nothing to harvest here. (Everything on the actual message-confidentiality
  path — G4, the PQXDH hybrid handshake — remains fully PQ-hybrid; this non-goal is scoped narrowly to the
  one-time enrollment token, not to any ongoing secrecy guarantee.)

## Data-at-rest classification (what may touch D1/R2/DO)

| Class | Examples | Allowed on host? |
|---|---|---|
| **PII** | email, OAuth `sub`, name, avatar | **NEVER** on the Messaging Plane. Enrollment Plane: only `PPID = HMAC(secret, sub)`. |
| **Linkable pseudonym** | handle↔email map, device↔email map | **NEVER stored anywhere.** Does not exist by construction. |
| **Opaque routing IDs** | rotating queue IDs, Merkle root, nullifiers, `issuer_token_null` (H(msg) of a spent RSABSSA redemption token — see [03](03-crypto-core.md) §2, DB_MSG) | Yes — unlinkable to identity |
| **Ciphertext** | messages, media, CRDT ops, encrypted backups | Yes — server has no keys |
| **Coarse ops metadata** | blob sizes (padded), timestamps (bucketed) | Yes, minimized/padded |

**Invariant enforced in CI:** a schema-lint test fails the build if any D1 column or R2 key can hold PII or a
cross-plane join key. See [04-serverless-architecture.md](04-serverless-architecture.md#d1-schema-zero-pii).
