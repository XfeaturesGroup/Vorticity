# 01 — Competitive Teardown & Technology Research

Analysis altitude: architecture and metadata, not UX. For each competitor we state the **structural weakness**
(not a bug — a design property) and the **Vorticity counter**.

---

## 1. Signal

**Model.** Phone-number identity. X3DH + Double Ratchet (now **PQXDH** with ML-KEM-768, and as of
2025-10-02 the **Triple Ratchet / SPQR** — Double Ratchet mixed with a Sparse Post-Quantum Ratchet).
Sealed Sender hides the *sender* from the server. Groups use Sender Keys + private group state.

**Structural weaknesses.**
- **Identity = phone number.** A permanent, real-world identifier and social-graph seed. Contact discovery
  historically leaked (SGX-based Private Contact Discovery is a mitigation, not an elimination).
- **Sealed Sender is porous.** Delivery receipts cannot be disabled and are on by default; academic work
  (UMD, NDSS'21; "No safety in numbers", 2023) shows the server can **relink sealed-sender users in as few
  as ~5 messages** via timing/receipt traffic analysis. Sealed Sender protects the *from* field, not the
  *observable delivery pattern*.
- **Centralized, single-operator.** One infrastructure operator sees all envelope metadata (who-connects,
  when, size, IP) even if content and sender are hidden.
- **Groups still leak to well-placed observers** (fan-out timing, receipts).

**Vorticity counter.** No phone number — identity is a **Semaphore commitment** unlinkable to the OAuth
account. **Sealed Sender++**: receipts are padded, delayed, and decoupled from the message path, and each
conversation rides **isolated pairwise queues** (SimpleX model) so cross-conversation timing correlation has
nothing to join on. Adopt Signal's *crypto* (PQXDH/Triple Ratchet) wholesale — it's best-in-class — and beat
its *metadata* posture.

---

## 2. Session (Oxen)

**Model.** No phone/email. Ed25519 "Session ID" (a long-term public key) as the account. Routes over the
**Oxen onion service network** (Lokinet-derived) with swarms of service nodes storing messages. Dropped
Perfect Forward Secrecy for a while (used a simplified session protocol) — has been re-adding ratcheting.

**Structural weaknesses.**
- **The Session ID *is* a stable long-term identifier.** Anonymous at signup, but every contact you give it to
  can correlate you forever; it's a persistent pseudonym, not per-connection isolation.
- **Onion routing ≠ metadata-free.** Better than centralized, but timing correlation across the service-node
  swarm and the economic/Sybil surface of a token-incentivized node set are real.
- **PFS/PCS history is spotty** relative to Signal's ratchet.
- **Blockchain/token coupling** adds an availability and governance dependency unrelated to messaging.

**Vorticity counter.** Rotating **pairwise** queue IDs instead of one global Session ID — a contact learns a
queue, not a durable identity, and queues rotate. We keep a **full modern ratchet (Triple Ratchet)** rather
than trading PFS for routing. We get onion-like IP hiding from **OHTTP relays** without a token economy.

---

## 3. Matrix

**Model.** Federated. Olm/Megolm (Double Ratchet + group ratchet). Homeservers replicate room state as a
**DAG**. Strong multi-device, rich ecosystem, bridges.

**Structural weaknesses.**
- **Metadata lives in the clear on homeservers.** Room membership, display names, timestamps, reactions,
  read markers, profile data, and the room DAG are visible to (and replicated across) homeservers. This is
  Matrix's best-known and most-cited privacy failure.
- **Megyalgo footguns.** Megolm session-key sharing, device verification friction, and historical
  key-share/UISI ("Unable to decrypt") issues.
- **Federation amplifies exposure** — your metadata is copied to every server your rooms touch.
- Encryption is **opt-in per room** historically, not a universal invariant.

**Vorticity counter.** We are **closed, not federated** — deliberately. No metadata DAG replicated to
untrusted servers. Group *membership itself* is a **Merkle set the server can't read as identities**, and
group state syncs as an **encrypted CRDT op-log** the server can only order, never interpret. E2EE is a
non-negotiable invariant, never a per-room toggle.

---

## 4. Threema

**Model.** Paid, no phone/email required. Random 8-char Threema ID. NaCl (X25519 + XSalsa20-Poly1305).
Swiss jurisdiction. Servers relay and forward-delete.

**Structural weaknesses.**
- **Server-trust for contact/graph handling.** The server brokers ID↔public-key lookups and message routing;
  you trust Threema's operational promises (forward deletion, minimal logging) rather than a cryptographic
  guarantee that it *can't* retain them.
- **No forward secrecy at the message layer for a long time** (added later; historically the long-term key
  pair did a lot of work) — compromise of the long-term key was catastrophic for stored ciphertext.
- **Closed but centralized**; the ID is a stable identifier like Session's.
- Group crypto is simpler than MLS (no efficient PCS at scale).

**Vorticity counter.** Replace "trust our promise not to keep it" with "we architecturally can't keep it":
opaque queue IDs, ZK membership, sealed sender. Full ratchet + MLS PCS instead of long-term-key reliance.

---

## 5. SimpleX Chat — the metadata benchmark to beat/borrow

**Model.** **No user identifiers of any kind — not even random ones.** Identity is replaced by **temporary
anonymous pairwise identifiers of unidirectional message queues**: two separate queues per connection, each
potentially on a different relay; relays pass messages one-way and hold nothing about the user's other
connections. Timestamps/metadata are sealed inside the envelope.

**Weaknesses.** UX cost of "no accounts" (connection bootstrap via links/QRs, multi-device is hard, backup/
restore is awkward). Relay-availability and out-of-band connection establishment are the usability tax.

**What Vorticity steals.** The **pairwise-queue transport** is the single best metadata idea in the field —
we implement it natively as **Durable Objects** (one DO per queue, addressed by a rotating opaque ID). What
Vorticity *adds on top*: a real account layer (Xfeatures OAuth) for onboarding, recovery, and anti-Sybil —
**without** reintroducing linkable identifiers, thanks to blinded enrollment + ZK. We get SimpleX's wire-level
anonymity **and** a usable account/recovery story.

---

## Scorecard

| Property | Signal | Session | Matrix | Threema | SimpleX | **Vorticity (target)** |
|---|---|---|---|---|---|---|
| No real-world identifier | ✖ (phone) | ✔ (stable ID) | ~ (server-side) | ✔ (stable ID) | ✔✔ (none) | ✔✔ (ZK, per-conn) |
| Per-connection ID isolation | ✖ | ✖ | ✖ | ✖ | ✔✔ | ✔✔ |
| Sender hidden from server | ~ (porous) | ✔ (onion) | ✖ | ✖ | ✔ | ✔ (Sealed++ ) |
| Server *cannot* learn social graph | ✖ | ~ | ✖ | ✖ | ✔ | ✔✔ |
| Post-quantum (default) | ✔ (2025) | ✖ | ✖ | ✖ | ~ (adding) | ✔✔ (hybrid) |
| Group post-compromise security | ~ (Sender Keys) | ~ | ~ (Megolm) | ✖ | ~ | ✔ (MLS) |
| Anonymous authorship in groups | ✖ | ✖ | ✖ | ✖ | ✖ | ✔ (ring sigs) |
| IP hidden from host | ✖ | ✔ | ✖ | ✖ | ~ | ✔ (OHTTP) |
| Account-based recovery w/o linkage | n/a | ✖ | ✖ | ✖ | ✖ | ✔ (blinded) |

`✔✔` = structural guarantee, `✔` = supported, `~` = partial/opt-in, `✖` = absent.

**Thesis:** *No shipping product simultaneously offers SimpleX-grade wire anonymity, Signal-grade PQC crypto,
MLS-grade group PCS, and an account/recovery layer. Vorticity's differentiator is combining all four — the
account layer without the linkability, via blinded enrollment + ZK membership.*

---

## Technologies selected for adoption (research output)

| Concern | Choice | Why |
|---|---|---|
| PQ KEM | **ML-KEM-768** (FIPS 203) hybrid w/ X25519 | NIST-final; WASM-ready (kyberlib-wasm ~120 KiB, ml-kem crate, noble-post-quantum). Hybrid = defense in depth. |
| 1:1 ratchet | **Triple Ratchet / SPQR-style** | Signal's Oct-2025 design; FS + PCS + PQ, silent. |
| Group protocol | **MLS (RFC 9420)** via `mls-rs` / OpenMLS | Tree-based PCS for thousands; production Rust → WASM. |
| ZK membership | **Semaphore v4** (Lean IMT, EdDSA id, Poseidon, Groth16) | Purpose-built anonymous group membership + nullifiers. |
| Anonymous enrollment | **RSA Blind Signatures (RSABSSA)** (RFC 9474) | Unlinkable "I'm an enrolled member" credential. |
| Anon authorship | **Linkable ring signatures (LSAG/bLSAG)** | Sender-in-set anonymity + per-epoch spam linkability. |
| Transport | **SimpleX-style pairwise queues** on Durable Objects | No user IDs on the wire; graph invisibility. |
| Real-time | **Durable Objects + WebSocket Hibernation** + `@cloudflare/actors` | Pub/Sub is retired; DO hibernation makes idle sockets ~free. |
| State sync | **Yjs or Automerge CRDT** over encrypted op-log | Offline-first multi-device; server orders blind ciphertext. |
| IP privacy | **OHTTP (Oblivious HTTP) relay** | Host never sees client IP; closes the network-linkage gap ZK can't. |
| Backups | **Argon2id + AES-GCM, BIP39 recovery phrase**, optional blind R2 blob | Local-first E2EE backup; server-stored copy unreadable. |

**Sources:** [Signal SPQR](https://signal.org/blog/spqr/) · [Quarkslab: Triple Ratchet](https://blog.quarkslab.com/triple-threat-signals-ratchet-goes-post-quantum.html) · [Improving Sealed Sender (NDSS'21)](https://www.cs.umd.edu/~kaptchuk/publications/ndss21.pdf) · [No safety in numbers](https://arxiv.org/pdf/2305.09799) · [SimpleX](https://github.com/simplex-chat/simplex-chat) · [Semaphore v4](https://github.com/semaphore-protocol/semaphore/releases/tag/v4.0.0) · [RFC 9420 (MLS)](https://datatracker.ietf.org/doc/html/rfc9420) · [mls-rs](https://github.com/awslabs/mls-rs) · [Matrix E2EE/metadata](https://matrix.org/docs/matrix-concepts/end-to-end-encryption/)
