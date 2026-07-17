# 05 — Features & Killer Features

## Must-have (parity + the privacy floor)

| Area | Feature | Notes |
|---|---|---|
| Messaging | 1:1 & group chat, media, replies, reactions, edits, threads | CRDT-backed; offline-first |
| Crypto | E2EE by default (no toggle), FS + PCS, hybrid PQC | Triple Ratchet (1:1), MLS (groups) |
| Identity | Xfeatures OAuth onboarding → anonymous handle | Blinded enrollment; no phone/email on wire |
| Multi-device | Encrypted CRDT sync, device add/revoke | MLS device add; op-log replay |
| Media | Encrypted images/video/files/voice notes | R2 presigned, chunked AES-GCM |
| Disappearing | Per-chat timers, view-once, screenshot flag | Enforced client-side + TTL server-side |
| Backups | Recovery phrase, local export, optional blind cloud | Argon2id + AES-GCM |
| Presence | Opt-in typing/online, sealed | Off by default (metadata hygiene) |
| Discovery | **Opt-in public `@aliases`** (default: invisible) + OOB capsules/QR | PoW-gated resolve; alias → disposable intro-queue only |
| Safety | Block, report (client-signed), spam control via nullifiers/ring tags/PoW | No central identity to report *to* |
| Verification | Safety-number / key-transparency style contact verification | QR + numeric; key change alerts |

## Killer features (for geeks & security people)

### K1 — **Pre-Session Security Gate** (the environment attestation) *(your idea, specced below)*
A scored client-side attestation on every new session: VPN, DNS, WebRTC leak, clock skew, root/devtools, TLS
posture, entropy. Full spec in the next section.

### K2 — **Sovereign / Ephemeral Identities**
Generate *multiple, unlinkable* handles from one Xfeatures account (each is its own blind enrollment). A
"burner" identity for a single conversation that self-destructs (commitment abandoned, keys wiped). Great for
sources/whistleblowers. Because linkage is cryptographic, even Vorticity can't merge them.

### K3 — **Anonymous group authorship rooms**
Post as "a verified member of this group" via linkable ring signatures (K→ [03](03-crypto-core.md#anonymous-authorship--linkable-ring-signatures)).
Anonymous polls, confessions, whistleblower channels — with per-epoch spam tags, no deanonymization.

### K4 — **Duress / Panic system**
- **Duress passphrase** unlocks a decoy vault (separate CRDT root) with plausible innocuous chats.
- **Panic wipe**: gesture / key-combo / dead-man's-switch (no unlock in N days → local secure-wipe of keys →
  history unrecoverable, forward secrecy already protects the past).
- **Silent panic**: opens decoy while emitting a signed "duress" beacon to pre-chosen contacts.

### K5 — **Metadata Diagnostics ("what the server sees")**
A live inspector showing the *actual* bytes/fields Cloudflare receives for your session — opaque queue IDs,
size buckets, ciphertext lengths — proving the zero-knowledge claim to the paranoid. Ships as a verifiable,
open panel; radical transparency as a feature.

### K6 — **Cover traffic / "Chaff" mode**
Opt-in constant-rate decoy sealed messages to your own queues to flatten timing side-channels (mitigates the
A7 traffic-analysis ceiling). Configurable rate/battery budget.

### K7 — **Local-first, self-verifying builds**
- Reproducible builds + **binary transparency** (published hashes) so the shipped client matches audited source.
- Optional **subresource/circuit pinning**: the client refuses ZK circuits / WASM whose hash isn't the pinned,
  audited one — defeats a compromised-CDN swap attack.

### K8 — **Key Transparency log**
Append-only, auditable log of identity-key↔handle bindings (CONIKS/Key-Transparency style) so a malicious
server can't silently MITM by injecting a fake key — clients detect equivocation.

### K9 — **Post-quantum "Harvest Shield" indicator**
Per-chat badge showing the live crypto posture (classical-only / hybrid-PQ / PQ-ratcheted) so power users can
require PQ before sending. Educates and enforces.

### K10 — **Sealed contact requests via out-of-band capsules**
SimpleX-style one-time invite links / QR "capsules" that bootstrap a pairwise queue with no directory lookup —
no searchable user directory exists to leak.

### K11 — **Scriptable / CLI client + local API**
A headless `vortic` CLI and a localhost API (capability-gated) so security teams can automate, run bots in
air-gapped setups, and audit. Geek catnip; also enables bridges you control.

### K12 — **Timed trust & "read-once" secrets**
Send a secret (password, key) that decrypts exactly once and is provably destroyed (key deleted from ratchet
after single use), with a tamper-evident "opened at" receipt.

### K13 — **Public Aliases (opt-in discovery)** *(mass-market UX, without a directory)*
Default is total invisibility. A user may claim a unique `@nickname` that resolves **only** to a *disposable
intro-queue* — never to identity, email/PPID, the messaging handle, or their real conversation queues. This
removes the reliance on QR/OOB links for onboarding non-technical users while preserving the linkage guarantee.
- **Cost to reach you = work, not luck.** Resolving *or* messaging an alias forces the sender's client to burn a
  **Proof-of-Work** (Hashcash / Argon2id, bound to target + hourly epoch), *and* to hold a valid session
  capability (⇒ be an enrolled member). Scraping the namespace and mass-spam become economically irrational;
  server-side verification of the PoW is a single cheap hash.
- **Inert database.** Records are stored as `H(nickname) → AEAD(HKDF(nickname), intro-queue)`, so even a full
  `AliasDO`/D1 dump reveals no readable nickname→queue map without an offline dictionary grind — and *never* an
  identity. (See [03 §8](03-crypto-core.md#8-public-aliases--proof-of-work-discovery-opt-in),
  [04 Flows 5–6](04-serverless-architecture.md#flow-5--register-an-opt-in-public-alias).)
- **Reaching ≠ contacting.** A resolved alias only lets you drop an **approval-gated** sealed request; the owner
  decides, and any accepted conversation immediately migrates off the alias onto rotating pairwise queues.
- **Tradeoff, stated plainly:** a public alias is a *deliberate, persistent, human-discoverable* identifier.
  The app warns on opt-in, recommends pairing an alias with an **ephemeral persona (K2)** rather than your whole
  account, and nudges a high-entropy nickname for sensitive users. Complements the directory-less **K10** capsules.

---

## Pre-Session Security Gate — full spec (K1)

**Goal.** Before establishing a session, measure the *environment's* contribution to deanonymization risk,
surface it honestly, and nudge remediation. This is not theater: per [02-threat-model.md](02-threat-model.md)
and [06](06-roadmap-and-risks.md), **network-level correlation is the residual risk ZK can't fix** — so the
user's own VPN/DNS posture is *load-bearing* for the anonymity model.

**Output:** a **Vorticity Secure Score (0–100)** + per-check severity, with a gate:
`OK (≥80) → proceed` · `Warn (50–79) → proceed w/ acknowledgement` · `Critical (<50) → strongly recommend fix`.

### Checks

| # | Check | Method (client) | Severity if bad | Remediation shown |
|---|---|---|---|---|
| 1 | **VPN / egress exposure** | Compare edge-observed egress ASN/geo (returned by a stateless echo) vs expected; heuristics for datacenter vs residential | High | "Enable VPN/Tor — your IP is visible to network observers" |
| 2 | **WebRTC IP leak** | Create `RTCPeerConnection`, enumerate ICE candidates for local/public IP leak | High | "Disable WebRTC / enable leak protection" |
| 3 | **DNS quality** | DoH probe to trusted resolver; detect plaintext/ISP/hijacked resolver, DNSSEC, NXDOMAIN hijack | Medium | "Switch to encrypted DNS (DoH/DoT)" |
| 4 | **Clock skew** | Compare local time to signed edge time | Medium | Skew breaks TOTP/ratchet/nullifier epoch — "sync clock" |
| 5 | **Secure context** | `isSecureContext`, TLS version hints, HSTS, mixed content | High | "Insecure context — do not proceed" |
| 6 | **Devtools / tamper** | Debugger-timing & `devtools-detect` heuristics; integrity of loaded WASM/circuit hashes (K7) | Medium | "Untrusted/modified client detected" |
| 7 | **Root / jailbreak / emulator** (Capacitor) | Native plugin: root, hooking (Frida/Xposed), emulator signals | High | "Rooted/emulated device raises key-theft risk" |
| 8 | **Entropy / RNG health** | Sanity-check `crypto.getRandomValues`, seed availability | High | Abort if RNG suspect |
| 9 | **Screen capture / overlay** | Native: screenshot-block availability, overlay/accessibility abuse detection | Medium | "Enable screen-capture protection" |
| 10 | **Storage isolation** | OPFS/IndexedDB availability, private-mode detection, persistence permission | Low | "Grant persistent storage or use decoy mode" |
| 11 | **Extension surface** (web) | Heuristic count of injected content scripts / DOM mutations pre-load | Low | "Disable untrusted extensions" |
| 12 | **Network reachability of decoys** | Confirm OHTTP relay + cover-traffic path reachable | Low | "Some privacy relays blocked on this network" |

### UX

```
┌───────────────────────────────────────────────┐
│  🌪  Vorticity Secure Score          62 ⚠      │
├───────────────────────────────────────────────┤
│  ⛔  VPN off — your IP is exposed        [Fix] │
│  ⚠   DNS is your ISP's plaintext resolver[Fix] │
│  ⚠   WebRTC may leak local IP            [Fix] │
│  ✅  Clock in sync                             │
│  ✅  Secure context / pinned client            │
│  ✅  RNG healthy                               │
├───────────────────────────────────────────────┤
│  Recommended: enable VPN + encrypted DNS.      │
│  [ Re-check ]   [ Proceed anyway ]  [ Learn ]  │
└───────────────────────────────────────────────┘
```

- Every check links to a **"why this matters"** explainer tied to the actual threat (educational, not scolding).
- Score, raw signals, and reasoning are **local**; only a coarse boolean "gate passed" (if anything) is used
  client-side — **the Gate results never leave the device** (they'd be metadata!).
- **Paranoia profiles:** *Standard / Journalist / Maximum* raise thresholds and auto-enable K6 chaff, force PQ
  (K9), require pinned circuits (K7), disable presence.
- Extensible **rule engine** (declarative checks) so new environment risks ship without a client rewrite.

**Implementation:** a `@vortic/security-gate` TS module + Capacitor native plugins for device-level checks;
results feed a scoring function; the gate is a React route rendered before session auth (Flow 2).
