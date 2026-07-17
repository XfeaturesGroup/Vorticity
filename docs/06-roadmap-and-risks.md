# 06 — Roadmap & Risk Register

Phased so that **crypto correctness and the unlinkability invariant are proven before any UI**. Each phase has
a hard **exit gate**; nothing downstream starts until the gate is green. Durations are engineering-effort
bands, not calendar promises.

## Phase 0 — Foundations & monorepo (S) — ✅ scaffolded
- Legacy app deleted; OAuth mechanics + binding shapes extracted first to `docs/legacy-reference/`.
- pnpm monorepo live: `apps/web`, `apps/mobile` (Capacitor placeholder, real scaffold deferred to Phase 4),
  `packages/vortic-core` (Rust→WASM, feature-gated `client-full`/`edge-verify-only`, both profiles verified
  to `cargo check` clean), `workers/enrollment`, `workers/messaging` (7 Durable Object stubs + D1 migrations
  matching the docs/04 schema), `packages/ui` (tokens + primitives inherited from Xfeatures HQ + Xfeatures
  Web — see [docs/07](07-ui-design-system.md)).
- CI **`schema-lint`** (`scripts/schema-lint.mjs`, zero dependencies) + GitHub Actions workflow wired.
- **Exit — verified, not just asserted:** empty-but-typed skeleton for both Workers exists; `cargo check`
  passes on both `vortic-core` feature profiles; `schema-lint` passes clean on the real migrations, and was
  live-tested against two deliberately-planted violations (an `email` column, a cross-plane `DB_ENROLL`
  binding leaked into `workers/messaging/wrangler.toml`) — both were caught (exit 1) and then reverted.
- **Verified end-to-end in this session:** `pnpm install` succeeded across all 7 workspace projects;
  `pnpm run typecheck` passes clean on `packages/ui`, `apps/web`, `workers/enrollment`, `workers/messaging`
  (two real strict-mode errors found and fixed along the way — a `verbatimModuleSyntax` type-only import,
  and missing `override` modifiers on the Durable Object stubs). `apps/web` was booted with the real Vite
  dev server and `@vorticity/ui`'s tokens confirmed rendering via computed styles (`bg-black/40` →
  `oklab(0 0 0 / 0.4)`, `backdrop-blur-3xl` → `blur(64px)`, `rounded-2xl` → `16px`, matching source exactly)
  — this also caught and fixed a real Tailwind v4 monorepo content-detection gap (see
  [docs/07](07-ui-design-system.md) and `packages/ui/src/styles/theme.css`'s header comment).
- **Still open before Phase 1:** confirm the real IDM API host against
  <https://account.xfeatures.net/docs/oauth2> (see `docs/legacy-reference/README.md` — the legacy code
  disagreed with its own `wrangler.toml` on this); run `wrangler d1 create` for both databases and replace
  the `REPLACE_ME_RUN_WRANGLER_D1_CREATE` placeholders.

## Phase 1 — Crypto core (`vortic-core`) (L) — 🚧 hybrid KEM + basic VOPRF landed
- **Done (2026-07):** hybrid **ML-KEM-768 + X25519** (`kem.rs`) — deterministic from a caller-supplied
  32-byte seed (`ml-kem`'s native `from_seed`/`encapsulate_deterministic` + `x25519-dalek`'s
  `StaticSecret::from(bytes)`; no RNG crate, no `getrandom` WASM backend needed anywhere in the crate).
  Full **VOPRF** (`oprf.rs`, Ristretto255 blind/evaluate/unblind + Chaum-Pedersen **DLEQ** as of the Этап 2
  pass — see the airlock entry in Phase 2 below; the DLEQ that was deferred here is now landed). Real HKDF-SHA256 (`util.rs`). All wasm-bindgen-exported. 5/5 unit tests green
  (KEM sender/receiver agree on root key, keypair round-trips through bytes, VOPRF blind∘evaluate∘unblind
  == direct evaluation). **Verified, not just asserted:** `cargo build --release --target
  wasm32-unknown-unknown` succeeds for both `--features client-full` and `--no-default-features --features
  edge-verify-only`; `cargo tree` confirms `ml-kem`/`x25519-dalek`/`kem` appear only in the `client-full`
  tree and are fully absent from `edge-verify-only` — the plane separation is enforced by the dependency
  graph itself, not just a `#[cfg]` convention.
- **Done (2026-07, "Real WASM" pass):** real symmetric AEAD (`symmetric.rs`) — **ChaCha20-Poly1305**
  (RFC 8439), fresh random 96-bit nonce per message (`getrandom` 0.2 with feature `js` → browser
  `crypto.getRandomValues` on wasm32; inert on native so `cargo test` still builds), wire format
  base64(`nonce‖ciphertext‖tag`). wasm-bindgen exports `encrypt_message`/`decrypt_message`; the real work
  lives in native-testable inner fns (`JsError` construction panics off-wasm), so `cargo test --features
  client-full` covers round-trip, per-message nonce freshness, tamper (tag bit-flip) rejection, and
  short/non-base64 rejection (4/4 green; full suite now 13). **This replaces the Phase-5 transport spike's
  reversible-XOR `mockCrypto.ts`** (deleted). `apps/web` now builds `pkg/client/` via `wasm-pack build
  --target web` and imports it through `js/crypto.ts` (a thin `initCrypto()` + sync `encryptMessage`/
  `decryptMessage` wrapper); `useChatWebSocket.ts` gates the socket on `initCrypto()`. **Verified live:** a
  two-tab QueueDO relay showed base64 ChaCha ciphertext on the wire and correct plaintext in the receiver's
  UI/console — real WASM, not the mock. **Honest gap:** the 32-byte key is still a hardcoded shared demo
  constant — no key agreement yet (that's the PQXDH/ratchet work below); this is real AEAD over a static key,
  not finished E2EE. `pkg/` is a git-ignored build artifact — `pnpm --filter @vorticity/vortic-core build`
  must run once before `apps/web` starts.
- **Done (2026-07, "Dynamic keys" pass — Этап 1): the hardcoded chat key is GONE.** `kem.rs` gained plain
  X25519 DH exports `x25519_generate_keypair(seed)` / `x25519_derive_shared(myPriv, theirPub)` (raw DH output
  → HKDF-SHA256 → 32-byte ChaCha key, domain-separated `vortic-x25519-dh-v1`). `symmetric.rs`'s
  `encrypt_message`/`decrypt_message` now take the key as their FIRST arg (no more `DEMO_KEY`). `js/crypto.ts`
  exposes `generateKeyPair`/`deriveSharedSecret` + keyed cipher. `useChatWebSocket.ts` runs a real handshake on
  connect: each peer sends `{type:"handshake",publicKey}`, replies once with `handshake_ack` (covers a late
  joiner; an ack never re-replies, so no loop), derives the shared secret, and only then encrypts. **Verified
  live (two tabs):** both derived the SAME key (`0xae0888f4…` from independent keypairs `0xbd00a956`/`0x602d8778`)
  and a message round-tripped through real ChaCha under it. Honest gaps: unauthenticated DH (MITM-able on first
  contact — needs signed prekeys), no PQ leg in the handshake yet (ml-kem exists but isn't wired into it), no
  ratchet/forward-secrecy. cargo tests: 16 (adds X25519 agreement + wrong-key rejection).
- **Still to implement:** **PQXDH** session-establishment framing around the hybrid KEM, **Triple Ratchet**
  (start from libsignal PQXDH + SPQR module), **MLS** wrapper (`mls-rs`), **bLSAG ring sigs**,
  **Argon2id/BIP39 backup**. VOPRF DLEQ proof (Phase 2 spike, per docs/03 §2).
- WASM boundary fuzzing + NIST ML-KEM KATs; constant-time & `zeroize` audit — deferred (explicitly out of
  scope for this pass; current tests are correctness-only, not fuzz/side-channel hardened).
- **Exit:** interop tests green (two clients ratchet PQ messages, form an MLS group, rotate epochs); backup
  round-trips; `cargo audit` + fuzz corpus clean.

## Phase 2 — ZK membership & the airlock (L, highest risk) — 🚧 edge verifier landed
- **Done (2026-07):** pure-Rust **Groth16/BN254 verifier** (`zk.rs`) — arkworks (`ark-bn254`/`ark-ff`/
  `ark-groth16`, `default-features=false`), 3-pairing verify, no snarkjs. Compiled into **both** profiles
  (verification is edge-safe per invariant #4) and builds clean for `wasm32-unknown-unknown` under
  `--features edge-verify-only` (**~194 KB** unoptimized bundle, pre-`wasm-opt`). Untrusted-input-hardened:
  bounds-checked, `new_unchecked` + explicit on-curve/subgroup validation on every point, returns `false`
  instead of panicking/trapping. wasm-bindgen boundary: `zk_verify_groth16_bytes` / `_hex`. Explicit
  big-endian byte-layout contract documented at the top of `zk.rs` (snarkjs decimal → BE32 → concat), incl.
  the G2 `[c0,c1]` ordering caveat (snarkjs's Solidity-export swap must NOT be applied here). `cargo tree -e
  normal` confirms `ml-kem`/`x25519-dalek`/`kem` absent from the edge binary; `ark-bn254`/`ark-groth16` present.
- **Integration test done (`zk_test.rs`, `#[cfg(test)]`):** generates a *real* Groth16/BN254 proof via
  arkworks (real setup + prover) over a Semaphore-shaped mock circuit (4 public inputs in the documented
  order), serializes VK/proof/inputs into `zk.rs`'s byte contract, and runs them through
  `zk_verify_groth16_bytes`. **4/4 green:** ACCEPT (valid), REJECT (tampered public input → pairing fails),
  REJECT (flipped proof bit), and a `g2_coordinate_order_is_load_bearing` case proving the swapped `[c1,c0]`
  G2 ordering is rejected — i.e. the crate's `[c0,c1]` convention is the correct one. Full suite: 9/9
  (5 Phase 1 + 4 Phase 2). This validates the serialization/parse/verify pipeline and the ordering; it is a
  structurally-equivalent mock, **not** Semaphore's real Poseidon/LeanIMT circuit.
- **Done (2026-07, "Airlock" pass — Этап 2): real `POST /oprf/issue` + DLEQ, end-to-end.** Added Chaum-Pedersen
  **DLEQ** to `oprf.rs` (`evaluate_with_dleq`/`verify_dleq` + wasm exports `oprf_evaluate_with_dleq` [128-byte
  `Z‖K‖c‖s`, unconditional/edge] and `oprf_verify_dleq` [client-full]) — proves the evaluator used the key
  committed in `K=k·G`, so a client detects a Worker that swapped a per-user key to deanonymise it. New WASM
  build profile `pkg/enroll` (`build:enroll`, `--target web --features edge-verify-only`, 124 KB, **no ml-kem**)
  is imported into `workers/enrollment` (`oprf-wasm.ts`, `.wasm` → `WebAssembly.Module` → `initSync`, no TLA) —
  first WASM-in-CF-Worker in this repo, and wrangler bundles it fine (health 200 on boot). `/oprf/issue` (was a
  501 stub): parses the base64 blinded point, draws a nonce (`crypto.getRandomValues`), evaluates under
  `env.OPRF_KEY` (demo key in wrangler.toml `[vars]` for local dev; a `wrangler secret` in prod), returns
  `{evaluated, publicKey, dleq:{challenge,response}}`. `AuthCallback.tsx` now does the real 3-step flow: OAuth
  exchange → `oprfBlind` a random seed → POST `/oprf/issue` → `oprfVerifyDleq` (aborts login if it fails) →
  `oprfUnblind` → **real capability token replaces `mock-token-123`** in `login()`. **Verified live:** a Node
  probe and a browser-origin (`localhost:5173`) fetch both hit the live `:8788/oprf/issue` → 200, DLEQ verifies
  true, unblind yields a token, a tampered proof verifies false. cargo tests 17 (adds the DLEQ honest/dishonest/
  tamper case). Full browser login still needs the user's real Xfeatures OAuth creds for step 1 (can't be driven
  via tooling) — the VOPRF leg itself is proven independently. **Honest gaps:** the blinded seed is
  random-per-session (real deploy blinds a stable per-identity seed so re-enrollment is detectable); the token
  isn't yet redeemed against the Messaging Plane (`MerkleTreeDO`/`RateGateDO` below); OHTTP relay not wired.
- **Done (2026-07, "ZK airlock" pass — Etapы 1-3): Flow 1 + Flow 2 wired end-to-end through the Messaging
  Worker.** `MerkleTreeDO` implemented (DO SQLite: `commitments` + `nullifiers` tables; deterministic mock root
  = SHA-256 over the ordered commitment list — real Poseidon/LeanIMT still deferred; one-spend nullifier set is
  real). `POST /membership/insert` (assumes the VOPRF token valid for now) forwards the commitment to the global
  `MerkleTreeDO` and returns the root. **`POST /auth/session` runs the REAL Groth16 verifier in WASM:** new
  `pkg/msg` build profile (`build:msg`, `--target web --features edge-verify-only`, imported via `zk-wasm.ts`,
  `initSync` — same WASM-in-CF-Worker recipe as enrollment; wrangler bundles it, health 200 on boot) exposes
  `zk_verify_groth16_bytes`; the Worker holds the VK + public inputs from `zk_test.rs`'s deterministic vector and
  the client sends the matching valid proof, so `zk_verify_groth16_bytes(VK, proof, inputs)` runs the real
  3-pairing verify. On `true` it spends the nullifier (replay-guard) and mints an HMAC-signed capability
  (`session.ts`, `env.SESSION_SIGNING_KEY`). `AuthCallback.tsx` now runs all 5 steps: OAuth → VOPRF blind →
  `/oprf/issue` → `/membership/insert` → `/auth/session`, and `login()` stores the **ZK-verified session
  capability** (no longer the VOPRF token or a mock). **Verified live:** Node probe + a browser-origin
  (`localhost:5173`) fetch both drove Flow 1+2 against `:8787` → insert 200, `/auth/session` 200 + capability;
  worker log shows `[Session] zk_verify_groth16_bytes -> true` for the valid proof, `-> false` (401) for a
  tampered one, and 409 on nullifier replay. **Honest gaps:** the proof is a fixed valid vector (not generated
  live from the client's witness — needs the real Semaphore circuit), so the client-sent merkleRoot/nullifier
  are carried/replay-guarded but aren't yet the proof's actual public inputs; VOPRF-token redemption at
  `/membership/insert` is assumed-valid (not yet checked against the Enrollment Plane); no OHTTP relay.
- **Done (2026-07, "Capability enforcement" pass): the airlock is now a real gate, not theater.** The session
  capability minted by `/auth/session` (HMAC-SHA256 over `{nullifier, iat, exp, plane}`) is now VERIFIED before
  every conversation route: `session.ts` gained `verifyCapability` (recompute HMAC, constant-time compare,
  expiry + plane check); `index.ts` gates `/queue`, `/conv`, `/group` via `requireCapability` (401 before the DO
  is reached). Capability transport: `Authorization: Bearer <cap>` for HTTP, `?cap=<cap>` query for the WS
  upgrade (a browser can't set headers on `new WebSocket()`). Client: `AuthContext` now exposes the stored
  capability as `token`; `useChatWebSocket` appends `?cap=` to the WS URL. **Verified:** Node probe — missing /
  invalid / tampered cap → 401, valid cap (`?cap=` or Bearer) → passes to the DO (404/200, not 401); browser —
  a valid capability connects (header shows **Online**), a junk token is rejected (stuck **Reconnecting**, WS
  401). **Honest gaps noted at the time, both now resolved — see the "Plane Bridge (RSABSSA)" entry right
  below:** the capability's `localStorage` persistence is fixed (now in-memory only); `/membership/insert`'s
  "assumed valid" VOPRF placeholder is replaced with a real, third-party-verifiable signature check. No
  revocation list beyond expiry remains open. Remaining gap: `.dev.vars` (not committed, but still plaintext
  on disk) is a step short of an actual key-management service — acceptable for this stage, revisit before a
  real production deploy.
- **Done (2026-07, "Plane Bridge (RSABSSA)" pass): VOPRF replaced with RSA Blind Signatures (RFC 9474) for the
  redemption-token bridge, plus a bugfix sweep.**
  **Explicit non-goal, accepted deliberately (same spirit as docs/02's N1-N5, added there as N6):
  RSABSSA is NOT post-quantum.** RSA-3072 falls to a sufficiently large quantum computer; a future quantum
  adversary (A6 in docs/02) could forge a redemption signature. Accepted because the token is single-use and
  immediately nullified at redemption (`issuer_token_null`) — there is no ciphertext or standing secret this
  signature protects, so harvest-now-decrypt-later has nothing to harvest here. The message-confidentiality
  path (G4, PQXDH hybrid) is unaffected and remains fully PQ-hybrid; this non-goal is scoped narrowly to the
  one-time enrollment token. See docs/02 N6 and docs/03 §2 for the full statement.

  The prior VOPRF-based bridge had a structural problem: a
  VOPRF evaluation cannot be verified by a third party (Messaging) without either the OPRF secret `k` or an
  equivalent shared secret — meaning "Messaging verifies a VOPRF token" always secretly meant "the planes
  share a secret," violating the hard plane-isolation invariant under a different name. RSABSSA fixes this by
  construction: the issuer's signature verifies with nothing but its PUBLIC key.
  - **`packages/vortic-core/src/blind_sig.rs`** (new): wraps the `blind-rsa-signatures` crate (pure Rust,
    RFC-9474-conformant, ships the RFC's own Appendix test vectors — not hand-rolled padding/blinding math,
    per this project's standing rule for exactly this class of primitive). RSA-3072,
    RSABSSA-SHA384-PSS-Randomized (RFC 9474 §4's recommended parameter set). **A THIRD Cargo feature,
    `issuer-full`** (additive, orthogonal to `client-full`/`edge-verify-only`) gates the secret-key-consuming
    `blindsig_sign` — stricter than the pre-existing `oprf::evaluate` precedent (which is unconditional,
    accepting a secret as a plain argument): here the sk-handling code isn't just uncalled in Messaging's
    build, it was never compiled in. Verified via each profile's generated `.d.ts`: `pkg/client`
    (`client-full`) exports `blind`+`finalize`+`verify`; `pkg/msg` (`edge-verify-only` only) exports **only**
    `verify`; new `pkg/issuer` (`edge-verify-only,issuer-full`) exports `sign`+`verify`. **RFC 9474 conformance
    test:** the crate's own official Appendix vector (`RSABSSA-SHA384-PSS-Randomized`), reconstructed from raw
    `(n,e,d,p,q)` components and run through this module's own `verify_inner` — accepts the genuine vector,
    rejects a bit-flipped copy. Plus a fresh-key round-trip test (blind→sign→finalize→verify) and negative
    controls (tampered message, wrong issuer key). cargo: 21/21 (4 new).
  - **Offline keygen:** `examples/rsabssa_keygen.rs` (native, `issuer-full`-gated, NOT wasm-bindgen-exported —
    RSA-3072 keygen is a one-time operation, never something a live Worker request should do). Generated the
    real production keypair once; sk PEM → `workers/enrollment/.dev.vars` (`ISSUER_SIGNING_KEY_PEM`,
    gitignored); pk PEM → `workers/messaging/src/issuer-keys.ts` (a plain committed source constant, keyed by
    `kid` for future rotation — `ISSUER_KEYS: Record<kid, pem>` — even though only one key exists today) and
    duplicated into `apps/web/src/lib/issuerKey.ts` (client needs it too, to blind against; public data, no
    coupling risk beyond remembering to update both on a future rotation).
  - **Enrollment (Issuer):** `POST /oauth/callback`'s sybil-guard write is unchanged; new
    **`POST /token/issue`** (replaces `/oprf/issue`, now deleted along with the now-dead `oprf-wasm.ts`)
    receives a blinded message and returns `BlindSign(sk_issuer, blinded)` — deliberately does NOT re-run the
    sybil check (already done in the same session's `/oauth/callback`).
  - **Messaging (Verifier):** `POST /membership/insert` now does a REAL check — parses `{msg, sig,
    msgRandomizer, commitment}`, calls `verifyBlindSig(pk_issuer, msg, msgRandomizer, sig)` via a new
    `blindsig-wasm.ts` (same `pkg/msg` bundle `zk-wasm.ts` already loads; `initSync` is idempotent, verified
    safe to call from both loaders), and only on success computes `tokenNull = H(msg)` and hands it to
    `MerkleTreeDO`, which now has a real `issuer_token_null` one-spend table (mirrors the existing
    `commitments`/`nullifiers` pattern) enforced BEFORE the commitment insert.
  - **Bugfix — `spent_tokens` was in the wrong plane (real, pre-existing bug, found during this pass's
    review):** docs/04 Flow 1's own diagram always showed the spend-nullifier check happening in Messaging
    (`M->>M: verify token · check spend-nullifier`), but the table backing it (`spent_tokens`) was defined in
    `DB_ENROLL`, not `DB_MSG` — a real self-contradiction. If actually implemented as originally schema'd, it
    would have forced Enrollment to participate in every redemption at runtime, creating exactly the
    timing/IP-correlation coupling docs/03 §2 already flags as a residual risk to *minimize*, not build into
    the schema. Fixed via a new migration (`0002_drop_spent_tokens.sql`, `DROP TABLE IF EXISTS` — migrations
    are append-only, so this drops rather than edits `0001_init.sql`) plus `issuer_token_null` added to
    `DB_MSG` (`0002_issuer_token_null.sql`). `scripts/schema-lint.mjs` gained a check that tracks NET table
    state across a plane's migrations in filename order (so legitimate CREATE-then-DROP history doesn't
    false-positive) and fails the build if a forbidden table (currently just `spent_tokens` in `enrollment`)
    is still standing — live-tested against a planted violation (recreated `spent_tokens` in a temp 0003
    migration with no matching drop → caught, exit 1; reverted).
  - **Bugfix — demo secrets committed in `[vars]` (audited both workers, not just new code):** `OPRF_KEY`
    (now moot — deleted with `/oprf/issue`) and `SESSION_SIGNING_KEY` were both plaintext values in
    wrangler.toml `[vars]`, labeled "local dev only" but with nothing actually preventing prod misuse — a
    `[vars]` entry and a same-named `wrangler secret` don't compose safely. Moved to `.dev.vars` (gitignored,
    wrangler auto-loads it for `wrangler dev`) + a committed `.dev.vars.example` per worker documenting the
    required names. `schema-lint.mjs` gained a generic check: any `[vars]` entry whose name matches
    `/SECRET|KEY|SIGNING|PRIVATE/i` fails the build — live-tested against a planted `TEST_PLANTED_SECRET_KEY`
    (caught, exit 1; reverted). `PLANE_FORBIDDEN_BINDINGS.messaging` also now explicitly lists
    `ISSUER_SIGNING_KEY_PEM` alongside the pre-existing `OAUTH_CLIENT_SECRET`/`PPID_HMAC_SECRET`.
  - **Bugfix — session capability in `localStorage` (flagged, now fixed):** `AuthContext.tsx` no longer reads
    or writes `localStorage` at all — the capability lives in React state only (`useState<string | null>`,
    starts `null` every mount). Tradeoff accepted deliberately, not hidden: a page reload loses the session
    and the user re-runs the enrollment flow to re-mint (cheap — the earlier redemption-token/commitment
    steps don't need repeating in principle, though the current client re-does the whole chain from scratch
    since there's no cross-reload caching of intermediate state either; a future improvement, not required
    here). This is the correct shape for a short-lived (1h) bearer credential — see the file's own header
    comment for the full rationale.
  - **Acceptance checks run:** `grep` across `workers/messaging/**` for `OPRF_KEY`/`sk_issuer`/
    `BEGIN PRIVATE KEY` — zero matches (confirmed live, not just asserted). `grep` for any runtime
    `fetch`/import from `workers/enrollment` inside `workers/messaging/src` — zero matches (only comments
    reference it). `pnpm typecheck` clean across `vortic-core`, `apps/web`, both workers. `cargo test
    --features client-full,issuer-full` 21/21. `schema-lint` clean (4 migrations, 2 wrangler.toml).
  - **Still open (honestly, not swept under the rug):** VOPRF (`oprf.rs`, `js/crypto.ts`'s `oprfBlind`/
    `oprfUnblind`/`oprfVerifyDleq`) remains in the crate, still tested, just no longer wired into this bridge
    — not deleted, since ripping out a whole tested cryptographic module was out of scope for a plumbing
    swap. Full browser login still needs the user's real Xfeatures OAuth creds (not tooling-drivable) — the
    RSABSSA leg itself needs independent live verification (Node probe / two-worker `wrangler dev`) since the
    OAuth leg can't be driven end-to-end here.
- **Still open:** confirm byte-compat against **one genuine snarkjs-produced Semaphore v4 proof + its
  ceremony VK** (needs the snarkjs toolchain — the mock proves our pipeline, not snarkjs's exact wire bytes);
  **benchmark verify CPU in a real Worker isolate** (target <100 ms; the whole reason for not using snarkjs,
  see R1); `wasm-opt -Oz`.
- **Spike remainder (de-risk):** decide trusted-setup (Groth16 ceremony) vs **transparent PLONK/Halo2** —
  still open, decide before it's load-bearing.
- PPID sybil guard done (enrollment). `MerkleTreeDO` + nullifier one-spend done (see the "ZK airlock" entry
  above); remaining here: a real Poseidon/LeanIMT tree (not the SHA-256 mock root), redeeming the VOPRF token at
  `/membership/insert` against the Enrollment Plane's issuance (currently assumed-valid), and `RateGateDO`.
- **Exit:** a client enrolls via OAuth, obtains a blind token, inserts a commitment through OHTTP, proves
  membership, and gets a capability — with an automated test asserting **no row in `DB_MSG` can be joined to
  `DB_ENROLL`** and verifier CPU is within budget (target <100 ms; hard cap documented).

## Phase 3 — Messaging plane (M) — 🚧 all four Durable Objects landed (QueueDO, ConvLogDO, GroupDO, AliasDO)
- **Done (2026-07): `QueueDO`** (`workers/messaging/src/durable-objects/QueueDO.ts`) — one DO instance =
  one unidirectional pairwise queue, addressed by its own opaque name (the DO never stores or knows a
  `queue_id` as data; rotation = a new DO instance by construction). DO-local SQLite (`ctx.storage.sql`) as
  hot-path storage per docs/04 (D1 `queue_messages` stays the durable-mirror concept, untouched by this
  class). API: `POST /push` (raw ciphertext body + `X-Ttl-Ms`/`X-Size-Bucket` headers, immediate fan-out to
  any attached WebSocket), `GET /pull` (non-destructive), `POST /ack` (`{upToSeq}`, explicit eviction — TTL
  is only the backstop), `GET /subscribe` (hibernatable WS: flushes backlog on connect, live fan-out
  thereafter, ack-over-socket via `{"type":"ack","upToSeq":N}`). Alarm-based TTL sweep (`ctx.storage.
  setAlarm` to the earliest pending expiry) so storage is reclaimed even with zero traffic. Isolation
  respected: no identifier beyond `seq`/ciphertext/size_bucket/timestamps ever touches this DO.
  Routed from `workers/messaging/src/index.ts` via `/queue/:queueId/*` (renamed from `/q/...` in the Phase 5
  local-dev wiring pass below, to match the path `apps/web`'s `useChatWebSocket.ts` hits directly against a
  local `wrangler dev` instance).
- **Verified against a live `wrangler dev` instance, not just typechecked:** push→pull→ack cycle, TTL
  expiry (alarm-driven eviction confirmed), cross-queue isolation (different `queue_id` ⇒ empty), and the
  full WebSocket path (catch-up backlog on connect, live fan-out to an already-open socket, ack-over-socket
  eviction) — all exercised end-to-end with real HTTP/WS traffic. **One real bug found and fixed this way**
  (would not have surfaced from types alone): `handlePush` validated headers before draining the request
  body, so an early-rejected push (bad/missing header) left the body stream unconsumed; once forwarded
  through the Worker→DO `fetch()` boundary this threw `Can't read from request stream after response has
  been sent` and 503'd the *next* request. Fixed by always draining the body first, before any validation
  branch — documented inline as a load-bearing ordering, not a style choice.
- **Done (2026-07): `ConvLogDO`** (`workers/messaging/src/durable-objects/ConvLogDO.ts`) — ordered append-only
  op-log for CRDT (Yjs/Automerge) multi-device sync per docs/03 §9 + docs/04 Flow 4. One DO = one
  conversation, same opaque-name-as-identity pattern as `QueueDO`. DO-local SQLite `entries(seq, blob,
  enqueued_at)`, no TTL (durable history, not a transient queue). API: `POST /append` (`{blobs: base64[]}`,
  sequential inserts so caller order == assigned seq order, returns `{seqs: number[]}`), `GET /sync?
  since_seq=N` (delta pull, `seq > N`, defaults to full history when omitted). Routed via `/conv/:convId/*`.
  Extracted `bufToBase64`/`base64ToBuf` into a shared `workers/messaging/src/base64.ts` (was duplicated
  logic in `QueueDO`) and refactored `QueueDO` to use it.
  **Verified against a live `wrangler dev` instance:** append→sync (full + delta) cycle, seq ordering
  preserved across multiple batches, conversation isolation (different `convId` ⇒ empty), and validation
  (empty batch / malformed JSON / non-base64 entries / negative `since_seq` all → 400, no crash, clean
  recovery on the next request). No repeat of the `QueueDO` body-drain bug — `/append`'s only path to
  knowing what to insert is reading the JSON body first, so there's no early-return-before-drain to
  construct by accident here; still confirmed live rather than assumed safe. Also reran `QueueDO`'s
  push/pull smoke test post-refactor — no regression from the shared base64 module.
- **Done (2026-07): `GroupDO`** (`workers/messaging/src/durable-objects/GroupDO.ts`) — blind MLS (RFC 9420)
  Delivery Service: one DO = one group, orders Commit/Application ciphertext (indistinguishable to this DO —
  both are opaque blobs) and fans it out. Combines `QueueDO`'s hibernatable-WS fan-out with `ConvLogDO`'s
  batch-append/`since_seq`-sync shape. DO-local SQLite `entries(seq, blob, sender_queue_id, enqueued_at)`,
  no TTL (durable log, like `ConvLogDO`). API: `POST /push` (`{blobs: base64[], senderQueueId?}` — batch
  insert + immediate live fan-out per entry), `GET /sync?since_seq=N` (offline catch-up), `GET /subscribe?
  since_seq=N&sender_queue_id=X` (hibernatable WS: connect-time catch-up, then live fan-out). New anti-echo
  mechanism: `sender_queue_id` is an **opaque per-connection tag, not an identity** — a subscribing socket is
  tagged via `ctx.acceptWebSocket(ws, [tag])`, and `fanOut()` skips any socket whose tags (`ctx.getTags(ws)`)
  match a push's `senderQueueId`, so a member's own live push isn't echoed back to their own socket while
  everyone else still receives it (catch-up/`/sync` is unaffected — it always returns full history,
  including the member's own past messages). To the server, "a group" is just a set of anonymous tagged
  sockets on one DO — no member identity anywhere. Routed via `/group/:groupId/*` (added to the shared
  `forwardToDO()` helper alongside `/queue/*` and `/conv/*`).
  **Verified against a live `wrangler dev` instance**, with particular focus on the one genuinely new piece
  of logic (fan-out + anti-echo, untested by the prior two DOs): pushed history before any subscriber
  existed → both a tagged ("alice") and an untagged ("bob") subscriber correctly received the full catch-up
  backlog on connect; a live push tagged `alice-conn` reached bob's socket but was correctly **excluded**
  from alice's own socket; a live untagged push reached both sockets (including the untagged pusher's own —
  the documented behavior, since an untagged push has no exclusion target). Also validation edge cases
  (empty batch, wrong-typed `senderQueueId`, negative `since_seq`) → 400 with clean recovery, and reran
  `QueueDO`/`ConvLogDO` smoke tests → no regression. All three DOs now share the isolation invariant, verified
  live, not just asserted.
- **Done (2026-07): `AliasDO`** (`workers/messaging/src/durable-objects/AliasDO.ts`) — opt-in public `@alias`
  registry, zero-knowledge to this DO per docs/03 §8: the nickname never reaches it (client hashes it into
  `lookup_key` and encrypts `{intro_queue_id, alias_pub, ...}` into `record` under a key only derivable from
  the nickname). DO-local SQLite: `aliases(lookup_key, record, created_at)` +
  `pow_stamps(stamp, expires_at)` (global replay set, alarm-swept like `QueueDO`'s TTL). Real Hashcash
  verification (`ver:alg:bits:epoch:resource:salt:counter`, SHA-256 via Web Crypto, exact leading-zero-bit
  count): `POST /register` (24-bit target, resource-bound to `lookup_key`, rejects if already taken),
  `GET /resolve/:lookup_key` (20-bit target, `X-PoW-Stamp` header) — a resolve **spends its stamp on a miss
  too**, so probing a nonexistent alias still costs real work, not a free retry. `alias_pub` is bundled inside
  the encrypted `record` for now rather than a separate plaintext column (a stronger property than docs/04's
  original sketch), since no signed update/revoke exists yet to need it in the clear. Currently one global DO
  instance (docs/04's `H(nickname)`-prefix sharding deferred until volume warrants it). Routed via `/alias/*`.
  **Verified against a live `wrangler dev` instance with genuinely mined stamps** — wrote an independent
  Node.js SHA-256 miner (not sharing code with `AliasDO`'s implementation) that brute-forced real 24-bit and
  20-bit stamps (tens of millions of SHA-256 calls, confirmed by wall-clock timing), then drove 12
  request/response checks against the running Worker: genuine-stamp register succeeds; the same stamp
  rejected as resource-bound to a different `lookup_key` (403) *before* even reaching replay-check; exact
  reuse rejected (409, already registered); an unmined (`counter=0`) stamp rejected with a message reporting
  the *exact* actual bit count (`"0 < 24"`) — proving the server's bit-counter isn't just returning a
  boolean; a genuinely-valid-PoW-but-5-epochs-stale stamp correctly rejected on freshness, independent of
  its bits; genuine 20-bit resolve returns the exact record registered; replayed resolve stamp → 409; a
  genuinely-mined-for-only-10-bits stamp correctly fails the 20-bit resolve bar; resolving a valid-PoW but
  never-registered alias → 404, and reusing that same stamp next → 409 (proving misses spend the stamp,
  not just hits); malformed JSON / bad `lookup_key` format / missing PoW header → 400. All 12 passed exactly.
  Also reran `QueueDO`/`ConvLogDO`/`GroupDO` smoke tests → no regression. One test-harness lesson (not an
  AliasDO bug): the first mining run held an open fetch connection across an ~80s synchronous CPU-bound
  mining pause and got `ECONNRESET` from the local dev server; restructured to mine all stamps upfront, then
  fire every request back-to-back with no CPU gaps in between.
- **Still open:** Sealed Sender++ envelope, `PresenceDO`. `@cloudflare/actors` fan-out for anything beyond
  single-DO WS (not yet needed — every DO so far handles its own fan-out directly). R2 presigned
  chunked-AES-GCM media path. Alias adaptive/per-target PoW difficulty, Argon2id hardened option, signed
  update/revoke (would need `alias_pub` back out as a plaintext column), approval-gated contact-request flow
  through the resolved `intro_queue_id`, `H(nickname)`-prefix sharding.
- **Exit:** two devices exchange 1:1 + group messages + media offline/online; **Metadata Diagnostics (K5)**
  shows only opaque IDs/ciphertext; an opt-in `@alias` registers, resolves under PoW, and bootstraps a contact
  with **owner approval** — while a raw `AliasDO` dump yields no readable nickname→identity link and no
  `DB_ENROLL` join; a forged/low-bit or replayed PoW stamp is rejected; kill-a-DO chaos test loses no delivered
  messages.

## Phase 4 — Client app & UI-kit integration (M) — 🚧 Security Gate layout landed
- **Done (2026-07): Pre-Session Security Gate (K1) — web layout + state machine, correctly positioned in the
  UX flow.** The gate is a **standalone pre-auth screen at `/`, outside `AppLayout`** — no sidebar, since the
  user hasn't authenticated yet and there's no app shell to show them. `pages/SecurityGate.tsx`: full-screen,
  centered, large Vorticity wordmark+shield above the dashboard, hero **"Vorticity Secure Score"** ring + KPI
  cards + detailed check list, then a large peach **"Proceed to Auth"** button (disabled until the scan
  completes) that navigates via `window.location.href` to
  `https://account.xfeatures.net/oauth/authorize?client_id=vorticity_web&response_type=code&redirect_uri=...`
  — mock params for this layout pass; the real `client_id` already lives in `workers/enrollment/wrangler.toml`
  for when apps/web's actual enrollment flow is wired. `AppLayout`+`Sidebar` (structure copied 1:1 from
  Xfeatures HQ's `hq/Sidebar.tsx`) now hosts only the **post-auth** routes `/chats` and `/settings` (no
  Security Gate entry in that nav — it doesn't belong there).
  **Refactored for reuse (bonus requirement):** the scan state machine lives in `hooks/useSecurityScan.ts`
  and the score-ring/KPI/checklist markup in `components/SecureScorePanel.tsx`, both independent of any one
  page. Proven, not just structured for it: `pages/Settings.tsx` embeds `<SecureScorePanel scan={useSecurityScan()} compact />`
  as a "Security Status" widget — a second, independent scan instance running inside the post-auth shell,
  same component, different context. `lib/securityChecks.ts` holds only the pure check definitions (6 checks;
  2 genuinely real — `window.isSecureContext`, `crypto.getRandomValues` sanity — 1 real-but-simplified
  `RTCPeerConnection` ICE probe, 3 honestly-labeled simulated placeholders pending the Phase 2 capability
  endpoint). Accent color = `fluid-peach` throughout; tier colors (`signal-success/warning/danger`) drive
  per-check icons and the ring color once resolved.
  **Verified in a live browser session, not just typechecked:** on `/`, confirmed via DOM inspection — no
  sidebar link present, big "Vorticity" wordmark present, button reads exactly "Proceed to Auth" (padding
  `16px 40px`/`font-size:16px` for the "large" requirement, peach `oklab(...)` background, black text) once
  the scan resolves. On `/settings`, confirmed the embedded widget runs its *own* independent scan concurrently
  with the page's own content (`<main>` wrapper confirms it's inside `AppLayout`, unlike `/`'s bare `<body>`
  root). On `/chats`, confirmed sidebar + correct active-nav highlight. Zero console errors throughout.
  (Couldn't safely intercept `window.location.href` to assert the literal assembled OAuth URL — browsers
  don't allow redefining `window.location` — so that specific line was verified by code review, not live
  capture; everything else was captured live.)
- **Done (2026-07): mock Auth flow + route gating.** `contexts/AuthContext.tsx` (`isAuthenticated`/`login`/
  `logout`, backed by a `localStorage` flag — explicitly documented as a Phase 4 mock, **not** the real
  session model; docs/03 §3's real session is a short-lived capability minted after a Groth16 verify, never
  a bearer token in localStorage). `components/AuthGuard.tsx` wraps `AppLayout`; unauthenticated visitors
  bounce to `/`. `pages/AuthCallback.tsx` (`/auth/callback`): reads `code` from the URL, animates the three
  requested steps ("Exchanging OAuth Token" → "Generating ML-KEM-768 Keypair" → "Provisioning ZK Identity")
  with a real per-check state machine (not a static fake-loading spinner), then `login()`s and forwards to
  `/chats`; also handles a real `?error=`/`error_description=` response (the exact "PKCE ... is required"
  error hit live against the real IDM) with a proper error card instead of silently breaking.
  **Fixed the real PKCE gap this surfaced:** `SecurityGate`'s "Proceed to Auth" redirect was missing
  `code_challenge`/`code_challenge_method=S256`, which the real IDM enforces — ported
  `docs/legacy-reference/oauth-pkce.js` to `lib/pkce.ts` (TS), generates a real verifier/challenge per click,
  stores the verifier in `sessionStorage` (single-use, tab-scoped — not `localStorage`) for the callback to
  eventually consume once real token exchange is wired.
  **Real bug caught and fixed via live testing, not just typecheck:** the callback's step-animation effect
  originally used a boolean `started` ref to guard against re-running. Under React 19 StrictMode's dev-only
  synchronous mount→cleanup→remount, the *first* effect run gets cancelled before its first `await` resolves,
  and the boolean guard then blocked the *second* (real, lasting) run from ever starting — the UI froze
  forever on step 1. Fixed by switching to the same monotonic run-id/token pattern already used in
  `useSecurityScan.ts` (increment on every effect run; in-flight loops check `runId.current !== token` to
  self-cancel) — the correct one lets the *latest* invocation win instead of using a guard that can only ever
  block re-entry. **Verified live end to end:** unauthenticated `/chats` → redirects to `/`; `/auth/callback?
  code=...` → full 3-step animation → `mock-token-123` in `localStorage` → lands on `/chats` with sidebar
  (confirmed on two separate runs after the fix, neither got stuck); `/auth/callback?error=...&error_description=...`
  → renders the red error card with the literal message, does not touch auth state, "Return to Security
  Gate" button correctly navigates back to `/`.
- **Done (2026-07): Chats UI — split-view messenger, card/list markup in the strict Xfeatures style.**
  `pages/Chats.tsx` (state: lifted `chats`/`activeChatId`, single source of truth so sending a message updates
  both the active conversation AND the list's preview/timestamp — not two disconnected pieces of state) +
  `components/chat/{ChatList,ChatListItem,ActiveChatPanel,MessageBubble}.tsx` + `lib/mockChats.ts` (4 mock
  contacts shown by pseudonymous `@alias`, matching Vorticity's own identity model — docs/03 §8 — not real
  names). Split view: left `w-80 md:w-96 border-r` chat list (glass search input, avatar-with-initials +
  online dot, truncated preview, peach unread badge, `bg-white/5` active state) + right active-chat panel
  (header with alias/online-status/`Lock` icon/"End-to-End Encrypted", scrollable message bubbles — mine
  `bg-fluid-peach/10`/`border-fluid-peach/20` right-aligned, theirs `bg-white/5` left-aligned — sticky
  composer with `Paperclip`/`Send`). Real interactive send (not just chat-switching): typing + submitting
  appends a message to that conversation's array and updates the list preview live; empty-state placeholder
  when no chat is selected.
  **`AppLayout.tsx` fix required for the layout requirement** ("`h-full`, scroll inside panels, not the whole
  page"): added `h-full` to the page-wrapper div inside `<main>` — since `main` already has a definite height
  (flexbox stretch inside `h-screen`), this lets a page opt into filling it exactly (Chats) while pages with
  normal overflowing content (Settings) are unaffected, since the wrapper itself doesn't clip — their content
  still bubbles up to `main`'s own `overflow-y-auto` for ordinary page scroll.
  **Real bug found and fixed via live testing (not typecheck):** clicking a chat list item did nothing.
  Root-caused to `NoiseOverlay`'s `pointer-events-none` utility silently not being generated at all — a
  `packages/ui/src` Tailwind-scanning gap that had been *masked* until now, because every other
  packages/ui-only utility exercised so far (`backdrop-blur-3xl`, `absolute`, `inset-0`, etc.) happened to
  *also* appear directly in already-scanned `apps/web/src` files. `pointer-events-none` is the first class
  used *exclusively* inside `packages/ui/src` (`NoiseOverlay.tsx`), so it's what finally exposed that
  `packages/ui/src` was never actually being explicitly scanned — Tailwind's documented "roots at the nearest
  package.json to the file with `@import tailwindcss`" behavior was not reliably covering it in practice. Fix:
  added an explicit `@source` for packages/ui's own `src/` in `theme.css` (previously only apps/web's source
  was explicitly listed). First attempt at the fix used `@source "./"`, which is WRONG — `theme.css` lives in
  `packages/ui/src/styles/`, so `"."` resolves to `styles/` (no source files there at all); the real code is
  one level up, so the correct line is `@source "../"`. Confirmed by the generated stylesheet growing from
  27,341 bytes to 42,840 bytes after the correct fix — meaning a substantial share of `packages/ui`'s own
  utility classes had likely been silently missing all along, not just this one. **This is a standing risk
  for any future packages/ui-only Tailwind class that happens not to overlap with something already used in
  apps/web** — worth an explicit smoke test (e.g. a class list snapshot count) if this class of bug recurs.
  **Verified live end-to-end:** click-to-select works and clears the unread badge; sending a message appends
  it and updates the list preview from the same state; the message area auto-scrolls to bottom on a realistic
  single send (confirmed `atBottom: true` after the smooth-scroll animation settles — a synthetic 15-messages-
  in-one-synchronous-tick stress test showed `atBottom: false`, but that's a test-harness artifact of React 18+
  batching under an unrealistic call pattern, not a real bug: a normal one-at-a-time send always lands
  correctly); confirmed the **whole page never scrolls** (`document.body.scrollHeight === window.innerHeight`
  even with an overflowing message list) — only the internal `.vx-scrollbar` panel does, exactly per the
  layout requirement; re-verified Settings and the Security Gate render with zero regression after the CSS fix.
- **Done (2026-07): real-time transport spike — `useChatWebSocket.ts` wires the active conversation to
  QueueDO over a raw WebSocket.** Scoped deliberately to a single live socket for whichever chat is active
  (matches QueueDO's one-instance-per-direction model, docs/04, and was the explicit ask — "ID активного
  чата", singular): selecting a different chat tears down the old socket and opens a new one; other chats get
  no push until selected. Plain-text JSON frames only, no E2EE envelope yet (Triple Ratchet is separate,
  below) — this spike proves the transport shape, not the crypto. Status surfaced in `ActiveChatPanel`'s
  header (`Connecting...` / `Online` / `Reconnecting...` / `Offline`, colored dot, pulses while unsettled),
  driven by the hook's own state machine rather than raw `readyState` in the component. Reconnect uses
  exponential backoff (1s doubling to a 30s cap) restarted from the top each time the chat changes.
  `sendMessage(text)` is exposed from the hook; `Chats.tsx` calls it *alongside* (not instead of) the existing
  optimistic local append — a deliberate scoping call, not a leftover mock: the placeholder endpoint
  doesn't exist yet, so relying solely on a server echo to render the sent bubble would make the UI look
  broken. **Domain corrected (2026-07):** the placeholder was originally `wss://api.xfeatures.net/ws/queue/...`;
  fixed to `wss://api.vort.xfeatures.net/ws/queue/...` — `api.xfeatures.net` is a live prod domain used by other
  Xfeatures products, and this messenger has its own dedicated `vort.xfeatures.net` subdomain reserved for it.
  Grepped the whole frontend for any other stray `api.xfeatures.net` references — none found; the only other
  `xfeatures.net` hits are the legitimate, unrelated `account.xfeatures.net` OAuth authorize URL.
  **Known protocol gap, not solved here:** the real QueueDO's
  WebSocket is receive-only fan-out (server → client) plus a `{type:"ack", upToSeq}` client frame; pushing a
  *new* message is actually a separate `POST /push` HTTP call with `X-Ttl-Ms`/`X-Size-Bucket` headers and a raw
  ciphertext body (see `workers/messaging/src/durable-objects/QueueDO.ts`) — `sendMessage` doing
  `ws.send(...)` on the same socket is not that real shape yet; reconciling it is follow-up work once the
  Enrollment↔Messaging capability bridge (blinded queue-id token) exists, together with pointing the hook at
  the actually-deployed Worker origin instead of the placeholder URL. **Verified live** (no real backend
  exists yet, so this exercises exactly what it should): selecting a chat opens a socket attempt, shows
  `Connecting...` then `Reconnecting...` once the (non-existent) endpoint fails to accept the upgrade;
  switching chats tears down and reopens against the new chat's id; sending while disconnected doesn't throw —
  the message still appends locally and the list preview updates; `pnpm run typecheck` clean; `/settings` and
  `/` re-checked with zero regression.
- **Done (2026-07): local dev loop — `useChatWebSocket.ts` now branches on `import.meta.env.DEV`** to hit a
  local `wrangler dev` instance of `workers/messaging` directly (`ws://localhost:8787/queue/...`, no TLS, no
  `/ws` prefix) instead of the prod placeholder host. Required a genuinely missing `apps/web/src/vite-env.d.ts`
  (`/// <reference types="vite/client" />`) — without it `import.meta.env.DEV` doesn't typecheck; this repo
  was hand-scaffolded rather than `npm create vite`'d, so the usual auto-generated file was never there.
  **Renamed `workers/messaging`'s queue mount from `/q/:queueId/*` to `/queue/:queueId/*`** in `index.ts` (and
  the corresponding prefix-strip in `forwardToDO`) to match the path the frontend now hits directly in dev —
  the `/ws` prefix on the prod path is edge-routing in front of `api.vort.xfeatures.net`, not something the
  Worker itself defines, so the Worker's own mount was always meant to be the shorter `/queue/...`; the old
  `/q/...` name predates this reconciliation. `QueueDO.ts`'s existing `fetch()` already checks the `Upgrade`
  header before any path switch, so no change was needed there for the Upgrade handshake itself to work under
  the new mount. **Added a relay in `QueueDO.webSocketMessage`:** any JSON text frame that isn't the
  `{type:"ack",...}` protocol frame (i.e. the plaintext `{type:"message",...}` shape this hook sends) is now
  broadcast verbatim to every *other* socket attached to that queue (`relayToOthers`, unpersisted, best-effort
  — dead sockets don't break the broadcast for the rest). This is explicitly **not** the real push/ack split
  documented elsewhere in that file (a real push is `POST /push` over HTTP with a ciphertext body + TTL/size-
  bucket headers, persisted and fanned out via the existing `fanOut()`); it's a deliberate, temporary widening
  of this DO's job so the local dev loop (`apps/web` on 5173 ↔ `wrangler dev` on 8787) can be exercised
  end-to-end before the real capability bridge and push/ack reconciliation land — flagged inline in both files
  so it isn't mistaken for the final protocol. Renamed the two other historical mentions of `/q/*` (in this
  doc) to `/queue/*` for consistency; left `docs/04`'s illustrative sequence-diagram pseudocode (`PUT /q/
  {queueId}`) alone since it already diverges from the real implementation in other ways (e.g. `PUT` vs. the
  actual `POST /push`) and isn't meant to track the literal router mount. **Verified (per this task's explicit
  instruction, `wrangler dev` was NOT started by the assistant):** `pnpm run typecheck` clean across the whole
  workspace, `schema-lint` clean; confirmed live in the browser (via a `WebSocket` constructor proxy) that
  under `import.meta.env.DEV` the hook actually constructs `ws://localhost:8787/queue/chat-1` — with nothing
  listening on 8787 yet it correctly falls into `Reconnecting...`, exactly as expected with no backend up.
  Full connect-to-a-real-local-`wrangler-dev`-instance end-to-end check is still pending — that's on the user
  to run once both servers are up.
- **Done (2026-07): first real end-to-end WebSocket relay test — `apps/web` (Vite, :5173) ↔ `wrangler dev`
  (workers/messaging, :8787) ↔ real `QueueDO` instance.** Two independent browser tabs, both authenticated
  (mock token), both selecting the same chat (`chat-1` / `@nightowl_42`) — confirmed both actually reach
  `Online` against the real local Worker (not the placeholder host). A message sent from one tab appeared in
  the other's conversation *and* its chat-list preview, live, no reload, in both directions (tab A → B and
  B → A) — the Durable Object genuinely relayed a message between two independent client connections for the
  first time this project.
  **Real bug found and fixed via this live test (not typecheck — this class of bug is invisible to types):**
  `QueueDO.webSocketClose` unconditionally called `ws.close(code, reason)`, which threw an uncaught exception
  on *every single connection teardown*, confirmed directly in `wrangler dev`'s own log output (one `Uncaught
  Error at webSocketClose` per close, for every dev-server hot-reload-triggered reconnect during testing). By
  the time this handler fires, the close handshake it's reporting has already happened — re-closing an
  already-closing/closed WebSocket throws in workerd. Symptom: this looked at first like the relay itself was
  broken (a message sent from tab A silently never reached tab B), but the real signal was in the *count* of
  attached sockets after churn — a quick temporary `console.log` in `webSocketMessage`/`relayToOthers` (added
  then removed once the real cause was confirmed) showed exactly the expected socket count and a successful
  relay once the close bug was fixed; before the fix, repeated hot-reload churn during testing left enough
  uncaught exceptions that a stale/wrong connection state was plausible. **Fix:** wrapped the `ws.close()` call
  in try/catch (same "a socket that's already gone isn't fatal" tolerance pattern already used in `fanOut`/
  `relayToOthers`). **Also note, for whoever debugs this class of test next:** during this pass the browser
  automation layer itself exhibited real flakiness independent of the app — a `get_page_text` call once
  returned a different chat's content than what `read_page`'s structured tree showed for the same tab at
  effectively the same moment, and a freshly created tab once rendered `/settings` without ever being
  navigated there. Closing and recreating the tab resolved it immediately, confirming it was tooling state,
  not app state (the app itself has no code path that changes `activeChatId` other than the explicit list-item
  `onClick`). If a future live test shows a tab on an unexpected screen with no corresponding user action,
  suspect the tool's tab tracking before suspecting the app.
  **Verified live, both directions, post-fix and post-debug-cleanup:** `pnpm run typecheck` clean, `schema-lint`
  clean, zero `Uncaught Error` lines across multiple subsequent hot-reloads, message relay confirmed working
  cleanly one more time after removing the temporary debug logging (so the shipped file has none of it).
- **Done (2026-07): Phase 5 finale — mock E2EE over the WebSocket transport.** `packages/vortic-core` gained a
  JS entry point (`js/mockCrypto.ts`, exported via `package.json`'s `exports: {".": "./js/mockCrypto.ts"}` and a
  new `tsconfig.json`/`typecheck` script mirroring `packages/ui`'s pattern) and is now a real `workspace:*`
  dependency of `apps/web`. **Important correction made before writing any code:** the task as given named a
  nonexistent `packages/crypto` with `encryptMessage`/`decryptMessage` already exported — neither exists; the
  real crate is `packages/vortic-core` (`kem.rs`/`oprf.rs`/`zk.rs` only, no encrypt/decrypt), and `wasm-pack`
  (needed to actually build it to WASM) isn't installed in this environment. Flagged this to the user before
  proceeding; they chose a lightweight TS-only mock over installing `wasm-pack` and writing a real AEAD in
  Rust, and confirmed `@vorticity/vortic-core` as the real package name to depend on.
  `mockCrypto.ts`'s `encryptMessage`/`decryptMessage` are an explicitly-labeled, deliberately-insecure
  reversible repeating-XOR keystream over UTF-8 bytes (hex-encoded, `0x`-prefixed) — proves the wire *contract*
  ("only ciphertext crosses the WebSocket") without claiming to be real cryptography. `useChatWebSocket.ts`:
  the wire's `text` field was renamed to `ciphertext`; `sendMessage` now encrypts before `ws.send` and logs
  `[Crypto] Sending ciphertext: 0x...`; `ws.onmessage` decrypts before handing a `ChatMessage` to React state
  and logs `[Crypto] Received ciphertext: 0x... -> decrypted: "..."`. `ActiveChatPanel.tsx` needed no changes —
  it never touches `ws.send`/`onmessage` directly, only calls `onSend(plaintext)`, so there was nothing crypto-
  shaped to add there; said so rather than forcing an unnecessary edit just to touch every file the task named.
  **Verified live on two tabs, both directions:** console showed `[Crypto] Sending ciphertext: 0x2200...` on
  the sender and `[Crypto] Received ciphertext: 0x2200... -> decrypted: "Top secret E2EE payload"` on the
  receiver — same hex string on both ends, confirming the wire genuinely carries ciphertext, and the decrypted
  plaintext rendered exactly once in React state (no duplication) on both list preview and message bubble.
  `pnpm run typecheck`/`schema-lint` clean.
  **SUPERSEDED (2026-07, "Real WASM" pass — see Phase 1 above):** `mockCrypto.ts` is deleted; `wasm-pack` was
  installed and the crate now compiles to real WASM. `encryptMessage`/`decryptMessage` are real
  ChaCha20-Poly1305 (base64 `nonce‖ct‖tag`, not `0x…` hex XOR), imported via the new `js/crypto.ts` with an
  `initCrypto()` gate. The wire *contract* this mock proved still holds; only the cipher behind it changed.
- **Done (2026-07): first real leg of the auth pipeline — `AuthCallback.tsx` calls the real Enrollment Worker.**
  Discovered `workers/enrollment/src/index.ts`'s `POST /oauth/callback` was already a fully real implementation
  (real PKCE token exchange against `auth.xfeatures.net`, real PPID computation, real sybil-guard upsert into
  `DB_ENROLL`) from earlier work, just never called from the frontend — `AuthCallback.tsx` only ever faked all
  three steps with `setTimeout`. Wired step 1 ("Exchanging OAuth Token") to a real `fetch(POST
  {ENROLLMENT_API_URL}/oauth/callback, {code, code_verifier})`, env-switched the same way as
  `useChatWebSocket.ts` (`http://localhost:8788` in dev, since :8787 is already `workers/messaging`;
  `https://id.vort.xfeatures.net` in prod, not actually deployed anywhere — same honest caveat as the
  messaging placeholder host). Steps 2-3 (ML-KEM keypair, ZK identity) and `login()`'s stored value remain
  mocked — the Worker itself doesn't issue a real capability token yet either (still a `501` stub at
  `/oprf/issue`, Phase 2 work), and there's no real WASM build to generate a real keypair with (same
  `wasm-pack` gap as above) — so this is a real step forward on the network leg, not the finished pipeline.
  **Real bug found and fixed along the way, unrelated to the task as framed:** `workers/enrollment/src/
  response.ts` hardcoded `Access-Control-Allow-Origin: https://vort.xfeatures.net` — a single prod-only value
  that would silently block every local-dev fetch from `localhost:5173` (the browser rejects the response
  client-side; the server never even sees it as an error). Fixed by making `corsHeaders` an origin-allow-list
  function (`["https://vort.xfeatures.net", "http://localhost:5173"]`, echoing back whichever matches, never
  reflecting an arbitrary caller-supplied origin) and threading `request.headers.get("Origin")` through every
  `jsonResp`/`errorResp` call site in `index.ts`. **Second real bug, also StrictMode-shaped like the earlier
  AuthCallback freeze:** the PKCE `code_verifier` read+`sessionStorage.removeItem` was unconditional at the
  top of the effect (copied from the old mock code, which never depended on the value so losing it silently on
  React 19 StrictMode's dev-only double-invoke had no visible effect) — once step 1 actually *needed* that
  value, the first (soon-to-be-cancelled) invocation deleted it before the second (real, lasting) invocation
  could read it, surfacing a false "Missing PKCE code_verifier" error even though the network tab showed a
  real POST had already fired with a valid one. Fixed with a `readOnceRef`/`codeVerifierRef` pair that performs
  the destructive read exactly once per mount and caches the result for every subsequent invocation — same
  family of fix as the original run-id/token pattern, applied to a *value* instead of a cancellation flag.
  **Verified live:** started `wrangler dev --port 8788` for `workers/enrollment`; `curl` confirmed the CORS fix
  (`Access-Control-Allow-Origin: http://localhost:5173` echoed correctly) and that a fake code genuinely round-
  trips to the real IDM and back (`502` with `"IDM error: ... invalid_grant"` — a live rejection from
  `auth.xfeatures.net`, not a canned response); reproduced the exact same real error through the actual browser
  UI at `/auth/callback?code=...` after seeding `sessionStorage` with a fake verifier, confirming the fix;
  regression-checked the pure `?error=...&error_description=...` URL-param path still renders correctly. Could
  not test the full happy path (a real successful login) — that requires real Xfeatures Account credentials,
  which is not something to enter through this tooling; that leg is only testable by the user, in their own
  browser session. `pnpm run typecheck`/`schema-lint` clean across the whole workspace.
- **Done (2026-07): third real bug in this same flow — `redirect_uri` mismatch, found from the user's own live
  test (not a self-discovered issue this time).** The user hit `invalid_grant` testing a real login locally and
  asked whether they were missing OAuth scopes — they weren't; `invalid_grant` at the token-exchange step fires
  *before* any scope/userinfo check ever runs. Root cause: `workers/enrollment` hardcoded
  `env.OAUTH_REDIRECT_URI` (`https://id.vort.xfeatures.net/oauth/callback`) as the `redirect_uri` sent to the
  IDM's token endpoint, unconditionally — but `SecurityGate.tsx`'s `/authorize` redirect sends
  `${window.location.origin}/auth/callback` (`http://localhost:5173/auth/callback` in local dev). Per RFC 6749
  §4.1.3 the token endpoint must see the byte-identical `redirect_uri` used at authorization or it rejects with
  `invalid_grant` — a guaranteed mismatch for anyone testing locally, regardless of granted scopes. **Fix:**
  the client now sends the `redirect_uri` it actually used (reconstructed the same way `SecurityGate.tsx`
  does, not hardcoded) in the `POST /oauth/callback` body; the Worker validates it against a fixed allow-list
  (`allowedRedirectUris()` — `env.OAUTH_REDIRECT_URI` plus the localhost dev value, mirroring `response.ts`'s
  CORS origin allow-list) before forwarding it to the IDM, rather than trusting an arbitrary caller-supplied
  value. **Verified live:** `curl` with the allow-listed localhost `redirect_uri` now correctly reaches the
  real IDM (still `invalid_grant`, but only because the test `code`/`code_verifier` are fake — the mismatch
  class of failure is gone); `curl` with a deliberately untrusted `redirect_uri` (`https://evil.example.com/
  callback`) is correctly rejected with `400 "redirect_uri not allowed"` *before* any call to the IDM;
  reproduced through the real browser flow too, same clean result. `pnpm run typecheck`/`schema-lint` clean.
- **Done (2026-07): fourth real bug, also user-reported — an intermittent 500 that the browser misreported as
  a CORS policy failure.** After the redirect_uri fix, the user's console showed "blocked by CORS policy: No
  'Access-Control-Allow-Origin' header" alongside the (correct) IDM error text — a confusing combination, since
  a truly CORS-blocked response can't normally be read by the calling code at all. Root cause, confirmed
  directly in this session's own `wrangler dev` log: some requests intermittently returned `POST /oauth/
  callback 500 Internal Server Error`, interleaved with the expected `502`s — and the top-level `.catch(error)`
  in `index.ts` (and the `router.all("*", ...)` 404 fallback) used itty-router's own `error()` helper, which
  builds a bare `Response` with **no CORS headers at all**. Any response that took that path — whatever
  actually threw — got reported by the browser as a CORS failure, even though the real defect had nothing to
  do with the origin allow-list (which was already correct). Under React 19 StrictMode's double-invoke, one of
  the two near-simultaneous requests hitting the exact same edge case would surface this while the other
  succeeded normally, which is why the user saw *both* a CORS error *and* the correct final error text in the
  same console. **Fix:** replaced the top-level `.catch()` with one that builds a response via this file's own
  `errorResp` (always CORS-aware) instead of itty-router's helper, replaced the 404 fallback the same way, and
  wrapped `request.json()` in its own try/catch for a clean `400` instead of letting a malformed body fall
  through to the top-level catch. Every response this Worker returns — success, expected error, or genuinely
  unexpected exception — now carries a correct CORS header, unconditionally. Could not pin down what exactly
  was throwing on those specific intermittent requests (an 8-way concurrent `curl` burst afterward returned 8
  clean `502`s, not reproducing it) — plausibly transient network flakiness calling the real external IDM
  under rapid/concurrent local-dev load, not necessarily a defect in this Worker's own logic — but regardless
  of root cause, the fix guarantees this can never again surface as a mystifying "CORS policy" message; worst
  case now it's a readable "Internal error: ..." in the actual UI. **Verified live:** browser round-trip
  through `/auth/callback` again — zero console errors, correct `invalid_grant` text rendered.
  `pnpm run typecheck`/`schema-lint` clean.
- **Done (2026-07): root cause of the intermittent 500 finally pinned down — StrictMode double-firing a
  single-use OAuth code — and fixed.** The previous entry's "couldn't pin down what was throwing" is now
  resolved. Instrumented the Worker's handlers + top-level catch with temporary full-stack logging and drove
  the real browser flow: the `wrangler dev` log showed **two `[DEBUG] ENTER` lines for a single browser
  navigation** — React 19 StrictMode double-invokes the `AuthCallback` effect, and *both* invocations issued
  their own `POST /oauth/callback`. The `runId`/token pattern correctly cancels stale *UI*, but it does **not**
  stop the second invocation's `fetch` from firing (both async IIFEs pass their guard before the other
  increments `runId`). Unified explanation for everything seen across the last several entries: an OAuth
  authorization code is **single-use**, so the two StrictMode requests *race to consume the same code* at the
  real IDM — with a fake code both just cleanly fail (two `502`s, which is why an 8-way/24-way `curl` burst
  never reproduced a 500), but with a real code one wins and the loser hits a mid-consumption code, which the
  real IDM answers unpredictably. The instrumentation also caught the real IDM returning
  `429 "Too many requests"` under this doubled load — direct confirmation that the doubled request rate was
  itself part of the problem. **Fix (`AuthCallback.tsx`):** the token exchange is now deduped via an
  `exchangeRef` holding the in-flight promise — the first invocation to reach that point creates the exchange
  and stores the promise; the StrictMode twin (and any re-render) `await`s that *same* promise instead of
  issuing a second request. Deliberately **not** the boolean-guard anti-pattern that caused the original
  AuthCallback freeze: the guard there wrongly blocked the surviving run's *UI work*; here we dedupe only the
  *destructive network side effect* while the `runId` guard still decides which run drives the UI — two
  distinct concerns. **Verified live:** with the fix, a single navigation now produces exactly **one**
  `[DEBUG] ENTER` server-side and exactly **one** `fetch` client-side
  (`performance.getEntriesByType('resource')` → `totalFetchPostsThisPageLoad: 1`, was 2 before); UI renders the
  single correct `invalid_grant`, zero console errors. All temporary `[DEBUG]` logging removed afterward (the
  shipped Worker keeps only one legitimate `console.error` in the top-level catch for genuinely-unhandled
  errors, worth having in `wrangler tail`/prod). `pnpm run typecheck`/`schema-lint` clean. **Standing lesson:
  the `runId`/token cancellation pattern and destructive-side-effect deduplication are SEPARATE tools for
  StrictMode — `runId` makes the *latest* run win for idempotent UI work; a shared-promise/`readOnceRef` guard
  is needed additionally whenever the effect performs a NON-idempotent side effect (consuming a single-use
  code, a one-time POST, reading+clearing storage). This file now needs all three: `runId` (UI), `readOnceRef`
  (PKCE verifier read), and `exchangeRef` (token exchange).** Note also: this double-invoke is dev-only
  (StrictMode); production fires once — but the dedupe is correct to keep regardless, and it's what makes the
  real login testable locally at all.
- **Done (2026-07): first genuine successful real login — got past every fixed bug and reached the D1 write.**
  User hit `D1_ERROR: no such table: enroll_ppid: SQLITE_ERROR` — this is real, confirmed progress, not a new
  bug: it means a REAL authorization code from a REAL Xfeatures login now survives PKCE, `redirect_uri`
  validation, and the IDM token exchange, and reached the sybil-guard write in `workers/enrollment/src/
  index.ts`. The failure was purely local-environment setup: `wrangler dev`'s local D1 (a SQLite file under
  `.wrangler/state/v3/d1`) had never had `migrations/0001_init.sql` applied, so `enroll_ppid`/`spent_tokens`
  simply didn't exist yet. Fixed by running `pnpm wrangler d1 migrations apply vorticity-enroll --local` from
  `workers/enrollment` (confirmed both tables now exist via `d1 execute ... "SELECT name FROM sqlite_master"`).
  Proactively applied the same for `workers/messaging`'s `vorticity-msg` too (`d1 migrations apply
  vorticity-msg --local`) since it had the identical gap and nothing had hit it yet only because none of the
  DOs currently read/write `DB_MSG` directly (they use their own DO-local SQLite storage) — no code change
  either way, purely local D1 setup. **Anyone spinning up this repo's local dev from scratch needs to run
  `pnpm wrangler d1 migrations apply <db-name> --local` once per Worker with a `[[d1_databases]]` binding
  before its first request that touches D1** — not currently automated (e.g. via a `predev` script), worth
  adding if this surprises someone else.
- **Still open:** (Both the vortic-core WASM build AND VOPRF capability issuance are now **done** — `/oprf/issue`
  is a real Ristretto VOPRF+DLEQ endpoint and `login()` stores a real unblinded token, see the Phase 1 "Real
  WASM"/"Dynamic keys" and Phase 2 "Airlock" entries above.) What remains: redeeming that capability token
  against the Messaging Plane (`MerkleTreeDO`/`RateGateDO`) so it actually authorises queue access; blinding a
  stable per-identity seed instead of a random one; wiring the ZK-membership (`zk_*`) proof into the flow. Real
  VPN/DNS/Clock checks (need the Phase-2 capability endpoint), Capacitor
  native checks (root/jailbreak, screen-capture, devtools — need `apps/mobile`, Phase 4 later work), rule-engine
  paranoia-profile switching (Standard/Journalist/Maximum, docs/05), pointing `useChatWebSocket` at the real
  deployed Worker + reconciling the push(HTTP)/ack(WS) protocol split instead of a single mock `ws.send`
  (currently both directions share one queue id per chat with a client-supplied `senderId` flag, which doesn't
  match `QueueDO`'s own documented one-instance-per-*direction* model — reconciling this needs a real two-queue-
  per-conversation scheme, deferred rather than rushed), fanning in more than the single active chat's queue,
  onboarding, device management, backups, multi-device UX, disappearing messages, safety-number verification +
  Key Transparency (K8).
- **Exit:** full user journey (onboard → gate → chat → multi-device → recover) on web + Android.

## Phase 5 — Hardening & audit (M)
- External crypto + appsec audit; trusted-setup ceremony (if Groth16); binary/circuit transparency (K7);
  duress/panic (K4); cover traffic (K6); abuse/rate-limit tuning; formal review of the unlinkability proof.
- Load/cost modeling for DO + verifier at scale; OHTTP relay hardening.
- **Exit:** audit findings closed; documented residual-risk statement shipped in-app (honesty about A7/N1).

## Phase 6 — Closed beta → release (M)
- Invite-only beta (fits the "closed network" model); telemetry that is itself privacy-preserving (aggregate,
  no per-user metadata); staged rollout of PQ ciphersuites; incident runbooks.
- **Exit:** stable beta, documented SLOs, publishable security whitepaper.

**Parallelizable:** Phase 1 and the Phase 2 *spike* can start together (the ZK spike is the gating unknown —
start it in week 1). UI kit work (Phase 4) can begin scaffolding as soon as kit paths arrive, against mocked cores.

---

## Risk register

Severity × likelihood; **R1 is the one the brief explicitly asked about.**

| ID | Risk | Sev | Like | Mitigation | Owner phase |
|---|---|---|---|---|---|
| **R1** | **ZK verifier cost on Workers** — snarkjs Groth16 verify ≈ 0.74–0.88 s CPU; per-message is infeasible, and even per-session at scale is pricey/latent | **High** | High | **Verify once/session → mint capability** (never per message); Rust pairing verifier target <100 ms; cache roots; move proving fully client-side | 2 |
| **R2** | **Network-level correlation defeats ZK** — same host sees both planes; IP+timing can relink enroll↔insert | **High** | Med | OHTTP relay (host never sees IP); temporal decoupling of enroll vs insert; distinct hostnames; the Security Gate's VPN/DNS nudge; padding | 2,4,5 |
| R3 | **Pub/Sub dependency dead** (beta ended 2025-08-20) | Med | Certain | Already re-architected to **DO + WS Hibernation + `@cloudflare/actors`**; brief updated | 3 |
| R4 | **Trusted setup (Groth16)** compromise / ceremony risk | High | Low | Multi-party ceremony w/ public transcript, **or** switch to transparent-setup PLONK/Halo2 (decide in Phase 2 spike) | 2,5 |
| R5 | **Single-host concentration** — Cloudflare is host *and* primary adversary; also a censorship/availability SPOF | High | Med | Confidentiality/anonymity are cryptographic (host-independent); track relay/P2P diversification for availability (post-v1) | 5,6 |
| R6 | **WASM size/perf** on mobile (ML-KEM+MLS+Groth16 prover) | Med | Med | Lazy-load prover; code-split; wasm-opt; native Capacitor crypto for hot paths | 1,4 |
| R7 | **MLS DS metadata** — delivery service still sees ordering/size/epoch | Med | High | Blind ordering only; pad sizes; bucket timestamps; pairwise-queue isolation; documented in N1 | 3 |
| R8 | **Sealed Sender residual leak** (receipts/traffic analysis) | Med | Med | Sealed++ (padded/delayed/decoupled receipts), queue isolation, optional chaff (K6) | 3 |
| R9 | **PQC library immaturity** (no CMVP-validated WASM ML-KEM yet) | Med | Med | Hybrid (classical still protects if PQ lib flawed); pin audited versions; track AWS-LC/OpenSSL 3.5 maturity | 1,5 |
| R10 | **DO 10 GB shard / hot-shard limits** | Low | Med | Per-conversation sharding; TTL-evict delivered ciphertext to R2; backpressure | 3 |
| R11 | **Enrollment Sybil** via multiple OAuth accounts | Med | Med | PPID quota per `sub`; invite-only closed network; per-epoch nullifier rate limits | 2 |
| R12 | **Key-loss / recovery** without linkage is hard UX | Med | High | Recovery phrase + optional blind cloud backup; clear "no phrase = no recovery" contract | 1,4 |
| R13 | **Legal compulsion** of Cloudflare | High | Low | "Can't produce what we can't compute": design ensures no email↔handle data exists to hand over; warrant-canary | all |
| R14 | **CDN/circuit swap** (malicious WASM) | Med | Low | Reproducible builds, binary transparency, client-side circuit-hash pinning (K7) | 5 |
| R15 | **Alias directory enumeration/scraping** — public aliases reintroduce a discoverable namespace | Med | Med | PoW-per-resolve + encrypted records (dump is inert) + capability gate; adaptive/per-target difficulty; opt-in & default-off | 3 |
| R16 | **PoW asymmetry** — botnet/GPU/ASIC mint stamps far cheaper than honest mobiles; or bits set too high hurt UX | Med | Med | Memory-hard Argon2id option; adaptive per-target bits; capability gate bounds actors to real accounts; tune bands; off-thread miner | 3,5 |
| R17 | **Host offline dictionary attack** on `AliasDO` dump (nicknames are low-entropy) | Med | Med | Documented residual (aliases are public by intent); high-entropy nickname advice; **identity-linkage stays cryptographically safe** — record holds no email/PPID/handle | 3 |
| R18 | **Nickname squatting / impersonation** | Low | Med | Registration PoW + capability; `alias_pub` signed ownership; reserved/verified namespaces; report+revoke; Key Transparency (K8) over alias→key | 3,5 |
| R19 | **Self-doxxing** — a human-chosen public alias is a persistent identifier the *user* exposes | Low | High | Default invisible; explicit opt-in warning; recommend pairing with an ephemeral persona (K2); never auto-suggest real-name aliases | 3,4 |
| R20 | **Session capability was in `localStorage`** — JS-readable, so any XSS or malicious extension with DOM access could trivially steal a live bearer credential authorising `/queue` etc. | High | Med | **Mitigated 2026-07** (Plane Bridge pass): moved to in-memory React state only, never persisted; reload loses the session by design. Open follow-up: a real "remember this device" UX (if ever added) needs a non-extractable key (WebCrypto non-exportable `CryptoKey` / platform keystore), not Web Storage | 2 |
| R21 | **`/auth/session` accepts a fixed, shared valid ZK proof vector, not one generated live from the client's own Semaphore witness** — the WASM verifier is real (Groth16/BN254, 3-pairing), but every client currently presents the *same* proof; the endpoint doesn't yet bind a caller's actual membership/commitment into the public inputs it checks | High | Certain (today) | Needs the real Semaphore v4 circuit (Poseidon/LeanIMT) + a genuine per-client witness/proof, replacing the `zk_test.rs` mock vector currently hardcoded in `workers/messaging/src/session.ts`. Tracked as the largest remaining gap before the ZK airlock is production-ready — status: **open**, not started | 2 |
| R22 | **Messaging chat transport is still a one-socket-both-directions mock** — `useChatWebSocket.ts` does one `ws.send()` for both send and receive on a single `queue_id`, not `QueueDO`'s actual documented asymmetric protocol (`POST /push` HTTP for send, WS receive-only fan-out + `{type:"ack"}` for receive) | Med | Certain (today) | Reconcile the transport with `QueueDO`'s real push/ack shape once the capability-authorised queue-id scheme (per-conversation, two queues) is designed. Status: **open**, explicitly deferred out of the RSABSSA Plane Bridge pass's scope, flagged here so it isn't lost | 3 |

### R1 & R2 — the ZKP↔Workers coupling, in depth (the brief's key question)

1. **Cost/latency (R1).** A Groth16 proof is tiny (3 group elements) and verification is constant-time, but the
   pure-WASM pairing math still costs ~**0.8 s CPU** in snarkjs. Workers *permit* this (paid plan: up to 5 min
   CPU/req; 30 s default) yet it's expensive per-invocation and adds latency. **Architectural fix:** treat ZK
   as **session establishment**, not per-message auth — verify one membership proof per epoch, issue a MAC'd
   capability, and let all messaging ride the capability. This bounds ZK verification to O(sessions), not
   O(messages), and is already baked into Flow 2. Secondary fix: a **Rust→WASM pairing verifier** (BN254/
   BLS12-381, 3 pairings) targeting sub-100 ms; benchmark in the Phase 2 spike before committing.
2. **Anonymity coupling (R2) — the deeper risk.** ZK guarantees the host cannot *cryptographically* link
   email→handle. It does **not** prevent the host, who terminates both planes, from attempting **IP+timing
   correlation** (enroll request from IP/T; first Merkle insertion from IP/T+ε). **ZK hides the math, not the
   packets.** This is why the design is not "ZK on Workers" alone but **ZK + OHTTP + temporal decoupling + the
   user's own VPN/Tor** (surfaced by the Security Gate). Verification running *inside* the adversary's
   infrastructure is acceptable **because the verifier holds no secret that helps deanonymize** — it only
   checks a proof and mints a scoped capability; the anonymity rests on blinding + network isolation, not on
   trusting the Worker. Honest ceiling: a **global passive adversary (A7)** watching both the user's uplink and
   Cloudflare's edge remains out of scope (N1) — we raise cost, we don't claim defeat.

**Bottom line:** binding *verification* to Workers is fine; binding *anonymity* to Workers is not — so we never
do. The Worker is an untrusted verifier by design, and every anonymity guarantee is enforced *before* the
packet reaches it (blinding, OHTTP, VPN) or *by cryptography the Worker can't undo* (ZK, sealed sender).
