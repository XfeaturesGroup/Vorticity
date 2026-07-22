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
- **Done (2026-07, "R24: real Triple Ratchet" pass) — closes R24, the last "unauthenticated DH, no
  ratchet" gap R22's own entry flagged as separate/deferred work.** See the risk-register R24 row and
  the full write-up further down (Phase 3's "R24: real Triple Ratchet" entry) for the design, the two
  real symmetry bugs found and fixed while building the Sparse PQ Ratchet, and live-verification
  results — the crypto-core module itself (`ratchet.rs`) lives here in Phase 1's scope; kept the
  detailed write-up in one place rather than duplicating it across two phase sections.
- **Done (2026-07, "R12: Argon2id/BIP39 backup" pass) — closes the crate-side half of R12
  ("Key-loss / recovery").** New module `backup.rs` (`client-full`-gated at `lib.rs` — the whole
  module is new, unlike previous passes that just added a `dep:` to an existing gate), implementing
  docs/03 §11's pipeline literally: 32-byte caller-supplied entropy → BIP39 (`bip39` crate) → 24-word
  phrase → BIP39's own standard seed derivation (PBKDF2-HMAC-SHA512) → 64-byte seed → Argon2id
  (`argon2` crate, `hash_password_into` — used as a raw KDF, not the crate's PHC-string
  password-hashing API) at the spec's own stated params (m=256MiB, t=3, p=1) → 32-byte master key →
  AES-256-GCM (`aes-gcm` crate) encrypt/decrypt of arbitrary local state. `bip39`/`argon2`/`aes-gcm`
  added to `client-full`'s dependency list (never linked into `edge-verify-only` — confirmed via
  `cargo tree`, same plane-separation check every prior pass runs). Real ecosystem API checked by
  reading each crate's actual source in the local registry cache BEFORE writing code (`Params::new`'s
  argument order, `Mnemonic::parse_normalized`/`to_seed_normalized`, `Aes256Gcm` needing the crate's
  `aes` feature flag) — avoided guessing wrong signatures. Entropy is caller-supplied, not drawn from
  an internal RNG, matching `kem.rs`'s established "seed-threaded" convention. The Argon2id salt is a
  FIXED, domain-separated constant (not random) — deliberately, not an oversight: see `backup.rs`'s
  header comment for why a fixed salt is correct when the thing being stretched is already a
  high-entropy BIP39 seed rather than a low-entropy human password.
  **Verified two ways, not just typed:** `cargo test` (54/54 crate-wide, up from 45 — 9 new, covering
  round-trip, phrase/entropy determinism, wrong-phrase and wrong-key rejection, GCM tamper detection,
  fresh-nonce-per-call) AND a separate Node probe against the actual COMPILED `pkg/client` WASM (not
  just native Rust) exercising all four `wasm-bindgen` exports end-to-end — same real-vs-mock
  discipline this doc's other entries hold themselves to. Real, observed Argon2id cost on this
  machine inside the actual WASM binary: **~485 ms per derivation** — comfortably under the "flag if
  1-2s" threshold this project has used elsewhere, so not flagged as a UX concern; noted as a real
  number, not assumed. `edge-verify-only` still builds clean (both with and without `issuer-full`)
  and `cargo tree` confirms none of the three new deps (nor `ml-kem`/`x25519-dalek`/`kem`) appear in
  that profile.
  **Honest scope, stated plainly:** this closes the CRATE half only — no `apps/web` UI wiring (a
  "generate/enter recovery phrase" screen, wiring `backup_export`/`backup_import` to actual local
  state serialization) and no live browser/mobile verification of Argon2id's real memory behavior at
  256 MiB inside a constrained WASM linear memory (this pass's own native + Node tests are
  unconstrained-memory environments, not a mobile browser) — both explicitly out of this pass's
  scope (crate-only, per the task's own boundary) and worth a dedicated follow-up before relying on
  this for a real user-facing recovery flow.
- **Done (2026-07, "R12: blind cloud backup" pass) — closes the SERVER half of R12** (the crate half
  above already closed the crypto pipeline; this pass wires docs/03 §11's "optional cloud copy: the
  same ciphertext blob may be stored in R2 keyed by an opaque backup ID; the server holds an
  unreadable blob" into a real, live-tested `workers/messaging` endpoint).
  **Backend-only scope, deliberately** — no `apps/web` UI (still the crate entry's own stated gap;
  not widened here).
  - New `backup.rs::derive_backup_id_inner` / `#[wasm_bindgen] backup_derive_id`: HKDF-derives the
    opaque 32-byte R2 key from the phrase-derived master key, domain-separated (distinct `info`
    string) so the ID the Worker necessarily sees and can log is never the encryption key itself or
    trivially related to it — a real, tested invariant (`backup_id_is_domain_separated_from_the_
    encryption_key_itself`), not just a comment.
  - **Two independent, non-overlapping authorization factors**, deliberately not one: (1) a valid
    session capability (ties storage cost to a real ZK-membership-proven account, the same
    Sybil-resistance argument AliasDO's capability gate already relies on) AND (2) knowledge of the
    256-bit backup ID (computable only from the recovery phrase). Neither alone suffices — a stolen
    capability without the phrase can't even address a specific victim's slot (2^256 search space);
    a leaked ID without a live capability can't touch storage at all. Same "belt and suspenders"
    shape this codebase already uses for alias register/resolve (capability + PoW), applied to a
    different pair of factors appropriate to this route's threat (targeted storage abuse, not
    directory scraping — PoW would be the wrong tool here).
  - New dedicated `BACKUP` R2 bucket (`wrangler.toml`), deliberately NOT reusing `MEDIA` — separates
    the lifecycle/access policy for "a user's full local identity/ratchet/message state" (extremely
    sensitive) from ordinary chat media at the infra level, at zero extra code cost.
  - `PUT`/`GET`/`DELETE /backup/:backupId` (both a direct route AND wrapped through the existing R25
    OHTTP Gateway dispatch, reusing the exact same core handlers either way so the two paths cannot
    drift — same discipline as every other dual-path route in `index.ts`). Wrapped because "this real
    IP is uploading/fetching/deleting THIS specific backup ID" is genuinely sensitive metadata —
    arguably worse than the alias-route metadata already wrapped, since a repeated GET on the same ID
    fingerprints a returning device across sessions.
  - Wire format follows this codebase's established base64-in-JSON convention for opaque binary
    payloads (same shape as `msg`/`sig`/`proof` elsewhere in `index.ts`) rather than a raw-bytes body
    or a presigned-direct-to-R2 upload — a deliberate, stated choice NOT to reuse docs/04's
    presigned-URL pattern earmarked for the (still unbuilt) media path: that split exists to keep the
    Worker off the hot path for large files, which backup blobs (capped well below media sizes)
    don't need, and funneling them through the Worker keeps the capability+rate-limit gate as the
    single enforcement point instead of a second one at the storage layer.
  - Real size cap (8 MiB, enforced before the R2 write, not just documented) and per-backup-ID rate
    limits via the existing generic `RateGateDO` primitive (PUT 10/epoch — the only one of the three
    that costs real storage/write-unit money, so bounded hardest; GET 20/epoch, DELETE 5/epoch) —
    keyed by the backup ID itself, not the capability's nullifier, so the limiter can't become a
    second identity-correlation surface for the very session the capability already represents.
    `DELETE` is idempotent and always returns 200 (existing-or-not), so the response itself can't be
    used to oracle whether a guessed ID currently holds data.
  - **Live-verified twice, both real, zero mocking:** (1) 20 checks against the direct routes over a
    real `wrangler dev` + real `BACKUP` R2 bucket — a REAL `backup_export`-produced ciphertext
    (compiled `pkg/client` WASM, not a stub) PUT, GET'd back byte-identical, and successfully
    `backup_import`-decrypted back to the original plaintext through the real WASM boundary;
    overwrite (latest-wins) semantics; cross-ID isolation; 401 on missing/tampered capability; 400 on
    a malformed ID; 413 on an 8 MiB+1 body; DELETE-then-404; idempotent re-DELETE; and the PUT rate
    limit tripping at exactly the 10th call for one ID while a different ID's budget stayed
    unaffected. (2) 8 checks of the SAME flow routed entirely through the real OHTTP Gateway dispatch
    (`encapsulateRequest`/`decapsulateResponse` from `@vorticity/ohttp`, confirmed the plaintext
    backup ID never appears in the encapsulated wire bytes) — real PUT/GET/DELETE through
    `/ohttp/gateway`, real WASM decrypt of the round-tripped blob, 401 on a missing capability with
    the real check running (not bypassed).
  - **Not done, stated plainly:** the "Forward-secret backup option: rotating backup keys" line from
    docs/03 §11 — explicitly scoped out rather than half-built; would need a real key-rotation design
    (which epoch owns which R2 slot, how an old key is retired) that deserves its own pass rather than
    a bolted-on parameter. `apps/web` wiring (unchanged from the crate entry's own gap). No D1 mirror
    of backup metadata into the pre-existing `blobs_meta` table — deliberately: R2's own object
    metadata (exact byte length, exact upload timestamp) is already visible to the host on every GET
    regardless of what a separate D1 row says, so a bucketed/rounded mirror column would be
    security-theater, not a real mitigation; noted here rather than silently added for its own sake.
- **Done (2026-07, "real MLS group encryption" pass) — closes the crate-core half of the "MLS
  wrapper" item below (R7's own progress note above this phase already flagged the gap this
  closes).** New module `group.rs`, `MlsGroupSession` (`client-full`-gated), built on `openmls`
  0.8.1 + `openmls_rust_crypto` — a real, decision-recorded choice over the AWS `mls-rs`
  alternative (see Cargo.toml's own comment for the full reasoning): neither has a confirmed
  third-party audit, but openmls's dedicated `openmls-wasm` package and CI wasm32 build target were
  a stronger WASM-maturity signal, and its RustCrypto-backed provider builds on the SAME
  `curve25519-dalek`/`ml-kem` family this crate already trusts elsewhere — a familiar, not novel,
  trust surface at the primitive level. **This was a genuine user decision, not a default this
  session picked alone** — asked explicitly given the real, disclosed audit-status uncertainty on
  BOTH candidate libraries, and a documented pure-Rust alternative (fan a group message out over N
  already-audited-adjacent pairwise Triple Ratchet sessions, zero new crypto dependency, real O(N)
  cost) was also on the table and explicitly declined in favor of real MLS.
  **A real ciphersuite gap found by actually running the code, not assumed from reading dependency
  lists:** the original intent was the X-Wing hybrid (ML-KEM-768 + X25519) ciphersuite, matching
  this crate's PQ-hybrid commitment for 1:1 (`kem.rs`) — `hpke-rs-rust-crypto`'s source confirms
  X-Wing support exists in the ecosystem, but the FIRST test run against `openmls_rust_crypto`
  0.5.1 panicked: X-Wing isn't wired through its own `OpenMlsCrypto` implementation yet. Fell back
  to `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (openmls's own official example's
  ciphersuite, chosen for maximum confidence of real end-to-end support). **Real, disclosed
  consequence: group messages are NOT post-quantum-resistant with the current provider, unlike 1:1
  messages** — a genuine gap from this project's own hybrid-PQ ambition, not swept under the rug.
  **`libcrux-provider` (the other in-tree crypto backend, which DOES wire up X-Wing) was
  investigated and rejected**: it pulls `rayon` (real-thread data-parallelism) into the dependency
  graph, meaningless-to-risky on `wasm32-unknown-unknown` (no OS threads by default) — confirmed via
  `cargo build --target wasm32-unknown-unknown` comparison between the two providers before deciding,
  not assumed.
  **Architecture:** openmls's own state model (a storage-provider keystore + a reloadable `MlsGroup`
  handle) doesn't fit this crate's usual pure-function style, so `MlsGroupSession` follows
  `ratchet.rs`'s `RatchetSession` precedent instead — a `#[wasm_bindgen]` class, opaque state handle,
  `exportState`/`importState` for persistence (length-prefixed binary framing of the provider's
  key-value store, mirroring openmls's own `examples/large-groups.rs` persistence approach
  structurally, different encoding). `GroupDO.ts` (workers/messaging) needed **zero changes** —
  confirmed, not assumed: Commit and Application messages are both just opaque bytes to it, exactly
  matching its pre-existing "blind ordering, can't tell a Commit from an Application message" design
  claim. A Welcome message (delivered to the new member only, never broadcast per RFC 9420)
  deliberately does NOT go through `GroupDO` at all — documented in that file's header as needing the
  existing 1:1 `QueueDO` infrastructure instead, not built in this pass.
  **A second real bug found by running the code:** `StagedWelcome::new_from_welcome` failed "No
  ratchet tree available to build initial tree after receiving a Welcome message" until
  `use_ratchet_tree_extension(true)` was set on group creation — without it, nothing ships the tree
  structure a joiner needs at all. Fixed, not worked around.
  **A third real (and correctly scoped) finding:** a tamper-rejection test panicked under plain
  `cargo test` (debug profile) — traced to openmls's OWN `debug_assert!(false, "Ciphertext
  decryption failed")` in its AEAD-open failure path, a no-op in release builds (what `wasm-pack`
  and this crate's own `[profile.release]` actually ship). Confirmed the same test passes clean
  under `cargo test --release` — an upstream debug-only artifact, not a bug in this module.
  **Verified two ways:** `cargo test --release --features client-full,issuer-full` — 59/59 (crate-
  wide, up from 54; 5 new: 2-member create/add/Welcome/join/bidirectional-application-message round
  trip, distinct-ciphertext-per-call, export/import state survival, an outsider's unrelated group
  correctly failing to process another group's ciphertext, tamper rejection). AND a separate live
  Node probe against the actual COMPILED `pkg/client` WASM (not native Rust) driving the exact same
  Alice/Bob flow end-to-end through the real wasm-bindgen boundary — group creation, real Commit+
  Welcome (707B/811B), real join, bidirectional real encrypted messages, distinct ciphertext for
  identical plaintext, state export/import survival (8771B exported session), and tamper rejection —
  all confirmed working through the actual browser-shipped artifact, not just its Rust source.
  `edge-verify-only` (with and without `issuer-full`) still builds clean for `wasm32-unknown-unknown`
  and `cargo tree` confirms `openmls`/`rayon` (and the pre-existing `ml-kem`/`x25519-dalek`/`kem`)
  remain absent from that profile — plane separation holds with the new dependency tree too.
  **Honest scope, stated plainly:** this closes the CRYPTO CORE only. Not done: `apps/web` UI/state
  wiring (create/join a group, persist a live `MlsGroupSession` across reloads, route a Welcome to
  the right `QueueDO`), member removal / self-update tested only implicitly (not a dedicated live
  test in this pass), no PQ ciphersuite (stated above), and bLSAG ring signatures remain untouched
  (a separate, previously-investigated-and-declined item — see the nazgul-crate rejection note
  earlier in this doc).
- **Done (2026-07, "bLSAG ring signatures" pass) — the last remaining Phase 1 `todo!()` skeleton is
  closed.** `ring.rs` had been a literal `todo!()` since Phase 0 (docs/03 §5, "anonymous authorship").
  Real, standard linkable ring signature (Liu-Wei-Wong LSAG, the same shape used pre-CLSAG by Monero)
  over Ristretto255 — zero new Cargo dependencies (curve25519-dalek/sha2 were already unconditional
  deps; the per-signature randomness reuses the SAME `getrandom` 0.2 `client-full`-only source
  `symmetric.rs`'s AEAD nonce already draws from). Key image (linkability tag)
  `I = x_pi · H_p(ctx)` — deliberately keyed by a caller-supplied CONTEXT (meant to be
  `group_id‖epoch`, per docs/03's own framing), not the signer's own pubkey as Monero's permanent key
  image does, so the SAME signer gets the SAME tag only within one epoch's context and an unrelated
  one the next epoch — exactly the "spam-linkable within an epoch, unlinkable across epochs" property
  docs/03 §5 asks for. `sign` is `client-full`-gated (needs the secret scalar); `verify` is
  unconditional (needs no secret, reveals nothing about which member signed) — same "verification is
  edge-safe" precedent as `zk.rs`/`blind_sig.rs`/`alias_sig.rs`.
  **Crate-core scope only, matching this codebase's own established precedent** (kem.rs, oprf.rs,
  backup.rs, group.rs all landed crate-only first): `GroupDO`/`apps/web` wiring — deciding what "the
  ring" is for a real MLS group (converting each member's MLS Ed25519 credential into a Ristretto
  keypair, vs. a separate parallel keypair per member) — is deliberately NOT decided here, left open
  for whenever this gets connected to a live group rather than guessed at.
  **Verified two ways:** `cargo test --release --features client-full,issuer-full` — 72/72
  (crate-wide, up from 59; 13 new: round-trip for every signer position in a 5-member ring, a
  non-member's signature correctly rejected, tampered message/ring rejected, same-signer-same-epoch
  linkability, same-signer-different-epoch unlinkability, different-signers-different-key-images,
  fresh-randomness-per-call (same key image, different `c0`), out-of-range-index/undersized-ring
  rejected, malformed-length inputs rejected without panicking, and an independent algebraic
  cross-check — not just calling this module's own `verify` — that the signer's solved `s` value
  reconstructs an `alpha`-consistent `(L,R)` pair under both bases, confirming the ring-closing math
  is exact, not coincidentally accepted). `edge-verify-only` still builds clean for
  `wasm32-unknown-unknown` and `cargo tree` confirms `ml-kem`/`x25519-dalek`/`kem`/`openmls`/`rayon`
  remain absent from that profile (only the pre-existing unconditional curve25519-dalek/sha2 are
  used). AND a separate live Node probe against the actual COMPILED WASM — BOTH `pkg/client`
  (client-full) and `pkg/msg` (edge-verify-only) — confirming `pkg/msg` exports `ring_verify` but
  genuinely has NO `ring_sign`/`ring_generate_keypair` at all (not just "unused"), that the SAME real
  signature verifies identically through both compiled profiles, that a tampered message/signature
  byte/wrong-epoch-context is rejected by the edge build specifically, and that the linkability/
  unlinkability properties hold through two independent real signing calls (not just asserted from
  the Rust-side unit tests).
  **Honest scope, stated plainly:** no fuzzing/side-channel hardening (same deferral as the rest of
  this crate, see below); no `GroupDO`/UI wiring (stated above); this crate treats `ctx` as an opaque
  byte string, so which layer computes/rotates the actual `group_id‖epoch` encoding is future work.
- **Done (2026-07, "Key Transparency consistency proofs" pass) — R18 progress, `workers/messaging`
  side: closes the specific residual gap the earlier "Key Transparency (K8)" pass's own header
  comment named** ("no RFC 6962 'consistency proof'... a server that controls the only copy of the
  log could in principle still fork it for one victim without those additional pieces"). New module
  `workers/messaging/src/merkleConsistency.ts` (pure TS/bigint, no new dependency): `mth`/
  `consistencyProof`/`verifyConsistency`, RFC 6962 §2.1.1/§2.1.2's actual recursive definitions.
  **A real design pitfall found by reading `@zk-kit/lean-imt`'s own `insert()` source before writing
  anything, not assumed:** a live tree's node matrix MUTATES in place (a "carried up unchanged" lone
  node gets overwritten once a later insertion gives it a real sibling), so this module always
  recomputes `MTH(...)` from the raw ordered leaf-hash list for whichever exact prefix size is asked
  for, rather than reusing `KeyTransparencyDO`'s cached `LeanIMT` node matrix, which would silently
  return TODAY's subtree value instead of history's.
  **A real soundness question found by this module's OWN brute-force adversarial testing (not
  assumed correct from the algorithm's description), investigated rather than papered over:** an
  exhaustive sweep first flagged `verifyConsistency(m, n_wrong, rootM, root_of_the_REAL_n, proof)` as
  accepting — traced to the fact that RFC 6962 consistency proofs authenticate that root_m's CONTENT
  is a genuine prefix of root_n's content, and deliberately do NOT independently authenticate the
  numeric size label attached to root_n (real Certificate Transparency binds `(tree_size, root_hash)`
  via a separate Signed-Tree-Head signature, outside the Merkle math entirely) — not a bug. Confirmed
  by the test that actually matters for K8's threat model: two trees sharing an identical prefix then
  diverging (a real fork) — a proof from one fork correctly fails to verify against the other fork's
  root at the same (m,n), which is the actual equivocation-detection property this feature exists
  for. Documented as an explicit, load-bearing scope note in the module's own header comment rather
  than silently "fixed" into a non-standard variant.
  New unauthenticated `GET /transparency/consistency?first=m&second=n` (matches `/root`/`/latest/
  :key`/`/proof/:seq`'s existing openness — this is the public audit log), rate-limited per
  `(first,second)` pair via the pre-existing `RateGateDO` `/check` primitive (`CONSISTENCY_RATE_
  LIMIT_PER_EPOCH = 20`, same "cheap check before expensive work" reasoning as `/membership/
  proof/:commitment`'s existing rate gate — this recomputes `MTH` over up to `second` leaves per
  call, materially more expensive than `/proof/:seq`'s O(log n) cached path).
  **Verified live, real running `wrangler dev`, not simulated:** appended 25 real entries to a fresh
  `KeyTransparencyDO`, then for seven `(first,second)` pairs (including non-power-of-two boundaries
  like (5,13), (13,25)) independently reconstructed the leaf list via the pre-existing public
  `/proof/:seq` route (not by reading DO internals) and confirmed the live endpoint's `firstRoot`/
  `secondRoot`/`proof` matched an independent recomputation byte-for-byte, and that
  `merkleConsistency.verifyConsistency` accepts the live proof while rejecting a tampered proof
  entry and swapped roots for every pair tested. Confirmed 400 on `first=0`, `first>=second`,
  `second` beyond the log's current size, and non-numeric input; confirmed the 429 rate limit fires
  on repeated requests for one `(first,second)` pair while a different pair's first request is
  unaffected (per-key isolation, same discipline as this file's other rate-gated routes).
  **Durability checked separately, same discipline as this DO's earlier passes:** killed the live
  `wrangler dev` process outright and started a completely fresh one against the same on-disk
  state — `/transparency/root` and `/transparency/consistency?first=13&second=25` both returned
  byte-identical results with zero new writes, confirming the log's persistence, not just a warm
  process's memory. `tsc --noEmit` and `schema-lint` both clean (no schema changes — this reads the
  existing `kt_entries` table, no new columns/tables).
  **Honest scope:** still no independent monitors/gossip, no client-side (`apps/web`) verification
  wiring, no RFC 6962-style Signed Tree Head (the piece that WOULD authenticate the numeric size
  label — see the soundness-question note above) — this pass closes the consistency-proof MATH and
  its live wiring specifically, matching K8's own "Mitigated, not Closed" framing.
- **Done (2026-07, "Signed Tree Head" pass) — R18 progress: closes the exact residual gap the
  previous pass's own header comment named** ("no RFC 6962-style Signed Tree Head — the piece that
  WOULD authenticate the numeric size label"). New module `workers/messaging/src/sth.ts`: signs
  `(size, root, timestamp)` with Ed25519 via `node:crypto` (this Worker already opts into
  `nodejs_compat`, same precedent `KeyTransparencyDO.ts`'s own `createHash` usage established) —
  deliberately NOT vortic-core/WASM, since this is a pure server-side signing operation with no
  client-side counterpart to keep in the same language, unlike `alias_sig.rs` (which needs the SAME
  sign/verify pair runnable from a browser). Ed25519 via `node:crypto` needs no digest-algorithm
  argument (`sign(null, message, key)`) — the hash is built into the signature scheme itself.
  **Stated plainly, matching this module's own header comment: signing alone does not make the log
  incapable of equivocating** — a dishonest operator could still sign two DIFFERENT roots for the
  SAME size and hand one to each of two observers. What it provides is DETECTABILITY: a captured STH
  becomes a durable, non-repudiable, independently-checkable statement, so two such STHs compared
  later (by gossip/monitoring — still not built, see below) constitute cryptographic proof of
  misbehavior. This is the same role an STH plays in real Certificate Transparency.
  New keypair: real Ed25519 (`node:crypto` `generateKeyPairSync`, one-time offline generation, same
  "generate once, private half to `.dev.vars`, public half committed" precedent as the RSABSSA
  issuer keypair) — private PKCS8 PEM in `env.KT_STH_SIGNING_KEY_PEM` (`.dev.vars`, gitignored;
  `wrangler secret put` in prod), public SPKI PEM committed in new `src/kt-sth-key.ts` (keyed by
  `kid`, same rotation-ready lookup-table shape as `issuer-keys.ts`). New unauthenticated
  `GET /transparency/sth` (matches this log's existing openness — a public, verifiable commitment is
  the whole point). No rate limit added: this call has the same cost as `/root` (cached-tree read,
  one Ed25519 sign), which itself carries none.
  **A real, non-cryptographic bug found and fixed during this pass, not swept under the rug:**
  `.dev.vars` stores the PKCS8 PEM as a single line with `\n` escapes rather than a literal
  multi-line quoted value — NOT because the literal-multiline form (which `workers/enrollment`'s
  pre-existing `ISSUER_SIGNING_KEY_PEM` already uses) is actually broken, but because this pass's own
  live testing was confused for a while by a genuinely unrelated problem: a STALE `wrangler dev`
  process from an earlier testing session had NOT been killed by `pkill -f "wrangler dev"` on this
  Windows/Git-Bash setup and kept answering on the same port with stale bundled code, making every
  new env var (not just this one — a plain unrelated test var showed the same symptom) appear to
  silently not exist. Diagnosed by testing on a brand-new, never-used port, which resolved
  immediately — recorded here so a future session doesn't waste time re-diagnosing the same
  red herring, and the `\n`-escaped format was kept afterward anyway since it was already confirmed
  working end-to-end and sidesteps any future doubt about literal-newline `.dev.vars` parsing.
  **Verified two ways:** a standalone round-trip test confirmed the REAL `.dev.vars` private key and
  the REAL committed `kt-sth-key.ts` public key are a genuine matching pair (not two independently
  generated keys that happen to both exist), plus tamper rejection on every field (size, root,
  timestamp, signature byte), wrong-public-key rejection, malformed-input handling without throwing,
  and confirmed Ed25519 signing is deterministic (same inputs sign identically twice — a real,
  checkable property, not assumed). **Live, real running `wrangler dev`:** `GET /transparency/sth`
  returns a real signature whose `(size, root)` matches `/root` exactly; independently verified
  against the committed public key; every tampered field rejected; two successive fetches with no
  intervening appends report the identical `(size, root)` but a genuinely fresh signature each time
  (not a cached response). **Durability checked separately, same discipline as this DO's other
  passes:** killed the live process and started a completely fresh one against the same on-disk
  state — the reported root/size were byte-identical to before the restart, and a freshly-signed STH
  against that persisted state still verified correctly.
  **Honest scope:** no gossip/gossip-gap detection, no independent monitors comparing STHs from
  different vantage points, no `apps/web` client-side verification wiring, no MaxMergeDelay/freshness
  policy beyond the raw `timestamp` field itself — this pass is the signing/verification primitive
  and its live wiring only, matching this doc's "Mitigated, not Closed" framing for R18's remaining
  pieces.
- **Done (2026-07, "KT gossip/monitor" pass) — R18 progress: closes the exact residual gap sth.ts's
  own header comment named** ("two such STHs compared later — by gossip/monitoring, still not built
  — constitute cryptographic proof of misbehavior"). New `workers/messaging/scripts/kt-monitor.mts`:
  an independent watchdog script that fetches `GET /transparency/sth`, verifies its Ed25519
  signature, and compares it against a LOCALLY PERSISTED prior STH the script itself remembers —
  never against anything the server currently claims about its own past. Three outcomes per run:
  same size + same root -> OK; size grew -> fetch `GET /transparency/consistency?first=prev&second=
  new`, cross-check the proof's own `firstRoot` against what THIS script already verified last time
  (not the server's restatement of it), then run the real RFC 6962 `verifyConsistency`; anything else
  (log shrank, same size but a different root, `firstRoot`/`secondRoot` mismatch, or a failing
  consistency proof) is an ALARM with both conflicting STHs (or the failing proof) dumped as evidence
  and a distinct exit code (0 = OK, 1 = ALARM, 2 = the check itself couldn't complete) so unattended
  cron alerting can tell "the log is lying" apart from "this script broke."
  **A real design choice made and stated, not defaulted into:** this reuses the project's own already-
  tested `verifySth`/`verifyConsistency`/`ktCombine` rather than a from-scratch reimplementation. The
  tempting "more independent" move — hand-rolling RFC 6962 §2.1.2's iterative verifier a second time —
  was rejected: a monitor with a subtly-wrong DIVERGENT verifier is worse than one sharing the tested
  implementation, either false-alarming constantly (gets ignored, defeats the point) or silently
  accepting forks it should catch. The property that actually provides equivocation detection is
  independent, tamper-evident MEMORY of prior state plus WHO/WHERE runs the check — not divergent
  arithmetic — so `ktCombine`/`fieldToHex` were extracted out of `KeyTransparencyDO.ts` into a new
  shared `src/ktHash.ts` (single source of truth for both the live DO and this script) rather than
  copied.
  **Live-verified with six real scenarios against a real `wrangler dev` KeyTransparencyDO, not
  simulated:** (1) first run with no state file establishes a baseline (exit 0); (2) a second run with
  no intervening change reports OK-unchanged (exit 0); (3) a state file hand-crafted with the SAME
  size as the live log but a DIFFERENT root correctly ALARMs as same-size equivocation (exit 1); (4) a
  state file claiming a LARGER size than the live log correctly ALARMs as an append-only violation
  (exit 1); (5) a state file with a plausible-looking but WRONG historical root correctly ALARMs when
  the live consistency endpoint's own `firstRoot` doesn't match it (exit 1) — the realistic shape a
  genuine rewritten-history attack would take; (6) **real, non-synthetic log growth**: mined an actual
  24-bit Hashcash stamp (real SHA-256 grinding, ~9.6M tries) and registered a real alias through the
  live `POST /alias/register` (the actual production append path, `AliasDO.handleRegister` ->
  `appendToTransparencyLog`), growing the log from a verified size=25 to size=26 — the monitor,
  re-run against its real prior baseline, fetched a REAL consistency proof from the live server,
  verified it with the real RFC 6962 algorithm, and reported OK-GREW (exit 0), confirming the
  positive path works against genuine append-only growth, not just its own negative controls. The
  JSONL audit trail (`--history-file`) correctly recorded all six verdicts (`BASELINE`,
  `OK-UNCHANGED`, three `ALARM`s, `OK-GREW`) as independent forensic evidence.
  **Honest scope, stated plainly:** this is the mechanism, not the deployment. Run from the same
  machine/account that operates `workers/messaging` (as every test above necessarily was), it proves
  the CODE works, not the THREAT MODEL it exists for — a single-operator monitor colludes trivially
  with a single-operator log. The property this whole feature is meant to buy requires a THIRD PARTY
  (or at minimum a separately-controlled account/schedule) actually running it on a cron against the
  public prod endpoint with a state file the primary operator cannot edit — not deployed or automated
  as part of this pass (no scheduled task, no publication of the script for outside operators to
  discover and run). No `apps/web` client-side verification wiring (unchanged from the STH pass's own
  gap) — a monitor is a server-operator/community tool, not a per-user browser check, so this is a
  deliberate scope boundary, not an oversight.
- **Done (2026-07, "reserved/verified namespaces" pass) — closes R18's last remaining "Not done"
  item repeated across three prior progress notes.** New `POST /alias/reserve` in `AliasDO.ts`: a
  `lookup_key` added to a new `reserved_namespaces` table can no longer be claimed by ordinary PoW
  alone — `handleRegister` additionally requires a `registrant_sig` binding an offline "namespace
  authority" key's approval to the SPECIFIC `alias_pub` attempting to register. A reserved name is
  therefore strictly HARDER to claim (PoW **and** an authority signature), never easier; the ordinary
  (non-reserved, overwhelming majority) path gained exactly one indexed `SELECT` and is otherwise
  byte-for-byte unchanged — checked BEFORE the PoW verification (cheap-check-first, same discipline
  as every other gate in this file).
  **Zero new Rust code — reused the crate's existing Ed25519 sign/verify (`alias_sig.rs`) wholesale,**
  the same primitive `/revoke` already uses: `verify(pubkey, message, sig)` doesn't care what the
  pubkey/message mean semantically, only that the bytes check out, so a second signed-action TYPE
  needed only new domain-separated message-prefix bytes (`"vortic-reserve-v1:"` /
  `"vortic-registrant-v1:"`) in TS, not a new crypto primitive.
  **Deliberately, the authority's signing key never touches Cloudflare at all** — unlike the RSABSSA
  issuer or the KT STH key (both sign LIVE per-request and therefore need `.dev.vars`/`wrangler
  secret put`), this authority signs rarely, offline, on an operator's own machine. New
  `workers/messaging/scripts/namespace-authority.mts` (`keygen`/`reserve`/`authorize` subcommands,
  reusing the crate's own `alias_lookup_key`/`identity_verifying_key`/`alias_sign_action` WASM
  exports — no second Ed25519 implementation) is the only place the seed is ever handled, and never
  writes it to disk itself. Only the PUBLIC key is committed, in new
  `src/namespace-authority-key.ts` (`kid`-keyed lookup table, same rotation-ready shape as
  `issuer-keys.ts`/`kt-sth-key.ts`) — a real, generated keypair for this pass, not a placeholder.
  **Live-verified with 10 checks against a real `wrangler dev` AliasDO, using the actual offline tool
  end-to-end (not a hand-crafted signature):** reserve without a capability -> 401 (the existing
  `/alias/*` capability gate applies to `/reserve` too, no special-casing needed); reserve with a
  tampered signature -> 401; a REAL reserve with a valid authority signature -> 204, idempotent
  re-reserve -> 204; registering the reserved name with no `registrant_sig` -> 403; a
  `registrant_sig` signed for a DIFFERENT `alias_pub` (an impostor trying to reuse someone else's
  grant) -> 401; a correct `registrant_sig` paired with garbage PoW -> still 403, proving the
  authority signature does **not** bypass PoW; the REAL full path (authority-authorized registrant +
  a genuinely mined 24-bit PoW stamp) -> 201; re-registering the same now-taken name -> 409 (same as
  any ordinary alias); and — the regression check that matters most — an ORDINARY, never-reserved
  nickname still registers with PoW alone, no `registrant_sig`, exactly as before. A separate 2-check
  pass confirmed the SAME reserve flow through the real OHTTP Gateway dispatch, including that the
  plaintext `lookup_key` never appears on the encapsulated wire.
  **Honest scope:** no UI for an operator to manage reservations (this is a `curl`/script-driven
  admin action, matching this feature's inherently-rare, offline-authority nature); no "list all
  reserved names" endpoint (not needed — an operator already knows what they reserved, and exposing
  the list publicly would hand squatters a target list of upcoming verified names); update-in-place
  for a registrant grant is not implemented (re-running `authorize` for the same name/different
  `alias_pub` produces a second valid signature, but nothing revokes the first — both remain
  independently valid until the name is actually claimed, an accepted, disclosed simplification for
  this pass, not a bug).
- **Done (2026-07, "Argon2id hardened PoW" pass) — R16 progress: `pow.rs` gets the SECOND `Hpow`
  option docs/03 §8.3 names** (`SHA-256 baseline | Argon2id hardened: memory-hard, botnet/GPU-
  resistant`) — only the SHA-256 mode existed before this pass. Same stamp grammar
  (`ver:alg:bits:epoch:resource:salt:counter`), same validity predicate
  (`leading_zero_bits(Hpow(stamp)) >= bits`); only `alg` becomes `"argon2id"` and `Hpow` becomes an
  Argon2id hash. New `mint_argon2id`/`pow_mint_argon2id` (client-full) — **added as a SEPARATE
  function, not a parameter on the existing `mint`/`pow_mint`**, specifically to avoid touching a
  REAL live caller found by checking first, not assumed absent: `apps/web/src/workers/
  powMiner.worker.ts` already calls `pow_mint` with its existing 4-argument signature. `verify`
  (unconditional) now dispatches on the stamp's own declared `alg`, accepting either — a backward-
  compatible generalization, not a breaking change (an existing `"sha256"` stamp verifies
  identically to before).
  **A real parameter-choice judgment call, stated plainly:** `backup.rs`'s existing Argon2id usage
  (m=256 MiB) is docs/03 §11's spec for stretching an already-high-entropy secret ONCE — completely
  wrong for a function that must run up to ~2^bits times per mint. This pass picks much lighter
  params (m=4 MiB, t=1, p=1) — still genuinely memory-hard relative to SHA-256's zero memory cost,
  but fast enough to mint in real time — and MEASURES the actual cost rather than assuming a number:
  a single Argon2id call at these params took **~2.66ms natively** (release profile); a full
  `mint_argon2id` search at a 9-bit target took **~1.33s** natively (found at counter 583, close to
  the 2^9=512 expected average) — both printed and recorded here, not guessed. Exact bit targets
  for real register/write/resolve-class difficulty under THIS param set are NOT decided in this
  pass (that's DO-wiring judgment, out of scope here) — but the real cost-per-attempt number now
  exists to base that decision on, where none did before.
  **`argon2` moved from a `client-full`-only optional dependency to an UNCONDITIONAL one**
  (`Cargo.toml`) so `verify` can compute an Argon2id digest at the edge too — same "verification is
  edge-safe" reasoning `ed25519-dalek`/`blind-rsa-signatures` already established for their own
  moves. `backup.rs`'s own `client-full`-gated module and behavior are completely unaffected; only
  the Cargo-level dependency gate moved. `bip39`/`aes-gcm` (backup.rs's other two deps) stay
  `client-full`-only, confirmed via `cargo tree`.
  **Verified two ways:** `cargo test --release --features client-full,issuer-full` — 77/77
  (crate-wide, up from 72; 5 new: argon2id mint/verify round-trip, wrong-resource/insufficient-bits
  rejection, a cross-alg test proving `verify` genuinely re-hashes under the stamp's OWN declared
  alg rather than always checking one hash regardless of label, and the two timing measurements
  above). `edge-verify-only` still builds clean for `wasm32-unknown-unknown`; `cargo tree` confirms
  `argon2` is now (correctly, intentionally) PRESENT in that profile while `ml-kem`/`x25519-dalek`/
  `kem`/`openmls`/`rayon`/`bip39`/`aes-gcm` remain absent — the plane-separation invariant holds
  with the new unconditional dependency too. AND a separate live Node probe against the actual
  COMPILED WASM, both `pkg/client` and `pkg/msg`: confirmed `pkg/msg` exports `pow_verify` but
  genuinely has NEITHER `pow_mint` NOR `pow_mint_argon2id` at all (mint stays client-only in both
  modes); a real WASM-mined 8-bit argon2id stamp (111ms, found at counter 66) verified identically
  through BOTH compiled profiles; the pre-existing SHA-256 path was re-run through the real WASM
  unchanged (3ms at 16 bits) to confirm it's genuinely unaffected, not just unchanged in the diff;
  relabeling a real argon2id stamp's `alg` field to `"sha256"` correctly fails edge verification
  (proving the digest is genuinely re-derived per the declared alg, not cached/reused); malformed/
  unrecognized-alg input rejected without throwing.
  **Honest scope, stated plainly, matching this module's own pre-existing precedent for the
  SHA-256 mode:** this crate-level `argon2id` mode is NOT wired into `AliasDO.ts`'s production
  verifier (`workers/messaging/src/pow.ts`, checked directly — still hardcodes
  `alg !== "sha256"` as a rejection), nor into any adaptive-difficulty or per-action bit-target
  policy. That is separate, later DO-side wiring work, consistent with how every other Phase 1
  primitive in this crate (kem, oprf, backup, group, ring) landed crate-core first.
- **Done (2026-07, "wire Argon2id PoW into AliasDO" pass) — closes the DO-wiring gap the pass above
  named by exact file path.** `workers/messaging/src/pow.ts`'s `verifyPowStamp` — the function that
  actually gates every live register/resolve/introduce request — now dispatches on the stamp's own
  declared `alg` instead of hardcoding `"sha256"`. SHA-256 stays plain `crypto.subtle.digest` (a
  single fast hash, no reason to add WASM overhead); `argon2id` is delegated to a REAL Argon2id
  computation via a new `pow-wasm.ts` loader (same `pkg/msg` edge-profile WASM bundle `zk-wasm.ts`/
  `blindsig-wasm.ts` already load, `initSync` idempotent across all three) calling `pow.rs`'s
  unconditional `pow_verify` — memory-hard hashing genuinely isn't reasonable to hand-roll in pure
  JS, unlike the SHA-256 mode.
  **The exact "choose real per-action bit targets" gap R16's row explicitly named is closed with a
  DERIVED number, not a picked one:** rather than hand-tuning a separate Argon2id bit target per
  action, `argonEquivalentBits(sha256Bits) = sha256Bits - ARGON2ID_BIT_DISCOUNT` derives it from the
  EXISTING SHA-256 target every call site already had. `ARGON2ID_BIT_DISCOUNT = 11` comes from two
  REAL measurements taken this pass, not assumed: a live 24-bit SHA-256 register-class mint on this
  machine took 9,583,205 tries in 11.468s (~1.197µs/attempt); `pow.rs`'s own timing test measured a
  single native Argon2id(m=4MiB,t=1,p=1) call at ~2.6824ms/attempt. Ratio ≈2240x → log2(2240)≈11 bits
  lower for equal expected wall-clock cost. Consequence: **every existing call site
  (`REGISTER_MIN_BITS=24`, resolve's adaptive base/max, `INTRODUCE_MIN_BITS=22`) needed ZERO code
  changes** — they still pass one number, which now transparently means "the SHA-256-equivalent
  difficulty for this action," and a client choosing to mint under `argon2id` automatically gets the
  cost-equivalent target derived from it.
  **Honest gap in the measurement itself, stated plainly:** the 2.6824ms figure is a NATIVE release
  build number (from `pow.rs`'s own test), not re-measured inside the actual WASM binary this Worker
  runs — plausibly somewhat slower again, the same class of native-vs-WASM timing gap `backup.rs`'s
  own Argon2id docs already disclose for their derivation. The derived discount is a reasonable
  estimate from real numbers, not a rounded-off guess, but not a WASM-in-Worker remeasurement either.
  **Live-verified against a real `wrangler dev` AliasDO with genuinely mined stamps (not synthetic
  bit-count assertions), two rounds:** (register route) a REAL argon2id stamp mined via the compiled
  `pkg/client` WASM (`pow_mint_argon2id`) at the derived 13-bit target (=24-11) accepted (201); the
  pre-existing real 24-bit SHA-256 path re-run unchanged to confirm zero regression (201); an
  argon2id stamp deliberately mined at a WEAKER 4-bit target correctly rejected (403, "insufficient
  PoW"); an argon2id stamp minted for the WRONG resource (a different `lookup_key`) correctly
  rejected (403); a wholly unrecognized `alg` (`"md5"`) correctly rejected with a clear reason; a
  genuine argon2id stamp replayed against a second, different resource correctly rejected on the
  resource-mismatch check (same replay-set machinery, unaffected by the alg change). (resolve route,
  regression check since this route wasn't directly touched) both a real 20-bit SHA-256 stamp and a
  real 9-bit argon2id stamp (=20-11) for the SAME never-registered lookup key both correctly pass PoW
  and reach the real "alias not found" 404 — proving PoW acceptance, not the unrelated existence
  check, for both algorithms. Mining was done fully upfront before firing any requests — this
  project's own prior-session lesson about `wrangler dev` local connections dropping (ECONNRESET)
  across a long synchronous CPU-bound mining pause held here too on the first attempt, fixed the same
  documented way.
  **Not done:** off-thread/worker-thread client miner for Argon2id specifically (unaffected by this
  pass — `apps/web`'s `powMiner.worker.ts` still only calls the SHA-256 `pow_mint`), in-Worker/WASM
  remeasurement of the Argon2id timing used to derive the discount, and any UI affordance for a user
  to actually CHOOSE the hardened mode (this pass makes the server accept it; nothing client-side
  offers it yet).
- **Done (2026-07, "adaptive difficulty for register/introduce" pass) — closes R15/R16's last named
  "Not done" scope note** ("adaptive difficulty on `/register`/`/introduce` (scoped to resolve only,
  per R15's specific enumeration-scraping angle)"). `AliasDO.ts`'s `adaptiveResolveBits` generalized
  into a shared `adaptivePowBits` method (same RateGateDO-counter-driven escalation, no cliff, just
  parameterized per action) plus a pure `adaptiveBits(count, base, step, bitsPerStep, max)`
  calculator — resolve's own behavior is BYTE-FOR-BYTE unchanged (same constants, same call shape),
  just reached through the shared helper instead of a copy-pasted method body.
  **Tuned independently per action, not copy-pasted from resolve's own numbers:** register
  (base=24, step every 3 attempts, +2 bits/step, cap 32) escalates FASTER than resolve (step every 5,
  +1 bit/step) — a registration attempt is rarer and higher-value than a lookup, so a repeat-target
  attacker (racing to grab a specific name, or grinding stamps against one about to be revoked)
  should hit escalating cost sooner. Introduce keeps resolve's own cadence (step every 5, +1/step,
  cap 30) starting from its existing 22-bit base — repeat-target intro-queue spam is closer in shape
  to repeat-target scraping than to a land-grab race.
  **Live-verified with 26 real checks total across two runs against a real `wrangler dev` AliasDO**
  (the second run fixed a TEST bug in the first — a wrong `sizeBucket` for a 23-byte ciphertext
  tripped `bucketing.ts`'s real validation on the introduce path's very last assertion; caught and
  fixed the same way this project's other "verify the comparison itself before concluding something
  is broken" lessons have been, not silently patched over): the required-bits number reported in a
  403 genuinely climbs from 24→26 after 4 garbage-stamp attempts against one `lookup_key` (and from
  22→23 after 6 against one `introQueueId`) — proving the counter-driven escalation is really wired,
  not just documented; a REAL stamp mined for the OLD base price (24 bits) is REJECTED once that
  same target has escalated to 26 (not a coin-flip risk — the pre-mined stamp's own real bit count,
  25, is shown directly in the rejection message, genuinely below the new 26-bit bar); a REAL stamp
  freshly mined AT the escalated 26-bit target for register (352s of real mining — the slowest single
  mint measured in this project so far, a real reminder that 26 bits is a meaningfully heavier ask
  than 24) is ACCEPTED; a REAL stamp mined at the escalated 23-bit target for introduce is ACCEPTED;
  and — cross-target isolation, the same check every rate-limit feature in this codebase carries —
  a completely different, never-touched `lookup_key` still only needs the unescalated BASE 24 bits,
  proving one hot target's counter never bleeds into another's. Mining was done fully upfront before
  firing any requests, same documented fix as the Argon2id-wiring pass above for the exact same
  `wrangler dev` local-connection-drop issue, which recurred here too (the very first attempt at this
  live test hit it again, this time because a 208-second mining pause left an idle connection stale)
  before being fixed.
  **Honest scope:** off-thread client miner unaffected (same standing gap named in every PoW-related
  row); no UI surfaces the current required-bits number to a user before they start mining (a client
  today only finds out the price was too low from a 403 after the fact, same UX gap resolve already
  had).
- **Still to implement (crate-core):** none remaining from this doc's original Phase 1 primitive
  list — VOPRF DLEQ (Phase 2 Airlock pass), MLS (real MLS group encryption pass), Argon2id/BIP39
  backup, bLSAG ring sigs, and now Argon2id-hardened PoW are all landed. Remaining Phase 1 work is
  UI/DO wiring (named per primitive above) and the hardening item below, not a missing primitive.
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
  structurally-equivalent mock, **not** Semaphore's real Poseidon/LeanIMT circuit. (This mock test still
  exists and still passes — the REAL Semaphore v4 circuit test, `real_semaphore_v4_vector_verifies`, was
  added alongside it, not in place of it; see the "Real Semaphore v4" entry further down.)
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
- **Done (2026-07, "Real Semaphore v4" pass — closes R21 server-side): the mock circuit is retired for the
  Messaging Plane's membership tree + ZK verifier.** Previously `MerkleTreeDO` computed a SHA-256-over-the-
  list placeholder root and `/auth/session` checked every proof against one fixed, shared vector from
  `zk_test.rs`'s mock circuit — this closes both gaps with the REAL, OFFICIAL Semaphore v4 circuit and a real
  per-request Merkle tree.
  - **Real circuit, not written from scratch:** the exact, unmodified `semaphore.circom` template from
    `@semaphore-protocol/circuits` v4.14.3 (github.com/semaphore-protocol/semaphore/packages/circuits/src),
    compiled with the real `circom 2.2.3` compiler (a prebuilt binary, no local build needed) against
    `circomlib` + `@zk-kit/binary-merkle-root.circom`'s real includes, MAX_DEPTH=20. Confirmed circuit shape
    empirically (not assumed): `identityCommitment = Poseidon2(Ax,Ay)` (BabyJubJub pubkey from a secret
    scalar — Semaphore v4's actual identity scheme, NOT v3's trapdoor/nullifier pair), `nullifier =
    Poseidon2(scope, secret)`, root via a variable-length `BinaryMerkleRoot` (confirming LeanIMT's dynamic-
    depth property at the circuit level), `nPublic=4` in circuit-output-then-input order:
    `[merkleRoot, nullifier, message, scope]`.
  - **`semaphore-rs` (Worldcoin's Rust crate, the obvious-looking candidate) was investigated and REJECTED**
    before writing any integration code: its `identity.rs` implements Semaphore v3's `{trapdoor, nullifier}`
    scheme (not v4's single-secret EdDSA scheme our docs commit to), its `poseidon_tree.rs` is a fixed-depth
    `MerkleTree`, not a LeanIMT, and its `build.rs` silently downloads a real trusted-setup zkey from a remote
    URL at `cargo build` time — wrong protocol version, wrong tree structure, and a network-dependent build
    besides. Caught by actually reading the crate's source rather than trusting its name/keywords.
  - **Trusted setup: real circuit, TEST-ONLY setup — not PSE's production ceremony.** `snarkjs`
    powersoftau(new→contribute→prepare phase2) + `groth16 setup` + a zkey contribution, run locally. Honest
    scope: this proves OUR verifier/tree/wire-contract pipeline is correct against the real circuit's real
    constraints; it does not attest to a specific mainnet ceremony's security. Swapping in PSE's published
    ceremony VK later is a drop-in change (same byte contract, same verifier).
  - **`MerkleTreeDO`'s `computeRoot()` now uses the REAL LeanIMT**, via the official `@zk-kit/lean-imt` +
    `poseidon-lite` npm packages **used directly, not re-implemented** — both are pure TypeScript/BigInt, no
    native/WASM dependency, so (unlike the RSABSSA pass) this needed ZERO Rust/WASM involvement. `commitments`/
    `nullifiers`/`issuer_token_null` tables are unchanged, per this task's explicit scope. Parity-verified: the
    exact same two leaves produce the exact same root via the TS module's logic and an independent Node script
    using the same packages (expected, since both call the same library — but confirms no bug in the
    hex↔field conversion glue). Added BN254 field-range validation on insert (reject a commitment ≥ Fr
    modulus) so a malformed value can never later crash `computeRoot()`'s read path.
  - **`zk.rs`'s verifier itself is UNCHANGED** — only `VK_HEX` (now real) and the public-input semantics
    changed, proving the "reuse the verifier, don't rewrite it" design genuinely holds. Added a permanent
    regression test, `zk_test.rs`'s `real_semaphore_v4_vector_verifies`, using a real proof/VK reconstructed
    from the actual generated artifacts — 22/22 tests green.
  - **`/auth/session`'s wire contract reworked for DYNAMIC public inputs:** the client now sends
    `merkleRoot`/`nullifier`/`message`/`scope` (each real, per-request field elements) instead of relying on a
    fixed shared vector; the Worker builds `public_inputs_bytes` from exactly what the caller sent
    (`session.ts`'s `buildPublicInputsBytes`) and — critically — fetches MerkleTreeDO's actual CURRENT root
    and rejects a mismatch (409) BEFORE running the expensive pairing check, closing the "valid proof against
    a stale/replayed root" gap a fixed-vector design couldn't even express.
  - **Verified live, full chain, both `wrangler dev` instances restarted fresh** (stale local DO storage from
    the mock-root era was cleared first — old random hex "commitments" were never real field elements/
    identities and could have poisoned the new real root computation): two real RSABSSA redemptions → real
    `MerkleTreeDO` root (confirmed byte-identical to an independently-computed reference root) → a real
    Groth16 witness+proof generated via `snarkjs.groth16.fullProve` against the real circuit for that exact
    root/identity → `POST /auth/session` → **200 + capability**. Worker log: `[Session]
    zk_verify_groth16_bytes -> true`. Negative controls, same live server: replay (same nullifier) → 409;
    claimed-but-wrong `merkleRoot` → 409 (`"merkleRoot does not match the current membership tree root"`,
    caught before verification even ran); tampered proof bytes → 401
    (`zk_verify_groth16_bytes -> false`). `schema-lint` clean.
  - **Deliberately NOT done in this pass (see R23):** `apps/web`'s `AuthCallback.tsx` was explicitly out of
    scope ("не трогать UI/Security Gate") and still references the retired mock vector — the live browser
    flow will now fail at step 5 until a follow-up wires real client-side proving (needs the circuit
    `.wasm`+`.zkey` bundled into the web app). Flagged clearly rather than silently patched, since fixing it
    either means building real client proving (a separate, larger task) or making a UI judgment call outside
    this task's stated boundary. Root history/staleness tolerance (accepting a *recent* root, not only the
    exact current one) is a reasonable future enhancement, not implemented — the simple "current root only"
    check is correct, just less forgiving of concurrent tree growth between a client fetching a root and
    submitting its proof.
- **Done (2026-07, "R21-continued" pass — replaces the local test-only trusted setup with a REAL
  multi-party ceremony VK).** The entry above intentionally used a single-party local Groth16 setup and said
  so plainly — this pass swaps that toxic-waste-known-to-one-party VK for PSE's actual production ceremony
  key, closing that gap.
  - **`git grep` across all history for `*.zkey`/`*.ptau`: zero matches.** Nothing toxic-waste-bearing was
    ever committed to this repo — the local test-only zkey generated for the original R21 pass lived only in
    a scratchpad temp directory outside the repo and was never at risk of leaking through git history.
  - **Official artifacts DO exist for our exact circuit (depth=20, MAX_DEPTH matching `MerkleTreeDO`)** —
    found, not assumed: `@zk-kit/semaphore-artifacts@4.13.0` (npm, maintained by PSE, homepage
    github.com/privacy-scaling-explorations/snark-artifacts) ships `semaphore-20.{json,wasm,zkey}` —
    `.json` is `verification_key.json` (snarkjs export format), `nPublic=4`, `IC.length=5`, matching our
    circuit shape exactly.
  - **Real multi-party ceremony, not a rebrand of a single-party one.** "Semaphore V4 Ceremony 1" — a
    Groth16 Phase 2 MPC ceremony run by PSE, 300-400+ independent contributors, finalized 2024-09-05.
    Verified via two independent contributor attestation gists: NicoSerranoP's finalization attestation
    (gist.github.com/NicoSerranoP/10b09d0539cb87445fee2d3d98cda96a, dated 2024-09-05, circuit
    `semaphorev4-1`) and hw010101's attestation (gist.github.com/hw010101/cccbdf986150b96d706b935668693a0e,
    dated 2024-06-23, contributor #291→#240 across **all 32 circuits `semaphorev4-1`..`semaphorev4-32`** —
    confirming the ceremony covers every supported tree depth 1..32 as separate sequential circuits within
    one coordinated event, `semaphorev4-20` being ours). As long as one of those hundreds of contributors
    destroyed their randomness, the toxic waste is unrecoverable — the real MPC trust assumption.
  - **File integrity checked, not assumed:** `semaphore-20.{json,wasm,zkey}` downloaded via unpkg and
    sha256-verified byte-for-byte against the hash **npm itself** reports for that exact published file
    (`unpkg.com/...?meta`'s `integrity` field). This confirms the download wasn't corrupted/tampered in
    transit — it does **not** independently re-derive npm's own hash from a separate root of trust (see
    "not independently verified" below).
  - **A real ecosystem version-skew bug found and worked around, not papered over:** the official client
    library `@semaphore-protocol/proof@4.11.1`'s `generateProof()` builds a witness input named
    `merkleProofIndices` (plural — a per-level bit array, the v3-era encoding), but the actual circuit ABI
    baked into these downloaded artifacts declares a single scalar `merkleProofIndex` (confirmed by reading
    the current `semaphore.circom` source and by direct empirical probing — `snarkjs.groth16.fullProve`
    rejects the plural array at every depth, accepts the scalar at exactly depth 20). Worked around by
    driving `snarkjs` directly with the correct signal names instead of going through the stale client
    library — not a problem with the ceremony artifacts or our own code, an upstream library/circuit drift
    worth knowing about if this codebase ever adopts `@semaphore-protocol/proof` client-side for R23.
  - **Validated offline first, cheaply, before touching Worker code** (same discipline as the original R21
    pass): a real 2-leaf LeanIMT tree (two real `@semaphore-protocol/identity` identities), a real Merkle
    proof, a real Groth16 witness+proof via `snarkjs.groth16.fullProve` against the OFFICIAL
    `semaphore-20.wasm`/`.zkey` — `snarkjs.groth16.verify()` against the official VK: **true**. Converted to
    `zk.rs`'s byte contract and checked natively: `zk_test.rs`'s new
    `official_ceremony_semaphore_v4_vector_verifies` test — **arkworks accepts it**, and correctly rejects a
    tampered public input. Full native suite: **23/23 passing** (up from 22, the one new test).
  - **`VK_HEX` in `session.ts` swapped to the official-ceremony key** (only the constant + header comment
    changed — `zk.rs`'s verifier, `MerkleTreeDO`'s LeanIMT logic, and the wire contract are all byte-for-byte
    unchanged from the original R21 pass, confirming the design's VK is a drop-in swap as promised at the
    time). `pnpm exec tsc --noEmit` clean.
  - **Verified live, full chain, against the OFFICIAL ceremony VK — both `wrangler dev` instances restarted
    fresh** (stale local DO storage from the earlier test-only-VK pass cleared first): two real RSABSSA
    redemptions → real `MerkleTreeDO` insert (root confirmed byte-identical to an independently-computed
    reference) → a real Groth16 proof generated with the **official** `semaphore-20.wasm`/`.zkey` → `POST
    /auth/session` → **200 + capability**. Live worker log: `[Session] zk_verify_groth16_bytes -> true` (this
    is the WASM build of `zk.rs` actually running inside the Workers runtime, not just the native `cargo
    test` — both independently confirm acceptance). Same three negative controls as the original pass, same
    live server: replay → 409; wrong `merkleRoot` → 409 (caught pre-pairing); tampered proof → 401
    (`zk_verify_groth16_bytes -> false`).
  - **What was NOT independently re-verified, said plainly:** the full ~300-400-contribution MPC transcript
    (each intermediate contribution's hash chain, beacon computation, `p0tion` ceremony-coordinator replay)
    was not reproduced by this pass — that is a materially heavier audit (would mean re-running PSE's own
    ceremony-verification tooling across hundreds of recorded contributions) than downloading the published
    end result and confirming it's structurally and cryptographically the right shape for our circuit, which
    is what was actually done here. This is the same trust level essentially every project consuming these
    artifacts operates at (there is no independent third-party re-audit published anywhere we found either);
    flagging the gap rather than implying a full audit happened.
  - **Остаточное доверие (явно, для будущего пересмотра перед продом):** Верифицированы: file integrity
    опубликованного zkey/wasm (sha256 против npm), структурная/криптографическая корректность против нашего
    circuit (via `zk_test.rs`), и два независимых contributor attestation (NicoSerranoP — finalizer, circuit
    #1; hw010101 — contributor #240-291, все 32 схемы включая `semaphorev4-20`). НЕ верифицирована полная
    транскрипт-цепочка ~300+ вкладов (hash chain между последовательными контрибуциями через p0tion/PSE
    tooling) — известное остаточное доверие, приемлемое для текущей стадии (pre-deployment), но требующее
    полного transcript-аудита перед прод.
  - **Net effect on R21's risk-register status:** the "single local operator knows the toxic waste" caveat
    from the original R21 entry is now closed. R21 remains annotated as not-fully-closed only because of
    R23 (no real client-side proving yet) — see below.
- **Done (2026-07, "R23: real client-side proving" pass — partially closes R23, sole-member case only).**
  Budget-constrained follow-up: `AuthCallback.tsx`'s step 5 generates a genuine Groth16 proof in-browser
  instead of sending the retired mock vector.
  - **Reused the R21-continued server reference E2E's call sequence** (RSABSSA redemption → real identity
    → insert → prove → `/auth/session`) rather than re-deriving it — only the proving step itself is new.
  - **The official ceremony artifacts (`semaphore-20.{wasm,zkey,json}`, sha256-verified in R21-continued)
    were copied — not re-downloaded — into `apps/web/public/zk/`** and confirmed to survive a real
    `vite build` + `vite preview` round-trip (correctly bundled, correctly served over HTTP, byte-length
    confirmed via `curl`).
  - **New client module `apps/web/src/lib/zkProof.ts`** drives `snarkjs.groth16.fullProve` directly with
    the real circuit's actual signal names (same `merkleProofIndex`-not-`merkleProofIndices` finding as
    R21-continued), computing `scope = H(epoch)` per docs/03 §3 and a fixed domain-separated `message`
    (no other established meaning existed for it yet).
  - **A real, load-bearing scope boundary was hit and is stated plainly, not glossed over:** building a
    Semaphore Merkle proof needs the FULL ordered leaf set (or at least a proof for one's own leaf) — and
    `MerkleTreeDO` exposes only `/root` (root only) and `/insert` (root+size). There is no
    "give me my Merkle proof" endpoint. Adding one means touching `MerkleTreeDO`, which this pass's own
    scope explicitly excluded ("только клиентский шаг ZK-пруфинга"). Consequence: `zkProof.ts` only
    supports proving membership when the caller's identity is the tree's SOLE member
    (`size === 1` right after its own insert — a LeanIMT with one leaf has `root === that leaf`, zero
    siblings, needing no path data from the server at all). For any tree with prior members it throws a
    descriptive error rather than silently sending a proof that would just fail server-side verification.
    **Not a workaround, a real remaining follow-up:** a real deployment needs `MerkleTreeDO` to answer
    "what's the Merkle proof for commitment X", which is separate, real work. **Resolved in the very next
    pass** — see "R23 follow-up: MerkleTreeDO /proof/:commitment" below; this sole-member restriction no
    longer applies.
  - **Live-verified, full chain, real HTTP servers, real bundler output:** two prior server DO restarts
    with cleared state were needed mid-pass (the sole-member precondition requires an empty tree; each
    verification attempt inserts one real identity) — done deliberately, not accidentally. `vite build`
    succeeded (789 KB main JS chunk including `snarkjs`, one >500 KB chunk-size warning noted, not
    addressed — code-splitting is a separate concern from this pass). `vite preview` served the real
    production build; `curl` confirmed `/zk/semaphore-20.{wasm,zkey}` reachable over HTTP with correct
    byte lengths. A driver script exercising the exact same witness-construction logic as `zkProof.ts` (not
    reimplemented differently) against the real backend workers: real RSABSSA redemption → real identity
    → `POST /membership/insert` → `size: 1` → real Groth16 proof (**485ms** wall-clock proving time — well
    under the "1-2s = flag it, don't optimize" threshold this task set, so not flagged as a UX concern) →
    proof's own `merkleRoot` output confirmed byte-identical to the server-reported root → `POST
    /auth/session` → **200 + capability**. Live worker log: `[Session] zk_verify_groth16_bytes -> true`
    (the real Workers-runtime WASM verifier, not a native test).
  - **Honest limitation on HOW this was tested:** no actual browser-automation tool was available in this
    session (no Browser-pane access), so this is NOT a literal clicked-through UI test. What WAS done: the
    real `vite build`/`vite preview` output, real HTTP-servability of the real artifacts, and the exact
    witness-construction logic `zkProof.ts` uses, run against the live backend. What's NOT independently
    re-confirmed: `snarkjs`'s own browser-side `fetch()`-based artifact loader specifically (its Node-side
    loader was exercised instead, since `snarkjs`'s environment detection is `typeof window`-based, not
    path-format-based, and no `window` exists in a plain Node process) — that is standard, widely-used
    `snarkjs` library behavior, not this codebase's own code, but it is a real, disclosed gap between "this
    was tested" and "a user clicked through the real page." A genuine UI click-through (or adding real
    browser automation to this environment) is the natural next verification step, not done here.
  - **A test-script bug was caught and fixed before being reported as a finding:** an early run appeared to
    show the circuit's own `merkleRoot` output NOT matching the server's reported root — investigated before
    concluding anything was broken, and traced to the verification script comparing a decimal-string
    public signal against a hex-string root without converting between bases; the underlying values were
    numerically identical once compared correctly. Recorded so this isn't mistaken for a resolved crypto
    bug — it was never a crypto bug.
  - **Found in passing, not fixed, not this pass's scope:** the live worker log showed a caught,
    non-fatal `D1 mirror error (nullifiers): table nullifiers has no column named nullifier` on a
    successful `/auth/session` call — a pre-existing D1 migration/DO-schema drift in the best-effort
    `waitUntil` mirror path (already wrapped in its own `.catch`, per `MerkleTreeDO.ts`), unrelated to R23
    and not touched here. Worth a follow-up look, flagged rather than silently noticed and dropped.
- **Done (2026-07, "R23 follow-up: MerkleTreeDO /proof/:commitment" pass) — closes R23's sole-member
  restriction, R23 now fully resolved.** The previous pass's own flagged remainder: a real Merkle-proof-
  retrieval endpoint, so client-side proving works for a tree of any size, not just one.
  - **New `MerkleTreeDO` route, `GET /proof/:commitment`:** rebuilds the LeanIMT from the full commitment
    list (same construction `computeRoot()` already uses — not a second implementation), looks up the
    caller's leaf index, calls the same `@zk-kit/lean-imt` `generateProof()` used throughout this
    codebase's server-side testing, returns `{index, siblings (hex64[]), merkleRoot}`. Forwarded through
    `workers/messaging/src/index.ts`'s new `GET /membership/proof/:commitment`.
  - **Deliberately no capability gate, per explicit instruction:** Semaphore's whole design is "prove I'm
    one of these known commitments without saying which" — the commitment set (and by extension, any
    single sibling path) is public information, not a secret the protocol tries to hide. This endpoint is
    also called BEFORE a session capability can exist (chicken-and-egg: the client needs this proof to
    attempt `/auth/session` at all), matching the pre-existing openness of `/root` and `/membership/insert`.
  - **Cost noted, not fixed, as instructed:** this endpoint pays the same O(n) "rebuild the whole tree from
    the commitments table" cost `/root` and `/insert` already paid before it existed — it doesn't introduce
    a new cost CLASS, just one more caller of an existing pattern. Fine at the hundreds-of-members scale
    this was built/tested against; flagged in `MerkleTreeDO.ts`'s header comment as the first place to look
    if latency becomes a problem at thousands+ members (fix would be incremental/cached tree state,
    deliberately not built now since it isn't a measured bottleneck).
  - **`apps/web/src/lib/zkProof.ts` reworked:** `proveSoleMemberSession(identity, size)` → `proveMembershipSession(identity, merkleProof)`, where `merkleProof` comes from the new endpoint (fetched by
    `AuthCallback.tsx`, matching this codebase's existing "network calls live in the page component, crypto
    lives in the lib module" split). Pads the real siblings to `MAX_DEPTH` with zeros for the unused
    levels — that part of the earlier trivial-case logic was correct and is reused, not rewritten.
  - **Live-verified: TWO real identities, proof requested for the SECOND (non-first) one — the key
    regression check** (the task's own words: testing only the first/trivial member would not catch a
    broken sibling-path/index). Real RSABSSA redemption ×2 → member A inserted (`size:1`) → member B
    inserted (`size:2`) → `GET /membership/proof/<B's commitment>` → `{index:1, siblings: 1 sibling}` →
    real Groth16 proof → circuit's own `merkleRoot` output confirmed byte-identical to the proof
    endpoint's `merkleRoot` → `POST /auth/session` → **200 + capability** for B. Then the same for A
    (`index:0`) to confirm the first member still works too → **200 + capability**. Live worker log for
    both: `[Session] zk_verify_groth16_bytes -> true`.
  - **Net effect on R23's risk-register status:** the sole-member restriction — R23's only remaining gap
    after the previous pass — is closed. R23 is now fully **Resolved**, not "resolved for the trivial case."
- **Done (2026-07, "/proof rate limit" pass) — closes the DoS gap the previous pass's own cost note flagged.**
  `GET /membership/proof/:commitment` is necessarily unauthenticated (chicken-and-egg: it's needed to even
  attempt `/auth/session`) and pays an O(n) tree-rebuild per call — an unrate-limited caller who already
  knows one commitment could force unlimited rebuilds against it. `RateGateDO` (previously an unimplemented
  `501` stub) now backs a generic `POST /check {key, limit}` counter, sharded by epoch bucket per docs/04
  (a fresh counter set every epoch — no explicit reset/cleanup logic needed). The proof route checks
  `key = "proof:" + commitment`, `limit = 20` per epoch, BEFORE touching `MerkleTreeDO` — a rejected caller
  never triggers the expensive rebuild at all. Deliberately per-COMMITMENT, not per-IP/OHTTP-session: real
  client IPs aren't reliably available in this OHTTP-fronted architecture (docs/03 §10), and per-commitment
  keying directly targets the actual realistic threat (repeatedly hammering ONE known commitment), not
  broad enumeration (which the commitment set being public doesn't newly enable — there's still no
  "list all commitments" endpoint). Same primitive is meant to be reused for the still-TODO capability-
  issuance rate limit `RateGateDO`'s own header comment already anticipated, not a proof-specific mechanism.
  **Live-verified:** 25 sequential requests against one real commitment → first 20 return 200, the next 5
  return 429 with a clear error message; a second, different real commitment's first request returns 200
  unaffected by the first commitment's counter (confirms per-key isolation, not a global limit).
- **Done (2026-07, "capability-issuance rate limit" pass) — closes the still-TODO gap the previous
  pass's own comment flagged.** `POST /auth/session` had NO rate gate at all: the nullifier-spend
  check (the only replay guard) ran AFTER the ~0.8 s Groth16 pairing verify (R1), so replaying the
  same `(proof, nullifier)` pair forced a full expensive re-verification on every resend before ever
  reaching the cheap check that would reject it — a real amplification path, not just a missing nice-
  to-have. Reused the exact same `RateGateDO` `/check` primitive the proof-rate-limit pass built,
  `key = "session:" + nullifier`, `limit = 5` per epoch, checked right after the (already-existing)
  cheap `merkleRoot` staleness check and before the pairing verify — same "cheap check before
  expensive work" ordering this function already used once. **Live-verified** (fresh local
  `wrangler dev`, stale `.wrangler` D1/DO state cleared first per this doc's own convention): 5
  attempts with a fixed nullifier all reached the real pairing check (`zk_verify_groth16_bytes ->
  false`, 401); the 6th and 7th were rejected with 429 *before* that log line ever printed — proof the
  short-circuit actually fires pre-verification, not just post-hoc; a different nullifier's first
  attempt still reached the pairing check unaffected (401, not 429) — confirms per-key isolation, same
  discipline as the `/proof` rate-limit test. `tsc --noEmit` clean, `schema-lint` clean (no schema
  changes).
- **Done (2026-07, "adaptive resolve difficulty" pass) — R15/R16 progress: `/alias/resolve` no
  longer charges a flat 20-bit PoW price regardless of how hot a target is.** Real gap closed: a
  scraper could hammer ONE known/guessed alias arbitrarily many times per epoch at the same flat
  cost — R15's own mitigation column ("adaptive/per-target difficulty") was still unimplemented.
  `AliasDO.ts` gained `adaptiveResolveBits(lookupKey)`: reuses the exact `RateGateDO` `/check`
  counter primitive the `/proof` and capability-issuance rate limits already established (its own
  header comment explicitly anticipated more callers), but instead of hard-blocking at a limit, the
  running per-epoch attempt count for that ONE `lookup_key` raises the required bits —
  `20 + floor((count-1)/5)`, capped at 28 — so the counter is bumped and the new bar computed BEFORE
  spending any work verifying the stamp (an under-difficulty probe still pushes the bar up, not a
  free look at the old price). Fails toward the MAX difficulty (not the base) if `RateGateDO` is
  unreachable — falling back to the cheapest price on that failure would make "make RateGateDO
  unreachable" a perverse incentive, caught during design, not after.
  **Live-verified** (fresh local `wrangler dev`, real mined stamps via the compiled `pkg/client`
  WASM's `pow_mint`, no shortcuts): attempts 1-5 against one real registered alias, each with a
  fresh real 20-bit stamp, all succeed; attempt 6 with a 20-bit stamp is rejected (403, message
  correctly states "required 21 bits"); the SAME attempt retried with a real 21-bit stamp succeeds;
  a different, never-touched `lookup_key`'s first attempt still only needs 20 bits (per-key
  isolation, not a global counter) — confirmed by a 404 (alias genuinely doesn't exist) rather than
  a 403 (PoW bar was never the blocker for it). `tsc --noEmit` clean, `schema-lint` clean (no schema
  changes — the counter reuses `RateGateDO`'s existing table).
  **Honest scope:** deliberately resolve-only, per R15's specific enumeration/scraping framing —
  `/register` and `/introduce` keep their flat bit costs. R16's other named mitigations (memory-hard
  Argon2id PoW option, off-thread client miner) are untouched by this pass.
- **Done (2026-07, "incremental tree cache" pass) — closes the R23-follow-up COST NOTE
  (`MerkleTreeDO`'s own header comment flagged this as "the first place to look if latency becomes a
  problem").** `/root`, `/insert`, and `/proof/:commitment` used to rebuild the ENTIRE LeanIMT from
  scratch (n Poseidon2 hashes) on every single call. Fixed using `@zk-kit/lean-imt`'s OWN
  `tree.export()`/`LeanIMT.import()` (serialize/deserialize without recomputing any hash) and its
  incremental `tree.insert(leaf)` (O(log n)) — reused verbatim, not reimplemented, matching this
  file's own "use the reference implementation, don't rewrite it" precedent from the original R21
  pass. A new `tree_cache` DO-internal SQLite row (`{size, exported}`) is the source of truth for a
  warm cache; `loadTreeForSize(n)` imports it when the recorded size matches the current commitment
  count, else falls back to the original full rebuild (a size mismatch — should be unreachable in
  normal single-threaded DO operation — is logged, not silently papered over). `/insert` loads the
  PRE-insert cached state BEFORE writing the new commitment row (loading after would double-count the
  just-written row when the cache-miss fallback re-reads the table), calls `.insert()`, then persists
  the updated state — detects a genuinely-new vs. idempotent-retry insert via `SqlStorageCursor
  .rowsWritten` on the `INSERT OR IGNORE`, so a retried request touches neither the tree nor the
  cache. `handleProof` also switched from a hand-rolled linear scan for the leaf index to the
  library's own `tree.indexOf()`.
  **Live-verified, real end-to-end, not simulated:** four REAL commitments redeemed through the full
  RSABSSA chain (`workers/enrollment`'s real `/token/issue` against the real committed issuer
  keypair, no shortcuts) and inserted one at a time — after EVERY insert, the Worker's reported
  `merkleRoot`/`size` were compared against an INDEPENDENTLY built reference tree (same
  `@zk-kit/lean-imt`+`poseidon-lite` packages, a completely separate in-script tree, not reusing
  `MerkleTreeDO`'s code) and matched byte-for-byte all 4 times — the same "parity-verified"
  discipline the original R21 pass established. `GET /proof/:commitment` checked for BOTH the last
  (non-first — the regression case that actually exercises sibling paths) and first member, index/
  siblings/root all matching the reference tree exactly. **Durability, not just correctness, checked
  separately:** killed the live `wrangler dev` process outright and started a completely fresh one
  against the SAME on-disk state (no rebuild-from-D1, no reseeding) — a brand-new DO instance,
  READ-ONLY (zero new inserts), correctly served all 4 commitments' proofs with the exact same root
  as before the restart, proving `tree_cache` genuinely persisted to durable storage rather than
  just staying warm in a live process's memory. Real observed timings, not claimed as a rigorous
  before/after benchmark: post-restart cached proof calls ran **4.7-9.6ms** (first call 62.9ms,
  cold-start overhead). `tsc --noEmit` clean, `schema-lint` clean (`tree_cache` is DO-internal
  SQLite, same non-D1-migrated situation this file's own header comment already documents for
  `commitments`/`nullifiers`).
  **Honest gap:** no adversarial test deliberately corrupted the cache to exercise the size-mismatch
  fallback path live (only reasoned through and code-reviewed) — the fallback logic is a straight
  reuse of the pre-existing rebuild code path, low-risk, but not itself live-fired in this pass. No
  formal before/after latency benchmark at the "thousands of members" scale the original cost note
  named as the threshold to worry about — this pass proves correctness and a real durability
  property, not a quantified performance claim at scale.
- **Done (2026-07, "Key Transparency (K8)" pass) — R18 progress: `alias_pub` bindings are now a
  publicly-auditable, append-only log, not just a mutable live table.** Real gap closed: before this,
  nothing stopped a compromised/malicious `AliasDO` from silently telling different askers different
  keys for the same nickname (equivocation) — no witness of what was ever published, and no way for
  an outside observer to catch a lie. New `KeyTransparencyDO` (`workers/messaging`, new DO class +
  wrangler.toml migration `v4`): every `AliasDO` register/revoke event is appended as a leaf in a
  REAL Merkle tree over SHA-256 (`@zk-kit/lean-imt` — the SAME official library `MerkleTreeDO`
  already uses for the Semaphore tree, reused again, not reimplemented), using the exact incremental-
  cache technique the "incremental tree cache" pass above just established (`tree.export()`/
  `LeanIMT.import()`/`tree.insert()`, a `kt_tree_cache` row) — this pass is a direct beneficiary of
  that one, not a coincidence of timing. Leaf preimage is domain-separated and position-bound
  (`vortic-kt-v1:{event}:{lookup_key}:{alias_pub}:{seq}`) so even a content-identical event (e.g. two
  revokes back to back) never collides on the same leaf. `AliasDO.ts`'s `handleRegister`/
  `handleRevoke` AWAIT the append (a deliberate difference from `MerkleTreeDO`'s fire-and-forget D1
  mirror: here the log genuinely must stay in lock-step with the live table or the whole point of
  auditability breaks) but don't hard-fail the parent operation on a log outage — logged loudly
  instead, since a real alias register/revoke doesn't depend on the log for ITS OWN correctness.
  Three new public, unauthenticated GET routes (`/transparency/root`, `/transparency/latest/:key`,
  `/transparency/proof/:seq`) — deliberately open, matching `/membership/proof/:commitment`'s own
  reasoning: hiding a transparency log behind a capability defeats the point of a log anyone can
  independently audit. `/append` itself has no public route — only `AliasDO` can write, via the
  internal DO binding.
  **A real toolchain gap hit and fixed, not glossed over:** `LeanIMT`'s hash function must be
  SYNCHRONOUS, but Workers' only native SHA-256 (`crypto.subtle.digest`) is async-only — solved with
  `node:crypto`'s synchronous `createHash` (this Worker already opts into `nodejs_compat` in
  `wrangler.toml`, so it's available at runtime), which needed `@types/node` added as a **dev-only**
  dependency (zero runtime/bundle footprint) plus `"node"` added to `tsconfig.json`'s `types` array
  for it to typecheck — Cloudflare's own documented pattern for this exact combination, not an ad hoc
  workaround.
  **Live-verified, real end-to-end, fresh `wrangler dev`:** registered a real alias (real PoW, real
  Ed25519 `alias_pub`) — `/transparency/latest` correctly showed a `register` event at seq 1, and its
  inclusion proof matched an INDEPENDENTLY built reference tree (separate script, separate
  `createHash` calls, not reusing `KeyTransparencyDO`'s code) byte-for-byte. Revoked it (real
  signature) — `/latest` correctly flipped to a `revoke` event at seq 2 with an empty `aliasPub`.
  **The append-only property itself was checked, not just asserted:** fetched entry #1's proof AGAIN
  after the tree had grown to size 2 — the returned root, index, and siblings had genuinely changed
  (correctly reflecting the bigger tree) yet still independently verified against the reference tree,
  proving old entries stay provably included as the log grows, not just present. Re-registered the
  SAME nickname under a DIFFERENT identity after the revoke — succeeded (proving revoke really freed
  it in `AliasDO`'s live table) and produced a THIRD log entry, correctly becoming the new `/latest`
  for that lookup_key. An untouched nickname correctly 404s. **Durability checked separately, same
  discipline as the tree-cache pass above:** killed the live `wrangler dev` process and started a
  completely fresh one against the same on-disk state — `/transparency/root` and `/transparency/
  proof/1` returned byte-identical results with zero new writes, confirming `kt_tree_cache` truly
  persisted rather than living only in a warm process's memory. `tsc --noEmit` clean, `schema-lint`
  clean (added `KEY_TRANSPARENCY_DO` to `PLANE_FORBIDDEN_BINDINGS.enrollment` proactively, matching
  every other Messaging-only DO already listed there).
  **A real test-script bug caught and fixed before being reported as a finding, not silently
  worked around:** an early re-registration attempt after revoke returned 409 and looked like a real
  bug (alias not actually freed) — traced to the TEST SCRIPT reusing the same deterministic PoW salt
  for both registration attempts of the same nickname, so `pow_mint` reproduced the byte-identical
  stamp and tripped the (correct, pre-existing) stamp-replay guard before ever reaching the alias-
  registration check. Fixed by varying the salt between calls; not a `KeyTransparencyDO`/`AliasDO`
  bug. Recorded so it isn't mistaken for a resolved product bug later.
  **Honest scope, stated plainly (this is "Mitigated," not "Closed" — see R18's own risk-register
  row):** no RFC 6962 cross-time consistency proofs (a structural proof that an OLDER root is a
  genuine prefix of a NEWER one, independent of any single leaf's inclusion proof — the piece that
  would let an auditor catch a log that forked for one victim without needing to already trust this
  operator's current root), no independent monitors/gossip between separate observers, and no
  `apps/web` client-side verification wiring (fetch a proof, check it locally, compare against a
  cached tree head) — this pass is the append-only log and inclusion-proof machinery only, a real
  precondition for those, not a substitute.
- **Done (2026-07, "server-side bucketing" pass) — R7 progress: closes a gap this doc had implicitly
  assumed was already handled.** docs/03 §6 (Sealed Sender++) point 4 says plainly: "constant-size
  envelopes via length padding to power-of-two buckets; timestamps bucketed server-side." Checked
  before writing anything, not assumed: `grep` across `QueueDO.ts`/`GroupDO.ts`/`ConvLogDO.ts` showed
  EVERY one of them stored and returned a raw `Date.now()` — no server-side timestamp bucketing
  existed anywhere in this codebase, despite R22's "Sealed Sender++" closure covering points 2/3
  (pairwise transport, padded/delayed/decoupled receipts) but never actually landing point 4. Worse:
  `QueueDO`'s existing `size_bucket` field was CLIENT-DECLARED and never validated against the real
  ciphertext length — a lying or buggy client could claim any bucket, silently defeating the padding.
  New shared `bucketing.ts`: `bucketTimestamp` (floor to a 1-minute boundary, tunable) and
  `validateSizeBucket` (real check: ciphertext length must fit `(2^(b-1), 2^b]` for declared bucket
  `b`, not just "some number the client typed").
  **A real design decision made and documented, not the obvious default:** bucketing happens AT
  WRITE TIME (before the row is ever persisted), not only when a response is formatted. docs/02's
  PRIMARY adversary A2 is the host itself — "reads all D1/R2/DO state" — so bucketing only at
  response time would protect against nothing that adversary actually does; it would only raise cost
  for a weaker, secondary adversary (a passive network observer). Real TTL/eviction timing (`QueueDO`)
  still uses the UNBUCKETED real clock internally — only the `enqueued_at` value that gets stored and
  exposed is coarsened, so scheduling correctness is unaffected.
  Applied to `QueueDO.ts` (real `validateSizeBucket` check added to `/push`, replacing the previous
  trust-the-client behavior), `GroupDO.ts` (gained a `size_bucket` column via the same guarded-`ALTER
  TABLE` migration pattern `AliasDO.ts`'s `alias_pub` column established, plus a wire-format change —
  `blobs` becomes `{blob, sizeBucket}[]` per entry, since a group batch can genuinely mix different
  real message sizes, unlike `QueueDO`'s one-ciphertext-per-call shape; verified beforehand that no
  client code calls this route yet, so this is a clean addition, not a breaking change to a live
  caller), and `ConvLogDO.ts` (timestamp bucketing ONLY — the original D1 schema for `conv_log` never
  had a `size_bucket` column, so this pass doesn't invent a padding requirement CRDT op-log entries
  were never designed to carry).
  **Live-verified, real `wrangler dev`, all three DOs:** `QueueDO` — a correctly-bucketed 32-byte
  push (bucket 5) succeeds; the SAME ciphertext declared as bucket 8 (way oversized) rejects with
  400; declared as bucket 4 (too small to actually fit 32 bytes) also rejects with 400 — both
  directions of the lie are caught, not just one; a pulled message's `enqueuedAt` is confirmed to be
  an exact multiple of 60000ms AND the correct floor of the real push instant (not just "some"
  multiple of 60000). `GroupDO` — a batch with one honest and one lying entry rejects the WHOLE
  batch (no partial-write inconsistency); a correct batch succeeds and `/sync` reflects both the
  stored `sizeBucket` and a correctly-bucketed `enqueuedAt`. `ConvLogDO` — append + sync confirms
  `enqueuedAt` is bucketed and, deliberately, carries no `sizeBucket` field at all. `tsc --noEmit`
  clean, `schema-lint` clean (no D1 migrations touched — these are DO-internal SQLite columns, same
  non-D1-migrated situation this codebase already documents elsewhere for `commitments`/`nullifiers`).
  **Honest scope:** `QueueDO`'s `expires_at`/TTL-eviction clock is deliberately real-time, unbucketed
  (state precisely above) — flagged so a future reader doesn't "fix" it into using the coarsened
  value and silently break eviction timing. Optional cover traffic (K6, R7's other named mitigation)
  is untouched by this pass. The 1-minute bucket granularity is a judgment call, not a value derived
  from a specific traffic-analysis threshold — reasonable default, not a proven-optimal one.
- **Done (2026-07, "R25: real OHTTP" pass) — closes R25: the OHTTP Relay was never implemented, only
  stub comments (`index.ts`, `wrangler.toml`) claiming it existed "in production."** README calls this
  "load-bearing, not cosmetic" — without it Cloudflare sees the real client IP on every anonymity-zone
  call even with full cryptographic identity unlinkability (docs/03 §2's whole point).
  - **Researched before writing anything, per this task's own instruction not to reinvent HPKE:**
    Cloudflare's "Privacy Gateway" (the link docs/04 already cited) is a **closed-beta managed
    service** ("select privacy-oriented companies and partners") — not self-serve, not usable here.
    `cloudflare/privacy-gateway-relay` is real, open-source, and reusable — but it only implements the
    **Relay** role (a dumb byte-forwarder, no HPKE at all). The **Gateway** role (HPKE decapsulation)
    has no maintained, Workers-verified package: `@hpke/ohttp` (from the actively-maintained
    `dajiaji/hpke-js`) is unreleased ("Coming Soon"); `chris-wood/ohttp-js` (from an actual RFC 9458
    co-author) is a stale 2023 v0.0.1, unverified for Workers. **Decision, confirmed with the user
    before coding:** the HPKE *primitive* is real and reusable (`@hpke/core` — confirmed by installing
    it and reading its actual `.d.ts` files, not assumed from docs — ships `DhkemX25519HkdfSha256`
    directly, Workers-verified via WebCrypto); the OHTTP-specific protocol *framing* (RFC 9292 Binary
    HTTP + RFC 9458's Key Config/request/response framing) has no reusable package and was implemented
    fresh, spec-driven, against the actual RFC text (fetched and read directly, not paraphrased from
    memory).
  - **New workspace package `packages/ohttp`** (pure TS, no Rust/WASM — `@hpke/core` already covers
    the WebCrypto-backed crypto in both the browser and Workers): `varint.ts` (RFC 9000 §16 QUIC
    varints), `bhttp.ts` (RFC 9292 Known-Length request/response framing — method/scheme/authority/
    path/headers/body; no informational responses, no chunked framing, empty trailers omitted, all
    conformant subsets of the spec, not shortcuts), `keyConfig.ts` (RFC 9458 §3.1), `hpkeSuite.ts`
    (shared constants + the RFC 9458 §4.4 response-key derivation, factored out once rather than
    duplicated between client.ts and gateway.ts), `client.ts` (encapsulate/decapsulate), `gateway.ts`
    (decapsulate/encapsulate, deterministic keypair from a seed — same "seed-threaded, no internal RNG"
    convention as `vortic-core`). 18 unit tests: varint boundary/round-trip, Binary HTTP round-trip
    (including duplicate headers, large bodies, wrong-framing-indicator rejection), and a full
    Client-encapsulate → Gateway-decapsulate → handle → Gateway-encapsulate → Client-decapsulate round
    trip (wrong key_id rejected, tampered ciphertext byte rejected, independent encapsulations per
    call, deterministic Key Config from a fixed seed).
  - **A real library bug found and worked around, not glossed over:** `@hpke/core`'s `kdf.extract()`
    artificially rejects any `salt` whose length isn't exactly the hash size — a narrowing of RFC 5869
    (whose `Extract` accepts a salt of *any* length) to match RFC 9180's own internal usage pattern,
    not a requirement of Extract itself. RFC 9458 §4.4's response derivation needs a 48-byte salt
    (32-byte X25519 `enc` + 16-byte `response_nonce`) — caught by a failing round-trip test, not
    predicted in advance, and fixed by calling WebCrypto's HMAC directly for this one step (still not
    "HPKE from scratch" — `expand()`, `.export()`, and the rest of the HPKE key schedule are all still
    the library's own code; only the one artificially-restricted primitive was replaced).
  - **`workers/messaging` Gateway wiring:** `GET /ohttp/keys` (publishes the Key Config, unauthenticated
    by necessity — same chicken-and-egg reasoning as `/membership/proof/:commitment`) and
    `POST /ohttp/gateway` (RFC 9458 §4: decapsulate → dispatch → encapsulate). The three existing
    handlers (`/membership/insert`, `/membership/proof/:commitment`, `/auth/session` — the ones docs/04's
    Flow 1/2 diagrams actually draw through the Relay) were refactored into plain functions over parsed
    input (`CoreResult { status, body }`, no `Request`/`Response`), reached BOTH by the direct router
    routes and by `dispatchBhttpRequest` — sharing logic rather than duplicating it, so the two paths
    cannot drift apart. `OHTTP_GATEWAY_SEED` (32 bytes hex) added to `.dev.vars`/`.dev.vars.example`,
    same secret-handling convention as `SESSION_SIGNING_KEY`.
  - **New `workers/ohttp-relay`** — the Relay role, deliberately as small as
    `cloudflare/privacy-gateway-relay` itself (written fresh for this repo's conventions, not vendored):
    forwards `GET /ohttp/keys` and `POST /ohttp/gateway` verbatim to `GATEWAY_ORIGIN`, refuses every
    other path outright (never an open proxy). **Residual note, stated plainly:** OHTTP's privacy
    property needs the Relay operator to be INDEPENDENT of the Gateway operator; a same-account
    Cloudflare deploy of both (as this local config does) closes the gap THIS pass targets (the
    Messaging Worker/Gateway structurally never receives the client's IP) but does not by itself defeat
    a single adversary who could operate or compel both — docs/03 §2 already names this class of
    residual risk ("different hostnames/Workers per plane" as a partial mitigation, VPN/Tor as the
    deeper one); an independently-hosted Relay is a real future step, not deployed here.
  - **`apps/web` wiring:** new `src/lib/ohttp.ts` (`ohttpFetch`, returns a real `Response` so
    `.ok`/`.status`/`.json()` call sites needed minimal changes), used for exactly the three calls in
    `AuthCallback.tsx` docs/04 draws through the Relay. `MESSAGING_API_URL` (now unused for those calls)
    removed rather than left as dead code.
  - **Live-verified against real `wrangler dev` processes for all three roles** (Client logic run via a
    vitest integration file that skips itself if the servers aren't reachable, not a hard CI dependency):
    Relay forwards the Gateway's real Key Config byte-for-byte; a full OHTTP round trip reaches the REAL
    `/membership/proof/:commitment` handler and returns its real 404 through full encryption both
    directions (with an explicit check that the plaintext path/commitment never appear in the wire
    bytes); a real `/membership/insert` call reaches real blind-signature verification through OHTTP
    (`[Membership] blindsig_verify -> false` in the worker's own log — the REAL handler ran, not a
    stub); wrong `Content-Type` on `/ohttp/gateway` is rejected (400). Confirmed via the worker's own
    logs (`POST /ohttp/gateway 200 OK`, not just script-side assertions).
  - **IP-visibility comparison (the task's explicit ask), done honestly rather than faked:** `wrangler
    dev`'s local loopback environment doesn't meaningfully simulate Cloudflare's edge-injected
    `cf-connecting-ip` the way production does (a direct local request's `cf-connecting-ip` is
    whatever value a caller sends, not edge-authoritative — confirmed empirically: a request with a
    spoofed `CF-Connecting-IP` header was read back verbatim by a temporarily-instrumented `/health`
    handler, then the instrumentation was reverted, not left in). Comparing raw header VALUES between
    "direct" and "via relay" in this local environment would therefore not be a meaningful proof either
    way. The real, load-bearing guarantee demonstrated instead is STRUCTURAL: the direct router routes
    receive a real `IRequest`/`Request` object (confirmed live — `request.headers.get(...)` is a live,
    populated access path), while `coreMembershipInsert`/`coreMembershipProof`/`coreAuthSession`/
    `dispatchBhttpRequest` — reached via `/ohttp/gateway` — never accept a `Request`/`IRequest`
    parameter at all; they only ever see `Env` plus a `BhttpRequest` this Worker's own HPKE-decapsulation
    code constructed from bytes the CLIENT chose to include (method/scheme/authority/path/headers/body —
    no IP field exists in that shape, by RFC 9292's own design). There is no code path from the
    `POST /ohttp/gateway` request's own transport metadata to those handlers — not a header that gets
    scrubbed (which could be forgotten on a future edit), but an argument that was never passed in the
    first place, verifiable by reading the function signatures in `index.ts`.
  - **Net effect (original pass):** R25 closed for the three routes docs/04 explicitly draws through
    the Relay. Explicitly NOT claimed: WebSocket-based routes OHTTP-wrapped (`/queue/:id` subscribe,
    `/conv/:id` — RFC 9458 is a single-shot request/response scheme, structurally incompatible with a
    persistent connection); `/queue/:id/push` (the plain-POST send path) OHTTP-wrapped; an
    independently-operated Relay (see the residual note above).
  - **Same-day follow-up, prompted by a direct question rather than found independently:** the user
    asked explicitly whether `POST /queue/:id/push` (`useQueueTransport.ts`'s `pushEnvelope`, the real
    1:1 message SEND path) went through `ohttpFetch` or a plain `fetch`. It was still plain `fetch` —
    correctly *disclosed* in the original pass's scope note, but under-prioritized: unlike the WS
    receive gap (structurally impossible to fix), `/queue/:id/push` is a plain POST/response with
    nothing blocking it, and it fires on every message send — the highest-FREQUENCY OHTTP-eligible
    route in the app, not a one-time enrollment call. Closed the same day:
    - `apps/web/src/lib/ohttp.ts`'s `ohttpFetch` extended to accept a binary body (`string | Uint8Array`),
      not just JSON strings, since `pushEnvelope`'s padded Sealed Sender++ envelope isn't JSON.
    - `workers/messaging/src/index.ts` gained `coreQueuePush` — capability verification re-expressed
      against the decapsulated `BhttpRequest`'s own header list (`getBhttpHeader`, case-insensitive
      lookup) rather than a real `IRequest`, calling the SAME `verifyCapability` HMAC check as the
      direct route (not a parallel/weaker auth path) — then forwards to `QueueDO` exactly like the
      direct route's `forwardToDO` does, just from decapsulated fields instead of a real `Request`.
    - `useQueueTransport.ts`'s `pushEnvelope` now calls `ohttpFetch` instead of `fetch`;
      `MESSAGING_API_URL` (now fully unused) removed rather than left dead.
    - **Live-verified with the strongest test in this whole R25 pass:** mint one REAL session
      capability via the full RSABSSA+official-ceremony-Semaphore chain, push one REAL message
      through the REAL OHTTP pipe (Client → Relay → Gateway → `coreQueuePush` → `QueueDO`), and
      confirm delivery via a DIRECT WebSocket subscribe (unwrapped — WS can't be OHTTP'd) — the
      exact plaintext marker round-tripped byte-for-byte, with the pushed `seq` matching what the
      subscriber received. Worker log shows the real chain end to end: `blindsig_verify -> true`,
      `POST /membership/insert 200`, `zk_verify_groth16_bytes -> true`, `Capability issued`,
      `GET /queue/... 101 Switching Protocols` (the direct WS subscribe), `POST /ohttp/gateway 200 OK`
      (the actual OHTTP-wrapped push) — not a mocked or isolated-unit proof.
  - **Net effect (after the follow-up):** R25 now covers all four plain request/response routes in the
    app (`/membership/insert`, `/membership/proof/:commitment`, `/auth/session`, `/queue/:id/push`).
    **Remaining, permanent, structural gap — now its own tracked risk, see R26 below:** a WS
    subscribe/receive connection (`/queue/:id`, `/conv/:id`) cannot be OHTTP-wrapped at all, so it
    hands its real connecting IP directly to the Messaging Worker — that is, to **A2, docs/02's
    primary adversary (the host itself)**, not merely to a passive network observer. Worth stating
    precisely rather than as a vague "IP visible to the edge" line: this is a materially different,
    more severe category of exposure than what R2's OHTTP/VPN/temporal-decoupling mitigation stack
    was built for, because the Security Gate's VPN nudge does nothing to stop A2 specifically from
    observing which IP is behind an active receiving session — see R26. An independently-operated
    Relay also remains undeployed (see the residual note above, a separate and lesser concern).
- **Researched, then implemented — "R26: WS proxy via the OHTTP Relay" pass (2026-07).** User asked
  specifically whether the existing OHTTP Relay could ALSO proxy the WS upgrade for `/queue/:id`/
  `/conv/:id` at the network level (not HPKE — OHTTP structurally cannot wrap a persistent connection),
  hiding the receiving client's IP from the Messaging Worker without falling back to polling.
  - **Research first, per explicit instruction not to guess by analogy with HTTP proxying:** confirmed
    via Cloudflare's own official docs (not community posts alone, though those pointed the same
    direction) that Worker-to-Worker WS proxying is a real, supported pattern —
    `await fetch(requestWithUpgradeHeader)` returns a `Response` with `.webSocket` set, and simply
    returning that Response verbatim completes the upgrade transparently; Cloudflare's own docs
    confirm a pure pass-through proxy (not reading individual frames in the relay's own code) does
    **not** keep the Worker "in use"/billed for the connection's lifetime — so this is genuinely
    real-time, not a disguised poll loop, and doesn't add meaningful per-connection cost.
  - **The actual IP-hiding mechanism, found in Cloudflare's official HTTP-headers reference
    (`developers.cloudflare.com/fundamentals/reference/http-request-headers/`), not assumed:** two
    distinct, documented behaviors for a Worker's outbound subrequest to another Worker —
    (1) **cross-zone** subrequests have `CF-Connecting-IP` automatically replaced by Cloudflare with a
    fixed internal placeholder "for security reasons" — pure platform behavior, no code needed, but
    requires the Relay to be deployed under a genuinely SEPARATE Cloudflare zone (apex domain) from
    the Messaging Worker, a deployment-topology decision this project hasn't made (nothing is deployed
    to any real zone yet); (2) **same-zone** subrequests have `CF-Connecting-IP` "reflect the value of
    `x-real-ip`, [which] can be altered by the user in their Worker script" — i.e., the Relay's own
    code CAN override the header that same-zone `CF-Connecting-IP` derives from, even without a
    separate zone. Implemented the same-zone lever (`x-real-ip` override in the Relay's WS-proxy
    branch) since it doesn't depend on an unmade deployment decision, while documenting the
    cross-zone path as the platform-guaranteed stronger alternative if/when real zones exist.
  - **The one honest, load-bearing limitation, checked before writing any code, not discovered after:**
    neither mechanism can be independently live-verified in this project's current environment.
    Confirmed (not assumed) that Miniflare/`wrangler dev` only simulates the static `request.cf`
    metadata object, not Cloudflare's dynamic same-zone/cross-zone edge-routing header-rewriting
    logic — that behavior is real Cloudflare edge-network infrastructure, inseparable from an actual
    deployed zone. Combined with this project having nothing deployed to a real Cloudflare zone yet
    (per multiple earlier entries in this doc), the IP-hiding property itself is **currently
    unverifiable**, full stop — not a gap in this pass's effort, a gap in what's checkable pre-deployment.
  - **Given this, stopped and reported findings + a size estimate before implementing, per the task's
    own explicit instruction** ("если сомнения в надёжности платформенного поведения — стоп и отчёт").
    User reviewed the research and explicitly chose to proceed with a documented-but-unverified
    implementation rather than wait for real deployment or fall back to polling.
  - **Implementation:** `workers/ohttp-relay/src/index.ts` gained `proxyWebSocket` — matches
    `/queue/{id}` or `/conv/{id}` (no trailing segment, so the OHTTP-wrapped `/queue/{id}/push` path
    is never accidentally caught by this branch) with an `Upgrade: websocket` header, overrides
    `x-real-ip` before forwarding, and returns the Gateway's response verbatim (the documented
    pure-pass-through pattern). `useQueueTransport.ts` and `convLogSync.ts`'s `WS_BASE_URL` now point
    at the Relay instead of the Messaging Worker directly — both carry the same explicit
    "unverified pending real deployment" comment, not silently presented as fixed.
  - **Live-verified what CAN be checked locally — functional correctness, explicitly NOT the IP
    property:** a real capability minted via the full RSABSSA+ZK chain, a WS subscribe opened through
    the Relay (`ws://127.0.0.1:8789/queue/...`, not the Gateway directly), a real message pushed, and
    delivery confirmed in real time (~500ms, not a multi-second poll interval) with the exact
    plaintext round-tripping. Worker logs confirm the full proxy chain fired: `GET /queue/... 101
    Switching Protocols` on BOTH the Relay's log and the Messaging Worker's log for the SAME queue id
    — i.e., the upgrade genuinely passed through two separate Worker instances, not a single direct
    hop mislabeled. This proves the proxy doesn't break real-time delivery; it does **not** and
    **cannot**, in this environment, prove the IP is actually hidden from the Messaging Worker.
  - **Net effect:** R26 stays **Open**, deliberately not marked Closed — a documented-but-unverified
    fix is not the same thing as a verified one, and this project's own standing discipline (every
    other numbered risk required live proof before "Closed") isn't relaxed just because a plausible
    fix exists. Marking this Closed should wait for a real Cloudflare deployment where the actual
    `CF-Connecting-IP` value the Messaging Worker receives can be directly inspected.
- **Topology revision (2026-07): cross-zone plan reverted to same-zone for the first deploy, not
  by choice of architecture but of availability.** A brief cross-zone prep pass (separate `account_id`
  per worker, a schema-lint check enforcing the Relay's account_id differ from the plane workers')
  was written and then reverted the same window once it became clear only one Cloudflare account with
  Workers Paid actually exists right now — a second account isn't available. All three workers
  (`enrollment`, `messaging`, `ohttp-relay`) deploy to that one account for the first closed alpha.
  This is an explicit, temporary, and structurally weaker choice than the cross-zone plan this section
  documented above: it relies entirely on `proxyWebSocket`'s `x-real-ip` override (same-zone
  `CF-Connecting-IP` behavior, already implemented, already the code path this section's live test
  exercised) rather than Cloudflare's platform-guaranteed cross-zone auto-anonymization, and it does
  NOT address the residual "colluding relay+gateway operator" gap — Relay and Gateway are one
  operator's infrastructure under same-zone, full stop. Accepted as the cost of reaching a real,
  working closed alpha now rather than staying undeployed indefinitely waiting on a second account.
  **Must be revisited (re-add the account-id split, re-run the R26 same-zone-vs-cross-zone comparison)
  before this project opens beyond a small trusted alpha circle who has been told this trade-off
  plainly** — see docs/deploy-checklist.md §5 for the exact steps to reapply once a second account
  exists.
- **First real Cloudflare deploy (2026-07-19) — nothing was deployed anywhere before this pass; now all
  three Workers + the frontend are live on the real domain.** Full step-by-step record in
  docs/deploy-checklist.md (secrets, D1, hostnames, R26 check — each section has its own "Executed"
  note); summarized here for the roadmap record.
  - All 5 secrets landed via `wrangler secret put` (`OAUTH_CLIENT_SECRET`/`ISSUER_SIGNING_KEY_PEM`
    reused from `.dev.vars` after independently re-deriving and diffing the issuer key's public half
    against both committed copies; the other 3 generated fresh). Both D1 databases migrated `--remote`
    with table lists confirmed matching `--local`. All three Workers deployed to real custom domains
    (`id`/`api`/`relay`.vort.xfeatures.net); `workers/ohttp-relay` needed an `[env.production]` split
    so its `GATEWAY_ORIGIN` stays `http://127.0.0.1:8787` for plain local `wrangler dev` and only
    switches to the real Messaging Worker URL under `--env production`. `apps/web` was built fresh and
    pushed straight to the existing Git-connected `vorticity-frontend` Pages project via
    `wrangler pages deploy` (not a git commit — none was requested this pass) so the live site actually
    carries today's changes (contact-bootstrap invite links, same-zone relay URLs) instead of a stale
    build.
  - **Two real mistakes made and fixed during this pass, neither swept under the rug:**
    1. **D1 delete resolved the wrong database.** `wrangler d1 delete vorticity-enroll`, intended to
       remove a duplicate this pass had just accidentally created, instead resolved via the LOCAL
       `wrangler.toml`'s `database_name` field (which didn't match the real Cloudflare-side name of the
       database it pointed to) and deleted the real, pre-existing enrollment database instead. Actual
       damage was zero (0 tables — migrations had never been applied to it), confirmed before acting
       further. Fixed by creating a genuine replacement, re-migrating it, and correcting the
       `database_name` mismatch in BOTH workers' `wrangler.toml`s (a latent version of the same footgun
       existed in `workers/messaging`'s config too, not exercised yet but fixed proactively).
    2. **A second, previously-undiscovered `OAUTH_REDIRECT_URI` mismatch**, caught by reading
       `SecurityGate.tsx`'s actual redirect construction against the live deployed frontend before
       attempting any real login: `workers/enrollment/wrangler.toml` had
       `https://id.vort.xfeatures.net/oauth/callback` (the Worker's own API domain, wrong host AND
       wrong path) while the real client has always sent `${window.location.origin}/auth/callback`
       (the SPA's own `/auth/callback` route) — on the real deployed frontend, that's
       `https://vort.xfeatures.net/auth/callback`. Fixed the Worker-side value and confirmed live (a
       `curl` with the corrected `redirect_uri` now reaches the real IDM and gets `invalid_grant` for a
       fake code, not this Worker's own `400`). **The IDM's OWN registered redirect_uri for this
       `client_id` — a separate, external system this repo cannot inspect — still needs to be confirmed
       or corrected to this same value by whoever has access to that panel; this repo cannot verify
       that from here.** This is the exact same bug CLASS this file already documented once before
       (the earlier `redirect_uri`-mismatch entry, Phase 4) — a second, independent instance of it,
       not a regression of the first fix.
  - **R26 live-verified for real** (see the R26 risk-register row and the topology-revision entry
    above): same-zone `x-real-ip` override confirmed working against the real deployed stack via
    `wrangler tail` (direct request showed the real caller IP; the same request via the Relay showed
    the override value `0.0.0.0`). Status moved from "Open (unverified)" to "Mitigated (same-zone,
    live-verified)" — deliberately not "Closed," see the R26 entry for why.
  - **A THIRD real bug, found by the architect's own first live click-through (not by this pass's own
    testing) and fixed same-day:** `workers/ohttp-relay` never sent any CORS headers at all, and
    `POST /ohttp/gateway`'s `Content-Type: message/ohttp-req` isn't a CORS-safelisted content type, so
    the browser sends a real preflight `OPTIONS` request first — which this Worker answered with a bare
    404 (`OPTIONS` wasn't in the method-aware path check), failing every OHTTP call from a real browser
    before it ever reached the Gateway. **Why this was invisible until now:** every prior test of this
    Worker was `curl` or a Node/vitest script — CORS is enforced by the BROWSER, not the server or a
    Node `fetch` client, so no amount of scripted testing could have caught it; it took an actual
    browser session to surface. Fixed with the same allow-list `corsHeaders` convention already used by
    `workers/enrollment`/`workers/messaging` (`vort.xfeatures.net` + `localhost:5173`, never a
    wildcard/reflected origin), added to the `OPTIONS` preflight response and both real response paths
    (`/ohttp/keys`, `/ohttp/gateway`). **Live-verified against the real deployed relay:** `curl` preflight
    and GET both now carry the correct `Access-Control-Allow-*` headers, AND a real `fetch()` executed
    from the actual live `https://vort.xfeatures.net` page (via the Browser pane, not a script) to
    `https://relay.vort.xfeatures.net/ohttp/keys` now succeeds (`ok: true, status: 200`), console clean.
  - **Diagnostic follow-up, same day: "does reload break an established chat?" — yes, root-caused,
    then fixed for real, not just diagnosed.** User asked specifically whether it's the Semaphore
    identity (`new Identity()` in `AuthCallback.tsx`, confirmed regenerating fresh every login) that
    breaks continuity. **It doesn't** — Semaphore identity only feeds the ZK membership proof, never
    chat addressing, so a fresh one each login is fine (arguably good for anonymity) and just grows
    `MerkleTreeDO`'s tree with unused leaves over time, a separate/minor concern. **The real cause:**
    `useQueueTransport.ts`'s PQXDH ratchet identity/KEM material AND the live ratchet session itself
    lived only in `useRef`s, wiped on every unmount (reload, chat switch) with no recovery path — the
    peer's `if (ratchetSessionRef.current) return` guards treated a legitimate re-handshake attempt as
    a duplicate to silently ignore, meaning a reload on EITHER side could permanently desync an
    established conversation.
  - **Full fix built (user's explicit choice over a minimal patch), two new pieces:**
    1. **`apps/web/src/lib/secureStore.ts`** (new): non-extractable AES-GCM-256 vault, `extractable:
       false` `CryptoKey` persisted as a structured-clone object in IndexedDB (not raw bytes) — usable
       for encrypt/decrypt via `crypto.subtle`, but its own key material cannot be exported by ANY
       code running in this origin, including a future XSS payload. `assertVaultKeyNonExtractable()`
       exists for exactly this claim to be checked, not just asserted.
    2. **Ratchet identity persistence + re-handshake recovery** (`useQueueTransport.ts`): the
       responder's `identitySeed`/`kemKeypair` are now generated ONCE per `chatId` and sealed via the
       vault instead of freshly regenerated every mount — stable across reloads, so a re-mounted
       responder republishes the byte-IDENTICAL signed bundle. This turns "peer republished while a
       session already exists" into a reliable signal: same verifying key + bundle = legitimate
       reset, redo the handshake; a DIFFERENT identity mid-session is rejected outright, not silently
       swapped in. Symmetric fix on the responder side for `session_init`: a NEW ciphertext that
       successfully decapsulates against the stable KEM keypair is accepted as a legitimate recovery
       (only the real responder holds that private key, so successful decapsulation IS the proof of
       legitimacy) rather than being ignored as a duplicate.
    3. **Capability persistence** (`AuthContext.tsx`): the session capability is now ALSO sealed to
       the same vault on `login()`, restored on mount (with the existing "reload loses the session"
       R20 tradeoff finally resolved the way that entry's own comment said it eventually should be —
       "a future 'remember this device' UX should use a non-extractable key... never a plain string in
       Web Storage"). Expiry (embedded in the capability's own HMAC-signed payload, readable
       client-side without the server) is checked before trusting a restored value; an expired one is
       discarded and its vault entry cleared, falling back to the original re-login behavior exactly
       as before. **A real bug caught before shipping, not after:** `AuthGuard.tsx` redirected on
       `isAuthenticated` synchronously on the FIRST render, before the now-async vault-restore effect
       had a chance to run — meaning a reload of an already-authenticated route would always bounce to
       "/" regardless of a valid persisted capability. Fixed with a new `isRestoring` flag `AuthGuard`
       waits on before deciding.
  - **Live-verified, real WASM crypto + a real browser, not just typecheck:** a Node script driving
    the actual `vortic_core` WASM (same glue file `packages/ohttp/src/live.e2e.test.ts`'s
    `getRealCapability()` already imports this way) walked the full sequence — first handshake,
    baseline message round-trip, simulated Bob-reloads (fresh identity regenerated from the SAME seed
    bytes, confirmed byte-identical to before), Alice recognizing the same peer and re-handshaking,
    Bob completing the recovery handshake, a NEW message round-tripping correctly post-recovery, and a
    negative control confirming a genuinely different identity is correctly rejected, not silently
    accepted — all 9 checks passed. Separately, in a real browser (Browser pane) against the local dev
    server: `secureStore.ts`'s seal/unseal round-trips correctly; `assertVaultKeyNonExtractable()`
    returns true; a direct adversarial probe — raw IndexedDB read of the `CryptoKey` object, bypassing
    the module's own code entirely, then `exportKey('raw', ...)` AND `exportKey('jwk', ...)` — both
    fail with `InvalidAccessError: key is not extractable`, confirming the property structurally, not
    just via the module's own self-check; a capability sealed with a future `exp` survives a real
    reload (`AuthGuard` correctly waits and lets the authenticated route through); one sealed with a
    past `exp` correctly falls back to the Security Gate AND clears its own stale vault entry.
  - **Item 4 (remove `mockChats.ts`'s 4 hardcoded contacts) and item 5 (invite-link production
    polish) done together, same pass** — closely coupled once ratchet identity started surviving
    reloads: leaving the chat LIST itself as `useState([])`-only would have been a regression (the
    crypto session would persist in the vault with nothing in the UI able to reach it again). New
    `lib/chat.ts` (renamed from `mockChats.ts` — once `INITIAL_CHATS` was gone it wasn't mock data
    anymore, just shared types) + new `lib/chatList.ts` persists chat list METADATA (id/alias/
    initials/role) through the same vault — deliberately NOT message history, which needs separate,
    larger work (reading from `ConvLogDO`'s op-log or local plaintext storage, neither built yet); a
    restored chat starts with empty history and picks up whatever arrives live. `lib/inviteLink.ts`
    gained an optional cosmetic inviter label (`buildInviteUrl(chatId, label)` → `#/invite/<id>
    ?from=<label>`), explicitly NOT a public `@alias` (docs/03 §8's Flow 5/6 directory) — no
    discoverability, no server storage, visible only to whoever already holds the link.
  - **A FOURTH real bug, found by this pass's own testing (not the architect's) while verifying the
    invite flow end-to-end for the first time with a genuinely unauthenticated visitor:** opening an
    invite link while NOT yet logged in hits `AuthGuard`, which redirects via `<Navigate replace>` —
    and a full-path `Navigate` replaces the ENTIRE URL, hash included. The invite was silently gone
    before `Chats.tsx` ever mounted to read it, and the OAuth round-trip that follows (SecurityGate ->
    IDM -> `AuthCallback` -> `/chats`) has no memory of it either — a brand-new contact's invite link,
    almost certainly the MOST common real use of this feature, would have silently failed. Fixed the
    same way this codebase already solves "a value must survive a redirect chain": `sessionStorage`,
    single-use, same convention as `pkce.ts`'s `code_verifier` — `AuthGuard` stashes the invite right
    before redirecting; `Chats.tsx` checks the stash if the URL itself has no invite hash.
    **Live-verified in the Browser pane, real app code:** an unauthenticated visit to an invite link
    correctly cleared the URL hash but landed the invite in `sessionStorage`; simulating login
    completing and landing on `/chats` picked up the stashed invite and created the chat entry with
    the correct `Invited by: Kriss` label; the stash was confirmed consumed (single-use, removed
    after read); console clean throughout.
  - **A FIFTH real bug — the actual first real two-person test, run by the architect and a friend
    over a real phone/desktop pair, hit it immediately: a message sent by the joining side never
    reached the inviter, live or on reconnect.** Root-caused with an independent Node probe against
    the REAL deployed production stack (mint a real capability via the full RSABSSA+ZK chain, open a
    real WS, push a real OHTTP-wrapped envelope, check live delivery) — reproduced the exact failure
    on demand, then bisected it: identical failure with the WS connected DIRECTLY to
    `api.vort.xfeatures.net`, bypassing the Relay entirely, which ruled out R26's WS-proxy mechanism
    as the cause and pointed at `workers/messaging` itself.
    - **Actual cause, found by reading `itty-router`'s own source (not assumed):** `IttyRouter.mjs`
      extracts route params as raw regex capture groups against `URL.pathname` — no decoding step.
      `URL.pathname` does NOT percent-decode a colon (`:` isn't in the WHATWG URL spec's path
      percent-encode set), so a client that `encodeURIComponent`s a queue name containing `:` (every
      real queue in this app — `${chatId}:AtoB` / `${chatId}:BtoA`, see `useQueueTransport.ts`) hands
      the direct WS-subscribe route (`forwardToDO`) the STILL-ENCODED name (`...%3AAtoB`), while
      `coreQueuePush`/`dispatchBhttpRequest` (the OHTTP-wrapped push path) already
      `decodeURIComponent`s theirs. Two different strings passed to `DurableObjectNamespace.idFromName`
      address two DIFFERENT Durable Object instances — a push durably lands in one DO, a WS subscribe
      attaches to a different, empty one. Not a delivery bug, not a Relay/R26 bug: a genuine addressing
      mismatch that affected EVERY real queue in the app (any chat, not just invite-bootstrapped ones),
      invisible to every earlier automated test in this project because none of them used a queue name
      containing a reserved character — a real, structural blind spot in test coverage, now closed by
      this exact regression being the trigger.
    - **Fix:** `forwardToDO` (`workers/messaging/src/index.ts`) now decodes its own `id` parameter
      before calling `idFromName`, matching the OHTTP path's existing behavior — one-line fix, doesn't
      touch `coreQueuePush`, the Relay, or any crypto code.
    - **Live-verified the fix on the REAL production stack, not just typecheck:** the SAME independent
      probe that first reproduced the bug, re-run after deploying the fix — real capability, real WS
      through the real Relay, real OHTTP push — received the pushed envelope live, byte-correct, no
      code changes to the probe itself between the failing and passing runs (only the server-side fix
      was deployed in between).
  - **Not done in this pass, said plainly:** the final end-to-end "two real people OAuth-login and chat"
    test still needs a human to actually authenticate through the real Xfeatures IDM (entering real
    credentials through tooling is out of bounds) — but the architect's own attempt today is what
    surfaced this fifth bug, and the underlying transport is now independently confirmed working on
    real production; the next real attempt should not hit this specific failure again. FIVE real
    blockers found so far across this and the prior pass (redirect_uri mismatch, relay CORS gap,
    ratchet-reload-breaks-chats gap, invite-link-lost-during-login gap, queue-DO-addressing mismatch)
    are now fixed; whether anything else surfaces is unknown until someone completes a full real
    two-person login+chat end to end.
- **Spike remainder (de-risk):** decide trusted-setup (Groth16 ceremony) vs **transparent PLONK/Halo2** —
  still open, decide before it's load-bearing.
- PPID sybil guard done (enrollment). `MerkleTreeDO` + nullifier one-spend done (see the "ZK airlock" entry
  above); remaining here: a real Poseidon/LeanIMT tree (not the SHA-256 mock root), redeeming the VOPRF token at
  `/membership/insert` against the Enrollment Plane's issuance (currently assumed-valid). `RateGateDO` now has
  a real (if minimal) generic counter implementation, currently used by `/membership/proof/:commitment`
  (see the "/proof rate limit" entry above) — capability-issuance rate limiting still doesn't call it yet.
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
- **Done (2026-07, "R22: real transport" pass) — closes R22, the last remaining mock in the messaging
  path.** `useChatWebSocket.ts`'s "one `ws.send()` both ways, unpersisted" placeholder is gone; the real
  Flow 3/Flow 4 protocol is wired end to end, including a genuine bug found in `ConvLogDO` along the way.
  - **`QueueDO` cleanup, not a rewrite:** the class already correctly implemented push/pull/ack/subscribe/
    hibernation/TTL per the DO catalog — the only mock artifact was `webSocketMessage`'s "Phase 5
    transport-spike relay" (broadcast any non-ack WS frame verbatim, unpersisted), which existed solely
    because the old client sent raw chat text over the same socket both ways. Removed outright: the WS
    now handles ONLY `{type:"ack",upToSeq}`, exactly as documented.
  - **A real, previously-undetected gap found in `ConvLogDO`:** the DO catalog lists it as hibernating and
    Flow 4 explicitly shows `L--)D2: push blob@n (WS)`, but the class had `POST /append`/`GET /sync` ONLY —
    no WebSocket support existed at all. Added `GET` + `Upgrade: websocket` → hibernatable subscribe
    (backlog since an optional `?since_seq=` flushed immediately on connect — the same "(re)connecting IS
    sync-on-wake" property `QueueDO`'s subscribe already had), and `handleAppend` now fans each newly
    -assigned entry out to every attached device via the same `fanOut()` pattern as `QueueDO`. Proactively
    applied `QueueDO`'s own documented live-discovered bug fix (re-closing an already-closing socket throws
    in workerd) rather than rediscovering it the hard way.
  - **New client transport, `apps/web/src/hooks/useQueueTransport.ts`** (replaces the deleted
    `useChatWebSocket.ts`, no fallback path kept): send = capability-gated `POST /queue/{id}/push`;
    receive = WS push + `{type:"ack"}`, exactly the documented asymmetric protocol. **Two real
    unidirectional queues per chat** (`{chatId}:AtoB`/`{chatId}:BtoA}`, per the DO catalog's "one
    unidirectional pairwise queue" and docs/README decision #7) — an explicit `role`
    ("initiator"/"responder") parameter stands in for real per-user queue-id *provisioning*, which is Flow
    5/6 contact-establishment machinery that doesn't exist in this codebase yet (the mock UI has no real
    per-user identity to assign roles from); this pass fixes the transport primitive, not that separate,
    larger system — said plainly, not glossed over.
  - **Sealed Sender++ receipts implemented for real** (docs/01 "Vorticity counter", docs/README decision
    #5) — this did not exist in any form before this pass. A receipt is a `{type:"receipt",ackSeq}`
    envelope on a SEPARATE `{queueId}:receipt` queue (not the message path), padded to the exact same size
    -bucket scheme as real messages (so it's not distinguishable by ciphertext length), pushed after a
    randomized 2-8s delay (decoupling receipt timing from message timing) — the concrete, specific
    countermeasure against the documented Signal weakness (receipt/timing traffic analysis relinking users
    in as few as ~5 messages), not a UX nicety.
  - **Crypto layer intentionally untouched:** the X25519 ephemeral-DH handshake + real ChaCha20-Poly1305
    from the earlier spike still has the same already-documented gaps (unauthenticated DH, no ratchet) —
    this pass changed HOW an envelope reaches its peer, not what's inside it or how it's encrypted. Those
    remain separate, tracked work (PQXDH/Triple Ratchet).
  - **New reusable client module, `apps/web/src/lib/convLogSync.ts`:** append/sync/subscribe primitives for
    `ConvLogDO`. Deliberately transport-only — no Yjs/Automerge integration exists yet; a real multi-device
    UI wiring this up would put an encrypted CRDT update in `blob` and call `Y.applyUpdate` on receipt.
    This module proves the transport is real, not that multi-device merge UX exists.
  - **Live-verified, both parts, zero mocking, against a live `wrangler dev`** (one real session capability
    minted first via the full RSABSSA+official-ceremony-Semaphore chain): **(A) QueueDO** — two roles
    (initiator/responder) complete a real X25519 handshake over the real queues, exchange real
    ChaCha20-encrypted messages BOTH directions, and both sides receive a real padded/delayed receipt for
    what they sent; confirmed via worker log (`GET /queue/... 101 Switching Protocols` ×4,
    `POST /queue/.../push 201 Created` ×6, matching the real request count with no relay/mock path
    involved). **(B) ConvLogDO** — one append, two LIVE devices both received the byte-identical entry
    (same seq, same blob) via WS push, and a THIRD device connecting AFTER the append received the same
    entry via backlog-on-connect — proving both live fan-out and late-join sync/"pull-on-wake" work, and
    that the server genuinely only orders opaque blobs (confirmed structurally: `ConvLogDO`'s code path
    from insert to `fanOut`/`rowToWire` never parses or interprets `blob`, only stores/forwards the raw
    bytes it was given).
  - **Net effect:** R22 closed as a transport-correctness risk. Explicitly NOT claiming Flow 5/6 (contact
    establishment / real queue-id provisioning) or the ratchet/PQXDH work are done — those remain open,
    separate, and larger.
- **Done (2026-07, "R24: real Triple Ratchet" pass) — closes R24: the unauthenticated, non-ratcheting
  X25519 DH that R22's own entry flagged and deferred is now gone.** Highest priority per this pass's
  own framing: a direct gap against docs/02's G1-G4 (confidentiality, forward secrecy, post-compromise
  security, PQ) sitting in the one transport R22 just finished making real.
  - **Audited before assuming anything was ready:** `kem.rs` already had real hybrid ML-KEM-768+X25519
    encapsulate/decapsulate and `symmetric.rs` had real ChaCha20-Poly1305 — both usable as-is.
    `ratchet.rs` was a literal `todo!()` stub; no Ed25519 identity/signing module existed anywhere in
    the crate. Nothing was assumed "basically done" without checking the actual code.
  - **PQXDH-style authenticated handshake:** new `ed25519-dalek` dependency (deterministic signing,
    no RNG needed, consistent with the crate's existing seed-threading convention). A responder
    ("Bob") publishes a hybrid KEM prekey bundle (`kem::HybridPublicKey`) *signed* by a long-term
    Ed25519 identity key; an initiator ("Alice") verifies that signature BEFORE doing anything else —
    `RatchetSession::handshakeInitiate` returns an `Err` outright on a bad/wrong-key signature
    (unit-tested: `handshake_rejects_bad_signature`). This is what makes it authenticated rather than
    bare DH: an attacker without Bob's identity signing key cannot get a substituted bundle accepted.
    (Not solved, same as Signal's own model: verifying a `verifying_key` really belongs to the expected
    peer the first time is a separate out-of-band UX problem, not addressed here.)
  - **Real Double Ratchet:** standard Signal algorithm — symmetric-key ratchet (HKDF hash chain,
    advances every message, forward secrecy) + DH ratchet (fresh X25519 keypair each time the sender
    direction flips, post-compromise security), including a bounded (`MAX_SKIP=25`) skipped-message-key
    cache for legitimate out-of-order delivery and an explicit rejection of replayed/already-consumed
    sequence numbers (rather than silently deriving a wrong key).
  - **Sparse PQ Ratchet — two real symmetry bugs found and fixed while building it, not glossed over:**
    the design periodically offers a fresh ML-KEM-768 keypair in a message header; the peer
    encapsulates to it and attaches the ciphertext to its own next new-chain message.
    1. **First bug:** a single `pending_pq_ss` slot got clobbered when a side both received an answer
       to its own earlier offer AND had to answer the peer's offer before the first value was ever
       consumed — caught by a live-alternating-senders test failing with a decryption error, not by
       inspection.
    2. **Second, deeper bug, found fixing the first:** mixing the ML-KEM secret into `state.rk`
       (the shared root key) at each side's own *next* DH ratchet turn assumed the two turns are
       paired 1:1 across peers — true for the plain DH ratchet, but an asynchronous PQ offer/response
       is NOT guaranteed to land on paired turns, so this **desynced every later turn's root-key
       salt** and broke the whole session, not just the PQ remix. Root-caused (not worked around):
       `state.rk` is a purely local value whose bitwise snapshots are never meant to match the peer's
       except at specific *paired* `kdf_rk` call-sites; touching it anywhere else breaks that.
       **Fix:** mix the PQ secret into the CHAIN key only, at the exact `n == 0` message that carries
       the ciphertext — both sides are, by construction, processing the *same wire message*, so no
       cross-message turn-pairing is needed. This is a real, working, but intentionally *narrower*
       property than a literal "into the root for every future chain" reading of docs/03 §4 — it
       strengthens the chain segment the remix lands in, on top of the DH ratchet's own already-proven
       per-turn PCS, not a permanent root-level fold. Documented in `ratchet.rs`'s module doc as a
       known, deliberate simplification, including *why* the more literal design doesn't work without
       a different synchronization primitive.
  - **6/6 ratchet unit tests, full crate suite 29/29:** handshake signature rejection; bidirectional
    round-trip; distinct ciphertext for identical repeated plaintext (proves per-message key rotation,
    not just "different sender"); forward secrecy (a consumed message key cannot be recovered from
    later state — the exact bug class the two fixes above were about); out-of-order delivery via the
    skipped-key cache; and the Sparse PQ Ratchet actually incrementing its remix counter after enough
    alternating turns (not just present-but-inert code). Both build profiles checked: `edge-verify-only`
    compiles clean with `ratchet.rs` entirely absent (module now gated `#[cfg(feature = "client-full")]`
    at `lib.rs`, matching `kem`/`symmetric` — crypto invariant #4).
  - **`apps/web` wiring:** `useQueueTransport.ts`'s flat X25519 handshake is GONE, no fallback kept.
    New envelope pair `prekey_offer`/`session_init` (PQXDH is one-sided, unlike the old symmetric DH
    swap) maps directly onto the existing `role` stand-in from R22: "responder" publishes a signed
    bundle once per chat mount, "initiator" answers with the KEM ciphertext. From then on, `message`
    envelopes carry `RatchetSession.encryptMessage`/`decryptMessage`'s own header+ciphertext framing.
    **Honestly scoped:** identity + prekey material is generated fresh per mount, not persisted to
    device storage or published to any directory service — real long-term identity persistence and a
    `PrekeyDO` (docs/03 §4) are separate, not-yet-built infrastructure; this pass replaced the key-
    exchange cryptography, not identity/prekey distribution (same honesty standard as R22's `role`
    stand-in for Flow 5/6).
  - **Live-verified against a real `wrangler dev` QueueDO, not just unit-tested:** a real capability
    minted via the full RSABSSA+official-ceremony-Semaphore chain, then Alice/Bob complete the real
    PQXDH handshake over real `prekey_offer`/`session_init` pushes, exchange 4 real alternating
    messages (all decrypt correctly), and: **key-rotation proof** — Alice sends literally "same text"
    twice; the two wire frames are provably distinct (not just "probably", diffed byte-for-byte) despite
    identical plaintext, confirming the message key rotates every message, not just per sender.
    **Forward-secrecy proof, live** — Alice's FIRST captured wire message replayed against Bob's
    NOW-ADVANCED session correctly throws (`decryption failed`), confirming the old message key is
    genuinely gone from current state, not just untested. `PQ_REMIX_EVERY_N_TURNS=3` is a small
    constant chosen for testability (docs/03 only requires "periodic"); the live 4-message run didn't
    reach a remix (expected, tuning note left in `ratchet.rs`), covered separately by the unit test
    that runs enough alternating turns to observe one.
  - **Net effect:** R24 closed as a crypto-correctness risk for 1:1 messaging. Explicitly NOT claiming:
    MLS/group ratcheting (separate, Phase 1 "still to implement"), a `PrekeyDO`/identity-persistence
    service (Flow 5/6-adjacent, not built — **built in the "PrekeyDO rotation" pass further down this
    same phase**), or a literal root-level (vs. chain-level) PQ remix — all said plainly above, not
    discovered later.
- **Done (2026-07, "contact-bootstrap invite link" pass) — minimal Flow 5/6 stand-in, NOT the real
  system.** Deploy-prep pass, explicit scope: unblock a first closed alpha (two real people starting a
  real 1:1 chat) without building AliasDO/PoW/directory infrastructure. `apps/web/src/lib/inviteLink.ts`
  (new): generates a fresh, high-entropy chat id (`inv-<16 random bytes, base64url>` — NOT a low-entropy
  `chat-N` mock id, since anyone holding a queue id can push/read on it, no ownership check in
  `QueueDO`) and a shareable URL (`#/invite/<id>`, pure client-side hash routing, no server involvement).
  `pages/Chats.tsx` gained: an invite-creation button (role `"responder"` on the new chat — triggers
  `useQueueTransport`'s existing responder-mount effect to publish a real signed PQXDH prekey bundle
  immediately, which `QueueDO`'s backlog-flush-on-connect delivers whenever the other side opens the
  link, even after this tab closes) and an invite-join effect (reads the URL hash on mount, adds the
  same chat id as role `"initiator"`). `lib/mockChats.ts`'s `Chat` gained a `role: TransportRole` field
  (moved the `TransportRole` type here from `useQueueTransport.ts`, which now imports it back, to avoid
  a circular import) — the 4 mock contacts keep their existing implicit `"initiator"` default, unchanged.
  **Deliberate scoping decision, stated plainly:** the invite link carries ONLY the chat id, not the
  PQXDH prekey bundle itself (the task that requested this pass described `{queueIds, prekey bundle}`
  in the link) — the bundle still flows exactly as before, Ed25519-signed over the queue itself and
  verified by `RatchetSession.handshakeInitiate`. Embedding it a second time in the URL wouldn't add a
  real security property here (this app has no safety-number/fingerprint-comparison UI, so either path
  is equally first-use-trust/TOFU), and reusing the existing signed-bundle-over-the-queue flow unchanged
  avoids needing to persist a generated identity/KEM keypair across a page navigation so it still
  matches what a URL-embedded bundle would have promised. See `lib/inviteLink.ts`'s header comment for
  the full reasoning; a future out-of-band-authenticated invite (bundle embedded + a real comparison UI)
  is a reasonable strengthening, not done here.
  **Verified:** `pnpm exec tsc --noEmit` clean across `apps/web`; a full `vite build` production build
  succeeds (bundles the new module with no new warnings beyond this repo's pre-existing, unrelated
  `@hpke/common` Rollup comment-annotation notices and >500KB chunk-size warning, both already noted
  elsewhere in this doc as separate, un-addressed concerns). **Honest gap on HOW this was verified:**
  could NOT be click-tested live in a browser this pass — `/chats` sits behind `AuthGuard`, which needs
  a real ZK-verified session capability from a real Xfeatures OAuth login (the capability is
  intentionally React-state-only per `AuthContext.tsx`, not fakeable via storage), and entering real
  OAuth credentials through tooling is out of bounds. Verified by typecheck + production build +
  careful code review instead — same honest-gap pattern already used elsewhere in this doc (e.g. R23's
  first pass) whenever the OAuth gate blocks live browser automation. A genuine two-browser click-through
  (generate a link in tab A, open it in tab B, confirm a real PQXDH handshake + message round-trip) is
  the natural next verification step, not done here.
  **Still not this pass, said plainly:** any directory/discoverability (AliasDO, PoW), invite expiry,
  a UI affordance for what happens if a link is opened twice or by more than one person, or persisting
  the invite/chat list itself (still `useState` in `Chats.tsx`, lost on reload — same lifecycle as the
  session capability it depends on).
- **Done (2026-07, "PresenceDO" pass) — closes the "Still open: PresenceDO" gap.** Ephemeral, opt-in
  online/typing presence, contact-scoped per docs/04's DO catalog (one instance per chat id, same
  high-entropy unguessable id `lib/inviteLink.ts` already generates).
  **`PresenceDO.ts` holds NO storage at all** (not even SQLite — unlike every other DO in this
  catalog) — "never persisted" was already this class's own pre-existing TODO comment; this pass
  keeps that property, not walks it back. On WS attach it tells the new socket about anyone already
  attached (`{type:"online"}`) and tells everyone already attached about the newcomer; `webSocketClose`/
  `webSocketError` broadcast `{type:"offline"}`; a client-sent `{type:"typing"}` is relayed verbatim to
  every OTHER attached socket. **"Sealed" (docs/05) is stated plainly as an architectural property,
  not per-frame AEAD:** signals are small plaintext control frames, deliberately NOT run through
  `useQueueTransport.ts`'s Double Ratchet — a "typing" signal fires on every keystroke, and
  interleaving that volume through the same chain as real messages risks exhausting the ratchet's
  bounded skipped-key window and breaking real message decryption (`packages/vortic-core/src/
  ratchet.rs`). Confidentiality instead rests on the same isolation `QueueDO` already relies on:
  unguessable per-chat id + capability-gated route.
  **`index.ts` gained `/presence/:chatId/*`**, gated by the same `requireCapability` as `/queue` and
  `/conv`. **`workers/ohttp-relay`'s `WS_PROXY_PATTERN` extended** from `/(queue|conv)/` to
  `/(queue|conv|presence)/` — this route's WS upgrade needed the same plain network-level proxy R26
  already established for the other two, for the same structural reason (RFC 9458 can't wrap a
  persistent connection).
  **Client: `apps/web/src/hooks/usePresence.ts`** (new) — opt-in per chat (`Chat.presenceEnabled`,
  persisted through the existing sealed `lib/chatList.ts` vault, not a new storage primitive), scoped
  to the active chat only (same documented limitation `useQueueTransport.ts` already has: a
  background/non-active chat has no live socket of any kind). Exposes `peerOnline`/`peerTyping` +
  a throttled `sendTyping()` (2s client-side gate, so an onChange-per-keystroke handler doesn't flood
  the relay) with a 4s client-side typing decay (the protocol has no explicit "stopped typing" frame).
  Wired into `ActiveChatPanel.tsx` (a "Presence On/Off" toggle button in the header; `peerTyping`
  replaces the socket-status line with "typing..." while active) and `ChatListItem.tsx`'s existing
  online dot (previously always `false` — this is the first real signal driving it). Deliberately kept
  OUT of `chats` state itself (would re-trigger the persist-on-change effect on every online/typing
  flicker) — rendered from a derived `displayChats`/`displayActiveChat` view instead.
  **Verified live, real stack, both checkpoints:**
  1. *Server-side* (isolated `wrangler dev` instance, port 8797, avoiding the port conflict with
     another already-running session in this same working directory): a Node WS probe minted a real
     HMAC capability against the local `SESSION_SIGNING_KEY` and confirmed — missing capability -> 401;
     two sockets on the same chat id see `online` on attach (both directions), `typing` relay, and
     `offline` on disconnect; a second, different chat id never sees the first one's traffic
     (isolation). Zero uncaught exceptions in the Worker log across the run.
  2. *Client-side, real browser* (`apps/web`'s actual Vite dev server + the real, already-running
     `workers/messaging`/`workers/ohttp-relay` stack): since `/chats` sits behind a real ZK-verified
     session capability that needs real Xfeatures OAuth credentials (not enterable through this
     tooling, same recurring honest gap as R23's first pass and the invite-link entry above), a valid
     capability was seeded directly into the browser's own non-extractable vault via `crypto.subtle`
     (the exact same primitive `lib/secureStore.ts` itself uses) — not a shortcut around any real
     code path, only a substitute for the OAuth leg specifically. From there everything exercised was
     the real app: clicked "Create invite link" through the real UI, toggled "Presence On" through the
     real button, then a Node script played the peer's role — connecting through the REAL
     `workers/ohttp-relay` (port 8789, exercising this pass's `WS_PROXY_PATTERN` change), not a
     shortcut straight to messaging. Confirmed via live DOM inspection: the list row's online dot
     went from absent to present the moment the peer connected, the header status line showed
     "typing..." live while the peer sent typing frames, and both cleared correctly the moment the
     peer disconnected. Toggling presence off in the UI produced zero console errors.
  **Honest scope, not built here:** presence for any chat other than the currently-active one; a
  server-side "who's online across all my chats" aggregate; disabling presence automatically under a
  future paranoia profile (docs/05 "Maximum ... disable presence" — the rule-engine that would drive
  that doesn't exist yet, tracked separately, not this pass's gap to close).
- **Done (2026-07, "PrekeyDO rotation" pass) — closes the "real `PrekeyDO`/identity-persistence
  service" gap the entry above (and R24's own Phase 1 write-up) flagged as separate/deferred: R24
  generated fresh identity/prekey material per mount but never persisted or published a fetchable
  bundle anywhere beyond the queue-pushed `prekey_offer`. Full docs/03 §4 X3DH-style bundle now real:
  identity key (unchanged, long-term per chat) + a ROTATING signed prekey + a pool of ONE-TIME
  prekeys, all durably published.**
  **Crypto (`packages/vortic-core`): one-time-prekey mixing is real, not cosmetic.**
  `kem.rs` gained `combine_with_onetime` (folds a SECOND independent hybrid-KEM root key into the
  first via HKDF); `ratchet.rs` gained `handshakeInitiateWithOnetime`/`handshakeRespondWithOnetime` —
  reuses `kem::encapsulate`/`decapsulate` twice rather than inventing new primitives. Security
  property, stated precisely: even a fully compromised signed-prekey private key is not enough to
  recover a session's root key on its own — the one-time leg's private key is used exactly once and
  discarded (PrekeyDO deletes the public half server-side on fetch; the client deletes its matching
  private half on consumption, `lib/prekeys.ts`'s `consumeFromPool`), so an attacker needs BOTH,
  and the one-time one is gone by the time any such compromise could matter. cargo: 27/27 (client-full),
  including a **load-bearing check** (`onetime_prekey_handshake_both_sides_agree_and_the_mix_is_load_bearing`)
  proving the mix actually changes the resulting root key, not just that both sides agree on *something*.
  **Real limitation found while writing tests, not swept under the rug:** `#[wasm_bindgen]`-annotated
  items generally cannot be called from a native (non-wasm) target at all — confirmed empirically
  (wasm-bindgen's own "cannot call wasm-bindgen imported functions on non-wasm targets" panic), a
  stronger restriction than "only `JsError` construction panics off-wasm" this file's tests previously
  assumed. The new adapter functions' own correctness was instead verified via a real compiled-WASM
  Node script against the actual `pkg/client` build (see the live-verification bullet below), not a
  native `cargo test` — same gap `handshake_initiate`/`handshake_respond` themselves already had (no
  adapter-level native test ever existed for those either).
  **Server: `workers/messaging/src/durable-objects/PrekeyDO.ts`** (new, contact-scoped like
  PresenceDO — one instance per chat id). Holds NO SQLite table for identity linkage beyond two plain
  tables (`bundle`: one row, upserted on publish/rotate; `onetime_prekeys`: a pool, atomically
  popped-and-deleted on fetch — the DO's single-threaded-per-instance execution model makes
  read-then-delete race-free without needing `DELETE...RETURNING`, same reasoning MerkleTreeDO's
  nullifier tables already rely on). `POST /publish` (upsert bundle, additive one-time top-up),
  `GET /status` (bundle presence + pool count, for the client to decide whether to rotate/replenish),
  `GET /fetch` (the initiator's read: bundle + at most one popped one-time prekey, or `null` if the
  pool is empty — a graceful degrade, not an error, matching real X3DH). New migration tag `v2`
  (DO migrations are append-only, per `wrangler.toml`'s own standing comment — `v1`'s array was not
  edited). Routed at `/prekey/:chatId/*` (direct, capability-gated, same as `/queue`/`/conv`) AND
  wrapped through the existing OHTTP Gateway (`corePrekeyRequest` in `index.ts`, same reasoning as
  `/queue/:id/push`'s R25 follow-up: this fires on roughly every chat mount / rotation check, not
  once per enrollment, so an unwrapped fetch would leak the real client IP on a non-one-time call).
  `workers/ohttp-relay`'s `WS_PROXY_PATTERN` needed no change here (unlike PresenceDO) — `/prekey` is
  plain request/response, not a WS upgrade.
  **Client (`apps/web`):** new `lib/prekeys.ts` — the PrekeyDO HTTP client (always via `ohttpFetch`)
  plus the RESPONDER's local one-time-prekey pool (sealed in the existing non-extractable vault,
  `lib/secureStore.ts` — same primitive the persisted ratchet identity already uses). **Honest gap,
  stated plainly:** this pool is LOCAL-DEVICE-ONLY; if local storage is ever lost while PrekeyDO
  server-side still remembers having handed out a since-orphaned one-time prekey's public half, that
  ONE handshake attempt fails to decapsulate — flagged in the module's own header comment as exactly
  the kind of gap a future multi-device design needs to account for, not solved here.
  `useQueueTransport.ts`: `getOrCreatePersistentIdentity` became `getOrRotateIdentity` — same persisted
  identity, but the signed KEM prekey now rotates (fresh keypair, same long-term Ed25519 identity —
  identity keys don't rotate, only the prekey they sign) once older than `SIGNED_PREKEY_ROTATE_AFTER_MS`
  (7 days), tracked via a third sealed record (`ratchet-kem-rotated-at`). The responder-mount effect
  now ALSO publishes to PrekeyDO and tops up the one-time pool (only when actually below
  `ONETIME_REPLENISH_THRESHOLD`, to avoid needless churn every mount) — the queue-pushed `prekey_offer`
  fast path is UNCHANGED, both paths coexist exactly like `/queue/:id/push`'s direct-vs-OHTTP split.
  A NEW initiator-mount effect proactively `GET`s PrekeyDO instead of only passively waiting for a
  queue push — works even if the responder is currently offline, which the queue-only fast path never
  could. `handleInboundMessage`'s `prekey_offer`/proactive-fetch handling was unified into one shared
  `initiateHandshakeFromBundle` callback (both call sites need identical signature-verification and
  re-handshake-recovery logic — kept as one function so they can't drift). `SessionInitEnvelope` gained
  an optional `oneTimePrekeyId` field so the responder knows which locally-persisted one-time private
  keypair to consume; absent means "plain signed-prekey-only handshake" (pool was empty, or the bundle
  came from the queue fast path, which never carries one) — real X3DH tolerates this, same strength as
  before this pass.
  **Verified live, real stack, both checkpoints:**
  1. *Server-side* (isolated `wrangler dev`, port 8798, same port-conflict avoidance as the PresenceDO
     pass): a Node probe confirmed — missing capability → 401; fresh chat has no bundle (`GET /fetch`
     → 404) until published; publish + 3 one-time prekeys → `GET /fetch` pops exactly one DIFFERENT
     key per call, three calls exhaust the pool; a 4th fetch on an exhausted pool still returns the
     bundle with `onetimePrekey: null` (graceful degrade, not an error); republishing with a new
     signed prekey rotates it (`GET /fetch` returns the NEW one, `rotatedAt` advances); replenishing
     tops up the pool without disturbing the bundle; a second, different chat id has fully independent
     empty state (isolation). Zero uncaught exceptions in the Worker log.
  2. *Client + real WASM, end-to-end, against the real already-running dev stack* (not simulated):
     opened a real invite chat in the browser (responder role) — console showed
     `[Crypto] Publishing signed prekey bundle (freshly rotated)...` and
     `[Crypto] PrekeyDO bundle published ..., one-time pool now 20`, confirming the rotation+top-up
     logic ran for real. A Node script loaded the ACTUAL COMPILED `pkg/client` WASM (via `initSync`
     over the raw `.wasm` bytes — no browser needed to exercise real WASM), fetched the bundle from
     PrekeyDO, and ran a REAL `RatchetSession.handshakeInitiateWithOnetime` — ciphertext length
     confirmed exactly 2240 bytes (`2×(1088+32)`, both KEM legs). Pushed `session_init` onto the real
     `QueueDO` queue; the browser's console showed
     `[Crypto] PQXDH handshake completed (responder side) (one-time-prekey strengthened) — ratchet
     session ready` — confirming the RESPONDER genuinely used `handshakeRespondWithOnetime`, not a
     silent fallback. The Node script's message decrypted correctly in the browser UI
     (`"hello from the Node initiator (one-time-prekey session)"`, visible in the chat panel); a reply
     typed and sent from the real browser UI decrypted correctly on the Node side
     (`"hello back from the real browser responder"`). Zero console errors throughout. **A stale-HMR
     false alarm caught and ruled out, not silently ignored:** an OLD browser tab (alive since much
     earlier in this same session, across many hot-reloads) showed a spurious React
     "change in the order of Hooks" error that persisted even across `location.reload()`; a BRAND NEW
     tab against the identical running dev server showed zero such errors and completed the full test
     cleanly — confirming it was accumulated Vite HMR module-graph drift in that one old tab, not a
     real hook-order bug in the new code (every hook in `useQueueTransport`/`usePresence` is called
     unconditionally at the top level; nothing in this diff conditions a hook call).
  **Done (2026-07, "device-linking" pass) — closes the "Multi-device" gap above. Design chosen by
  the architect (asked explicitly, both options real): a second device gets the SAME per-chat
  identity/ratchet state (not a per-device Sesame-style key + sender fan-out) — simpler, reuses the
  existing single-`RatchetSession` model unchanged, at the cost of only one device ever being "live"
  for send/receive at a time (a real, accepted tradeoff, not hidden).**
  **Rust (`packages/vortic-core`): full live-state export/import, not a placeholder.**
  `ratchet.rs` gained `RatchetSession.exportState()`/`RatchetSession.importState()` — serializes
  EVERY field of `RatchetState` (both DH keypairs, root/chain keys, the skipped-message-key cache,
  turn counters, any pending Sparse-PQ offer) to a fixed byte layout, matching this crate's own
  established "fixed layout, not a serde crate" convention (`kem.rs`'s `to_bytes`/`from_bytes` pairs).
  `MlKemKeyPair` gained a matching `pub(crate)` `to_bytes`/`from_bytes` (kept crate-private
  deliberately — a bare ML-KEM private keypair has no legitimate reason to cross the WASM boundary on
  its own, only bundled inside a whole state export). **The correctness bar was "a linked device can
  actually continue the conversation," not just "the bytes round-trip"** —
  `exported_state_round_trips_and_a_linked_device_continues_the_conversation` exchanges real messages
  BEFORE export, exports mid-conversation, and proves the reconstructed session both decrypts a NEW
  message from the real peer and sends one the peer can decrypt back. A second test
  (`exported_state_preserves_skipped_keys_and_pending_pq_offer`) forces an out-of-order skipped-key
  cache entry and enough turns to populate a Sparse-PQ pending offer specifically to cover the
  variable-length/optional parts of the layout, not just the always-present fields — and confirms the
  ONCE-skipped message still decrypts correctly on the linked device (functional, not just
  byte-identical). A third rejects truncated input at every cut length rather than panicking. cargo:
  33/33 (client-full+issuer-full). **Real limitation found and worked around, not glossed over:**
  `#[wasm_bindgen]`-annotated items cannot be called from a native target AT ALL (a stronger
  restriction than "only `JsError` construction panics off-wasm" the rotation pass's own tests had
  assumed) — confirmed empirically, so the adapter layer's own correctness was verified separately via
  a real compiled-WASM Node script against a real browser-produced payload (see the live-verification
  bullet below), the same "no native adapter-level test, WASM-boundary coverage lives elsewhere" gap
  `handshake_initiate`/`handshake_respond` themselves already had.
  **Server: three new contact/chat-scoped DOs**, same convention as PresenceDO/PrekeyDO (opaque ids
  only, capability-gated one layer up in `index.ts`, own migration tag — `v3` — since these are new
  classes shipping after `v1`/`v2`):
  - **`DeviceLinkDO`** — a one-time, TTL'd (10 min) dead-drop keyed by a linkId derived
    ONE-WAY (SHA-256) from a random "linking secret" that never crosses the server — `POST /put` /
    `GET /take`, the latter deleting in the same call it reads (same race-free
    read-then-delete-within-one-DO-instance reasoning as PrekeyDO's one-time-prekey pop). The DO
    never sees plaintext: the stored blob is AEAD-sealed client-side under a key HKDF-derived from
    the same secret. Wrapped through OHTTP (`coreDeviceLinkRequest`) — this payload is full private
    key material, arguably the single most sensitive thing this app ever puts on the wire, so it gets
    at least the same IP-correlation protection as ordinary message pushes.
  - **`DeviceLeaseDO`** — the real correctness guard this pass could not skip: without SOME mutual
    exclusion, two of a user's own linked devices both running a live ratchet session for the same
    chat would desync it, for the PEER too, not just the linked user (their ratchet only ever expects
    ONE sender-direction chain advancing in order). A simple heartbeat-renewed lease (45s TTL, one
    holder at a time, `POST /acquire` returns 409 with the current holder if denied, `POST /release`
    is a no-op for a non-holder rather than an error, an alarm reclaims an abandoned lease so a
    crashed/closed device can never permanently lock a chat). Also OHTTP-wrapped (fires on a ~20s
    heartbeat cadence per open chat — leaving it unwrapped would let the Worker continuously correlate
    a real IP with "this device has chat X open right now").
  **Client (`apps/web`):** `lib/deviceLink.ts` (AEAD seal/unseal — HKDF-SHA256 over the linking
  secret into an AES-GCM key, same WebCrypto primitives `lib/secureStore.ts` already uses — plus
  `buildLinkPayload`/`applyLinkPayload`, which gather/restore identity+KEM+one-time-pool+live-ratchet-
  state+message-history under the exact same `secureStore` keys `useQueueTransport.ts`/`lib/prekeys.ts`
  already use, so neither of those files needed special-casing for "was this chat linked in") and
  `lib/deviceLease.ts` (a non-secret, plain-`localStorage` `deviceId` label — NOT identity material,
  safe outside the vault unlike everything else this pass touches — plus the acquire/release HTTP
  client). `useQueueTransport.ts`: the responder/initiator-mount effects are now gated on a NEW
  `hasLease` state (acquired + heartbeat-renewed every 15s, well inside the server's 45s TTL); a
  **real ordering hazard found and fixed while wiring this, not shipped broken:** the pre-existing
  reset of `ratchetSessionRef`/etc. lived at the TOP of the responder-mount effect and in its cleanup,
  both of which also fire on every `hasLease` transition — including the transition FROM a just-
  imported session TO `hasLease=true`, which would have silently wiped a device-link import the
  instant it landed. Fixed by moving the reset to a SEPARATE effect keyed only on `[chatId]` (so a
  `hasLease` flip alone can't trigger it) and removing the reset from the responder effect's own
  cleanup entirely (a transient lease hiccup must not nuke a live session either). The
  lease-acquire effect itself now hydrates: on first successful acquire with no session yet, checks
  for a sealed `ratchet-imported-state:${chatId}` record and, if present, reconstructs the session via
  `RatchetSession.importState` plus the trusted peer bundle (also carried in the transfer payload, so
  a linked initiator-role device doesn't lose the existing "peer republished, treat as recovery, not
  attack" detection) instead of starting a fresh handshake — and the initiator's proactive-PrekeyDO-
  fetch effect now skips entirely once a session already exists, so hydration doesn't needlessly burn
  a one-time prekey fetching a bundle it will just reject as "different peer" anyway. New hook exports:
  `hasLease`, `leaseHeldByOther`, `exportRatchetState`, `getTrustedPeerBundle`. `Chats.tsx`/
  `ActiveChatPanel.tsx`: a "Link Device" button (disabled unless `hasLease`, matching
  `exportRatchetState`'s own "exporting from a read-only device would hand over stale state" doc
  comment), a device-link banner (same shape as the invite banner, but explicitly worded — "move to
  your OWN other device only, valid 10 min" — since this is a materially higher-stakes secret than an
  invite code, see `lib/deviceLink.ts`'s header comment), a read-only banner when `leaseHeldByOther`,
  and `#/device-link/<code>` hash redemption alongside the existing `#/invite/<id>` handling in the
  restore effect (requires `cap` — DeviceLinkDO is capability-gated, so linking does NOT bypass
  account-level auth; the second device still needs its own real OAuth+ZK login first).
  **Verified live, real stack, every layer:**
  1. *DeviceLinkDO in isolation* (isolated `wrangler dev`, same port-conflict-avoidance discipline as
     every prior pass this phase): missing capability → 401; take before put → 404; put → take →
     exact blob match; SECOND take on the same link → 404 (single-use confirmed); a different linkId
     sees nothing (isolation).
  2. *DeviceLeaseDO in isolation*: device-1 acquires; device-2's acquire on the SAME chat → 409 with
     `holder: "device-1"`; device-1 renews its own lease successfully; device-2's release attempt (not
     the holder) is a no-op, lease unaffected; device-1's real release clears it; device-2 can then
     acquire.
  3. *Full chain, real browser + real independent Node-side crypto, not simulated*: re-used the
     rotation pass's live chat (a real prior one-time-prekey-strengthened session with actual exchanged
     messages). Clicked "Link Device" for real in the browser — zero console errors, a real code
     appeared. **An independent Node script — using Node's own WebCrypto, NOT importing any of this
     app's seal/unseal code — fetched the real blob from the live `DeviceLinkDO` and decrypted it
     successfully**, proving the AEAD scheme genuinely round-trips between two separate
     implementations, not just "the same code that sealed it can unseal it." The decrypted JSON
     contained a genuine responder identity/KEM/17-entry one-time pool and real message history
     including the earlier cross-device exchange. **First attempt correctly showed `ratchetStateB64:
     null`** — not a bug: no live session existed yet on that fresh page load (the original Node
     initiator process from the rotation pass had long since exited, and a responder's ratchet session
     is real in-memory-only state, never persisted across reloads by design). Re-ran a fresh real
     one-time-prekey handshake against the same chat to establish a genuinely live session, confirmed
     via the browser's own console (`PQXDH handshake completed (responder side) (one-time-prekey
     strengthened)`), linked again — this time the payload's `ratchetStateB64` was present, and
     **`RatchetSession.importState` against the REAL compiled `pkg/client` WASM (via Node's `initSync`
     over the raw `.wasm` bytes, no browser needed) accepted it and produced a functional session**
     (non-crashing `pqRemixCount()`, a well-formed encrypted wire frame). A direct `GET
     /device-lease/:chatId/status` call against the live stack, made WHILE the browser tab had the chat
     open, confirmed a real, currently-unexpired lease held by that tab's own generated `deviceId` —
     the heartbeat is genuinely running, not just present in the code. Zero console errors throughout
     the entire sequence.
  **Honest scope, stated plainly:** only ONE device is ever live at a time — this is the accepted cost
  of the chosen design (see the architect's decision at the top of this entry), not an oversight. No
  UI affordance yet for "see which of my devices currently holds the lease" beyond the read-only
  banner on the losing side. `lib/prekeys.ts`'s pre-existing local-pool-loss gap is now closable BY
  linking (a linked device gets the real pool, not a fresh empty one) but is still real for a device
  that was never linked. Re-linking an already-locally-present chat OVERWRITES local state with the
  linked payload (`applyLinkPayload`'s own doc comment) — reasonable for "recover this chat on a
  second device," not yet a considered choice for "merge two devices' independently-diverged history,"
  which isn't a scenario this design (one-live-device-at-a-time) should actually produce in normal use.
  **Still open:** `@cloudflare/actors` fan-out for anything beyond
  single-DO WS (not yet needed — every DO so far handles its own fan-out directly). R2 presigned
  chunked-AES-GCM media path. Alias adaptive/per-target PoW difficulty, Argon2id hardened option, signed
  update/revoke (would need `alias_pub` back out as a plaintext column), `H(nickname)`-prefix sharding.
  **Approval-gated contact-request flow through the resolved `intro_queue_id`: done — see the "alias
  contact establishment" pass further down this phase.** That pass closes discovery specifically (look
  someone up by `@nickname`, they approve) but, said plainly there too, does NOT close the deeper gap
  this paragraph originally flagged: "R22: real transport" fixed the transport primitive and "R24: real
  Triple Ratchet" fixed the crypto, but both still rely on an explicit `role` stand-in for queue
  bootstrap itself, not real contact-driven queue/identity assignment — a resolved alias contact still
  starts a chat exactly like an invite link does under the hood.
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
- **Done (2026-07, "Security Gate de-simulation" pass) — closes the "3 honestly-labeled simulated
  placeholders" gap above.** No more `Math.random()` coin-flips anywhere in `lib/securityChecks.ts`.
  **Clock Synchronization** is now a real HTTP round trip to the Enrollment Worker's public `/health`,
  comparing the local clock against the response's `Date` header (NTP-style round-trip-midpoint
  correction) — honestly reports "server sent no Date header" rather than fabricating a skew number
  when one is genuinely unavailable (observed in local `wrangler dev`/Miniflare, which doesn't add
  one; real Cloudflare edge responses always do). **DNS Resolver Quality → renamed DNS Lookup
  Latency**, not just re-implemented: a browser has no API surface that reveals which resolver the OS
  used or its transport (DoH/DoT) — confirmed before writing anything, not assumed — so rather than
  keep a label promising something structurally unmeasurable, this now reports the real Navigation
  Timing `domainLookupEnd - domainLookupStart` for what it actually is. **VPN/Egress Exposure**
  couldn't be made real without either the still-not-built Phase 2 capability endpoint or calling a
  third-party IP-intelligence service (which would leak "this user is checking VPN status" to that
  third party — against this project's own no-third-party-leak posture) — kept deterministic and
  honest instead: a fixed, clearly-worded "not yet verifiable, needs a server-side endpoint" message,
  replacing the coin-flip. **Two new real checks added** ("add more environment tests," per the task):
  Automation Detection (`navigator.webdriver`, a real standardized signal — flags Selenium/Playwright/
  CDP-driven sessions) and Privacy Signal (`navigator.globalPrivacyControl`/`doNotTrack`, purely
  informational, always "ok" since their absence says nothing about actual risk). 8 checks total now
  (was 6), `useSecurityScan.ts` needed zero changes (already fully driven by `CHECK_DEFS.length`, no
  hardcoded count anywhere). **Verified live:** ran the real scan on `/` and the embedded `/settings`
  widget, zero console errors both times; re-ran the scan a second time and confirmed every result was
  either byte-identical or explainably different by a real measurement (clock round-trip varying by a
  few ms between runs, a genuine timing artifact — not the old behavior where VPN/DNS/Clock could
  flip between "ok" and "warn" on every re-run for no real reason).
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
- **Done (2026-07, "logout + contact deletion" pass) — two small, real gaps closed together.**
  **Sidebar's "End Session" button was a `console.log` stub, not wired to anything** — a real leftover
  from before `AuthContext` grew a real capability/vault model; nobody had updated the button when
  that landed. Fixed: calls the real `logout()` (clears in-memory token + the sealed vault entry);
  `AuthGuard` re-evaluates `isAuthenticated` every render (not just on mount), so it reactively
  redirects to `/` on the very next render with no manual navigation needed in `Sidebar.tsx` itself.
  **Verified live:** clicked the real button — landed back on the Security Gate; a direct
  post-logout navigation to `/chats` correctly bounced back to `/` too (confirms the vault entry was
  genuinely cleared, not just the in-memory flag). **Contact/chat deletion, not previously possible at
  all:** `ChatListItem.tsx` gained a hover-revealed delete control (restructured from a single
  `<button>` wrapper to a `role="button"` div + a real nested `<button>`, since a `<button>` inside a
  `<button>` isn't valid HTML); `Chats.tsx`'s `handleDeleteChat` removes the chat from the list AND
  every associated local secureStore record (`ratchet-identity`/`ratchet-kem`/`ratchet-kem-rotated-at`/
  `ratchet-imported-state`/`onetime-pool`, all keyed by chat id) — a stale identity/prekey-pool record
  left behind after "deleting" a chat would be a real residual-data leak, not just visual clutter.
  Native `window.confirm()` gates the action (simple, unblockable-by-accident, no new modal component
  needed for a single destructive action). **Honest scope:** local-device only, same as the rest of
  `lib/chatList.ts` — does not notify the peer, does not reach `PrekeyDO`/`PresenceDO`/`DeviceLeaseDO`
  server-side state for that chat (left to its own existing TTL/alarm cleanup, same as an abandoned
  chat already is), and does not delete the chat on any other of the user's own linked devices.
  **Verified live:** created a real chat, confirmed its 4 crypto-state keys existed in the vault,
  triggered a real delete (list count 3→2), confirmed all 4 keys were gone while a DIFFERENT chat's
  keys were untouched (isolation), reloaded the page and confirmed the deletion persisted. Zero
  console errors throughout both checks.
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
- **Done (2026-07, "alias contact establishment" pass) — real Flow 5/6 DISCOVERY, closing the
  long-flagged "real per-user queue-id provisioning" gap for how a chat gets FOUND, not for the
  `role` (initiator/responder) queue-bootstrap mechanism itself, which is unchanged and still an
  honest stand-in (said plainly, matching this doc's own convention — see "Still open" below).**
  Before this pass the only way to start a chat was `lib/inviteLink.ts`'s out-of-band URL; this adds
  the actual thing Flow 5/6 describes — look someone up by `@nickname`, they approve — on top of
  `AliasDO.ts`, which existed fully wired (register/resolve, PoW-gated) since an earlier pass but had
  **no client ever calling it**.
  **Rust (`packages/vortic-core`): closed two Phase-0 `todo!()` skeletons, not new modules.**
  `alias.rs`'s `lookup_key`/`derive_record_key` were literal `todo!("Phase 3: ...")` stubs since
  Phase 0 — now real (`lookup_key = SHA-256("vortic-alias-v1"||nickname)`,
  `derive_record_key = HKDF-SHA256(ikm=nickname, salt="", info="vortic-alias-enc")`, the same HKDF
  shape `lib/deviceLink.ts`'s `deriveAeadKey` already uses for an analogous derivation). `pow.rs`'s
  `mint`/`verify` were the other Phase-0 stub — now a REAL synchronous Hashcash miner.
  **Why the miner had to be Rust/WASM, not a TS loop:** `crypto.subtle.digest` is async; at the
  required 18-26 bit difficulties (docs/03 §8.3) the per-call Promise dispatch overhead — not the
  hash itself — dominates, turning a register-class mint into minutes instead of docs/03's
  targeted "a few seconds". A synchronous WASM loop has no such overhead. `AliasDO.ts`'s own
  `verifyPowStamp` is deliberately NOT replaced by the new `pow_verify` WASM export — verification
  is a single hash, cheap enough server-side that swapping a working, already-tested implementation
  for a WASM call would be unrelated risk; `pow.rs::verify` exists to close the crate's own TODO and
  give the Rust test suite a same-language mint/verify round-trip, not to gate real requests.
  No new `AliasOwnershipKey` type either — reuses `ratchet::identity_verifying_key` (deterministic
  from a random seed, already wasm-bindgen-exported and tested) for `alias_pub`, since `AliasDO.ts`
  doesn't verify a signature yet regardless (no signed update/revoke — see its own header comment).
  Both build profiles re-checked clean (`edge-verify-only` still compiles with zero `client-full`
  code linked). 40/40 crate tests green (was 33; +7 new: lookup/record-key determinism + a Node-
  cross-checkable SHA-256 test vector, PoW leading-zero-bit counting, mint→verify round-trip at a
  real difficulty, wrong-resource/insufficient-bits rejection, malformed-stamp rejection).
  **Server (`workers/messaging`), two real bugs found and fixed, not just new code:**
  1. **`/alias/*` had NO `requireCapability` check at all** — every other conversation route in
     `index.ts` gates on it, and docs/03 §8.1 itself lists "a capability gate" as an accepted
     mitigation for the alias plane's low-entropy-nickname residual risk; this route silently had
     none, meaning the "one enrolled account per actor" economics argument in §8.3 was false in
     practice. Fixed to match every other route.
  2. **The OHTTP dispatch table had `POST /queue/:id/push` wrapped but no `GET /queue/:id/pull`** —
     caught LIVE, not by inspection: every real message receive goes over WS subscribe, so nothing
     had ever exercised a pulled OHTTP GET on this queue path before, but this pass's own
     `useAliasInbox.ts` polls its owner's intro queue on a ~15s cadence via `ohttpFetch`, and every
     single poll 404'd (`"Not found (via OHTTP gateway)"`) until `coreQueuePull` was added and wired
     into `dispatchBhttpRequest` alongside `coreQueuePush`. Left unwrapped, a real deployment would
     have let the Messaging Worker correlate a real IP with "this device is checking its alias
     inbox" on every poll — exactly the leak class R25/R25-follow-up already prioritized closing for
     every other repeating call in this file.
  **New: `AliasDO.handleIntroduce`** (`POST /introduce`) — Flow 6's "write to intro queue" step.
  Verifies a WRITE-class PoW stamp (22 bits, mid docs/03's 20-24 range) bound to the target
  `introQueueId` (not the `lookup_key` — binding to the queue, not the alias, is what actually stops
  a single ground stamp from spamming every enumerable queue), spends it against the same
  `pow_stamps` replay set register/resolve already share, then forwards the opaque sealed
  ciphertext as a normal push into that `QueueDO` instance via `env.QUEUE_DO` — the DO never
  decrypts it, same isolation property every other DO in this catalog already has. `register`/
  `resolve`/`introduce` are all now OHTTP-wrapped (`coreAliasRequest`, mirroring
  `corePrekeyRequest`'s shape) — a register/resolve/introduce call reveals "this real IP is
  claiming/looking up/contacting @nickname", exactly the correlation docs/03 §8's privacy model
  exists to prevent leaking. `verifyPowStamp`/`countLeadingZeroBits` extracted from `AliasDO.ts`
  into a new shared `pow.ts` so `handleIntroduce` reuses the exact already-tested check rather than
  a second hand-rolled copy.
  **Client (`apps/web`):** `lib/alias.ts` (new) — nickname validation, `lookup_key`/`rec_key`
  derivation via the new WASM exports, AEAD seal/unseal (same HKDF+AES-GCM shape as
  `lib/deviceLink.ts`, but the WASM `rec_key` output IS the final key, no extra HKDF layer needed
  client-side), `registerAlias`/`resolveAlias`/`sendContactRequest`/`pullContactRequests`, all via
  `ohttpFetch`. **PoW mining runs in a dedicated Web Worker**
  (`apps/web/src/workers/powMiner.worker.ts`) — even WASM-fast mining is a genuine multi-second
  synchronous block at register's 24 bits (observed live: anywhere from ~2s to ~60s depending on
  luck — Hashcash difficulty is a random search, not a fixed cost), and freezing the whole UI for
  that is a real, avoidable regression for what's otherwise a rare one-time click; verified live
  that the main thread stayed responsive (page state/DOM queries kept working) throughout a real
  mine. `hooks/useAliasInbox.ts` polls the owner's own registered intro queue every 15s; **does NOT
  use `QueueDO`'s `/ack`** (deliberately) — its "everything `seq <= upToSeq`" cumulative semantics
  are wrong for an inbox of independent, individually-actionable requests (acking one accepted
  request could silently drop a different, still-pending, lower-`seq` one) — already-handled
  requests are instead remembered client-side (a persisted seq set in the vault) and filtered out of
  future polls, leaving the raw entry to expire via `QueueDO`'s own TTL. `components/AliasPanel.tsx`
  (Settings: register a nickname, read-only once set — no update/revoke UI, matching `AliasDO.ts`'s
  own current scope), `ChatList.tsx` gained an "Add contact by @alias" composer alongside the
  existing invite-link one, `Chats.tsx` gained accept/decline banner cards + `handleAddByAlias`
  (resolves, sends the request, adds the proposed chat locally as role `"initiator"` immediately —
  same "waiting for the other side" UX an invite link already has) + `handleAcceptRequest` (adds the
  chat as role `"responder"`, mirroring `handleCreateInvite` exactly — nothing alias-specific happens
  past this one-time local bootstrap step, `useQueueTransport.ts` takes over unchanged).
  **Verified, every layer, real crypto/real network throughout:**
  1. *Rust*: 40/40 `cargo test --features client-full,issuer-full`; `edge-verify-only` and
     `edge-verify-only,issuer-full` both still compile clean.
  2. *WASM vs. independent Node implementations* (real compiled `pkg/client`, `initSync` over raw
     `.wasm` bytes, no browser): `alias_lookup_key`'s output matched a hand-computed Node
     `crypto.createHash("sha256")` over the literal byte concatenation; `alias_derive_record_key`'s
     output matched Node's own built-in `crypto.hkdfSync` computed independently (not sharing code
     with `util.rs`'s `hkdf_sha256`); confirmed the two derived keys never collide for the same
     nickname (domain separation genuinely holds). `pow_mint`→`pow_verify` round-tripped, and a
     WASM-mined stamp's bit count was independently re-measured by the SERVER's own JS algorithm
     copy, confirming a WASM-mined stamp is one the real server will actually accept.
  3. *Server, isolated `wrangler dev`, real mined PoW (a Node script, no shortcuts)*: missing
     capability → 401 on all three new routes; register succeeds with a real 24-bit stamp, a second
     register on the same `lookup_key` → 409; resolve succeeds with a real 20-bit stamp and returns
     the exact registered record, a replayed resolve stamp → 409; a stamp mined for the WRONG
     resource (lookup_key instead of introQueueId) → 403 on introduce; introduce succeeds with a
     real 22-bit stamp bound to the right resource, a replayed introduce stamp → 409; **pulled the
     target `QueueDO` directly afterward and confirmed the forwarded message is byte-identical to
     what was sent** — not just "got a 201", proof the forward genuinely happened.
  4. *Live, real browser + real independent Node process, zero shortcuts*: registered `@nightowl_test`
     for real through the Settings UI (real 24-bit PoW mined in the Worker, confirmed the main thread
     stayed responsive throughout); an independent Node script — using the same real compiled WASM,
     not the browser's copy — resolved the alias and sent a real sealed, PoW-stamped contact request
     over the live stack; **the OHTTP `/queue/pull` bug above was caught by this exact step** (the
     inbox never showed anything until it was fixed); after the fix, the request appeared in the real
     inbox UI, clicking Accept added a real chat as responder and the console showed a genuine
     `PrekeyDO` bundle publish for it; a second request was sent and Declined — no chat was created,
     and after a full page reload NEITHER the accepted nor the declined request resurfaced (the
     handled-set persisted correctly). Zero console errors across the entire sequence.
  **Honest scope, stated plainly:** this closes DISCOVERY, not the deeper `role` stand-in
  `useQueueTransport.ts` still uses for the queue-bootstrap mechanism itself — a resolved contact
  still starts a chat exactly like an invite link does, just found via alias instead of an
  out-of-band URL; a genuinely different per-user persistent-identity/queue-directory model is a
  separate, larger piece of work, not done here. No signed update/revoke (`AliasDO.ts` doesn't
  verify a signature yet either), no Key Transparency (K8) binding for `alias_pub`, no adaptive
  per-target PoW difficulty. Register-class PoW timing is a REAL, observed several-seconds-to-
  roughly-a-minute cost (Hashcash is a random search, not fixed-time) — acceptable for a rare
  one-time action but worth knowing before assuming it's always fast. The inbox's "handled" set is
  local-device-only, same honest scope as the rest of `lib/chatList.ts` — declining/accepting on one
  device doesn't sync that decision to another of the user's own linked devices.
- **Done (2026-07, "signed alias revoke" pass) — R18 progress: `alias_pub` signed ownership +
  revoke are now real, closing the "a nickname can never be freed, not even by its own owner" gap.**
  `alias_pub` moves from bundled-inside-`record` to also being a plaintext `AliasDO` column
  (populated at register time) — no new privacy leak (a bare Ed25519 key has no structural link to
  a nickname/identity, same property the bundled copy already had). New `vortic-core` module
  `alias_sig.rs` (unconditionally compiled, unlike `ratchet.rs` which is `client-full`-only): `sign`
  (client-only, reuses the SAME long-term identity key `ratchet.rs` derives for PQXDH prekey
  signing — not a second keypair) + `verify` (edge-safe, no secret). `ed25519-dalek` moved from a
  `client-full`-optional dep to always-compiled, same precedent as `blind-rsa-signatures`/
  `ark-groth16` ("verification is edge-safe, link it unconditionally, gate only the secret-key
  calls"). New `AliasDO.ts` route `POST /revoke {lookup_key, sig}`: verifies the signature against
  the row's stored `alias_pub` over a canonical `revoke_message(lookup_key)`, then deletes the row —
  no separate nonce needed (a captured signature only ever authorizes revoking the SAME
  (lookup_key, alias_pub) pairing it was made under; see `alias.rs`'s doc comment for the full
  argument). Wired through both the direct `/alias/*` route (already capability-gated) and the
  OHTTP-wrapped path, matching register/resolve/introduce.
  **A real bug found by this pass's own negative test, not assumed in advance:** plain
  `ed25519_dalek::Verifier::verify` (cofactored) accepted an all-zero 32-byte "public key" paired
  with an all-zero 64-byte "signature" as valid for ANY message — the well-known Ed25519 identity-
  point/zero-signature malleability. Real exposure here specifically: `alias_pub` is CLIENT-SUPPLIED
  at registration (the server never derives it), so an attacker could register a row with a
  deliberately degenerate key. Fixed by switching to `verify_strict` (ed25519-dalek's own documented
  mitigation for exactly this class of signature malleability) — reused, not hand-rolled, per this
  crate's standing rule. A legitimately derived `identity_verifying_key(seed)` can never BE the
  degenerate point (RFC 8032 clamping keeps the signing scalar non-zero), so this only ever rejects
  deliberately-malformed input.
  **Live-verified, real WASM, real `wrangler dev` (no browser needed — this is a Worker-API-only
  change, not UI):** a Node probe using the actual compiled `pkg/client` WASM (not a mock) drove 5
  cases against a fresh local instance — real-owner revoke succeeds (204) and the row is genuinely
  gone (replay → 404); a WRONG identity's signature is rejected (401); revoking a nonexistent alias
  → 404; a malformed (wrong-length) signature → 400; and, the one most worth checking explicitly,
  the REJECTED wrong-key revoke did NOT delete the row — confirmed by resolving it afterward and
  getting the original record back byte-for-byte. `cargo test` 45/45 (crate-wide, up from 40 — 8 new
  in `alias_sig.rs`/`alias.rs`), `edge-verify-only` still builds clean for `wasm32-unknown-unknown`
  and `cargo tree` confirms `ml-kem`/`x25519-dalek`/`kem` remain absent from that profile (only
  `ed25519-dalek` newly joined it, as intended). `tsc --noEmit` and `schema-lint` both clean.
  **Honest scope:** update-in-place is NOT implemented (revoke + re-register under a fresh PoW
  stamp covers the same outcome, deliberately kept smaller — see `alias.rs`'s doc comment); reserved/
  verified namespaces and Key Transparency (K8) over alias→key remain open, per R18's own row.
  Pre-existing `AliasDO` instances (created before this pass) get the new `alias_pub` column via a
  guarded `ALTER TABLE` on next wake-up, but any row registered before this pass has an empty
  `alias_pub` and simply can't be revoked until its owner re-registers — not a live concern yet
  (pre-beta, no real registered aliases exist outside local dev testing).

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
| **R7** | **MLS DS metadata** — delivery service still sees ordering/size/epoch | Med | High | Blind ordering only; pad sizes; bucket timestamps; pairwise-queue isolation; documented in N1 | 3 |
| — | *(R7 progress, 2026-07, "server-side bucketing" pass — Mitigated, not fully Closed):* real size-bucket validation + server-side timestamp bucketing now exist for `QueueDO`/`GroupDO`/`ConvLogDO` — see the Phase 3 entry below. **Not done:** optional cover traffic (K6). | | | | |
| — | *(R7 progress, 2026-07, "real MLS group encryption" pass):* the actual MLS crypto core now exists (`MlsGroupSession`, Phase 1 entry above) — `GroupDO`'s blind-ordering design confirmed to need zero changes to carry real Commit/Application messages. **Not done:** `apps/web` wiring (no group is created/joined by a real user yet), PQ ciphersuite for groups (real, disclosed gap — see the Phase 1 entry), Welcome delivery plumbing over `QueueDO`. | | | | |
| R8 | **Sealed Sender residual leak** (receipts/traffic analysis) | Med | Med | Sealed++ (padded/delayed/decoupled receipts), queue isolation, optional chaff (K6) | 3 |
| R9 | **PQC library immaturity** (no CMVP-validated WASM ML-KEM yet) | Med | Med | Hybrid (classical still protects if PQ lib flawed); pin audited versions; track AWS-LC/OpenSSL 3.5 maturity | 1,5 |
| R10 | **DO 10 GB shard / hot-shard limits** | Low | Med | Per-conversation sharding; TTL-evict delivered ciphertext to R2; backpressure | 3 |
| R11 | **Enrollment Sybil** via multiple OAuth accounts | Med | Med | PPID quota per `sub`; invite-only closed network; per-epoch nullifier rate limits | 2 |
| **R12** | **Key-loss / recovery** without linkage is hard UX | Med | High | Recovery phrase + optional blind cloud backup; clear "no phrase = no recovery" contract | 1,4 |
| — | *(R12 progress, 2026-07, "Argon2id/BIP39 backup" pass — Mitigated, not fully Closed):* the crypto pipeline is real and live-WASM-verified — see the Phase 1 entry above. **Not done:** `apps/web` UI (generate/enter phrase, wire to real local state), optional blind cloud backup to R2, live browser/mobile Argon2id-at-256MiB memory verification. | | | | |
| — | *(R12 progress, 2026-07, "blind cloud backup" pass — Mitigated, not fully Closed):* the optional cloud-backup gap the row above named is now closed — real capability+opaque-ID-gated `PUT`/`GET`/`DELETE /backup/:backupId` in `workers/messaging`, both direct and OHTTP-wrapped, backed by a dedicated `BACKUP` R2 bucket, live-verified end-to-end with real WASM-produced ciphertext (see the Phase 1 entry below for the full write-up). **Not done:** `apps/web` UI (unchanged), forward-secret key rotation (docs/03 §11's own explicitly-optional line, deliberately not built this pass), live browser/mobile Argon2id-at-256MiB memory verification. | | | | |
| R13 | **Legal compulsion** of Cloudflare | High | Low | "Can't produce what we can't compute": design ensures no email↔handle data exists to hand over; warrant-canary | all |
| R14 | **CDN/circuit swap** (malicious WASM) | Med | Low | Reproducible builds, binary transparency, client-side circuit-hash pinning (K7) | 5 |
| **R15** | **Alias directory enumeration/scraping** — public aliases reintroduce a discoverable namespace | Med | Med | PoW-per-resolve + encrypted records (dump is inert) + capability gate; adaptive/per-target difficulty; opt-in & default-off | 3 |
| **R16** | **PoW asymmetry** — botnet/GPU/ASIC mint stamps far cheaper than honest mobiles; or bits set too high hurt UX | Med | Med | Memory-hard Argon2id option; adaptive per-target bits; capability gate bounds actors to real accounts; tune bands; off-thread miner | 3,5 |
| — | *(R15/R16 progress, 2026-07, "adaptive resolve difficulty" pass — Mitigated, not fully Closed):* per-target adaptive PoW bits for `/alias/resolve` are real and live-verified — see the Phase 3 entry below. **Not done:** the Argon2id memory-hard PoW option, off-thread/worker-thread client miner, adaptive difficulty on `/register`/`/introduce` (scoped to resolve only, per R15's specific enumeration-scraping angle). | | | | |
| — | *(R16 progress, 2026-07, "Argon2id hardened PoW" pass — Mitigated, not fully Closed):* the memory-hard Argon2id `Hpow` option the row above named is now real and live-verified (crate-core, both native and real compiled WASM, both build profiles) — see the Phase 1 entry above for the full write-up, including real measured costs (~2.66ms/hash at m=4MiB,t=1,p=1) rather than assumed ones. **Not done:** off-thread/worker-thread client miner for this mode specifically, wiring into `AliasDO.ts`'s production verifier or any adaptive-difficulty policy (checked directly: `workers/messaging/src/pow.ts` still only accepts `alg==="sha256"`), and choosing real per-action bit targets under the new param set. | | | | |
| — | *(R16 progress, 2026-07, "wire Argon2id PoW into AliasDO" pass — Mitigated, not fully Closed):* the DO-wiring gap the row above named is now closed — `pow.ts` dispatches on the stamp's own `alg`, argon2id verified via real WASM, and every existing call site's bit target now automatically has a derived (not guessed) Argon2id-equivalent via `argonEquivalentBits`, live-verified with real mined stamps on both register and resolve (see the Phase 1 entry below). **Not done:** off-thread client miner (unaffected — unchanged from the row above), UI to let a user choose the hardened mode, in-Worker/WASM remeasurement of the timing the bit-discount is derived from (currently a native figure). | | | | |
| — | *(R15/R16 progress, 2026-07, "adaptive difficulty for register/introduce" pass — Mitigated, not fully Closed):* the "adaptive difficulty on `/register`/`/introduce`" gap the first row above named (scoped out of the original resolve-only pass) is now closed — both endpoints escalate required bits per-target the same way resolve already did, live-verified with real mined stamps proving both the escalation AND that a stamp mined only for the old base price is rejected once a target has heated up (see the Phase 3 entry below). **Not done:** off-thread client miner (unaffected, same gap as the rows above), UI to surface the current required-bits number to a user before they mine. | | | | |
| R17 | **Host offline dictionary attack** on `AliasDO` dump (nicknames are low-entropy) | Med | Med | Documented residual (aliases are public by intent); high-entropy nickname advice; **identity-linkage stays cryptographically safe** — record holds no email/PPID/handle | 3 |
| **R18** | **Nickname squatting / impersonation** | Low | Med | Registration PoW + capability; `alias_pub` signed ownership; reserved/verified namespaces; report+revoke; Key Transparency (K8) over alias→key | 3,5 |
| — | *(R18 progress, 2026-07, "signed alias revoke" pass — Mitigated, not fully Closed):* `alias_pub` signed ownership + revoke are now real — see the entry below. **Not done:** reserved/verified namespaces, update-in-place (revoke + re-register covers the same outcome for now). | | | | |
| — | *(R18 progress, 2026-07, "Key Transparency (K8)" pass — Mitigated, not fully Closed):* an append-only, publicly-auditable log of every register/revoke event now exists — see the Phase 3 entry below. **Not done:** RFC 6962-style cross-time consistency proofs, independent monitors/gossip, client-side verification wiring, reserved/verified namespaces. | | | | |
| — | *(R18 progress, 2026-07, "Key Transparency consistency proofs" pass — Mitigated, not fully Closed):* the cross-time consistency-proof gap the row above named is now closed — real `GET /transparency/consistency?first=m&second=n`, live-verified against a real running log including a genuine fork/equivocation test (see the Phase 1/3 entries below for the full write-up, including a real soundness question this pass's own adversarial testing raised and resolved: the math authenticates root CONTENT consistency, not the numeric size label — that binding is a separate, still-not-built Signed-Tree-Head mechanism). **Not done:** independent monitors/gossip, client-side (`apps/web`) verification wiring, the STH signature itself, reserved/verified namespaces. | | | | |
| — | *(R18 progress, 2026-07, "Signed Tree Head" pass — Mitigated, not fully Closed):* the STH signature gap the row above named is now closed — real Ed25519-signed `(size, root, timestamp)` via `GET /transparency/sth`, live-verified against a real running log (see the Phase 3 entry below for the full write-up, including the honest "signing alone doesn't prevent equivocation, it makes it DETECTABLE" framing this pass states plainly). **Not done:** independent monitors/gossip (the piece that actually USES a captured STH for detection), client-side (`apps/web`) verification wiring, reserved/verified namespaces. | | | | |
| — | *(R18 progress, 2026-07, "KT gossip/monitor" pass — Mitigated, not fully Closed):* the "independent monitors/gossip" gap the row above named is now closed AS A MECHANISM — `workers/messaging/scripts/kt-monitor.mts` persists its own STH history independently of the server and alarms on equivocation/shrink/rewritten-history, live-verified with 3 real alarm scenarios plus a real growth scenario driven by an actual mined PoW + alias registration (see the Phase 3 entry below). **Not done, and this is the load-bearing gap:** actual THIRD-PARTY deployment — running this from a separately-controlled account/machine/schedule against the public prod endpoint is what makes equivocation detection real rather than theoretical; a single operator running their own monitor against their own log proves the code, not the trust property. Also still not done: client-side (`apps/web`) verification wiring, reserved/verified namespaces. | | | | |
| — | *(R18 progress, 2026-07, "reserved/verified namespaces" pass — R18's last named "Not done" item, now closed):* `POST /alias/reserve` + a `registrant_sig` requirement on `handleRegister` mean a reserved name needs BOTH real PoW and an offline namespace-authority Ed25519 signature to claim — live-verified with 10 real checks (direct) + 2 (OHTTP) including the key regression that ordinary names are completely unaffected (see the Phase 3 entry below). R18 now has no remaining item marked "Not done" across any of its progress notes except the still-open client-side (`apps/web`) verification wiring for R18's OTHER sub-features (KT consistency/STH), which this pass didn't touch. | | | | |
| R19 | **Self-doxxing** — a human-chosen public alias is a persistent identifier the *user* exposes | Low | High | Default invisible; explicit opt-in warning; recommend pairing with an ephemeral persona (K2); never auto-suggest real-name aliases | 3,4 |
| **R20** | **Session capability was in `localStorage`** — JS-readable, so any XSS or malicious extension with DOM access could trivially steal a live bearer credential authorising `/queue` etc. | High | Closed | **Mitigated 2026-07** (Plane Bridge pass): moved to in-memory React state only, never persisted; reload loses the session by design. Open follow-up: a real "remember this device" UX (if ever added) needs a non-extractable key (WebCrypto non-exportable `CryptoKey` / platform keystore), not Web Storage | 2 |
| **R21** | **`/auth/session` accepted a fixed, shared valid ZK proof vector, not one generated live from the client's own Semaphore witness** — the mock circuit's public inputs never changed, so every client presented the *same* proof. | High | Closed | **Resolved 2026-07 (server side — see docs/06's "Real Semaphore v4" and "R21-continued" entries below).** `/auth/session` now verifies a REAL Semaphore v4 proof (official circuit, real LeanIMT+Poseidon root in `MerkleTreeDO`) against public inputs built from the CALLER's own `(merkleRoot, nullifier, message, scope)`, with `merkleRoot` additionally checked against the tree's actual current root. `VK_HEX` is now the OFFICIAL PSE multi-party trusted-setup ceremony key ("Semaphore V4 Ceremony 1", 300-400+ contributors, finalized 2024-09-05) — not a local single-party test setup. Live-verified against the official artifacts: a genuinely different proof/root/nullifier per request, replay/stale-root/tampered-proof all correctly rejected, both natively (arkworks) and inside the live Workers WASM runtime. **Not independently re-verified:** the full multi-party ceremony transcript (per-contribution hash chain / beacon replay) — only the published end result's file integrity and structural/cryptographic correctness against our circuit. | 2 |
| **R22** | **Messaging chat transport is still a one-socket-both-directions mock** — `useChatWebSocket.ts` does one `ws.send()` for both send and receive on a single `queue_id`, not `QueueDO`'s actual documented asymmetric protocol (`POST /push` HTTP for send, WS receive-only fan-out + `{type:"ack"}` for receive) | Med | Closed | **Resolved 2026-07** (see the "R22: real transport" entry below). `useChatWebSocket.ts` deleted outright, no fallback path; the real `useQueueTransport.ts` uses the documented `POST /push` + WS-receive + `{type:"ack"}` protocol over two real unidirectional queues, plus Sealed Sender++ receipts (padded/delayed/decoupled — docs/01, docs/README #5) and real `ConvLogDO` multi-device sync (a genuine WS-hibernation gap in `ConvLogDO` found and fixed in the same pass). Live-verified: real bidirectional 1:1 delivery + receipts through `QueueDO`, and 3-device `ConvLogDO` fan-out (2 live + 1 backlog-on-connect), all against a live `wrangler dev`, zero mocking. **Not fully closed as a PRODUCT feature** — see the entry below for the honest remaining gap (real per-user queue-id provisioning / contact establishment, Flow 5/6, still doesn't exist; this pass fixed the transport primitive, not that separate system). | 3 |
| **R23** | **Client (`apps/web`) does not generate a real Semaphore proof** — `AuthCallback.tsx`'s step 5 still references the retired mock-circuit vector and sends no `message`/`scope`; against the now-real `/auth/session` (R21, resolved server-side) this will fail (missing fields, and even patched, the old proof bytes won't verify against the new real VK). Real client-side proving needs the circuit `.wasm`+`.zkey` bundled into the web app and a browser proving step (docs/06 R6 territory — WASM size/perf). | High | Closed | **Fully Resolved 2026-07** (see the "R23: real client-side proving" and "R23 follow-up: MerkleTreeDO /proof/:commitment" entries below). `AuthCallback.tsx` generates a real Groth16 proof in-browser via `snarkjs` against the official ceremony `semaphore-20.wasm`/`.zkey`, fetching its own real Merkle proof from `MerkleTreeDO`'s new `GET /proof/:commitment` — works for a tree of ANY size, not just the sole-member case the first sub-pass shipped. Live-verified with TWO real identities, proof requested for the non-first member specifically (the key regression check): both authenticate successfully (`zk_verify_groth16_bytes -> true`, capability minted for both). | 2,4 |
| **R24** | **1:1 message transport (R22, resolved) still ran on unauthenticated, non-ratcheting X25519 DH** — a bare ephemeral key swap with no signed prekeys (MITM-able on first contact) and no ratchet at all (one static session key for the whole chat, so a single key compromise exposes every message, past and future) — a direct gap against docs/02's G1-G4 (confidentiality, forward secrecy, post-compromise security, PQ). | High | Closed | **Resolved 2026-07** (see the "R24: real Triple Ratchet" entries in both Phase 1 and Phase 3 below). Real PQXDH-style handshake (Ed25519-signed hybrid ML-KEM-768+X25519 prekey bundle, rejects an unsigned/wrong-key bundle outright) + real Double Ratchet (per-message forward secrecy, DH-turn post-compromise security) + Sparse PQ Ratchet (periodic ML-KEM remix, chain-scoped — see the entry for why root-scoped hit a real symmetry bug and was descoped honestly). `useQueueTransport.ts`'s flat DH deleted, no fallback. Live-verified over a real `wrangler dev` QueueDO: PQXDH handshake, 4 alternating messages, key-rotation proof (identical plaintext → provably distinct ciphertext), and forward-secrecy proof (replaying an old captured message against the receiver's advanced session correctly fails). **Not claiming:** MLS/group ratcheting, a real `PrekeyDO`/identity-persistence service (still a `role`-style stand-in, same honesty standard as R22), or literal root-level (vs. chain-level) PQ propagation. | 1,3 |
| **R25** | **OHTTP was never implemented, only stub comments claiming it existed "in production"** — `index.ts`/`wrangler.toml` said this Worker "sits behind an OHTTP relay" with no relay, no Gateway route, and no client-side encapsulation anywhere in the codebase. README calls this "load-bearing, not cosmetic": without it Cloudflare sees the real client IP on every anonymity-zone call regardless of cryptographic identity unlinkability (docs/03 §2). | High | Closed | **Resolved 2026-07** (see the "R25: real OHTTP" entry above, plus its same-day follow-up). Real RFC 9458 implementation: new `packages/ohttp` (RFC 9292 Binary HTTP framing + RFC 9458 Key Config/request/response framing, built on the real `@hpke/core` HPKE library — researched first, confirmed no maintained Gateway/framing package exists before writing any protocol code, per this task's own instruction), `workers/messaging`'s new Gateway routes (`/ohttp/keys`, `/ohttp/gateway`), new `workers/ohttp-relay` (the Relay role), `apps/web`'s `ohttpFetch` wired into all FOUR plain request/response routes: the three original ones (`/membership/insert`, `/membership/proof/:commitment`, `/auth/session`) plus `/queue/:id/push` — the real message-send path, added same-day after being flagged as under-prioritized (it's the highest-frequency OHTTP-eligible route, not a one-time enrollment call). Live-verified against real `wrangler dev` for all three roles, including a full round trip that mints a real capability, pushes a real message through OHTTP, and confirms delivery via a direct WS subscribe with the exact plaintext round-tripping. IP-visibility demonstrated structurally (the Gateway-dispatched handlers never receive a `Request` object at all, only a decapsulated `BhttpRequest` with no IP field) rather than via a locally-meaningless header comparison — see the entry above for why. **Not claiming:** WebSocket routes are OHTTP-wrapped (structurally impossible — single-shot scheme vs. persistent connection; a subscriber's IP is handed directly to A2, the Messaging Worker itself — see **R26**, tracked separately because this is a different, more severe adversary category than the network-observer threat R2's VPN/OHTTP mitigation stack targets), or an independently-operated Relay (same-account Cloudflare deploy closes this pass's target gap, not the deeper "colluding relay+gateway operator" threat docs/03 §2 already names). | 2 |
| **R26** | **A WS subscribe/receive connection (`/queue/:id`, `/conv/:id`) hands its real connecting IP directly to A2 — docs/02's PRIMARY adversary, the host itself** ("reads all D1/R2/DO state, sees Worker inputs incl. client IP, can log & correlate, can be legally compelled") — not merely to a passive network observer (A1/A7). R25's OHTTP cannot wrap this: RFC 9458 is a single-shot request/response scheme, structurally incompatible with a persistent connection, so for the ENTIRE time a client is online receiving messages, its IP is an ordinary Worker input the Messaging Worker (and therefore Cloudflare) sees directly — no wiretap, no traffic analysis required, just an ordinary connection log. **This is a categorically different and more severe risk than R2** ("network-level correlation defeats ZK"): R2 is about an adversary correlating separate requests across time/IP; this is the primary adversary observing, continuously and trivially, exactly which IP is behind an active receiving session. | High | **Mitigated (same-zone, live-verified 2026-07-19) — not fully Closed** | `workers/ohttp-relay` proxies the WS upgrade for `/queue/:id`/`/conv/:id` at the network level (not HPKE — WS structurally can't be OHTTP-wrapped), preserving genuine real-time delivery (no polling). **Live-verified against the real deployed stack (first real Cloudflare deploy, 2026-07-19 — see docs/deploy-checklist.md), not simulated:** a `wrangler tail` capture on the real `vorticity-messaging` Worker showed a DIRECT request's `cf-connecting-ip` as the real caller IP (`87.110.116.194`, edge-authoritative on real Cloudflare — confirmed different from local `wrangler dev`'s spoofable behavior), and the SAME request routed THROUGH `relay.vort.xfeatures.net` showed `cf-connecting-ip=0.0.0.0` — the literal override value `proxyWebSocket`'s `x-real-ip` sets, confirming the documented same-zone `CF-Connecting-IP`-reflects-`x-real-ip` behavior fires exactly as Cloudflare's own docs describe. **What this DOES prove:** the same-zone mitigation this repo's own code implements genuinely works on real infrastructure, not just in theory. **What this does NOT prove, stated as plainly as the "unverified" status was before:** this is not the platform-guaranteed cross-zone `CF-Connecting-IP` auto-anonymization the original R26 design targeted — it depends on `proxyWebSocket`'s override staying correct forever, and the "colluding relay+gateway operator" gap (docs/03 §2) remains fully open, since Relay and Gateway are the same operator's infrastructure under same-zone (see docs/deploy-checklist.md §5 for the topology decision and why cross-zone isn't available right now). Genuinely a step forward from "unverified" to "verified for the weaker mechanism," not yet the stronger property — hence "Mitigated," not "Closed." **Revisit before opening beyond a small trusted alpha circle who has been told this trade-off plainly.** | 3 |

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
