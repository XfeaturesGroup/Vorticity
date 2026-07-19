# First real Cloudflare deploy — preparation checklist

**EXECUTED 2026-07-19 — this is no longer a plan, it's what actually happened.** All of §1-§4 below were
run for real against the account confirmed by the architect (`XfeaturesGroup`, domain `vort.xfeatures.net`,
`OAUTH_REDIRECT_URI` confirmed set on the IDM side). Original per-section text is left as-was (still
accurate as a description of *what each step does*); this note plus each section's own "Executed" callout
records what actually landed, including one real mistake made and fixed along the way.

**Real incident during §2 (D1), fixed, said plainly:** `wrangler d1 delete vorticity-enroll` was run
intending to delete an accidentally-self-created duplicate database — but `wrangler d1 delete <name>`
resolves the name against the LOCAL `wrangler.toml`'s `database_name` field first, not a fresh
Cloudflare-side lookup, and `workers/enrollment/wrangler.toml`'s `database_name` field ("vorticity-enroll")
didn't match the real Cloudflare-side name of the database it pointed to ("vortic-enroll-db", pre-existing
since 2026-07-15). Result: the REAL, pre-existing enrollment D1 database was deleted, not the duplicate.
**Actual damage: zero** — the deleted database had 0 tables (migrations had never been applied to it), so
no data existed to lose; confirmed via `wrangler d1 list` before deletion. Fixed by creating a fresh
replacement (`vortic-enroll-db`, new `database_id`), re-applying migrations, and — since this exact
name/database_name mismatch was ALSO present in `workers/messaging/wrangler.toml` (a latent version of the
same footgun) — correcting both files' `database_name` fields to match their real Cloudflare-side names,
so `wrangler d1 delete` by name can't silently resolve to the wrong database again. Full incident + fix
narrated in this session's own record; not swept under the rug.

Everything below the incident note is now a record of what was done, not a forward-looking plan — kept in
its original per-step structure since that structure is still the right reference for redoing this on a
future environment (e.g. a genuine cross-zone migration, see §5).

**One Cloudflare account, same-zone (2026-07 — see §5, revised from an earlier cross-zone plan):**
`workers/enrollment`, `workers/messaging`, AND `workers/ohttp-relay` all deploy to the **same** account.
A second, independent account for the Relay was the original plan (stronger R26 guarantee) but isn't
available right now — Workers Paid is provisioned on only one account. This is explicit, temporary, and
weaker than cross-zone — see §5 for exactly what it costs and when to revisit it.

Every section below is still broken out per-worker for clarity, even though all three now share one account.

---

## 1. Secrets to move from `.dev.vars` to `wrangler secret put`

### `workers/enrollment`

| Secret | `.dev.vars.example` name | Notes |
|---|---|---|
| OAuth client secret | `OAUTH_CLIENT_SECRET` | Already issued by the Xfeatures IDM — reuse the existing value, don't regenerate. |
| PPID HMAC key | `PPID_HMAC_SECRET` | sybil-guard hash key — generate fresh for prod; rotating it later invalidates all existing PPIDs. |
| RSABSSA issuer signing key | `ISSUER_SIGNING_KEY_PEM` | RSA-3072 secret key PEM, already generated once via `examples/rsabssa_keygen.rs`. **Do NOT regenerate** — the matching public key is already committed (`workers/messaging/src/issuer-keys.ts`, `apps/web/src/lib/issuerKey.ts`); before `secret put`, diff the PEM's public component against both committed copies to confirm they still match the same keypair. |

```bash
# from workers/enrollment/, once logged into the Cloudflare account
wrangler secret put OAUTH_CLIENT_SECRET
wrangler secret put PPID_HMAC_SECRET
wrangler secret put ISSUER_SIGNING_KEY_PEM
```

### `workers/messaging`

| Secret | `.dev.vars.example` name | Notes |
|---|---|---|
| Session capability HMAC key | `SESSION_SIGNING_KEY` | signs/verifies the short-lived bearer capability — generate fresh for prod. |
| OHTTP Gateway HPKE seed | `OHTTP_GATEWAY_SEED` | 32-byte hex seed, deterministic keypair derivation for the OHTTP Gateway role — generate fresh for prod. |

```bash
# from workers/messaging/, once logged into the Cloudflare account
wrangler secret put SESSION_SIGNING_KEY
wrangler secret put OHTTP_GATEWAY_SEED
```

### `workers/ohttp-relay` — none

The Relay currently has **zero secrets** — its only config is `GATEWAY_ORIGIN`, a plain URL, not
secret-shaped (`schema-lint`'s check #4 would catch it if it ever became one). This is correct for its
role: a dumb byte-forwarder that never touches HPKE keys or plane secrets, independent of same-zone or
cross-zone topology. Confirm this is still true before deploy (re-check
`workers/ohttp-relay/wrangler.toml`'s `[vars]` block and that no `.dev.vars` file has been added for it
since this was written) — don't assume it stays empty forever without looking.

**Before executing any of the above:** grep both plane workers' `.dev.vars.example` files directly
(`workers/enrollment/.dev.vars.example`, `workers/messaging/.dev.vars.example`) to confirm the tables above
are still exhaustive. `schema-lint.mjs`'s `/SECRET|KEY|SIGNING|PRIVATE/i` check on `[vars]` (all three
`wrangler.toml`s) should be re-run as a belt-and-suspenders confirmation nothing secret-shaped is sitting
in a plain `[vars]` block anywhere.

Values must NOT be reused between local `.dev.vars` and prod, except `ISSUER_SIGNING_KEY_PEM` specifically
(identity-coupled to the already-committed public key — regenerating it breaks every already-issued token
verification path until both public-key copies are re-synced).

**Executed 2026-07-19:** all 5 secrets landed (`wrangler secret list` confirmed on both workers).
`OAUTH_CLIENT_SECRET` and `ISSUER_SIGNING_KEY_PEM` reused as-is from `.dev.vars` — the latter's public
half was independently re-derived via `openssl rsa -pubout` and diffed byte-for-byte against BOTH
committed copies (`issuer-keys.ts`, `issuerKey.ts`) before reuse, not assumed. `PPID_HMAC_SECRET`,
`SESSION_SIGNING_KEY`, `OHTTP_GATEWAY_SEED` generated fresh (`openssl rand -hex 32`). Cloudflare's API
returned `504 Gateway Timeout` twice during this (once on a call that actually succeeded server-side
despite the error — confirmed via `secret list`; once on a call that genuinely failed and was retried) —
transient platform flakiness on Cloudflare's end, not a config issue, worth remembering if this is ever
scripted/automated (don't treat a `secret put` 504 as authoritative failure without checking `secret list`).

---

## 2. D1 databases to create

Only the two plane workers have D1 bindings — **the Relay has none, by design** (`schema-lint`'s check #5
enforces this: the Relay must never bind either plane's D1/R2/DO, independent of account topology).

### `workers/enrollment`

`database_id = "REPLACE_ME_RUN_WRANGLER_D1_CREATE"` in `workers/enrollment/wrangler.toml`.

```bash
# from workers/enrollment/
wrangler d1 create vorticity-enroll
# copy the returned database_id into workers/enrollment/wrangler.toml
wrangler d1 migrations apply vorticity-enroll --remote
```

### `workers/messaging`

`database_id = "REPLACE_ME_RUN_WRANGLER_D1_CREATE"` in `workers/messaging/wrangler.toml`.

```bash
# from workers/messaging/
wrangler d1 create vorticity-msg
# copy the returned database_id into workers/messaging/wrangler.toml
wrangler d1 migrations apply vorticity-msg --remote
```

Confirm table lists match `--local` (`SELECT name FROM sqlite_master`) for both — both planes have had
schema drift caught before (see docs/06's `spent_tokens` bugfix and the `nullifiers` column-name mismatch
noted as a still-open, non-fatal D1-mirror error), so don't assume `--remote` behaves identically without
checking.

**Executed 2026-07-19, with one real incident (see the top-of-file note):** both databases exist, both
fully migrated, `--remote`/`--local` table lists confirmed matching for both (`vortic-enroll-db`:
`enroll_ppid`; `vortic-msg-db`: `aliases`, `blobs_meta`, `commitments`, `conv_log`, `group_roots`,
`issuer_token_null`, `merkle_nodes`, `nullifiers`, `pow_stamps`, `prekeys`, `queue_messages`, `queues`
— 4 messaging migrations applied, not the 1 originally described above; migrations grew since this
checklist was first written, applied cleanly regardless). Also discovered and fixed: BOTH workers'
`wrangler.toml`s had a `database_name` field that didn't match the real Cloudflare-side database name
(a latent footgun, not just in the one file that bit us) — corrected both.

---

## 3. Hostnames to resolve

All three now live under the same account's zone(s), but keep distinct subdomains — this is still needed
independent of the account-topology question (separate CORS/redirect-uri scoping, separate Worker routes).

| Placeholder | Worker | Used by | What's needed |
|---|---|---|---|
| `id.vort.xfeatures.net` | `workers/enrollment` | prod `OAUTH_REDIRECT_URI` in `wrangler.toml`; `apps/web`'s enrollment API base | DNS + Worker route/custom domain binding |
| `api.vort.xfeatures.net` | `workers/messaging` | prod API base for non-OHTTP-wrapped calls (`apps/web/src/lib/convLogSync.ts`'s `MESSAGING_API_URL`) | DNS + Worker route/custom domain binding |
| `relay.vort.xfeatures.net` | `workers/ohttp-relay` | prod `RELAY_URL` in `apps/web/src/lib/ohttp.ts`; prod `WS_BASE_URL` in `useQueueTransport.ts`/`convLogSync.ts` | DNS + Worker route/custom domain binding |

**These are the subdomains this repo's docs/code have consistently assumed (`vort.xfeatures.net` apex) —
NOT confirmed as actually registered/available.** Whatever real domain is actually ready needs to be
confirmed explicitly before provisioning anything; do not assume `vort.xfeatures.net` is live without
checking.

The Relay's `GATEWAY_ORIGIN` var also needs to change from the local-dev default
(`http://127.0.0.1:8787`) to the real, deployed `api.vort.xfeatures.net` once the Messaging Worker is live.

Also needs a decision, not just DNS: production `OAUTH_REDIRECT_URI` must exactly match what's registered
with the Xfeatures IDM (RFC 6749 §4.1.3 — this repo already hit `invalid_grant` once from a redirect_uri
mismatch, see docs/06) — this requires access to the Xfeatures IDM app-registration panel, not just DNS.

**A SECOND, real instance of this exact bug class found+fixed 2026-07-19, before it could block the final
live test:** `OAUTH_REDIRECT_URI` in `workers/enrollment/wrangler.toml` was `https://id.vort.xfeatures.net/
oauth/callback` — wrong host AND wrong path. `id.vort.xfeatures.net` is the Enrollment Worker's own API
domain, not where a user's browser lands after the IDM redirect; `SecurityGate.tsx` has always built
`redirect_uri` as `${window.location.origin}/auth/callback` (the SPA's own client-side route,
`App.tsx`'s `/auth/callback` → `AuthCallback.tsx`), which on the real deployed frontend is
`https://vort.xfeatures.net/auth/callback`. Fixed the var to match; confirmed via a live `curl` to
`https://id.vort.xfeatures.net/oauth/callback` with `redirect_uri: "https://vort.xfeatures.net/auth/
callback"` — reached the real IDM and got `invalid_grant` (expected for a fake code), not this Worker's
own `400 "redirect_uri not allowed"`, confirming the allow-list check now passes.

### Not a placeholder, but verify

| Host | Status |
|---|---|
| `account.xfeatures.net` | Already real/external (Xfeatures IDM) — confirm the registered `client_id`/redirect URIs on the IDM side match whatever `id.vort.xfeatures.net` ends up being. **Open question for the architect, per the bug above: the redirect_uri that must be registered on the IDM panel for `client_id=xf_9116480c21a94a849a1182717e35f335` is `https://vort.xfeatures.net/auth/callback` — NOT `id.vort.xfeatures.net/oauth/callback`. This Worker-side allow-list is now fixed to expect the correct value, but the IDM's OWN registration (a separate, external system this repo can't inspect or edit) needs to match it too, or `/authorize` will reject before a code is ever issued — this repo cannot confirm that from here.** |

**Executed 2026-07-19:** `vort.xfeatures.net` is real, on the `XfeaturesGroup` Cloudflare account, and
already serves `apps/web` via a Git-connected Pages project (`vorticity-frontend`) — discovered live,
not previously known to this doc. Architect confirmed the domain and confirmed `OAUTH_REDIRECT_URI` is
correctly registered on the IDM side. All three `[[routes]]`/`custom_domain = true` entries added
(`workers/ohttp-relay` needed an `[env.production]` split, since its `GATEWAY_ORIGIN` must stay
`http://127.0.0.1:8787` for plain local `wrangler dev` — only `wrangler deploy --env production` picks
up the real `https://api.vort.xfeatures.net` override and the production route). All three workers
deployed; custom-domain TLS certificates took several minutes to provision after first deploy (normal
Cloudflare behavior, not a config issue) — confirmed live via `curl`/`openssl s_client` once ready.
`workers/messaging`'s R2 bucket (`vorticity-media`, referenced in `wrangler.toml` but never created) was
auto-provisioned by `wrangler deploy` itself.

---

## 4. R26 — how to actually check the IP-hiding property post-deploy

R26's status in docs/06 is **"Open (implemented, unverified)"** specifically because this cannot be checked
in `wrangler dev`/Miniflare — it only simulates the static `request.cf` object, not Cloudflare's real
edge-network header behavior. Concrete verification steps once the real zone exists:

1. **Temporarily instrument** `workers/messaging/src/index.ts`'s WS-upgrade handler (or reuse the same
   temporary-`/health`-log pattern already used once for R25's local-dev IP check) to log
   `request.headers.get("cf-connecting-ip")` on every `/queue/:id` or `/conv/:id` upgrade. Remove the
   instrumentation again once the check is done — don't ship it.
2. **Direct-connection baseline:** from a machine with a known public IP, open a WS connection straight to
   `api.vort.xfeatures.net` (bypassing the Relay entirely), confirm the logged `cf-connecting-ip` is that
   real IP. This is the "before" — confirms the header is edge-authoritative on the real platform (unlike
   local dev, where it was empirically shown to be spoofable/non-authoritative).
3. **Via-relay test:** open the same WS connection through `relay.vort.xfeatures.net` instead, from the
   same known-public-IP machine. Compare the logged `cf-connecting-ip` on the Messaging Worker's side:
   - **Expected result, given the SAME-ZONE topology in §5:** per Cloudflare's documented same-zone
     `CF-Connecting-IP` behavior, this reflects `x-real-ip`, which the Relay's own code
     (`proxyWebSocket` in `workers/ohttp-relay/src/index.ts`) already overrides to `0.0.0.0`. If this
     override is honored as documented, the Messaging Worker should see `0.0.0.0`, not the real client
     IP — a real result, but note **what it proves**: this is this repo's own code working as intended,
     not a platform-enforced guarantee. It's a materially weaker result than the cross-zone
     auto-anonymization the original plan targeted (see §5's honest cost accounting).
   - If it still shows the real client IP → the `x-real-ip` override isn't taking effect (header
     stripped/overridden somewhere in the request path, same-zone `CF-Connecting-IP` derivation doesn't
     behave as Cloudflare's docs describe for this exact setup, etc.) — needs debugging before R26 can be
     marked anything but Open.
   - If it shows some THIRD value — investigate before concluding either way; don't assume it's
     equivalent to either expected outcome.
4. **Report the result exactly as observed** — do not round an ambiguous or partial result up to "Closed".
   Given the same-zone topology, even a clean pass (Messaging sees `0.0.0.0`) should be recorded as
   "verified: same-zone `x-real-ip` override confirmed working" — a real, meaningful result, but distinct
   from and weaker than "verified: platform-guaranteed cross-zone IP anonymization", which is what the
   original R26 design targeted and cannot be claimed from a same-zone test. See docs/06's R26 entry for
   the exact wording convention already established for this distinction.

**Executed 2026-07-19 — exactly the expected same-zone result, not the ambiguous third case.** Used plain
HTTP requests (`curl`, with real `Upgrade: websocket` headers for the relay leg) rather than a full WS
handshake — sufficient, since the IP-check log line fires before any capability/protocol logic runs.
`wrangler tail` on the live `vorticity-messaging` Worker showed: **direct** request →
`cf-connecting-ip=87.110.116.194` (the real caller IP — confirms the header IS edge-authoritative on real
Cloudflare, unlike local `wrangler dev`); **via relay** → `cf-connecting-ip=0.0.0.0` (the literal
`x-real-ip` override value `proxyWebSocket` sets — confirms the same-zone override genuinely works on
real infrastructure). Instrumentation was temporary (added, deployed, tested, removed, redeployed clean —
confirmed via `git diff` showing zero residual change to `index.ts`). **Recorded in docs/06 as
"Mitigated (same-zone, live-verified)" — deliberately NOT "Closed"**, per this section's own guidance
above: this proves the weaker same-zone mechanism works, not the platform-guaranteed cross-zone property
the original design targeted.

---

## 5. Relay account topology — RESOLVED: same-zone, temporary (revised from cross-zone)

**Decided by the architect (2026-07).** The originally-planned cross-zone/separate-account topology (see
git history / prior docs/06 entries for that write-up) is **not currently deployable**: Workers Paid is
provisioned on only one Cloudflare account, and a second account isn't available right now. Reverted to
**same-zone**: `workers/ohttp-relay` deploys to the same account as `workers/enrollment` +
`workers/messaging`.

**What this costs, stated plainly, not glossed over:**
- The platform-guaranteed `CF-Connecting-IP` auto-replacement for cross-account/cross-zone subrequests
  does NOT apply here. The only mechanism protecting Messaging from seeing the real WS-connecting IP is
  this repo's own `x-real-ip` header override in `proxyWebSocket` — correct as documented Cloudflare
  same-zone behavior, but contingent on that code staying correct forever, not a platform-level guarantee
  that survives a future edit mistake.
- The residual "colluding relay+gateway operator" gap (docs/03 §2) is **not addressed at all** by
  same-zone — Relay and Gateway are, literally, one operator's infrastructure right now. Cross-zone under
  a separate account was specifically meant to close this; same-zone does not.
- This is an accepted, explicit, temporary trade-off for reaching a first working closed alpha — not a
  silent downgrade. It must be revisited before the project opens beyond a small trusted circle who can be
  told this plainly (see docs/06's R26 entry for the exact status language this maps to).

**Config-level state after reverting the earlier cross-zone prep:**
- The explicit-`account_id`-per-worker split (added, then reverted, this same window) is gone from all
  three `wrangler.toml`s — same-zone means there's nothing to structurally separate. `wrangler login`
  once, for one account, covers all three workers.
- `scripts/schema-lint.mjs`'s Relay-isolation check (#5) still enforces "the Relay must never bind either
  plane's D1/R2/DO" — that invariant holds regardless of account topology — but no longer enforces
  account-id separation, since same-zone means the Relay legitimately shares an account with both plane
  workers now.

### What actually needs to happen before deploy (single account)

1. Confirm/select the one Cloudflare account (Workers Paid) that will host all three workers.
2. `wrangler login` (or a `CLOUDFLARE_API_TOKEN`) against that account.
3. Provision DNS for `id.vort.xfeatures.net`, `api.vort.xfeatures.net`, `relay.vort.xfeatures.net` under
   that account's zone (see §3 — confirm the real apex domain first, don't assume `vort.xfeatures.net`).
4. Run §1's secret-put and §2's D1-create steps.
5. Deploy `workers/enrollment` and `workers/messaging` first (the Relay depends on Messaging being live
   for `GATEWAY_ORIGIN`), then `workers/ohttp-relay`.
6. Run §4's R26 check and record the result exactly as observed.

### When to revisit cross-zone

Before opening this beyond a small trusted alpha circle who has been told plainly about the same-zone
trade-off above. A second Cloudflare account becoming available is the trigger to re-do the account-split
prep (re-add per-worker `account_id`, re-add the schema-lint account-separation check — both were written
once already this project, see git history for the exact diff to reapply) and re-run §4's R26 check
against the stronger cross-zone topology before claiming that gap closed.

---

## 6. Real incident (2026-07-19): the git-triggered Pages build is structurally broken, and always has been

**What happened:** pushing a real commit (`8db0eb1`) to `main` triggered `vorticity-frontend`'s
connected Cloudflare Pages build, which failed:
```
Could not resolve "../pkg/client/vortic_core.js" from "../../packages/vortic-core/js/crypto.ts"
```
Cloudflare correctly kept serving the last-good deployment (the site never actually went down for
users), but the NEW frontend code was not live — a real, user-visible gap between "workers deployed"
and "frontend deployed" until this was caught and fixed the same session.

**Root cause, confirmed not assumed:** `packages/vortic-core/pkg/` (the `wasm-pack build` output
`js/crypto.ts` imports) is deliberately git-ignored (a build artifact, never committed — `git log --all
-- packages/vortic-core/pkg/` returns nothing, confirmed before writing this). Cloudflare Pages' build
image runs `pnpm install` + `npm run build` (`apps/web`'s own `vite build`, since the Pages project's
root directory is `apps/web`) — it never runs `wasm-pack build`, has no Rust/cargo/wasm-pack toolchain
invoked anywhere in that pipeline, and `apps/web/package.json`'s own `"build": "vite build"` script has
no step that would build the dependency first. **This has been true since the very first pass that made
`crypto.ts` import from `pkg/` (Phase 1, "Real WASM") — it did not newly break today.** The deployment
history shows exactly this: some earlier deployments of the SAME commit succeeded, others of that same
commit failed — the only way that's possible is if the "successful" ones were never a git-triggered CI
build at all, but a manual `wrangler pages deploy <local-dist>` upload from a machine that already had
`pkg/` built on disk (bypassing Cloudflare's build pipeline entirely). That was never written down
until now.

**Fix applied THIS incident (a workaround, not a structural fix — said plainly):** built `apps/web`
locally (`pkg/` already present on disk from this session's own WASM rebuild) and deployed the resulting
`dist/` directly — `wrangler pages deploy dist --project-name=vorticity-frontend --branch=main`. Verified
live: the direct deployment URL and, ~20s later, the custom domain `vort.xfeatures.net` both served the
new build's asset hash, matching the local build exactly. This is the SAME mechanism the historical
successful deployments must have used, now written down.

**Standing gap, NOT closed by this incident, needs a real decision before the next push to `main`:**
every future push to `main` will trigger the SAME auto-build, and it will fail the SAME way, every
time, until one of these is actually done:
- Give the Pages build environment a way to produce `pkg/` (a Rust+`wasm-pack` toolchain in the build
  command, if Cloudflare's build image supports installing one — not yet investigated), **or**
- Change `apps/web/package.json`'s `build` script to build `vortic-core`'s WASM first (would still need
  cargo/wasm-pack available in that CI image — same open question as above), **or**
- Deliberately commit the built `pkg/client` output (a real, if unusual, pattern for exactly this kind
  of "CI can't build a non-JS toolchain's output" constraint) — reverses this project's own stated
  "`pkg/` is a git-ignored build artifact" convention on purpose, would need to be re-generated and
  re-committed on every `vortic-core` source change, **or**
- Formalize "manual `wrangler pages deploy` after every push that touches `vortic-core`/`apps/web`" as
  the actual documented process, disconnect or ignore the auto-build entirely.
None of these was decided or implemented — this incident's fix got the CURRENT push live, it did not
prevent the next one from failing its auto-build the same way. Whoever pushes to `main` next should
expect the same Cloudflare build-failure notification and know it does not mean the site is down.
