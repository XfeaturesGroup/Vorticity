<div align="center">
  <h1>🌪️ Xfeatures — Vorticity</h1>

  <p>
    <strong>A closed, metadata-hostile E2EE messenger. Cloudflare hosts it and cannot link your
    account to your identity, your sessions, or your messages.</strong>
  </p>
</div>

---

> [!CAUTION]
> ## 🛑 STRICTLY PROPRIETARY — DO NOT USE
> The source code, assets, and architecture in this repository are the exclusive intellectual
> property of **XfeaturesGroup**. No license is granted. Unauthorized use, reproduction, or
> commercial exploitation is prohibited. By viewing this repository, you agree to these terms.
> Copyright © 2026 XfeaturesGroup. All Rights Reserved.

---

## What this is

Vorticity is being rebuilt from scratch as a **two-plane architecture**: an *Enrollment Plane* that
talks to Xfeatures Account OAuth2 and never sees a message, and a *Messaging Plane* that carries all
chat traffic and never sees an email. The two are bridged only by a blind signature — the design
goal is that even Cloudflare, with full database access and a court order, cannot reconstruct
who-talks-to-whom.

**Start here:** [docs/README.md](docs/README.md) — full architecture, threat model, crypto core,
serverless design, feature list, and roadmap.

## Monorepo layout

```
apps/
  web/                  React + Vite client (TypeScript)
  mobile/               Capacitor shell around apps/web (native checks for the Security Gate)
packages/
  ui/                   Shared design system — inherited from Xfeatures HQ + Xfeatures Web
  vortic-core/          Rust → WASM crypto core (ratchet, MLS, ZK, ring sigs, VOPRF, PoW)
workers/
  enrollment/           Cloudflare Worker — OAuth2, PPID, blind token issuance. Sees identity.
  messaging/             Cloudflare Worker — Durable Objects, D1(msg), R2. Sees only ciphertext.
docs/                   Architecture dossier (read this first)
scripts/                CI tooling, incl. schema-lint (plane-isolation enforcement)
```

## Stack

TypeScript · React · Vite · Cloudflare Workers · Durable Objects · D1 · R2 · Rust/WASM ·
Xfeatures Account OAuth2 (the only auth provider — <https://account.xfeatures.net/docs/oauth2>).

## Status

Phase 0 (monorepo scaffold + CI plane-isolation gate) — see
[docs/06-roadmap-and-risks.md](docs/06-roadmap-and-risks.md) for the full phased plan.
