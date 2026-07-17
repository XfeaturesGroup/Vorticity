# 07 — UI Design System (`packages/ui`)

Per the brief: Vorticity's frontend must **strictly inherit** the visual language of two existing
ecosystem projects — it invents no new visual identity. This doc records what was actually found in
those two repos, the decisions made where they disagree, and the resulting token/primitive set now
scaffolded at [`packages/ui`](../packages/ui).

**Sources inspected:**
- **Xfeatures HQ** — `C:\Users\User\Desktop\Projects\Web\Xfeatures\XfeaturesAccount\xfeatures-hq-web`
- **Xfeatures Web** — `C:\Users\User\Desktop\Projects\Web\Xfeatures\XfeaturesWeb\xfeatures-web`

## What both sources agree on (inherited directly)

- **Pure black, dark-only canvas.** Neither kit has a light theme or `dark:` variants — dark is the
  only mode. Vorticity follows suit; no light-theme work is planned.
- **Glassmorphism as the primary surface language**: `backdrop-blur-*` + low-opacity black/white
  fills (`bg-black/20`–`/60`, `bg-white/[0.02]`) + hairline borders (`border-white/5`–`/10`) instead
  of solid fills or drop-shadow-driven depth.
- **A global film-grain/noise overlay** (SVG `feTurbulence`, tiny opacity, `mix-blend-mode`) applied
  site-wide in Web and per-section in HQ. Extracted as a shared `<NoiseOverlay />` primitive.
- **The same motion signature**: `cubic-bezier(0.16, 1, 0.3, 1)` recurs in both kits' framer-motion
  usage (entrances, hover/tap, transitions). Codified as `--ease-house` in the token file.
- **`lucide-react`** for icons, **`clsx` + `tailwind-merge`** (`cn()`) for class composition, in both.
- **No `class-variance-authority` / `tailwind-variants` / Radix in either kit.** Variants are hand-
  rolled `Record<Variant, string>` maps composed with `cn()`. `packages/ui` follows this convention —
  introducing `cva` now would be inventing a new pattern neither source project uses.
- **Roboto Flex / Playfair Display** as the sans/serif pair — the one font decision both kits'
  *configuration* agrees on (HQ's `@theme`, Web's `tailwind.config.js`).

## Where the sources disagree — decisions made, and why

| Divergence | HQ | Web | Decision | Why |
|---|---|---|---|---|
| Tailwind version | v4 (`@theme`, no config file) | v3.4 (`tailwind.config.js`) | **v4** | HQ is the more current setup; v4's `@theme` is where the token file (`theme.css`) now lives. |
| Componentization | Real primitives exist (`Button`, `Input`, `GlassPanel`, `Modal`) | **None** — every "card"/"button" is inline duplicated Tailwind strings, `cn()` imported but unused | **Port from HQ** | Web has nothing reusable to inherit here; it's a marketing site, not a component kit. |
| Accent color | "Fluid" gradient family: peach/purple/magenta/pink | Plain orange/red, used as a singular accent + warning color | **HQ's fluid palette**, as `--color-fluid-*` | HQ is the account/security-facing product — closer to Vorticity's context — and already established this as *its* accent, vs. Web's generic marketing orange. |
| Mono font | Used (`font-mono` on `Input`) but never declared in HQ's `@theme` | Declared (`JetBrains Mono`) in `tailwind.config.js` | **JetBrains Mono**, declared properly | Fills a real gap in HQ; Web already made the choice. |
| Third font pair | N/A | `index.html` currently loads **Newsreader/Switzer** via a live `FontSwitcher` dev toggle, contradicting its own `tailwind.config.js` | **Not inherited** | That pair is explicitly an in-flux A/B experiment (a debug widget lets a user swap it live), not a settled brand decision — the *configured* pair (Roboto Flex/Playfair Display) is the defensible choice. |

## Bugs found in the source kits — fixed, not propagated

- **HQ's `Button.tsx`/`Input.tsx` reference `shadow-edge-lit` and `shadow-focus-ring`** as Tailwind
  utilities, but **neither token is defined anywhere** in HQ's `@theme` block or CSS — a dangling
  reference in the source kit itself (these classes silently no-op in HQ today). `packages/ui`
  defines both for real (see `theme.css`), following the same construction pattern as the sibling
  `shadow-glass-hover` token, instead of shipping the same silent bug.
- **HQ's `Modal.tsx` uses a raw `bg-[#111]`** instead of the obsidian scale or the glass pattern
  every other surface in the same kit uses — an inconsistency within HQ itself. Fixed in
  `packages/ui/src/primitives/Modal.tsx` to use `bg-obsidian-800/95` + the shared glass shadow.
- **Web's `hide-scrollbar` class** is referenced (`DropdownFilter.tsx`) but never defined. Not
  ported — `packages/ui` ships one working scrollbar utility (`.vx-scrollbar`) instead of two, one
  of which doesn't exist.

## What's new (additions, not invented style)

- **Semantic signal colors** (`--color-signal-danger/warning/success/info`) for the Pre-Session
  Security Gate (docs/05 K1) and PoW/verification feedback — neither kit needed these. `danger`/
  `warning` alias the existing `fluid-pink`/`fluid-peach` tokens; `success`/`info` fall back to
  stock Tailwind hues (emerald/blue), matching Web's own convention of using un-tokenized stock
  Tailwind colors when no brand token exists, rather than inventing new brand colors.
- **`<NoiseOverlay />`**: both kits apply the grain motif via inline markup/CSS at different call
  sites (Web: global `body::before`; HQ: per-section `<div>`). Extracted once as a shared primitive
  so `apps/web` doesn't re-derive it, with the data URI inlined (no external asset dependency).

## Package layout

```
packages/ui/
  src/
    styles/theme.css       @theme tokens (colors, fonts, shadows, motion) + base/component layers
    lib/cn.ts              clsx + tailwind-merge, ported verbatim
    primitives/
      Button.tsx            ported from HQ (variants incl. "hold to confirm" — reusable for
                             Vorticity's duress/panic-wipe actions, docs/05 K4)
      Input.tsx              ported from HQ
      GlassPanel.tsx          ported from HQ
      Modal.tsx               ported from HQ, fixed (see above)
      NoiseOverlay.tsx        extracted from both kits' inline usage
    index.ts               barrel export
```

## Gotcha discovered while wiring `apps/web` (worth knowing before adding a second consumer)

Tailwind v4's automatic content detection is rooted at whichever file contains `@import
"tailwindcss"` — and `@tailwindcss/vite` transforms CSS files individually as they pass through
Vite's module graph, so an `@apply`-using file needs that import *in itself*, not just inherited
textually from an importer. Concretely, `packages/ui/src/styles/theme.css` keeps `@import
"tailwindcss"` (it's the file with `@apply` in the base layer) and lists every consumer's source
directory via `@source`. **Adding a new consumer (e.g. `apps/mobile` once Phase 4 gives it real
source) means adding its path as another `@source` line in that file** — a consumer's own CSS
entry doing only `@import "@vorticity/ui/theme.css";` is not sufficient on its own. Verified
empirically in this session: computed styles (`bg-black/40` → `oklab(0 0 0 / 0.4)`,
`backdrop-blur-3xl` → `blur(64px)`) confirmed generating correctly in `apps/web` after this fix.

**Follow-up gotcha (Phase 4, Chats UI pass):** `packages/ui`'s own source was never given an
explicit `@source` line — only consumers were. The assumption was that Tailwind's "roots at the
nearest package.json to the `@import tailwindcss` file" behavior covers `packages/ui/src`
automatically. In practice this silently missed at least one utility: `NoiseOverlay.tsx`'s
`pointer-events-none` never made it into the generated stylesheet, which broke click-through on
every page using `<NoiseOverlay />` (confirmed live: `getComputedStyle(overlay).pointerEvents`
was `"auto"`, and the class was absent from `document.styleSheets` entirely). It went unnoticed
until now because every *other* packages/ui-only class exercised so far (`absolute`, `inset-0`,
`backdrop-blur-3xl`, etc.) also happens to be used directly somewhere in `apps/web/src`, so those
generated correctly regardless of whether `packages/ui/src` itself was truly being scanned.
`pointer-events-none` was the first class used *exclusively* inside `packages/ui/src`, so it's
what exposed the gap. **Fix:** an explicit `@source "../"` for this package's own `src/` (added
alongside the consumer entries — `theme.css` lives in `packages/ui/src/styles/`, so `"../"` reaches
`src/`; a first attempt used `"./"`, which is wrong — that resolves to `styles/`, which has no
source files in it at all). Confirmed by the generated stylesheet growing from 27,341 to 42,840
bytes after the correct fix, meaning a meaningful share of this package's own utility classes had
likely been silently missing all along. **Lesson: never rely on Tailwind v4's implicit
nearest-package.json rooting for a shared package — always list its own `src/` in `@source`
explicitly too, right next to the consumer entries, from day one.**

## Explicitly out of scope here

Messenger-specific composite UI — the actual Security Gate panel (docs/05 K1), chat bubbles/message
list, alias registration flow, PoW-mining progress indicator — belongs in `apps/web` (Phase 4), built
*from* these primitives/tokens. `packages/ui` stays a pure design-system layer: tokens + generic
primitives inherited from the two source kits, nothing product-specific.
