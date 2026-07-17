# @vorticity/mobile — placeholder

Deferred to **Phase 4** ([docs/06-roadmap-and-risks.md](../../docs/06-roadmap-and-risks.md)). This
package reserves the workspace slot; there is nothing to build yet.

When Phase 4 starts:
1. `pnpm --filter @vorticity/web build` (Capacitor wraps the built web bundle, not source).
2. `cap init` here, `cap add android`, point `webDir` at `../web/dist`.
3. Add native plugins for the **Pre-Session Security Gate** (docs/05 K1) checks that only exist
   natively: root/jailbreak/emulator detection, screen-capture protection — a web build cannot
   perform these. The legacy app's `frontend/android` Capacitor project (now deleted, still in git
   history at the pre-rebuild commit) can be referenced for Gradle/Capacitor plumbing, but its
   dependencies (`@capacitor/*` on the old React app) are not reusable as-is since the whole
   frontend was rebuilt on `@vorticity/ui`.
