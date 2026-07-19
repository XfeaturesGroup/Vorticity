import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { stashPendingInviteFromCurrentLocation } from "../lib/inviteLink";

/** Wraps the post-auth app shell. Unauthenticated visitors bounce to the Security Gate ("/") —
 * there is nothing app-shell-shaped to show someone who hasn't been through the gate yet.
 *
 * Waits for `isRestoring` before deciding (2026-07): the session capability is now restored from
 * lib/secureStore.ts's vault on mount, which is asynchronous — redirecting on `isAuthenticated`
 * alone would bounce a reload on an already-authenticated route to "/" on the very first render,
 * before the restore attempt even runs.
 *
 * Stashes a pending invite before redirecting (2026-07, real bug found in the first genuine two-
 * person invite test): `<Navigate replace>` swaps the ENTIRE URL, hash included — someone opening an
 * invite link for the first time, not yet authenticated, would silently lose it right here, before
 * Chats.tsx ever mounts to read it. See lib/inviteLink.ts's header comment for the full story and
 * where it gets picked back up after login. */
export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated, isRestoring } = useAuth();
  if (isRestoring) return null;
  if (!isAuthenticated) {
    stashPendingInviteFromCurrentLocation();
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
