import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

/** Wraps the post-auth app shell. Unauthenticated visitors bounce to the Security Gate ("/") —
 * there is nothing app-shell-shaped to show someone who hasn't been through the gate yet. */
export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/" replace />;
  return <>{children}</>;
}
