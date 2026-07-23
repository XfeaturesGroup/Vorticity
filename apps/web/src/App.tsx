import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { ToastProvider } from "./contexts/ToastContext";
import { AuthGuard } from "./components/AuthGuard";
import { AppLayout } from "./components/layout/AppLayout";
import { ToastViewport } from "./components/Toast";
import { SecurityGate } from "./pages/SecurityGate";
import { AuthCallback } from "./pages/AuthCallback";
import { Chats } from "./pages/Chats";
import { Settings } from "./pages/Settings";

export function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <ToastViewport />
        <BrowserRouter>
          <Routes>
            {/* Pre-Session Security Gate: standalone, no sidebar (docs/05 K1) — this is the airlock
                before OAuth, not part of the post-auth app shell. */}
            <Route path="/" element={<SecurityGate />} />

            {/* OAuth redirect target — also standalone, no sidebar (nothing to show pre-auth). */}
            <Route path="/auth/callback" element={<AuthCallback />} />

            {/* Post-auth app shell, gated. */}
            <Route
              element={
                <AuthGuard>
                  <AppLayout />
                </AuthGuard>
              }
            >
              <Route path="/chats" element={<Chats />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
