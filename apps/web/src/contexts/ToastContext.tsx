// Phase D app-level polish (2026-07): a single toast mechanism to replace the ad hoc inline
// copy-confirmation/error banners scattered through Chats.tsx (invite link, device-link code,
// media-upload failures) — same "one mechanism, not N one-off pieces of state" reasoning already
// applied elsewhere in this app (see chatReducer.ts's header comment).
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

export type ToastKind = "info" | "success" | "error";

export interface Toast {
  id: string;
  kind: ToastKind;
  message: string;
}

interface ToastContextValue {
  toasts: Toast[];
  showToast: (message: string, kind?: ToastKind) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const TOAST_DURATION_MS = 4000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    (message: string, kind: ToastKind = "info") => {
      const id = crypto.randomUUID();
      setToasts((prev) => [...prev, { id, kind, message }]);
      setTimeout(() => dismissToast(id), TOAST_DURATION_MS);
    },
    [dismissToast],
  );

  return <ToastContext.Provider value={{ toasts, showToast, dismissToast }}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast() must be called within a ToastProvider");
  return ctx;
}
