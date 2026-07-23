import { AnimatePresence, motion } from "framer-motion";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import { cn } from "@vorticity/ui";
import { useToast, type Toast as ToastData } from "../contexts/ToastContext";

const KIND_META = {
  info: { icon: Info, cls: "border-white/10 bg-white/5 text-white/90" },
  success: { icon: CheckCircle2, cls: "border-signal-success/30 bg-signal-success/10 text-white" },
  error: { icon: AlertCircle, cls: "border-signal-danger/30 bg-signal-danger/10 text-white" },
} as const;

function ToastRow({ toast, onDismiss }: { toast: ToastData; onDismiss: () => void }) {
  const { icon: Icon, cls } = KIND_META[toast.kind];
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 16, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: 40, transition: { duration: 0.15 } }}
      transition={{ type: "spring", stiffness: 400, damping: 30 }}
      className={cn("flex items-center gap-2.5 pointer-events-auto rounded-xl border px-4 py-3 shadow-glass backdrop-blur-md max-w-sm", cls)}
    >
      <Icon className="w-4 h-4 shrink-0" />
      <span className="text-sm flex-1 min-w-0">{toast.message}</span>
      <button type="button" onClick={onDismiss} className="shrink-0 text-white/40 hover:text-white transition-colors">
        <X className="w-3.5 h-3.5" />
      </button>
    </motion.div>
  );
}

/** Mount once near the root (App.tsx) — reads `useToast()` itself, no props needed. */
export function ToastViewport() {
  const { toasts, dismissToast } = useToast();
  return (
    <div className="fixed bottom-6 right-6 z-[100] flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {toasts.map((t) => (
          <ToastRow key={t.id} toast={t} onDismiss={() => dismissToast(t.id)} />
        ))}
      </AnimatePresence>
    </div>
  );
}
