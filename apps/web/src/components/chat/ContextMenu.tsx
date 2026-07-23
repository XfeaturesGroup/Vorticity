import { useEffect, useRef, type ReactNode } from "react";
import { cn } from "@vorticity/ui";

export interface ContextMenuItem {
  label: string;
  icon: ReactNode;
  onClick: () => void;
  danger?: boolean;
}

const MENU_WIDTH = 180;
const ROW_HEIGHT = 36;

/** Right-click menu, positioned at the cursor and clamped to stay inside the viewport. Replaces
 * MessageBubble's old always-visible inline action row (edit/delete/copy) — that row reserved
 * horizontal layout space even while invisible (opacity-0), pushing bubbles noticeably off the
 * screen edge toward center; a right-click menu takes zero layout space until actually open. */
export function ContextMenu({ x, y, items, onClose }: { x: number; y: number; items: ContextMenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [onClose]);

  const left = Math.min(x, window.innerWidth - MENU_WIDTH - 8);
  const top = Math.min(y, window.innerHeight - items.length * ROW_HEIGHT - 16);

  return (
    <div
      ref={ref}
      style={{ left, top, width: MENU_WIDTH }}
      className="fixed z-[70] rounded-xl border border-white/10 bg-black/95 backdrop-blur-md shadow-glass py-1"
    >
      {items.map((item) => (
        <button
          key={item.label}
          type="button"
          onClick={() => {
            item.onClick();
            onClose();
          }}
          className={cn(
            "w-full flex items-center gap-2.5 px-3 py-2 text-sm text-left transition-colors",
            item.danger ? "text-signal-danger hover:bg-signal-danger/10" : "text-white/80 hover:bg-white/10 hover:text-white",
          )}
        >
          {item.icon}
          {item.label}
        </button>
      ))}
    </div>
  );
}
