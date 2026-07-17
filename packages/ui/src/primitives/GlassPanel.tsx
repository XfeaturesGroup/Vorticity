// Ported from Xfeatures HQ's src/components/ui/GlassPanel.tsx — same API, same entrance motion.
import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { cn } from "../lib/cn";

interface GlassPanelProps {
  children: ReactNode;
  className?: string;
  /** Framer-motion entrance delay, seconds. */
  delay?: number;
}

export const GlassPanel = ({ children, className, delay = 0 }: GlassPanelProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1], delay }}
      className={cn(
        "relative overflow-hidden rounded-2xl",
        "bg-black/40 backdrop-blur-3xl",
        "border border-white/[0.04]",
        "shadow-[0_16px_40px_rgba(0,0,0,0.8)]",
        className,
      )}
    >
      {/* hairline glass edge */}
      <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent opacity-70 pointer-events-none" />
      <div className="relative z-10 p-8">{children}</div>
    </motion.div>
  );
};
