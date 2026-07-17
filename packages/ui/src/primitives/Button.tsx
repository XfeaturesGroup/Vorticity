// Ported from Xfeatures HQ's src/components/ui/Button.tsx — same API, same variants, same
// "hold to confirm" affordance (useful as-is for Vorticity's destructive/duress actions).
// Only change: shadow-edge-lit now resolves to a real token (see styles/theme.css) instead of
// a dangling reference.
import {
  forwardRef,
  useState,
  useRef,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { motion, type HTMLMotionProps } from "framer-motion";
import { cn } from "../lib/cn";

export type ButtonVariant =
  | "primary"
  | "secondary"
  | "outline"
  | "danger"
  | "destructive"
  | "hold"
  | "ghost";

interface ButtonProps extends Omit<HTMLMotionProps<"button">, "children"> {
  variant?: ButtonVariant;
  isLoading?: boolean;
  children?: ReactNode;
  /** Only used when variant="hold" — ms of sustained press before onHoldComplete fires. */
  holdTimeMs?: number;
  onHoldComplete?: () => void | Promise<void>;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = "primary",
      isLoading,
      children,
      disabled,
      holdTimeMs = 1500,
      onHoldComplete,
      ...props
    },
    ref,
  ) => {
    const [isHolding, setIsHolding] = useState(false);
    const holdTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

    const startHold = (e: React.PointerEvent) => {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      if (variant !== "hold" || disabled || isLoading) return;

      setIsHolding(true);
      if (holdTimeout.current) clearTimeout(holdTimeout.current);

      holdTimeout.current = setTimeout(() => {
        setIsHolding(false);
        if (onHoldComplete) void onHoldComplete();
      }, holdTimeMs);
    };

    const cancelHold = useCallback(() => {
      if (variant !== "hold") return;
      setIsHolding(false);
      if (holdTimeout.current) {
        clearTimeout(holdTimeout.current);
        holdTimeout.current = null;
      }
    }, [variant]);

    useEffect(() => () => cancelHold(), [cancelHold]);

    const variants: Record<ButtonVariant, string> = {
      primary: cn(
        "bg-white/[0.02] border border-white/10 text-white shadow-glass backdrop-blur-md",
        "hover:bg-black/20 hover:border-transparent hover:shadow-edge-lit hover:text-white",
      ),
      secondary: cn(
        "bg-black/20 border border-white/5 text-white/60",
        "hover:text-white hover:bg-black/30 hover:border-transparent hover:shadow-[0_0_0_1px_rgba(255,255,255,0.2)]",
      ),
      outline: cn(
        "bg-black/20 border border-white/5 text-white/60",
        "hover:text-white hover:bg-black/30 hover:border-transparent hover:shadow-[0_0_0_1px_rgba(255,255,255,0.2)]",
      ),
      danger: cn(
        "bg-fluid-pink/5 border border-fluid-pink/20 text-fluid-pink/90",
        "hover:bg-black/20 hover:border-transparent hover:text-fluid-pink hover:shadow-[0_0_0_1px_rgba(255,51,102,0.6),0_12px_24px_-8px_rgba(255,51,102,0.25)]",
      ),
      destructive: cn(
        "bg-fluid-pink/5 border border-fluid-pink/20 text-fluid-pink/90",
        "hover:bg-black/20 hover:border-transparent hover:text-fluid-pink hover:shadow-[0_0_0_1px_rgba(255,51,102,0.6),0_12px_24px_-8px_rgba(255,51,102,0.25)]",
      ),
      hold: cn(
        "bg-transparent border border-dashed border-white/20 text-white/50",
        "hover:text-white hover:border-white/50 hover:bg-white/[0.02] active:border-fluid-pink active:text-fluid-pink",
      ),
      ghost: cn("bg-transparent border-transparent text-white/50", "hover:text-white hover:bg-white/[0.05]"),
    };

    const disableScale = disabled || isLoading || variant === "hold";

    return (
      <motion.button
        ref={ref}
        whileHover={disableScale ? {} : { scale: 1.015 }}
        whileTap={disableScale ? {} : { scale: 0.98 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className={cn(
          "relative flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl font-medium text-sm transition-colors duration-300 overflow-hidden group",
          "select-none touch-none",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          variants[variant],
          className,
        )}
        disabled={disabled || isLoading}
        onPointerDown={(e) => {
          startHold(e);
          props.onPointerDown?.(e);
        }}
        onPointerUp={(e) => {
          cancelHold();
          props.onPointerUp?.(e);
        }}
        onPointerLeave={(e) => {
          cancelHold();
          props.onPointerLeave?.(e);
        }}
        onPointerCancel={(e) => {
          cancelHold();
          props.onPointerCancel?.(e);
        }}
        onContextMenu={(e) => {
          if (variant === "hold") e.preventDefault();
        }}
        style={{
          WebkitUserSelect: "none",
          WebkitTouchCallout: "none",
          ...(props.style ?? {}),
        }}
        {...props}
      >
        {variant === "hold" && (
          <div
            className="absolute inset-0 w-full bg-[#FF3366]/30 z-0 pointer-events-none origin-left"
            style={{
              transform: isHolding ? "scaleX(1)" : "scaleX(0)",
              transition: isHolding ? `transform ${holdTimeMs}ms linear` : "transform 0.2s ease-out",
            }}
          />
        )}

        {isLoading ? (
          <div className="w-5 h-5 border-2 border-white/20 border-t-fluid-peach rounded-full animate-spin relative z-10" />
        ) : (
          <span className="relative z-10 pointer-events-none">{children}</span>
        )}
      </motion.button>
    );
  },
);
Button.displayName = "Button";
