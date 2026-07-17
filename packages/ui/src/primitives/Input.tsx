// Ported from Xfeatures HQ's src/components/ui/Input.tsx — same API. `shadow-focus-ring` now
// resolves to a real token (see styles/theme.css) instead of a dangling reference.
import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../lib/cn";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, ...props }, ref) => {
    return (
      <div className="flex flex-col gap-2 w-full">
        {label && <label className="text-sm font-medium text-white/60 tracking-wide">{label}</label>}
        <div className="relative group">
          <input
            ref={ref}
            className={cn(
              "w-full bg-black/20 border border-white/5 rounded-xl px-4 py-3.5",
              "text-white font-mono text-sm placeholder:text-white/20 tracking-wide",
              "transition-all duration-300 ease-out shadow-inner",
              "hover:border-white/10 hover:bg-black/30",
              "focus:outline-none focus:border-transparent focus:shadow-focus-ring focus:bg-black/40",
              "disabled:opacity-50 disabled:cursor-not-allowed",
              error && "border-fluid-pink text-fluid-pink focus:shadow-[0_0_0_1px_rgba(255,51,102,0.8)]",
              className,
            )}
            {...props}
          />
        </div>
        {error && <span className="text-xs font-mono text-fluid-pink mt-1">{error}</span>}
      </div>
    );
  },
);
Input.displayName = "Input";
