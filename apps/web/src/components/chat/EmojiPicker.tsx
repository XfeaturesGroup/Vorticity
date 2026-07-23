import { useEffect, useRef, useState } from "react";
import { Plus } from "lucide-react";
import { cn } from "@vorticity/ui";

const QUICK_REACT = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

// A hand-maintained grid, not a full unicode emoji library — this is quick-react on a message
// bubble, not a rich-text composer picker (that'd be a much bigger, lower-priority feature).
const FULL_GRID = [
  "👍", "👎", "❤️", "🔥", "😂", "😮", "😢", "😡", "🙏", "🎉",
  "👏", "🤔", "😍", "😎", "🤯", "💯", "✅", "❌", "👀", "🚀",
  "😅", "😭", "🥳", "🤝", "💀", "😴", "🤗", "👌", "😏", "🫡",
];

export function EmojiPicker({ onPick, onClose }: { onPick: (emoji: string) => void; onClose: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [onClose]);

  return (
    <div ref={rootRef} className="rounded-xl border border-white/10 bg-black/90 backdrop-blur-md shadow-glass p-2">
      <div className={cn("grid gap-1", expanded ? "grid-cols-10" : "grid-cols-7")}>
        {(expanded ? FULL_GRID : QUICK_REACT).map((emoji) => (
          <button
            key={emoji}
            type="button"
            onClick={() => onPick(emoji)}
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white/10 text-base transition-colors"
          >
            {emoji}
          </button>
        ))}
        {!expanded && (
          <button
            type="button"
            title="More emoji"
            onClick={() => setExpanded(true)}
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white/10 text-white/50 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}
