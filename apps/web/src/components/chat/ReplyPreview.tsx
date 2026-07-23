import { X } from "lucide-react";

/** Shown above the composer while replying to (or editing) a message — dismissible. `accent` swaps
 * the left border/label color so "replying" and "editing" read as visually distinct at a glance. */
export function ReplyPreview({
  label,
  text,
  onCancel,
  accent = "peach",
}: {
  label: string;
  text: string;
  onCancel: () => void;
  accent?: "peach" | "info";
}) {
  return (
    <div
      className={
        "shrink-0 flex items-center gap-3 px-4 py-2 border-t border-b border-white/10 bg-white/[0.03] border-l-2 " +
        (accent === "peach" ? "border-l-fluid-peach" : "border-l-signal-info")
      }
    >
      <div className="flex-1 min-w-0">
        <div className={"text-xs font-medium " + (accent === "peach" ? "text-fluid-peach" : "text-signal-info")}>{label}</div>
        <div className="text-xs text-white/50 truncate">{text || "Attachment"}</div>
      </div>
      <button type="button" onClick={onCancel} className="shrink-0 p-1 rounded-lg text-white/40 hover:text-white hover:bg-white/10 transition-colors">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}
