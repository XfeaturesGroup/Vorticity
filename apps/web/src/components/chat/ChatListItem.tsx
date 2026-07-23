import { Trash2 } from "lucide-react";
import { cn } from "@vorticity/ui";
import type { Chat } from "../../lib/chat";

interface ChatListItemProps {
  chat: Chat;
  isActive: boolean;
  onClick: () => void;
  onDelete: () => void;
}

export function ChatListItem({ chat, isActive, onClick, onDelete }: ChatListItemProps) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onClick()}
      className={cn(
        "group w-full flex items-center gap-3.5 px-4 py-3.5 text-left transition-colors border-b border-white/5 cursor-pointer",
        isActive ? "bg-white/[0.06]" : "hover:bg-white/[0.04]",
      )}
    >
      <div className="relative shrink-0">
        <div className="w-12 h-12 rounded-full bg-fluid-peach/15 border border-fluid-peach/20 flex items-center justify-center text-sm font-semibold text-fluid-peach">
          {chat.initials}
        </div>
        {chat.online && (
          <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-signal-success border-2 border-black" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-medium text-white truncate">{chat.alias}</span>
          <span className="text-[10px] text-white/40 shrink-0">{chat.lastMessageAt}</span>
        </div>
        <div className="flex items-center justify-between gap-2 mt-1">
          <span className="text-xs text-white/50 truncate">{chat.lastMessage}</span>
          {chat.unreadCount > 0 && (
            <span className="shrink-0 min-w-[18px] h-[18px] px-1 rounded-full bg-fluid-peach/20 text-fluid-peach text-[10px] font-bold flex items-center justify-center">
              {chat.unreadCount}
            </span>
          )}
        </div>
      </div>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        title="Delete this chat (removes local history and crypto state — cannot be undone)"
        className="shrink-0 p-1.5 rounded-lg text-white/0 group-hover:text-white/40 hover:!text-signal-danger hover:bg-signal-danger/10 transition-colors"
      >
        <Trash2 className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
