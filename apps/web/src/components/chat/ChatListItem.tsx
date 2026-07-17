import { cn } from "@vorticity/ui";
import type { Chat } from "../../lib/mockChats";

interface ChatListItemProps {
  chat: Chat;
  isActive: boolean;
  onClick: () => void;
}

export function ChatListItem({ chat, isActive, onClick }: ChatListItemProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors border-b border-white/5",
        isActive ? "bg-white/5" : "hover:bg-white/[0.03]",
      )}
    >
      <div className="relative shrink-0">
        <div className="w-11 h-11 rounded-full bg-fluid-peach/15 border border-fluid-peach/20 flex items-center justify-center text-sm font-semibold text-fluid-peach">
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
        <div className="flex items-center justify-between gap-2 mt-0.5">
          <span className="text-xs text-white/50 truncate">{chat.lastMessage}</span>
          {chat.unreadCount > 0 && (
            <span className="shrink-0 min-w-[18px] h-[18px] px-1 rounded-full bg-fluid-peach/20 text-fluid-peach text-[10px] font-bold flex items-center justify-center">
              {chat.unreadCount}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}
