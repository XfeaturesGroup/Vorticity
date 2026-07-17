import { useState } from "react";
import { Search } from "lucide-react";
import type { Chat } from "../../lib/mockChats";
import { ChatListItem } from "./ChatListItem";

interface ChatListProps {
  chats: Chat[];
  activeChatId: string | null;
  onSelect: (id: string) => void;
}

export function ChatList({ chats, activeChatId, onSelect }: ChatListProps) {
  const [search, setSearch] = useState("");
  const filtered = chats.filter((c) => c.alias.toLowerCase().includes(search.trim().toLowerCase()));

  return (
    <div className="w-80 md:w-96 shrink-0 border-r border-white/10 flex flex-col h-full min-h-0">
      <div className="p-4 border-b border-white/10 shrink-0">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
          <input
            type="text"
            placeholder="Search chats..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-black/30 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
          />
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto vx-scrollbar">
        {filtered.length === 0 ? (
          <div className="p-6 text-center text-white/30 text-sm">No chats found</div>
        ) : (
          filtered.map((chat) => (
            <ChatListItem key={chat.id} chat={chat} isActive={chat.id === activeChatId} onClick={() => onSelect(chat.id)} />
          ))
        )}
      </div>
    </div>
  );
}
