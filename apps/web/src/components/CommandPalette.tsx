// Phase D app-level polish (2026-07): Ctrl/Cmd+K quick-jump to a chat, from anywhere in the app.
// Mounted once in AppLayout (global), NOT inside Chats.tsx — chat SELECTION state lives there, not
// here, so this reads the persisted chat list independently (same lib/chatList.ts vault Chats.tsx
// itself restores from) and hands off a selection via a `?open=<chatId>` query param rather than a
// shared context, mirroring the same "read a URL signal on mount" pattern Chats.tsx already uses for
// invite/device-link hashes. Filter logic is deliberately the same plain substring match
// ChatList.tsx's own search box uses — no new fuzzy-match dependency for what's still a small list.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { MessageSquare, Search } from "lucide-react";
import { loadChatList } from "../lib/chatList";
import type { Chat } from "../lib/chat";

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeIndex, setActiveIndex] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActiveIndex(0);
    loadChatList()
      .then(setChats)
      .catch(() => setChats([]));
  }, [open]);

  const filtered = chats.filter((c) => c.alias.toLowerCase().includes(query.trim().toLowerCase()));

  const selectChat = (chatId: string) => {
    setOpen(false);
    navigate(`/chats?open=${encodeURIComponent(chatId)}`);
  };

  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[90] bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[15vh]"
        onClick={() => setOpen(false)}
      >
        <motion.div
          initial={{ opacity: 0, y: -12, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -12, scale: 0.97 }}
          transition={{ type: "spring", stiffness: 400, damping: 32 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-lg mx-4 rounded-2xl border border-white/10 bg-black/90 shadow-glass overflow-hidden"
        >
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/10">
            <Search className="w-4 h-4 text-white/40 shrink-0" />
            <input
              autoFocus
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActiveIndex(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActiveIndex((i) => Math.min(i + 1, filtered.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActiveIndex((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter" && filtered[activeIndex]) {
                  selectChat(filtered[activeIndex]!.id);
                }
              }}
              placeholder="Jump to a chat..."
              className="flex-1 min-w-0 bg-transparent text-sm text-white placeholder-white/40 focus:outline-none"
            />
            <kbd className="shrink-0 text-[10px] text-white/30 border border-white/10 rounded px-1.5 py-0.5">Esc</kbd>
          </div>
          <div className="max-h-80 overflow-y-auto vx-scrollbar">
            {filtered.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-white/30">No chats found</div>
            ) : (
              filtered.map((chat, i) => (
                <button
                  key={chat.id}
                  type="button"
                  onClick={() => selectChat(chat.id)}
                  onMouseEnter={() => setActiveIndex(i)}
                  className={
                    "w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors " +
                    (i === activeIndex ? "bg-white/10" : "hover:bg-white/5")
                  }
                >
                  <div className="w-8 h-8 rounded-full bg-fluid-peach/15 border border-fluid-peach/20 flex items-center justify-center text-xs font-semibold text-fluid-peach shrink-0">
                    {chat.initials}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-white truncate">{chat.alias}</div>
                    <div className="text-xs text-white/40 truncate">{chat.lastMessage}</div>
                  </div>
                  <MessageSquare className="w-3.5 h-3.5 text-white/20 shrink-0" />
                </button>
              ))
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
