import { useEffect, useRef, useState, type FormEvent } from "react";
import { Lock, MessageSquare, Paperclip, Send } from "lucide-react";
import { cn } from "@vorticity/ui";
import type { Chat } from "../../lib/mockChats";
import type { SocketStatus } from "../../hooks/useChatWebSocket";
import { MessageBubble } from "./MessageBubble";

interface ActiveChatPanelProps {
  chat: Chat | null;
  socketStatus: SocketStatus;
  onSend: (text: string) => void;
}

const SOCKET_STATUS_META: Record<SocketStatus, { label: string; dot: string; pulse: boolean }> = {
  connecting: { label: "Connecting...", dot: "bg-fluid-peach", pulse: true },
  online: { label: "Online", dot: "bg-signal-success", pulse: false },
  reconnecting: { label: "Reconnecting...", dot: "bg-signal-danger", pulse: true },
  offline: { label: "Offline", dot: "bg-white/30", pulse: false },
};

export function ActiveChatPanel({ chat, socketStatus, onSend }: ActiveChatPanelProps) {
  const [draft, setDraft] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [chat?.id, chat?.messages.length]);

  if (!chat) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
        <MessageSquare className="w-12 h-12" />
        <p className="text-sm">Select a chat to start messaging</p>
      </div>
    );
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setDraft("");
  };

  return (
    <div className="flex-1 flex flex-col h-full min-h-0 min-w-0">
      {/* Header */}
      <div className="shrink-0 flex items-center gap-3 px-5 py-4 border-b border-white/10">
        <div className="w-10 h-10 rounded-full bg-fluid-peach/15 border border-fluid-peach/20 flex items-center justify-center text-sm font-semibold text-fluid-peach shrink-0">
          {chat.initials}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white truncate">{chat.alias}</div>
          <div className="flex items-center gap-1.5 text-xs text-white/40">
            <span
              className={cn(
                "w-1.5 h-1.5 rounded-full",
                SOCKET_STATUS_META[socketStatus].dot,
                SOCKET_STATUS_META[socketStatus].pulse && "animate-pulse",
              )}
            />
            {SOCKET_STATUS_META[socketStatus].label}
          </div>
        </div>
        <div className="flex items-center gap-1.5 text-white/40 shrink-0">
          <Lock className="w-3.5 h-3.5" />
          <span className="text-[11px] uppercase tracking-wider hidden sm:inline">End-to-End Encrypted</span>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto vx-scrollbar px-5 py-4 space-y-3">
        {chat.messages.map((m) => (
          <MessageBubble key={m.id} message={m} />
        ))}
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="shrink-0 flex items-center gap-2 px-4 py-3 border-t border-white/10">
        <button type="button" className="p-2 text-white/40 hover:text-white transition-colors shrink-0">
          <Paperclip className="w-5 h-5" />
        </button>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Type a message..."
          className="flex-1 bg-black/30 border border-white/10 rounded-xl py-2.5 px-4 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
        />
        <button
          type="submit"
          disabled={!draft.trim()}
          className="w-10 h-10 rounded-xl bg-fluid-peach/90 hover:bg-fluid-peach disabled:opacity-30 disabled:cursor-not-allowed text-black flex items-center justify-center shrink-0 transition-colors"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
}
