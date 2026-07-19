import { useEffect, useRef, useState, type FormEvent } from "react";
import { Laptop, Lock, MessageSquare, Paperclip, Radio, Send } from "lucide-react";
import { cn } from "@vorticity/ui";
import type { Chat } from "../../lib/chat";
import type { SocketStatus } from "../../hooks/useQueueTransport";
import { MessageBubble } from "./MessageBubble";

interface ActiveChatPanelProps {
  chat: Chat | null;
  socketStatus: SocketStatus;
  onSend: (text: string) => void;
  /** True while the peer's presence socket reported a recent "typing" signal — decays on its own
   * (usePresence.ts), this panel just renders whatever it's currently told. */
  peerTyping: boolean;
  /** Call on every draft keystroke; usePresence.ts throttles the actual wire sends internally. */
  onTypingDraft: () => void;
  onTogglePresence: () => void;
  /** Device-linking pass (docs/06): generates a one-time code to hand this chat's full state to
   * another of the user's own devices — see lib/deviceLink.ts's header comment. */
  onLinkDevice: () => void;
  /** Whether THIS device currently holds the live-session lease — linking is only offered when true
   * (see useQueueTransport.ts's `exportRatchetState` doc comment on why exporting from a read-only
   * device would be wrong). */
  canLinkDevice: boolean;
  /** True when another of the user's own linked devices currently holds the lease — this device is
   * read-only for live send/receive until that device releases it or its lease expires. */
  leaseHeldByOther: boolean;
}

const SOCKET_STATUS_META: Record<SocketStatus, { label: string; dot: string; pulse: boolean }> = {
  connecting: { label: "Connecting...", dot: "bg-fluid-peach", pulse: true },
  online: { label: "Online", dot: "bg-signal-success", pulse: false },
  reconnecting: { label: "Reconnecting...", dot: "bg-signal-danger", pulse: true },
  offline: { label: "Offline", dot: "bg-white/30", pulse: false },
};

export function ActiveChatPanel({
  chat,
  socketStatus,
  onSend,
  peerTyping,
  onTypingDraft,
  onTogglePresence,
  onLinkDevice,
  canLinkDevice,
  leaseHeldByOther,
}: ActiveChatPanelProps) {
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
            {peerTyping ? (
              <span className="text-fluid-peach">typing...</span>
            ) : (
              <>
                <span
                  className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    SOCKET_STATUS_META[socketStatus].dot,
                    SOCKET_STATUS_META[socketStatus].pulse && "animate-pulse",
                  )}
                />
                {SOCKET_STATUS_META[socketStatus].label}
              </>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onTogglePresence}
          title={chat.presenceEnabled ? "Sharing online status — click to stop" : "Not sharing online status — click to enable"}
          className={cn(
            "flex items-center gap-1.5 shrink-0 px-2 py-1 rounded-lg text-[11px] uppercase tracking-wider transition-colors",
            chat.presenceEnabled ? "text-signal-success bg-signal-success/10" : "text-white/30 hover:text-white/50",
          )}
        >
          <Radio className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Presence {chat.presenceEnabled ? "On" : "Off"}</span>
        </button>
        <button
          type="button"
          onClick={onLinkDevice}
          disabled={!canLinkDevice}
          title={canLinkDevice ? "Link another of your own devices to this chat" : "Not available — this device doesn't hold the live-session lease"}
          className="flex items-center gap-1.5 shrink-0 px-2 py-1 rounded-lg text-[11px] uppercase tracking-wider text-white/30 hover:text-white/50 disabled:opacity-30 disabled:hover:text-white/30 transition-colors"
        >
          <Laptop className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Link Device</span>
        </button>
        <div className="flex items-center gap-1.5 text-white/40 shrink-0">
          <Lock className="w-3.5 h-3.5" />
          <span className="text-[11px] uppercase tracking-wider hidden sm:inline">End-to-End Encrypted</span>
        </div>
      </div>

      {leaseHeldByOther && (
        <div className="shrink-0 px-5 py-2 bg-signal-danger/10 border-b border-signal-danger/20 text-xs text-signal-danger">
          This chat is currently active on another linked device — read-only here until it's released.
        </div>
      )}

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
          onChange={(e) => {
            setDraft(e.target.value);
            if (e.target.value.trim()) onTypingDraft();
          }}
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
