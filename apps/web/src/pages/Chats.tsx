// Split-view messenger UI (Phase 4). Real interactive state, not static mockup: selecting a chat
// clears its unread badge, and sending a message appends it to that conversation AND updates the
// list's preview/timestamp — both driven from one `chats` array here, not two disconnected
// pieces of state. Real data source (ConvLogDO's op-log) lands later per docs/06 Phase 3; this is
// the client-side shape it'll eventually feed.
import { useCallback, useState } from "react";
import { ChatList } from "../components/chat/ChatList";
import { ActiveChatPanel } from "../components/chat/ActiveChatPanel";
import { useQueueTransport } from "../hooks/useQueueTransport";
import { INITIAL_CHATS, formatNow, type Chat, type ChatMessage } from "../lib/mockChats";

export function Chats() {
  const [chats, setChats] = useState<Chat[]>(INITIAL_CHATS);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);

  const activeChat = chats.find((c) => c.id === activeChatId) ?? null;

  // Appends a message pushed down the wire for `chatId` into that chat's history. Only the active
  // chat ever has a live socket (see useQueueTransport's scoping note), so this always targets the
  // conversation currently on screen — no unread-badge bump needed, it's already being read live.
  const handleIncoming = useCallback((chatId: string, message: ChatMessage) => {
    setChats((prev) =>
      prev.map((c) =>
        c.id === chatId
          ? { ...c, messages: [...c.messages, message], lastMessage: message.text, lastMessageAt: message.timestamp }
          : c,
      ),
    );
  }, []);

  // "initiator" default: this mock UI has no real per-user identity yet to derive a role from (real
  // queue-id/role provisioning is Flow 5/6 contact establishment, not built) — see
  // useQueueTransport.ts's header comment. A real two-party exchange needs one side on each role.
  const { status: socketStatus, sendMessage } = useQueueTransport(activeChatId, "initiator", handleIncoming);

  const handleSelect = (id: string) => {
    setActiveChatId(id);
    setChats((prev) => prev.map((c) => (c.id === id ? { ...c, unreadCount: 0 } : c)));
  };

  const handleSend = (text: string) => {
    if (!activeChatId) return;
    // Optimistic local echo (instant feedback, standard messaging UX) *and* a real send over the
    // wire — the mock endpoint won't echo it back, so without the local append the sent bubble
    // would never appear. This is a deliberate Phase 5 scoping call, not a leftover mock.
    const message: ChatMessage = { id: crypto.randomUUID(), senderId: "me", text, timestamp: formatNow() };
    setChats((prev) =>
      prev.map((c) =>
        c.id === activeChatId ? { ...c, messages: [...c.messages, message], lastMessage: text, lastMessageAt: message.timestamp } : c,
      ),
    );
    sendMessage(text);
  };

  return (
    <div className="h-full flex rounded-2xl border border-white/10 overflow-hidden vx-glass-dimmable">
      <ChatList chats={chats} activeChatId={activeChatId} onSelect={handleSelect} />
      <ActiveChatPanel chat={activeChat} socketStatus={socketStatus} onSend={handleSend} />
    </div>
  );
}
