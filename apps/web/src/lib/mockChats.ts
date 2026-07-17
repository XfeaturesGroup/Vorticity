// Mock chat data for the Phase 4 UI pass. Contacts are shown by pseudonymous @alias (docs/03 §8
// Public Aliases), never a real name — matching Vorticity's own identity model, not an arbitrary
// styling choice. Real data will come from ConvLogDO's op-log (docs/06 Phase 3) once wired.
export interface ChatMessage {
  id: string;
  senderId: "me" | "them";
  text: string;
  timestamp: string;
}

export interface Chat {
  id: string;
  alias: string;
  initials: string;
  online: boolean;
  lastMessage: string;
  lastMessageAt: string;
  unreadCount: number;
  messages: ChatMessage[];
}

export function formatNow(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export const INITIAL_CHATS: Chat[] = [
  {
    id: "chat-1",
    alias: "@nightowl_42",
    initials: "N4",
    online: true,
    unreadCount: 2,
    lastMessage: "yeah, sent it through the usual queue",
    lastMessageAt: "10:24 AM",
    messages: [
      { id: "m1", senderId: "them", text: "hey, you around?", timestamp: "10:11 AM" },
      { id: "m2", senderId: "me", text: "yep, what's up", timestamp: "10:13 AM" },
      { id: "m3", senderId: "them", text: "can you resend those notes from yesterday", timestamp: "10:15 AM" },
      { id: "m4", senderId: "me", text: "sure, one sec", timestamp: "10:20 AM" },
      { id: "m5", senderId: "them", text: "yeah, sent it through the usual queue", timestamp: "10:24 AM" },
    ],
  },
  {
    id: "chat-2",
    alias: "@cipher_relay",
    initials: "CR",
    online: false,
    unreadCount: 0,
    lastMessage: "appreciate you double-checking that",
    lastMessageAt: "Yesterday",
    messages: [
      { id: "m1", senderId: "me", text: "hey, quick one — did that file come through okay?", timestamp: "6:02 PM" },
      { id: "m2", senderId: "them", text: "yep, checksum matched on my end", timestamp: "6:10 PM" },
      { id: "m3", senderId: "me", text: "nice, wasn't sure if the connection dropped mid-transfer", timestamp: "6:11 PM" },
      { id: "m4", senderId: "them", text: "appreciate you double-checking that", timestamp: "6:15 PM" },
    ],
  },
  {
    id: "chat-3",
    alias: "@ghost_paper",
    initials: "GP",
    online: true,
    unreadCount: 0,
    lastMessage: "haha fair enough",
    lastMessageAt: "9:48 AM",
    messages: [
      { id: "m1", senderId: "them", text: "how's the new setup treating you", timestamp: "9:30 AM" },
      { id: "m2", senderId: "me", text: "honestly kind of nice not worrying about who's reading this", timestamp: "9:41 AM" },
      { id: "m3", senderId: "them", text: "low bar but sure, i'll take it", timestamp: "9:45 AM" },
      { id: "m4", senderId: "me", text: "haha fair enough", timestamp: "9:48 AM" },
    ],
  },
  {
    id: "chat-4",
    alias: "@zero_trace",
    initials: "ZT",
    online: false,
    unreadCount: 5,
    lastMessage: "let's finalize the plan tomorrow",
    lastMessageAt: "Mon",
    messages: [
      { id: "m1", senderId: "them", text: "still on for the call this week?", timestamp: "Mon 3:02 PM" },
      { id: "m2", senderId: "me", text: "yeah should work, i'll ping you the details", timestamp: "Mon 3:20 PM" },
      { id: "m3", senderId: "them", text: "sounds good, no rush", timestamp: "Mon 3:22 PM" },
      { id: "m4", senderId: "them", text: "just don't forget like last time lol", timestamp: "Mon 3:23 PM" },
      { id: "m5", senderId: "them", text: "let's finalize the plan tomorrow", timestamp: "Mon 4:01 PM" },
    ],
  },
];
