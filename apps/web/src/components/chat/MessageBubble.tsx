import { cn } from "@vorticity/ui";
import type { ChatMessage } from "../../lib/mockChats";

export function MessageBubble({ message }: { message: ChatMessage }) {
  const isMine = message.senderId === "me";
  return (
    <div className={cn("flex", isMine ? "justify-end" : "justify-start")}>
      <div
        className={cn(
          "max-w-[70%] rounded-2xl px-4 py-2.5 border text-sm",
          isMine ? "bg-fluid-peach/10 border-fluid-peach/20 text-white" : "bg-white/5 border-white/10 text-white/90",
        )}
      >
        <p className="whitespace-pre-wrap break-words">{message.text}</p>
        <span className="block text-[10px] text-white/40 mt-1 text-right">{message.timestamp}</span>
      </div>
    </div>
  );
}
