import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { motion } from "framer-motion";
import { AlertCircle, Check, CheckCheck, Clock, Copy, File as FileIcon, Pencil, Reply, SmilePlus, Trash2 } from "lucide-react";
import { cn } from "@vorticity/ui";
import type { AttachmentMeta, ChatMessage } from "../../lib/chat";
import { useAuth } from "../../contexts/AuthContext";
import { formatBytes, getAttachmentObjectUrl } from "../../lib/media";
import { EmojiPicker } from "./EmojiPicker";
import { MediaLightbox } from "./MediaLightbox";
import { ContextMenu, type ContextMenuItem } from "./ContextMenu";

interface MessageBubbleProps {
  message: ChatMessage;
  /** Resolved target of `message.replyTo` — `undefined` if this isn't a reply, `null` if the id no
   * longer resolves to anything (the target was deleted — deleted messages are fully removed, not
   * tombstoned, so this is the normal/expected way a reply-to-a-deleted-message renders). */
  replyToMessage?: ChatMessage | null | undefined;
  /** Briefly true right after jumping here from a reply-preview click — a quick highlight flash so the
   * user can actually find the message that scrolled into view. */
  isHighlighted?: boolean;
  onReply: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
  onReact: (id: string, emoji: string | null) => void;
  onJumpToMessage: (id: string) => void;
}

const STATUS_ICON: Record<NonNullable<ChatMessage["status"]>, ReactNode> = {
  sending: <Clock className="w-3 h-3 text-white/30" />,
  sent: <Check className="w-3.5 h-3.5 text-white/40" />,
  delivered: <CheckCheck className="w-3.5 h-3.5 text-white/40" />,
  read: <CheckCheck className="w-3.5 h-3.5 text-signal-info" />,
  failed: <AlertCircle className="w-3.5 h-3.5 text-signal-danger" />,
};

export function MessageBubble({ message, replyToMessage, isHighlighted, onReply, onEdit, onDelete, onReact, onJumpToMessage }: MessageBubbleProps) {
  const [pickerOpen, setPickerOpen] = useState(false);
  const [lightbox, setLightbox] = useState<{ src: string; alt: string } | null>(null);
  const [menuPos, setMenuPos] = useState<{ x: number; y: number } | null>(null);
  const isMine = message.senderId === "me";
  const reactions = Object.entries(message.reactions ?? {}).filter(([, who]) => who && who.length > 0);

  // Deleted messages are removed from the chat's message array entirely (see chatReducer.ts) rather
  // than tombstoned — this defensive branch just guards against ever rendering a stray one if some
  // code path somehow misses that.
  if (message.deleted) return null;

  const handlePick = (emoji: string) => {
    const mine = message.reactions?.[emoji]?.includes("me");
    onReact(message.id, mine ? null : emoji);
    setPickerOpen(false);
  };

  const handleContextMenu = (e: MouseEvent) => {
    e.preventDefault();
    setMenuPos({ x: e.clientX, y: e.clientY });
  };

  const menuItems: ContextMenuItem[] = [
    { label: "Reply", icon: <Reply className="w-4 h-4" />, onClick: () => onReply(message.id) },
    ...(isMine
      ? [
          { label: "Edit", icon: <Pencil className="w-4 h-4" />, onClick: () => onEdit(message.id) },
          { label: "Delete", icon: <Trash2 className="w-4 h-4" />, onClick: () => onDelete(message.id), danger: true },
        ]
      : []),
    ...(message.text ? [{ label: "Copy", icon: <Copy className="w-4 h-4" />, onClick: () => void navigator.clipboard?.writeText(message.text) }] : []),
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 500, damping: 35 }}
      className={cn("group flex", isMine ? "justify-end" : "justify-start")}
      id={`msg-${message.id}`}
    >
      <div className="relative max-w-[70%]" onContextMenu={handleContextMenu}>
        {/* Hover micro-toolbar — absolutely positioned outside the bubble so it never reserves
            layout space (the old always-in-flow toolbar row was what pushed bubbles toward center). */}
        <div
          className={cn(
            "absolute top-1 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity z-10",
            isMine ? "right-full mr-1.5" : "left-full ml-1.5",
          )}
        >
          <MiniButton icon={<SmilePlus className="w-3.5 h-3.5" />} title="React" onClick={() => setPickerOpen((v) => !v)} />
          <MiniButton icon={<Reply className="w-3.5 h-3.5" />} title="Reply" onClick={() => onReply(message.id)} />
        </div>

        {pickerOpen && (
          <div className={cn("absolute z-20 bottom-full mb-1", isMine ? "right-0" : "left-0")}>
            <EmojiPicker onPick={handlePick} onClose={() => setPickerOpen(false)} />
          </div>
        )}
        {menuPos && (
          <ContextMenu x={menuPos.x} y={menuPos.y} items={menuItems} onClose={() => setMenuPos(null)} />
        )}

        <div
          className={cn(
            "rounded-2xl px-4 py-3 border text-sm transition-shadow",
            isMine ? "bg-fluid-peach/10 border-fluid-peach/20 text-white" : "bg-white/5 border-white/10 text-white/90",
            isHighlighted && "ring-2 ring-fluid-peach/60",
          )}
        >
          {message.replyTo && (
            <button
              type="button"
              onClick={() => onJumpToMessage(message.replyTo!)}
              className="block w-full text-left mb-2 pl-2 border-l-2 border-white/20 hover:border-fluid-peach/50 transition-colors"
            >
              <span className="block text-[11px] text-white/50 truncate">
                {replyToMessage === null ? "Original message deleted" : replyToMessage ? replyToMessage.text || "Attachment" : "..."}
              </span>
            </button>
          )}
          {message.attachments && message.attachments.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-2">
              {message.attachments.map((att) => (
                <AttachmentThumb key={att.mediaId} meta={att} onOpenLightbox={(src) => setLightbox({ src, alt: att.name })} />
              ))}
            </div>
          )}
          {message.text && <p className="whitespace-pre-wrap break-words leading-relaxed">{message.text}</p>}
          <span className="flex items-center justify-end gap-1.5 mt-1.5">
            {message.edited && <span className="text-[10px] text-white/30">edited</span>}
            <span className="text-[10px] text-white/40">{message.timestamp}</span>
            {isMine && message.status && STATUS_ICON[message.status]}
          </span>
        </div>
        {reactions.length > 0 && (
          <div className={cn("flex flex-wrap gap-1 mt-1", isMine ? "justify-end" : "justify-start")}>
            {reactions.map(([emoji, who]) => (
              <button
                key={emoji}
                type="button"
                onClick={() => onReact(message.id, who!.includes("me") ? null : emoji)}
                className={cn(
                  "flex items-center gap-1 pl-1.5 pr-2 py-1 rounded-full border transition-colors",
                  who!.includes("me") ? "bg-fluid-peach/15 border-fluid-peach/30" : "bg-white/5 border-white/10 hover:bg-white/10",
                )}
              >
                <span className="text-base leading-none">{emoji}</span>
                <span className="text-white/50 text-[11px] leading-none">{who!.length}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      {lightbox && <MediaLightbox src={lightbox.src} alt={lightbox.alt} onClose={() => setLightbox(null)} />}
    </motion.div>
  );
}

function AttachmentThumb({ meta, onOpenLightbox }: { meta: AttachmentMeta; onOpenLightbox: (objectUrl: string) => void }) {
  const { token: cap } = useAuth();
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const isImage = meta.mime.startsWith("image/");

  useEffect(() => {
    if (!cap) return;
    let cancelled = false;
    getAttachmentObjectUrl(meta, cap)
      .then((u) => {
        if (!cancelled) setUrl(u);
      })
      .catch((err) => {
        if (!cancelled) setError((err as Error).message);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [meta.mediaId, cap]);

  if (isImage) {
    if (error) {
      return (
        <div className="w-48 h-32 rounded-xl bg-signal-danger/10 border border-signal-danger/20 flex items-center justify-center text-[11px] text-signal-danger px-2 text-center">
          Failed to load
        </div>
      );
    }
    if (!url) return <div className="w-48 h-32 rounded-xl bg-white/5 animate-pulse" />;
    return (
      <button type="button" onClick={() => onOpenLightbox(url)} className="block max-w-[320px] rounded-xl overflow-hidden">
        <img src={url} alt={meta.name} className="w-full h-auto max-h-96 object-cover" />
      </button>
    );
  }

  return (
    <a
      href={url ?? undefined}
      download={meta.name}
      onClick={(e) => {
        if (!url) e.preventDefault();
      }}
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 max-w-[240px] transition-colors",
        !url && !error && "opacity-60",
      )}
    >
      <FileIcon className="w-5 h-5 text-white/50 shrink-0" />
      <div className="min-w-0">
        <div className="text-xs text-white truncate">{meta.name}</div>
        <div className="text-[10px] text-white/40">{error ? "Failed to load" : formatBytes(meta.size)}</div>
      </div>
    </a>
  );
}

function MiniButton({ icon, title, onClick }: { icon: ReactNode; title: string; onClick: () => void }) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="p-1.5 rounded-full bg-black/60 border border-white/10 text-white/60 hover:text-white hover:bg-black/80 backdrop-blur-sm transition-colors shadow-glass"
    >
      {icon}
    </button>
  );
}
