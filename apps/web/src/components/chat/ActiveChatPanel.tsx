import { useEffect, useMemo, useRef, useState, type ClipboardEvent, type DragEvent, type FormEvent } from "react";
import { motion } from "framer-motion";
import { ArrowDown, ChevronLeft, File as FileIcon, Laptop, Loader2, Lock, MessageSquare, Paperclip, Radio, Send, X } from "lucide-react";
import { cn } from "@vorticity/ui";
import { formatDayLabel, type AttachmentMeta, type Chat, type ChatMessage } from "../../lib/chat";
import type { SocketStatus } from "../../hooks/useQueueTransport";
import { useAuth } from "../../contexts/AuthContext";
import { formatBytes, MEDIA_MAX_BYTES, uploadAttachment } from "../../lib/media";
import { MessageBubble } from "./MessageBubble";
import { ReplyPreview } from "./ReplyPreview";

interface PendingAttachment {
  localId: string;
  file: File;
  previewUrl?: string | undefined;
  status: "uploading" | "ready" | "error";
  meta?: AttachmentMeta;
  error?: string;
}

interface ActiveChatPanelProps {
  chat: Chat | null;
  socketStatus: SocketStatus;
  onSend: (text: string, opts?: { replyTo?: string; attachments?: AttachmentMeta[] }) => void;
  onEditMessage: (targetId: string, text: string) => void;
  onDeleteMessage: (targetId: string) => void;
  onReact: (targetId: string, emoji: string | null) => void;
  /** Mobile-only (below `md`) back button in the header — returns to the chat list. Desktop always
   * shows both panes side by side, so this has nothing to do there (button is `md:hidden`). */
  onBack: () => void;
  /** Id of the first message that was still unread when this chat was opened — renders a "New
   * messages" divider just above it. `null`/`undefined` renders nothing (nothing was unread, or this
   * chat has never been opened this session yet). Recomputed by Chats.tsx on every `onSelect`. */
  unreadDividerMessageId?: string | null;
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

// Below this many px from the bottom, treat the user as "reading history" — new arrivals shouldn't
// yank their scroll position, and the floating scroll-to-bottom button should appear.
const NEAR_BOTTOM_PX = 120;

export function ActiveChatPanel({
  chat,
  socketStatus,
  onSend,
  onEditMessage,
  onDeleteMessage,
  onReact,
  onBack,
  unreadDividerMessageId,
  peerTyping,
  onTypingDraft,
  onTogglePresence,
  onLinkDevice,
  canLinkDevice,
  leaseHeldByOther,
}: ActiveChatPanelProps) {
  const { token: cap } = useAuth();
  const [draft, setDraft] = useState("");
  const [replyTarget, setReplyTarget] = useState<ChatMessage | null>(null);
  const [editTarget, setEditTarget] = useState<ChatMessage | null>(null);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [pendingAttachments, setPendingAttachments] = useState<PendingAttachment[]>([]);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const messagesById = useMemo(() => {
    const map = new Map<string, ChatMessage>();
    chat?.messages.forEach((m) => map.set(m.id, m));
    return map;
  }, [chat?.messages]);

  // Reset in-progress composer state on chat switch — a reply/edit target (or a not-yet-sent
  // attachment) from a different conversation makes no sense to carry over.
  useEffect(() => {
    setDraft("");
    setReplyTarget(null);
    setEditTarget(null);
    setPendingAttachments((prev) => {
      prev.forEach((a) => a.previewUrl && URL.revokeObjectURL(a.previewUrl));
      return [];
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chat?.id]);

  const isNearBottom = () => {
    const el = scrollRef.current;
    if (!el) return true;
    return el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
  };

  const scrollToBottom = (behavior: ScrollBehavior = "smooth") => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior });
  };

  useEffect(() => {
    if (isNearBottom()) {
      scrollToBottom(chat?.messages.length ? "smooth" : "auto");
      setShowScrollButton(false);
    } else {
      setShowScrollButton(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chat?.id, chat?.messages.length]);

  useEffect(() => {
    return () => {
      if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    };
  }, []);

  const handleJumpToMessage = (id: string) => {
    scrollRef.current?.querySelector<HTMLElement>(`#msg-${id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    setHighlightId(id);
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => setHighlightId(null), 1600);
  };

  const handleReplyRequest = (id: string) => {
    const target = messagesById.get(id);
    if (!target) return;
    setEditTarget(null);
    setReplyTarget(target);
  };

  const handleEditRequest = (id: string) => {
    const target = messagesById.get(id);
    if (!target) return;
    setReplyTarget(null);
    setEditTarget(target);
    setDraft(target.text);
  };

  // Attaches each file immediately (encrypt + upload starts right away, not deferred to send-time)
  // so by the time the user hits Send, most/all attachments already have a real `mediaId`/`key` —
  // matches `MEDIA_MAX_BYTES` enforced server-side in `coreMediaPut`.
  const handleFiles = (files: FileList | File[]) => {
    if (!cap) return;
    for (const file of Array.from(files)) {
      const localId = crypto.randomUUID();
      const previewUrl = file.type.startsWith("image/") ? URL.createObjectURL(file) : undefined;
      setPendingAttachments((prev) => [...prev, { localId, file, previewUrl, status: "uploading" }]);
      uploadAttachment(file, cap)
        .then((meta) => {
          setPendingAttachments((prev) => prev.map((a) => (a.localId === localId ? { ...a, status: "ready", meta } : a)));
        })
        .catch((err) => {
          setPendingAttachments((prev) => prev.map((a) => (a.localId === localId ? { ...a, status: "error", error: (err as Error).message } : a)));
        });
    }
  };

  const removeAttachment = (localId: string) => {
    setPendingAttachments((prev) => {
      const target = prev.find((a) => a.localId === localId);
      if (target?.previewUrl) URL.revokeObjectURL(target.previewUrl);
      return prev.filter((a) => a.localId !== localId);
    });
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const files = Array.from(e.clipboardData.items)
      .filter((item) => item.kind === "file")
      .map((item) => item.getAsFile())
      .filter((f): f is File => f !== null);
    if (files.length > 0) handleFiles(files);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingFile(false);
    if (e.dataTransfer.files.length > 0) handleFiles(e.dataTransfer.files);
  };

  if (!chat) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.25 }}
        className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30"
      >
        <MessageSquare className="w-12 h-12" />
        <p className="text-sm">Select a chat to start messaging</p>
      </motion.div>
    );
  }

  const readyAttachments = pendingAttachments.filter((a): a is PendingAttachment & { meta: AttachmentMeta } => a.status === "ready" && !!a.meta);
  const hasUploading = pendingAttachments.some((a) => a.status === "uploading");
  const trimmedDraft = draft.trim();
  const canSubmit = !editTarget ? (trimmedDraft.length > 0 || readyAttachments.length > 0) && !hasUploading : trimmedDraft.length > 0;

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    if (editTarget) {
      onEditMessage(editTarget.id, trimmedDraft);
      setEditTarget(null);
    } else {
      onSend(trimmedDraft, {
        ...(replyTarget ? { replyTo: replyTarget.id } : {}),
        ...(readyAttachments.length > 0 ? { attachments: readyAttachments.map((a) => a.meta) } : {}),
      });
      setReplyTarget(null);
      setPendingAttachments([]);
    }
    setDraft("");
  };

  const cancelComposerContext = () => {
    setReplyTarget(null);
    setEditTarget(null);
    setDraft("");
  };

  return (
    <div
      className="relative flex-1 flex flex-col h-full min-h-0 min-w-0"
      onDragOver={(e) => {
        e.preventDefault();
        setIsDraggingFile(true);
      }}
      onDragLeave={() => setIsDraggingFile(false)}
      onDrop={handleDrop}
    >
      {isDraggingFile && (
        <div className="absolute inset-0 z-20 bg-fluid-peach/10 border-2 border-dashed border-fluid-peach/50 flex items-center justify-center pointer-events-none">
          <span className="text-sm text-fluid-peach font-medium">Drop to attach</span>
        </div>
      )}
      {/* Header */}
      <div className="shrink-0 flex items-center gap-3 px-5 py-4 border-b border-white/10">
        <button
          type="button"
          onClick={onBack}
          title="Back to chat list"
          className="md:hidden shrink-0 p-1 -ml-1 rounded-lg text-white/60 hover:text-white hover:bg-white/10 transition-colors"
        >
          <ChevronLeft className="w-5 h-5" />
        </button>
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
      <div className="relative flex-1 min-h-0">
        <div
          ref={scrollRef}
          onScroll={() => setShowScrollButton(!isNearBottom())}
          className="h-full overflow-y-auto vx-scrollbar px-5 py-4"
        >
          {chat.messages.map((m, i) => {
            const prev = chat.messages[i - 1];
            const showDateSeparator = Boolean(m.dateKey) && prev?.dateKey !== m.dateKey;
            const showUnreadDivider = unreadDividerMessageId === m.id;
            return (
              <div key={m.id}>
                {showDateSeparator && (
                  <div className="flex items-center justify-center py-2">
                    <span className="px-3 py-1 rounded-full bg-white/5 text-[11px] text-white/40 uppercase tracking-wider">
                      {formatDayLabel(m.dateKey!)}
                    </span>
                  </div>
                )}
                {showUnreadDivider && (
                  <div className="flex items-center gap-2 py-2">
                    <div className="flex-1 h-px bg-signal-danger/30" />
                    <span className="text-[11px] text-signal-danger uppercase tracking-wider shrink-0">New messages</span>
                    <div className="flex-1 h-px bg-signal-danger/30" />
                  </div>
                )}
                <div className="py-1">
                  <MessageBubble
                    message={m}
                    replyToMessage={m.replyTo ? messagesById.get(m.replyTo) ?? null : undefined}
                    isHighlighted={highlightId === m.id}
                    onReply={handleReplyRequest}
                    onEdit={handleEditRequest}
                    onDelete={onDeleteMessage}
                    onReact={onReact}
                    onJumpToMessage={handleJumpToMessage}
                  />
                </div>
              </div>
            );
          })}
        </div>
        {showScrollButton && (
          <button
            type="button"
            onClick={() => scrollToBottom()}
            title="Scroll to latest"
            className="absolute bottom-4 right-4 w-9 h-9 rounded-full bg-black/80 border border-white/10 flex items-center justify-center text-white/70 hover:text-white shadow-glass transition-colors"
          >
            <ArrowDown className="w-4 h-4" />
          </button>
        )}
      </div>

      {replyTarget && (
        <ReplyPreview
          label={`Replying to ${replyTarget.senderId === "me" ? "yourself" : chat.alias}`}
          text={replyTarget.text}
          onCancel={() => setReplyTarget(null)}
        />
      )}
      {editTarget && <ReplyPreview label="Editing message" text={editTarget.text} accent="info" onCancel={cancelComposerContext} />}

      {pendingAttachments.length > 0 && (
        <div className="shrink-0 flex flex-wrap gap-2 px-4 py-2 border-t border-white/10 bg-white/[0.02]">
          {pendingAttachments.map((a) => (
            <div key={a.localId} className="relative group/att">
              {a.previewUrl ? (
                <img src={a.previewUrl} alt={a.file.name} className="w-16 h-16 rounded-lg object-cover border border-white/10" />
              ) : (
                <div className="w-16 h-16 rounded-lg border border-white/10 bg-white/5 flex flex-col items-center justify-center gap-0.5 px-1">
                  <FileIcon className="w-4 h-4 text-white/50" />
                  <span className="text-[9px] text-white/40 truncate max-w-full">{formatBytes(a.file.size)}</span>
                </div>
              )}
              {a.status === "uploading" && (
                <div className="absolute inset-0 rounded-lg bg-black/50 flex items-center justify-center">
                  <Loader2 className="w-4 h-4 text-white animate-spin" />
                </div>
              )}
              {a.status === "error" && (
                <div className="absolute inset-0 rounded-lg bg-signal-danger/60 flex items-center justify-center" title={a.error}>
                  <span className="text-[9px] text-white px-1 text-center">Failed</span>
                </div>
              )}
              <button
                type="button"
                onClick={() => removeAttachment(a.localId)}
                className="absolute -top-1.5 -right-1.5 w-5 h-5 rounded-full bg-black border border-white/20 flex items-center justify-center text-white/70 hover:text-white transition-colors"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="shrink-0 flex items-center gap-2 px-4 py-3 border-t border-white/10">
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            if (e.target.files) handleFiles(e.target.files);
            e.target.value = "";
          }}
        />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          title={`Attach a file (up to ${Math.floor(MEDIA_MAX_BYTES / (1024 * 1024))} MiB)`}
          className="p-2 text-white/40 hover:text-white transition-colors shrink-0"
        >
          <Paperclip className="w-5 h-5" />
        </button>
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            if (e.target.value.trim()) onTypingDraft();
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape" && (editTarget || replyTarget)) cancelComposerContext();
          }}
          onPaste={handlePaste}
          placeholder={editTarget ? "Edit message..." : "Type a message..."}
          className="flex-1 bg-black/30 border border-white/10 rounded-xl py-2.5 px-4 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
        />
        <button
          type="submit"
          disabled={!canSubmit}
          className="w-10 h-10 rounded-xl bg-fluid-peach/90 hover:bg-fluid-peach disabled:opacity-30 disabled:cursor-not-allowed text-black flex items-center justify-center shrink-0 transition-colors"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
}
