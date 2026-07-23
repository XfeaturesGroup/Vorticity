// Promoted out of Settings.tsx into its own top-level nav tab (2026-07 redesign pass). Adding a
// contact itself still lives in ChatList.tsx's own composer (the "@" button next to search) — that
// flow is tightly wired into Chats.tsx's chat-list state (a resolved request immediately becomes a
// new chat), and duplicating it here would mean either lifting that state up or maintaining two
// copies. This page owns the one contact-related thing that ISN'T chat-list state: your own public
// alias registration.
import { AtSign } from "lucide-react";
import { AliasPanel } from "../components/AliasPanel";

export function Contacts() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white font-sans">Contacts</h1>
        <p className="text-white/50 mt-1">Manage how people can find and reach you.</p>
      </div>
      <AliasPanel />
      <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 flex items-start gap-3">
        <AtSign className="w-4 h-4 text-white/40 shrink-0 mt-0.5" />
        <p className="text-sm text-white/50">
          To add someone, open <span className="text-white/80">Chats</span> and use the <span className="text-white/80">@</span> button next
          to search — look them up by alias, or share an invite link directly.
        </p>
      </div>
    </div>
  );
}
