// Structure copied 1:1 from Xfeatures HQ's src/components/hq/Sidebar.tsx (nav-group shape,
// classNames, active-state treatment, bottom identity card) — see docs/07-ui-design-system.md.
// Simplified content only: Vorticity has no permissions store yet, and no real session/auth
// wiring in apps/web until Phase 4's enrollment flow lands, so the identity card is a neutral
// placeholder rather than a real user record — fittingly, since the whole point of this app is
// that the server (and this sidebar) never holds a real identity to show.
import { NavLink } from "react-router-dom";
import { Shield, MessageSquare, Settings, LogOut } from "lucide-react";
import { cn } from "@vorticity/ui";

type NavItem = {
  path: string;
  label: string;
  icon: typeof Shield;
  exact?: boolean;
};

type NavGroup = {
  label: string;
  items: NavItem[];
};

// Note: no "/" entry here — the Security Gate at "/" is a pre-auth standalone screen, not part of
// this post-auth shell (see pages/SecurityGate.tsx and App.tsx's routing split).
const navGroups: NavGroup[] = [
  {
    label: "Messenger",
    items: [{ path: "/chats", label: "Chats", icon: MessageSquare, exact: true }],
  },
  {
    label: "Workspace",
    items: [{ path: "/settings", label: "Settings", icon: Settings }],
  },
];

export function Sidebar() {
  const handleEndSession = () => {
    // TODO(Phase 4): wire to the real enrollment/session flow once it exists in apps/web.
    console.log("End session — no real auth wired into apps/web yet (Phase 4).");
  };

  return (
    <div className="w-64 bg-black flex flex-col h-full shrink-0 overflow-y-auto vx-scrollbar border-r border-white/5">
      <div className="p-6 flex items-center gap-3 shrink-0 mb-2">
        <Shield className="w-7 h-7 text-fluid-peach" />
        <span className="font-serif text-lg tracking-tight text-white">Vorticity</span>
      </div>

      <div className="flex-1 px-4 py-2 space-y-6">
        {navGroups.map((group) => (
          <div key={group.label} className="flex flex-col gap-1">
            <span className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-3 mb-2 font-sans">
              {group.label}
            </span>
            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.exact ?? false}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 px-3 py-2 rounded-xl transition-all duration-200",
                    isActive ? "bg-white/10 text-white shadow-edge-lit" : "text-white/60 hover:text-white hover:bg-white/5",
                  )
                }
              >
                <item.icon className="w-4 h-4" />
                <span className="font-medium text-sm font-sans">{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      <div className="p-4 mt-auto">
        <div className="vx-glass-dimmable rounded-2xl p-4 shadow-glass border border-white/5 flex flex-col gap-4">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-10 h-10 rounded-full bg-fluid-peach/20 flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-fluid-peach" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-medium text-white truncate">Local Device</span>
              <span className="text-xs text-white/50 truncate">no identity held by design</span>
            </div>
          </div>
          <button
            onClick={handleEndSession}
            className="flex items-center justify-center gap-2 w-full py-2 rounded-xl bg-white/5 hover:bg-red-500/20 hover:text-red-400 text-white/70 transition-colors text-sm font-medium"
          >
            <LogOut className="w-4 h-4" />
            End Session
          </button>
        </div>
      </div>
    </div>
  );
}
