import { Outlet } from "react-router-dom";
import { NoiseOverlay } from "@vorticity/ui";
import { Sidebar } from "./Sidebar";

export function AppLayout() {
  return (
    <div className="relative flex h-screen bg-black overflow-hidden">
      <NoiseOverlay className="z-50" />
      <Sidebar />
      <main className="flex-1 overflow-y-auto vx-scrollbar">
        {/* h-full here (not just the parent's implicit height) is what lets a page like Chats
            fill exactly the available viewport and manage its OWN internal split-panel scrolling
            instead of the page itself scrolling. Pages with normal (possibly overflowing) content
            — Settings, the gate — are unaffected: this div doesn't clip, so taller content still
            bubbles up to this <main>'s own overflow-y-auto for a regular page scroll. */}
        <div className="h-full max-w-7xl mx-auto p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
