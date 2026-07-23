// Phase D reorg (2026-07), Security/Contacts later promoted to their own top-level nav tabs
// (2026-07 redesign pass — see Security.tsx/Contacts.tsx): Settings itself now just holds
// Notifications (purely local: browser permission + sound toggle, no server concept at all) and
// Danger Zone (clear all local data — fitting for a paranoid-security product where per-chat delete
// already existed but a full local wipe didn't). Deliberately NOT adding a server-held "profile"
// section — that would cut against the zero-knowledge identity model this whole app is built on
// (see docs/02's threat model).
import { useState } from "react";
import { AlertTriangle, Bell, BellOff, Loader2, Shield, Volume2, VolumeX } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../contexts/ToastContext";
import { clearEntireVault } from "../lib/secureStore";

const SOUND_PREF_KEY = "vorticity-notif-sound";

function SectionHeading({ icon: Icon, title }: { icon: typeof Shield; title: string }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <Icon className="w-4 h-4 text-white/40" />
      <h2 className="text-lg font-semibold text-white">{title}</h2>
    </div>
  );
}

function NotificationsSection() {
  const [permission, setPermission] = useState<NotificationPermission>(
    typeof Notification !== "undefined" ? Notification.permission : "denied",
  );
  const [soundEnabled, setSoundEnabled] = useState(() => localStorage.getItem(SOUND_PREF_KEY) !== "off");
  const [requesting, setRequesting] = useState(false);

  const requestPermission = async () => {
    if (typeof Notification === "undefined" || requesting) return;
    setRequesting(true);
    try {
      const result = await Notification.requestPermission();
      setPermission(result);
    } finally {
      setRequesting(false);
    }
  };

  const toggleSound = () => {
    setSoundEnabled((prev) => {
      const next = !prev;
      localStorage.setItem(SOUND_PREF_KEY, next ? "on" : "off");
      return next;
    });
  };

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 divide-y divide-white/10">
      <div className="flex items-center gap-4 p-4">
        <div className="w-10 h-10 rounded-xl bg-fluid-peach/15 flex items-center justify-center shrink-0">
          {permission === "granted" ? <Bell className="w-5 h-5 text-fluid-peach" /> : <BellOff className="w-5 h-5 text-white/40" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white">Desktop notifications</div>
          <div className="text-xs text-white/50">
            {permission === "granted" ? "Enabled — new messages can show a system notification" : "Not enabled for this browser"}
          </div>
        </div>
        {permission !== "granted" && (
          <button
            type="button"
            onClick={() => void requestPermission()}
            disabled={requesting || permission === "denied"}
            title={permission === "denied" ? "Blocked at the browser level — re-enable it in your browser's site settings" : undefined}
            className="shrink-0 px-3 py-1.5 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors disabled:opacity-40 flex items-center gap-1.5"
          >
            {requesting && <Loader2 className="w-3 h-3 animate-spin" />}
            {permission === "denied" ? "Blocked" : "Enable"}
          </button>
        )}
      </div>
      <div className="flex items-center gap-4 p-4">
        <div className="w-10 h-10 rounded-xl bg-fluid-peach/15 flex items-center justify-center shrink-0">
          {soundEnabled ? <Volume2 className="w-5 h-5 text-fluid-peach" /> : <VolumeX className="w-5 h-5 text-white/40" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white">Notification sound</div>
          <div className="text-xs text-white/50">Purely local — never sent anywhere</div>
        </div>
        <button
          type="button"
          onClick={toggleSound}
          className={
            "shrink-0 relative w-11 h-6 rounded-full transition-colors " + (soundEnabled ? "bg-fluid-peach" : "bg-white/10")
          }
        >
          <span
            className={
              "absolute top-0.5 w-5 h-5 rounded-full bg-black transition-transform " + (soundEnabled ? "translate-x-[22px]" : "translate-x-0.5")
            }
          />
        </button>
      </div>
    </div>
  );
}

function DangerZoneSection() {
  const { logout } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [clearing, setClearing] = useState(false);

  const handleClearAll = async () => {
    if (
      !window.confirm(
        "Clear ALL local data? This permanently deletes every chat, message, and cryptographic identity stored on this device. " +
          "It cannot be undone, and this device will not be able to decrypt past messages afterward.",
      )
    ) {
      return;
    }
    setClearing(true);
    try {
      await clearEntireVault();
      logout();
      showToast("All local data cleared", "success");
      navigate("/", { replace: true });
    } catch (err) {
      showToast(`Failed to clear local data: ${(err as Error).message}`, "error");
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="rounded-2xl border border-signal-danger/20 bg-signal-danger/5 p-4 flex items-center gap-4">
      <div className="w-10 h-10 rounded-xl bg-signal-danger/15 flex items-center justify-center shrink-0">
        <AlertTriangle className="w-5 h-5 text-signal-danger" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-white">Clear all local data</div>
        <div className="text-xs text-white/50">Wipes every chat, message, and identity key on this device. Cannot be undone.</div>
      </div>
      <button
        type="button"
        onClick={() => void handleClearAll()}
        disabled={clearing}
        className="shrink-0 px-3 py-1.5 text-xs rounded-lg bg-signal-danger/90 hover:bg-signal-danger text-black transition-colors disabled:opacity-40 flex items-center gap-1.5"
      >
        {clearing && <Loader2 className="w-3 h-3 animate-spin" />}
        Clear everything
      </button>
    </div>
  );
}

export function Settings() {
  return (
    <div className="space-y-10 pb-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white font-sans">Settings</h1>
      </div>

      <section>
        <SectionHeading icon={Bell} title="Notifications" />
        <NotificationsSection />
      </section>

      <section>
        <SectionHeading icon={AlertTriangle} title="Danger Zone" />
        <DangerZoneSection />
      </section>
    </div>
  );
}
