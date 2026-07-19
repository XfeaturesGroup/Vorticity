// Client half of DeviceLeaseDO (device-linking pass) — see
// workers/messaging/src/durable-objects/DeviceLeaseDO.ts's header comment for why this exists.
import { ohttpFetch } from "./ohttp";

const DEVICE_ID_KEY = "vorticity-device-id";

/** A random, non-secret label identifying THIS BROWSER/DEVICE for lease bookkeeping only — not
 * identity material, not capable of decrypting anything, safe in plain `localStorage` (unlike every
 * per-chat secret this project seals in lib/secureStore.ts's vault). Stable for the lifetime of this
 * browser profile; generated once, reused after that. */
export function getDeviceId(): string {
  let id = localStorage.getItem(DEVICE_ID_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(DEVICE_ID_KEY, id);
  }
  return id;
}

export interface LeaseAcquireResult {
  granted: boolean;
  holder?: string;
  expiresAt?: number;
}

export async function acquireLease(chatId: string, cap: string): Promise<LeaseAcquireResult> {
  const res = await ohttpFetch(`/device-lease/${encodeURIComponent(chatId)}/acquire`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId: getDeviceId() }),
  });
  if (res.status !== 200 && res.status !== 409) throw new Error(`lease acquire failed: HTTP ${res.status}`);
  return (await res.json()) as LeaseAcquireResult;
}

/** Best-effort — a failed release just means the lease expires on its own (DeviceLeaseDO's TTL is the
 * real safety net, not this call), so callers should not treat a release failure as fatal. */
export async function releaseLease(chatId: string, cap: string): Promise<void> {
  try {
    await ohttpFetch(`/device-lease/${encodeURIComponent(chatId)}/release`, {
      method: "POST",
      headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
      body: JSON.stringify({ deviceId: getDeviceId() }),
    });
  } catch {
    // Expiry is the real safety net — see this file's own doc comment.
  }
}
