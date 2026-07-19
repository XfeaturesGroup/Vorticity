// Dedicated Web Worker for Hashcash mining (docs/03 §8.3, "alias contact establishment" pass,
// 2026-07). `packages/vortic-core`'s `pow_mint` is a real synchronous Rust/WASM loop — fast
// (native-speed, not the async-`crypto.subtle.digest`-per-iteration approach that would be far too
// slow at the required 18-26 bit difficulties, see pow.rs's module doc) but still genuinely
// blocking for however long it runs (up to several seconds at the top of docs/03's range, e.g.
// register's 24-26 bits). Running it on the main thread would freeze the whole UI for that
// duration — a real, avoidable UX regression for what's otherwise a rare, one-time-per-action
// click. This worker exists solely to keep that block off the main thread; it has no other state.
import { initCrypto, powMint } from "@vorticity/vortic-core";

export interface MineRequest {
  requestId: string;
  resource: string;
  minBits: number;
  epoch: number;
  salt: string;
}
export type MineResponse = { requestId: string; stamp: string } | { requestId: string; error: string };

self.onmessage = async (event: MessageEvent<MineRequest>) => {
  const { requestId, resource, minBits, epoch, salt } = event.data;
  try {
    await initCrypto();
    const stamp = powMint(resource, minBits, epoch, salt);
    (self as unknown as Worker).postMessage({ requestId, stamp } satisfies MineResponse);
  } catch (err) {
    (self as unknown as Worker).postMessage({ requestId, error: (err as Error).message } satisfies MineResponse);
  }
};
