// Sharding key: contact-scoped. Ephemeral, opt-in, sealed presence/typing signals.
// See docs/04 DO catalog + docs/05 (must-have "Presence" — off by default, metadata hygiene).
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

export class PresenceDO extends DurableObject<Env> {
  override async fetch(_request: Request): Promise<Response> {
    // TODO(Phase 3): opt-in only; never persisted; sealed like any other envelope.
    return new Response("PresenceDO: not implemented (Phase 3)", { status: 501 });
  }
}
