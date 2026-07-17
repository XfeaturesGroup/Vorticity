// Sharding key: epoch bucket. Nullifier + capability issuance rate limits; also backs the
// alias plane's PoW spent-stamp set when not colocated with AliasDO. See docs/04 DO catalog.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

export class RateGateDO extends DurableObject<Env> {
  override async fetch(_request: Request): Promise<Response> {
    // TODO(Phase 2): check + record nullifier_hash for (external_nullifier, epoch); one
    // anonymous session per member per epoch. See docs/03 §3.
    return new Response("RateGateDO: not implemented (Phase 2)", { status: 501 });
  }
}
