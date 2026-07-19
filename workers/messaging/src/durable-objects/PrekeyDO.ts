// Sharding key: contact-scoped (one instance per chat id, same convention as PresenceDO — chat id is
// already the high-entropy unguessable identifier lib/inviteLink.ts generates, so no separate
// capability-worthy secret is needed to address this DO safely). Durable directory for the
// "responder" role's X3DH-style prekey bundle (docs/03 §4: "Prekey bundles published to a
// PrekeyDO/D1 include: identity key, signed prekey, one-time prekeys ... all rotated").
//
// WHY THIS EXISTS, on top of the prekey_offer envelope useQueueTransport.ts already pushes over the
// message queue: that push only reaches an initiator who is ALREADY subscribed (or picks it up from
// QueueDO's backlog) — real X3DH's whole point is a bundle a prospective initiator can fetch
// on-demand, asynchronously, even while the responder is offline. This DO is that fetchable
// directory; the queue-pushed `prekey_offer` is unchanged and still used as the fast path when both
// sides happen to be live at once (see useQueueTransport.ts's header comment for the exact split).
//
// TWO KINDS OF PREKEY, DIFFERENT LIFECYCLE:
//   - the SIGNED prekey (one row, `bundle` table): long-lived, Ed25519-signed, rotated periodically
//     by the client (age-based — see useQueueTransport.ts's ROTATE_AFTER_MS) by re-publishing.
//   - ONE-TIME prekeys (`onetime_prekeys` table, a pool): each is handed out to at most ONE fetcher,
//     ever — `popOnetime` below deletes the row in the SAME query that reads it, so two concurrent
//     fetchers can never receive the same one-time prekey (the real security property one-time
//     prekeys exist for: even a fully compromised signed-prekey private key isn't enough to recover a
//     session's root key, since the one-time leg's private key is used once and gone — see
//     packages/vortic-core/src/kem.rs's `combine_with_onetime` doc comment for the crypto side).
//     Replenished by the client (`POST /prekey/publish` again, more `onetimePubKeys`) when running low.
//
// ISOLATION: same standing as every DO in this catalog — only opaque public-key bytes and an id
// pass through here, no account/session identifier, no capability check (that already happened one
// layer up in index.ts's `requireCapability` before a request reaches this DO at all).
//
// D1 MIRRORING: not built here, same honestly-noted gap as MerkleTreeDO's own header comment —
// this DO's SQLite is the sole live-authoritative store; losing the DO loses its prekey pool, an
// accepted risk at this stage (worst case, the affected chat's next handshake attempt falls back to
// the queue-pushed prekey_offer path, or the responder simply republishes on its next mount).
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

interface BundleRow {
  verifying_key: string;
  signed_prekey_pub: string;
  signed_prekey_sig: string;
  rotated_at: number;
  [key: string]: SqlStorageValue;
}
interface OnetimeRow {
  id: string;
  pub_key: string;
  [key: string]: SqlStorageValue;
}
interface CountRow {
  n: number;
  [key: string]: SqlStorageValue;
}

export class PrekeyDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bundle (
        id                 INTEGER PRIMARY KEY CHECK (id = 0),
        verifying_key      TEXT NOT NULL,
        signed_prekey_pub  TEXT NOT NULL,
        signed_prekey_sig  TEXT NOT NULL,
        rotated_at         INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS onetime_prekeys (
        id         TEXT PRIMARY KEY,
        pub_key    TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /publish":
        return this.handlePublish(request);
      case "GET /status":
        return this.handleStatus();
      case "GET /fetch":
        return this.handleFetchAndPop();
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  // ── publish (responder: initial bundle, rotation, and/or one-time-prekey replenishment) ─────────

  private async handlePublish(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const b = body as {
      verifyingKey?: unknown;
      signedPrekeyPub?: unknown;
      signedPrekeySig?: unknown;
      onetimePubKeys?: unknown;
    };
    if (typeof b.verifyingKey !== "string" || typeof b.signedPrekeyPub !== "string" || typeof b.signedPrekeySig !== "string") {
      return new Response("verifyingKey, signedPrekeyPub, signedPrekeySig (base64) are required", { status: 400 });
    }
    const onetimePubKeys = Array.isArray(b.onetimePubKeys) ? b.onetimePubKeys.filter((x): x is string => typeof x === "string") : [];

    // A single-row "current bundle" table (CHECK id=0 enforces at most one row) — publish always
    // overwrites it. This IS the rotation mechanism: the client decides an existing bundle is stale
    // (see useQueueTransport.ts's ROTATE_AFTER_MS) and republishes with a freshly generated signed
    // prekey; there is no separate "rotate" verb.
    this.ctx.storage.sql.exec(
      `INSERT INTO bundle (id, verifying_key, signed_prekey_pub, signed_prekey_sig, rotated_at)
       VALUES (0, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         verifying_key = excluded.verifying_key,
         signed_prekey_pub = excluded.signed_prekey_pub,
         signed_prekey_sig = excluded.signed_prekey_sig,
         rotated_at = excluded.rotated_at`,
      b.verifyingKey,
      b.signedPrekeyPub,
      b.signedPrekeySig,
      Date.now(),
    );

    // Additive only — replenishment tops up the pool, it never clears what's already there. IDs are
    // caller-supplied (the client already generates a fresh id per one-time keypair it seals locally,
    // to look the matching private key back up on decapsulation) rather than DO-assigned, so the
    // client's local pool bookkeeping and this DO's pool never need a reconciliation round-trip.
    if (onetimePubKeys.length > 0) {
      const now = Date.now();
      for (const entry of onetimePubKeys) {
        const sep = entry.indexOf(":");
        if (sep < 0) continue; // malformed "id:pubkey" pair — skip rather than fail the whole publish
        const id = entry.slice(0, sep);
        const pubKey = entry.slice(sep + 1);
        this.ctx.storage.sql.exec(
          `INSERT INTO onetime_prekeys (id, pub_key, created_at) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING`,
          id,
          pubKey,
          now,
        );
      }
    }

    return Response.json({ ok: true, onetimeCount: this.onetimeCount() }, { status: 200 });
  }

  // ── status (responder: decide whether to rotate / replenish) ──────────────────────────────────

  private handleStatus(): Response {
    // `.one()` THROWS unless the result set has exactly one row (Cloudflare's documented behavior),
    // unlike QueueDO's `MIN(...)` aggregate use of it elsewhere which always returns exactly one row
    // by construction — a plain `SELECT * ... WHERE id = 0` can genuinely return zero rows (no bundle
    // published yet), so this reads via `.toArray()[0]` instead, same as every other "maybe absent"
    // lookup in this DO.
    const row = this.ctx.storage.sql.exec<BundleRow>("SELECT * FROM bundle WHERE id = 0").toArray()[0] ?? null;
    return Response.json({
      hasBundle: row !== null,
      rotatedAt: row?.rotated_at ?? null,
      onetimeCount: this.onetimeCount(),
    });
  }

  private onetimeCount(): number {
    return this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM onetime_prekeys").one().n;
  }

  // ── fetch-and-pop (initiator: get the bundle + at most one one-time prekey, atomically) ──────────

  private handleFetchAndPop(): Response {
    const bundle = this.ctx.storage.sql.exec<BundleRow>("SELECT * FROM bundle WHERE id = 0").toArray()[0] ?? null;
    if (!bundle) {
      return new Response("no prekey bundle published for this chat yet", { status: 404 });
    }

    // Pop one row atomically: a DO's SQLite calls are already serialized per-instance (no concurrent
    // JS execution within one DO), so "SELECT one, then DELETE that exact id" cannot race a second
    // fetch between the two statements the way it could across separate connections/processes — this
    // is the same single-spend guarantee MerkleTreeDO's nullifier tables rely on, just via ordinary
    // read-then-delete instead of a returning-delete, since SQLite's DELETE...RETURNING support here
    // isn't needed for correctness (nothing else can interleave).
    const onetime = this.ctx.storage.sql.exec<OnetimeRow>("SELECT * FROM onetime_prekeys ORDER BY created_at ASC LIMIT 1").toArray()[0] ?? null;
    if (onetime) {
      this.ctx.storage.sql.exec("DELETE FROM onetime_prekeys WHERE id = ?", onetime.id);
    }

    return Response.json({
      verifyingKey: bundle.verifying_key,
      signedPrekeyPub: bundle.signed_prekey_pub,
      signedPrekeySig: bundle.signed_prekey_sig,
      onetimePrekey: onetime ? { id: onetime.id, pubKey: onetime.pub_key } : null,
    });
  }
}
