// Membership accumulator for the ZK airlock (docs/03 §3 Semaphore v4, docs/04 DO catalog). A client
// that redeemed an Enrollment-issued RSABSSA token (see docs/03 §2, packages/vortic-core/src/
// blind_sig.rs) inserts its `commitment` here; later it proves membership in zero knowledge (via
// /auth/session) to mint a session capability, and spends a one-time `nullifier` so a single
// enrollment yields a single session (no double-spend).
//
// TWO DISTINCT NULLIFIER CONCEPTS live in this DO, do not conflate them:
//   - `issuer_token_null`: one-spend guard on the REDEMPTION TOKEN itself (H(msg) of the RSABSSA
//     message) — enforced here in `/insert`, so the SAME signed token cannot mint two commitments.
//   - `nullifiers`: the Semaphore ZK SESSION nullifier (Flow 2, `/auth/session`) — one anonymous
//     session per member per epoch. Different flow, different data, deliberately not reused.
//
// SCOPE (Phase 2 pass): this stores commitments and computes a REAL-but-mock root — the running
// SHA-256 over the ordered commitment list, not yet a Lean Incremental Merkle Tree with Poseidon
// (that's the remaining Semaphore-circuit work in docs/06). It is authoritative, deterministic, and
// deduplicating, which is enough to wire Flow 1 + Flow 2 end to end. The nullifier sets are real and
// enforce one-spend semantics. Single global instance for now (addressed by "global"), like AliasDO.
//
// D1 MIRRORING NOTE: docs/04 describes DB_MSG as the "durable mirror" of this DO's authoritative
// state, and `issuer_token_null` is documented there too (see migrations/0002_issuer_token_null.sql)
// so schema-lint scans it and the schema stays honestly documented — but, consistent with this DO's
// EXISTING `commitments`/`nullifiers` tables (which were never actually mirrored to D1 either), the
// live enforcement path is this DO's own SQLite, not a D1 round-trip. Wiring real D1 mirroring is
// pre-existing, not-yet-done work for all of this DO's tables, not something new introduced here.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

const HEX64_RE = /^[0-9a-f]{64}$/; // a 32-byte value, lowercase hex

interface CommitmentRow {
  commitment: string;
  [key: string]: SqlStorageValue;
}
interface CountRow {
  n: number;
  [key: string]: SqlStorageValue;
}
interface TokenNullRow {
  token_null: string;
  [key: string]: SqlStorageValue;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class MerkleTreeDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS commitments (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        commitment TEXT UNIQUE NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS nullifiers (
        nullifier TEXT PRIMARY KEY,
        spent_at  INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS issuer_token_null (
        token_null TEXT PRIMARY KEY,
        spent_at   INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/insert") return this.handleInsert(request);
    if (request.method === "POST" && url.pathname === "/nullifier/spend") return this.handleSpend(request);
    if (request.method === "GET" && url.pathname === "/root") {
      return Response.json({ merkleRoot: await this.computeRoot() });
    }
    return new Response("Not found", { status: 404 });
  }

  // Deterministic mock root: SHA-256 over every commitment in insertion order, domain-separated.
  // Real Semaphore uses a Lean IMT with Poseidon — tracked in docs/06.
  private async computeRoot(): Promise<string> {
    const rows = this.ctx.storage.sql
      .exec<CommitmentRow>("SELECT commitment FROM commitments ORDER BY seq")
      .toArray();
    return sha256Hex("vortic-merkle-v1" + rows.map((r) => r.commitment).join(""));
  }

  private async handleInsert(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const commitment = (body as { commitment?: unknown }).commitment;
    const tokenNull = (body as { tokenNull?: unknown }).tokenNull;
    if (typeof commitment !== "string" || !HEX64_RE.test(commitment)) {
      return new Response("commitment must be a 64-char lowercase hex (32-byte) value", { status: 400 });
    }
    if (typeof tokenNull !== "string" || !HEX64_RE.test(tokenNull)) {
      return new Response("tokenNull must be a 64-char lowercase hex (32-byte) value", { status: 400 });
    }

    // The caller (index.ts's /membership/insert) has already verified the RSABSSA signature over the
    // message this tokenNull is derived from (H(msg)) BEFORE forwarding here — this DO enforces the
    // one-spend guard on that already-verified token, so the same signed redemption token can never
    // insert twice. Checked before the commitment insert, matching "verify -> check nullifier ->
    // insert" ordering (docs/04 Flow 1) — mirrors the existing /auth/session -> nullifier/spend order.
    const existingToken = this.ctx.storage.sql
      .exec<TokenNullRow>("SELECT token_null FROM issuer_token_null WHERE token_null = ?", tokenNull)
      .toArray();
    if (existingToken.length > 0) {
      return new Response("redemption token already spent (replay)", { status: 409 });
    }
    this.ctx.storage.sql.exec("INSERT INTO issuer_token_null (token_null, spent_at) VALUES (?, ?)", tokenNull, Date.now());

    // Idempotent: re-inserting an existing commitment is a no-op (INSERT OR IGNORE), so a retried
    // request doesn't grow the tree or change the root. (The tokenNull check above already prevents a
    // single token from being redeemed twice; this guards the separate case of the same commitment
    // bytes colliding, which INSERT OR IGNORE handles safely either way.)
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO commitments (commitment, created_at) VALUES (?, ?)",
      commitment,
      Date.now(),
    );
    const { n } = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM commitments").one();
    return Response.json({ merkleRoot: await this.computeRoot(), size: n });
  }

  private async handleSpend(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const nullifier = (body as { nullifier?: unknown }).nullifier;
    if (typeof nullifier !== "string" || !HEX64_RE.test(nullifier)) {
      return new Response("nullifier must be a 64-char lowercase hex (32-byte) value", { status: 400 });
    }

    const existing = this.ctx.storage.sql
      .exec<{ nullifier: string; [key: string]: SqlStorageValue }>(
        "SELECT nullifier FROM nullifiers WHERE nullifier = ?",
        nullifier,
      )
      .toArray();
    if (existing.length > 0) {
      return new Response("nullifier already spent (replay)", { status: 409 });
    }
    this.ctx.storage.sql.exec("INSERT INTO nullifiers (nullifier, spent_at) VALUES (?, ?)", nullifier, Date.now());
    return Response.json({ ok: true });
  }
}
