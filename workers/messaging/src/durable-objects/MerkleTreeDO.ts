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
// ROOT COMPUTATION (R21, 2026-07): a REAL LeanIMT (Lean Incremental Merkle Tree) with Poseidon2,
// matching Semaphore v4's actual circuit exactly — see the real, official circom source
// (github.com/semaphore-protocol/semaphore/packages/circuits/src/semaphore.circom, `BinaryMerkleRoot`
// template) and `@zk-kit/lean-imt`'s reference TS implementation, which we use here VERBATIM (not
// re-implemented) via the official `@zk-kit/lean-imt` + `poseidon-lite` npm packages — both pure
// TS/BigInt, no native/WASM dependency, so no Rust/WASM involvement is needed for this DO at all.
// LeanIMT differs from a fixed-depth IMT: depth grows with leaf count, and a node with only one
// child takes that child's value unchanged (no zero-padding hash) — this is exactly what makes a
// REAL client-generated Semaphore proof's `merkleProofLength`/`merkleRoot` match what this DO
// computes; a fixed-depth or differently-hashed tree would never agree with the real circuit.
// Superseded the earlier SHA-256-over-the-list placeholder (see git history) — that could never have
// matched a real proof's public `merkleRoot` regardless of how correct the ZK verifier itself was.
// Rebuilds the tree from the full commitment list on every query — simple and correct at this scale;
// incrementally persisting tree state is a future optimization, not required for correctness.
// COST NOTE (R23 follow-up, 2026-07 — flagged, not fixed): `/root`, `/insert`, and the new `/proof/:commitment`
// (below) all pay this same O(n) Poseidon2-hashes-from-scratch cost per call, n = total commitment count.
// Fine at the hundreds-of-members scale this pass was built/tested against; at thousands+ members this
// rebuild-per-request pattern (now hit by proof requests too, not just insert/root) is the first place
// to look if MerkleTreeDO latency becomes a problem — the fix would be incremental/cached tree state,
// deliberately not built here since it wasn't yet a measured bottleneck. `/proof/:commitment` is
// additionally per-commitment rate-limited at the `index.ts` route level (via `RateGateDO`) precisely
// because it's unauthenticated AND pays this cost — see that route's comment.
// SCOPE (Phase 2 pass): commitments/nullifier tables are unchanged. The nullifier sets are real and
// enforce one-spend semantics. Single global instance for now (addressed by "global"), like AliasDO.
//
// D1 MIRRORING NOTE: docs/04 describes DB_MSG as the "durable mirror" of this DO's authoritative
// state, and `issuer_token_null` is documented there too (see migrations/0002_issuer_token_null.sql)
// so schema-lint scans it and the schema stays honestly documented — but, consistent with this DO's
// EXISTING `commitments`/`nullifiers` tables (which were never actually mirrored to D1 either), the
// live enforcement path is this DO's own SQLite, not a D1 round-trip. Wiring real D1 mirroring is
// pre-existing, not-yet-done work for all of this DO's tables, not something new introduced here.
import { DurableObject } from "cloudflare:workers";
import { LeanIMT } from "@zk-kit/lean-imt";
import { poseidon2 } from "poseidon-lite";
import type { Env } from "../env";

const HEX64_RE = /^[0-9a-f]{64}$/; // a 32-byte value, lowercase hex

// BN254 scalar field order (Fr) — every real leaf/root value is an element of this field. A 32-byte
// big-endian value always fits (Fr < 2^254 < 2^256), but not every 32-byte value is a VALID field
// element; reject out-of-range values defensively rather than silently accepting unreachable inputs.
const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function hexToField(hex: string): bigint {
  const n = BigInt(`0x${hex}`);
  if (n >= FR_MODULUS) throw new RangeError("value is not a valid BN254 field element (>= Fr modulus)");
  return n;
}
function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}
/// The conventional root of an empty tree — LeanIMT has no defined root with zero leaves, so this DO
/// reports this sentinel instead of constructing a tree at all (avoids `.root` being `undefined`).
const EMPTY_TREE_ROOT = "0".repeat(64);

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
      return Response.json({ merkleRoot: this.computeRoot() });
    }
    if (request.method === "GET" && url.pathname.startsWith("/proof/")) {
      return this.handleProof(url.pathname.slice("/proof/".length));
    }
    return new Response("Not found", { status: 404 });
  }

  // Real Lean IMT root over Poseidon2, matching Semaphore v4's actual circuit — see this file's
  // header comment. Rebuilt from the full commitment list each call (simple, correct; incremental
  // persistence is a future optimization).
  private computeRoot(): string {
    const rows = this.ctx.storage.sql
      .exec<CommitmentRow>("SELECT commitment FROM commitments ORDER BY seq")
      .toArray();
    if (rows.length === 0) return EMPTY_TREE_ROOT;
    const leaves = rows.map((r) => hexToField(r.commitment));
    const tree = new LeanIMT((a: bigint, b: bigint) => poseidon2([a, b]), leaves);
    return fieldToHex(tree.root as bigint);
  }

  // Real Merkle proof (siblings path + leaf index) for a given commitment — what a client needs to
  // build a real Semaphore witness for any tree, not just the trivial size===1 case (R23 follow-up,
  // 2026-07). Commitments in a Semaphore membership set are PUBLIC BY DESIGN — the protocol's whole
  // point is "prove I'm one of these known commitments without saying which one", so handing out a
  // sibling path here is expected protocol behavior, not an anonymity leak. No capability gating: this
  // is called BEFORE a session capability exists (the client needs this proof to even attempt
  // /auth/session in the first place), matching the existing openness of /root and /insert.
  // Rebuilds the tree from the full commitment list, same as `computeRoot()` — see that method's
  // comment on the cost tradeoff; this endpoint doesn't change the cost CLASS (already O(n) Poseidon2
  // hashes per call before this endpoint existed), just adds one more caller that pays it.
  private handleProof(commitment: string): Response {
    if (!HEX64_RE.test(commitment)) {
      return new Response("commitment must be a 64-char lowercase hex (32-byte) value", { status: 400 });
    }
    const rows = this.ctx.storage.sql
      .exec<CommitmentRow>("SELECT commitment FROM commitments ORDER BY seq")
      .toArray();
    const leafIndex = rows.findIndex((r) => r.commitment === commitment);
    if (leafIndex === -1) {
      return new Response("commitment not found in the membership tree", { status: 404 });
    }
    const leaves = rows.map((r) => hexToField(r.commitment));
    const tree = new LeanIMT((a: bigint, b: bigint) => poseidon2([a, b]), leaves);
    const proof = tree.generateProof(leafIndex);
    return Response.json({
      index: proof.index,
      siblings: proof.siblings.map((s) => fieldToHex(s as bigint)),
      merkleRoot: fieldToHex(tree.root as bigint),
    });
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
    // Must also be a valid BN254 field element (< Fr modulus) — the real Semaphore circuit's
    // identityCommitment is a Poseidon output over this field; an out-of-range value could never
    // have come from a real proof and would otherwise poison computeRoot() the next time it reads
    // this row back (hexToField throws on out-of-range input).
    try {
      hexToField(commitment);
    } catch {
      return new Response("commitment is not a valid BN254 field element", { status: 400 });
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
    const tokenSpentAt = Date.now();
    this.ctx.storage.sql.exec("INSERT INTO issuer_token_null (token_null, spent_at) VALUES (?, ?)", tokenNull, tokenSpentAt);
    this.ctx.waitUntil(
      this.env.DB_MSG.prepare("INSERT INTO issuer_token_null (token_null, spent_at) VALUES (?, ?)")
        .bind(tokenNull, tokenSpentAt)
        .run()
        .catch((err) => console.error("D1 mirror error (issuer_token_null):", err))
    );

    // Idempotent: re-inserting an existing commitment is a no-op (INSERT OR IGNORE), so a retried
    // request doesn't grow the tree or change the root. (The tokenNull check above already prevents a
    // single token from being redeemed twice; this guards the separate case of the same commitment
    // bytes colliding, which INSERT OR IGNORE handles safely either way.)
    const commitCreatedAt = Date.now();
    this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO commitments (commitment, created_at) VALUES (?, ?)",
      commitment,
      commitCreatedAt,
    );
    this.ctx.waitUntil(
      this.env.DB_MSG.prepare("INSERT OR IGNORE INTO commitments (commitment, created_at) VALUES (?, ?)")
        .bind(commitment, commitCreatedAt)
        .run()
        .catch((err) => console.error("D1 mirror error (commitments):", err))
    );
    const { n } = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM commitments").one();
    return Response.json({ merkleRoot: this.computeRoot(), size: n });
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
    const spentAt = Date.now();
    this.ctx.storage.sql.exec("INSERT INTO nullifiers (nullifier, spent_at) VALUES (?, ?)", nullifier, spentAt);
    this.ctx.waitUntil(
      this.env.DB_MSG.prepare("INSERT INTO nullifiers (nullifier, spent_at) VALUES (?, ?)")
        .bind(nullifier, spentAt)
        .run()
        .catch((err) => console.error("D1 mirror error (nullifiers):", err))
    );
    return Response.json({ ok: true });
  }
}
