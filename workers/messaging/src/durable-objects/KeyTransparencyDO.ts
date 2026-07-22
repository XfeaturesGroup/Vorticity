// K8: append-only Key Transparency log for alias->key bindings. See docs/03-crypto-core.md §8 and
// the R18 risk-register row ("Nickname squatting / impersonation" — mitigation column names "Key
// Transparency (K8) over alias→key"). Every `AliasDO` register/revoke event is appended here as a
// leaf in a REAL Merkle tree (`@zk-kit/lean-imt` — the same official library `MerkleTreeDO` already
// uses for the Semaphore membership tree, reused again here, not reimplemented) over SHA-256, not
// Poseidon2 — this log is never verified inside a ZK circuit, so there's no reason to pay for
// circuit-compatible field arithmetic; plain SHA-256 is the right tool.
//
// THREAT MODEL THIS ADDRESSES: a malicious/compromised `AliasDO` could equivocate — silently tell
// one asker a nickname's owner holds key K1 and another asker it holds key K2. A public, append-
// only, auditable log makes that detectable: every observer sees the SAME sequence of published
// events (register/revoke), and an inclusion proof against a given root is a checkable witness that
// an entry was genuinely published at a specific position — it cannot be fabricated after the fact
// for one specific asker without changing the root everyone else also sees.
//
// HONEST SCOPE, STATED PLAINLY (this pass, K8 — "Mitigated" not "Closed", matching this doc's own
// convention for a real-but-partial fix): this implements the append-only LOG and CURRENT-root
// inclusion proofs, not the full Certificate-Transparency-style CROSS-TIME machinery — no RFC 6962
// "consistency proof" (a structural proof that root R1, size N1, is a genuine append-only prefix of
// a LATER root R2, size N2 > N1), no independent third-party monitors/gossip, no client-side
// verification wiring in `apps/web`. A single-operator log without those pieces still lets an
// auditor with the CURRENT root catch an entry that was never published at all, but a server that
// controls the only copy of the log could in principle still fork it for one victim without those
// additional pieces — a real, named limitation of a single log, not a bug in what IS built here.
import { DurableObject } from "cloudflare:workers";
import { createHash } from "node:crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
import { mth, consistencyProof } from "../merkleConsistency";
import { signSth } from "../sth";
import type { Env } from "../env";

const LOOKUP_KEY_RE = /^[0-9a-f]{64}$/;
const ALIAS_PUB_RE = /^[0-9a-f]{64}$/;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
// LeanIMT's hash function must be synchronous (unlike `crypto.subtle.digest`) — `node:crypto`'s
// `createHash` is, and this Worker already opts into `nodejs_compat` (wrangler.toml). Combines two
// field elements (here: arbitrary 256-bit values, not BN254-field-constrained — no ZK circuit ever
// reads this tree) by hashing their big-endian byte concatenation.
function combine(a: bigint, b: bigint): bigint {
  const aHex = a.toString(16).padStart(64, "0");
  const bHex = b.toString(16).padStart(64, "0");
  const bytes = Buffer.from(aHex + bHex, "hex");
  return BigInt("0x" + sha256Hex(bytes));
}
function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

interface EntryRow {
  seq: number;
  leaf_hash: string;
  lookup_key: string;
  alias_pub: string;
  event: string;
  created_at: number;
  [key: string]: SqlStorageValue;
}
interface CountRow {
  n: number;
  [key: string]: SqlStorageValue;
}
interface TreeCacheRow {
  size: number;
  exported: string;
  [key: string]: SqlStorageValue;
}

const EMPTY_TREE_ROOT = "0".repeat(64);

export class KeyTransparencyDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS kt_entries (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        leaf_hash  TEXT NOT NULL,
        lookup_key TEXT NOT NULL,
        alias_pub  TEXT NOT NULL,
        event      TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_kt_entries_lookup_key ON kt_entries(lookup_key);
      CREATE TABLE IF NOT EXISTS kt_tree_cache (
        id       INTEGER PRIMARY KEY CHECK (id = 1),
        size     INTEGER NOT NULL,
        exported TEXT NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/append") return this.handleAppend(request);
    if (request.method === "GET" && url.pathname === "/root") return Response.json(this.currentRoot());
    if (request.method === "GET" && url.pathname.startsWith("/latest/")) {
      return this.handleLatest(url.pathname.slice("/latest/".length));
    }
    if (request.method === "GET" && url.pathname.startsWith("/proof/")) {
      const seq = Number(url.pathname.slice("/proof/".length));
      return this.handleProofForSeq(seq);
    }
    if (request.method === "GET" && url.pathname === "/consistency") return this.handleConsistency(url);
    if (request.method === "GET" && url.pathname === "/sth") return this.handleSth();
    return new Response("Not found", { status: 404 });
  }

  // Same incremental-cache technique as MerkleTreeDO's "incremental tree cache" pass (2026-07) —
  // reused, not reinvented: `tree.export()`/`LeanIMT.import()` avoid rehashing on a warm cache,
  // `tree.insert()` is O(log n). See that file's header comment for the full design rationale.
  private loadTreeForSize(expectedSize: number): LeanIMT<bigint> {
    const cached = this.ctx.storage.sql.exec<TreeCacheRow>("SELECT size, exported FROM kt_tree_cache WHERE id = 1").toArray()[0];
    if (cached && cached.size === expectedSize) {
      return LeanIMT.import<bigint>(combine, cached.exported, (v) => BigInt(v));
    }
    if (cached) {
      console.warn(`[KeyTransparencyDO] tree cache size mismatch (cached ${cached.size}, expected ${expectedSize}) — rebuilding`);
    }
    const rows = this.ctx.storage.sql.exec<EntryRow>("SELECT leaf_hash FROM kt_entries ORDER BY seq").toArray();
    const leaves = rows.map((r) => BigInt("0x" + r.leaf_hash));
    return new LeanIMT<bigint>(combine, leaves);
  }

  private persistTreeCache(tree: LeanIMT<bigint>): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO kt_tree_cache (id, size, exported) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET size = excluded.size, exported = excluded.exported",
      tree.size,
      tree.export(),
    );
  }

  private currentRoot(): { merkleRoot: string; size: number } {
    const { n } = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM kt_entries").one();
    if (n === 0) return { merkleRoot: EMPTY_TREE_ROOT, size: 0 };
    return { merkleRoot: fieldToHex(this.loadTreeForSize(n).root as bigint), size: n };
  }

  // Appends one event. Called by AliasDO on a successful register/revoke — never directly by a
  // client (no public route forwards here; see index.ts, only /transparency/root, /latest/:key,
  // and /proof/:seq are exposed — the log is written from inside the Messaging Worker only).
  private async handleAppend(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const lookupKey = (body as { lookup_key?: unknown }).lookup_key;
    const aliasPub = (body as { alias_pub?: unknown }).alias_pub;
    const event = (body as { event?: unknown }).event;
    if (typeof lookupKey !== "string" || !LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex value", { status: 400 });
    }
    if (event !== "register" && event !== "revoke") {
      return new Response('event must be "register" or "revoke"', { status: 400 });
    }
    // A revoke event has no key to bind — recorded as an empty string, matching the "revoke frees
    // the nickname" semantics AliasDO.ts itself uses (no alias_pub survives a revoke).
    const aliasPubValue = event === "register" ? aliasPub : "";
    if (event === "register" && (typeof aliasPubValue !== "string" || !ALIAS_PUB_RE.test(aliasPubValue))) {
      return new Response("alias_pub must be a 64-char lowercase hex value for a register event", { status: 400 });
    }

    const beforeCount = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM kt_entries").one().n;
    const preTree = beforeCount === 0 ? new LeanIMT<bigint>(combine, []) : this.loadTreeForSize(beforeCount);

    const createdAt = Date.now();
    // The NEXT seq is predicted before inserting (safe: DO execution is single-threaded, same
    // property every other DO in this codebase already relies on) so it can be bound INTO the leaf
    // preimage in a single INSERT — no insert-then-patch two-step. seq domain-separates the leaf so
    // two content-identical events (e.g. two revokes in a row — can't happen today since AliasDO
    // deletes on revoke, but the log must stay correct even if that ever changes) never collide on
    // the same leaf hash.
    const { next } = this.ctx.storage.sql
      .exec<{ next: number; [key: string]: SqlStorageValue }>("SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM kt_entries")
      .one();
    const preimage = `vortic-kt-v1:${event}:${lookupKey}:${aliasPubValue}:${next}`;
    const leafHash = sha256Hex(new TextEncoder().encode(preimage));

    const row = this.ctx.storage.sql
      .exec<{ seq: number; [key: string]: SqlStorageValue }>(
        "INSERT INTO kt_entries (leaf_hash, lookup_key, alias_pub, event, created_at) VALUES (?, ?, ?, ?, ?) RETURNING seq",
        leafHash,
        lookupKey,
        aliasPubValue,
        event,
        createdAt,
      )
      .one();
    if (row.seq !== next) {
      // Should be unreachable under single-threaded DO execution — a real corruption signal if it
      // ever fires (the predicted seq and the actual assigned seq must always agree).
      return new Response("internal error: seq prediction drift", { status: 500 });
    }

    preTree.insert(BigInt("0x" + leafHash));
    this.persistTreeCache(preTree);

    return Response.json({
      seq: row.seq,
      leafHash,
      merkleRoot: fieldToHex(preTree.root as bigint),
      size: preTree.size,
    });
  }

  private handleLatest(lookupKey: string): Response {
    if (!LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex value", { status: 400 });
    }
    const row = this.ctx.storage.sql
      .exec<EntryRow>("SELECT * FROM kt_entries WHERE lookup_key = ? ORDER BY seq DESC LIMIT 1", lookupKey)
      .toArray()[0];
    if (!row) return new Response("no transparency log entry for this lookup_key", { status: 404 });
    return this.proofResponse(row);
  }

  private handleProofForSeq(seq: number): Response {
    if (!Number.isInteger(seq) || seq < 1) {
      return new Response("seq must be a positive integer", { status: 400 });
    }
    const row = this.ctx.storage.sql.exec<EntryRow>("SELECT * FROM kt_entries WHERE seq = ?", seq).toArray()[0];
    if (!row) return new Response("no such log entry", { status: 404 });
    return this.proofResponse(row);
  }

  // Builds an inclusion proof for `row` against the CURRENT tree (see this file's header comment —
  // this is an inclusion proof against the latest root, not an RFC-6962 cross-time consistency
  // proof). `LeanIMT.indexOf` finds the leaf's position (seq is 1-based; LeanIMT index is 0-based
  // and matches insertion order, so `seq - 1`, but we look it up via the actual leaf value rather
  // than assuming that arithmetic, in case a future schema ever changes insertion order).
  private proofResponse(row: EntryRow): Response {
    const { n } = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM kt_entries").one();
    const tree = this.loadTreeForSize(n);
    const leafIndex = tree.indexOf(BigInt("0x" + row.leaf_hash));
    if (leafIndex === -1) {
      // Should be unreachable (every inserted leaf stays in the tree forever, append-only) — a real
      // corruption signal if it ever fires, not a normal 404 case, so this is a 500 not a 404.
      return new Response("internal error: log entry not found in tree (append-only invariant violated)", { status: 500 });
    }
    const proof = tree.generateProof(leafIndex);
    return Response.json({
      seq: row.seq,
      lookupKey: row.lookup_key,
      aliasPub: row.alias_pub,
      event: row.event,
      createdAt: row.created_at,
      leafHash: row.leaf_hash,
      index: proof.index,
      siblings: proof.siblings.map((s) => fieldToHex(s as bigint)),
      merkleRoot: fieldToHex(tree.root as bigint),
      size: n,
    });
  }

  // RFC 6962-style consistency proof between two PAST sizes of this log — see merkleConsistency.ts's
  // header comment for the full design and the honest scope note on what this does and doesn't
  // authenticate. Deliberately recomputes MTH(...) from the raw ordered leaf-hash list rather than
  // reusing `loadTreeForSize`'s cached LeanIMT node matrix, which — confirmed by reading
  // `@zk-kit/lean-imt`'s own `insert()` source, not assumed — MUTATES earlier "carried up unchanged"
  // node values once a later insertion gives them a real sibling, so it cannot answer "what was the
  // subtree hash back when the tree had only `first` leaves" for an arbitrary past `first`.
  // Unauthenticated (matches /root, /latest/:key, /proof/:seq — this IS the public audit log) but
  // rate-limited at the index.ts route level (see PROOF_RATE_LIMIT precedent): this recomputation is
  // O(second) hashes per call, materially more expensive than /proof/:seq's O(log n) cached path, so
  // an unrate-limited caller could force repeated full-log rehashes.
  private handleConsistency(url: URL): Response {
    const first = Number(url.searchParams.get("first"));
    const second = Number(url.searchParams.get("second"));
    if (!Number.isInteger(first) || !Number.isInteger(second) || first < 1 || second <= first) {
      return new Response("first and second must be integers with 0 < first < second", { status: 400 });
    }
    const { n } = this.ctx.storage.sql.exec<CountRow>("SELECT COUNT(*) AS n FROM kt_entries").one();
    if (second > n) {
      return new Response(`second (${second}) exceeds the log's current size (${n})`, { status: 400 });
    }
    const rows = this.ctx.storage.sql
      .exec<EntryRow>("SELECT leaf_hash FROM kt_entries ORDER BY seq LIMIT ?", second)
      .toArray();
    const leaves = rows.map((r) => BigInt("0x" + r.leaf_hash));
    const firstRoot = mth(combine, leaves.slice(0, first));
    const secondRoot = mth(combine, leaves);
    const proof = consistencyProof(combine, first, leaves);
    return Response.json({
      first,
      second,
      firstRoot: fieldToHex(firstRoot),
      secondRoot: fieldToHex(secondRoot),
      proof: proof.map(fieldToHex),
    });
  }

  // Signed Tree Head (STH) — see sth.ts's header comment for the full design and the gap this
  // closes (consistency proofs authenticate root CONTENT, not the numeric size label; a signature
  // over (size, root, timestamp) does). Signs whatever the CURRENT root genuinely is at request
  // time, not a cached/stale value — reuses `currentRoot()`, the same read `/root` uses.
  private handleSth(): Response {
    const { merkleRoot, size } = this.currentRoot();
    const sth = signSth(this.env.KT_STH_SIGNING_KEY_PEM, size, merkleRoot, Date.now());
    return Response.json(sth);
  }
}
