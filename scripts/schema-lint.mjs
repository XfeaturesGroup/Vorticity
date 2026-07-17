#!/usr/bin/env node
// Plane-isolation CI gate. See docs/04-serverless-architecture.md "D1 schema (zero PII)" and
// docs/06-roadmap-and-risks.md Phase 0 exit gate: "CI blocks a deliberately-planted email column."
//
// Four checks, zero dependencies (must run with plain `node`, no install step required):
//   1. No D1 migration, in either plane, may define a column matching the forbidden PII/join-key
//      list. (Enrollment Plane is NOT exempt — docs/02 says it may hold a PPID hash and nothing
//      else identity-shaped; it must never store the raw email/sub either.)
//   2. No worker's wrangler.toml may bind the other plane's D1 database or Durable Objects
//      (physical plane separation — see docs/04 Worker/plane separation table).
//   3. No enrollment-plane migration may define a table from a fixed list of retired/forbidden
//      names — currently just `spent_tokens` (a real bug: it lived in DB_ENROLL, contradicting
//      docs/04 Flow 1's own diagram, which has always shown the spend-nullifier check happening in
//      the Messaging plane — see workers/enrollment/migrations/0002_drop_spent_tokens.sql). This
//      exists so a future refactor can't silently reintroduce that exact mistake.
//   4. No wrangler.toml `[vars]` block may define a var whose NAME looks like a secret
//      (`/SECRET|KEY|SIGNING|PRIVATE/i`) — those must be `wrangler secret put` / `.dev.vars`
//      (gitignored) only, never a plaintext value committed in `[vars]`.
//
// Exit code 0 = clean. Exit code 1 = violation(s) found (printed to stderr).

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKERS_DIR = join(REPO_ROOT, "workers");

const FORBIDDEN_COLUMNS = ["email", "sub", "user_id", "phone", "handle", "ip", "nickname"];

const PLANE_FORBIDDEN_BINDINGS = {
  enrollment: ["DB_MSG", "MEDIA", "MERKLE_TREE_DO", "QUEUE_DO", "GROUP_DO", "CONV_LOG_DO", "PRESENCE_DO", "ALIAS_DO", "RATE_GATE_DO"],
  messaging: ["DB_ENROLL", "OAUTH_CLIENT_SECRET", "PPID_HMAC_SECRET", "ISSUER_SIGNING_KEY_PEM"],
};

// Table names that must never reappear in a given plane's migrations — retired-for-a-reason, not
// just "unused right now". See check #3 above.
const PLANE_FORBIDDEN_TABLES = {
  enrollment: ["spent_tokens"],
  messaging: [],
};

// A var name matching this looks like a secret and must never be a plaintext `[vars]` value.
const SECRET_LIKE_VAR_RE = /SECRET|KEY|SIGNING|PRIVATE/i;

/** @returns {string[]} absolute paths */
function walk(dir, predicate) {
  if (!statSync(dir, { throwIfNoEntry: false })) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, predicate));
    else if (predicate(full)) out.push(full);
  }
  return out;
}

/** Depth-aware split on top-level commas (handles nested parens like PRIMARY KEY (a, b)). */
function splitTopLevel(body) {
  const parts = [];
  let depth = 0;
  let current = "";
  for (const ch of body) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (current.trim()) parts.push(current);
  return parts;
}

function findForbiddenColumns(sql, filePath) {
  const violations = [];
  const createTableRe = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?(\w+)["`]?\s*\(/gi;
  let match;
  while ((match = createTableRe.exec(sql))) {
    const tableName = match[1];
    // Find the matching close paren by depth-scanning from the open paren after this match.
    const openIdx = sql.indexOf("(", match.index);
    let depth = 0;
    let closeIdx = -1;
    for (let i = openIdx; i < sql.length; i++) {
      if (sql[i] === "(") depth++;
      if (sql[i] === ")") {
        depth--;
        if (depth === 0) {
          closeIdx = i;
          break;
        }
      }
    }
    if (closeIdx === -1) continue;
    const body = sql.slice(openIdx + 1, closeIdx);
    for (const rawColumn of splitTopLevel(body)) {
      const trimmed = rawColumn.trim();
      const firstToken = trimmed.split(/\s+/)[0]?.replace(/["`]/g, "").toLowerCase();
      if (!firstToken) continue;
      if (["primary", "foreign", "unique", "check", "constraint"].includes(firstToken)) continue;
      if (FORBIDDEN_COLUMNS.includes(firstToken)) {
        violations.push(
          `${filePath}: table "${tableName}" defines forbidden column "${firstToken}" — ` +
            `PII/join-key columns are not permitted in any D1 migration (docs/04).`,
        );
      }
    }
  }
  return violations;
}

function findForbiddenBindings(tomlText, filePath, forbidden) {
  const violations = [];
  for (const name of forbidden) {
    const bindingRe = new RegExp(`(?:binding|name)\\s*=\\s*["']${name}["']`, "i");
    const varRe = new RegExp(`^\\s*${name}\\s*=`, "im");
    if (bindingRe.test(tomlText) || varRe.test(tomlText)) {
      violations.push(`${filePath}: forbidden cross-plane binding/var "${name}" (docs/04 Worker/plane separation).`);
    }
  }
  return violations;
}

/**
 * Migrations are append-only (never edit an already-applied file) — so a retired table legitimately
 * appears as `CREATE TABLE x` in an old migration and `DROP TABLE x` in a later one. Flagging any
 * mention would fight that convention (and did, until this was written this way — an earlier version
 * of this check flagged `spent_tokens` in 0001_init.sql even though 0002_drop_spent_tokens.sql
 * removes it). So this tracks NET state: process a plane's migration files in filename order,
 * toggle existence on CREATE/DROP, and only flag a forbidden table if it's still standing after all
 * of them — i.e. actually present in the schema today, not merely mentioned in history.
 */
function findForbiddenTablesAcrossMigrations(files, forbiddenTables) {
  const violations = [];
  if (forbiddenTables.length === 0) return violations;
  const exists = new Set();
  const createRe = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?(\w+)["`]?/gi;
  const dropRe = /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?["`]?(\w+)["`]?/gi;
  for (const file of [...files].sort()) {
    const sql = readFileSync(file, "utf8");
    let match;
    createRe.lastIndex = 0;
    while ((match = createRe.exec(sql))) exists.add(match[1].toLowerCase());
    dropRe.lastIndex = 0;
    while ((match = dropRe.exec(sql))) exists.delete(match[1].toLowerCase());
  }
  for (const table of forbiddenTables) {
    if (exists.has(table)) {
      violations.push(
        `${files[0] ? join(files[0], "..") : "migrations"}: table "${table}" is still present after ` +
          `applying all migrations in order — this name is retired/forbidden in this plane (see the ` +
          `migration that was meant to drop/move it).`,
      );
    }
  }
  return violations;
}

/** Isolate the `[vars]` section's body: everything between a `[vars]` header and the next `[`
 * header (or EOF). Good enough for this file's simple, hand-written TOML — not a general parser. */
function extractVarsSection(tomlText) {
  const headerMatch = /^\s*\[vars\]\s*$/im.exec(tomlText);
  if (!headerMatch) return "";
  const start = headerMatch.index + headerMatch[0].length;
  const rest = tomlText.slice(start);
  const nextHeader = /^\s*\[/m.exec(rest);
  return nextHeader ? rest.slice(0, nextHeader.index) : rest;
}

function findVarsSecrets(tomlText, filePath) {
  const violations = [];
  const varsSection = extractVarsSection(tomlText);
  const assignRe = /^\s*([A-Z0-9_]+)\s*=/gim;
  let match;
  while ((match = assignRe.exec(varsSection))) {
    const varName = match[1];
    if (SECRET_LIKE_VAR_RE.test(varName)) {
      violations.push(
        `${filePath}: [vars] defines "${varName}", which looks like a secret (matches ` +
          `/SECRET|KEY|SIGNING|PRIVATE/i) — use \`wrangler secret put ${varName}\` (prod) or ` +
          `\`.dev.vars\` (local, gitignored) instead of a plaintext [vars] value.`,
      );
    }
  }
  return violations;
}

function main() {
  const violations = [];

  const migrationFiles = walk(WORKERS_DIR, (p) => p.includes(`${join("migrations", "")}`) && extname(p) === ".sql");
  for (const file of migrationFiles) {
    const sql = readFileSync(file, "utf8");
    violations.push(...findForbiddenColumns(sql, file));
  }

  for (const plane of ["enrollment", "messaging"]) {
    const planeFiles = migrationFiles.filter((f) => f.includes(`${sep}${plane}${sep}migrations${sep}`));
    violations.push(...findForbiddenTablesAcrossMigrations(planeFiles, PLANE_FORBIDDEN_TABLES[plane]));
  }

  for (const plane of ["enrollment", "messaging"]) {
    const tomlPath = join(WORKERS_DIR, plane, "wrangler.toml");
    if (!statSync(tomlPath, { throwIfNoEntry: false })) continue;
    const tomlText = readFileSync(tomlPath, "utf8");
    violations.push(...findForbiddenBindings(tomlText, tomlPath, PLANE_FORBIDDEN_BINDINGS[plane]));
    violations.push(...findVarsSecrets(tomlText, tomlPath));
  }

  if (violations.length > 0) {
    console.error(`schema-lint: ${violations.length} plane-isolation violation(s) found:\n`);
    for (const v of violations) console.error(`  ✗ ${v}`);
    console.error("\nSee docs/02-threat-model.md and docs/04-serverless-architecture.md.");
    process.exit(1);
  }

  console.log(`schema-lint: OK — scanned ${migrationFiles.length} migration file(s), 2 wrangler.toml(s), no violations.`);
}

main();
