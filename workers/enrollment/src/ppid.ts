// PPID = HMAC-SHA256(secret, oauth_sub). This is the ONLY residue of a real identity permitted
// anywhere in Vorticity (docs/02, docs/03 §2). It is one-way and is used exclusively as a
// sybil-guard counter key in DB_ENROLL — it must never be written anywhere near DB_MSG.
export async function computePpid(sub: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(sub));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
