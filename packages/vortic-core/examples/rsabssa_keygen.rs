//! One-off, OFFLINE issuer keypair generator for the RSABSSA Plane Bridge (see `src/blind_sig.rs`).
//! Run natively (never in a Worker): `cargo run --example rsabssa_keygen --no-default-features
//! --features issuer-full`. Prints the secret key PEM (paste into `workers/enrollment/.dev.vars` /
//! `wrangler secret put`, NEVER commit it) and the public key PEM (paste into
//! `workers/messaging/src/issuer-keys.ts` as a new `kid` entry — that one is fine to commit, it's
//! public by design).
use vortic_core::blind_sig::generate_keypair_pem;

fn main() {
    let (sk_pem, pk_pem) = generate_keypair_pem().expect("RSA-3072 keygen failed");
    println!("=== sk_issuer (SECRET — workers/enrollment/.dev.vars ISSUER_SIGNING_KEY_PEM, never commit) ===");
    println!("{sk_pem}");
    println!("=== pk_issuer (PUBLIC — workers/messaging/src/issuer-keys.ts, safe to commit) ===");
    println!("{pk_pem}");
}
