//! Vorticity cryptographic core. See `docs/03-crypto-core.md` for the full design.
//!
//! Phase 0 status: module skeleton only — no cryptographic implementation yet (that's Phase 1+).
//! What this crate proves *today* is the build pipeline: one Rust source tree, two feature-gated
//! outputs (`client-full` for the app, `edge-verify-only` for the Workers), both reachable from
//! WASM via `wasm-bindgen`.

pub mod alias;
pub mod backup;
pub mod blind_sig;
pub mod group;
#[cfg(feature = "client-full")]
pub mod kem;
pub mod oprf;
pub mod pow;
#[cfg(feature = "client-full")]
pub mod ratchet;
pub mod ring;
pub mod seal;
#[cfg(feature = "client-full")]
pub mod symmetric;
pub mod util;
pub mod zk;

#[cfg(test)]
mod zk_test;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn vortic_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Which build this binary is — lets the TS side assert it never accidentally loaded a
/// `client-full` binary into an edge Worker context, or vice versa.
#[wasm_bindgen]
pub fn vortic_core_build() -> String {
    if cfg!(feature = "client-full") {
        "client-full".to_string()
    } else if cfg!(feature = "edge-verify-only") {
        "edge-verify-only".to_string()
    } else {
        "unknown".to_string()
    }
}
