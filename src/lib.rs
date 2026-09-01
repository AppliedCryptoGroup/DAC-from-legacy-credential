//! Delegatable ECDSA: a Plonky2-based ZK proof system for delegatable credentials.
//!
//! The pipeline is: Base proof (credential issuance) -> Base-wrapper (bridge) ->
//! Delegation (cyclic recursion for multi-hop delegation) -> Presentation (ZK disclosure).
//!
//! Credentials are ECDSA-signed JWTs; the base circuit verifies the signature
//! and decodes and parses the JWT in-circuit (see [`credential::jwt`]).

// Circuit code loops over several index-parallel target arrays at once, or uses
// the index arithmetically (`base + j`), so a range loop reads better here than
// `iter().enumerate()`.
#![allow(clippy::needless_range_loop)]

pub mod circuits;
pub mod credential;
pub mod utils;
