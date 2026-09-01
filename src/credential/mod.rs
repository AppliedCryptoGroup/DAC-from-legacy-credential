//! Credential data structures and issuance utilities.
//!
//! Defines the shared [`attribute::Attribute`] primitive and the JWT-based
//! credential format ([`jwt`]), including the [`cnf`] confirmation key that
//! binds the holder's public key inside the signed payload.

pub mod attribute;
pub mod cnf;
pub mod jwt;
