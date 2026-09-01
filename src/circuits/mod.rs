//! The ZK circuits, in pipeline order: `R_Base -> R_Wrap -> R_Del -> R_Pres`.
//!
//! - [`layout`] -- shared base public-input layout and the `HasBaseLayout` trait
//!   that R_Wrap and R_Del consume.
//! - [`jwt_base`] -- JWT base circuit (R_Base): verifies the issuer signature and
//!   parses the JWT in-circuit.
//! - [`jwt_wrapper`] -- bridge circuit (R_Wrap) matching the base proof to the
//!   delegation circuit's `CommonCircuitData`.
//! - [`delegate`] -- cyclic delegation circuit (R_Del) with recursive verification.
//! - [`present`] -- presentation circuit (R_Pres) for selective attribute disclosure.
//!
//! [`gadgets`] holds the reusable sub-circuits these compose (base64, JSON
//! parsing, ECDSA, SHA-256, scalar conversion).
//!
//! A single delegation circuit serves many credential types: `R_Del` and
//! `R_Pres` are co-built once with the first credential type (see
//! [`delegate::build_delegation_and_wrapper`]), and every further credential
//! type joins by supplying only a matching wrapper built against the existing
//! `R_Del` via [`jwt_wrapper::build_jwt_wrapper_circuit`].

pub mod gadgets;

pub mod delegate;
pub mod jwt_base;
pub mod jwt_wrapper;
pub mod layout;
pub mod present;
