//! The JWT `cnf.jwk` confirmation claim.
//!
//! The credential binds the holder's public key inside the signed payload as a
//! `cnf` (confirmation) JWK with the P-256 coordinates `x` and `y`. The block
//! has a fixed structure, so this module holds its layout constants together
//! with the helpers that build it, locate it, and convert between an
//! [`ECDSAPublicKey`] and its base64url coordinates. The base circuit's CNF
//! extractor (`gadgets/cnf_parse.rs`) parses the same block in-circuit.

use anyhow::Result;
use num_bigint::BigUint;
use plonky2::field::types::{Field, PrimeField};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::p256::P256;

use crate::circuits::gadgets::base64::{base64url_decode, base64url_encode};
use crate::utils::crypto::pad_be_bytes;

/// Fixed prefix of the `cnf` block in the JWT payload (everything before the x value).
pub const CNF_PREFIX: &str = r#""cnf":{"jwk":{"kty":"EC","crv":"P-256","x":""#;

/// Separator between the x and y values in the cnf block.
pub const CNF_XY_SEPARATOR: &str = r#"","y":""#;

/// Closing of the cnf block after the y value.
pub const CNF_CLOSING: &str = r#""}}"#;

/// Length of a base64url-encoded P-256 coordinate (32 bytes -> 43 chars, no padding).
pub const B64URL_COORD_LEN: usize = 43;

/// Total byte length of the entire cnf block in the JWT payload.
pub const CNF_BLOCK_LEN: usize = CNF_PREFIX.len()
    + B64URL_COORD_LEN
    + CNF_XY_SEPARATOR.len()
    + B64URL_COORD_LEN
    + CNF_CLOSING.len();

/// Convert an EC public key's x and y coordinates to base64url-encoded strings.
///
/// Each coordinate is 32 bytes (P-256) -> 43 base64url characters (no padding).
pub fn pk_coords_to_base64url(pk: &ECDSAPublicKey<P256>) -> (String, String) {
    let x_biguint = pk.0.x.to_canonical_biguint();
    let y_biguint = pk.0.y.to_canonical_biguint();

    let mut x_bytes = x_biguint.to_bytes_be();
    pad_be_bytes(&mut x_bytes, 32);
    let mut y_bytes = y_biguint.to_bytes_be();
    pad_be_bytes(&mut y_bytes, 32);

    let x_b64 = String::from_utf8(base64url_encode(&x_bytes)).unwrap();
    let y_b64 = String::from_utf8(base64url_encode(&y_bytes)).unwrap();

    debug_assert_eq!(x_b64.len(), B64URL_COORD_LEN);
    debug_assert_eq!(y_b64.len(), B64URL_COORD_LEN);

    (x_b64, y_b64)
}

/// Decode base64url-encoded x and y coordinate strings back to an EC public key.
pub fn base64url_coords_to_pk(x_b64: &str, y_b64: &str) -> Result<ECDSAPublicKey<P256>> {
    use plonky2_ecdsa::curve::curve_types::AffinePoint;
    use plonky2_ecdsa::field::p256_base::P256Base;

    let x_bytes = base64url_decode(x_b64.as_bytes())?;
    let y_bytes = base64url_decode(y_b64.as_bytes())?;

    let x = P256Base::from_noncanonical_biguint(BigUint::from_bytes_be(&x_bytes));
    let y = P256Base::from_noncanonical_biguint(BigUint::from_bytes_be(&y_bytes));

    Ok(ECDSAPublicKey(AffinePoint::<P256>::nonzero(x, y)))
}

/// Build the cnf block string from base64url-encoded x and y coordinates.
pub(crate) fn build_cnf_block(x_b64: &str, y_b64: &str) -> String {
    format!(
        "{}{}{}{}{}",
        CNF_PREFIX, x_b64, CNF_XY_SEPARATOR, y_b64, CNF_CLOSING
    )
}

/// Find the byte offset where the cnf block starts in a decoded JSON payload.
pub fn find_cnf_start(json_payload: &[u8]) -> Result<usize> {
    let json_str = std::str::from_utf8(json_payload)?;
    json_str
        .find(CNF_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("cnf block not found in payload"))
}

/// Extract the x and y base64url strings from the cnf block at the given offset.
pub fn extract_cnf_coords(json_payload: &[u8], cnf_start: usize) -> Result<(String, String)> {
    let json_str = std::str::from_utf8(json_payload)?;
    let x_start = cnf_start + CNF_PREFIX.len();
    let x_end = x_start + B64URL_COORD_LEN;

    let separator_start = x_end;
    let separator_end = separator_start + CNF_XY_SEPARATOR.len();
    if &json_str[separator_start..separator_end] != CNF_XY_SEPARATOR {
        anyhow::bail!(
            "cnf block: expected separator '{}' at position {}",
            CNF_XY_SEPARATOR,
            separator_start
        );
    }

    let y_start = separator_end;
    let y_end = y_start + B64URL_COORD_LEN;

    let closing_start = y_end;
    let closing_end = closing_start + CNF_CLOSING.len();
    if &json_str[closing_start..closing_end] != CNF_CLOSING {
        anyhow::bail!(
            "cnf block: expected closing '{}' at position {}",
            CNF_CLOSING,
            closing_start
        );
    }

    Ok((
        json_str[x_start..x_end].to_string(),
        json_str[y_start..y_end].to_string(),
    ))
}
