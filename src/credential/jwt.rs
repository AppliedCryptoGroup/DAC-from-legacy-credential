use std::path::Path;

use anyhow::Result;
use plonky2::field::types::PrimeField;
use plonky2_ecdsa::curve::ecdsa::{
    ECDSAPublicKey, ECDSASecretKey, ECDSASignature, sign_message, verify_message,
};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use serde::{Deserialize, Serialize};

use crate::circuits::gadgets::base64::{base64url_decode, base64url_encode};
use crate::circuits::gadgets::json_parse::{ClaimPosition, find_claim_position};
use crate::credential::attribute::{Attribute, IssuerKeypair, ensure_valid_attribute_len_bytes};
use crate::credential::cnf::{
    B64URL_COORD_LEN, base64url_coords_to_pk, build_cnf_block, extract_cnf_coords, find_cnf_start,
    pk_coords_to_base64url,
};
use crate::utils::crypto::{byte_array_to_scalar, hash_to_scalar, keypair_from_hex};

/// The fixed JWT header JSON used for all credentials in this system.
/// Algorithm: ES256 (P-256), Type: JWT.
pub const JWT_HEADER_JSON: &[u8] = br#"{"alg":"ES256","typ":"JWT"}"#;

/// Default issuer URI for JWT VC credentials.
pub const JWT_ISS_VALUE: &str = "https://server.example.com";

/// Maximum value length for the `iss` claim (padded to multiple of 4).
pub const JWT_ISS_MAX_VALUE_LEN: usize = 28;

/// Maximum value length for the `iat` claim (padded to multiple of 4).
pub const JWT_IAT_MAX_VALUE_LEN: usize = 12;

/// Default `iat` (issued-at) timestamp for dummy credentials.
pub const JWT_IAT_DEFAULT: &str = "1311280970";

/// Fixed challenge bytes the holder signs as in-circuit Proof of Possession
/// (see [`pop_message_scalar`]). The R_Base circuit verifies an ECDSA signature
/// on this message under the owner PK extracted from `cnf.jwk`. The message is
/// a compile-time constant and is used because the
/// non-native scalar-mul gadget admits no knowledge extractor for plain DL-PoP.
pub const POP_CHALLENGE_BYTES: &[u8] = b"delegatable-ECDSA-PoP-v1";

/// The constant PoP message scalar that the holder signs in R_Base.
/// Derived from [`POP_CHALLENGE_BYTES`] via SHA-256 -> P256Scalar, matching the
/// issuer ECDSA path's digest-to-scalar mapping. Computed off-circuit; the
/// circuit materializes it as a `constant_nonnative`, so no SHA gadget is
/// instantiated for the PoP.
pub fn pop_message_scalar() -> P256Scalar {
    hash_to_scalar(POP_CHALLENGE_BYTES)
        .expect("POP_CHALLENGE_BYTES hash always yields a valid 32-byte digest")
}

/// Layout information for building JWT base circuits.
///
/// Encapsulates all sizes and keys needed to build the circuit,
/// computed from a maximum-length JWT. The circuit handles variable-length
/// JWTs: any JWT whose payload fits within the layout's maximum capacity
/// can be proved by the same circuit, regardless of actual value lengths.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JWTLayout {
    /// The claim keys (e.g., ["claim_00", "claim_01", ...]).
    pub claim_keys: Vec<String>,
    /// Maximum key length across all claim keys, padded to a multiple of 4.
    /// Derived automatically from `claim_keys`. This ensures all attributes
    /// (key || value) have a uniform byte length for Merkle commitment: shorter
    /// keys are zero-padded to `max_key_len` so every leaf is the same size.
    pub max_key_len: usize,
    /// Maximum value length in bytes (must be a multiple of 4).
    pub max_value_len: usize,
    /// Attribute byte length (max_key_len + max_value_len).
    pub attribute_len_bytes: usize,
    /// Maximum JWT message length in bytes (header_b64 + "." + max_payload_b64).
    /// Determines the number of SHA-256 blocks in the variable-length circuit.
    pub max_msg_len_bytes: usize,
    /// Maximum Base64url payload length in characters (always a multiple of 4).
    pub max_payload_b64_len: usize,
    /// Byte offset where payload Base64url starts in the JWT message.
    pub payload_b64_byte_offset: usize,
    /// Length of the Base64url header.
    pub header_b64_len: usize,
    /// Maximum decoded payload length (padded to a multiple of 3 for clean Base64).
    pub max_decoded_payload_len: usize,
}

/// Parsed JWT credential ready for circuit proving.
#[derive(Debug, PartialEq)]
pub struct JWTCredential {
    /// Base64url-encoded header bytes (ASCII).
    pub header_b64: Vec<u8>,
    /// Base64url-encoded payload bytes (ASCII).
    pub payload_b64: Vec<u8>,
    /// The full JWT message bytes that were signed: header_b64 + "." + payload_b64
    pub jwt_message_bytes: Vec<u8>,
    /// ECDSA signature over the JWT message.
    pub signature: ECDSASignature<P256>,
    /// The scalar hash of the JWT message (for ECDSA verification).
    pub message_hash: P256Scalar,
    /// Issuer public key.
    pub issuer_pk: ECDSAPublicKey<P256>,
    /// Extracted user-claim positions within the decoded payload (for Merkle tree).
    pub claims: Vec<ClaimPosition>,
    /// Raw decoded JSON payload bytes (unpadded, i.e. without null-padding).
    pub decoded_payload: Vec<u8>,
    /// Credential owner secret key (independent of JWT, for delegation).
    pub cred_sk: ECDSASecretKey<P256>,
    /// Credential owner public key (derived from cnf.jwk in the JWT payload).
    pub cred_pk: ECDSAPublicKey<P256>,
    /// User-claim values as Attributes (key_padded || value_padded, for Merkle tree).
    pub attributes: Vec<Attribute>,
    /// The user-claim keys used.
    pub claim_keys: Vec<String>,
    /// Maximum key length (padded to multiple of 4).
    pub max_key_len: usize,
    /// Maximum value length.
    pub max_value_len: usize,
    /// Issuer URI from the `iss` claim.
    pub iss: String,
    /// Issued-at timestamp from the `iat` claim.
    pub iat: String,
    /// Claim position for the `iss` standard claim (for circuit witness filling).
    pub iss_claim: ClaimPosition,
    /// Claim position for the `iat` standard claim (for circuit witness filling).
    pub iat_claim: ClaimPosition,
    /// Byte offset of the `cnf` block in the decoded JSON payload.
    pub cnf_start: usize,
}

/// Generate a fixed JWT issuer keypair (deterministic, for testing only).
pub fn generate_fixed_jwt_issuer_keypair() -> IssuerKeypair {
    let (sk, pk) =
        keypair_from_hex("7a8e3b2c1d4f5e6a9b0c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f");
    IssuerKeypair { sk, pk }
}

/// Generate a fixed credential owner keypair (deterministic, for testing only).
fn generate_fixed_cred_keypair() -> (ECDSASecretKey<P256>, ECDSAPublicKey<P256>) {
    keypair_from_hex("b5d4c3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5")
}

/// Build the JSON payload string with JWT VC standard claims.
///
/// Format: `{"iss":"<iss>","iat":"<iat>","cnf":{...},"key1":"val1",...}`
fn build_payload_json(
    claim_keys: &[String],
    claim_values: &[String],
    iss: &str,
    iat: &str,
    cred_pk_x_b64: &str,
    cred_pk_y_b64: &str,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("\"iss\":\"{}\"", iss));
    parts.push(format!("\"iat\":\"{}\"", iat));
    parts.push(build_cnf_block(cred_pk_x_b64, cred_pk_y_b64));
    for (key, val) in claim_keys.iter().zip(claim_values.iter()) {
        parts.push(format!("\"{}\":\"{}\"", key, val));
    }
    format!("{{{}}}", parts.join(","))
}

/// Generate a JWT layout for circuit building (determines all sizes).
///
/// Uses synthetic keys `claim_00`, `claim_01`, ... and max-length dummy values
/// to determine the fixed message, payload, and decoded lengths.
pub fn generate_empty_jwt_layout(num_claims: usize, max_value_len: usize) -> Result<JWTLayout> {
    if num_claims == 0 {
        anyhow::bail!("num_claims must be ≥ 1");
    }
    ensure_valid_attribute_len_bytes(max_value_len)?;

    let claim_keys: Vec<String> = (0..num_claims).map(|i| format!("claim_{:02}", i)).collect();

    generate_jwt_layout_inner(&claim_keys, max_value_len)
}

/// Generate a JWT layout for circuit building with explicit claim keys.
pub fn generate_jwt_layout_with_keys(
    claim_keys: &[&str],
    max_value_len: usize,
) -> Result<JWTLayout> {
    let num_claims = claim_keys.len();
    if num_claims == 0 {
        anyhow::bail!("claim_keys must be non-empty");
    }
    ensure_valid_attribute_len_bytes(max_value_len)?;

    let keys: Vec<String> = claim_keys.iter().map(|k| k.to_string()).collect();
    generate_jwt_layout_inner(&keys, max_value_len)
}

/// Internal layout computation shared by both layout functions.
///
/// Determines maximum sizes by building a max-length payload (all values at `max_value_len`).
/// The payload includes standard JWT VC claims (iss, iat, cnf) plus user claims.
/// The decoded payload is rounded to a multiple of 3 so the Base64 output is a multiple of 4,
/// enabling clean fixed-length Base64 decode in the circuit.
fn generate_jwt_layout_inner(claim_keys: &[String], max_value_len: usize) -> Result<JWTLayout> {
    let max_key_among = claim_keys.iter().map(|k| k.len()).max().unwrap_or(0);
    let max_key_len = max_key_among.div_ceil(4) * 4;
    let attribute_len_bytes = max_key_len + max_value_len;

    let header_b64 = base64url_encode(JWT_HEADER_JSON);
    let header_b64_len = header_b64.len();

    // Build max-length payload to determine maximum sizes.
    // Uses max-length iss, iat, cnf placeholders, plus max-length user claims.
    let max_claim_values: Vec<String> = (0..claim_keys.len())
        .map(|_| "x".repeat(max_value_len))
        .collect();

    // Use max-length iss and iat values for worst-case sizing.
    let max_iss = "x".repeat(JWT_ISS_MAX_VALUE_LEN);
    let max_iat = "x".repeat(JWT_IAT_MAX_VALUE_LEN);
    // cnf block has fixed size (B64URL_COORD_LEN = 43 for each coordinate).
    let x_placeholder = "x".repeat(B64URL_COORD_LEN);
    let y_placeholder = "x".repeat(B64URL_COORD_LEN);

    let payload_json = build_payload_json(
        claim_keys,
        &max_claim_values,
        &max_iss,
        &max_iat,
        &x_placeholder,
        &y_placeholder,
    );
    let decoded_len = payload_json.len();

    // Pad to multiple of 3 for clean Base64url encoding (no remainder).
    // This sizing is for the maximum case; actual payloads may be shorter.
    let max_decoded_payload_len = decoded_len.div_ceil(3) * 3;

    let mut padded = payload_json.into_bytes();
    padded.resize(max_decoded_payload_len, 0);

    let payload_b64 = base64url_encode(&padded);
    let max_payload_b64_len = payload_b64.len();
    let payload_b64_byte_offset = header_b64_len + 1;

    let max_msg_len_bytes = header_b64_len + 1 + max_payload_b64_len;

    Ok(JWTLayout {
        claim_keys: claim_keys.to_vec(),
        max_key_len,
        max_value_len,
        attribute_len_bytes,
        max_msg_len_bytes,
        max_payload_b64_len,
        payload_b64_byte_offset,
        header_b64_len,
        max_decoded_payload_len,
    })
}

/// Build a JWT credential from claim keys and values.
///
/// Produces a JWT VC with standard claims (iss, iat, cnf) plus user claims.
/// No null-padding is applied: the issuer signs the raw JWT. The variable-length
/// SHA-256 circuit handles payloads of any length up to the layout's maximum.
fn build_jwt_credential(
    issuer_sk: &ECDSASecretKey<P256>,
    issuer_pk: &ECDSAPublicKey<P256>,
    layout: &JWTLayout,
    claim_keys: &[String],
    claim_values: &[String],
    iss: &str,
    iat: &str,
) -> Result<JWTCredential> {
    let num_claims = claim_keys.len();
    let (cred_sk, cred_pk) = generate_fixed_cred_keypair();
    let (x_b64, y_b64) = pk_coords_to_base64url(&cred_pk);

    let header_b64 = base64url_encode(JWT_HEADER_JSON);

    // Build actual JSON payload with standard + user claims (unpadded).
    let payload_json = build_payload_json(claim_keys, claim_values, iss, iat, &x_b64, &y_b64);

    // NO null-padding. The raw payload is Base64-encoded directly.
    let decoded_payload = payload_json.into_bytes();
    assert!(
        decoded_payload.len() <= layout.max_decoded_payload_len,
        "payload too large for layout: {} > {}",
        decoded_payload.len(),
        layout.max_decoded_payload_len
    );

    // Base64url-encode the raw (unpadded) payload.
    let payload_b64 = base64url_encode(&decoded_payload);
    assert!(
        payload_b64.len() <= layout.max_payload_b64_len,
        "payload Base64 length too large for layout: {} > {}",
        payload_b64.len(),
        layout.max_payload_b64_len
    );

    // Build JWT message: header_b64 + "." + payload_b64 (variable length!)
    let mut jwt_message_bytes = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    jwt_message_bytes.extend_from_slice(&header_b64);
    jwt_message_bytes.push(b'.');
    jwt_message_bytes.extend_from_slice(&payload_b64);

    // Sign the raw JWT message; no padding required.
    let message_hash = hash_to_scalar(&jwt_message_bytes)?;
    let signature = sign_message(message_hash, *issuer_sk);

    // Find user-claim positions in the decoded payload.
    let mut claims = Vec::with_capacity(num_claims);
    for key in claim_keys {
        let pos = crate::circuits::gadgets::json_parse::find_claim_position(&decoded_payload, key)?;
        claims.push(pos);
    }

    // Find standard claim positions.
    let iss_claim = find_claim_position(&decoded_payload, "iss")?;
    let iat_claim = find_claim_position(&decoded_payload, "iat")?;
    let cnf_start = find_cnf_start(&decoded_payload)?;

    // Build attributes for Merkle tree commitment (user claims only).
    // Standard claims (iss, iat, cnf) are NOT included in the Merkle tree.
    let mut attributes = Vec::with_capacity(num_claims);
    for (key, val) in claim_keys.iter().zip(claim_values.iter()) {
        let mut attr_bytes = Vec::with_capacity(layout.attribute_len_bytes);
        attr_bytes.extend_from_slice(key.as_bytes());
        attr_bytes.resize(layout.max_key_len, 0);
        attr_bytes.extend_from_slice(val.as_bytes());
        attr_bytes.resize(layout.attribute_len_bytes, 0);
        attributes.push(Attribute::from_vec(attr_bytes)?);
    }

    Ok(JWTCredential {
        header_b64,
        payload_b64,
        jwt_message_bytes,
        signature,
        message_hash,
        issuer_pk: *issuer_pk,
        claims,
        decoded_payload,
        cred_sk,
        cred_pk,
        attributes,
        claim_keys: claim_keys.to_vec(),
        max_key_len: layout.max_key_len,
        max_value_len: layout.max_value_len,
        iss: iss.to_string(),
        iat: iat.to_string(),
        iss_claim,
        iat_claim,
        cnf_start,
    })
}

/// Generate a dummy JWT credential with synthetic claim keys and varying-length values.
///
/// Uses keys `claim_00`, `claim_01`, ... with deterministic but varying-length values.
/// The `num_claims` parameter refers to user claims only; standard claims (iss, iat, cnf)
/// are always added automatically. The JWT message is not padded.
pub fn generate_dummy_jwt(
    issuer_sk: &ECDSASecretKey<P256>,
    issuer_pk: &ECDSAPublicKey<P256>,
    num_claims: usize,
    max_value_len: usize,
) -> Result<JWTCredential> {
    let layout = generate_empty_jwt_layout(num_claims, max_value_len)?;

    // Generate varying-length claim values (deterministic but not all max-length).
    let claim_values: Vec<String> = (0..num_claims)
        .map(|i| {
            // Length varies from 1 to max_value_len
            let len = (i * 7 + 3) % max_value_len + 1;
            let base_char = (b'a' + (i as u8 % 26)) as char;
            std::iter::repeat_n(base_char, len).collect()
        })
        .collect();

    build_jwt_credential(
        issuer_sk,
        issuer_pk,
        &layout,
        &layout.claim_keys.clone(),
        &claim_values,
        JWT_ISS_VALUE,
        JWT_IAT_DEFAULT,
    )
}

/// Generate a JWT credential from explicit claim keys and values.
///
/// Validates that all values fit within `max_value_len` and are non-empty.
/// The `claim_keys`/`claim_values` are user claims only; standard claims (iss, iat, cnf)
/// are always added automatically.
pub fn generate_jwt_from_claims(
    issuer_sk: &ECDSASecretKey<P256>,
    issuer_pk: &ECDSAPublicKey<P256>,
    claim_keys: &[&str],
    claim_values: &[&str],
    max_value_len: usize,
) -> Result<JWTCredential> {
    if claim_keys.len() != claim_values.len() {
        anyhow::bail!(
            "claim_keys and claim_values must have the same length: {} vs {}",
            claim_keys.len(),
            claim_values.len()
        );
    }

    for (key, val) in claim_keys.iter().zip(claim_values.iter()) {
        if val.is_empty() {
            anyhow::bail!("claim '{}' value must not be empty", key);
        }
        if val.len() > max_value_len {
            anyhow::bail!(
                "claim '{}' value length {} exceeds max_value_len {}",
                key,
                val.len(),
                max_value_len
            );
        }
    }

    let layout = generate_jwt_layout_with_keys(claim_keys, max_value_len)?;
    let keys: Vec<String> = claim_keys.iter().map(|k| k.to_string()).collect();
    let values: Vec<String> = claim_values.iter().map(|v| v.to_string()).collect();

    build_jwt_credential(
        issuer_sk,
        issuer_pk,
        &layout,
        &keys,
        &values,
        JWT_ISS_VALUE,
        JWT_IAT_DEFAULT,
    )
}

impl JWTCredential {
    /// Get the payload_b64 padded with 'A' characters to `max_len`.
    ///
    /// 'A' is Base64url value 0, so trailing 'A' characters decode to zero bytes.
    /// Used by the prover to create a fixed-length Base64 input for the circuit.
    pub fn padded_payload_b64(&self, max_len: usize) -> Vec<u8> {
        assert!(
            self.payload_b64.len() <= max_len,
            "payload_b64 ({}) exceeds max_len ({})",
            self.payload_b64.len(),
            max_len
        );
        let mut padded = self.payload_b64.clone();
        padded.resize(max_len, b'A');
        padded
    }

    /// Get the decoded payload padded with zeros to `target_len`.
    ///
    /// Used by the prover for JSON claim extraction in the circuit.
    pub fn padded_decoded_payload(&self, target_len: usize) -> Vec<u8> {
        let mut padded = self.decoded_payload.clone();
        padded.resize(target_len, 0);
        padded
    }

    /// Save this credential as a standard compact JWT file (plain text).
    ///
    /// Writes the three-part JWT string `header.payload.signature` with no JSON
    /// wrapping. The file can be loaded back via [`JWTCredential::from_jwt_file`].
    pub fn save_jwt_file(&self, path: &Path) -> Result<()> {
        let header_str = String::from_utf8(self.header_b64.clone())?;
        let payload_str = String::from_utf8(self.payload_b64.clone())?;

        let sig_bytes = scalar_to_be32(&self.signature.r)
            .into_iter()
            .chain(scalar_to_be32(&self.signature.s))
            .collect::<Vec<u8>>();
        let sig_str = String::from_utf8(base64url_encode(&sig_bytes))?;

        std::fs::write(path, format!("{}.{}.{}", header_str, payload_str, sig_str))?;
        Ok(())
    }

    /// Save a human-readable JSON file with the decoded header and payload.
    ///
    /// This file is for inspection only; it contains no signature and cannot
    /// be used to reconstruct the credential. Use [`JWTCredential::save_jwt_file`]
    /// for the machine-readable form.
    pub fn save_readable_json(&self, path: &Path) -> Result<()> {
        let header_json: serde_json::Value = serde_json::from_slice(JWT_HEADER_JSON)?;
        let decoded = base64url_decode(self.payload_b64.as_slice())?;
        let trimmed = decoded
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| &decoded[..=i])
            .unwrap_or(&[]);
        let payload_json: serde_json::Value = serde_json::from_slice(trimmed)?;

        let doc = serde_json::json!({
            "header": header_json,
            "payload": payload_json,
        });
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }

    /// Build and sign a credential from a readable definition JSON.
    ///
    /// The file is the `{header, payload}` form written by [`Self::save_readable_json`].
    /// Every payload field other than the standard `iss`, `iat` and `cnf` claims
    /// is taken as a user claim, in file order, and signed into a fresh JWT with
    /// the given issuer keypair; the standard claims and confirmation key follow
    /// the generator defaults, so a definition produced by this crate round-trips.
    ///
    /// Unlike [`Self::from_jwt_file`] this re-signs the credential, so it does
    /// not depend on a stored signature: the definition JSON alone suffices.
    pub fn from_definition_json(
        path: &Path,
        issuer_sk: &ECDSASecretKey<P256>,
        issuer_pk: &ECDSAPublicKey<P256>,
        max_value_len: usize,
    ) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let doc: serde_json::Value = serde_json::from_str(&text)?;
        let payload = doc
            .get("payload")
            .and_then(|p| p.as_object())
            .ok_or_else(|| anyhow::anyhow!("definition JSON must contain an object `payload`"))?;

        let mut keys: Vec<String> = Vec::new();
        let mut values: Vec<String> = Vec::new();
        for (key, value) in payload {
            if matches!(key.as_str(), "iss" | "iat" | "cnf") {
                continue;
            }
            let v = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("claim `{key}` must have a string value"))?;
            keys.push(key.clone());
            values.push(v.to_string());
        }
        if keys.is_empty() {
            anyhow::bail!("definition JSON has no user claims");
        }

        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let value_refs: Vec<&str> = values.iter().map(String::as_str).collect();
        generate_jwt_from_claims(issuer_sk, issuer_pk, &key_refs, &value_refs, max_value_len)
    }

    /// Load a credential from a compact JWT file, reconstructing all derived fields.
    ///
    /// Returns an error if the JWT signature is invalid or the decoded payload
    /// does not match the layout's expected size.
    pub fn from_jwt_file(path: &Path, layout: &JWTLayout) -> Result<Self> {
        let compact = std::fs::read_to_string(path)?;
        let compact = compact.trim();

        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("compact JWT must have exactly 3 dot-separated parts");
        }

        let header_b64 = parts[0].as_bytes().to_vec();
        let payload_b64 = parts[1].as_bytes().to_vec();

        let mut jwt_message_bytes = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
        jwt_message_bytes.extend_from_slice(&header_b64);
        jwt_message_bytes.push(b'.');
        jwt_message_bytes.extend_from_slice(&payload_b64);

        let message_hash = hash_to_scalar(&jwt_message_bytes)?;

        let sig_bytes = base64url_decode(parts[2].as_bytes())?;
        if sig_bytes.len() != 64 {
            anyhow::bail!("signature must be 64 bytes (r||s), got {}", sig_bytes.len());
        }
        let r = byte_array_to_scalar(&sig_bytes[..32])?;
        let s = byte_array_to_scalar(&sig_bytes[32..])?;
        let signature = ECDSASignature { r, s };

        let issuer = generate_fixed_jwt_issuer_keypair();
        if !verify_message(message_hash, signature, issuer.pk) {
            anyhow::bail!("JWT signature verification failed");
        }

        let decoded_payload = base64url_decode(payload_b64.as_slice())?;
        if decoded_payload.len() > layout.max_decoded_payload_len {
            anyhow::bail!(
                "decoded payload length {} exceeds layout max ({})",
                decoded_payload.len(),
                layout.max_decoded_payload_len
            );
        }

        // Extract user-claim positions.
        let mut claims = Vec::with_capacity(layout.claim_keys.len());
        for key in &layout.claim_keys {
            claims.push(find_claim_position(&decoded_payload, key)?);
        }

        // Extract standard claim positions.
        let iss_claim = find_claim_position(&decoded_payload, "iss")?;
        let iat_claim = find_claim_position(&decoded_payload, "iat")?;
        let cnf_start = find_cnf_start(&decoded_payload)?;

        // Reconstruct cred_pk from the cnf block's x,y coordinates.
        let (x_b64, y_b64) = extract_cnf_coords(&decoded_payload, cnf_start)?;
        let cred_pk = base64url_coords_to_pk(&x_b64, &y_b64)?;

        // Reconstruct cred_sk from the fixed keypair (PoC: deterministic key).
        let (cred_sk, expected_pk) = generate_fixed_cred_keypair();
        assert_eq!(
            cred_pk, expected_pk,
            "cnf public key in JWT does not match expected fixed credential key"
        );

        let mut attributes = Vec::with_capacity(layout.claim_keys.len());
        for (key, claim) in layout.claim_keys.iter().zip(claims.iter()) {
            let mut attr_bytes = Vec::with_capacity(layout.attribute_len_bytes);
            attr_bytes.extend_from_slice(key.as_bytes());
            attr_bytes.resize(layout.max_key_len, 0);
            attr_bytes.extend_from_slice(claim.value.as_bytes());
            attr_bytes.resize(layout.attribute_len_bytes, 0);
            attributes.push(Attribute::from_vec(attr_bytes)?);
        }

        Ok(JWTCredential {
            header_b64,
            payload_b64,
            jwt_message_bytes,
            signature,
            message_hash,
            issuer_pk: issuer.pk,
            claims,
            decoded_payload,
            cred_sk,
            cred_pk,
            attributes,
            claim_keys: layout.claim_keys.clone(),
            max_key_len: layout.max_key_len,
            max_value_len: layout.max_value_len,
            iss: iss_claim.value.clone(),
            iat: iat_claim.value.clone(),
            iss_claim,
            iat_claim,
            cnf_start,
        })
    }
}

/// Encode a `P256Scalar` as a 32-byte big-endian array (zero-padded if needed).
fn scalar_to_be32(scalar: &P256Scalar) -> Vec<u8> {
    let big = scalar.to_canonical_biguint();
    let mut bytes = big.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2_ecdsa::curve::ecdsa::verify_message;

    #[test]
    fn test_generate_dummy_jwt() -> Result<()> {
        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, 4, 32)?;

        // Verify the signature.
        assert!(
            verify_message(jwt.message_hash, jwt.signature, jwt.issuer_pk),
            "JWT signature should verify"
        );

        // Check claim count.
        assert_eq!(jwt.claims.len(), 4);
        assert_eq!(jwt.attributes.len(), 4);

        // Check that claim values are varying length.
        let lengths: Vec<usize> = jwt.claims.iter().map(|c| c.value.len()).collect();
        assert!(
            lengths.windows(2).any(|w| w[0] != w[1]),
            "claim values should have varying lengths, got {:?}",
            lengths
        );

        // Check attribute format: key_padded || value_padded
        for (i, (claim, attr)) in jwt.claims.iter().zip(jwt.attributes.iter()).enumerate() {
            let attr_bytes = attr.as_bytes();
            assert_eq!(
                attr_bytes.len(),
                jwt.max_key_len + jwt.max_value_len,
                "attribute {} length mismatch",
                i
            );
            // Key portion
            let key_bytes = jwt.claim_keys[i].as_bytes();
            assert_eq!(
                &attr_bytes[..key_bytes.len()],
                key_bytes,
                "attribute {} key mismatch",
                i
            );
            // Value portion
            let val_bytes = claim.value.as_bytes();
            assert_eq!(
                &attr_bytes[jwt.max_key_len..jwt.max_key_len + val_bytes.len()],
                val_bytes,
                "attribute {} value mismatch",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_generate_jwt_from_claims() -> Result<()> {
        let issuer = generate_fixed_jwt_issuer_keypair();
        let keys = ["email", "name", "role", "dept"];
        let values = ["alice@example.com", "Alice", "admin", "engineering"];
        let jwt = generate_jwt_from_claims(&issuer.sk, &issuer.pk, &keys, &values, 32)?;

        assert!(verify_message(
            jwt.message_hash,
            jwt.signature,
            jwt.issuer_pk
        ));
        assert_eq!(jwt.claims.len(), 4);

        // Verify claim values match input.
        for (claim, &expected_val) in jwt.claims.iter().zip(values.iter()) {
            assert_eq!(claim.value, expected_val);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_layout_consistency() -> Result<()> {
        // Layout represents maximum sizes; any JWT for that layout should fit within.
        let layout = generate_empty_jwt_layout(4, 32)?;
        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, 4, 32)?;

        assert!(jwt.jwt_message_bytes.len() <= layout.max_msg_len_bytes);
        assert!(jwt.payload_b64.len() <= layout.max_payload_b64_len);
        assert!(jwt.decoded_payload.len() <= layout.max_decoded_payload_len);

        Ok(())
    }

    #[test]
    fn test_jwt_deterministic() -> Result<()> {
        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt1 = generate_dummy_jwt(&issuer.sk, &issuer.pk, 4, 32)?;
        let jwt2 = generate_dummy_jwt(&issuer.sk, &issuer.pk, 4, 32)?;

        // Both should produce identical JWT messages.
        assert_eq!(jwt1.jwt_message_bytes, jwt2.jwt_message_bytes);
        assert_eq!(jwt1.decoded_payload, jwt2.decoded_payload);

        Ok(())
    }

    /// Round-trip a credential through `save_jwt_file` / `from_jwt_file`: the
    /// compact JWT reloads into a credential equal to the original.
    #[test]
    fn test_jwt_json_round_trip() -> Result<()> {
        let issuer = generate_fixed_jwt_issuer_keypair();

        let keys = ["employer", "position", "department", "project"];
        let values = [
            "Meridian Technologies",
            "Principal Engineer",
            "Applied Cryptography",
            "Quantum-Safe Protocol",
        ];
        let max_value_len = 32;

        let layout = generate_jwt_layout_with_keys(&keys, max_value_len)?;
        let jwt = generate_jwt_from_claims(&issuer.sk, &issuer.pk, &keys, &values, max_value_len)?;

        let dir = std::env::temp_dir().join("delegatable_ecdsa_test");
        std::fs::create_dir_all(&dir)?;
        let jwt_path = dir.join("work_credential.jwt");
        jwt.save_jwt_file(&jwt_path)?;

        let loaded = JWTCredential::from_jwt_file(&jwt_path, &layout)?;
        assert_eq!(jwt, loaded);

        let _ = std::fs::remove_dir_all(&dir);

        Ok(())
    }

    /// Round-trip a credential through `from_definition_json`: a readable
    /// definition JSON re-signs into a credential equal to the original.
    #[test]
    fn test_definition_json_round_trip() -> Result<()> {
        let issuer = generate_fixed_jwt_issuer_keypair();

        let keys = ["employer", "position", "department", "project"];
        let values = [
            "Meridian Technologies",
            "Principal Engineer",
            "Applied Cryptography",
            "Quantum-Safe Protocol",
        ];
        let max_value_len = 32;

        let jwt = generate_jwt_from_claims(&issuer.sk, &issuer.pk, &keys, &values, max_value_len)?;

        let dir = std::env::temp_dir().join("delegatable_ecdsa_test");
        std::fs::create_dir_all(&dir)?;
        let json_path = dir.join("definition.json");
        jwt.save_readable_json(&json_path)?;

        let signed =
            JWTCredential::from_definition_json(&json_path, &issuer.sk, &issuer.pk, max_value_len)?;
        assert_eq!(jwt.claim_keys, signed.claim_keys);
        assert_eq!(jwt.attributes, signed.attributes);
        assert_eq!(jwt.decoded_payload, signed.decoded_payload);

        let _ = std::fs::remove_dir_all(&dir);

        Ok(())
    }
}
