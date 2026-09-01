//! Shared credential-attribute primitives.
//!
//! Defines [`Attribute`], a fixed-width byte vector with hex (de)serialization
//! and a canonical "empty" sentinel, and [`IssuerKeypair`]. These are used by
//! the JWT credential format, the delegation and presentation circuits, and the
//! Merkle commitment utilities.

use anyhow::Result;
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use plonky2_ecdsa::curve::p256::P256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const ATTRIBUTE_LEN_BYTES: usize = 32; // Default length of each attribute in bytes (multiple of 4 as we use u32 under the hood i.e. 4 bytes).

/// Returns the byte pattern for the "empty" attribute sentinel.
///
/// An empty attribute is all zeros except the first byte set to 1.
/// This ensures it is distinct from any zero-padded real attribute.
fn empty_attribute_bytes(attribute_len_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; attribute_len_bytes];
    bytes[0] = 1;
    bytes
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute(Vec<u8>);

impl Attribute {
    pub fn new<const N: usize>(bytes: [u8; N]) -> Self {
        assert!(
            N > 0 && N.is_multiple_of(4),
            "attribute byte-length must be a non-zero multiple of 4" // multiple of 4 as we use u32 under the hood i.e. 4 bytes
        );
        Self(bytes.to_vec())
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Self> {
        ensure_valid_attribute_len_bytes(bytes.len())?;
        Ok(Self(bytes))
    }

    /// Create the sentinel attribute used for redacted (masked) positions.
    ///
    /// Delegation steps replace masked attributes with this marker before
    /// recomputing the Merkle commitment, so that revoked attributes are
    /// indistinguishable in the resulting tree.
    pub fn empty_marker(attribute_len_bytes: usize) -> Self {
        Self(empty_attribute_bytes(attribute_len_bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len_bytes(&self) -> usize {
        self.0.len()
    }

    /// Pack attribute bytes into u32 limbs for circuit field encoding.
    ///
    /// The packing uses reversed chunk order with big-endian bytes:
    /// - Limb `i` covers bytes `[n - (i+1)*4 .. n - i*4]` (chunks from the end).
    /// - Within each chunk, bytes are interpreted as big-endian u32.
    ///
    /// This matches the circuit's `u32_limbs_from_message_bits` extraction,
    /// which reads SHA-256 message bits in the same reversed-chunk, big-endian order.
    pub fn to_u32_limbs_le(&self) -> Vec<u32> {
        let mut limbs = vec![0u32; self.0.len() / 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = self.0.len() - (i + 1) * 4;
            let chunk: [u8; 4] = self.0[start..start + 4].try_into().expect("slice length");
            *limb = u32::from_be_bytes(chunk);
        }
        limbs
    }

    pub fn is_empty(&self) -> bool {
        self.0 == empty_attribute_bytes(self.0.len())
    }
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom(
                "attribute hex length must be even",
            ));
        }
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        ensure_valid_attribute_len_bytes(bytes.len()).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

#[derive(Serialize, Deserialize)]
pub struct IssuerKeypair {
    pub sk: ECDSASecretKey<P256>,
    pub pk: ECDSAPublicKey<P256>,
}

/// Validate that an attribute byte-length is a nonzero multiple of 4.
pub fn ensure_valid_attribute_len_bytes(attribute_len_bytes: usize) -> Result<()> {
    if attribute_len_bytes == 0 || !attribute_len_bytes.is_multiple_of(4) {
        anyhow::bail!("attribute byte-length must be a non-zero multiple of 4");
    }
    Ok(())
}
