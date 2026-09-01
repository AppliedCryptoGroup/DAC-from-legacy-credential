//! Cryptographic conversion utilities: scalar encoding, public key compression, witness helpers.

use anyhow::{Result, anyhow};
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField, PrimeField64};
use plonky2::iop::witness::PartialWitness;
use plonky2_ecdsa::curve::curve_types::{AffinePoint, Curve, CurveScalar};
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use sha2::{Digest, Sha256};

/// Helper to set a nonnative field element as a circuit target value
pub fn set_nonnative_target<F, FF, const D: usize>(
    pw: &mut PartialWitness<F>,
    target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
    value: FF,
) -> Result<()>
where
    F: PrimeField64 + Extendable<D>,
    FF: PrimeField,
{
    pw.set_biguint_target(&target.value, &value.to_canonical_biguint())?;
    Ok(())
}

/// Hash a byte array with SHA256 and convert the 32-byte digest into a P256Scalar.
pub fn hash_to_scalar(msg: &[u8]) -> Result<P256Scalar> {
    let digest = Sha256::digest(msg); // 32 bytes

    byte_array_to_scalar(digest.as_ref())
}

pub fn byte_array_to_scalar(bytes: &[u8]) -> Result<P256Scalar> {
    if bytes.len() != 32 {
        return Err(anyhow!("Expected 32 bytes for P256Scalar"));
    }
    Ok(P256Scalar::from_noncanonical_biguint(
        BigUint::from_bytes_be(bytes),
    ))
}

/// Left-pad a big-endian byte vector to exactly `len` bytes with leading zeros.
pub fn pad_be_bytes(bytes: &mut Vec<u8>, len: usize) {
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.append(bytes);
        *bytes = padded;
    }
}

/// Encode a P-256 public key as a compressed SEC1 hex string (33 bytes -> 66 hex chars).
pub fn compressed_pubkey_hex(pk: &ECDSAPublicKey<P256>) -> String {
    let point: AffinePoint<P256> = pk.0;

    let x_big: BigUint = point.x.to_canonical_biguint();
    let y_big: BigUint = point.y.to_canonical_biguint();

    let mut x_bytes = x_big.to_bytes_be();
    pad_be_bytes(&mut x_bytes, 32);

    let prefix = if &y_big % 2u8 == 0u8.into() {
        0x02
    } else {
        0x03
    };

    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(&x_bytes);

    hex::encode(compressed)
}

/// Generate a P-256 ECDSA keypair from a hex-encoded secret key string.
pub fn keypair_from_hex(sk_hex: &str) -> (ECDSASecretKey<P256>, ECDSAPublicKey<P256>) {
    let sk = ECDSASecretKey::<P256>(P256Scalar::from_noncanonical_biguint(
        BigUint::from_str_radix(sk_hex, 16).unwrap(),
    ));
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * P256::GENERATOR_PROJECTIVE).to_affine());
    (sk, pk)
}
