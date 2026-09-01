//! Reusable sub-circuits composed by the pipeline circuits.
//!
//! JWT parsing:
//! - [`base64`] -- Base64url encoding/decoding
//! - [`json_parse`] -- JSON claim extraction with known keys
//! - [`array_slice`] -- Variable-position array slicing via one-hot indicator vectors
//! - [`cnf_parse`] -- CNF claim extraction (cnf.jwk public key) with base64url decode
//!
//! Cryptographic primitives:
//! - [`ecdsa`] -- ECDSA (P-256) signature verification
//! - [`sha256_variable`] -- variable-length SHA-256
//! - [`scalar_conversion`] -- SHA-256 digest to ECDSA message scalar
//!
//! Shared helpers:
//! - [`make_one_hot_indicator`] -- Reusable one-hot indicator circuit pattern
//! - [`unpack_words_to_bytes`] -- Unpack u32 words into individual byte targets
//! - [`select_bytes_by_offset`] -- Select bytes using a one-hot byte-offset indicator

pub mod array_slice;
pub mod base64;
pub mod cnf_parse;
pub mod ecdsa;
pub mod json_parse;
pub mod scalar_conversion;
pub mod sha256_variable;

// Re-export general-purpose byte-packing helpers for convenience.
pub use json_parse::{pack_4_bytes_be, pack_constants_be};

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Targets for a one-hot indicator circuit.
pub struct OneHotTargets {
    /// One-hot indicator vector: exactly one element is 1, rest are 0.
    pub indicator: Vec<Target>,
    /// The value encoded by the indicator: `sum_i((i + offset) * indicator[i])`.
    pub value: Target,
}

/// Build a one-hot indicator sub-circuit.
///
/// Creates `size` boolean targets constrained to sum to 1, with a weighted sum
/// encoding a value. The weight for index `i` is `i + offset`.
///
/// Constraints:
/// 1. Each indicator element is boolean (ind^2 == ind).
/// 2. Exactly one indicator is 1 (sum == 1).
/// 3. Weighted sum equals the value target: `sum_i((i + offset) * indicator[i]) == value`.
pub fn make_one_hot_indicator<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    size: usize,
    offset: usize,
) -> OneHotTargets {
    assert!(size > 0, "one-hot indicator size must be positive");

    let indicator: Vec<Target> = (0..size).map(|_| builder.add_virtual_target()).collect();

    // Boolean constraint: ind^2 == ind for each element.
    for &ind in &indicator {
        let sq = builder.mul(ind, ind);
        builder.connect(ind, sq);
    }

    // Sum-to-one constraint.
    let mut sum = builder.zero();
    for &ind in &indicator {
        sum = builder.add(sum, ind);
    }
    let one = builder.one();
    builder.connect(sum, one);

    // Weighted-sum constraint: sum_i((i + offset) * indicator[i]) == value.
    let value = builder.add_virtual_target();
    let mut weighted = builder.zero();
    for (i, &ind) in indicator.iter().enumerate() {
        let weight = builder.constant(F::from_canonical_usize(i + offset));
        let contrib = builder.mul(ind, weight);
        weighted = builder.add(weighted, contrib);
    }
    builder.connect(weighted, value);

    OneHotTargets { indicator, value }
}

/// Unpack u32 word targets into individual byte targets.
///
/// Creates 4 virtual byte targets per word and constrains them to pack back
/// into the original word via big-endian packing:
///   word = b0 * 2^24 + b1 * 2^16 + b2 * 2^8 + b3
///
/// Each byte is range-checked to `[0, 256)`. Over Goldilocks the packing
/// equation alone admits non-canonical decompositions, which a prover could use
/// to commit attribute limbs that differ from the signature-bound payload.
///
/// Returns the byte targets (length = words.len() * 4).
pub fn unpack_words_to_bytes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    words: &[Target],
) -> Vec<Target> {
    let num_bytes = words.len() * 4;
    let bytes: Vec<Target> = (0..num_bytes)
        .map(|_| builder.add_virtual_target())
        .collect();

    let (c256, c65536, c16m) = pack_constants_be(builder);
    for (word_idx, &word) in words.iter().enumerate() {
        let base = word_idx * 4;
        let reconstructed = pack_4_bytes_be(
            builder,
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
            c256,
            c65536,
            c16m,
        );
        builder.connect(word, reconstructed);
    }

    // Makes the byte solution to the packing above unique.
    for &b in &bytes {
        builder.range_check(b, 8);
    }

    bytes
}

/// Select bytes from a padded byte array using a one-hot offset indicator.
///
/// Computes: `output[j] = sum_k(indicator[k] * bytes[k + j])` for j in 0..count.
///
/// This is used when a substring might not start at a word boundary: the indicator
/// encodes the byte offset (0–3) and this function extracts the correctly-aligned bytes.
pub fn select_bytes_by_offset<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bytes_with_padding: &[Target],
    offset_indicator: &[Target],
    count: usize,
) -> Vec<Target> {
    (0..count)
        .map(|j| {
            let mut result = builder.zero();
            for (k, &ind) in offset_indicator.iter().enumerate() {
                let src = bytes_with_padding[k + j];
                let contrib = builder.mul(ind, src);
                result = builder.add(result, contrib);
            }
            result
        })
        .collect()
}
