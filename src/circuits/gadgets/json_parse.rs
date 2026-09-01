use anyhow::Result;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::array_slice::{
    PackedArraySliceTargets, fill_array_slice_witness_packed_u32,
    make_array_slice_circuit_packed_u32,
};
use super::{make_one_hot_indicator, select_bytes_by_offset, unpack_words_to_bytes};

/// Big-endian byte-packing constants: 2^8, 2^16, 2^24.
///
/// Used to pack 4 individual byte targets into a single u32 word target:
///   word = b0 * 2^24 + b1 * 2^16 + b2 * 2^8 + b3
///
/// These are deduplicated by `builder.constant()` so calling this multiple
/// times returns the same targets.
pub fn pack_constants_be<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (Target, Target, Target) {
    let c256 = builder.constant(F::from_canonical_u32(1 << 8)); // 2^8
    let c65536 = builder.constant(F::from_canonical_u32(1 << 16)); // 2^16
    let c16m = builder.constant(F::from_canonical_u32(1 << 24)); // 2^24
    (c256, c65536, c16m)
}

/// Pack 4 byte targets into a single u32 word target (big-endian).
///
///   word = b0 * 2^24 + b1 * 2^16 + b2 * 2^8 + b3
///
/// This matches the byte layout used by `u32::from_be_bytes([b0, b1, b2, b3])`.
/// Pass the constants from `pack_constants_be()` to avoid re-creating them.
#[allow(clippy::too_many_arguments)]
pub fn pack_4_bytes_be<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    b0: Target,
    b1: Target,
    b2: Target,
    b3: Target,
    c256: Target,
    c65536: Target,
    c16m: Target,
) -> Target {
    let mut word = b3;
    word = builder.mul_add(b2, c256, word); // + b2 * 2^8
    word = builder.mul_add(b1, c65536, word); // + b1 * 2^16
    word = builder.mul_add(b0, c16m, word); // + b0 * 2^24
    word
}

/// Targets for extracting a single JSON claim with a known key (fixed at circuit build time).
///
/// Supports variable-length values up to `max_value_len` via a `value_len_indicator`.
///
/// The output `attribute_u32_words` contains `key_padded || value_padded` for Merkle tree leaves,
/// preventing claim-swapping during selective disclosure.
pub struct JsonClaimTargetsKnownKey {
    /// The packed array slice targets (u32 words).
    pub slice_targets: PackedArraySliceTargets,
    /// Attribute as u32 words (key_padded || value_padded, for Merkle leaf).
    pub attribute_u32_words: Vec<Target>,
    /// Total attribute byte length (max_key_len + max_value_len).
    pub attribute_len_bytes: usize,
    /// Witness: actual value length (1..max_value_len).
    pub value_len: Target,
    /// Private: one-hot indicator for value length (index i represents length i+1).
    value_len_indicator: Vec<Target>,
    /// Private: byte offset within first word (0..3).
    byte_offset: Target,
    /// Private: one-hot indicator for byte offset.
    byte_offset_indicator: Vec<Target>,
    /// Private: unpacked bytes with padding for offset handling.
    substring_bytes_with_padding: Vec<Target>,
    /// Private: inverse witnesses proving each active value byte differs from '"'.
    value_quote_inv: Vec<Target>,
}

/// Build a JSON claim extraction sub-circuit for a claim with a known key.
///
/// The key bytes are hard-wired as constants at circuit build time. The prover provides
/// the position of the claim in the decoded JSON as a private input; the circuit then
/// verifies the expected key bytes appear at that position along with structural characters.
///
/// # Parameters
/// - `json_len_bytes`: word-aligned decoded JSON length (padded)
/// - `key`: known key bytes (e.g., `b"email"`)
/// - `max_value_len`: maximum value length in bytes (must be a multiple of 4)
/// - `max_key_len`: padded key length for uniform attribute size across all claims (must be a multiple of 4)
///
/// # Returns
/// `JsonClaimTargetsKnownKey` with `attribute_u32_words` = key_padded || value_padded
pub fn make_json_claim_circuit_known_key<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    json_len_bytes: usize,
    key: &[u8],
    max_value_len: usize,
    max_key_len: usize,
) -> JsonClaimTargetsKnownKey {
    assert!(!key.is_empty() && max_value_len > 0);
    assert!(key.len() <= max_key_len, "key length exceeds max_key_len");
    assert_eq!(
        json_len_bytes % 4,
        0,
        "json length must be word-aligned for packed slicing"
    );
    assert_eq!(
        max_value_len % 4,
        0,
        "max_value_len must be a multiple of 4"
    );
    assert_eq!(max_key_len % 4, 0, "max_key_len must be a multiple of 4");

    let key_len = key.len();
    let attribute_len_bytes = max_key_len + max_value_len;

    // Substring layout: delimiter + "key":"value" + trailing delimiter
    // We need at least: 1({/,) + 1(") + key_len + 1(") + 1(:) + 1(") + max_value_len + 1(") + 1(,/})
    // = key_len + max_value_len + 7
    let min_substring_len = key_len + max_value_len + 7;
    // Round up to multiple of 4 for word alignment
    let per_claim_substring_len = min_substring_len.div_ceil(4) * 4;
    // Plus 4 extra bytes for byte-offset handling (non-word-aligned claim starts)
    let slice_len_with_padding = per_claim_substring_len + 4;

    // Slice out the claim's neighbourhood from the packed JSON.
    let slice_targets = make_array_slice_circuit_packed_u32::<F, D>(
        builder,
        json_len_bytes,
        slice_len_with_padding,
    );

    let substring_words = &slice_targets.output_packed;

    // Unpack the slice words into individual bytes.
    let substring_bytes_with_padding = unpack_words_to_bytes(builder, substring_words);

    // Handle byte offset (claim start might not be word-aligned)
    let offset_one_hot = make_one_hot_indicator(builder, 4, 0);
    let byte_offset = offset_one_hot.value;
    let byte_offset_indicator = offset_one_hot.indicator;

    // Extract per_claim_substring_len bytes starting from byte_offset
    let substring_bytes = select_bytes_by_offset(
        builder,
        &substring_bytes_with_padding,
        &byte_offset_indicator,
        per_claim_substring_len,
    );

    // Structural validation against constant key and delimiter bytes.
    let quote = builder.constant(F::from_canonical_u32(0x22)); // "
    let colon = builder.constant(F::from_canonical_u32(0x3A)); // :

    // substring[0] must be '{' (0x7B) or ',' (0x2C): the prefix delimiter.
    // Prevents matching a key that appears inside a string value.
    // Constraint: (byte - 0x7B) * (byte - 0x2C) == 0
    let left_brace = builder.constant(F::from_canonical_u32(0x7B));
    let comma = builder.constant(F::from_canonical_u32(0x2C));
    let diff_brace = builder.sub(substring_bytes[0], left_brace);
    let diff_comma = builder.sub(substring_bytes[0], comma);
    let product = builder.mul(diff_brace, diff_comma);
    let zero_t = builder.zero();
    builder.connect(product, zero_t);

    // substring[1] == '"' (opening quote of key)
    builder.connect(substring_bytes[1], quote);

    // substring[2..2+key_len] == key bytes (hard-wired as constants)
    for (j, &kb) in key.iter().enumerate() {
        let expected = builder.constant(F::from_canonical_u32(kb as u32));
        builder.connect(substring_bytes[2 + j], expected);
    }

    // substring[2+key_len] == '"' (closing quote of key)
    builder.connect(substring_bytes[2 + key_len], quote);

    // substring[3+key_len] == ':' (colon)
    builder.connect(substring_bytes[3 + key_len], colon);

    // substring[4+key_len] == '"' (opening quote of value)
    builder.connect(substring_bytes[4 + key_len], quote);

    // Variable-length value extraction.
    // value_len_indicator: one-hot over max_value_len positions
    // index i represents value length i+1 (lengths 1..max_value_len)
    let vlen_one_hot = make_one_hot_indicator(builder, max_value_len, 1);
    let value_len_indicator = vlen_one_hot.indicator;
    let value_len = vlen_one_hot.value;

    // Check: closing quote at position 5 + key_len + value_len
    let value_start = 5 + key_len;
    let mut char_at_close = builder.zero();
    for (v, &ind) in value_len_indicator.iter().enumerate() {
        let actual_len = v + 1;
        let close_pos = value_start + actual_len;
        if close_pos < per_claim_substring_len {
            let contrib = builder.mul(ind, substring_bytes[close_pos]);
            char_at_close = builder.add(char_at_close, contrib);
        }
    }
    builder.connect(char_at_close, quote);

    // Extract value bytes with zero-padding beyond value_len.
    // Use prefix-sum from right: is_active[j] = sum(indicator[j..])
    // is_active[j] == 1 iff value_len >= j+1 (i.e., byte j is within the value)
    let mut prefix_sum_from_right = vec![builder.zero(); max_value_len + 1];
    for v in (0..max_value_len).rev() {
        prefix_sum_from_right[v] =
            builder.add(prefix_sum_from_right[v + 1], value_len_indicator[v]);
    }

    let value_bytes: Vec<Target> = (0..max_value_len)
        .map(|j| {
            let raw_idx = value_start + j;
            if raw_idx < per_claim_substring_len {
                let raw = substring_bytes[raw_idx];
                builder.mul(raw, prefix_sum_from_right[j])
            } else {
                builder.zero()
            }
        })
        .collect();

    // Each active value byte must differ from '"' (0x22): the inverse witness
    // exists only when the byte is non-zero, so inactive positions are free.
    // Positions past the substring slice are never constrained; they only ever
    // cover padding bytes, so leaving their inv targets free is sound.
    let mut value_quote_inv = Vec::with_capacity(max_value_len);
    for j in 0..max_value_len {
        let raw_idx = value_start + j;
        let inv_j = builder.add_virtual_target();
        if raw_idx < per_claim_substring_len {
            let diff = builder.sub(substring_bytes[raw_idx], quote);
            let product = builder.mul(diff, inv_j);
            builder.connect(product, prefix_sum_from_right[j]);
        }
        value_quote_inv.push(inv_j);
    }

    // Assemble the attribute as key_padded || value_padded.
    // Key portion: actual key bytes (constants) + zero-padding to max_key_len
    let mut attribute_bytes = Vec::with_capacity(attribute_len_bytes);
    for j in 0..max_key_len {
        if j < key_len {
            attribute_bytes.push(builder.constant(F::from_canonical_u32(key[j] as u32)));
        } else {
            attribute_bytes.push(builder.zero());
        }
    }
    // Value portion: extracted value_bytes (already zero-padded by prefix-sum mask)
    attribute_bytes.extend_from_slice(&value_bytes);

    // Pack attribute bytes into u32 words following Attribute::to_u32_limbs_le() convention:
    //   - Reversed chunk order: limb 0 = last 4 bytes, limb 1 = second-to-last 4 bytes, ...
    //   - Big-endian bytes within each limb: word = b[0]*2^24 + b[1]*2^16 + b[2]*2^8 + b[3]
    // This must match the off-circuit Attribute::to_u32_limbs_le() for Merkle root consistency.
    let (c256, c65536, c16m) = pack_constants_be(builder);
    let attribute_u32_limbs = attribute_len_bytes / 4;
    let attribute_u32_words: Vec<Target> = (0..attribute_u32_limbs)
        .map(|limb_idx| {
            let start = attribute_len_bytes - (limb_idx + 1) * 4;
            pack_4_bytes_be(
                builder,
                attribute_bytes[start],
                attribute_bytes[start + 1],
                attribute_bytes[start + 2],
                attribute_bytes[start + 3],
                c256,
                c65536,
                c16m,
            )
        })
        .collect();

    JsonClaimTargetsKnownKey {
        slice_targets,
        attribute_u32_words,
        attribute_len_bytes,
        value_len,
        value_len_indicator,
        byte_offset,
        byte_offset_indicator,
        substring_bytes_with_padding,
        value_quote_inv,
    }
}

/// Fill witness for a known-key JSON claim extraction circuit.
///
/// The prover provides `claim.start` (byte position in the decoded JSON) as the key
/// private input. The circuit verifies that the expected key bytes actually appear there.
pub fn fill_json_claim_witness_known_key<F: RichField + Extendable<D>, const D: usize>(
    targets: &JsonClaimTargetsKnownKey,
    pw: &mut PartialWitness<F>,
    json_payload: &[u8],
    claim: &ClaimPosition,
) -> Result<()> {
    // Adjusted start: include the prefix delimiter byte ('{' or ',') before the key.
    assert!(claim.start > 0, "JSON key cannot start at position 0");
    let adjusted_start = claim.start - 1;

    // Fill the packed array slice witness (provides adjusted_start as position)
    fill_array_slice_witness_packed_u32::<F, D>(
        &targets.slice_targets,
        pw,
        json_payload,
        adjusted_start,
    )?;

    // Set value_len
    let val_len = claim.value.len();
    if val_len == 0 {
        anyhow::bail!("claim value length must be at least 1");
    }
    pw.set_target(targets.value_len, F::from_canonical_usize(val_len))?;

    // Set value_len_indicator (one-hot at position val_len - 1)
    for (i, tgt) in targets.value_len_indicator.iter().enumerate() {
        let val = if i == val_len - 1 { F::ONE } else { F::ZERO };
        pw.set_target(*tgt, val)?;
    }

    // Set byte offset (misalignment within first u32 word)
    let byte_offset_val = adjusted_start % 4;
    pw.set_target(
        targets.byte_offset,
        F::from_canonical_usize(byte_offset_val),
    )?;

    // Set byte offset indicator (one-hot)
    for (i, tgt) in targets.byte_offset_indicator.iter().enumerate() {
        let val = if i == byte_offset_val {
            F::ONE
        } else {
            F::ZERO
        };
        pw.set_target(*tgt, val)?;
    }

    // Set unpacked substring bytes from the word-aligned slice
    let start_aligned = (adjusted_start / 4) * 4;
    for (j, tgt) in targets.substring_bytes_with_padding.iter().enumerate() {
        let byte_idx = start_aligned + j;
        let byte_val = if byte_idx < json_payload.len() {
            json_payload[byte_idx]
        } else {
            0
        };
        pw.set_target(*tgt, F::from_canonical_u32(byte_val as u32))?;
    }

    // Set value_quote_inv: inverse of (byte - 0x22) for each active value byte.
    let quote_f = F::from_canonical_u32(0x22);
    for (j, tgt) in targets.value_quote_inv.iter().enumerate() {
        if j < val_len {
            let byte_f = F::from_canonical_u32(claim.value.as_bytes()[j] as u32);
            let diff_f = byte_f - quote_f;
            assert!(
                diff_f != F::ZERO,
                "value byte at position {} is a quote character",
                j
            );
            pw.set_target(*tgt, diff_f.inverse())?;
        } else {
            pw.set_target(*tgt, F::ZERO)?;
        }
    }

    // substring_bytes and attribute_u32_words are computed by circuit constraints.

    Ok(())
}

/// Position metadata for a claim within a JSON payload (off-circuit).
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimPosition {
    /// The claim key (e.g., "sub", "email").
    pub key: String,
    /// Byte offset in the decoded JSON where `"key":"value",` starts.
    pub start: usize,
    /// The extracted value (without quotes).
    pub value: String,
    /// Position of ':' within the substring (relative to start).
    pub colon_offset: usize,
}

/// Find a claim's position in a JSON payload (off-circuit helper).
///
/// Searches for `"key":` in the payload and extracts the value.
/// Returns the position metadata needed for circuit witness generation.
pub fn find_claim_position(json_payload: &[u8], key: &str) -> Result<ClaimPosition> {
    let json_str = std::str::from_utf8(json_payload)?;
    let search_key = format!("\"{}\":", key);

    let key_start = json_str
        .find(&search_key)
        .ok_or_else(|| anyhow::anyhow!("claim key '{}' not found in JSON", key))?;

    // Validate that the key is preceded by '{' or ',' (top-level JSON key).
    if key_start == 0 {
        anyhow::bail!("claim key '{}' cannot start at position 0 in JSON", key);
    }
    let prefix = json_payload[key_start - 1];
    if prefix != b'{' && prefix != b',' {
        anyhow::bail!(
            "claim key '{}' at position {} is not preceded by '{{' or ','",
            key,
            key_start
        );
    }

    let colon_pos = key_start + key.len() + 2; // skip opening quote + key + closing quote
    let colon_offset = colon_pos - key_start;

    // Find the value: skip the opening quote after colon.
    let value_start = colon_pos + 2; // skip ': "'
    let value_end = json_str[value_start..]
        .find('"')
        .ok_or_else(|| anyhow::anyhow!("unterminated string value for claim '{}'", key))?
        + value_start;

    let value = json_str[value_start..value_end].to_string();

    Ok(ClaimPosition {
        key: key.to_string(),
        start: key_start,
        value,
        colon_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_find_claim_position() -> Result<()> {
        let json = br#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;
        let claim = find_claim_position(json, "sub")?;
        assert_eq!(claim.key, "sub");
        assert_eq!(claim.value, "1234567890");
        assert_eq!(claim.start, 1); // starts after opening brace
        assert_eq!(claim.colon_offset, 5); // "sub": -> position of ':'

        let claim2 = find_claim_position(json, "name")?;
        assert_eq!(claim2.value, "John Doe");

        Ok(())
    }

    #[test]
    fn test_known_key_circuit_basic() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let key = b"sub";
        let max_value_len = 32;
        let max_key_len = 8;

        // Build a JSON payload with known structure
        let json = br#"{"sub":"hello_world","age":"25"}"#;
        let json_len = json.len();

        // Pad to word alignment
        let padded_len = (json_len + max_key_len + max_value_len + 7).div_ceil(4) * 4;
        let mut padded_json = json.to_vec();
        padded_json.resize(padded_len, 0);

        // Build circuit
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let targets = make_json_claim_circuit_known_key::<F, D>(
            &mut builder,
            padded_len,
            key,
            max_value_len,
            max_key_len,
        );
        let data = builder.build::<C>();

        // Fill witness
        let claim = find_claim_position(json, "sub")?;
        assert_eq!(claim.value, "hello_world");

        let mut pw = PartialWitness::new();
        fill_json_claim_witness_known_key::<F, D>(&targets, &mut pw, &padded_json, &claim)?;

        // Prove and verify
        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_known_key_variable_value_length() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let key = b"email";
        let max_value_len = 32;
        let max_key_len = 8;

        // Short value: "a@b.c" (5 bytes, well under max_value_len=32)
        let json = br#"{"email":"a@b.c","other":"data"}"#;
        let json_len = json.len();

        let padded_len = (json_len + max_key_len + max_value_len + 7).div_ceil(4) * 4;
        let mut padded_json = json.to_vec();
        padded_json.resize(padded_len, 0);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let targets = make_json_claim_circuit_known_key::<F, D>(
            &mut builder,
            padded_len,
            key,
            max_value_len,
            max_key_len,
        );
        let data = builder.build::<C>();

        let claim = find_claim_position(json, "email")?;
        assert_eq!(claim.value, "a@b.c");
        assert_eq!(claim.value.len(), 5);

        let mut pw = PartialWitness::new();
        fill_json_claim_witness_known_key::<F, D>(&targets, &mut pw, &padded_json, &claim)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_known_key_attribute_format() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let key = b"sub";
        let max_value_len = 16; // Smaller for faster test
        let max_key_len = 4;

        // Value "test" (4 bytes)
        let json = br#"{"sub":"test","x":"y"}"#;
        let json_len = json.len();

        let padded_len = (json_len + max_key_len + max_value_len + 7).div_ceil(4) * 4;
        let mut padded_json = json.to_vec();
        padded_json.resize(padded_len, 0);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let targets = make_json_claim_circuit_known_key::<F, D>(
            &mut builder,
            padded_len,
            key,
            max_value_len,
            max_key_len,
        );

        // Register attribute_u32_words as public inputs so we can inspect them
        for &t in &targets.attribute_u32_words {
            builder.register_public_input(t);
        }
        let data = builder.build::<C>();

        let claim = find_claim_position(json, "sub")?;
        assert_eq!(claim.value, "test");

        let mut pw = PartialWitness::new();
        fill_json_claim_witness_known_key::<F, D>(&targets, &mut pw, &padded_json, &claim)?;

        let proof = data.prove(pw)?;
        data.verify(proof.clone())?;

        // Verify attribute format matches off-circuit Attribute::to_u32_limbs_le()
        let attribute_len_bytes = max_key_len + max_value_len;
        let mut expected_bytes = Vec::with_capacity(attribute_len_bytes);
        // Key portion: "sub" + padding
        expected_bytes.extend_from_slice(b"sub");
        expected_bytes.resize(max_key_len, 0);
        // Value portion: "test" + padding
        expected_bytes.extend_from_slice(b"test");
        expected_bytes.resize(attribute_len_bytes, 0);

        // Compute expected u32 limbs (reversed chunk order, big-endian per limb)
        let num_limbs = attribute_len_bytes / 4;
        for (limb_idx, pi) in proof.public_inputs.iter().enumerate() {
            let start = attribute_len_bytes - (limb_idx + 1) * 4;
            let expected_word = u32::from_be_bytes([
                expected_bytes[start],
                expected_bytes[start + 1],
                expected_bytes[start + 2],
                expected_bytes[start + 3],
            ]);
            let actual = pi.to_canonical_u64();
            assert_eq!(
                actual,
                expected_word as u64,
                "limb {} mismatch: expected {}, got {} (bytes {:?})",
                limb_idx,
                expected_word,
                actual,
                &expected_bytes[start..start + 4]
            );
        }

        // Sanity check: we have the right number of limbs
        assert_eq!(proof.public_inputs.len(), num_limbs);

        Ok(())
    }
}
