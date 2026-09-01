//! CNF claim extractor circuit for JWT VC credentials.
//!
//! Extracts the `cnf.jwk` public key (x, y coordinates) from a decoded JWT JSON payload.
//! The entire cnf block has a fixed structure; only the base64url-encoded x and y values
//! vary. All structural bytes are hardcoded as circuit constants.
//!
//! The circuit:
//! 1. Extracts a fixed-length substring from the decoded JSON via packed array slice
//! 2. Matches all structural constant bytes (key names, delimiters, etc.)
//! 3. Base64url-decodes the x and y coordinates (43 chars -> 32 bytes each)
//! 4. Packs decoded bytes into u32 limbs matching the owner_pk public input format

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuits::gadgets::array_slice::{
    PackedArraySliceTargets, fill_array_slice_witness_packed_u32,
    make_array_slice_circuit_packed_u32,
};
use crate::circuits::gadgets::base64::{
    Base64DecodeTargets, base64url_decode, fill_base64url_decode_witness,
    make_base64url_decode_circuit,
};
use crate::circuits::gadgets::json_parse::{pack_4_bytes_be, pack_constants_be};
use crate::circuits::gadgets::{
    make_one_hot_indicator, select_bytes_by_offset, unpack_words_to_bytes,
};
use crate::credential::cnf::{B64URL_COORD_LEN, CNF_CLOSING, CNF_PREFIX, CNF_XY_SEPARATOR};

/// Number of u32 limbs per EC coordinate (32 bytes / 4 = 8 limbs).
const COORD_U32_LIMBS: usize = 8;

/// Number of decoded bytes per coordinate (P-256 = 32 bytes).
const COORD_BYTES: usize = 32;

/// Total byte length of the cnf block in the JWT payload.
const CNF_BLOCK_BYTES: usize = CNF_PREFIX.len()
    + B64URL_COORD_LEN
    + CNF_XY_SEPARATOR.len()
    + B64URL_COORD_LEN
    + CNF_CLOSING.len();

/// Byte length of the cnf substring padded to multiple of 4 for word alignment,
/// plus 4 extra bytes for byte-offset handling (non-word-aligned starts).
const CNF_SUBSTRING_LEN: usize = CNF_BLOCK_BYTES.div_ceil(4) * 4;
const CNF_SLICE_LEN_WITH_PADDING: usize = CNF_SUBSTRING_LEN + 4;

/// Targets for the CNF extractor circuit.
pub struct CnfExtractorTargets {
    /// Packed array slice targets (bind packed_array to decoded JSON words externally).
    pub slice_targets: PackedArraySliceTargets,
    /// Byte offset within the word-aligned slice (0-3).
    pub byte_offset: Target,
    /// One-hot indicator for byte offset.
    pub byte_offset_indicator: Vec<Target>,
    /// Extracted x-coordinate u32 limbs (reversed order, big-endian bytes per limb).
    pub x_limbs: Vec<Target>,
    /// Extracted y-coordinate u32 limbs (reversed order, big-endian bytes per limb).
    pub y_limbs: Vec<Target>,
    /// Unpacked byte targets from the slice (need explicit witness filling).
    substring_bytes_with_padding: Vec<Target>,
    // Internal base64 decode targets for witness filling:
    x_b64: Base64DecodeTargets,
    y_b64: Base64DecodeTargets,
}

/// Pack 32 decoded byte targets into 8 u32 limbs (reversed order, big-endian per limb).
///
/// limb[i] = bytes[(7-i)*4]*2^24 + bytes[(7-i)*4+1]*2^16 + bytes[(7-i)*4+2]*2^8 + bytes[(7-i)*4+3]
fn pack_coord_limbs<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    decoded_bytes: &[Target],
) -> Vec<Target> {
    assert_eq!(decoded_bytes.len(), COORD_BYTES);
    let (c256, c65536, c16m) = pack_constants_be(builder);
    (0..COORD_U32_LIMBS)
        .map(|i| {
            let byte_start = (COORD_U32_LIMBS - 1 - i) * 4;
            pack_4_bytes_be(
                builder,
                decoded_bytes[byte_start],
                decoded_bytes[byte_start + 1],
                decoded_bytes[byte_start + 2],
                decoded_bytes[byte_start + 3],
                c256,
                c65536,
                c16m,
            )
        })
        .collect()
}

/// Build the CNF extractor circuit.
///
/// Extracts the `cnf.jwk` block from the decoded JWT JSON payload, decodes the
/// base64url x and y coordinates, and outputs them as u32 limbs suitable for
/// wiring to the owner_pk public inputs.
///
/// `json_len_bytes` is the total padded JSON payload length (must be divisible by 4).
pub fn make_cnf_extractor_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    json_len_bytes: usize,
) -> CnfExtractorTargets {
    assert_eq!(json_len_bytes % 4, 0, "JSON length must be word-aligned");

    // Extract the cnf substring from the decoded JSON via packed array slice.
    let slice_targets = make_array_slice_circuit_packed_u32::<F, D>(
        builder,
        json_len_bytes,
        CNF_SLICE_LEN_WITH_PADDING,
    );

    // Unpack the slice words into individual bytes.
    let substring_bytes_with_padding = unpack_words_to_bytes(builder, &slice_targets.output_packed);

    // Handle byte offset (cnf start might not be word-aligned).
    let offset_one_hot = make_one_hot_indicator(builder, 4, 0);
    let byte_offset = offset_one_hot.value;
    let byte_offset_indicator = offset_one_hot.indicator;

    // Extract CNF_BLOCK_BYTES bytes starting from byte_offset
    let substring_bytes = select_bytes_by_offset(
        builder,
        &substring_bytes_with_padding,
        &byte_offset_indicator,
        CNF_BLOCK_BYTES,
    );

    // Match all constant structural bytes.
    let prefix_bytes = CNF_PREFIX.as_bytes();
    let separator_bytes = CNF_XY_SEPARATOR.as_bytes();
    let closing_bytes = CNF_CLOSING.as_bytes();

    for (j, &expected_byte) in prefix_bytes.iter().enumerate() {
        let expected = builder.constant(F::from_canonical_u32(expected_byte as u32));
        builder.connect(substring_bytes[j], expected);
    }

    let x_start = CNF_PREFIX.len();
    let x_end = x_start + B64URL_COORD_LEN;

    let sep_start = x_end;
    for (j, &expected_byte) in separator_bytes.iter().enumerate() {
        let expected = builder.constant(F::from_canonical_u32(expected_byte as u32));
        builder.connect(substring_bytes[sep_start + j], expected);
    }

    let y_start = sep_start + CNF_XY_SEPARATOR.len();
    let y_end = y_start + B64URL_COORD_LEN;

    let closing_start = y_end;
    for (j, &expected_byte) in closing_bytes.iter().enumerate() {
        let expected = builder.constant(F::from_canonical_u32(expected_byte as u32));
        builder.connect(substring_bytes[closing_start + j], expected);
    }

    // Base64url-decode the x and y coordinates.
    // Reuse the generic base64url decode circuit for each 43-char coordinate.
    // builder.constant() deduplicates, so both calls share the same alphabet table.
    let x_b64 = make_base64url_decode_circuit::<F, D>(builder, B64URL_COORD_LEN);
    let y_b64 = make_base64url_decode_circuit::<F, D>(builder, B64URL_COORD_LEN);

    // Connect the base64 input chars to the substring positions.
    for (b64_in, &char_tgt) in x_b64
        .input_ascii
        .iter()
        .zip(&substring_bytes[x_start..x_end])
    {
        builder.connect(*b64_in, char_tgt);
    }
    for (b64_in, &char_tgt) in y_b64
        .input_ascii
        .iter()
        .zip(&substring_bytes[y_start..y_end])
    {
        builder.connect(*b64_in, char_tgt);
    }

    // Pack decoded bytes into u32 limbs (reversed order, big-endian per limb).
    let x_limbs = pack_coord_limbs(builder, &x_b64.decoded_bytes);
    let y_limbs = pack_coord_limbs(builder, &y_b64.decoded_bytes);

    CnfExtractorTargets {
        slice_targets,
        byte_offset,
        byte_offset_indicator,
        x_limbs,
        y_limbs,
        substring_bytes_with_padding,
        x_b64,
        y_b64,
    }
}

/// Fill witness for the CNF extractor circuit.
///
/// `padded_payload` is the decoded JSON payload zero-padded to `json_len_bytes`.
/// `cnf_start` is the byte offset where the cnf block starts in the payload.
/// `x_b64` and `y_b64` are the base64url-encoded coordinate strings (43 chars each).
pub fn fill_cnf_extractor_witness<F: RichField + Extendable<D>, const D: usize>(
    targets: &CnfExtractorTargets,
    pw: &mut PartialWitness<F>,
    padded_payload: &[u8],
    cnf_start: usize,
    x_b64: &str,
    y_b64: &str,
) -> Result<()> {
    // Fill the packed array slice witness.
    fill_array_slice_witness_packed_u32::<F, D>(
        &targets.slice_targets,
        pw,
        padded_payload,
        cnf_start,
    )?;

    // Fill byte offset (cnf_start % 4).
    let byte_offset_val = cnf_start % 4;
    pw.set_target(
        targets.byte_offset,
        F::from_canonical_usize(byte_offset_val),
    )?;

    // Fill byte offset indicator (one-hot).
    for (i, &tgt) in targets.byte_offset_indicator.iter().enumerate() {
        let val = if i == byte_offset_val {
            F::ONE
        } else {
            F::ZERO
        };
        pw.set_target(tgt, val)?;
    }

    // Fill unpacked byte targets from the slice output.
    let start_word = cnf_start / 4;
    for (byte_idx, &tgt) in targets.substring_bytes_with_padding.iter().enumerate() {
        let abs_byte = start_word * 4 + byte_idx;
        let byte_val = if abs_byte < padded_payload.len() {
            padded_payload[abs_byte]
        } else {
            0
        };
        pw.set_target(tgt, F::from_canonical_u32(byte_val as u32))?;
    }

    // Fill base64url decode witnesses for x and y using the shared base64 witness filler.
    let x_decoded = base64url_decode(x_b64.as_bytes())?;
    let y_decoded = base64url_decode(y_b64.as_bytes())?;
    fill_base64url_decode_witness::<F, D>(&targets.x_b64, pw, x_b64.as_bytes(), &x_decoded)?;
    fill_base64url_decode_witness::<F, D>(&targets.y_b64, pw, y_b64.as_bytes(), &y_decoded)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::cnf::{CNF_BLOCK_LEN, pk_coords_to_base64url};
    use crate::credential::jwt::{generate_dummy_jwt, generate_fixed_jwt_issuer_keypair};
    use plonky2::field::types::{PrimeField, PrimeField64};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_cnf_block_length() {
        let prefix = CNF_PREFIX;
        let sep = CNF_XY_SEPARATOR;
        let closing = CNF_CLOSING;
        let total = prefix.len() + B64URL_COORD_LEN + sep.len() + B64URL_COORD_LEN + closing.len();
        assert_eq!(total, CNF_BLOCK_LEN);
        assert_eq!(total, CNF_BLOCK_BYTES);
        println!("CNF block: {} bytes", total);
        println!("  prefix: {} bytes = {:?}", prefix.len(), prefix);
        println!("  x: {} chars", B64URL_COORD_LEN);
        println!("  separator: {} bytes = {:?}", sep.len(), sep);
        println!("  y: {} chars", B64URL_COORD_LEN);
        println!("  closing: {} bytes = {:?}", closing.len(), closing);
    }

    #[test]
    fn test_cnf_extractor_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, 4, 32)?;

        let cnf_start = jwt.cnf_start;
        let (x_b64, y_b64) = pk_coords_to_base64url(&jwt.cred_pk);

        let min_padded_len = cnf_start + CNF_SLICE_LEN_WITH_PADDING + 4;
        let json_len_bytes = min_padded_len.max(jwt.decoded_payload.len()).div_ceil(4) * 4;
        let mut padded_payload = jwt.decoded_payload.clone();
        padded_payload.resize(json_len_bytes, 0);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_cnf_extractor_circuit::<F, D>(&mut builder, json_len_bytes);

        for &limb in targets.x_limbs.iter().chain(targets.y_limbs.iter()) {
            builder.register_public_input(limb);
        }

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_cnf_extractor_witness::<F, D>(
            &targets,
            &mut pw,
            &padded_payload,
            cnf_start,
            &x_b64,
            &y_b64,
        )?;

        let proof = data.prove(pw)?;
        data.verify(proof.clone())?;

        let pk_x_biguint = jwt.cred_pk.0.x.to_canonical_biguint();
        let pk_y_biguint = jwt.cred_pk.0.y.to_canonical_biguint();
        let x_bytes = {
            let mut b = pk_x_biguint.to_bytes_be();
            while b.len() < 32 {
                b.insert(0, 0);
            }
            b
        };
        let y_bytes = {
            let mut b = pk_y_biguint.to_bytes_be();
            while b.len() < 32 {
                b.insert(0, 0);
            }
            b
        };

        for i in 0..COORD_U32_LIMBS {
            let byte_start = (COORD_U32_LIMBS - 1 - i) * 4;
            let expected = u32::from_be_bytes([
                x_bytes[byte_start],
                x_bytes[byte_start + 1],
                x_bytes[byte_start + 2],
                x_bytes[byte_start + 3],
            ]);
            let actual = proof.public_inputs[i].to_canonical_u64() as u32;
            assert_eq!(actual, expected, "x limb {} mismatch", i);
        }

        for i in 0..COORD_U32_LIMBS {
            let byte_start = (COORD_U32_LIMBS - 1 - i) * 4;
            let expected = u32::from_be_bytes([
                y_bytes[byte_start],
                y_bytes[byte_start + 1],
                y_bytes[byte_start + 2],
                y_bytes[byte_start + 3],
            ]);
            let actual = proof.public_inputs[COORD_U32_LIMBS + i].to_canonical_u64() as u32;
            assert_eq!(actual, expected, "y limb {} mismatch", i);
        }

        println!("CNF extractor test passed: x,y limbs match expected public key");
        Ok(())
    }
}
