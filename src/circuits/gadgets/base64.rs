use anyhow::Result;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Auxiliary split targets for a base64 group (4 chars -> 3 bytes).
/// These need explicit witness values since plonky2 can't auto-generate them.
struct GroupSplitTargets {
    v1_hi2: Target,
    v1_lo4: Target,
    v2_hi4: Target,
    v2_lo2: Target,
}

/// Auxiliary split targets for a 2-char remainder group.
struct Remainder2SplitTargets {
    v1_hi2: Target,
    v1_lo4: Target,
}

/// Auxiliary split targets for a 3-char remainder group.
struct Remainder3SplitTargets {
    v1_hi2: Target,
    v1_lo4: Target,
    v2_hi4: Target,
    v2_lo2: Target,
}

/// Targets for a Base64url decode circuit.
pub struct Base64DecodeTargets {
    /// Input: Base64url ASCII byte targets.
    pub input_ascii: Vec<Target>,
    /// Output: decoded raw byte targets.
    pub decoded_bytes: Vec<Target>,
    /// Private witness: 6-bit values for each input character.
    sixbit_values: Vec<Target>,
    /// Auxiliary: split targets for full groups.
    group_splits: Vec<GroupSplitTargets>,
    /// Auxiliary: split targets for remainder (if any).
    remainder2_splits: Option<Remainder2SplitTargets>,
    remainder3_splits: Option<Remainder3SplitTargets>,
}

/// Build a Base64url decode sub-circuit.
///
/// The circuit constrains:
/// 1. Each 6-bit witness value is in range [0, 64) via range check.
/// 2. Re-encoding each 6-bit value to Base64url ASCII matches the input byte (via lookup table).
/// 3. Groups of 4 × 6-bit values pack into 3 decoded bytes.
pub fn make_base64url_decode_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    encoded_len: usize,
) -> Base64DecodeTargets {
    assert!(encoded_len > 0, "encoded_len must be positive");
    let full_groups = encoded_len / 4;
    let remainder = encoded_len % 4;
    let decoded_len = full_groups * 3
        + match remainder {
            0 => 0,
            2 => 1,
            3 => 2,
            _ => panic!("invalid Base64url encoded length (remainder 1 is not valid)"),
        };

    let input_ascii: Vec<Target> = (0..encoded_len)
        .map(|_| builder.add_virtual_target())
        .collect();

    let decoded_bytes: Vec<Target> = (0..decoded_len)
        .map(|_| builder.add_virtual_target())
        .collect();

    let sixbit_values: Vec<Target> = (0..encoded_len)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Build a constant lookup table: BASE64URL_TABLE[v] = ASCII char for 6-bit value v.
    let table: Vec<Target> = BASE64URL_ALPHABET
        .iter()
        .map(|&ch| builder.constant(F::from_canonical_u32(ch as u32)))
        .collect();

    // For each input character: range-check v, look up expected ASCII, connect to input.
    for i in 0..encoded_len {
        let v = sixbit_values[i];
        let ascii = input_ascii[i];

        builder.range_check(v, 6); // v in [0, 64)
        let expected = builder.random_access(v, table.clone());
        builder.connect(ascii, expected);
    }

    // Full groups: 4 chars -> 3 bytes.
    let mut group_splits = Vec::with_capacity(full_groups);
    let sixteen = builder.constant(F::from_canonical_u32(16));
    let four = builder.constant(F::from_canonical_u32(4));
    let sixty_four = builder.constant(F::from_canonical_u32(64));

    for g in 0..full_groups {
        let v0 = sixbit_values[g * 4];
        let v1 = sixbit_values[g * 4 + 1];
        let v2 = sixbit_values[g * 4 + 2];
        let v3 = sixbit_values[g * 4 + 3];
        let b0 = decoded_bytes[g * 3];
        let b1 = decoded_bytes[g * 3 + 1];
        let b2 = decoded_bytes[g * 3 + 2];

        // Split v1 = v1_hi2 * 16 + v1_lo4
        let v1_hi2 = builder.add_virtual_target();
        let v1_lo4 = builder.add_virtual_target();
        let recomposed_v1 = builder.mul_add(v1_hi2, sixteen, v1_lo4);
        builder.connect(v1, recomposed_v1);
        builder.range_check(v1_hi2, 2);
        builder.range_check(v1_lo4, 4);

        // Split v2 = v2_hi4 * 4 + v2_lo2
        let v2_hi4 = builder.add_virtual_target();
        let v2_lo2 = builder.add_virtual_target();
        let recomposed_v2 = builder.mul_add(v2_hi4, four, v2_lo2);
        builder.connect(v2, recomposed_v2);
        builder.range_check(v2_hi4, 4);
        builder.range_check(v2_lo2, 2);

        // b0 = v0 * 4 + v1_hi2
        let expected_b0 = builder.mul_add(v0, four, v1_hi2);
        builder.connect(b0, expected_b0);

        // b1 = v1_lo4 * 16 + v2_hi4
        let expected_b1 = builder.mul_add(v1_lo4, sixteen, v2_hi4);
        builder.connect(b1, expected_b1);

        // b2 = v2_lo2 * 64 + v3
        let expected_b2 = builder.mul_add(v2_lo2, sixty_four, v3);
        builder.connect(b2, expected_b2);

        group_splits.push(GroupSplitTargets {
            v1_hi2,
            v1_lo4,
            v2_hi4,
            v2_lo2,
        });
    }

    // Handle remainder.
    let mut remainder2_splits = None;
    let mut remainder3_splits = None;

    if remainder == 2 {
        let v0 = sixbit_values[full_groups * 4];
        let v1 = sixbit_values[full_groups * 4 + 1];
        let b0 = decoded_bytes[full_groups * 3];

        let v1_hi2 = builder.add_virtual_target();
        let v1_lo4 = builder.add_virtual_target();
        let recomposed = builder.mul_add(v1_hi2, sixteen, v1_lo4);
        builder.connect(v1, recomposed);
        builder.range_check(v1_hi2, 2);
        builder.range_check(v1_lo4, 4);

        let expected_b0 = builder.mul_add(v0, four, v1_hi2);
        builder.connect(b0, expected_b0);

        // v1_lo4 must be 0 (padding bits in the last base64 group).
        let zero = builder.zero();
        builder.connect(v1_lo4, zero);

        remainder2_splits = Some(Remainder2SplitTargets { v1_hi2, v1_lo4 });
    } else if remainder == 3 {
        let v0 = sixbit_values[full_groups * 4];
        let v1 = sixbit_values[full_groups * 4 + 1];
        let v2 = sixbit_values[full_groups * 4 + 2];
        let b0 = decoded_bytes[full_groups * 3];
        let b1 = decoded_bytes[full_groups * 3 + 1];

        let v1_hi2 = builder.add_virtual_target();
        let v1_lo4 = builder.add_virtual_target();
        let recomposed_v1 = builder.mul_add(v1_hi2, sixteen, v1_lo4);
        builder.connect(v1, recomposed_v1);
        builder.range_check(v1_hi2, 2);
        builder.range_check(v1_lo4, 4);

        let expected_b0 = builder.mul_add(v0, four, v1_hi2);
        builder.connect(b0, expected_b0);

        let v2_hi4 = builder.add_virtual_target();
        let v2_lo2 = builder.add_virtual_target();
        let recomposed_v2 = builder.mul_add(v2_hi4, four, v2_lo2);
        builder.connect(v2, recomposed_v2);
        builder.range_check(v2_hi4, 4);
        builder.range_check(v2_lo2, 2);

        let expected_b1 = builder.mul_add(v1_lo4, sixteen, v2_hi4);
        builder.connect(b1, expected_b1);

        // v2_lo2 must be 0 (padding bits in the last base64 group).
        let zero = builder.zero();
        builder.connect(v2_lo2, zero);

        remainder3_splits = Some(Remainder3SplitTargets {
            v1_hi2,
            v1_lo4,
            v2_hi4,
            v2_lo2,
        });
    }

    Base64DecodeTargets {
        input_ascii,
        decoded_bytes,
        sixbit_values,
        group_splits,
        remainder2_splits,
        remainder3_splits,
    }
}

/// Base64url alphabet: maps 6-bit index to ASCII character.
pub const BASE64URL_ALPHABET: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Fill witness for the base64url decode circuit.
pub fn fill_base64url_decode_witness<F: RichField + Extendable<D>, const D: usize>(
    targets: &Base64DecodeTargets,
    pw: &mut PartialWitness<F>,
    encoded_ascii: &[u8],
    decoded_bytes: &[u8],
) -> Result<()> {
    if encoded_ascii.len() != targets.input_ascii.len() {
        anyhow::bail!(
            "encoded length mismatch: expected {}, got {}",
            targets.input_ascii.len(),
            encoded_ascii.len()
        );
    }
    if decoded_bytes.len() != targets.decoded_bytes.len() {
        anyhow::bail!(
            "decoded length mismatch: expected {}, got {}",
            targets.decoded_bytes.len(),
            decoded_bytes.len()
        );
    }

    // Set input ASCII targets.
    for (tgt, &byte) in targets.input_ascii.iter().zip(encoded_ascii.iter()) {
        pw.set_target(*tgt, F::from_canonical_u32(byte as u32))?;
    }

    // Set decoded byte targets.
    for (tgt, &byte) in targets.decoded_bytes.iter().zip(decoded_bytes.iter()) {
        pw.set_target(*tgt, F::from_canonical_u32(byte as u32))?;
    }

    // Compute and set 6-bit values.
    let sixbit_vals: Vec<u8> = encoded_ascii
        .iter()
        .map(|&c| base64url_char_to_value(c))
        .collect::<Result<Vec<_>>>()?;
    for (tgt, &val) in targets.sixbit_values.iter().zip(sixbit_vals.iter()) {
        pw.set_target(*tgt, F::from_canonical_u32(val as u32))?;
    }

    // Set split targets for full groups.
    for (g, splits) in targets.group_splits.iter().enumerate() {
        let v1 = sixbit_vals[g * 4 + 1] as u32;
        let v2 = sixbit_vals[g * 4 + 2] as u32;
        pw.set_target(splits.v1_hi2, F::from_canonical_u32(v1 >> 4))?;
        pw.set_target(splits.v1_lo4, F::from_canonical_u32(v1 & 0xF))?;
        pw.set_target(splits.v2_hi4, F::from_canonical_u32(v2 >> 2))?;
        pw.set_target(splits.v2_lo2, F::from_canonical_u32(v2 & 0x3))?;
    }

    // Set split targets for remainder.
    let full_groups = encoded_ascii.len() / 4;
    if let Some(ref splits) = targets.remainder2_splits {
        let v1 = sixbit_vals[full_groups * 4 + 1] as u32;
        pw.set_target(splits.v1_hi2, F::from_canonical_u32(v1 >> 4))?;
        pw.set_target(splits.v1_lo4, F::from_canonical_u32(v1 & 0xF))?;
    }
    if let Some(ref splits) = targets.remainder3_splits {
        let v1 = sixbit_vals[full_groups * 4 + 1] as u32;
        let v2 = sixbit_vals[full_groups * 4 + 2] as u32;
        pw.set_target(splits.v1_hi2, F::from_canonical_u32(v1 >> 4))?;
        pw.set_target(splits.v1_lo4, F::from_canonical_u32(v1 & 0xF))?;
        pw.set_target(splits.v2_hi4, F::from_canonical_u32(v2 >> 2))?;
        pw.set_target(splits.v2_lo2, F::from_canonical_u32(v2 & 0x3))?;
    }

    Ok(())
}

/// Decode a Base64url ASCII character to its 6-bit value.
pub fn base64url_char_to_value(c: u8) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => anyhow::bail!("invalid Base64url character: {}", c as char),
    }
}

/// Off-circuit Base64url decoding (no padding).
pub fn base64url_decode(encoded: &[u8]) -> Result<Vec<u8>> {
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
    let s = std::str::from_utf8(encoded)?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64url decode: {}", e))
}

/// Off-circuit Base64url encoding (no padding).
pub fn base64url_encode(data: &[u8]) -> Vec<u8> {
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_base64url_decode_circuit_small() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // "AQID" decodes to [1, 2, 3] (4 chars -> 3 bytes)
        let encoded = b"AQID";
        let decoded = base64url_decode(encoded)?;
        assert_eq!(decoded, vec![1, 2, 3]);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_base64url_decode_circuit::<F, D>(&mut builder, encoded.len());
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_base64url_decode_witness::<F, D>(&targets, &mut pw, encoded, &decoded)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_base64url_all_chars() {
        for v in 0u8..64 {
            let expected = match v {
                0..=25 => b'A' + v,
                26..=51 => b'a' + (v - 26),
                52..=61 => b'0' + (v - 52),
                62 => b'-',
                63 => b'_',
                _ => unreachable!(),
            };
            let decoded_back = base64url_char_to_value(expected).unwrap();
            assert_eq!(decoded_back, v, "roundtrip failed for value {v}");
        }
    }
}
