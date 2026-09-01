use anyhow::Result;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::make_one_hot_indicator;

/// Targets for an array slicing circuit.
///
/// Given an input byte array of length `max_array_len`, extracts a contiguous slice
/// of length `max_slice_len` starting at a witness-provided index.
///
/// Uses the indicator-vector approach from the zkLogin paper: for each output
/// position `j`, compute `output[j] = sum_i(indicator[i] * array[i + j])` where
/// `indicator` is a one-hot vector with a 1 at the start index.
pub struct ArraySliceTargets {
    /// Input: byte array as field elements.
    pub array: Vec<Target>,
    /// Witness: start index (field element, must be in [0, max_array_len - max_slice_len]).
    pub start_idx: Target,
    /// Output: the extracted slice (max_slice_len elements).
    pub output: Vec<Target>,
    /// Private: one-hot indicator vector.
    indicator: Vec<Target>,
}

/// Build an array slicing sub-circuit.
///
/// The circuit constrains:
/// 1. `indicator` is a valid one-hot vector (exactly one 1, rest 0s).
/// 2. `indicator[start_idx] == 1`.
/// 3. `output[j] = sum_i(indicator[i] * array[i + j])` for each j in [0, max_slice_len).
///
/// Constraint cost: O(valid_starts * max_slice_len) multiplications.
pub fn make_array_slice_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_array_len: usize,
    max_slice_len: usize,
) -> ArraySliceTargets {
    assert!(
        max_slice_len <= max_array_len,
        "slice length cannot exceed array length"
    );
    assert!(max_array_len > 0 && max_slice_len > 0);

    // Number of valid start positions: the slice of length max_slice_len
    // can start at indices 0..=(max_array_len - max_slice_len).
    let valid_starts = max_array_len - max_slice_len + 1;

    let array: Vec<Target> = (0..max_array_len)
        .map(|_| builder.add_virtual_target())
        .collect();

    let start_idx = builder.add_virtual_target();

    let output: Vec<Target> = (0..max_slice_len)
        .map(|_| builder.add_virtual_target())
        .collect();

    // One-hot indicator: indicator[i] = 1 iff i == start_idx.
    let one_hot = make_one_hot_indicator(builder, valid_starts, 0);
    let indicator = one_hot.indicator;
    builder.connect(one_hot.value, start_idx);

    // Constrain output: output[j] = sum_i(indicator[i] * array[i + j]).
    for j in 0..max_slice_len {
        let mut dot = builder.zero();
        for i in 0..valid_starts {
            let contrib = builder.mul(indicator[i], array[i + j]);
            dot = builder.add(dot, contrib);
        }
        builder.connect(output[j], dot);
    }

    ArraySliceTargets {
        array,
        start_idx,
        output,
        indicator,
    }
}

/// Targets for u32-packed array slicing (4 bytes per word).
///
/// This is an optimized variant that operates on u32-packed words instead of individual bytes,
/// reducing the constraint cost by ~4x following the zkLogin paper approach.
pub struct PackedArraySliceTargets {
    /// Input: u32-packed array (each target represents 4 bytes in big-endian).
    pub packed_array: Vec<Target>,
    /// Witness: start index in BYTES (not words).
    pub start_idx_bytes: Target,
    /// Output: packed u32 words from the slice.
    pub output_packed: Vec<Target>,
    /// Private: one-hot indicator for word-aligned start positions.
    indicator: Vec<Target>,
    /// Word-level start index (derived from start_idx_bytes / 4).
    start_idx_words: Target,
}

/// Build a u32-packed array slicing sub-circuit.
///
/// Similar to `make_array_slice_circuit` but operates on u32 words (4 bytes each) instead
/// of individual bytes. This reduces constraint count by ~4x for large arrays.
///
/// Requirements:
/// - `max_array_len_bytes` must be divisible by 4
/// - `max_slice_len_bytes` must be divisible by 4
/// - Witness `start_idx_bytes` must be word-aligned (divisible by 4)
///
/// Constraint cost: O(valid_starts_words * max_slice_len_words) multiplications
/// where valid_starts_words = (max_array_len_bytes / 4) - (max_slice_len_bytes / 4) + 1
pub fn make_array_slice_circuit_packed_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_array_len_bytes: usize,
    max_slice_len_bytes: usize,
) -> PackedArraySliceTargets {
    assert_eq!(
        max_array_len_bytes % 4,
        0,
        "array length must be divisible by 4 for u32 packing"
    );
    assert_eq!(
        max_slice_len_bytes % 4,
        0,
        "slice length must be divisible by 4 for u32 packing"
    );
    assert!(
        max_slice_len_bytes <= max_array_len_bytes,
        "slice length cannot exceed array length"
    );
    assert!(max_array_len_bytes > 0 && max_slice_len_bytes > 0);

    let max_array_len_words = max_array_len_bytes / 4;
    let max_slice_len_words = max_slice_len_bytes / 4;
    let valid_starts_words = max_array_len_words - max_slice_len_words + 1;

    // Create packed array targets (u32 words)
    let packed_array: Vec<Target> = (0..max_array_len_words)
        .map(|_| builder.add_virtual_target())
        .collect();

    let start_idx_bytes = builder.add_virtual_target();

    // Derive word-level start index: start_idx_words = start_idx_bytes / 4
    // Constraint: start_idx_bytes = start_idx_words * 4
    let four = builder.constant(F::from_canonical_u32(4));
    let start_idx_words = builder.add_virtual_target();
    let reconstructed = builder.mul(start_idx_words, four);
    builder.connect(start_idx_bytes, reconstructed);

    // Output packed words
    let output_packed: Vec<Target> = (0..max_slice_len_words)
        .map(|_| builder.add_virtual_target())
        .collect();

    // One-hot indicator for word-level start positions
    let one_hot = make_one_hot_indicator(builder, valid_starts_words, 0);
    let indicator = one_hot.indicator;
    builder.connect(one_hot.value, start_idx_words);

    // Constrain output: output_packed[j] = sum_i(indicator[i] * packed_array[i + j])
    for j in 0..max_slice_len_words {
        let mut dot = builder.zero();
        for i in 0..valid_starts_words {
            let contrib = builder.mul(indicator[i], packed_array[i + j]);
            dot = builder.add(dot, contrib);
        }
        builder.connect(output_packed[j], dot);
    }

    PackedArraySliceTargets {
        packed_array,
        start_idx_bytes,
        output_packed,
        indicator,
        start_idx_words,
    }
}

/// Fill witness for the packed u32 array slice circuit.
///
/// Packs the input byte array into u32 words (big-endian) and fills all witness targets.
///
/// Requirements:
/// - `bytes.len()` must equal `targets.packed_array.len() * 4`
/// - `start_bytes` will be rounded down to the nearest word boundary (divisible by 4)
///
/// If `start_bytes` is not word-aligned it is rounded down, so the caller must
/// handle any byte-level offset when unpacking the output.
pub fn fill_array_slice_witness_packed_u32<F: RichField + Extendable<D>, const D: usize>(
    targets: &PackedArraySliceTargets,
    pw: &mut PartialWitness<F>,
    bytes: &[u8],
    start_bytes: usize,
) -> Result<()> {
    let max_array_len_words = targets.packed_array.len();
    let max_slice_len_words = targets.output_packed.len();

    // Validate byte array length
    if bytes.len() != max_array_len_words * 4 {
        anyhow::bail!(
            "byte array length mismatch: expected {}, got {}",
            max_array_len_words * 4,
            bytes.len()
        );
    }

    // Round down start_bytes to word boundary
    let start_bytes_aligned = (start_bytes / 4) * 4;

    let start_words = start_bytes_aligned / 4;
    let valid_starts_words = max_array_len_words - max_slice_len_words + 1;

    if start_words >= valid_starts_words {
        anyhow::bail!(
            "start index {} (from byte {}) out of range [0, {})",
            start_words,
            start_bytes,
            valid_starts_words
        );
    }

    // Pack bytes into u32 words (big-endian: matches existing attribute packing)
    for (word_idx, tgt) in targets.packed_array.iter().enumerate() {
        let byte_start = word_idx * 4;
        let word_val = u32::from_be_bytes([
            bytes[byte_start],
            bytes[byte_start + 1],
            bytes[byte_start + 2],
            bytes[byte_start + 3],
        ]);
        pw.set_target(*tgt, F::from_canonical_u32(word_val))?;
    }

    // Set byte-level start index (aligned)
    pw.set_target(
        targets.start_idx_bytes,
        F::from_canonical_usize(start_bytes_aligned),
    )?;

    // Set word-level start index
    pw.set_target(
        targets.start_idx_words,
        F::from_canonical_usize(start_words),
    )?;

    // Set output packed words
    for (j, tgt) in targets.output_packed.iter().enumerate() {
        let byte_start = (start_words + j) * 4;
        let word_val = u32::from_be_bytes([
            bytes[byte_start],
            bytes[byte_start + 1],
            bytes[byte_start + 2],
            bytes[byte_start + 3],
        ]);
        pw.set_target(*tgt, F::from_canonical_u32(word_val))?;
    }

    // Set indicator (one-hot at start_words)
    for (i, tgt) in targets.indicator.iter().enumerate() {
        let val = if i == start_words { F::ONE } else { F::ZERO };
        pw.set_target(*tgt, val)?;
    }

    Ok(())
}

/// Fill witness for the array slice circuit.
pub fn fill_array_slice_witness<F: RichField + Extendable<D>, const D: usize>(
    targets: &ArraySliceTargets,
    pw: &mut PartialWitness<F>,
    array: &[u8],
    start: usize,
) -> Result<()> {
    let max_array_len = targets.array.len();
    let max_slice_len = targets.output.len();
    let valid_starts = max_array_len - max_slice_len + 1;

    if array.len() != max_array_len {
        anyhow::bail!(
            "array length mismatch: expected {}, got {}",
            max_array_len,
            array.len()
        );
    }
    if start >= valid_starts {
        anyhow::bail!("start index {} out of range [0, {})", start, valid_starts);
    }

    // Set array targets.
    for (tgt, &byte) in targets.array.iter().zip(array.iter()) {
        pw.set_target(*tgt, F::from_canonical_u32(byte as u32))?;
    }

    // Set start index.
    pw.set_target(targets.start_idx, F::from_canonical_usize(start))?;

    // Set output targets.
    for (j, tgt) in targets.output.iter().enumerate() {
        pw.set_target(*tgt, F::from_canonical_u32(array[start + j] as u32))?;
    }

    // Set indicator (one-hot at start).
    for (i, tgt) in targets.indicator.iter().enumerate() {
        let val = if i == start { F::ONE } else { F::ZERO };
        pw.set_target(*tgt, val)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_array_slice_basic() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let array: Vec<u8> = (0..20).collect();
        let start = 5;
        let slice_len = 4;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_array_slice_circuit::<F, D>(&mut builder, array.len(), slice_len);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_array_slice_witness::<F, D>(&targets, &mut pw, &array, start)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_array_slice_start_zero() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let array: Vec<u8> = vec![10, 20, 30, 40, 50];
        let start = 0;
        let slice_len = 3;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_array_slice_circuit::<F, D>(&mut builder, array.len(), slice_len);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_array_slice_witness::<F, D>(&targets, &mut pw, &array, start)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_packed_array_slice_basic() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // 80 bytes = 20 u32 words
        let bytes: Vec<u8> = (0..80).collect();
        let start_bytes = 16; // word-aligned (word index 4)
        let slice_len_bytes = 16; // 4 u32 words

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets =
            make_array_slice_circuit_packed_u32::<F, D>(&mut builder, bytes.len(), slice_len_bytes);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_array_slice_witness_packed_u32::<F, D>(&targets, &mut pw, &bytes, start_bytes)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_packed_array_slice_start_zero() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // 40 bytes = 10 u32 words
        let bytes: Vec<u8> = (0..40).collect();
        let start_bytes = 0; // word-aligned
        let slice_len_bytes = 12; // 3 u32 words

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets =
            make_array_slice_circuit_packed_u32::<F, D>(&mut builder, bytes.len(), slice_len_bytes);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_array_slice_witness_packed_u32::<F, D>(&targets, &mut pw, &bytes, start_bytes)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_packed_array_slice_end() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // 60 bytes = 15 u32 words
        let bytes: Vec<u8> = (0..60).collect();
        let start_bytes = 44; // word-aligned (word index 11), last valid start for 4-word slice
        let slice_len_bytes = 16; // 4 u32 words

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets =
            make_array_slice_circuit_packed_u32::<F, D>(&mut builder, bytes.len(), slice_len_bytes);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        fill_array_slice_witness_packed_u32::<F, D>(&targets, &mut pw, &bytes, start_bytes)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }
}
