use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::GenericConfig;
use plonky2_sha256::circuit::{Sha256VarlenTargets, array_to_bits};

/// Add a variable-length SHA-256 circuit that can hash messages up to `max_msg_len_bytes`.
///
/// The circuit processes the maximum number of SHA-256 blocks and uses a one-hot mux
/// to select the correct block's output as the digest. This enables a single circuit
/// to handle any message length from 1 to `max_msg_len_bytes`.
pub fn make_sha256_varlen_circuit<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_msg_len_bytes: usize,
) -> Sha256VarlenTargets
where
    F: RichField + Extendable<D>,
{
    assert!(max_msg_len_bytes > 0, "max_msg_len_bytes must be positive");
    let max_msg_bits = (max_msg_len_bytes * 8) as u64;
    let max_blocks = (max_msg_bits + 65).div_ceil(512) as usize;

    plonky2_sha256::circuit::make_varlen_circuits(builder, max_blocks)
}

/// Fill witness for a variable-length SHA-256 circuit.
///
/// Takes the raw (unpadded) message bytes and the expected digest.
/// Automatically applies SHA-256 padding, computes `num_blocks`, and fills
/// all internal witness targets (block indicator, byte indicator).
pub fn fill_sha256_varlen_circuit_witness<F, Cfg, const D: usize>(
    targets: &Sha256VarlenTargets,
    pw: &mut PartialWitness<F>,
    msg_bytes: &[u8],
    digest_bits: &[bool],
) -> Result<()>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let msg_len = msg_bytes.len();
    let msg_len_bits = (msg_len * 8) as u64;
    let block_count = (msg_len_bits + 65).div_ceil(512) as usize;
    let padded_bit_len = block_count * 512;
    let total_bits = targets.message.len();

    assert!(
        padded_bit_len <= total_bits,
        "message too large: {} padded bits > {} max bits",
        padded_bit_len,
        total_bits
    );
    assert_eq!(digest_bits.len(), 256, "digest must be 256 bits");

    // Build SHA-256-padded message bits.
    let mut padded_bits = array_to_bits(msg_bytes);
    padded_bits.push(true); // 0x80 marker (MSB = 1)
    let zeros_needed = padded_bit_len - (msg_len * 8) - 1 - 64;
    padded_bits.extend(std::iter::repeat_n(false, zeros_needed));
    // 64-bit big-endian length encoding.
    for i in 0..64 {
        padded_bits.push(((msg_len_bits >> (63 - i)) & 1) == 1);
    }
    // Trailing zeros for unused blocks.
    padded_bits.resize(total_bits, false);

    // Fill message bits.
    for (i, &b) in padded_bits.iter().enumerate() {
        pw.set_bool_target(targets.message[i], b)?;
    }

    // Fill digest bits.
    for (i, &b) in digest_bits.iter().enumerate() {
        pw.set_bool_target(targets.digest[i], b)?;
    }

    // Fill num_blocks and msg_len_bytes.
    pw.set_target(targets.num_blocks, F::from_canonical_usize(block_count))?;
    pw.set_target(targets.msg_len_bytes, F::from_canonical_usize(msg_len))?;

    // Fill block_indicator: one-hot for num_blocks (1-indexed), so indicator[block_count-1] = 1.
    for (i, tgt) in targets.block_indicator.iter().enumerate() {
        let val = if i + 1 == block_count {
            F::ONE
        } else {
            F::ZERO
        };
        pw.set_target(*tgt, val)?;
    }

    // Fill msg_byte_indicator: one-hot for msg_len_bytes, so indicator[msg_len] = 1.
    for (p, tgt) in targets.msg_byte_indicator.iter().enumerate() {
        let val = if p == msg_len { F::ONE } else { F::ZERO };
        pw.set_target(*tgt, val)?;
    }

    // The SHA-256 padding constraints reuse the shared `msg_byte_indicator`;
    // they add no virtual targets, so no further witness values are needed.

    Ok(())
}
