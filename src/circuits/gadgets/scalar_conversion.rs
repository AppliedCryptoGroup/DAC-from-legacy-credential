use crate::circuits::gadgets::ecdsa::ECDSACircuitTargets;
#[cfg(test)]
use crate::utils::crypto::byte_array_to_scalar;
use crate::utils::crypto::set_nonnative_target;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
#[cfg(test)]
use plonky2::plonk::circuit_data::CircuitConfig;
#[cfg(test)]
use plonky2::plonk::config::GenericConfig;
#[cfg(test)]
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2_sha256::circuit::array_to_bits;

pub struct DigestToScalarTargets {
    pub digest_bits_targets: Vec<BoolTarget>,
    pub expected_scalar: NonNativeTarget<P256Scalar>,
}

/// Builds a circuit that packs a 32-byte digest into a `P256Scalar`.
///
/// Constrains:
/// - the 256 digest bits correspond to the provided nonnative scalar limbs (little-endian limbs).
pub fn make_digest_to_scalar_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> DigestToScalarTargets {
    let digest_targets: Vec<BoolTarget> = (0..256)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();
    let expected_scalar: NonNativeTarget<P256Scalar> = builder.add_virtual_nonnative_target();

    for limb_idx in 0..8 {
        let mut limb = builder.zero();
        for bit_in_limb in 0..32 {
            let bit = digest_targets[255 - (limb_idx * 32 + bit_in_limb)];

            let coeff = builder.constant(F::from_canonical_u64(1u64 << bit_in_limb));
            let contrib = builder.mul(bit.target, coeff);

            limb = builder.add(limb, contrib);
        }
        builder.connect(limb, expected_scalar.value.limbs[limb_idx].0);
    }

    DigestToScalarTargets {
        digest_bits_targets: digest_targets,
        expected_scalar,
    }
}

pub fn fill_digest_to_scalar_witness<F, const D: usize>(
    circuit: &DigestToScalarTargets,
    pw: &mut PartialWitness<F>,
    digest: &[u8; 32],
    scalar: &P256Scalar,
) -> Result<()>
where
    F: RichField + Extendable<D>,
{
    let digests_targets = &circuit.digest_bits_targets;
    let digest_bits_val = array_to_bits(digest);
    for (t, bit) in digests_targets.iter().zip(digest_bits_val.iter()) {
        pw.set_bool_target(*t, *bit)?;
    }

    set_nonnative_target(pw, &circuit.expected_scalar, *scalar)?;

    Ok(())
}

/// Wire SHA-256 digest bits through DigestToScalar to the ECDSA message scalar.
///
/// Connects hash digest bits to the digest-to-scalar conversion to the ECDSA
/// message scalar.
/// The JWT base circuit uses this wiring to bind its SHA-256 digest to the
/// ECDSA verifier's message scalar.
pub fn wire_digest_to_ecdsa<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    digest_bits: &[BoolTarget],
    digest_to_scalar: &DigestToScalarTargets,
    ecdsa_targets: &ECDSACircuitTargets<P256, P256Scalar>,
) {
    assert_eq!(
        digest_bits.len(),
        digest_to_scalar.digest_bits_targets.len(),
        "digest bit-length mismatch"
    );
    for (h, d) in digest_bits
        .iter()
        .zip(digest_to_scalar.digest_bits_targets.iter())
    {
        builder.connect(h.target, d.target);
    }
    assert_eq!(
        digest_to_scalar.expected_scalar.value.limbs.len(),
        ecdsa_targets.msg.value.limbs.len(),
        "scalar limb-length mismatch"
    );
    for (lhs, rhs) in digest_to_scalar
        .expected_scalar
        .value
        .limbs
        .iter()
        .zip(ecdsa_targets.msg.value.limbs.iter())
    {
        builder.connect(lhs.0, rhs.0);
    }
}

#[test]
fn test_digest_to_scalar_targets_shape() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = make_digest_to_scalar_circuit::<F, D>(&mut builder);

    assert_eq!(targets.digest_bits_targets.len(), 256);
    assert_eq!(targets.expected_scalar.value.limbs.len(), 8);

    let digest = [7u8; 32];
    let scalar = byte_array_to_scalar(&digest)?;
    let mut pw = PartialWitness::new();
    fill_digest_to_scalar_witness::<F, D>(&targets, &mut pw, &digest, &scalar)?;

    Ok(())
}
