use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
#[cfg(test)]
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
#[cfg(test)]
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2_ecdsa::gadgets::ecdsa::{
    ECDSAPublicKeyTarget, ECDSASignatureTarget, verify_p256_message_circuit,
};
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

pub struct ECDSACircuitTargets<C: Curve, P: PrimeField> {
    pub issuer_pk: AffinePointTarget<C>,
    pub msg: NonNativeTarget<P>,
    pub sig: ECDSASignatureTarget<C>,
}

/// Add the ECDSA verification constraints to the circuit builder and return the targets.
/// Registers the issuer public key as public inputs (16 limbs).
pub fn make_ecdsa_circuit<F, Cfg, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ECDSACircuitTargets<P256, P256Scalar>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let msg_target = builder.add_virtual_nonnative_target();
    let r_target = builder.add_virtual_nonnative_target();
    let s_target = builder.add_virtual_nonnative_target();
    let pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
    let sig_target = ECDSASignatureTarget {
        r: r_target,
        s: s_target,
    };

    // Register the issuer public key as public input.
    register_pk_as_pi::<D>(builder, &pk_target);

    verify_p256_message_circuit(
        builder,
        msg_target.clone(),
        sig_target.clone(),
        pk_target.clone(),
    );

    ECDSACircuitTargets {
        issuer_pk: pk_target.0,
        msg: msg_target,
        sig: sig_target,
    }
}

pub(crate) fn register_pk_as_pi<const D: usize>(
    builder: &mut CircuitBuilder<impl RichField + Extendable<D>, D>,
    pk_target: &ECDSAPublicKeyTarget<P256>,
) {
    let limbs_iter = pk_target
        .0
        .x
        .value
        .limbs
        .iter()
        .chain(pk_target.0.y.value.limbs.iter());
    for limb in limbs_iter {
        builder.register_public_input(limb.0);
    }
}

#[test]
pub fn test_ecdsa_public_inputs_count() {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    make_ecdsa_circuit::<F, Cfg, D>(&mut builder);

    // Issuer pk is registered as 16 public input limbs (x||y, 8 each).
    assert_eq!(builder.num_public_inputs(), 16);
}
