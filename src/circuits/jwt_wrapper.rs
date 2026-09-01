//! JWT wrapper circuit `R_Wrap`: the adapter stage of the delegation pipeline.
//!
//! `R_Wrap` verifies the JWT base proof against `CCD_Base` and re-exposes its public
//! inputs under a new proof whose `CommonCircuitData` matches that of the
//! delegation circuit `R_Del`. The delegation circuit can then verify wrapper
//! proofs (at level 1) and its own cyclic proofs (at level > 1) with a single
//! in-circuit verifier.
//!
//! This adapter is what lets one delegation circuit serve many credential
//! types: `R_Del` and `R_Pres` are co-built once with the first credential
//! type (see [`build_delegation_and_wrapper`](crate::circuits::delegate::build_delegation_and_wrapper)),
//! and every further credential type joins by supplying only a matching
//! wrapper, built against the existing `R_Del` via [`build_jwt_wrapper_circuit`].

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::circuits::delegate::MIN_WIRES_FOR_RECURSION;

/// Targets for the base-wrapper circuit witness.
pub struct JwtWrapperTargets<const D: usize> {
    /// The base proof to verify inside the wrapper.
    pub base_proof: ProofWithPublicInputsTarget<D>,
    /// The forwarded base public inputs.
    pub outer_pis: Vec<Target>,
    /// Verifier data exposed as public inputs (for cyclic compatibility).
    pub verifier_data_target: VerifierCircuitTarget,
    /// Number of base public inputs (excluding VK PIs).
    pub base_pi_count: usize,
    /// Dummy PIs matching the delegation circuit's wrapper_digest PI slots.
    /// Not constrained in the wrapper; exist only to match the PI count.
    pub wrapper_digest_pis: Vec<Target>,
}

/// Build the base-wrapper circuit `R_Wrap` against a target `CommonCircuitData`.
///
/// This is how a credential type attaches to a delegation circuit: it compiles
/// the wrapper with `cyclic_common` as its build goal and reports whether the
/// result matches (`Ok`) or needs gate types `R_Del` lacks (`Mismatch`). The
/// initial co-build [`build_delegation_and_wrapper`](crate::circuits::delegate::build_delegation_and_wrapper)
/// uses a `Mismatch` to drive its gate-registration step; once `R_Del` is
/// fixed, every further credential type's wrapper is expected to return `Ok`.
///
/// `base_common`: `CommonCircuitData` of the base circuit `R_Base`.
/// `base_verifier_only`: `VerifierOnlyCircuitData` of `R_Base`. Its VK is
/// hardcoded into the wrapper, so the wrapper's circuit digest commits to the
/// exact base circuit (not merely to `base_common`, the base circuit's shape).
/// `cyclic_common`: `CommonCircuitData` of the delegation circuit (build goal).
pub fn build_jwt_wrapper_circuit<F, C, const D: usize>(
    base_common: &CommonCircuitData<F, D>,
    base_verifier_only: &VerifierOnlyCircuitData<C, D>,
    cyclic_common: &CommonCircuitData<F, D>,
) -> JwtWrapperBuildResult<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut cfg = CircuitConfig::standard_recursion_zk_config();
    cfg.num_wires = cfg.num_wires.max(MIN_WIRES_FOR_RECURSION);
    let mut builder = CircuitBuilder::<F, D>::new(cfg);

    // Pre-populate the gate set with the delegation's gates so the gate ordering
    // in CommonCircuitData matches exactly. Gates added later by verify_proof
    // will already be present and won't change the order.
    for gate in &cyclic_common.gates {
        builder.add_gate_to_gate_set(gate.clone());
    }

    // Register base public inputs (same count as the base circuit).
    let base_pi_count = base_common.num_public_inputs;
    let mut outer_pis = Vec::with_capacity(base_pi_count);
    for _ in 0..base_pi_count {
        outer_pis.push(builder.add_virtual_public_input());
    }

    // Add dummy PIs for the wrapper_digest slot (matches the delegation
    // circuit's PI layout: base PIs, wrapper_digest, VK PIs). These are
    // unconstrained in the wrapper; they exist only so that num_public_inputs
    // matches the delegation circuit's CommonCircuitData.
    let wrapper_digest_pis: Vec<Target> = (0..NUM_HASH_OUT_ELTS)
        .map(|_| builder.add_virtual_public_input())
        .collect();

    // Add verifier data as public inputs (matches the delegation circuit's PI
    // layout: base PIs followed by VK PIs).
    let verifier_data_target = builder.add_verifier_data_public_inputs();

    // Add the base proof target and verify it under the hardcoded base VK.
    // Baking the VK in (instead of taking it as a free witness) makes the
    // wrapper's circuit digest depend on the exact base circuit, so the wrapper
    // digest carried through the delegation chain genuinely pins the credential
    // type, not merely the base circuit's `CommonCircuitData` shape, which a
    // constraint-free look-alike circuit would also satisfy.
    let base_proof = builder.add_virtual_proof_with_pis(base_common);
    let base_vk = builder.constant_verifier_data::<C>(base_verifier_only);
    builder.verify_proof::<C>(&base_proof, &base_vk, base_common);

    // Connect forwarded PIs to the base proof's PIs.
    for i in 0..base_pi_count {
        builder.connect(outer_pis[i], base_proof.public_inputs[i]);
    }

    // No manual NoopGate padding: ZK blinding (~8K gates) plus plonky2's
    // auto-padding to the next power of two are enough to reach the target
    // degree. Manual padding risks overshooting the boundary.

    // Set the goal and build.
    let mut goal = cyclic_common.clone();
    goal.num_public_inputs = builder.num_public_inputs();
    builder.set_goal_common_data(goal);

    let (cd, success) = builder.try_build_with_options::<C>(true);
    if !success {
        return JwtWrapperBuildResult::Mismatch(cd.common);
    }

    JwtWrapperBuildResult::Ok(
        cd,
        JwtWrapperTargets {
            base_proof,
            outer_pis,
            verifier_data_target,
            base_pi_count,
            wrapper_digest_pis,
        },
    )
}

/// Result of attempting to build the base-wrapper circuit.
#[allow(clippy::large_enum_variant)]
pub enum JwtWrapperBuildResult<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Success: wrapper `CommonCircuitData` matches `cyclic_common`.
    Ok(CircuitData<F, C, D>, JwtWrapperTargets<D>),
    /// Mismatch: the wrapper's `CommonCircuitData` differs from the target.
    /// Contains the wrapper's actual common data so the caller can extract
    /// extra gates and rebuild the delegation circuit.
    Mismatch(CommonCircuitData<F, D>),
}

/// Produce a base-wrapper proof that wraps a base proof.
pub fn prove_jwt_wrapper<F, C, const D: usize>(
    wrapper_circuit: &CircuitData<F, C, D>,
    wrapper_targets: &JwtWrapperTargets<D>,
    base_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut pw = PartialWitness::new();

    // Set base PIs from the base proof.
    for i in 0..wrapper_targets.base_pi_count {
        pw.set_target(wrapper_targets.outer_pis[i], base_proof.public_inputs[i])?;
    }

    // Set the base proof. The base VK is hardcoded into the wrapper as a
    // constant, so there is no VK witness to set.
    pw.set_proof_with_pis_target::<C, D>(&wrapper_targets.base_proof, base_proof)?;

    // Set wrapper_digest dummy PIs (unconstrained in wrapper, but needed for PI count).
    for (j, tgt) in wrapper_targets.wrapper_digest_pis.iter().enumerate() {
        pw.set_target(
            *tgt,
            wrapper_circuit.verifier_only.circuit_digest.elements[j],
        )?;
    }

    // Set the wrapper circuit's own VK as public inputs.
    pw.set_verifier_data_target(
        &wrapper_targets.verifier_data_target,
        &wrapper_circuit.verifier_only,
    )?;

    wrapper_circuit.prove(pw)
}
