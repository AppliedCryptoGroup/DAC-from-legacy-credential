//! Presentation circuit (R_Pres): final stage of the delegation pipeline.
//!
//! Wraps a delegation proof in zero knowledge and selectively discloses any
//! subset of the credential's attributes.
//!
//! The circuit takes the attribute leaf digests as a private witness, recomputes
//! the attribute Merkle commitment in-circuit, and connects it to the commitment
//! of the verified delegation proof. The commitment therefore never becomes a
//! public input and presentations stay unlinkable. Operating on 4-element leaf
//! digests, never raw attribute bytes, keeps R_Pres independent of the attribute
//! width.
//!
//! Disclosure is driven by a per-slot reveal bit: a revealed slot publishes its
//! genuine leaf digest, an unrevealed one the zero leaf. The verifier confirms a
//! claimed attribute by hashing it and matching against the disclosed digest.

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, PartitionWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::plonk::prover::prove_with_partition_witness;
use plonky2::util::timing::TimingTree;

use crate::circuits::delegate::MIN_WIRES_FOR_RECURSION;
use crate::credential::attribute::Attribute;
use crate::utils::merkle::{attribute_to_hashed_leaf, merkle_root_from_leaves};
#[cfg(test)]
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Public wrapper that exposes issuer pk, the disclosed attribute array, and a
/// verifier-supplied challenge nonce, while keeping the delegation proof PIs
/// (incl. commitment, delegation level, and depth cap) private.
pub struct PresentationTargets<const D: usize> {
    /// Public inputs for issuer public key limbs (x||y).
    pub issuer_pk_pis: Vec<Target>,
    /// Public disclosed array: `num_max_attributes` slots, each a 4-element
    /// Poseidon leaf digest, laid out slot-major
    /// (`disclosed_pis[i * NUM_HASH_OUT_ELTS + j]`). A revealed slot holds the
    /// genuine attribute's leaf digest; an unrevealed or redacted slot holds the
    /// zero leaf.
    pub disclosed_pis: Vec<Target>,
    /// Public input for the verifier-supplied challenge nonce (one field element).
    /// Binds the proof to a specific challenge via Plonky2's PI / Fiat-Shamir
    /// mechanism to prevent replay/precomputation. No in-circuit constraint is
    /// needed: a proof produced with `nonce = N1` will not verify against PIs
    /// containing `nonce = N2`.
    pub nonce_pi: Target,
    /// Public inputs for the base-wrapper circuit digest (`NUM_HASH_OUT_ELTS`
    /// elements), copied from the delegation proof. The verifier checks these
    /// against the known `H(vk_Wrap)` of the credential type it expects; keeping
    /// them public (rather than hardcoding an expected value) lets one R_Pres
    /// serve every credential type.
    pub wrapper_digest_pis: Vec<Target>,
    /// Private: per-slot attribute leaf digest (4 elements each). A present
    /// attribute hashes to its digest; an empty or redacted slot is the zero
    /// leaf. `[num_max_attributes][NUM_HASH_OUT_ELTS]`.
    pub leaf_digests: Vec<Vec<Target>>,
    /// Private: per-slot holder's choice to disclose the attribute.
    pub reveal: Vec<BoolTarget>,
    /// Private: the full delegation proof object to be verified inside the wrapper.
    pub inner_delegation_proof: ProofWithPublicInputsTarget<D>,
    /// Index metadata to map public inputs to the inner proof PIs.
    pub issuer_pk_pi_start: usize,
    pub issuer_pk_pi_len: usize,
    /// Merkle tree size / attribute capacity.
    pub num_max_attributes: usize,
}

/// Build the presentation circuit (R_Pres).
///
/// Constrains:
/// - Verifies a delegation proof internally (private), bound in-circuit to the
///   delegation VK, which is hardcoded as a constant (not a public input).
/// - Exposes issuer pk, the disclosed digest array, the verifier nonce, and the
///   base-wrapper circuit digest carried by the delegation proof.
/// - Recomputes the attribute Merkle commitment in-circuit from the per-slot
///   leaf digests (private witness) and connects it to the *private* commitment
///   of the verified delegation proof. The commitment is never a public input.
/// - For each slot, publishes the genuine leaf digest if the holder reveals it,
///   otherwise the zero leaf.
///
/// Public inputs (in order):
/// - issuer pk limbs
/// - disclosed digest array: `num_max_attributes * NUM_HASH_OUT_ELTS` elements, slot-major
/// - verifier-supplied nonce (one field element)
/// - base-wrapper circuit digest (`NUM_HASH_OUT_ELTS` elements); the verifier
///   checks it against the `H(vk_Wrap)` of the credential type it expects
///
/// Neither the delegation level nor the depth cap is a public input; both stay
/// bound inside the verified proof. They are public inputs of R_Del so each step
/// can constrain its parent, but only the delegatee ever sees an R_Del proof.
///
/// # Parameters
///
/// All index/length parameters refer to the delegation proof's public input layout:
///
/// - `delegation_common`: `CommonCircuitData` of the delegation circuit.
/// - `delegation_verifier_only`: `VerifierOnlyCircuitData` of the delegation
///   circuit; its VK is hardcoded into R_Pres so the inner proof is pinned to
///   this exact circuit, not merely to any circuit sharing `delegation_common`.
/// - `issuer_pk_pi_start` / `issuer_pk_pi_len`: PI range for issuer public key limbs.
/// - `com_pi_start` / `com_pi_len`: PI range for the Merkle commitment (4 elements).
/// - `num_max_attributes`: Merkle tree size; the delegation circuit's attribute capacity (nonzero power of two).
/// - `wrapper_digest_pi_start`: PI offset of the base-wrapper circuit digest in the delegation proof.
#[allow(clippy::too_many_arguments)]
pub fn build_presentation_circuit<F, C, const D: usize>(
    delegation_common: &CommonCircuitData<F, D>,
    delegation_verifier_only: &VerifierOnlyCircuitData<C, D>,
    issuer_pk_pi_start: usize,
    issuer_pk_pi_len: usize,
    com_pi_start: usize,
    com_pi_len: usize,
    num_max_attributes: usize,
    wrapper_digest_pi_start: usize,
) -> (CircuitData<F, C, D>, PresentationTargets<D>)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    assert!(
        num_max_attributes.is_power_of_two() && num_max_attributes > 0,
        "num_max_attributes must be a nonzero power of two"
    );

    // ZK-enabled recursion config.
    let mut cfg = CircuitConfig::standard_recursion_zk_config();
    cfg.fri_config.reduction_strategy =
        plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(1, 0);

    cfg.num_wires = cfg.num_wires.max(MIN_WIRES_FOR_RECURSION);
    let mut builder = CircuitBuilder::<F, D>::new(cfg);

    assert!(
        issuer_pk_pi_start + issuer_pk_pi_len <= delegation_common.num_public_inputs,
        "issuer pk inputs exceed delegation proof PI range"
    );
    assert!(
        com_pi_start + com_pi_len <= delegation_common.num_public_inputs && com_pi_len == 4,
        "commitment PIs must be 4 elements within delegation proof PI range"
    );

    // Public issuer pk limbs (x||y).
    let mut issuer_pk_pis = Vec::with_capacity(issuer_pk_pi_len);
    for _ in 0..issuer_pk_pi_len {
        issuer_pk_pis.push(builder.add_virtual_public_input());
    }

    // Reserve the public disclosed digest array (slot-major). Values are filled
    // in from the per-slot disclosure selectors below.
    let disclosed_len = num_max_attributes * NUM_HASH_OUT_ELTS;
    let mut disclosed_pis = Vec::with_capacity(disclosed_len);
    for _ in 0..disclosed_len {
        disclosed_pis.push(builder.add_virtual_public_input());
    }

    // Public verifier-supplied nonce. Binds this proof to a specific
    // challenge via Plonky2's PI / Fiat-Shamir mechanism: a proof generated for
    // nonce N1 will not verify against PIs containing nonce N2. No in-circuit
    // constraint is needed for soundness.
    let nonce_pi = builder.add_virtual_public_input();

    // Public base-wrapper circuit digest. The delegation proof carries this
    // digest unchanged from level 1; it identifies the wrapper, and thereby the
    // credential type. Exposing it as a public input, rather than hardcoding an
    // expected value, lets one R_Pres serve every credential type: the verifier
    // checks it against the known H(vk_Wrap) for the type it expects, exactly as
    // it checks the issuer pk. Connected to the inner proof below.
    let wrapper_digest_pis: Vec<Target> = (0..NUM_HASH_OUT_ELTS)
        .map(|_| builder.add_virtual_public_input())
        .collect();

    // Hardcode the delegation verifier key as an in-circuit constant.
    // Baking the exact VK in (instead of taking it as a public input the verifier
    // must remember to check) pins `inner_delegation_proof` to the genuine
    // delegation circuit: a proof from any look-alike circuit that merely shares
    // `delegation_common` cannot be substituted.
    let delegation_vk = builder.constant_verifier_data::<C>(delegation_verifier_only);

    // Private delegation proof to be verified.
    let inner_delegation_proof = builder.add_virtual_proof_with_pis(delegation_common);

    // Connect public issuer pk to inner proof PIs. Commitment, level and cap
    // are left unconnected, so they stay private witness targets here.
    for (i, &pk) in issuer_pk_pis.iter().enumerate() {
        builder.connect(
            pk,
            inner_delegation_proof.public_inputs[issuer_pk_pi_start + i],
        );
    }

    // Verify the inner delegation proof inside this wrapper, under the hardcoded
    // delegation VK.
    builder.verify_proof::<C>(&inner_delegation_proof, &delegation_vk, delegation_common);

    // Pin the delegation proof's embedded verifier key (carried in its
    // own public inputs for cyclic recursion) to the same constant. This is the
    // in-circuit equivalent of `check_cyclic_proof_verifier_data`: without it the
    // delegation chain could be anchored on a counterfeit verifier key, letting a
    // forged sub-chain slip in beneath a genuine outermost step. The delegation
    // circuit lays its VK out as the final public-input block, right after the
    // base-wrapper digest.
    let vk_pi_start = wrapper_digest_pi_start + NUM_HASH_OUT_ELTS;
    let cap_len = delegation_verifier_only.constants_sigmas_cap.0.len();
    assert_eq!(
        vk_pi_start + NUM_HASH_OUT_ELTS * (1 + cap_len),
        delegation_common.num_public_inputs,
        "delegation VK public-input range does not reach the end of the PI layout"
    );
    let inner_vk = VerifierCircuitTarget {
        circuit_digest: HashOutTarget {
            elements: std::array::from_fn(|j| {
                inner_delegation_proof.public_inputs[vk_pi_start + j]
            }),
        },
        constants_sigmas_cap: MerkleCapTarget(
            (0..cap_len)
                .map(|i| HashOutTarget {
                    elements: std::array::from_fn(|j| {
                        inner_delegation_proof.public_inputs
                            [vk_pi_start + NUM_HASH_OUT_ELTS * (1 + i) + j]
                    }),
                })
                .collect(),
        ),
    };
    builder.connect_verifier_data(&inner_vk, &delegation_vk);

    // Expose the base-wrapper circuit digest carried by the delegation proof on
    // the public inputs reserved above. The verifier matches it
    // against the known H(vk_Wrap) of the credential type it expects. Because the
    // wrapper hardcodes vk_Base (see jwt_wrapper.rs), this digest pins the exact
    // base circuit, and thereby the credential type.
    for j in 0..NUM_HASH_OUT_ELTS {
        builder.connect(
            wrapper_digest_pis[j],
            inner_delegation_proof.public_inputs[wrapper_digest_pi_start + j],
        );
    }

    // Recompute the attribute Merkle commitment and prove selective
    // disclosure. Each slot is witnessed as its 4-element Poseidon leaf digest:
    // a present attribute hashes to its digest, an empty or redacted slot is the
    // canonical zero leaf. This is the exact leaf form the delegation circuit
    // commits to, so R_Pres never touches raw attribute bytes and is independent
    // of the attribute width. A per-slot `reveal` bit is the holder's choice to
    // disclose the slot.
    let mut leaf_digests: Vec<Vec<Target>> = Vec::with_capacity(num_max_attributes);
    let mut reveal: Vec<BoolTarget> = Vec::with_capacity(num_max_attributes);
    for _ in 0..num_max_attributes {
        leaf_digests.push(builder.add_virtual_targets(NUM_HASH_OUT_ELTS));
        reveal.push(builder.add_virtual_bool_target_safe());
    }

    // Recompute the Merkle root from the witnessed leaf digests and connect it
    // to the private commitment carried by the delegation proof.
    // This pins every leaf digest to its committed value by Poseidon collision
    // resistance. The commitment never becomes a public input, which is what
    // preserves unlinkability.
    let recomputed_root = merkle_root_from_leaves::<F, C::Hasher, D>(&mut builder, &leaf_digests);
    for j in 0..NUM_HASH_OUT_ELTS {
        builder.connect(
            recomputed_root.elements[j],
            inner_delegation_proof.public_inputs[com_pi_start + j],
        );
    }

    // Selective disclosure. A revealed slot publishes its leaf digest;
    // an unrevealed slot publishes the zero leaf, which no genuine attribute can
    // hash to. A redacted slot's committed digest is already the zero leaf, so it
    // can never disclose a real attribute regardless of `reveal`. The verifier
    // confirms a claimed attribute `X` for a slot by checking `hash(X)` against
    // the disclosed digest.
    let zero = builder.zero();
    for i in 0..num_max_attributes {
        for j in 0..NUM_HASH_OUT_ELTS {
            let disclosed = builder.select(reveal[i], leaf_digests[i][j], zero);
            builder.connect(disclosed_pis[i * NUM_HASH_OUT_ELTS + j], disclosed);
        }
    }

    let cd = builder.build::<C>();
    let targets = PresentationTargets {
        issuer_pk_pis,
        disclosed_pis,
        nonce_pi,
        wrapper_digest_pis,
        leaf_digests,
        reveal,
        inner_delegation_proof,
        issuer_pk_pi_start,
        issuer_pk_pi_len,
        num_max_attributes,
    };
    (cd, targets)
}

/// Build the `PartialWitness` for a presentation proof, without running the prover.
///
/// `attributes` is the full attribute set at the current delegation level
/// (length `num_max_attributes`); redacted/padding slots must be the
/// `Attribute::empty_marker`. `reveal_mask` (same length) selects which slots the
/// holder discloses.
pub fn build_presentation_witness<F, C, const D: usize>(
    presentation_targets: &PresentationTargets<D>,
    delegation_circuit: &CircuitData<F, C, D>,
    delegation_proof: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    reveal_mask: &[bool],
    nonce: u32,
) -> Result<PartialWitness<F>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    assert!(
        delegation_proof.public_inputs.len() == delegation_circuit.common.num_public_inputs,
        "delegation proof PI length mismatch with delegation circuit"
    );

    if attributes.len() != presentation_targets.num_max_attributes {
        anyhow::bail!(
            "attributes length mismatch: expected {}, got {}",
            presentation_targets.num_max_attributes,
            attributes.len()
        );
    }
    if reveal_mask.len() != presentation_targets.num_max_attributes {
        anyhow::bail!(
            "reveal_mask length mismatch: expected {}, got {}",
            presentation_targets.num_max_attributes,
            reveal_mask.len()
        );
    }

    let mut pw = PartialWitness::<F>::new();

    // 1) Set issuer pk public inputs from the delegation proof.
    for i in 0..presentation_targets.issuer_pk_pi_len {
        pw.set_target(
            presentation_targets.issuer_pk_pis[i],
            delegation_proof.public_inputs[presentation_targets.issuer_pk_pi_start + i],
        )?;
    }

    // 1b) Set per-slot leaf digests and the reveal witness bits. The leaf digest
    // matches the delegation and base circuits: a present attribute hashes to its
    // 4-element digest, an empty marker is the canonical zero leaf.
    for (i, attr) in attributes.iter().enumerate() {
        let leaf = attribute_to_hashed_leaf::<F, C::Hasher>(attr);
        for (tgt, &elem) in presentation_targets.leaf_digests[i].iter().zip(leaf.iter()) {
            pw.set_target(*tgt, elem)?;
        }
        pw.set_bool_target(presentation_targets.reveal[i], reveal_mask[i])?;
    }
    // The disclosed public inputs are not set here: they are `select` outputs
    // connected inside the circuit, so the witness generator fills them.

    // 1c) Set verifier-supplied nonce public input.
    pw.set_target(presentation_targets.nonce_pi, F::from_canonical_u32(nonce))?;

    // 2) Provide the inner delegation proof (private witness).
    pw.set_proof_with_pis_target::<C, D>(
        &presentation_targets.inner_delegation_proof,
        delegation_proof,
    )?;

    // The delegation VK is hardcoded into R_Pres as a constant, so there is no VK
    // witness to set here.

    Ok(pw)
}

/// Produce a presentation proof for a given delegation proof.
/// - Sets the wrapper's public inputs to issuer pk + disclosed array + level + nonce + base-wrapper digest.
/// - Verifies the delegation proof inside, under the delegation VK that
///   `build_presentation_circuit` hardcoded into the circuit.
/// - Recomputes the attribute commitment in-circuit and discloses the slots
///   selected by `reveal_mask`.
/// - The `nonce` is the verifier-supplied 4-byte challenge that binds the proof
///   to a specific challenge for replay protection.
///
/// `attributes` must have length `num_max_attributes` (the delegation circuit's
/// attribute capacity), with redacted/padding slots set to `Attribute::empty_marker`.
/// `reveal_mask` has the same length and selects which slots to disclose.
pub fn prove_presentation<F, C, const D: usize>(
    presentation_circuit: &CircuitData<F, C, D>,
    presentation_targets: &PresentationTargets<D>,
    delegation_circuit: &CircuitData<F, C, D>,
    delegation_proof: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    reveal_mask: &[bool],
    nonce: u32,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let pw = build_presentation_witness::<F, C, D>(
        presentation_targets,
        delegation_circuit,
        delegation_proof,
        attributes,
        reveal_mask,
        nonce,
    )?;
    presentation_circuit.prove(pw)
}

/// Run only the witness-generation stage of a presentation proof.
///
/// Returns a `PartitionWitness` with every wire derived from the supplied
/// inputs (delegation proof, attributes, reveal mask, nonce). The result can be
/// fed into [`prove_presentation_cached`] to produce a proof without rerunning
/// generators.
///
/// The nonce is baked into the partition: the same partition produces proofs
/// whose `nonce_pi` public input is fixed. Use this only when the nonce can be
/// reused across presentations or is not load-bearing for the verifier. For a
/// fresh challenge per proof, fall back to [`prove_presentation`].
pub fn precompute_presentation_partition<'a, F, C, const D: usize>(
    presentation_targets: &PresentationTargets<D>,
    presentation_circuit: &'a CircuitData<F, C, D>,
    delegation_circuit: &CircuitData<F, C, D>,
    delegation_proof: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    reveal_mask: &[bool],
    nonce: u32,
) -> Result<PartitionWitness<'a, F>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let pw = build_presentation_witness::<F, C, D>(
        presentation_targets,
        delegation_circuit,
        delegation_proof,
        attributes,
        reveal_mask,
        nonce,
    )?;
    generate_partial_witness(
        pw,
        &presentation_circuit.prover_only,
        &presentation_circuit.common,
    )
}

/// Produce a presentation proof from a precomputed `PartitionWitness`.
///
/// ZK blinders are sampled inside `prove_with_partition_witness`, so repeated
/// calls with the same partition yield unlinkable proof bytes. The partition is
/// cloned per call (the prover consumes it), which is cheap relative to FRI.
pub fn prove_presentation_cached<F, C, const D: usize>(
    presentation_circuit: &CircuitData<F, C, D>,
    partition: &PartitionWitness<F>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    prove_with_partition_witness(
        &presentation_circuit.prover_only,
        &presentation_circuit.common,
        partition.clone(),
        &mut TimingTree::default(),
    )
}

#[test]
#[should_panic(expected = "num_max_attributes must be a nonzero power of two")]
fn test_presentation_rejects_non_power_of_two_attributes() {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    builder.add_virtual_public_input();
    let dummy = builder.build::<Cfg>();

    // num_max_attributes is validated first; other indices are ignored for this test.
    let _ = build_presentation_circuit::<F, Cfg, D>(
        &dummy.common,
        &dummy.verifier_only,
        0,
        1,
        0,
        4,
        3,
        0,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::delegate::{
        build_delegation_and_wrapper, build_delegation_dummy_proof, prove_delegation_base,
        prove_delegation_step,
    };
    use crate::circuits::jwt_base::{build_jwt_base_circuit, prove_jwt_base};
    use crate::circuits::jwt_wrapper::prove_jwt_wrapper;
    use crate::circuits::layout::HasBaseLayout;
    use crate::credential::jwt::{generate_dummy_jwt, generate_fixed_jwt_issuer_keypair};
    use crate::utils::merkle::mask_attributes;
    use plonky2::field::types::Field;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Full-pipeline soundness test for the multi-attribute presentation circuit.
    ///
    /// Builds base + delegation + presentation circuits, runs a 2-level
    /// delegation chain that redacts one attribute, then proves a presentation
    /// that exercises every disclosure case. Heavy (builds and proves the JWT
    /// base circuit); run with `cargo test --release -- --ignored`.
    ///
    /// Asserts:
    /// - (A) happy path: a revealed slot discloses its genuine leaf digest;
    ///   a withheld slot discloses the zero leaf; a redacted slot discloses the
    ///   zero leaf regardless of `reveal`.
    /// - (B) mutating a disclosed public input breaks verification.
    /// - (C) mutating the nonce public input breaks verification.
    #[test]
    #[ignore = "expensive; run with: cargo test --release -- --ignored"]
    fn test_presentation_selective_disclosure_soundness() -> anyhow::Result<()> {
        const NUM_ATTRS: usize = 4;
        const MAX_VALUE_LEN: usize = 32;
        const NONCE: u32 = 0xCAFE_BABE;

        // Build the pipeline.
        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, NUM_ATTRS, MAX_VALUE_LEN)?;

        // num_max_attributes == NUM_ATTRS: every Merkle leaf is a real claim, no padding.
        let (base_cd, base_targets) =
            build_jwt_base_circuit::<F, C, D>(NUM_ATTRS, MAX_VALUE_LEN, NUM_ATTRS)?;
        let base_layout = base_targets.base_layout();
        let base_proof = prove_jwt_base::<F, C, D>(&base_cd, &base_targets, &jwt, &issuer.pk)?;

        let (del_cd, _del_common, del_targets, wrapper_cd, wrapper_targets) =
            build_delegation_and_wrapper::<F, C, D>(
                base_layout,
                &base_cd.common,
                &base_cd.verifier_only,
            )?;

        let (pres_cd, pres_targets) = build_presentation_circuit::<F, C, D>(
            &del_cd.common,
            &del_cd.verifier_only,
            base_layout.issuer_pk_pi_start,
            base_layout.issuer_pk_pi_len,
            del_targets.com_pi_start,
            del_targets.com_pi_len,
            base_layout.num_max_attributes,
            del_targets.wrapper_digest_pi_start,
        );

        let wrapper_proof =
            prove_jwt_wrapper::<F, C, D>(&wrapper_cd, &wrapper_targets, &base_proof.proof)?;
        let dummy_proof = build_delegation_dummy_proof::<F, C, D>(&del_cd, &del_targets);

        // 2-level delegation chain, redacting slot 0 at level 2.
        let attrs_lvl1 = jwt.attributes.clone();
        let keep_all = vec![true; NUM_ATTRS];
        let del_proof_1 = prove_delegation_base::<F, C, D>(
            &del_cd,
            &del_targets,
            &wrapper_cd,
            &wrapper_proof,
            &dummy_proof,
            &attrs_lvl1,
            &keep_all,
            None,
        )?;

        let mut keep_lvl2 = vec![true; NUM_ATTRS];
        keep_lvl2[0] = false;
        let del_proof_2 = prove_delegation_step::<F, C, D>(
            &del_cd,
            &del_targets,
            &wrapper_cd,
            &dummy_proof,
            &del_proof_1,
            &attrs_lvl1,
            &keep_lvl2,
            None,
        )?;
        let attrs_lvl2 = mask_attributes(&attrs_lvl1, &keep_lvl2)?;
        assert!(attrs_lvl2[0].is_empty(), "slot 0 should be redacted");

        let digest_len = NUM_HASH_OUT_ELTS;
        let zero_leaf = vec![F::ZERO; digest_len];
        let leaf_of = |a: &Attribute| -> Vec<F> {
            attribute_to_hashed_leaf::<F, <C as GenericConfig<D>>::Hasher>(a)
        };

        // (A) Prove a presentation exercising every disclosure case.
        // slot 0: redacted upstream, holder sets reveal=true -> still the zero leaf;
        // slot 1: present + revealed; slot 2: present + withheld; slot 3: present + revealed.
        let reveal_mask = vec![true, true, false, true];
        let pres = prove_presentation::<F, C, D>(
            &pres_cd,
            &pres_targets,
            &del_cd,
            &del_proof_2,
            &attrs_lvl2,
            &reveal_mask,
            NONCE,
        )?;
        pres_cd.verify(pres.clone())?;

        // PI layout: [issuer_pk:16][disclosed:NUM_ATTRS*4][nonce:1][wrapper_digest:4].
        let disclosed_start = base_layout.issuer_pk_pi_len;
        let disclosed =
            &pres.public_inputs[disclosed_start..disclosed_start + NUM_ATTRS * digest_len];

        assert_eq!(
            &disclosed[0..digest_len],
            zero_leaf.as_slice(),
            "a redacted slot must disclose the zero leaf"
        );
        assert_eq!(
            &disclosed[digest_len..2 * digest_len],
            leaf_of(&attrs_lvl2[1]).as_slice(),
            "a revealed slot must disclose its genuine leaf digest"
        );
        assert_eq!(
            &disclosed[2 * digest_len..3 * digest_len],
            zero_leaf.as_slice(),
            "a withheld slot must disclose the zero leaf"
        );
        assert_eq!(
            &disclosed[3 * digest_len..4 * digest_len],
            leaf_of(&attrs_lvl2[3]).as_slice(),
            "a revealed slot must disclose its genuine leaf digest"
        );

        // The base-wrapper digest is exposed so the verifier can confirm the
        // credential type; it must equal H(vk_Wrap) of the chain's wrapper.
        let wd_start = disclosed_start + NUM_ATTRS * digest_len + 1;
        assert_eq!(
            &pres.public_inputs[wd_start..wd_start + NUM_HASH_OUT_ELTS],
            wrapper_cd.verifier_only.circuit_digest.elements.as_slice(),
            "presentation must expose the base-wrapper digest of the chain"
        );

        // (B) Tampered disclosed value fails verification.
        let mut tampered = pres.clone();
        let idx = disclosed_start + digest_len; // first element of slot 1's digest
        tampered.public_inputs[idx] += F::ONE;
        assert!(
            pres_cd.verify(tampered).is_err(),
            "mutating a disclosed public input must break verification"
        );

        // (C) Tampered nonce fails verification.
        let nonce_idx = disclosed_start + NUM_ATTRS * digest_len;
        let mut tampered_nonce = pres.clone();
        tampered_nonce.public_inputs[nonce_idx] += F::ONE;
        assert!(
            pres_cd.verify(tampered_nonce).is_err(),
            "mutating the nonce public input must break verification"
        );

        // (D) Cached-witness path verifies and produces fresh bytes.
        let partition = precompute_presentation_partition::<F, C, D>(
            &pres_targets,
            &pres_cd,
            &del_cd,
            &del_proof_2,
            &attrs_lvl2,
            &reveal_mask,
            NONCE,
        )?;
        let cached_a = prove_presentation_cached::<F, C, D>(&pres_cd, &partition)?;
        let cached_b = prove_presentation_cached::<F, C, D>(&pres_cd, &partition)?;
        pres_cd.verify(cached_a.clone())?;
        pres_cd.verify(cached_b.clone())?;
        assert_eq!(
            cached_a.public_inputs, pres.public_inputs,
            "cached path must yield the same public inputs as the direct path"
        );
        assert_ne!(
            cached_a.proof.openings, cached_b.proof.openings,
            "ZK blinders must differ across cached invocations"
        );

        Ok(())
    }
}
