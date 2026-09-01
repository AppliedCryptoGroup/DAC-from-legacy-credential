//! Cyclic delegation circuit (R_Del): third stage of the delegation pipeline.
//!
//! Uses a single conditional cyclic verifier that accepts either a previous
//! delegation proof (when `L > 1`) or a base-wrapper proof (when `L == 1`).
//! Both proof types share the same `CommonCircuitData`, reducing the number
//! of in-circuit verifiers from two to one.

use crate::circuits::jwt_wrapper::{
    JwtWrapperBuildResult, JwtWrapperTargets, build_jwt_wrapper_circuit,
};
use crate::circuits::layout::{BasePublicInputLayout, MAX_LEVEL_BITS};
use crate::credential::attribute::Attribute;
use crate::utils::merkle::{
    attribute_to_hashed_leaf, compute_merkle_root, mask_attributes, merkle_root_from_leaves,
    pad_attributes,
};
use anyhow::Result;
use hashbrown::HashMap;
use plonky2::field::extension::Extendable;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

/// Minimum `num_wires` for circuits that verify a recursive proof.
///
/// Plonky2's `verify_proof` gadget needs at least this many wires internally.
/// The standard recursion config already satisfies it, but the wrapper and
/// presentation circuits set it explicitly so they match the delegation
/// circuit's shape even if the default config changes.
pub const MIN_WIRES_FOR_RECURSION: usize = 136;

/// Build the fixed-point `CommonCircuitData` the cyclic delegation circuit
/// verifies against.
///
/// Repeatedly building a circuit that verifies a proof of itself converges on a
/// stable `CommonCircuitData`; this performs enough passes to reach that fixed
/// point and returns it as the seed shape for [`build_delegation_circuit`].
fn common_data_for_recursion<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_zk_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_zk_config();
    let num_consts = config.num_constants;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(num_consts)));
    builder.build::<C>().common
}

/// Targets we need to fill witnesses for proving.
pub struct DelegationTargets<const D: usize> {
    pub outer_pis: Vec<Target>,
    pub base_pi_count: usize,
    pub level_idx: usize,     // position of the delegation level in pis
    pub max_level_idx: usize, // position of the delegation depth cap in pis
    pub com_pi_start: usize,
    pub com_pi_len: usize,
    pub attr_targets: Vec<Vec<Target>>,
    pub attribute_mask: Vec<BoolTarget>,

    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget, // VK for recursion circuit (as PIs)

    pub wrapper_proof: ProofWithPublicInputsTarget<D>,
    pub wrapper_vk: VerifierCircuitTarget, // VK for base-wrapper circuit (private)

    pub wrapper_digest_pi_start: usize,
    pub wrapper_digest_pis: Vec<Target>,
}

/// Build the delegation circuit (R_Del).
///
/// Uses a single conditional cyclic verifier that accepts either:
/// - a previous delegation proof (when `L > 1`), or
/// - a base-wrapper proof wrapping the base proof (when `L == 1`).
///
/// Both proof types share the same `CommonCircuitData`, which is the key
/// enabler: one `verify_proof` call instead of two.
///
/// Constrains:
/// - Verifies either the wrapper proof (if `L == 1`) or the previous delegation proof (if `L > 1`).
/// - Enforces `L' = L_prev + 1` (level increments every step).
/// - Enforces `L' <= maxLevel' <= maxLevel_prev` (the depth cap binds this step
///   and may be tightened but never loosened).
/// - Recomputes `com_prev = MerkleRoot(tilde_a_1..tilde_a_n)` and matches it to the previous proof.
/// - Computes masked attributes: `a'_i = b[i] ? tilde_a_i : EMPTY_MARKER`.
/// - Outputs `com_next = MerkleRoot(a'_1..a'_n)` as the commitment for the new proof.
/// - Forwards all other public inputs unchanged.
///
/// No delegatee authentication is performed: the delegation proof itself is the
/// capability, so anyone holding a level-N proof can produce a level-(N+1) proof.
///
/// Public inputs match the base circuit shape:
/// - issuer pk limbs
/// - commitment `com_next`
/// - level `L'`
/// - depth cap `maxLevel'`
///
/// `base_pi_count` is derived from `base_layout.base_pi_count()`.
pub fn build_delegation_circuit<F, C, const D: usize>(
    base_layout: BasePublicInputLayout,
    extra_gates: &[GateRef<F, D>],
) -> (
    CircuitData<F, C, D>,
    CommonCircuitData<F, D>,
    DelegationTargets<D>,
)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let seed_common = common_data_for_recursion::<F, C, D>();
    let (trial_cd, _, _) =
        build_delegation_circuit_with_common::<F, C, D>(base_layout, &seed_common, extra_gates);
    let cyclic_common = trial_cd.common.clone();
    let (cd, targets, _) =
        build_delegation_circuit_with_common::<F, C, D>(base_layout, &cyclic_common, extra_gates);
    assert_eq!(
        cd.common, cyclic_common,
        "delegation circuit failed to converge"
    );
    (cd, cyclic_common, targets)
}

fn build_delegation_circuit_with_common<F, C, const D: usize>(
    base_layout: BasePublicInputLayout,
    cyclic_common: &CommonCircuitData<F, D>,
    extra_gates: &[GateRef<F, D>],
) -> (CircuitData<F, C, D>, DelegationTargets<D>, bool)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut cfg = CircuitConfig::standard_recursion_zk_config();
    cfg.num_wires = cfg.num_wires.max(MIN_WIRES_FOR_RECURSION);
    let mut builder = CircuitBuilder::<F, D>::new(cfg);

    // Pre-add any extra gate types that the base-wrapper circuit needs (e.g.
    // ExponentiationGate for FRI verification of larger proofs).  This
    // ensures both circuits share the same gate set in CommonCircuitData.
    for gate in extra_gates {
        builder.add_gate_to_gate_set(gate.clone());
    }

    // Public input layout (must match the base circuit).
    let base_pi_count = base_layout.base_pi_count();
    let level_idx = base_layout.level_pi_idx;
    let max_level_idx = base_layout.max_level_pi_idx;
    assert_eq!(
        max_level_idx,
        level_idx + 1,
        "depth cap must be the last base PI, directly after the level"
    );
    let com_pi_start = base_layout.com_pi_start;
    let com_pi_len = base_layout.com_pi_len;
    // Delegation circuit sizing is driven by `num_max_attributes`. The real
    // `num_attributes` count travels in the base layout but does not shape this
    // circuit: padding slots witness empty leaves and their mask bits are
    // forced false at prove time.
    let num_max_attributes = base_layout.num_max_attributes;
    let attribute_len_bytes = base_layout.attribute_len_bytes;

    // Expose outer public inputs (forwarded except com/level).
    let mut outer_pis = Vec::with_capacity(base_pi_count);
    for _ in 0..base_pi_count {
        outer_pis.push(builder.add_virtual_public_input());
    }
    let level = outer_pis[level_idx];

    // Expose the base-wrapper circuit digest as public inputs (4 field elements).
    // In the base case this is constrained to wrapper_vk.circuit_digest;
    // in recursive steps it is forwarded unchanged from the inner proof.
    let wrapper_digest_pi_start = builder.num_public_inputs();
    let wrapper_digest_pis: Vec<Target> = (0..NUM_HASH_OUT_ELTS)
        .map(|_| builder.add_virtual_public_input())
        .collect();

    // Expose the recursion VK as public inputs (needed for cyclic recursion).
    let verifier_data_target = builder.add_verifier_data_public_inputs();

    // Common data for the recursive (inner) proof: must match this outer shape.
    let mut cyclic_common = cyclic_common.clone();
    cyclic_common.num_public_inputs = builder.num_public_inputs();

    // Proof targets. Both use the same CommonCircuitData; the base-wrapper
    // circuit is built to match.
    // - inner: previous delegation proof (same shape as this circuit)
    // - wrapper: base-wrapper proof wrapping the base proof (same shape)
    let inner = builder.add_virtual_proof_with_pis(&cyclic_common);
    let wrapper = builder.add_virtual_proof_with_pis(&cyclic_common);
    let wrapper_vk = builder.add_virtual_verifier_data(cyclic_common.config.fri_config.cap_height);

    // Select which branch to verify based on `L == 1` (base step).
    let one = builder.one();
    let is_base = builder.is_equal(level, one);
    let not_base = builder.not(is_base);

    // Forward PIs from wrapper vs inner, except com/level/max_level. Level and
    // cap are the last two base PIs, so the loop bound already excludes them.
    for i in 0..level_idx {
        if (com_pi_start..com_pi_start + com_pi_len).contains(&i) {
            continue;
        }
        let selected = builder.select(is_base, wrapper.public_inputs[i], inner.public_inputs[i]);
        builder.connect(outer_pis[i], selected);
    }

    // Level rule `L' = L_prev + 1`.
    let prev_level = builder.select(
        is_base,
        wrapper.public_inputs[level_idx],
        inner.public_inputs[level_idx],
    );
    let expected_level = builder.add(prev_level, one);
    builder.connect(level, expected_level);

    // Depth-cap rule `L' <= maxLevel' <= maxLevel_prev`: the cap only tightens,
    // and the chain stops once the level reaches it.
    //
    // Each comparison is a range check on a difference: for byte-wide values
    // `a - b` stays in range exactly when `b <= a`, and wraps near the modulus
    // otherwise. Range-checking `max_level` bounds `level` too, via the first
    // difference, so wraparound cannot push a level past its cap.
    let max_level = outer_pis[max_level_idx];
    let prev_max_level = builder.select(
        is_base,
        wrapper.public_inputs[max_level_idx],
        inner.public_inputs[max_level_idx],
    );
    builder.range_check(max_level, MAX_LEVEL_BITS);
    let cap_headroom = builder.sub(max_level, level);
    builder.range_check(cap_headroom, MAX_LEVEL_BITS);
    let cap_tightening = builder.sub(prev_max_level, max_level);
    builder.range_check(cap_tightening, MAX_LEVEL_BITS);

    // Single conditional proof verification.
    // - When not_base (L > 1): verify inner (cyclic proof), check VK match.
    // - When is_base  (L == 1): verify wrapper proof with wrapper_vk.
    builder
        .conditionally_verify_cyclic_proof::<C>(
            not_base,
            &inner,
            &wrapper,
            &wrapper_vk,
            &cyclic_common,
        )
        .unwrap();

    // Constrain the base-wrapper circuit digest.
    // Base case (L=1): must equal wrapper_vk.circuit_digest (binds the wrapper identity).
    // Recursive (L>1): forwarded from the inner (previous delegation) proof.
    for j in 0..NUM_HASH_OUT_ELTS {
        let from_vk = wrapper_vk.circuit_digest.elements[j];
        let from_inner = inner.public_inputs[wrapper_digest_pi_start + j];
        let selected = builder.select(is_base, from_vk, from_inner);
        builder.connect(wrapper_digest_pis[j], selected);
    }

    // Private attribute hashes and mask.
    // Attributes are pre-hashed to 4-element Poseidon digests, making the delegation
    // circuit independent of the raw attribute size.
    let mut attr_targets = Vec::with_capacity(num_max_attributes);
    let mut attribute_mask = Vec::with_capacity(num_max_attributes);
    for _ in 0..num_max_attributes {
        attr_targets.push(builder.add_virtual_targets(NUM_HASH_OUT_ELTS));
        attribute_mask.push(builder.add_virtual_bool_target_safe());
    }

    // Recompute `com_prev` and match it to the previous proof.
    let com_prev = merkle_root_from_leaves::<F, C::Hasher, D>(&mut builder, &attr_targets);
    for i in 0..com_pi_len {
        let wrapper_com = wrapper.public_inputs[com_pi_start + i];
        let inner_com = inner.public_inputs[com_pi_start + i];
        let selected_prev = builder.select(is_base, wrapper_com, inner_com);
        builder.connect(com_prev.elements[i], selected_prev);
    }

    // Compute masked attributes.
    //
    // The empty leaf is the canonical zero leaf `[F::ZERO; NUM_HASH_OUT_ELTS]`,
    // independent of `attribute_len_bytes`. The same constant is emitted by the
    // base circuit's padding (see jwt_base.rs) and by off-circuit `attribute_to_hashed_leaf`
    // for empty markers (see utils/merkle.rs), so one delegation circuit serves
    // credential types whose real attributes pack into different widths.
    let _ = attribute_len_bytes; // kept on layout for the base-side use; unused here.
    let zero = builder.zero();
    let empty_hash_tgts: Vec<Target> = (0..NUM_HASH_OUT_ELTS).map(|_| zero).collect();
    let mut masked_attrs = Vec::with_capacity(num_max_attributes);
    for (attr_hash, b) in attr_targets.iter().zip(attribute_mask.iter()) {
        let masked = attr_hash
            .iter()
            .zip(empty_hash_tgts.iter())
            .map(|(h, empty_h)| builder.select(*b, *h, *empty_h))
            .collect::<Vec<_>>();
        masked_attrs.push(masked);
    }

    // Compute `com_next` and expose it as the commitment for this step.
    let com_next = merkle_root_from_leaves::<F, C::Hasher, D>(&mut builder, &masked_attrs);
    for i in 0..com_pi_len {
        builder.connect(outer_pis[com_pi_start + i], com_next.elements[i]);
    }

    let (cd, success) = builder.try_build_with_options::<C>(true);

    let targets = DelegationTargets {
        outer_pis,
        wrapper_proof: wrapper,
        inner_proof: inner,
        level_idx,
        max_level_idx,
        base_pi_count,
        com_pi_start,
        com_pi_len,
        attr_targets,
        attribute_mask,
        verifier_data_target,
        wrapper_vk,
        wrapper_digest_pi_start,
        wrapper_digest_pis,
    };
    (cd, targets, success)
}

/// Build a delegation dummy proof (used for the base step's inner branch).
pub fn build_delegation_dummy_proof<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
) -> ProofWithPublicInputs<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut overrides: HashMap<usize, F> = HashMap::new();
    overrides.insert(del_targets.level_idx, F::ZERO);
    cyclic_base_proof::<F, C, D>(&del_circuit.common, &del_circuit.verifier_only, overrides)
}

/// Fill witness with hashed attribute leaves (4 elements each).
///
/// Empty markers are written as the canonical zero leaf (matches
/// `attribute_to_hashed_leaf` in `utils/merkle.rs` and the base circuit's
/// padding leaves).
fn fill_hashed_attribute_witness<F, H, const D: usize>(
    pw: &mut PartialWitness<F>,
    attr_targets: &[Vec<Target>],
    attributes: &[Attribute],
) -> Result<()>
where
    F: RichField + Extendable<D>,
    H: Hasher<F, Hash = HashOut<F>>,
{
    if attr_targets.len() != attributes.len() {
        anyhow::bail!(
            "attribute count mismatch: targets={}, values={}",
            attr_targets.len(),
            attributes.len()
        );
    }
    for (attr_tgts, attr) in attr_targets.iter().zip(attributes.iter()) {
        let leaf = attribute_to_hashed_leaf::<F, H>(attr);
        for (tgt, &elem) in attr_tgts.iter().zip(leaf.iter()) {
            pw.set_target(*tgt, elem)?;
        }
    }
    Ok(())
}

fn fill_attribute_mask_witness<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    attribute_mask: &[BoolTarget],
    bitmap: &[bool],
) -> Result<()> {
    if attribute_mask.len() != bitmap.len() {
        anyhow::bail!(
            "bitmap length mismatch: targets={}, values={}",
            attribute_mask.len(),
            bitmap.len()
        );
    }
    for (tgt, bit) in attribute_mask.iter().zip(bitmap.iter()) {
        pw.set_bool_target(*tgt, *bit)?;
    }
    Ok(())
}

/// Resolve the cap for the step producing `level_next`, given the parent's cap.
///
/// `None` inherits it unchanged. The circuit enforces the same
/// `level' <= maxLevel' <= maxLevel`; checking here only buys a readable error.
fn resolve_depth_cap(max_level: Option<u8>, level_next: u64, prev_max_level: u64) -> Result<u64> {
    let cap = max_level.map_or(prev_max_level, u64::from);
    if cap > prev_max_level {
        anyhow::bail!(
            "depth cap {cap} exceeds the inherited cap {prev_max_level}: \
             a delegator may tighten the cap but never loosen it"
        );
    }
    if level_next > cap {
        anyhow::bail!(
            "delegating to level {level_next} would exceed the depth cap {cap}: \
             this credential cannot be delegated further"
        );
    }
    Ok(cap)
}

/// Prove the *base* outer step (level == 1).
/// - Verifies the base-wrapper proof (the cyclic inner branch is a dummy).
/// - Sets `com_1` as the new commitment for the first delegation step.
///
/// `max_level` caps the credential handed on: `None` leaves it uncapped,
/// `Some(1)` blocks re-delegation outright.
#[allow(clippy::too_many_arguments)]
pub fn prove_delegation_base<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    wrapper_circuit: &CircuitData<F, C, D>,
    wrapper_proof: &ProofWithPublicInputs<F, C, D>,
    del_proof_dummy: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    bitmap: &[bool],
    max_level: Option<u8>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let cap_next = resolve_depth_cap(
        max_level,
        wrapper_proof.public_inputs[del_targets.level_idx].to_canonical_u64() + 1,
        wrapper_proof.public_inputs[del_targets.max_level_idx].to_canonical_u64(),
    )?;
    prove_delegation_base_with_cap(
        del_circuit,
        del_targets,
        wrapper_circuit,
        wrapper_proof,
        del_proof_dummy,
        attributes,
        bitmap,
        cap_next,
    )
}

/// [`prove_delegation_base`] with the cap resolved and *unchecked*.
///
/// Split out so the tests can push a bad cap past the guard and watch the
/// circuit reject it.
#[allow(clippy::too_many_arguments)]
fn prove_delegation_base_with_cap<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    wrapper_circuit: &CircuitData<F, C, D>,
    wrapper_proof: &ProofWithPublicInputs<F, C, D>,
    del_proof_dummy: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    bitmap: &[bool],
    cap_next: u64,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let base_pi_count = del_targets.base_pi_count;
    let num_max_attributes = del_targets.attr_targets.len();

    // The wrapper proof has cyclic_common PIs; read only the base slice.
    let mut next_pis = wrapper_proof.public_inputs[..base_pi_count].to_vec();
    next_pis[del_targets.level_idx] += F::ONE;
    next_pis[del_targets.max_level_idx] = F::from_canonical_u64(cap_next);
    // Pad real-attribute inputs up to the delegation circuit's attribute
    // capacity. Padding slots get empty_marker attributes and mask=false, so the
    // masked leaf is the canonical empty leaf either way, matching the padding
    // leaves the base circuit emitted.
    let padded_attrs = pad_attributes(attributes, num_max_attributes)?;
    let mut padded_bitmap = bitmap.to_vec();
    padded_bitmap.resize(num_max_attributes, false);
    let masked_attrs = mask_attributes(&padded_attrs, &padded_bitmap)?;
    let com_next = compute_merkle_root::<F, C::Hasher>(&masked_attrs)?;
    for i in 0..del_targets.com_pi_len {
        next_pis[del_targets.com_pi_start + i] = com_next.elements[i];
    }

    let mut pw = PartialWitness::new();
    for i in 0..base_pi_count {
        pw.set_target(del_targets.outer_pis[i], next_pis[i])?;
    }
    // Set wrapper circuit digest PIs (constrained to wrapper_vk.circuit_digest in base case).
    for (j, tgt) in del_targets.wrapper_digest_pis.iter().enumerate() {
        pw.set_target(
            *tgt,
            wrapper_circuit.verifier_only.circuit_digest.elements[j],
        )?;
    }
    fill_hashed_attribute_witness::<F, C::Hasher, D>(
        &mut pw,
        &del_targets.attr_targets,
        &padded_attrs,
    )?;
    fill_attribute_mask_witness::<F, D>(&mut pw, &del_targets.attribute_mask, &padded_bitmap)?;

    // inner = dummy cyclic proof (carries correct VK for the connect check)
    pw.set_proof_with_pis_target::<C, D>(&del_targets.inner_proof, del_proof_dummy)?;
    // wrapper = real base-wrapper proof
    pw.set_proof_with_pis_target::<C, D>(&del_targets.wrapper_proof, wrapper_proof)?;
    pw.set_verifier_data_target(
        &del_targets.verifier_data_target,
        &del_circuit.verifier_only,
    )?;
    pw.set_verifier_data_target(&del_targets.wrapper_vk, &wrapper_circuit.verifier_only)?;

    del_circuit.prove(pw)
}

/// Prove a *recursive* delegation step (level > 1).
/// - Verifies the previous delegation proof and enforces `L' = L_prev + 1`.
///   The wrapper branch is dummy here; pass a precomputed `wrapper_dummy`.
///
/// `max_level` caps the credential handed on; `None` inherits the parent's cap.
#[allow(clippy::too_many_arguments)]
pub fn prove_delegation_step<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    wrapper_circuit: &CircuitData<F, C, D>,
    wrapper_dummy: &ProofWithPublicInputs<F, C, D>,
    prev_del_proof: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    bitmap: &[bool],
    max_level: Option<u8>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let cap_next = resolve_depth_cap(
        max_level,
        prev_del_proof.public_inputs[del_targets.level_idx].to_canonical_u64() + 1,
        prev_del_proof.public_inputs[del_targets.max_level_idx].to_canonical_u64(),
    )?;
    prove_delegation_step_with_cap(
        del_circuit,
        del_targets,
        wrapper_circuit,
        wrapper_dummy,
        prev_del_proof,
        attributes,
        bitmap,
        cap_next,
    )
}

/// [`prove_delegation_step`] with the cap resolved and *unchecked*.
///
/// See [`prove_delegation_base_with_cap`].
#[allow(clippy::too_many_arguments)]
fn prove_delegation_step_with_cap<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    wrapper_circuit: &CircuitData<F, C, D>,
    wrapper_dummy: &ProofWithPublicInputs<F, C, D>,
    prev_del_proof: &ProofWithPublicInputs<F, C, D>,
    attributes: &[Attribute],
    bitmap: &[bool],
    cap_next: u64,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    // Only the OUTER PIs (not the VK PIs)
    let base_pi_count = del_targets.base_pi_count;
    let lvl_idx = del_targets.level_idx;
    let num_max_attributes = del_targets.attr_targets.len();

    // Forward all outer PIs; increment delegation level and update commitment.
    let mut next_pis = prev_del_proof.public_inputs[..base_pi_count].to_vec();
    next_pis[lvl_idx] += F::ONE;
    next_pis[del_targets.max_level_idx] = F::from_canonical_u64(cap_next);
    let padded_attrs = pad_attributes(attributes, num_max_attributes)?;
    let mut padded_bitmap = bitmap.to_vec();
    padded_bitmap.resize(num_max_attributes, false);
    let masked_attrs = mask_attributes(&padded_attrs, &padded_bitmap)?;
    let com_next = compute_merkle_root::<F, C::Hasher>(&masked_attrs)?;
    for i in 0..del_targets.com_pi_len {
        next_pis[del_targets.com_pi_start + i] = com_next.elements[i];
    }

    let mut pw = PartialWitness::new();
    for i in 0..base_pi_count {
        pw.set_target(del_targets.outer_pis[i], next_pis[i])?;
    }
    // Forward wrapper circuit digest from previous delegation proof.
    for (j, tgt) in del_targets.wrapper_digest_pis.iter().enumerate() {
        pw.set_target(
            *tgt,
            prev_del_proof.public_inputs[del_targets.wrapper_digest_pi_start + j],
        )?;
    }
    fill_hashed_attribute_witness::<F, C::Hasher, D>(
        &mut pw,
        &del_targets.attr_targets,
        &padded_attrs,
    )?;
    fill_attribute_mask_witness::<F, D>(&mut pw, &del_targets.attribute_mask, &padded_bitmap)?;

    // inner = real previous delegation proof; wrapper = dummy (unused)
    pw.set_proof_with_pis_target::<C, D>(&del_targets.inner_proof, prev_del_proof)?;
    pw.set_proof_with_pis_target::<C, D>(&del_targets.wrapper_proof, wrapper_dummy)?;
    pw.set_verifier_data_target(
        &del_targets.verifier_data_target,
        &del_circuit.verifier_only,
    )?;
    pw.set_verifier_data_target(&del_targets.wrapper_vk, &wrapper_circuit.verifier_only)?;

    let proof = del_circuit.prove(pw)?;
    Ok(proof)
}

/// Co-build the delegation circuit `R_Del` with the first credential type's
/// wrapper `R_Wrap`.
///
/// This establishes the delegation circuit. `R_Del` is reused unmodified for
/// every subsequent credential type, each of which attaches by supplying only
/// its own wrapper via [`build_jwt_wrapper_circuit`].
///
/// The wrapper may require gate types `R_Del` does not naturally produce (e.g.
/// an `ExponentiationGate` for FRI verification of the larger base proof), so
/// the two circuits are co-built iteratively:
///
/// 1. Build `R_Del` with no extra gates.
/// 2. Build `R_Wrap` against `R_Del`'s `CommonCircuitData`.
/// 3. On mismatch, register the extra gate types in `R_Del`, rebuild it, retry.
///
/// A single iteration suffices: registering a gate type only extends the gate
/// set without changing the circuit logic.
///
/// Returns `(del_cd, del_common, del_targets, wrapper_cd, wrapper_targets)`.
#[allow(clippy::type_complexity)]
pub fn build_delegation_and_wrapper<F, C, const D: usize>(
    base_layout: BasePublicInputLayout,
    base_common: &CommonCircuitData<F, D>,
    base_verifier_only: &VerifierOnlyCircuitData<C, D>,
) -> Result<(
    CircuitData<F, C, D>,
    CommonCircuitData<F, D>,
    DelegationTargets<D>,
    CircuitData<F, C, D>,
    JwtWrapperTargets<D>,
)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let (del_cd, del_common, del_targets) = build_delegation_circuit::<F, C, D>(base_layout, &[]);

    match build_jwt_wrapper_circuit::<F, C, D>(base_common, base_verifier_only, &del_common) {
        JwtWrapperBuildResult::Ok(cd, tgts) => Ok((del_cd, del_common, del_targets, cd, tgts)),
        JwtWrapperBuildResult::Mismatch(wrapper_common) => {
            let extra_gates: Vec<_> = wrapper_common
                .gates
                .iter()
                .filter(|g| !del_common.gates.contains(g))
                .cloned()
                .collect();
            let (del_cd, del_common, del_targets) =
                build_delegation_circuit::<F, C, D>(base_layout, &extra_gates);
            match build_jwt_wrapper_circuit::<F, C, D>(base_common, base_verifier_only, &del_common)
            {
                JwtWrapperBuildResult::Ok(cd, tgts) => {
                    Ok((del_cd, del_common, del_targets, cd, tgts))
                }
                JwtWrapperBuildResult::Mismatch(_) => {
                    anyhow::bail!(
                        "base-wrapper CommonCircuitData still mismatches after adding extra gates"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_delegation_and_wrapper, build_delegation_dummy_proof, prove_delegation_base,
        prove_delegation_step, prove_delegation_step_with_cap,
    };
    use crate::circuits::jwt_base::{
        build_jwt_base_circuit, build_jwt_base_circuit_with_keys, prove_jwt_base,
    };
    use crate::circuits::jwt_wrapper::{
        JwtWrapperBuildResult, build_jwt_wrapper_circuit, prove_jwt_wrapper,
    };
    use crate::circuits::layout::{HasBaseLayout, LEVEL_UNBOUNDED};
    use crate::credential::jwt::{generate_dummy_jwt, generate_fixed_jwt_issuer_keypair};
    use anyhow::Result;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use std::time::Instant;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// One delegation circuit serves many JWT credential types.
    ///
    /// Each credential type still needs its own freshly-built wrapper `R_Wrap`,
    /// but once `R_Del` is co-built (with a reference type), every further
    /// type's wrapper must compile against the *existing* `R_Del`
    /// `CommonCircuitData`: `build_jwt_wrapper_circuit` returns `Ok`, not
    /// `Mismatch`, so attaching a credential type never rebuilds `R_Del`.
    #[test]
    #[ignore = "expensive; run with: cargo test --release -- --ignored"]
    fn delegation_ccd_serves_multiple_jwt_types() -> Result<()> {
        let ref_keys = ["iss", "iat", "exp", "sub"];
        let ref_max_value_len = 64;
        let ref_num_max_attributes = 4;

        let t = Instant::now();
        let (ref_base, ref_targets) = build_jwt_base_circuit_with_keys::<F, C, D>(
            &ref_keys,
            ref_max_value_len,
            ref_num_max_attributes,
        )?;
        println!(
            "reference base built in {:.1?}, degree_bits = {}",
            t.elapsed(),
            ref_base.common.degree_bits()
        );

        let t = Instant::now();
        let (_, del_common, _, _, _) = build_delegation_and_wrapper::<F, C, D>(
            ref_targets.base_layout(),
            &ref_base.common,
            &ref_base.verifier_only,
        )?;
        println!(
            "reference delegation co-built in {:.1?}, del_common.degree_bits = {}",
            t.elapsed(),
            del_common.degree_bits()
        );

        let keys_8 = generate_claim_keys(8);
        let keys_16 = generate_claim_keys(16);
        let variants: &[(&[&str], usize, usize, &str)] = &[
            (&ref_keys, 128, 4, "same keys, larger max_value_len"),
            (
                &["alg", "typ", "kid", "cty"],
                64,
                4,
                "different keys, same claim count",
            ),
            (&ref_keys, 32, 4, "same keys, smaller max_value_len"),
            (&keys_8.refs(), 64, 8, "8-claim credential type"),
            (&keys_16.refs(), 64, 16, "16-claim credential type"),
        ];

        for (keys, max_value_len, num_max_attributes, label) in variants {
            let t = Instant::now();
            let (base, _) = build_jwt_base_circuit_with_keys::<F, C, D>(
                keys,
                *max_value_len,
                *num_max_attributes,
            )?;
            let aligned = matches!(
                build_jwt_wrapper_circuit::<F, C, D>(
                    &base.common,
                    &base.verifier_only,
                    &del_common
                ),
                JwtWrapperBuildResult::Ok(..),
            );
            println!(
                "  {:<40} base bits={} {:.1?} -> aligned={}",
                label,
                base.common.degree_bits(),
                t.elapsed(),
                aligned
            );
            assert!(
                aligned,
                "wrapper for `{label}` did not align with the delegation circuit"
            );
        }

        Ok(())
    }

    /// The delegation depth cap binds every descendant of a chain.
    ///
    /// Asserts:
    /// - (A) a cap set at the base step is inherited by later steps;
    /// - (B) delegating past the cap is refused;
    /// - (C) raising the cap to buy more depth is refused;
    /// - (D) `maxLevel' = L'` pins the credential as a leaf;
    /// - (E) (B) and (C) also hold in the circuit, not just in the guard.
    #[test]
    #[ignore = "expensive; run with: cargo test --release -- --ignored"]
    fn depth_cap_binds_the_chain() -> Result<()> {
        const NUM_ATTRS: usize = 4;
        const MAX_VALUE_LEN: usize = 32;

        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, NUM_ATTRS, MAX_VALUE_LEN)?;
        let (base_cd, base_targets) =
            build_jwt_base_circuit::<F, C, D>(NUM_ATTRS, MAX_VALUE_LEN, NUM_ATTRS)?;
        let base_layout = base_targets.base_layout();
        let base_proof = prove_jwt_base::<F, C, D>(&base_cd, &base_targets, &jwt, &issuer.pk)?;

        assert_eq!(
            base_proof.proof.public_inputs[base_layout.max_level_pi_idx],
            F::from_canonical_u64(LEVEL_UNBOUNDED),
            "a base credential carries no cap yet"
        );

        let (del_cd, _, del_targets, wrapper_cd, wrapper_targets) =
            build_delegation_and_wrapper::<F, C, D>(
                base_layout,
                &base_cd.common,
                &base_cd.verifier_only,
            )?;
        let wrapper_proof =
            prove_jwt_wrapper::<F, C, D>(&wrapper_cd, &wrapper_targets, &base_proof.proof)?;
        let dummy = build_delegation_dummy_proof::<F, C, D>(&del_cd, &del_targets);

        let attrs = jwt.attributes.clone();
        let keep = vec![true; NUM_ATTRS];
        let cap_of = |p: &ProofWithPublicInputs<F, C, D>| {
            p.public_inputs[del_targets.max_level_idx].to_canonical_u64()
        };
        let delegate_from = |prev: &ProofWithPublicInputs<F, C, D>, cap: Option<u8>| {
            prove_delegation_step::<F, C, D>(
                &del_cd,
                &del_targets,
                &wrapper_cd,
                &dummy,
                prev,
                &attrs,
                &keep,
                cap,
            )
        };

        // (A) Cap the chain at level 2 on the way out of the base step.
        let lvl1 = prove_delegation_base::<F, C, D>(
            &del_cd,
            &del_targets,
            &wrapper_cd,
            &wrapper_proof,
            &dummy,
            &attrs,
            &keep,
            Some(2),
        )?;
        del_cd.verify(lvl1.clone())?;
        assert_eq!(
            cap_of(&lvl1),
            2,
            "the chosen cap must reach the public inputs"
        );

        // A delegator that passes `None` hands the inherited cap on untouched.
        let lvl2 = delegate_from(&lvl1, None)?;
        del_cd.verify(lvl2.clone())?;
        assert_eq!(
            cap_of(&lvl2),
            2,
            "an unspecified cap must be inherited, not reset"
        );

        // (B) Level 3 lies past the cap of 2, so the chain ends at `lvl2`.
        assert!(
            delegate_from(&lvl2, None).is_err(),
            "delegating past the cap must be refused"
        );

        // (C) A holder cannot buy depth by raising the cap they inherited.
        assert!(
            delegate_from(&lvl1, Some(5)).is_err(),
            "loosening the cap must be refused"
        );

        // (D) `maxLevel' = L'` prevents re-delegation outright.
        let leaf = prove_delegation_base::<F, C, D>(
            &del_cd,
            &del_targets,
            &wrapper_cd,
            &wrapper_proof,
            &dummy,
            &attrs,
            &keep,
            Some(1),
        )?;
        del_cd.verify(leaf.clone())?;
        assert_eq!(cap_of(&leaf), 1);
        assert!(
            delegate_from(&leaf, None).is_err(),
            "a credential capped at its own level must be a leaf"
        );

        // A cap below the level being produced is inadmissible from the start.
        assert!(
            prove_delegation_base::<F, C, D>(
                &del_cd,
                &del_targets,
                &wrapper_cd,
                &wrapper_proof,
                &dummy,
                &attrs,
                &keep,
                Some(0),
            )
            .is_err(),
            "a cap below the produced level must be refused"
        );

        // (E) Bypass `resolve_depth_cap` and push a bad cap into the witness:
        // the range checks must make it unsatisfiable on their own.
        let force = |prev: &ProofWithPublicInputs<F, C, D>, cap: u64| {
            prove_delegation_step_with_cap::<F, C, D>(
                &del_cd,
                &del_targets,
                &wrapper_cd,
                &dummy,
                prev,
                &attrs,
                &keep,
                cap,
            )
        };
        assert!(
            force(&lvl2, 2).is_err(),
            "circuit must reject a level beyond its cap"
        );
        assert!(
            force(&lvl1, 5).is_err(),
            "circuit must reject a cap loosened beyond the inherited one"
        );

        Ok(())
    }

    /// Owns `String` claim-key names and lends `&str` references on demand.
    struct ClaimKeys {
        owned: Vec<String>,
    }

    impl ClaimKeys {
        fn refs(&self) -> Vec<&str> {
            self.owned.iter().map(|s| s.as_str()).collect()
        }
    }

    fn generate_claim_keys(n: usize) -> ClaimKeys {
        ClaimKeys {
            owned: (0..n).map(|i| format!("c{:02}", i)).collect(),
        }
    }
}
