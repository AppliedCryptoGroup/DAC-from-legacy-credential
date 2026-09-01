use anyhow::Result;
use hashbrown::HashMap;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::time::SystemTime;

/// Pass-structured fixed-point common data constructor used by Plonky2 recursion utilities.
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

/// Targets for the base circuit (counter == 0).
struct BaseTargets {
    counter: Target,
}

/// Targets we need to fill witnesses for proving in the cyclic circuit.
struct CyclicTargets<const D: usize> {
    counter: Target,
    inner: ProofWithPublicInputsTarget<D>,
    base: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
    base_verifier_data_target: VerifierCircuitTarget,
}

/// Build the base circuit which enforces counter == 0.
fn build_base_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>() -> (CircuitData<F, C, D>, BaseTargets)
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let counter = builder.add_virtual_public_input();
    let zero = builder.zero();
    builder.connect(counter, zero);

    let data = builder.build::<C>();
    let targets = BaseTargets { counter };
    (data, targets)
}

/// Build the cyclic recursion circuit.
/// - If counter == 0, verifies the base proof.
/// - Otherwise verifies the previous cyclic proof and enforces counter = prev + 1.
fn build_cyclic_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    base_common: &CommonCircuitData<F, D>,
) -> (CircuitData<F, C, D>, CommonCircuitData<F, D>, CyclicTargets<D>)
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public inputs: [counter] + cyclic verifier data.
    let counter = builder.add_virtual_public_input();
    let verifier_data_target = builder.add_verifier_data_public_inputs();

    // Stabilized common data template for recursion; adjust PI count to match this circuit.
    let mut common_data = common_data_for_recursion::<F, C, D>();
    common_data.num_public_inputs = builder.num_public_inputs();

    // Virtual proofs with public inputs of their respective shapes.
    let inner = builder.add_virtual_proof_with_pis(&common_data);
    let base = builder.add_virtual_proof_with_pis(base_common);
    let base_verifier_data_target =
        builder.add_virtual_verifier_data(base_common.config.fri_config.cap_height);

    let zero = builder.zero();
    let one = builder.one();
    let is_base = builder.is_equal(counter, zero);
    let not_base = builder.not(is_base);

    let inner_counter = inner.public_inputs[0];
    let next_level_if_rec = builder.add(inner_counter, one);
    let expected_counter = builder.select(is_base, zero, next_level_if_rec);
    builder.connect(counter, expected_counter);

    // - Verify INNER (previous delegation) iff NOT base, otherwise allow dummy.
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(not_base, &inner, &common_data)
        .unwrap();
    // - Verify BASE iff base, otherwise allow dummy.
    builder
        .conditionally_verify_proof_or_dummy::<C>(is_base, &base, &base_verifier_data_target, base_common)
        .unwrap();

    let circuit_data = builder.build::<C>();
    let targets = CyclicTargets {
        counter,
        inner,
        base,
        verifier_data_target,
        base_verifier_data_target,
    };
    (circuit_data, common_data, targets)
}

/// Prove the base step (counter == 0).
fn prove_base_step<F, C, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    targets: &CyclicTargets<D>,
    base_circuit: &CircuitData<F, C, D>,
    base_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut overrides = HashMap::new();
    overrides.insert(0, F::ZERO);
    let inner_dummy = cyclic_base_proof::<F, C, D>(common_data, &circuit.verifier_only, overrides);

    let mut pw = PartialWitness::new();
    pw.set_target(targets.counter, F::ZERO)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.inner, &inner_dummy)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.base, base_proof)?;
    pw.set_verifier_data_target(&targets.verifier_data_target, &circuit.verifier_only)?;
    pw.set_verifier_data_target(&targets.base_verifier_data_target, &base_circuit.verifier_only)?;

    Ok(circuit.prove(pw)?)
}

/// Prove a recursive step (counter > 0), verifying the previous cyclic proof.
fn prove_next_step<F, C, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    targets: &CyclicTargets<D>,
    base_circuit: &CircuitData<F, C, D>,
    base_proof: &ProofWithPublicInputs<F, C, D>,
    prev: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let next_counter = prev.public_inputs[0] + F::ONE;

    let mut pw = PartialWitness::new();
    pw.set_target(targets.counter, next_counter)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.inner, prev)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.base, base_proof)?;
    pw.set_verifier_data_target(&targets.verifier_data_target, &circuit.verifier_only)?;
    pw.set_verifier_data_target(&targets.base_verifier_data_target, &base_circuit.verifier_only)?;

    Ok(circuit.prove(pw)?)
}

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let num_steps: usize = 5;

    let t0 = SystemTime::now();
    let (base_circuit, base_targets) = build_base_circuit::<F, C, D>();
    let (cyclic_circuit, cyclic_common, cyclic_targets) =
        build_cyclic_circuit::<F, C, D>(&base_circuit.common);
    println!(
        "Constructed circuits in {}s",
        t0.elapsed().unwrap().as_secs()
    );

    let mut base_pw = PartialWitness::new();
    base_pw.set_target(base_targets.counter, F::ZERO)?;
    let base_proof = base_circuit.prove(base_pw)?;
    base_circuit.verify(base_proof.clone())?;

    let t1 = SystemTime::now();
    let base_cyclic = prove_base_step::<F, C, D>(
        &cyclic_circuit,
        &cyclic_common,
        &cyclic_targets,
        &base_circuit,
        &base_proof,
    )?;

    let mut proofs = Vec::with_capacity(num_steps + 1);
    proofs.push(base_cyclic);
    for _ in 0..num_steps {
        let next = prove_next_step::<F, C, D>(
            &cyclic_circuit,
            &cyclic_targets,
            &base_circuit,
            &base_proof,
            proofs.last().unwrap(),
        )?;
        proofs.push(next);
    }
    println!(
        "Constructed {} cyclic proofs in {}s",
        proofs.len(),
        t1.elapsed().unwrap().as_secs()
    );

    for (i, proof) in proofs.iter().enumerate() {
        check_cyclic_proof_verifier_data(&proof, &cyclic_circuit.verifier_only, &cyclic_circuit.common)?;
        cyclic_circuit.verify(proof.clone())?;
        let expected = F::from_canonical_usize(i);
        assert_eq!(proof.public_inputs[0], expected);
        println!("Verified step {} (counter = {}).", i, expected);
    }

    Ok(())
}
