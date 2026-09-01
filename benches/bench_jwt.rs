#[path = "common.rs"]
mod common;

use anyhow::Result;
use clap::Parser;
use std::time::Instant;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

use delegatable_ecdsa::circuits::delegate::{
    build_delegation_circuit, build_delegation_dummy_proof, prove_delegation_base,
    prove_delegation_step,
};
use delegatable_ecdsa::circuits::jwt_base::{build_jwt_base_circuit, prove_jwt_base};
use delegatable_ecdsa::circuits::jwt_wrapper::{
    JwtWrapperBuildResult, build_jwt_wrapper_circuit, prove_jwt_wrapper,
};
use delegatable_ecdsa::circuits::layout::HasBaseLayout;
use delegatable_ecdsa::circuits::present::{
    build_presentation_circuit, precompute_presentation_partition, prove_presentation,
    prove_presentation_cached,
};
use delegatable_ecdsa::credential::jwt::{generate_dummy_jwt, generate_fixed_jwt_issuer_keypair};
use delegatable_ecdsa::utils::merkle::{mask_attributes, pad_attributes};

use common::{BenchArgs, BenchResults, append_csv_row, bench_verify, print_results};

const VERIFY_ITERS: usize = 100;
const PRESENTATION_NONCE: u32 = 0xCAFEBABE;

fn run() -> Result<()> {
    let args = BenchArgs::parse();
    // Always benchmark the full version: the Merkle capacity equals the claim
    // count, so every leaf is a real claim (no padding). This requires `claims`
    // to be a nonzero power of two.
    let num_max_attributes = args.claims;
    if !num_max_attributes.is_power_of_two() {
        anyhow::bail!("claims ({}) must be a nonzero power of two", args.claims);
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let mut results = BenchResults::new();

    let issuer = generate_fixed_jwt_issuer_keypair();
    let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, args.claims, args.max_claim_size)?;

    // Build times.

    let t = Instant::now();
    let (base_cd, base_targets) =
        build_jwt_base_circuit::<F, C, D>(args.claims, args.max_claim_size, num_max_attributes)?;
    results.add_build("Base circuit (JWT)", t.elapsed());
    results.add_circuit_size(
        "Base circuit (JWT)",
        base_cd.common.degree_bits(),
        base_cd.common.num_gates_pre_padding,
    );

    let base_layout = base_targets.base_layout();

    let (probe_del_cd, probe_del_common, _) = build_delegation_circuit::<F, C, D>(base_layout, &[]);
    let extra_gates = match build_jwt_wrapper_circuit::<F, C, D>(
        &base_cd.common,
        &base_cd.verifier_only,
        &probe_del_common,
    ) {
        JwtWrapperBuildResult::Ok(..) => Vec::new(),
        JwtWrapperBuildResult::Mismatch(wrapper_common) => wrapper_common
            .gates
            .iter()
            .filter(|g| !probe_del_common.gates.contains(g))
            .cloned()
            .collect(),
    };
    drop(probe_del_cd);

    let t = Instant::now();
    let (del_cd, del_common, del_targets) =
        build_delegation_circuit::<F, C, D>(base_layout, &extra_gates);
    results.add_build("Delegation circuit", t.elapsed());
    results.add_circuit_size(
        "Delegation circuit",
        del_cd.common.degree_bits(),
        del_cd.common.num_gates_pre_padding,
    );

    let t = Instant::now();
    let (wrapper_cd, wrapper_targets) = match build_jwt_wrapper_circuit::<F, C, D>(
        &base_cd.common,
        &base_cd.verifier_only,
        &del_common,
    ) {
        JwtWrapperBuildResult::Ok(cd, tgts) => (cd, tgts),
        JwtWrapperBuildResult::Mismatch(_) => {
            anyhow::bail!("wrapper still mismatches after registering probed gates")
        }
    };
    results.add_build("Wrapper circuit", t.elapsed());
    results.add_circuit_size(
        "Wrapper circuit",
        wrapper_cd.common.degree_bits(),
        wrapper_cd.common.num_gates_pre_padding,
    );

    let t = Instant::now();
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
    results.add_build("Presentation circuit", t.elapsed());
    results.add_circuit_size(
        "Presentation circuit",
        pres_cd.common.degree_bits(),
        pres_cd.common.num_gates_pre_padding,
    );

    // Proving times.

    let t = Instant::now();
    let base_proof = prove_jwt_base::<F, C, D>(&base_cd, &base_targets, &jwt, &issuer.pk)?;
    results.add_proving("Base proof (JWT)", t.elapsed());

    let t = Instant::now();
    let wrapper_proof =
        prove_jwt_wrapper::<F, C, D>(&wrapper_cd, &wrapper_targets, &base_proof.proof)?;
    results.add_proving("Wrapper proof", t.elapsed());

    let dummy_proof = build_delegation_dummy_proof::<F, C, D>(&del_cd, &del_targets);

    let mut current_attrs = jwt.attributes.clone();
    let bitmap = current_attrs
        .iter()
        .map(|a| !a.is_empty())
        .collect::<Vec<_>>();

    let t = Instant::now();
    let base_outer = prove_delegation_base::<F, C, D>(
        &del_cd,
        &del_targets,
        &wrapper_cd,
        &wrapper_proof,
        &dummy_proof,
        &current_attrs,
        &bitmap,
        None,
    )?;
    results.add_proving("Delegation (base step)", t.elapsed());

    // Recursive step (level 2).
    let mut bitmap = current_attrs
        .iter()
        .map(|a| !a.is_empty())
        .collect::<Vec<_>>();
    let non_zero_count = bitmap.iter().filter(|v| **v).count();
    if non_zero_count > 1
        && let Some(idx) = bitmap.iter().rposition(|v| *v)
    {
        bitmap[idx] = false;
    }

    let t = Instant::now();
    let recursive_outer = prove_delegation_step::<F, C, D>(
        &del_cd,
        &del_targets,
        &wrapper_cd,
        &dummy_proof,
        &base_outer,
        &current_attrs,
        &bitmap,
        None,
    )?;
    results.add_proving("Delegation (recursive step)", t.elapsed());

    current_attrs = mask_attributes(&current_attrs, &bitmap)?;

    // Presentation proof: pad to capacity, disclose every claim still held.
    let padded = pad_attributes(&current_attrs, num_max_attributes)?;
    let reveal_mask: Vec<bool> = padded.iter().map(|a| !a.is_empty()).collect();

    let t = Instant::now();
    let pres = prove_presentation::<F, C, D>(
        &pres_cd,
        &pres_targets,
        &del_cd,
        &recursive_outer,
        &padded,
        &reveal_mask,
        PRESENTATION_NONCE,
    )?;
    results.add_proving("Presentation proof", t.elapsed());

    // Cached-witness path: reuse the witness across repeated proofs that share a
    // nonce. Each cached proof still samples fresh ZK blinders, so its bytes stay
    // unlinkable.
    let t = Instant::now();
    let pres_partition = precompute_presentation_partition::<F, C, D>(
        &pres_targets,
        &pres_cd,
        &del_cd,
        &recursive_outer,
        &padded,
        &reveal_mask,
        PRESENTATION_NONCE,
    )?;
    results.add_proving("Pres. precompute (witness)", t.elapsed());

    let t = Instant::now();
    let pres_cached = prove_presentation_cached::<F, C, D>(&pres_cd, &pres_partition)?;
    results.add_proving("Pres. proof (cached witness)", t.elapsed());
    pres_cd.verify(pres_cached.clone())?;

    // Proof sizes (compressed serialization). A circuit's proof size is fixed by
    // its FRI config, so one sample per proof suffices.
    results.add_proof_size("Base proof", base_proof.proof.to_bytes().len());
    results.add_proof_size("Wrapper proof", wrapper_proof.to_bytes().len());
    results.add_proof_size("Delegation proof", recursive_outer.to_bytes().len());
    results.add_proof_size("Presentation proof", pres.to_bytes().len());

    // Verification times.

    let del_vd = del_cd.verifier_data();
    let del_vo = &del_cd.verifier_only;
    let del_common = &del_cd.common;
    let del_proof = recursive_outer.clone();
    let avg_del = bench_verify(
        || {
            del_vd.verify(del_proof.clone()).unwrap();
            check_cyclic_proof_verifier_data(&del_proof, del_vo, del_common).unwrap();
        },
        VERIFY_ITERS,
    );
    results.add_verification("Delegation proof", avg_del);

    let pres_clone = pres.clone();
    let avg_pres = bench_verify(
        || {
            pres_cd.verify(pres_clone.clone()).unwrap();
        },
        VERIFY_ITERS,
    );
    results.add_verification("Presentation proof", avg_pres);

    print_results("JWT Credential Benchmark", &args, &results, VERIFY_ITERS);

    // Append a CSV row when --csv-out is set.
    if let Some(path) = args.csv_out.as_ref() {
        append_csv_row(&args, &results, path)?;
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
