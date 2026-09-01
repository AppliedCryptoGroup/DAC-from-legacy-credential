use anyhow::Result;
use std::path::Path;
use std::time::Instant;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

use delegatable_ecdsa::circuits::delegate::{
    build_delegation_and_wrapper, build_delegation_dummy_proof, prove_delegation_base,
    prove_delegation_step,
};
use delegatable_ecdsa::circuits::jwt_base::{build_jwt_base_circuit_with_keys, prove_jwt_base};
use delegatable_ecdsa::circuits::jwt_wrapper::{
    JwtWrapperBuildResult, build_jwt_wrapper_circuit, prove_jwt_wrapper,
};
use delegatable_ecdsa::circuits::layout::HasBaseLayout;
use delegatable_ecdsa::circuits::present::{build_presentation_circuit, prove_presentation};
use delegatable_ecdsa::credential::cnf::pk_coords_to_base64url;
use delegatable_ecdsa::credential::jwt::{JWTCredential, generate_fixed_jwt_issuer_keypair};
use delegatable_ecdsa::utils::crypto::compressed_pubkey_hex;
use delegatable_ecdsa::utils::merkle::{mask_attributes, pad_attributes};

// End-to-end demo: sign a JWT credential, prove it, delegate it with selective
// disclosure, and present it at each level. Then run a second credential (with
// different claims) through the same pipeline, reusing the delegation circuit.

/// Max claim value length for the work credential (`work_credential.json`).
const CRED_A_MAX_VALUE_LEN: usize = 32;

/// Max claim value length for the ID credential (`id_credential.json`). Its
/// claim keys differ from the work credential, so it builds a different base
/// circuit (and wrapper) but runs against the same delegation circuit.
const CRED_B_MAX_VALUE_LEN: usize = 32;

/// Attribute capacity of the delegation circuit: the Merkle commitment is built
/// over this many leaves, padding any slots beyond the credential's real claim
/// count with the canonical empty leaf.
const NUM_MAX_ATTRIBUTES: usize = 16;

const NUM_LAYERS_A: usize = 2;
const PRESENTATION_NONCE: u32 = 0xCAFEBABE;

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    eprintln!(
        "WARNING: Running in debug mode. Use `cargo run --release --example demo` \
         for realistic performance.\n"
    );

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let sep = "=".repeat(63);

    println!("\n{sep}");
    println!("  Delegatable ECDSA - end-to-end demo");
    println!("{sep}\n");

    let issuer = generate_fixed_jwt_issuer_keypair();

    // Work credential (4 claims)
    // The definition JSON holds the claim data; we sign it at runtime
    println!("[1/8] Signing the work credential (4 claims) from work_credential.json");
    let cred_a_dir = format!("{}/examples/fixtures", env!("CARGO_MANIFEST_DIR"));
    let jwt_a = JWTCredential::from_definition_json(
        Path::new(&format!("{cred_a_dir}/work_credential.json")),
        &issuer.sk,
        &issuer.pk,
        CRED_A_MAX_VALUE_LEN,
    )?;
    // Write the freshly-signed compact JWT next to the definition for inspection.
    jwt_a.save_jwt_file(Path::new(&format!("{cred_a_dir}/work_credential.jwt")))?;
    let (owner_x_a, owner_y_a) = pk_coords_to_base64url(&jwt_a.cred_pk);
    println!(
        "      JWT: {} bytes, {} claims, max_value_len={}",
        jwt_a.jwt_message_bytes.len(),
        jwt_a.claims.len(),
        CRED_A_MAX_VALUE_LEN,
    );
    println!("      Issuer PK:  {}", compressed_pubkey_hex(&issuer.pk));
    println!("      iss=\"{}\"  iat=\"{}\"", jwt_a.iss, jwt_a.iat);
    println!("      cnf.jwk.x=\"{}\"", owner_x_a);
    println!("      cnf.jwk.y=\"{}\"", owner_y_a);
    for (i, (key, claim)) in jwt_a.claim_keys.iter().zip(jwt_a.claims.iter()).enumerate() {
        println!("        [{i}] {key:<12} \"{}\"", claim.value);
    }

    println!("\n[2/8] Building the base circuit (capacity {NUM_MAX_ATTRIBUTES} claims)");
    let cred_a_keys: Vec<&str> = jwt_a.claim_keys.iter().map(|s| s.as_str()).collect();
    let t = Instant::now();
    let (base_cd_a, base_targets_a) = build_jwt_base_circuit_with_keys::<F, C, D>(
        &cred_a_keys,
        CRED_A_MAX_VALUE_LEN,
        NUM_MAX_ATTRIBUTES,
    )?;
    let base_layout_a = base_targets_a.base_layout();
    println!(
        "      Built in {:.2?}, base degree_bits = {}",
        t.elapsed(),
        base_cd_a.common.degree_bits()
    );

    println!("\n[3/8] Proving the base, building the delegation and presentation circuits");
    let t = Instant::now();
    let base_proof_a = prove_jwt_base::<F, C, D>(&base_cd_a, &base_targets_a, &jwt_a, &issuer.pk)?;
    println!("      Base proof  ({:.2?})", t.elapsed());

    // Build the delegation circuit together with this credential's wrapper.
    let t = Instant::now();
    let (del_cd, del_common, del_targets, wrapper_cd_a, wrapper_targets_a) =
        build_delegation_and_wrapper::<F, C, D>(
            base_layout_a,
            &base_cd_a.common,
            &base_cd_a.verifier_only,
        )?;
    println!(
        "      Delegation and wrapper built ({:.2?}); delegation degree_bits = {}",
        t.elapsed(),
        del_cd.common.degree_bits()
    );

    let t = Instant::now();
    let (pres_cd_a, pres_targets_a) = build_presentation_circuit::<F, C, D>(
        &del_cd.common,
        &del_cd.verifier_only,
        base_layout_a.issuer_pk_pi_start,
        base_layout_a.issuer_pk_pi_len,
        del_targets.com_pi_start,
        del_targets.com_pi_len,
        base_layout_a.num_max_attributes,
        del_targets.wrapper_digest_pi_start,
    );
    println!("      Presentation circuit  ({:.2?})", t.elapsed());

    let t = Instant::now();
    let wrapper_proof_a =
        prove_jwt_wrapper::<F, C, D>(&wrapper_cd_a, &wrapper_targets_a, &base_proof_a.proof)?;
    println!("      Wrapper proof  ({:.2?})", t.elapsed());

    let dummy_proof = build_delegation_dummy_proof::<F, C, D>(&del_cd, &del_targets);

    // Delegate the work credential, dropping a claim at each level.
    println!("\n[4/8] Delegating with selective disclosure ({NUM_LAYERS_A} levels)\n");
    let claim_values_a: Vec<String> = jwt_a.claims.iter().map(|c| c.value.clone()).collect();
    let mut current_attrs_a = jwt_a.attributes.clone();
    let bitmap_a = current_attrs_a
        .iter()
        .map(|a| !a.is_empty())
        .collect::<Vec<_>>();

    let t = Instant::now();
    let mut prev = prove_delegation_base::<F, C, D>(
        &del_cd,
        &del_targets,
        &wrapper_cd_a,
        &wrapper_proof_a,
        &dummy_proof,
        &current_attrs_a,
        &bitmap_a,
        None,
    )?;
    let dt_del = t.elapsed();
    del_cd.verifier_data().verify(prev.clone())?;
    check_cyclic_proof_verifier_data(&prev, &del_cd.verifier_only, &del_cd.common)?;
    present_one::<F, C, D>(
        1,
        &pres_cd_a,
        &pres_targets_a,
        &del_cd,
        &prev,
        &current_attrs_a,
        &jwt_a.claim_keys,
        &claim_values_a,
        dt_del,
    )?;

    for i in 1..NUM_LAYERS_A {
        let mut bitmap = current_attrs_a
            .iter()
            .map(|a| !a.is_empty())
            .collect::<Vec<_>>();
        let non_zero = bitmap.iter().filter(|v| **v).count();
        if non_zero > 1
            && let Some(idx) = bitmap.iter().rposition(|v| *v)
        {
            bitmap[idx] = false;
        }

        let t = Instant::now();
        let next = prove_delegation_step::<F, C, D>(
            &del_cd,
            &del_targets,
            &wrapper_cd_a,
            &dummy_proof,
            &prev,
            &current_attrs_a,
            &bitmap,
            None,
        )?;
        let dt_del = t.elapsed();

        current_attrs_a = mask_attributes(&current_attrs_a, &bitmap)?;
        del_cd.verifier_data().verify(next.clone())?;
        check_cyclic_proof_verifier_data(&next, &del_cd.verifier_only, &del_cd.common)?;

        present_one::<F, C, D>(
            i + 1,
            &pres_cd_a,
            &pres_targets_a,
            &del_cd,
            &next,
            &current_attrs_a,
            &jwt_a.claim_keys,
            &claim_values_a,
            dt_del,
        )?;
        prev = next;
    }

    // ID credential (12 claims)
    println!("\n[5/8] Signing the ID credential (12 claims) from id_credential.json");
    let cred_b_dir = format!("{}/examples/fixtures", env!("CARGO_MANIFEST_DIR"));
    let jwt_b = JWTCredential::from_definition_json(
        Path::new(&format!("{cred_b_dir}/id_credential.json")),
        &issuer.sk,
        &issuer.pk,
        CRED_B_MAX_VALUE_LEN,
    )?;
    // Write the freshly-signed compact JWT next to the definition for inspection.
    jwt_b.save_jwt_file(Path::new(&format!("{cred_b_dir}/id_credential.jwt")))?;
    let (owner_x_b, owner_y_b) = pk_coords_to_base64url(&jwt_b.cred_pk);
    println!(
        "      JWT: {} bytes, {} claims, max_value_len={}",
        jwt_b.jwt_message_bytes.len(),
        jwt_b.claims.len(),
        CRED_B_MAX_VALUE_LEN,
    );
    println!("      Issuer PK:  {}", compressed_pubkey_hex(&issuer.pk));
    println!("      iss=\"{}\"  iat=\"{}\"", jwt_b.iss, jwt_b.iat);
    println!("      cnf.jwk.x=\"{}\"", owner_x_b);
    println!("      cnf.jwk.y=\"{}\"", owner_y_b);
    for (i, (key, claim)) in jwt_b.claim_keys.iter().zip(jwt_b.claims.iter()).enumerate() {
        println!("        [{i:>2}] {key:<14} \"{}\"", claim.value);
    }

    println!("\n[6/8] Building its base circuit");
    let cred_b_keys: Vec<&str> = jwt_b.claim_keys.iter().map(|s| s.as_str()).collect();
    let t = Instant::now();
    let (base_cd_b, base_targets_b) = build_jwt_base_circuit_with_keys::<F, C, D>(
        &cred_b_keys,
        CRED_B_MAX_VALUE_LEN,
        NUM_MAX_ATTRIBUTES,
    )?;
    let base_layout_b = base_targets_b.base_layout();
    println!(
        "      Built in {:.2?}, base degree_bits = {}",
        t.elapsed(),
        base_cd_b.common.degree_bits()
    );

    // Reuse the delegation circuit from step 3 by building only a new wrapper.
    // A `Mismatch` would mean this credential needs a gate type the delegation
    // circuit was not built with.
    println!("\n[7/8] Reusing the same delegation circuit");
    let t = Instant::now();
    let (wrapper_cd_b, wrapper_targets_b) = match build_jwt_wrapper_circuit::<F, C, D>(
        &base_cd_b.common,
        &base_cd_b.verifier_only,
        &del_common,
    ) {
        JwtWrapperBuildResult::Ok(cd, tgts) => (cd, tgts),
        JwtWrapperBuildResult::Mismatch(_) => {
            anyhow::bail!("the ID credential's wrapper does not align with the delegation circuit")
        }
    };
    println!("      Wrapper built ({:.2?})", t.elapsed());

    let t = Instant::now();
    let (pres_cd_b, pres_targets_b) = build_presentation_circuit::<F, C, D>(
        &del_cd.common,
        &del_cd.verifier_only,
        base_layout_b.issuer_pk_pi_start,
        base_layout_b.issuer_pk_pi_len,
        del_targets.com_pi_start,
        del_targets.com_pi_len,
        base_layout_b.num_max_attributes,
        del_targets.wrapper_digest_pi_start,
    );
    println!("      Presentation circuit ({:.2?})", t.elapsed());

    println!("\n[8/8] Proving and presenting");
    let t = Instant::now();
    let base_proof_b = prove_jwt_base::<F, C, D>(&base_cd_b, &base_targets_b, &jwt_b, &issuer.pk)?;
    println!("      Base proof  ({:.2?})", t.elapsed());
    let t = Instant::now();
    let wrapper_proof_b =
        prove_jwt_wrapper::<F, C, D>(&wrapper_cd_b, &wrapper_targets_b, &base_proof_b.proof)?;
    println!("      Wrapper proof  ({:.2?})", t.elapsed());

    let claim_values_b: Vec<String> = jwt_b.claims.iter().map(|c| c.value.clone()).collect();
    let current_attrs_b = jwt_b.attributes.clone();
    let bitmap_b = current_attrs_b
        .iter()
        .map(|a| !a.is_empty())
        .collect::<Vec<_>>();
    let t = Instant::now();
    let del_proof_b = prove_delegation_base::<F, C, D>(
        &del_cd,
        &del_targets,
        &wrapper_cd_b,
        &wrapper_proof_b,
        &dummy_proof,
        &current_attrs_b,
        &bitmap_b,
        None,
    )?;
    let dt_del_b = t.elapsed();
    del_cd.verifier_data().verify(del_proof_b.clone())?;
    check_cyclic_proof_verifier_data(&del_proof_b, &del_cd.verifier_only, &del_cd.common)?;
    present_one::<F, C, D>(
        1,
        &pres_cd_b,
        &pres_targets_b,
        &del_cd,
        &del_proof_b,
        &current_attrs_b,
        &jwt_b.claim_keys,
        &claim_values_b,
        dt_del_b,
    )?;

    let del_digest = del_cd.verifier_only.circuit_digest;
    let wd_a = wrapper_cd_a.verifier_only.circuit_digest;
    let wd_b = wrapper_cd_b.verifier_only.circuit_digest;
    assert_ne!(
        wd_a, wd_b,
        "the two credentials must have distinct wrapper digests"
    );

    println!("\n{sep}");
    println!("  Done");
    println!("{sep}");
    println!(
        "  Delegation circuit : {}",
        hash_short(&del_digest.elements)
    );
    println!("  Work wrapper       : {}", hash_short(&wd_a.elements));
    println!("  ID wrapper         : {}", hash_short(&wd_b.elements));
    println!();

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn present_one<F, C, const D: usize>(
    level: usize,
    pres_cd: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    pres_targets: &delegatable_ecdsa::circuits::present::PresentationTargets<D>,
    del_cd: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    del_proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
    current_attrs: &[delegatable_ecdsa::credential::attribute::Attribute],
    claim_keys: &[String],
    claim_values: &[String],
    dt_del: std::time::Duration,
) -> Result<()>
where
    F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>,
    C: plonky2::plonk::config::GenericConfig<D, F = F> + 'static,
    C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
    let padded = pad_attributes(current_attrs, NUM_MAX_ATTRIBUTES)?;
    // Disclose every claim the holder still holds; padding slots stay redacted.
    let reveal_mask: Vec<bool> = padded.iter().map(|a| !a.is_empty()).collect();

    let t = Instant::now();
    let pres = prove_presentation::<F, C, D>(
        pres_cd,
        pres_targets,
        del_cd,
        del_proof,
        &padded,
        &reveal_mask,
        PRESENTATION_NONCE,
    )?;
    let dt_pres = t.elapsed();
    let t = Instant::now();
    pres_cd.verify(pres)?;
    let dt_pres_v = t.elapsed();

    let disclosed: Vec<String> = padded
        .iter()
        .enumerate()
        .filter(|(i, a)| reveal_mask[*i] && !a.is_empty())
        .map(|(i, _)| {
            let key = claim_keys.get(i).map(|s| s.as_str()).unwrap_or("<padding>");
            let value = claim_values.get(i).map(|s| s.as_str()).unwrap_or("");
            format!("[{i}] {key}: \"{value}\"")
        })
        .collect();
    println!(
        "      Level {level}: delegation {dt_del:.2?}, present {} ({dt_pres:.2?}, verify {dt_pres_v:.2?})",
        disclosed.join(", ")
    );
    Ok(())
}

fn hash_short<F: plonky2::field::types::Field>(elements: &[F]) -> String {
    let bytes: Vec<u8> = elements
        .iter()
        .flat_map(|e| {
            let s = format!("{e}");
            s.into_bytes()
        })
        .collect();
    let hex: String = bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    format!("0x{hex}...")
}
