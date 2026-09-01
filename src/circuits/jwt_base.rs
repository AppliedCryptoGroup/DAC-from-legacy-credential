//! JWT base circuit (R_Base): first stage of the delegation pipeline for JWT credentials.
//!
//! Proves that a JWT was signed by the issuer (ECDSA over SHA-256), decodes the
//! Base64url payload in-circuit, extracts claim key+value pairs via JSON parsing
//! gadgets, and commits to the attributes via a Poseidon Merkle root.

use crate::circuits::gadgets::base64::{
    Base64DecodeTargets, fill_base64url_decode_witness, make_base64url_decode_circuit,
};
use crate::circuits::gadgets::cnf_parse::{
    CnfExtractorTargets, fill_cnf_extractor_witness, make_cnf_extractor_circuit,
};
use crate::circuits::gadgets::ecdsa::{ECDSACircuitTargets, make_ecdsa_circuit};
use crate::circuits::gadgets::json_parse::{
    JsonClaimTargetsKnownKey, fill_json_claim_witness_known_key, make_json_claim_circuit_known_key,
    pack_4_bytes_be, pack_constants_be,
};
use crate::circuits::gadgets::make_one_hot_indicator;
use crate::circuits::gadgets::scalar_conversion::{
    DigestToScalarTargets, fill_digest_to_scalar_witness, make_digest_to_scalar_circuit,
    wire_digest_to_ecdsa,
};
use crate::circuits::gadgets::sha256_variable::{
    fill_sha256_varlen_circuit_witness, make_sha256_varlen_circuit,
};
use crate::circuits::layout::{
    BasePublicInputLayout, HasBaseLayout, LEVEL_UNBOUNDED, ensure_valid_attribute_counts,
};
use crate::credential::cnf::{CNF_BLOCK_LEN, pk_coords_to_base64url};
use crate::credential::jwt::{
    JWT_IAT_MAX_VALUE_LEN, JWT_ISS_MAX_VALUE_LEN, JWTCredential, JWTLayout,
    generate_empty_jwt_layout, generate_jwt_layout_with_keys, pop_message_scalar,
};
use crate::utils::crypto::set_nonnative_target;
use crate::utils::merkle::merkle_root_from_leaves;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField;
use plonky2::hash::hash_types::{NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, sign_message};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2_ecdsa::gadgets::ecdsa::{
    ECDSAPublicKeyTarget, ECDSASignatureTarget, verify_p256_message_circuit,
};
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2_sha256::circuit::{Sha256VarlenTargets, array_to_bits};

/// Bind an extractor's packed_array to the canonical decoded-payload words.
fn bind_packed_array<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    extractor_packed: &[Target],
    json_packed: &[Target],
) {
    assert_eq!(
        extractor_packed.len(),
        json_packed.len(),
        "packed_array size must match padded JSON word count"
    );
    for (a, &b) in extractor_packed.iter().zip(json_packed.iter()) {
        builder.connect(*a, b);
    }
}

pub struct JWTBaseTargets {
    pub ecdsa_targets: ECDSACircuitTargets<P256, P256Scalar>,
    pub digest_to_scalar: DigestToScalarTargets,
    pub hash_targets: Sha256VarlenTargets,
    pub b64_targets: Base64DecodeTargets,
    pub claim_targets: Vec<JsonClaimTargetsKnownKey>,
    pub iss_targets: JsonClaimTargetsKnownKey,
    pub iat_targets: JsonClaimTargetsKnownKey,
    pub cnf_targets: CnfExtractorTargets,
    /// PoP signature `(r, s)` on the fixed constant message
    /// `pop_message_scalar()`. Verified in-circuit against the owner PK
    /// extracted from `cnf.jwk`.
    pub owner_sig: ECDSASignatureTarget<P256>,
    pub layout: BasePublicInputLayout,
    pub max_key_len: usize,
    pub max_value_len: usize,
    pub level_pi: Target,
    /// Depth cap public input; always `LEVEL_UNBOUNDED` for a base credential.
    pub max_level_pi: Target,
    /// Maximum payload Base64url length (for witness filling).
    pub max_payload_b64_len: usize,
    /// Byte offset where payload b64 starts in the JWT message.
    pub payload_b64_byte_offset: usize,
    /// Maximum JWT message length in bytes.
    pub max_msg_len_bytes: usize,
    /// Padded JSON length for claim extraction (for witness filling).
    pub padded_json_len_bytes: usize,
    /// Claim keys (for per-claim circuit witness filling).
    pub claim_keys: Vec<String>,
    /// One-hot indicator for actual payload Base64 length (for witness filling).
    pub payload_len_indicator: Vec<Target>,
}

impl HasBaseLayout for JWTBaseTargets {
    fn base_layout(&self) -> BasePublicInputLayout {
        self.layout
    }
}

pub struct JWTBaseProof<F: RichField + Extendable<D>, Cfg: GenericConfig<D, F = F>, const D: usize>
{
    pub proof: ProofWithPublicInputs<F, Cfg, D>,
    /// Verifier data for checking `proof` on its own. The pipeline pins the base
    /// VK inside the wrapper, so this is provided for standalone use only.
    #[allow(dead_code)]
    pub verifier_data: VerifierCircuitData<F, Cfg, D>,
}

/// Extract a byte-level Target from 8 consecutive SHA-256 message BoolTargets (MSB-first).
fn byte_from_message_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_bits: &[BoolTarget],
    byte_index: usize,
) -> Target {
    let bit_start = byte_index * 8;
    let mut byte = builder.zero();
    for bit_in_byte in 0..8u32 {
        let bit = message_bits[bit_start + bit_in_byte as usize];
        let weight = builder.constant(F::from_canonical_u32(1 << (7 - bit_in_byte)));
        let contrib = builder.mul(bit.target, weight);
        byte = builder.add(byte, contrib);
    }
    byte
}

/// Extract a range of byte-level Targets from SHA-256 message bits.
fn bytes_from_message_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_bits: &[BoolTarget],
    byte_start: usize,
    num_bytes: usize,
) -> Vec<Target> {
    (0..num_bytes)
        .map(|i| byte_from_message_bits(builder, message_bits, byte_start + i))
        .collect()
}

/// Constrain the JWT header bytes in the SHA-256 message to match the expected constant.
///
/// The JWT message layout is: `header_b64 + "." + payload_b64`
/// This function verifies bytes 0..header_b64_len match the Base64url encoding
/// of `JWT_HEADER_JSON`, and that the separator byte "." follows immediately.
fn constrain_jwt_header<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_bits: &[BoolTarget],
    header_b64_len: usize,
) {
    use crate::circuits::gadgets::base64::base64url_encode;
    use crate::credential::jwt::JWT_HEADER_JSON;

    let expected_header_b64 = base64url_encode(JWT_HEADER_JSON);
    assert_eq!(
        expected_header_b64.len(),
        header_b64_len,
        "header_b64_len mismatch with JWT_HEADER_JSON encoding"
    );

    // Constrain each header byte to the expected Base64url-encoded constant.
    for (i, &expected_byte) in expected_header_b64.iter().enumerate() {
        let msg_byte = byte_from_message_bits(builder, message_bits, i);
        let expected = builder.constant(F::from_canonical_u32(expected_byte as u32));
        builder.connect(msg_byte, expected);
    }

    // Constrain the separator byte "." between header and payload.
    let dot_byte = byte_from_message_bits(builder, message_bits, header_b64_len);
    let expected_dot = builder.constant(F::from_canonical_u32(b'.' as u32));
    builder.connect(dot_byte, expected_dot);
}

/// Build the JWT base circuit using a pre-computed layout.
///
/// Public inputs (the standard [`BasePublicInputLayout`] order, so the
/// delegation circuit can consume the proof):
/// - issuer pk limbs (16, from ECDSA gadget)
/// - commitment (4, Poseidon Merkle root of key+value attributes)
/// - level (1, must be 0)
fn make_jwt_base_circuit<F, Cfg, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    layout: &JWTLayout,
    num_max_attributes: usize,
) -> Result<JWTBaseTargets>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    Cfg::Hasher: AlgebraicHasher<F>,
{
    let num_claims = layout.claim_keys.len();
    ensure_valid_attribute_counts(num_claims, num_max_attributes)?;
    let attribute_len_bytes = layout.attribute_len_bytes;
    let attribute_u32_limbs = attribute_len_bytes / 4;

    // 1) ECDSA verification gadget; registers issuer pk as public inputs.
    let issuer_pk_pi_start = builder.num_public_inputs();
    let ecdsa_targets = make_ecdsa_circuit::<F, Cfg, D>(builder);
    let issuer_pk_pi_len = builder.num_public_inputs() - issuer_pk_pi_start;

    // 2) Byte-array to scalar conversion for the SHA256 digest.
    let digest_to_scalar = make_digest_to_scalar_circuit(builder);

    // 3) Variable-length SHA-256 of the JWT message bytes.
    let hash_targets = make_sha256_varlen_circuit::<F, D>(builder, layout.max_msg_len_bytes);

    // 4) Wire SHA256 digest -> digest2scalar -> ECDSA message.
    let digest_bits: Vec<_> = hash_targets.digest.to_vec();
    wire_digest_to_ecdsa(builder, &digest_bits, &digest_to_scalar, &ecdsa_targets);

    // 5) Verify the JWT header is the expected constant.
    constrain_jwt_header::<F, D>(builder, &hash_targets.message, layout.header_b64_len);

    // 6a) Create Base64url decode circuit for the maximum payload length.
    //     The input will be the 'A'-padded payload (fixed length = max_payload_b64_len).
    let b64_targets = make_base64url_decode_circuit::<F, D>(builder, layout.max_payload_b64_len);

    // 6b) Payload consistency constraint: link SHA-256 message bytes to Base64 input.
    //
    //     The SHA-256 message contains the actual variable-length JWT. The Base64 decoder
    //     needs a fixed-length input ('A'-padded). We constrain that:
    //       - Active positions (i < actual_payload_b64_len) match SHA-256 message bytes
    //       - Inactive positions (i >= actual_payload_b64_len) are 'A' (0x41)
    //
    //     actual_payload_b64_len = msg_len_bytes - payload_b64_byte_offset
    let offset_const = builder.constant(F::from_canonical_usize(layout.payload_b64_byte_offset));
    let actual_payload_len = builder.sub(hash_targets.msg_len_bytes, offset_const);

    let max_payload_b64_len = layout.max_payload_b64_len;

    // One-hot indicator for actual_payload_len over [0..=max_payload_b64_len].
    let payload_one_hot = make_one_hot_indicator(builder, max_payload_b64_len + 1, 0);
    let payload_len_indicator = payload_one_hot.indicator;
    builder.connect(payload_one_hot.value, actual_payload_len);

    // Build prefix-sum mask: is_active[i] = 1 iff i < actual_payload_len.
    //   is_active[i] = sum_{k > i} indicator[k]
    // Compute from right to left as cumulative sum.
    let mut is_active = vec![builder.zero(); max_payload_b64_len];
    {
        let mut cumsum = builder.zero();
        for i in (0..max_payload_b64_len).rev() {
            // indicator[i+1] means "actual length == i+1", so position i IS active
            cumsum = builder.add(cumsum, payload_len_indicator[i + 1]);
            is_active[i] = cumsum;
        }
    }

    // Extract payload byte targets from SHA-256 message bits (all max_payload_b64_len
    // positions, some may be in SHA-256 padding region for shorter messages).
    let sha256_payload_bytes = bytes_from_message_bits::<F, D>(
        builder,
        &hash_targets.message,
        layout.payload_b64_byte_offset,
        max_payload_b64_len,
    );

    // Per-position consistency constraint:
    //   b64_input[i] = is_active[i] * sha256_byte[i] + (1 - is_active[i]) * 'A'
    // Rearranged: b64_input[i] = is_active[i] * (sha256_byte[i] - 'A') + 'A'
    let char_a = builder.constant(F::from_canonical_u32(b'A' as u32));
    for i in 0..max_payload_b64_len {
        let diff = builder.sub(sha256_payload_bytes[i], char_a);
        let active_contrib = builder.mul(is_active[i], diff);
        let expected = builder.add(active_contrib, char_a);
        builder.connect(b64_targets.input_ascii[i], expected);
    }

    // Compute padded JSON length for claim extraction.
    // Must accommodate the largest extraction window across ALL extractors:
    // user claims, standard claims (iss, iat), and the cnf extractor.
    let decoded_len = b64_targets.decoded_bytes.len();
    let max_user_claim_slice = layout
        .claim_keys
        .iter()
        .map(|k| {
            let min_ss = k.len() + layout.max_value_len + 7;
            min_ss.div_ceil(4) * 4 + 4 // word-aligned + byte-offset padding
        })
        .max()
        .unwrap_or(0);
    let iss_slice = {
        let min_ss = 3 + JWT_ISS_MAX_VALUE_LEN + 7;
        min_ss.div_ceil(4) * 4 + 4
    };
    let iat_slice = {
        let min_ss = 3 + JWT_IAT_MAX_VALUE_LEN + 7;
        min_ss.div_ceil(4) * 4 + 4
    };
    let cnf_slice = CNF_BLOCK_LEN.div_ceil(4) * 4 + 4;
    let max_slice = [max_user_claim_slice, iss_slice, iat_slice, cnf_slice]
        .into_iter()
        .max()
        .unwrap();
    let padded_json_len_bytes = (decoded_len + max_slice).div_ceil(4) * 4;

    // 6c) Pack base64-decoded byte targets into u32 words (big-endian).
    //
    // The JSON claim extraction circuits operate on u32-packed arrays. Here we build
    // the canonical packed representation of the decoded payload so we can bind each
    // claim extraction's input to it (see step 7b).
    //
    // Bytes beyond decoded_len are zero-padded to fill padded_json_len_bytes, which
    // accommodates the per-claim array slice windows.
    let padded_json_len_words = padded_json_len_bytes / 4;
    let (c256, c65536, c16m) = pack_constants_be(builder);
    let zero = builder.zero();

    let json_packed_words: Vec<Target> = (0..padded_json_len_words)
        .map(|word_idx| {
            let byte_start = word_idx * 4;
            // Use decoded byte targets where available, zero for padding region.
            // These branches resolve at build time (decoded_len is a constant).
            let b0 = if byte_start < decoded_len {
                b64_targets.decoded_bytes[byte_start]
            } else {
                zero
            };
            let b1 = if byte_start + 1 < decoded_len {
                b64_targets.decoded_bytes[byte_start + 1]
            } else {
                zero
            };
            let b2 = if byte_start + 2 < decoded_len {
                b64_targets.decoded_bytes[byte_start + 2]
            } else {
                zero
            };
            let b3 = if byte_start + 3 < decoded_len {
                b64_targets.decoded_bytes[byte_start + 3]
            } else {
                zero
            };
            pack_4_bytes_be(builder, b0, b1, b2, b3, c256, c65536, c16m)
        })
        .collect();

    // 7) JSON claim extraction for each claim (per-claim known-key circuits).
    let mut claim_targets = Vec::with_capacity(num_claims);
    for key_str in &layout.claim_keys {
        let ct = make_json_claim_circuit_known_key::<F, D>(
            builder,
            padded_json_len_bytes,
            key_str.as_bytes(),
            layout.max_value_len,
            layout.max_key_len,
        );
        claim_targets.push(ct);
    }

    // 7b) Bind each claim extraction's input to the actual decoded payload.
    // Without this, the packed_array inputs are unconstrained witness data, so a
    // prover could parse claims from a different payload than what was ECDSA-signed.
    for ct in &claim_targets {
        bind_packed_array(builder, &ct.slice_targets.packed_array, &json_packed_words);
    }

    // 7c) Standard claim extractors (iss, iat): parsed dynamically with hardcoded keys.
    //     These are NOT included in the Merkle tree commitment.
    let iss_targets = make_json_claim_circuit_known_key::<F, D>(
        builder,
        padded_json_len_bytes,
        b"iss",
        JWT_ISS_MAX_VALUE_LEN,
        4, // max_key_len: ceil("iss".len() = 3 to multiple of 4)
    );
    let iat_targets = make_json_claim_circuit_known_key::<F, D>(
        builder,
        padded_json_len_bytes,
        b"iat",
        JWT_IAT_MAX_VALUE_LEN,
        4,
    );

    // Bind standard claim packed_arrays to the actual decoded payload.
    for ct in [&iss_targets, &iat_targets] {
        bind_packed_array(builder, &ct.slice_targets.packed_array, &json_packed_words);
    }

    // 7d) CNF extractor: extracts the cnf.jwk public key (x, y coordinates) from the payload.
    let cnf_targets = make_cnf_extractor_circuit::<F, D>(builder, padded_json_len_bytes);

    // Bind cnf packed_array to the actual decoded payload.
    bind_packed_array(
        builder,
        &cnf_targets.slice_targets.packed_array,
        &json_packed_words,
    );

    // 8) Proof of Possession: verify an ECDSA signature, under the owner PK
    //    extracted from `cnf.jwk`, on a fixed constant message.
    //    Soundness chain: JWT signature -> payload -> cnf.jwk -> ECDSA(cred_sk).
    //    The owner pk is not exposed as a public input.
    //
    //    Why a sig and not a DL-knowledge check (sk*G == pk): the non-native
    //    scalar-mul gadget admits no knowledge-soundness extractor, so DL-PoP
    //    cannot extract `sk`. A signature over a fixed message reduces PoP to
    //    ECDSA unforgeability under the standard assumption.
    //
    //    The message is `pop_message_scalar()` (a compile-time constant
    //    derived from `POP_CHALLENGE_BYTES`), materialised as a non-native
    //    constant, so no in-circuit SHA is needed for the PoP.
    let owner_pk = ECDSAPublicKeyTarget(plonky2_ecdsa::gadgets::curve::AffinePointTarget {
        x: NonNativeTarget::from_target_vec(&cnf_targets.x_limbs),
        y: NonNativeTarget::from_target_vec(&cnf_targets.y_limbs),
    });
    let owner_sig = ECDSASignatureTarget::<P256> {
        r: builder.add_virtual_nonnative_target(),
        s: builder.add_virtual_nonnative_target(),
    };
    let pop_msg = builder.constant_nonnative(pop_message_scalar());
    verify_p256_message_circuit(builder, pop_msg, owner_sig.clone(), owner_pk);

    // 9) Merkle commitment over key+value attributes.
    // Hash each attribute (key_padded || value_padded) to a 4-element Poseidon digest,
    // then build the Merkle tree from hashed leaves. This matches the delegation circuit
    // which stores 4-element hashed leaves for efficiency.
    //
    // If num_max_attributes > num_claims, pad the leaf vector with the canonical
    // empty leaf: 4 zero field elements, independent of `attribute_len_bytes`.
    // This matches the delegation circuit's empty-mask branch (delegate.rs) and
    // the off-circuit `attribute_to_hashed_leaf` for empty markers
    // (utils/merkle.rs), so one delegation circuit serves credential types whose
    // real attributes pack into different widths.
    let mut hashed_leaves: Vec<Vec<Target>> = claim_targets
        .iter()
        .map(|ct| {
            builder
                .hash_or_noop::<Cfg::Hasher>(ct.attribute_u32_words.clone())
                .elements
                .to_vec()
        })
        .collect();
    if num_max_attributes > num_claims {
        let zero = builder.zero();
        let empty_leaf: Vec<Target> = (0..NUM_HASH_OUT_ELTS).map(|_| zero).collect();
        for _ in num_claims..num_max_attributes {
            hashed_leaves.push(empty_leaf.clone());
        }
    }

    let commitment = merkle_root_from_leaves::<F, Cfg::Hasher, D>(builder, &hashed_leaves);
    let com_pi_start = builder.num_public_inputs();
    for elem in commitment.elements {
        builder.register_public_input(elem);
    }
    let com_pi_len = NUM_HASH_OUT_ELTS;

    // 10) Public input for the delegation level (must be last for recursion wiring).
    //     The base circuit always outputs L=0. The delegation circuit increments this
    //     by one at each step, so the first delegation proof has L=1.
    let level_pi_idx = builder.num_public_inputs();
    let level_pi = builder.add_virtual_public_input();
    builder.assert_zero(level_pi);

    // 11) Public input for the delegation depth cap (must follow the level).
    //     A base credential carries no cap yet, so it emits LEVEL_UNBOUNDED;
    //     delegators tighten it from there but can never loosen it.
    let max_level_pi_idx = builder.num_public_inputs();
    let max_level_pi = builder.add_virtual_public_input();
    let unbounded = builder.constant(F::from_canonical_u64(LEVEL_UNBOUNDED));
    builder.connect(max_level_pi, unbounded);

    Ok(JWTBaseTargets {
        ecdsa_targets,
        digest_to_scalar,
        hash_targets,
        b64_targets,
        claim_targets,
        iss_targets,
        iat_targets,
        cnf_targets,
        owner_sig,
        layout: BasePublicInputLayout {
            issuer_pk_pi_start,
            issuer_pk_pi_len,
            com_pi_start,
            com_pi_len,
            level_pi_idx,
            max_level_pi_idx,
            num_attributes: num_claims,
            num_max_attributes,
            attribute_u32_limbs,
            attribute_len_bytes,
        },
        max_key_len: layout.max_key_len,
        max_value_len: layout.max_value_len,
        level_pi,
        max_level_pi,
        max_payload_b64_len: layout.max_payload_b64_len,
        payload_b64_byte_offset: layout.payload_b64_byte_offset,
        max_msg_len_bytes: layout.max_msg_len_bytes,
        padded_json_len_bytes,
        claim_keys: layout.claim_keys.clone(),
        payload_len_indicator,
    })
}

/// Build and finalize the JWT base circuit with synthetic claim keys.
///
/// `num_max_attributes` is the Merkle tree size: the delegation circuit's
/// attribute capacity. Must be a power of two and at least `num_claims`. The base pads
/// `num_max_attributes - num_claims` canonical empty leaves into the Merkle
/// commitment.
pub fn build_jwt_base_circuit<F, Cfg, const D: usize>(
    num_claims: usize,
    max_value_len: usize,
    num_max_attributes: usize,
) -> Result<(CircuitData<F, Cfg, D>, JWTBaseTargets)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    Cfg::Hasher: AlgebraicHasher<F>,
{
    let layout = generate_empty_jwt_layout(num_claims, max_value_len)?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let targets = make_jwt_base_circuit::<F, Cfg, D>(&mut builder, &layout, num_max_attributes)?;
    let data = builder.build::<Cfg>();
    Ok((data, targets))
}

/// Build and finalize the JWT base circuit with explicit claim keys.
///
/// `num_max_attributes` is the Merkle tree size: the delegation circuit's
/// attribute capacity. Must be a power of two and at least `claim_keys.len()`. The
/// base pads `num_max_attributes - claim_keys.len()` canonical empty leaves
/// into the Merkle commitment.
pub fn build_jwt_base_circuit_with_keys<F, Cfg, const D: usize>(
    claim_keys: &[&str],
    max_value_len: usize,
    num_max_attributes: usize,
) -> Result<(CircuitData<F, Cfg, D>, JWTBaseTargets)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    Cfg::Hasher: AlgebraicHasher<F>,
{
    let layout = generate_jwt_layout_with_keys(claim_keys, max_value_len)?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let targets = make_jwt_base_circuit::<F, Cfg, D>(&mut builder, &layout, num_max_attributes)?;
    let data = builder.build::<Cfg>();
    Ok((data, targets))
}

/// Prove the JWT base circuit with a concrete JWT credential.
pub fn prove_jwt_base<F, Cfg, const D: usize>(
    circuit: &CircuitData<F, Cfg, D>,
    targets: &JWTBaseTargets,
    jwt: &JWTCredential,
    iss_pk: &ECDSAPublicKey<P256>,
) -> Result<JWTBaseProof<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    Cfg::Hasher: AlgebraicHasher<F>,
{
    if jwt.claims.len() != targets.layout.num_attributes {
        anyhow::bail!(
            "claim count mismatch: circuit expects {}, JWT has {}",
            targets.layout.num_attributes,
            jwt.claims.len()
        );
    }

    // Prepare SHA-256 inputs.
    let digest = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&jwt.jwt_message_bytes);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    };
    let digest_bits = array_to_bits(&digest);

    let mut pw = PartialWitness::new();

    // Fill ECDSA witness.
    set_nonnative_target(&mut pw, &targets.ecdsa_targets.msg, jwt.message_hash)?;
    set_nonnative_target(&mut pw, &targets.ecdsa_targets.sig.r, jwt.signature.r)?;
    set_nonnative_target(&mut pw, &targets.ecdsa_targets.sig.s, jwt.signature.s)?;
    pw.set_biguint_target(
        &targets.ecdsa_targets.issuer_pk.x.value,
        &iss_pk.0.x.to_canonical_biguint(),
    )?;
    pw.set_biguint_target(
        &targets.ecdsa_targets.issuer_pk.y.value,
        &iss_pk.0.y.to_canonical_biguint(),
    )?;

    // Fill digest-to-scalar witness.
    fill_digest_to_scalar_witness(
        &targets.digest_to_scalar,
        &mut pw,
        &digest,
        &jwt.message_hash,
    )?;

    // Fill variable-length SHA-256 witness (raw JWT message, no padding needed here).
    fill_sha256_varlen_circuit_witness::<F, Cfg, D>(
        &targets.hash_targets,
        &mut pw,
        &jwt.jwt_message_bytes,
        &digest_bits,
    )?;

    // Fill Base64url decode witness with 'A'-padded payload.
    // The circuit's payload consistency constraint ensures active positions match
    // the SHA-256 message, and inactive positions are 'A'.
    let padded_b64 = jwt.padded_payload_b64(targets.max_payload_b64_len);
    let decoded_padded_b64 = crate::circuits::gadgets::base64::base64url_decode(&padded_b64)?;
    fill_base64url_decode_witness::<F, D>(
        &targets.b64_targets,
        &mut pw,
        &padded_b64,
        &decoded_padded_b64,
    )?;

    // Fill payload length indicator (one-hot for actual_payload_b64_len).
    let actual_payload_b64_len = jwt.payload_b64.len();
    for (k, &tgt) in targets.payload_len_indicator.iter().enumerate() {
        let val = if k == actual_payload_b64_len {
            F::ONE
        } else {
            F::ZERO
        };
        pw.set_target(tgt, val)?;
    }

    // Pad the decoded payload for JSON claim extraction.
    // Use the Base64 decode of the 'A'-padded payload (same as what the circuit computes),
    // then zero-pad to accommodate per-claim extraction windows.
    let mut padded_payload = decoded_padded_b64.clone();
    padded_payload.resize(targets.padded_json_len_bytes, 0u8);

    // Fill JSON claim witnesses (per-claim known-key circuits).
    for (ct, claim) in targets.claim_targets.iter().zip(jwt.claims.iter()) {
        fill_json_claim_witness_known_key::<F, D>(ct, &mut pw, &padded_payload, claim)?;
    }

    // Fill standard claim witnesses (iss, iat).
    fill_json_claim_witness_known_key::<F, D>(
        &targets.iss_targets,
        &mut pw,
        &padded_payload,
        &jwt.iss_claim,
    )?;
    fill_json_claim_witness_known_key::<F, D>(
        &targets.iat_targets,
        &mut pw,
        &padded_payload,
        &jwt.iat_claim,
    )?;

    // Fill cnf extractor witness (extracts owner PK from JWT payload).
    let (x_b64, y_b64) = pk_coords_to_base64url(&jwt.cred_pk);
    fill_cnf_extractor_witness::<F, D>(
        &targets.cnf_targets,
        &mut pw,
        &padded_payload,
        jwt.cnf_start,
        &x_b64,
        &y_b64,
    )?;

    // PoP: sign the constant `pop_message_scalar()` with the holder's secret
    // key, then fill the (r, s) witness. Verified in-circuit at step 8 above.
    let pop_sig = sign_message(pop_message_scalar(), jwt.cred_sk);
    set_nonnative_target::<F, P256Scalar, D>(&mut pw, &targets.owner_sig.r, pop_sig.r)?;
    set_nonnative_target::<F, P256Scalar, D>(&mut pw, &targets.owner_sig.s, pop_sig.s)?;

    // Fill level = 0 and the depth cap = unbounded.
    pw.set_target(targets.level_pi, F::ZERO)?;
    pw.set_target(targets.max_level_pi, F::from_canonical_u64(LEVEL_UNBOUNDED))?;

    let proof = circuit.prove(pw)?;

    Ok(JWTBaseProof {
        proof: proof.clone(),
        verifier_data: circuit.verifier_data(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::jwt::{generate_dummy_jwt, generate_fixed_jwt_issuer_keypair};
    use crate::utils::merkle::compute_merkle_root;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    /// Verify that the attribute leaf values from JWTCredential match
    /// what the circuit would compute from claim key+value bytes.
    #[test]
    fn test_jwt_attribute_leaf_consistency() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = <C as GenericConfig<D>>::Hasher;

        let issuer = generate_fixed_jwt_issuer_keypair();
        let jwt = generate_dummy_jwt(&issuer.sk, &issuer.pk, 2, 32)?;
        let attribute_len_bytes = jwt.max_key_len + jwt.max_value_len;
        let attribute_u32_limbs = attribute_len_bytes / 4;

        // Compare key+value attribute bytes
        for (i, (claim, attr)) in jwt.claims.iter().zip(jwt.attributes.iter()).enumerate() {
            let attr_bytes = attr.as_bytes();
            assert_eq!(
                attr_bytes.len(),
                attribute_len_bytes,
                "attribute {} total length mismatch",
                i
            );

            // Key portion
            let key_bytes = jwt.claim_keys[i].as_bytes();
            assert_eq!(
                &attr_bytes[..key_bytes.len()],
                key_bytes,
                "attribute {} key mismatch",
                i
            );
            // Key padding should be zeros
            for j in key_bytes.len()..jwt.max_key_len {
                assert_eq!(
                    attr_bytes[j], 0,
                    "claim {} key padding byte {} not zero",
                    i, j
                );
            }

            // Value portion
            let val_bytes = claim.value.as_bytes();
            assert_eq!(
                &attr_bytes[jwt.max_key_len..jwt.max_key_len + val_bytes.len()],
                val_bytes,
                "attribute {} value mismatch",
                i
            );
            // Value padding should be zeros
            for j in (jwt.max_key_len + val_bytes.len())..attribute_len_bytes {
                assert_eq!(
                    attr_bytes[j], 0,
                    "claim {} value padding byte {} not zero",
                    i, j
                );
            }

            // Compare u32 limbs (LE packing)
            let attr_limbs = attr.to_u32_limbs_le();
            assert_eq!(attr_limbs.len(), attribute_u32_limbs);

            let n = attr_bytes.len();
            for (li, limb) in attr_limbs.iter().enumerate() {
                let start = n - (li + 1) * 4;
                let expected = u32::from_be_bytes([
                    attr_bytes[start],
                    attr_bytes[start + 1],
                    attr_bytes[start + 2],
                    attr_bytes[start + 3],
                ]);
                assert_eq!(*limb, expected, "claim {} limb {} mismatch", i, li);
            }
        }

        // Compute merkle root from attributes
        let root = compute_merkle_root::<F, H>(&jwt.attributes)?;
        println!("Off-circuit merkle root: {:?}", root);

        Ok(())
    }

    /// Verify that the same JWT base circuit can prove JWTs with different payload lengths.
    /// This is the key feature of the variable-length SHA-256 support: a single circuit
    /// handles all JWTs that fit within the layout's maximum capacity.
    ///
    #[test]
    #[ignore = "expensive; run with: cargo test --release -- --ignored"]
    fn test_jwt_base_circuit_variable_length() -> Result<()> {
        use crate::credential::jwt::generate_jwt_from_claims;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let issuer = generate_fixed_jwt_issuer_keypair();

        // Build ONE circuit with max_value_len=8 (small for fast test).
        let keys = ["name", "role"];
        let (circuit, targets) = build_jwt_base_circuit_with_keys::<F, C, D>(&keys, 8, keys.len())?;

        // Prove with short claim values.
        let jwt_short = generate_jwt_from_claims(&issuer.sk, &issuer.pk, &keys, &["Al", "op"], 8)?;
        println!(
            "Short JWT: msg={} bytes, payload_b64={} bytes",
            jwt_short.jwt_message_bytes.len(),
            jwt_short.payload_b64.len()
        );
        let proof_short = prove_jwt_base::<F, C, D>(&circuit, &targets, &jwt_short, &issuer.pk)?;
        circuit.verify(proof_short.proof)?;
        println!("Short JWT proof verified!");

        // Prove with max-length claim values using the SAME circuit.
        let long_val_a = "a".repeat(8);
        let long_val_b = "b".repeat(8);
        let jwt_long = generate_jwt_from_claims(
            &issuer.sk,
            &issuer.pk,
            &keys,
            &[long_val_a.as_str(), long_val_b.as_str()],
            8,
        )?;
        println!(
            "Long JWT: msg={} bytes, payload_b64={} bytes",
            jwt_long.jwt_message_bytes.len(),
            jwt_long.payload_b64.len()
        );
        let proof_long = prove_jwt_base::<F, C, D>(&circuit, &targets, &jwt_long, &issuer.pk)?;
        circuit.verify(proof_long.proof)?;
        println!("Long JWT proof verified!");

        // Verify message lengths differ (variable-length support works).
        assert_ne!(
            jwt_short.jwt_message_bytes.len(),
            jwt_long.jwt_message_bytes.len(),
            "short and long JWTs should have different message lengths"
        );

        Ok(())
    }
}
