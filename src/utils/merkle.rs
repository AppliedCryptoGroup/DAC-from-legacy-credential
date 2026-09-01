use crate::credential::attribute::Attribute;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, Hasher};

pub fn attribute_to_field_elements<F: RichField>(attr: &Attribute) -> Vec<F> {
    attr.to_u32_limbs_le()
        .iter()
        .map(|&limb| F::from_canonical_u32(limb))
        .collect()
}

/// Compute Poseidon hash of an attribute's field elements (4-element digest).
///
/// Empty markers hash to the canonical zero leaf `[F::ZERO; NUM_HASH_OUT_ELTS]`,
/// independent of `attribute_len_bytes`. This lets one delegation circuit serve
/// credential types whose real attributes pack into different widths: the
/// real-attribute hashes remain per-credential-type, while the empty / padded /
/// masked-out leaves are shared.
pub fn attribute_to_hashed_leaf<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    attr: &Attribute,
) -> Vec<F> {
    if attr.is_empty() {
        return vec![F::ZERO; NUM_HASH_OUT_ELTS];
    }
    let elements = attribute_to_field_elements::<F>(attr);
    H::hash_or_noop(&elements).elements.to_vec()
}

/// Convert attributes to hashed Merkle leaves (4 Poseidon hash elements each).
///
/// Pre-hashing attributes makes the Merkle tree leaves fixed at 4 elements,
/// regardless of attribute byte length. The Merkle root is identical to building
/// the tree from raw u32 limbs because `hash_or_noop(4 elements)` is a noop.
pub fn attributes_to_leaves<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    attrs: &[Attribute],
) -> Result<Vec<Vec<F>>> {
    if attrs.is_empty() || !attrs.len().is_power_of_two() {
        anyhow::bail!("attribute count must be a nonzero power of two");
    }
    let expected_len = attrs[0].len_bytes();
    for (idx, attr) in attrs.iter().enumerate() {
        if attr.len_bytes() != expected_len {
            anyhow::bail!(
                "attribute length mismatch at index {}: expected {}, got {}",
                idx,
                expected_len,
                attr.len_bytes()
            );
        }
    }
    Ok(attrs
        .iter()
        .map(|a| attribute_to_hashed_leaf::<F, H>(a))
        .collect())
}

pub fn compute_merkle_root<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    attrs: &[Attribute],
) -> Result<H::Hash> {
    let leaves = attributes_to_leaves::<F, H>(attrs)?;
    let tree = MerkleTree::<F, H>::new(leaves, 0);
    Ok(tree.cap.0[0])
}

pub fn compute_merkle_proof<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    attrs: &[Attribute],
    index: usize,
) -> Result<MerkleProof<F, H>> {
    let leaves = attributes_to_leaves::<F, H>(attrs)?;
    let tree = MerkleTree::<F, H>::new(leaves, 0);
    Ok(tree.prove(index))
}

/// Pad an attribute list with `Attribute::empty_marker` up to a power-of-two
/// length.
///
/// Used at delegation prove time to bring a real-attribute list up to the
/// delegation circuit's attribute capacity, so the off-circuit Merkle root
/// matches the padded commitment computed inside the base circuit.
pub fn pad_attributes(attrs: &[Attribute], num_max_attributes: usize) -> Result<Vec<Attribute>> {
    if attrs.is_empty() {
        anyhow::bail!("attributes must be non-empty");
    }
    if num_max_attributes < attrs.len() || !num_max_attributes.is_power_of_two() {
        anyhow::bail!(
            "num_max_attributes ({}) must be a power of two ≥ attrs.len() ({})",
            num_max_attributes,
            attrs.len()
        );
    }
    let attr_len = attrs[0].len_bytes();
    let mut out = attrs.to_vec();
    out.resize(num_max_attributes, Attribute::empty_marker(attr_len));
    Ok(out)
}

pub fn mask_attributes(attrs: &[Attribute], bitmap: &[bool]) -> Result<Vec<Attribute>> {
    if attrs.len() != bitmap.len() {
        anyhow::bail!("bitmap length must match attribute count");
    }
    let mut out = Vec::with_capacity(attrs.len());
    for (attr, &keep) in attrs.iter().zip(bitmap.iter()) {
        if keep {
            out.push(attr.clone());
        } else {
            out.push(Attribute::empty_marker(attr.len_bytes()));
        }
    }
    Ok(out)
}

pub fn merkle_root_from_leaves<F, H, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaves: &[Vec<Target>],
) -> HashOutTarget
where
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    assert!(
        !leaves.is_empty() && leaves.len().is_power_of_two(),
        "leaf count must be a nonzero power of two"
    );
    let mut level: Vec<HashOutTarget> = leaves
        .iter()
        .map(|leaf| builder.hash_or_noop::<H>(leaf.clone()))
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = &pair[1];
            let mut inputs = Vec::with_capacity(NUM_HASH_OUT_ELTS * 2);
            inputs.extend_from_slice(&left.elements);
            inputs.extend_from_slice(&right.elements);
            let combined = builder.hash_n_to_hash_no_pad::<H>(inputs);
            next.push(combined);
        }
        level = next;
    }
    level[0]
}
