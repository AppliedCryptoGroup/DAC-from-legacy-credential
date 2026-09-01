//! Base circuit support types.
//!
//! The [`BasePublicInputLayout`] describes the public input positions that the
//! delegation and presentation circuits depend on. A base circuit exposes its
//! public inputs in this standard order so that the downstream circuits can
//! interpret them uniformly, independent of how the base proof was produced.

/// Describes the public input layout of a base circuit.
///
/// A base circuit exposes its public inputs in this standard order so that the
/// delegation and presentation circuits can interpret them uniformly.
///
/// Layout: `[issuer_pk: 16 limbs] [commitment: 4 elements] [level: 1] [max_level: 1]`
///
/// The Merkle commitment is built over `num_max_attributes` leaves. When a
/// credential carries fewer real attributes than the delegation circuit
/// admits, the base circuit pads the leaf vector with canonical empty leaves
/// up to `num_max_attributes`. This decouples the parser's claim count from
/// the delegation circuit's attribute capacity, so one delegation and
/// presentation circuit serve every credential type whose real claim count
/// fits within that capacity.
#[derive(Clone, Copy, Debug)]
pub struct BasePublicInputLayout {
    /// Start index of the issuer public key limbs (x||y, 8 limbs each).
    pub issuer_pk_pi_start: usize,
    /// Number of issuer PK limbs (16: 8 for x + 8 for y).
    pub issuer_pk_pi_len: usize,
    /// Start index of the Merkle commitment (Poseidon hash root).
    pub com_pi_start: usize,
    /// Number of commitment elements (4 = NUM_HASH_OUT_ELTS).
    pub com_pi_len: usize,
    /// Index of the delegation level public input.
    pub level_pi_idx: usize,
    /// Index of the depth cap `maxLevel`: the deepest level this chain may
    /// still reach. Must be the last base PI, right after `level_pi_idx`.
    pub max_level_pi_idx: usize,
    /// Number of *real* attributes in the credential (parser-driven count).
    /// May be any positive integer; not required to be a power of two.
    pub num_attributes: usize,
    /// Merkle tree size: the attribute capacity of the delegation circuit
    /// (power of two, at least `num_attributes`). Padding slots
    /// `[num_attributes, num_max_attributes)` hold the canonical empty leaf.
    pub num_max_attributes: usize,
    /// Number of u32 limbs per attribute (= attribute_len_bytes / 4).
    pub attribute_u32_limbs: usize,
    /// Byte length of each attribute (must be a nonzero multiple of 4).
    pub attribute_len_bytes: usize,
}

impl BasePublicInputLayout {
    /// Number of base public inputs; the depth cap is the last one.
    pub fn base_pi_count(&self) -> usize {
        self.max_level_pi_idx + 1
    }
}

/// Bit width of the delegation level and depth cap.
///
/// Chains are short in practice, so a byte is plenty and keeps each range check
/// down to a single `BaseSumGate`.
pub const MAX_LEVEL_BITS: usize = 8;

/// Stands in for the paper's `maxLevel = ∞`.
///
/// Sitting at the top of the range means `maxLevel' <= maxLevel` needs no special
/// case for "uncapped". The catch is that uncapped really means 255 levels deep,
/// which no deployment will reach.
pub const LEVEL_UNBOUNDED: u64 = (1u64 << MAX_LEVEL_BITS) - 1;

/// Validate the relationship between `num_attributes` and `num_max_attributes`.
pub fn ensure_valid_attribute_counts(
    num_attributes: usize,
    num_max_attributes: usize,
) -> anyhow::Result<()> {
    if num_attributes == 0 {
        anyhow::bail!("num_attributes must be ≥ 1");
    }
    if !num_max_attributes.is_power_of_two() {
        anyhow::bail!("num_max_attributes must be a nonzero power of two");
    }
    if num_max_attributes < num_attributes {
        anyhow::bail!(
            "num_max_attributes ({}) must be ≥ num_attributes ({})",
            num_max_attributes,
            num_attributes
        );
    }
    Ok(())
}

/// Trait for circuit target structs that can provide their base PI layout.
pub trait HasBaseLayout {
    fn base_layout(&self) -> BasePublicInputLayout;
}
