use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

#[rustfmt::skip]
pub const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

/// Constants necessary for SHA-256 family of digests.
#[rustfmt::skip]
pub const K256: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];

pub struct Sha256Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

pub fn array_to_bits(bytes: &[u8]) -> Vec<bool> {
    let len = bytes.len();
    let mut ret = Vec::new();
    for byte in bytes.iter().take(len) {
        for j in 0..8 {
            let b = (*byte >> (7 - j)) & 1u8;
            ret.push(b == 1u8);
        }
    }
    ret
}

pub fn u32_to_bits_target<F: RichField + Extendable<D>, const D: usize, const B: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> Vec<BoolTarget> {
    let mut res = Vec::new();
    let bit_targets = builder.split_le_base::<B>(a.0, 32);
    for i in (0..32).rev() {
        res.push(BoolTarget::new_unsafe(bit_targets[i]));
    }
    res
}

pub fn bits_to_u32_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> U32Target {
    let bit_len = bits_target.len();
    assert_eq!(bit_len, 32);
    U32Target(builder.le_sum(bits_target[0..32].iter().rev()))
}

// define ROTATE(x, y)  (((x)>>(y)) | ((x)<<(32-(y))))
fn rotate32(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for i in 32 - y..32 {
        res.push(i);
    }
    for i in 0..32 - y {
        res.push(i);
    }
    res
}

// x>>y
// Assume: 0 at index 32
fn shift32(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for _ in 32 - y..32 {
        res.push(32);
    }
    for i in 0..32 - y {
        res.push(i);
    }
    res
}

/*
a ^ b ^ c = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c
          = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c
          = a*( 1 - 2*b -2*c + 4*m ) + b + c - 2*m
where m = b*c
 */
fn xor3<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    b: BoolTarget,
    c: BoolTarget,
) -> BoolTarget {
    let m = builder.mul(b.target, c.target);
    let two_b = builder.add(b.target, b.target);
    let two_c = builder.add(c.target, c.target);
    let two_m = builder.add(m, m);
    let four_m = builder.add(two_m, two_m);
    let one = builder.one();
    let one_sub_two_b = builder.sub(one, two_b);
    let one_sub_two_b_sub_two_c = builder.sub(one_sub_two_b, two_c);
    let one_sub_two_b_sub_two_c_add_four_m = builder.add(one_sub_two_b_sub_two_c, four_m);
    let mut res = builder.mul(a.target, one_sub_two_b_sub_two_c_add_four_m);
    res = builder.add(res, b.target);
    res = builder.add(res, c.target);

    BoolTarget::new_unsafe(builder.sub(res, two_m))
}

//#define Sigma0(x)    (ROTATE((x), 2) ^ ROTATE((x),13) ^ ROTATE((x),22))
fn big_sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let rotate2 = rotate32(2);
    let rotate13 = rotate32(13);
    let rotate22 = rotate32(22);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate2[i]],
            a_bits[rotate13[i]],
            a_bits[rotate22[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define Sigma1(x)    (ROTATE((x), 6) ^ ROTATE((x),11) ^ ROTATE((x),25))
fn big_sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let rotate6 = rotate32(6);
    let rotate11 = rotate32(11);
    let rotate25 = rotate32(25);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate6[i]],
            a_bits[rotate11[i]],
            a_bits[rotate25[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define sigma0(x)    (ROTATE((x), 7) ^ ROTATE((x),18) ^ ((x)>> 3))
fn sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let mut a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate7 = rotate32(7);
    let rotate18 = rotate32(18);
    let shift3 = shift32(3);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate7[i]],
            a_bits[rotate18[i]],
            a_bits[shift3[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define sigma1(x)    (ROTATE((x),17) ^ ROTATE((x),19) ^ ((x)>>10))
fn sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let mut a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate17 = rotate32(17);
    let rotate19 = rotate32(19);
    let shift10 = shift32(10);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate17[i]],
            a_bits[rotate19[i]],
            a_bits[shift10[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

/*
ch = a&b ^ (!a)&c
   = a*(b-c) + c
 */
fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
    c: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = u32_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = u32_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        let b_sub_c = builder.sub(b_bits[i].target, c_bits[i].target);
        let a_mul_b_sub_c = builder.mul(a_bits[i].target, b_sub_c);
        let a_mul_b_sub_c_add_c = builder.add(a_mul_b_sub_c, c_bits[i].target);
        res_bits.push(BoolTarget::new_unsafe(a_mul_b_sub_c_add_c));
    }
    bits_to_u32_target(builder, res_bits)
}

/*
maj = a&b ^ a&c ^ b&c
    = a*b   +  a*c  +  b*c  -  2*a*b*c
    = a*( b + c - 2*b*c ) + b*c
    = a*( b + c - 2*m ) + m
where m = b*c
 */
fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
    c: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = u32_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = u32_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        let m = builder.mul(b_bits[i].target, c_bits[i].target);
        let two = builder.two();
        let two_m = builder.mul(two, m);
        let b_add_c = builder.add(b_bits[i].target, c_bits[i].target);
        let b_add_c_sub_two_m = builder.sub(b_add_c, two_m);
        let a_mul_b_add_c_sub_two_m = builder.mul(a_bits[i].target, b_add_c_sub_two_m);
        let res = builder.add(a_mul_b_add_c_sub_two_m, m);

        res_bits.push(BoolTarget::new_unsafe(res));
    }
    bits_to_u32_target(builder, res_bits)
}

fn add_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
) -> U32Target {
    let (res, _carry) = builder.add_u32(*a, *b);
    res
}

/// SHA-256 compression function for a single 512-bit block.
///
/// Compresses the block with the given 8-word state and returns the updated state
/// (including the Davies-Meyer addition of the input state).
pub fn sha256_compress_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state_in: [U32Target; 8],
    block_bits: &[BoolTarget],
    k256: &[U32Target; 64],
) -> [U32Target; 8] {
    assert_eq!(block_bits.len(), 512);

    let mut x = Vec::new();
    let mut a = state_in[0];
    let mut b = state_in[1];
    let mut c = state_in[2];
    let mut d = state_in[3];
    let mut e = state_in[4];
    let mut f = state_in[5];
    let mut g = state_in[6];
    let mut h = state_in[7];

    for i in 0..16 {
        let index = i * 32;
        let u32_target = builder.le_sum(block_bits[index..index + 32].iter().rev());

        x.push(U32Target(u32_target));
        let mut t1 = h;
        let big_sigma1_e = big_sigma1(builder, &e);
        t1 = add_u32(builder, &t1, &big_sigma1_e);
        let ch_e_f_g = ch(builder, &e, &f, &g);
        t1 = add_u32(builder, &t1, &ch_e_f_g);
        t1 = add_u32(builder, &t1, &k256[i]);
        t1 = add_u32(builder, &t1, &x[i]);

        let mut t2 = big_sigma0(builder, &a);
        let maj_a_b_c = maj(builder, &a, &b, &c);
        t2 = add_u32(builder, &t2, &maj_a_b_c);

        h = g;
        g = f;
        f = e;
        e = add_u32(builder, &d, &t1);
        d = c;
        c = b;
        b = a;
        a = add_u32(builder, &t1, &t2);
    }

    for i in 16..64 {
        let s0 = sigma0(builder, &x[(i + 1) & 0x0f]);
        let s1 = sigma1(builder, &x[(i + 14) & 0x0f]);

        let s0_add_s1 = add_u32(builder, &s0, &s1);
        let s0_add_s1_add_x = add_u32(builder, &s0_add_s1, &x[(i + 9) & 0xf]);
        x[i & 0xf] = add_u32(builder, &x[i & 0xf], &s0_add_s1_add_x);

        let big_sigma0_a = big_sigma0(builder, &a);
        let big_sigma1_e = big_sigma1(builder, &e);
        let ch_e_f_g = ch(builder, &e, &f, &g);
        let maj_a_b_c = maj(builder, &a, &b, &c);

        let h_add_sigma1 = add_u32(builder, &h, &big_sigma1_e);
        let h_add_sigma1_add_ch_e_f_g = add_u32(builder, &h_add_sigma1, &ch_e_f_g);
        let h_add_sigma1_add_ch_e_f_g_add_k256 =
            add_u32(builder, &h_add_sigma1_add_ch_e_f_g, &k256[i]);

        let t1 = add_u32(builder, &x[i & 0xf], &h_add_sigma1_add_ch_e_f_g_add_k256);
        let t2 = add_u32(builder, &big_sigma0_a, &maj_a_b_c);

        h = g;
        g = f;
        f = e;
        e = add_u32(builder, &d, &t1);
        d = c;
        c = b;
        b = a;
        a = add_u32(builder, &t1, &t2);
    }

    [
        add_u32(builder, &state_in[0], &a),
        add_u32(builder, &state_in[1], &b),
        add_u32(builder, &state_in[2], &c),
        add_u32(builder, &state_in[3], &d),
        add_u32(builder, &state_in[4], &e),
        add_u32(builder, &state_in[5], &f),
        add_u32(builder, &state_in[6], &g),
        add_u32(builder, &state_in[7], &h),
    ]
}

// padded_msg_len = block_count x 512 bits
// Size: msg_len_in_bits (L) |  p bits   | 64 bits
// Bits:      msg            | 100...000 |    L
pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_in_bits: u64,
) -> Sha256Targets {
    let mut message = Vec::new();
    let mut digest = Vec::new();
    let block_count = (msg_len_in_bits + 65 + 511) / 512;
    let padded_msg_len = 512 * block_count;
    let p = padded_msg_len - 64 - msg_len_in_bits;
    assert!(p > 1);

    for _ in 0..msg_len_in_bits {
        message.push(builder.add_virtual_bool_target_unsafe());
    }
    message.push(builder.constant_bool(true));
    for _ in 0..p - 1 {
        message.push(builder.constant_bool(false));
    }
    for i in 0..64 {
        let b = (msg_len_in_bits >> (63 - i)) & 1;
        message.push(builder.constant_bool(b == 1));
    }

    // init states
    let mut state: [U32Target; 8] = std::array::from_fn(|i| builder.constant_u32(H256[i]));
    let k256: [U32Target; 64] = std::array::from_fn(|i| builder.constant_u32(K256[i]));

    for blk in 0..block_count {
        let start = blk as usize * 512;
        let block_bits = &message[start..start + 512];
        state = sha256_compress_block(builder, state, block_bits, &k256);
    }

    for word in state.iter().take(8) {
        let bit_targets = builder.split_le_base::<2>(word.0, 32);
        for j in (0..32).rev() {
            digest.push(BoolTarget::new_unsafe(bit_targets[j]));
        }
    }

    Sha256Targets { message, digest }
}

/// Targets for a variable-length SHA-256 circuit.
///
/// The circuit processes `max_blocks` SHA-256 compression rounds unconditionally,
/// then uses a one-hot mux to select the correct intermediate state as the digest.
/// This allows a single circuit to hash messages of any length up to `max_blocks * 64` bytes.
pub struct Sha256VarlenTargets {
    /// The full padded message buffer (`max_blocks * 512` BoolTargets).
    /// Prover fills with: actual message bits + SHA-256 padding + trailing zero blocks.
    pub message: Vec<BoolTarget>,
    /// SHA-256 digest output (256 BoolTargets).
    pub digest: Vec<BoolTarget>,
    /// Witness: number of SHA-256 blocks containing the padded message (1-indexed).
    pub num_blocks: Target,
    /// Witness: actual message length in bytes (before SHA-256 padding).
    pub msg_len_bytes: Target,
    /// Internal: one-hot indicator for block selection (length = max_blocks).
    /// `block_indicator[i] == 1` iff `num_blocks == i + 1`.
    pub block_indicator: Vec<Target>,
    /// Internal: one-hot indicator for the 0x80 padding byte position (length = max_blocks * 64).
    /// `msg_byte_indicator[p] == 1` iff `msg_len_bytes == p`.
    pub msg_byte_indicator: Vec<Target>,
}

/// Build a variable-length SHA-256 circuit.
///
/// The circuit can hash messages from 1 to `max_blocks * 64 - 9` bytes. It processes
/// all `max_blocks` compression rounds and uses a one-hot selector to pick the correct
/// block's output as the final digest.
///
/// The prover provides:
/// - The full padded message buffer (actual msg + SHA-256 padding + trailing zeros)
/// - `num_blocks`: how many blocks contain the actual padded message (1-indexed)
/// - `msg_len_bytes`: actual message length before SHA-256 padding
///
/// Soundness: the circuit verifies that the 0x80 marker byte is at position `msg_len_bytes`,
/// and that `num_blocks` is consistent with `msg_len_bytes` (via range checks on block boundaries).
pub fn make_varlen_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_blocks: usize,
) -> Sha256VarlenTargets {
    assert!(max_blocks >= 1, "need at least 1 block");
    let total_bits = max_blocks * 512;
    let max_msg_bytes = max_blocks * 64;

    // 1) Message buffer: all virtual BoolTargets (prover fills with padded message).
    let message: Vec<BoolTarget> = (0..total_bits)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect();

    // 2) Witness targets for num_blocks and msg_len_bytes.
    let num_blocks = builder.add_virtual_target();
    let msg_len_bytes = builder.add_virtual_target();

    // 3) IV and round constants.
    let mut state: [U32Target; 8] = std::array::from_fn(|i| builder.constant_u32(H256[i]));
    let k256: [U32Target; 64] = std::array::from_fn(|i| builder.constant_u32(K256[i]));

    // 4) Run all max_blocks compression rounds, storing each block's output state.
    let mut block_states: Vec<[U32Target; 8]> = Vec::with_capacity(max_blocks);
    for blk in 0..max_blocks {
        let start = blk * 512;
        let block_bits = &message[start..start + 512];
        state = sha256_compress_block(builder, state, block_bits, &k256);
        block_states.push(state);
    }

    // 5) One-hot mux: select the correct block's state as the final digest.
    //    block_indicator[i] == 1 iff num_blocks == i + 1.
    let block_indicator: Vec<Target> = (0..max_blocks)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Boolean: ind^2 == ind
    for &ind in &block_indicator {
        let sq = builder.mul(ind, ind);
        builder.connect(ind, sq);
    }

    // One-hot: sum == 1
    let mut ind_sum = builder.zero();
    for &ind in &block_indicator {
        ind_sum = builder.add(ind_sum, ind);
    }
    let one = builder.one();
    builder.connect(ind_sum, one);

    // Weighted sum == num_blocks - 1 (0-indexed)
    let num_blocks_minus_one = builder.sub(num_blocks, one);
    let mut weighted = builder.zero();
    for (i, &ind) in block_indicator.iter().enumerate() {
        let i_const = builder.constant(F::from_canonical_usize(i));
        let contrib = builder.mul(ind, i_const);
        weighted = builder.add(weighted, contrib);
    }
    builder.connect(weighted, num_blocks_minus_one);

    // Select state: final_state[j] = sum_blk(indicator[blk] * states[blk][j])
    let final_state: [U32Target; 8] = std::array::from_fn(|j| {
        let mut selected = builder.zero();
        for (blk, &ind) in block_indicator.iter().enumerate() {
            let contrib = builder.mul(ind, block_states[blk][j].0);
            selected = builder.add(selected, contrib);
        }
        U32Target(selected)
    });

    // 6) Convert final state to 256-bit digest.
    let mut digest = Vec::with_capacity(256);
    for word in final_state.iter() {
        let bit_targets = builder.split_le_base::<2>(word.0, 32);
        for j in (0..32).rev() {
            digest.push(BoolTarget::new_unsafe(bit_targets[j]));
        }
    }

    // 7) Build the msg_byte_indicator: one-hot encoding of msg_len_bytes.
    //    Used both for the padding verification (0x80 check) and for witness filling.
    let msg_byte_indicator: Vec<Target> = (0..max_msg_bytes)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Boolean: ind^2 == ind
    for &ind in &msg_byte_indicator {
        let sq = builder.mul(ind, ind);
        builder.connect(ind, sq);
    }

    // One-hot: sum == 1
    let mut byte_ind_sum = builder.zero();
    for &ind in &msg_byte_indicator {
        byte_ind_sum = builder.add(byte_ind_sum, ind);
    }
    builder.connect(byte_ind_sum, one);

    // Weighted sum == msg_len_bytes
    let mut byte_weighted = builder.zero();
    for (p, &ind) in msg_byte_indicator.iter().enumerate() {
        let p_const = builder.constant(F::from_canonical_usize(p));
        let contrib = builder.mul(ind, p_const);
        byte_weighted = builder.add(byte_weighted, contrib);
    }
    builder.connect(byte_weighted, msg_len_bytes);

    // 8) SHA-256 padding verification using the shared msg_byte_indicator.
    constrain_sha256_padding(
        builder,
        &message,
        &msg_byte_indicator,
        msg_len_bytes,
        num_blocks,
        max_blocks,
    );

    Sha256VarlenTargets {
        message,
        digest,
        num_blocks,
        msg_len_bytes,
        block_indicator,
        msg_byte_indicator,
    }
}

/// Verify SHA-256 padding within the variable-length message buffer.
///
/// Checks:
/// 1. The byte at position `msg_len_bytes` is 0x80 (bit pattern: 1 followed by 7 zeros).
/// 2. `num_blocks` is consistent with `msg_len_bytes`:
///    `(num_blocks - 1) * 64 < msg_len_bytes + 9 <= num_blocks * 64`
///
/// The `msg_byte_indicator` is a pre-built one-hot indicator for `msg_len_bytes`
/// (shared with the caller to avoid duplicate constraints).
fn constrain_sha256_padding<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_bits: &[BoolTarget],
    msg_byte_indicator: &[Target],
    msg_len_bytes: Target,
    num_blocks: Target,
    max_blocks: usize,
) {
    // --- Check 1: Verify the 0x80 byte at position msg_len_bytes ---
    //
    // Use the pre-built one-hot indicator to select the byte at the variable position.
    // The MSB (bit 0 of the byte) must be 1, and bits 1-7 must be 0.
    // 0x80 in binary: 10000000

    let one = builder.one();

    // For each bit offset 0..8 in the selected byte, verify the 0x80 pattern.
    for bit_offset in 0..8usize {
        let mut selected_bit = builder.zero();
        for (p, &ind) in msg_byte_indicator.iter().enumerate() {
            let bit_idx = p * 8 + bit_offset;
            if bit_idx < message_bits.len() {
                let contrib = builder.mul(ind, message_bits[bit_idx].target);
                selected_bit = builder.add(selected_bit, contrib);
            }
        }
        if bit_offset == 0 {
            // MSB of 0x80 is 1
            builder.connect(selected_bit, one);
        } else {
            // Remaining 7 bits are 0
            let zero = builder.zero();
            builder.connect(selected_bit, zero);
        }
    }

    // --- Check 2: num_blocks consistency with msg_len_bytes ---
    //
    // The padded message occupies exactly num_blocks * 64 bytes.
    // Minimum padded length: msg_len_bytes + 9 (1 byte for 0x80 + 8 bytes for length field).
    // So: (num_blocks - 1) * 64 < msg_len_bytes + 9 <= num_blocks * 64
    //
    // Rewritten as range checks:
    //   num_blocks * 64 - msg_len_bytes - 9 >= 0       (upper bound)
    //   msg_len_bytes + 72 - num_blocks * 64 >= 0       (lower bound: msg_len_bytes + 9 > (num_blocks-1)*64)

    let sixty_four = builder.constant(F::from_canonical_usize(64));
    let nine = builder.constant(F::from_canonical_usize(9));
    let seventy_two = builder.constant(F::from_canonical_usize(72));

    let num_blocks_times_64 = builder.mul(num_blocks, sixty_four);

    // Upper: num_blocks * 64 - msg_len_bytes - 9 >= 0
    let upper = builder.sub(num_blocks_times_64, msg_len_bytes);
    let upper = builder.sub(upper, nine);
    // Use enough bits to cover max range: max_blocks * 64
    let range_bits = (max_blocks * 64).next_power_of_two().trailing_zeros() as usize + 1;
    builder.range_check(upper, range_bits);

    // Lower: msg_len_bytes + 72 - num_blocks * 64 >= 0
    let lower = builder.add(msg_len_bytes, seventy_two);
    let lower = builder.sub(lower, num_blocks_times_64);
    builder.range_check(lower, range_bits);
}

#[cfg(test)]
mod tests {
    use crate::circuit::{array_to_bits, make_circuits};
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_u32::gates::arithmetic_u32::{U32GateSerializer, U32GeneratorSerializer};
    use rand::Rng;

    const EXPECTED_RES: [u8; 256] = [
        0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0,
        0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0,
        0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0,
        1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1,
        1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
        1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    ];

    #[test]
    fn test_sha256() -> Result<()> {
        let mut msg = vec![0; 128 as usize];
        for i in 0..127 {
            msg[i] = i as u8;
        }

        let msg_bits = array_to_bits(&msg);
        let len = msg.len() * 8;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_circuits(&mut builder, len as u64);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i])?;
        }

        for i in 0..EXPECTED_RES.len() {
            if EXPECTED_RES[i] == 1 {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let gate_serializer = U32GateSerializer;
        let generator_serializer = U32GeneratorSerializer::<C, D>::default();
        let bytes = data
            .to_bytes(&gate_serializer, &generator_serializer)
            .unwrap();
        let data =
            CircuitData::<F, C, D>::from_bytes(&bytes, &gate_serializer, &generator_serializer)
                .unwrap();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn test_sha256_failure() {
        let mut msg = vec![0; 128 as usize];
        for i in 0..127 {
            msg[i] = i as u8;
        }

        let msg_bits = array_to_bits(&msg);
        let len = msg.len() * 8;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_circuits(&mut builder, len as u64);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]).unwrap();
        }

        let mut rng = rand::thread_rng();
        let rnd = rng.gen_range(0..256);
        for i in 0..EXPECTED_RES.len() {
            let b = (i == rnd && EXPECTED_RES[i] != 1) || (i != rnd && EXPECTED_RES[i] == 1);
            if b {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).expect("");
    }
}