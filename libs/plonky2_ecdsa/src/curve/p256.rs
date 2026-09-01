//! Curve‐level constants and type aliases for NIST P-256 (= P256)

use crate::field::p256_base::P256Base;
use crate::field::p256_scalar::P256Scalar;
use serde::{Deserialize, Serialize};

use crate::curve::curve_types::{AffinePoint, Curve};

#[derive(Debug, Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct P256;

impl Curve for P256 {
    type BaseField = P256Base;
    type ScalarField = P256Scalar;

    /// *a* = −3 (mod *p*)  
    /// Hex = `0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc`
    const A: P256Base = P256Base([
        0xFFFFFFFFFFFFFFFC,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);

    /// *b* = `5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B`
    const B: P256Base = P256Base([
        0x3BCE3C3E27D2604B,
        0x651D06B0CC53B0F6,
        0xB3EBBD55769886BC,
        0x5AC635D8AA3A93E7,
    ]);

    /// SEC 1 / FIPS 186-4 base point **G**
    const GENERATOR_AFFINE: AffinePoint<Self> = AffinePoint {
        x: P256_GENERATOR_X,
        y: P256_GENERATOR_Y,
        zero: false,
    };
}

/* -------------------------------------------------------------------------- */
/*                               Base-point                                   */
/* -------------------------------------------------------------------------- */

/// Gₓ = `6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296`
const P256_GENERATOR_X: P256Base = P256Base([
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
]);

/// Gᵧ = `4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5`
const P256_GENERATOR_Y: P256Base = P256Base([
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
]);

/* -------------------------------------------------------------------------- */
/*                                   tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use crate::field::p256_scalar::P256Scalar;
    use num::BigUint;
    use plonky2::field::types::{Field, PrimeField};

    use super::P256;
    use crate::curve::curve_types::{AffinePoint, Curve, ProjectivePoint};

    #[test]
    fn test_generator_is_on_curve() {
        let g = P256::GENERATOR_AFFINE;
        assert!(g.is_valid());

        let neg_g = AffinePoint::<P256> {
            x: g.x,
            y: -g.y,
            zero: g.zero,
        };
        assert!(neg_g.is_valid());
    }

    #[test]
    fn test_simple_mul() {
        let g = P256::GENERATOR_PROJECTIVE;
        let ten = P256Scalar::from_canonical_u64(10);
        let prod = mul_naive(ten, g);
        let sum = g + g + g + g + g + g + g + g + g + g;
        assert_eq!(prod, sum);
    }

    #[test]
    fn test_vs_naive_mul() {
        let lhs = P256Scalar::from_noncanonical_biguint(BigUint::from_slice(&[
            1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888,
        ]));
        assert_eq!(
            P256::convert(lhs) * P256::GENERATOR_PROJECTIVE,
            mul_naive(lhs, P256::GENERATOR_PROJECTIVE)
        );
    }

    /// Very small, unoptimised double-and-add – just for reference checks.
    fn mul_naive(k: P256Scalar, mut p: ProjectivePoint<P256>) -> ProjectivePoint<P256> {
        let mut acc = ProjectivePoint::<P256>::ZERO;
        for limb in k.to_canonical_biguint().to_u64_digits().iter() {
            for j in 0..64 {
                if (limb >> j) & 1 == 1 {
                    acc = acc + p;
                }
                p = p.double();
            }
        }
        acc
    }
}
