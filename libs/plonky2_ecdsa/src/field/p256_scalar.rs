//! Scalar field of the NIST P-256 (= secp256r1) curve.
//!
//! Curve order  
//! ```text
//! n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
//!   = 115792089210356248762697446949407573529996955224135760342422259061068512044369
//!   = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 −  189 … (*see SEC 1*)
//! ```

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use itertools::Itertools;
use num::bigint::BigUint;
use num::{Integer, One};
use serde::{Deserialize, Serialize};

use plonky2::field::types::{Field, PrimeField, Sample};

/* -------------------------------------------------------------------------- */
/*                    helpers (identical to k-variant)                        */
/* -------------------------------------------------------------------------- */

fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}

/* -------------------------------------------------------------------------- */
/*                                 new type                                   */
/* -------------------------------------------------------------------------- */

/// Scalar field element of **secp256r1 / P-256**
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct P256Scalar(pub [u64; 4]);

/* -------------------------------------------------------------------------- */
/*                           blanket impls / IO                               */
/* -------------------------------------------------------------------------- */

impl Default for P256Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}
impl PartialEq for P256Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.to_canonical_biguint() == other.to_canonical_biguint()
    }
}
impl Eq for P256Scalar {}

impl Hash for P256Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_canonical_biguint().hash(state)
    }
}
impl Display for P256Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.to_canonical_biguint(), f)
    }
}
impl Debug for P256Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.to_canonical_biguint(), f)
    }
}

impl Sample for P256Scalar {
    fn sample<R>(rng: &mut R) -> Self
    where
        R: rand::RngCore + ?Sized,
    {
        use num::bigint::RandBigInt;
        Self::from_noncanonical_biguint(rng.gen_biguint_below(&Self::order()))
    }
}

/* -------------------------------------------------------------------------- */
/*                             Field / PrimeField                             */
/* -------------------------------------------------------------------------- */

impl Field for P256Scalar {
    const ZERO: Self = Self([0; 4]);
    const ONE: Self = Self([1, 0, 0, 0]);
    const TWO: Self = Self([2, 0, 0, 0]);

    // n − 1 (little-endian 64-bit limbs)
    const NEG_ONE: Self = Self([
        0xF3B9CAC2FC632550,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    ]);

    const TWO_ADICITY: usize = 4; // ν₂(n-1) = 4
    const CHARACTERISTIC_TWO_ADICITY: usize = Self::TWO_ADICITY;

    // First small primitive root found with Sage / sympy
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self([7, 0, 0, 0]);

    // g₂ = g^{(n-1)/2⁴}
    const POWER_OF_TWO_GENERATOR: Self = Self([
        0x0592D7FBB41E6602,
        0x1546CAD004378DAF,
        0xBA807ACE842A3DFC,
        0xFFC97F062A770992,
    ]);

    const BITS: usize = 256;

    fn order() -> BigUint {
        BigUint::from_slice(&[
            0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
            0xFFFFFFFF,
        ])
    }
    fn characteristic() -> BigUint {
        Self::order()
    }

    fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.exp_biguint(&(Self::order() - BigUint::one() - BigUint::one())))
    }

    fn from_noncanonical_biguint(val: BigUint) -> Self {
        Self(
            val.to_u64_digits()
                .into_iter()
                .pad_using(4, |_| 0)
                .collect::<Vec<_>>()[..]
                .try_into()
                .expect("error converting to u64 array"),
        )
    }

    #[inline]
    fn from_canonical_u64(n: u64) -> Self {
        Self([n, 0, 0, 0])
    }
    #[inline]
    fn from_noncanonical_u128(n: u128) -> Self {
        Self([n as u64, (n >> 64) as u64, 0, 0])
    }
    #[inline]
    fn from_noncanonical_u96(n: (u64, u32)) -> Self {
        Self([n.0, n.1 as u64, 0, 0])
    }

    fn from_noncanonical_i64(n: i64) -> Self {
        let f = Self::from_canonical_u64(n.unsigned_abs());
        if n < 0 {
            -f
        } else {
            f
        }
    }
    fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }
}

impl PrimeField for P256Scalar {
    fn to_canonical_biguint(&self) -> BigUint {
        let mut res = biguint_from_array(self.0);
        if res >= Self::order() {
            res -= Self::order();
        }
        res
    }
}

/* -------------------------------------------------------------------------- */
/*                             arithmetic impls                               */
/* -------------------------------------------------------------------------- */

impl Neg for P256Scalar {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self::from_noncanonical_biguint(Self::order() - self.to_canonical_biguint())
        }
    }
}
impl Add for P256Scalar {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let mut res = self.to_canonical_biguint() + rhs.to_canonical_biguint();
        if res >= Self::order() {
            res -= Self::order();
        }
        Self::from_noncanonical_biguint(res)
    }
}
impl AddAssign for P256Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sum for P256Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl Sub for P256Scalar {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self + -rhs
    }
}
impl SubAssign for P256Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for P256Scalar {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::from_noncanonical_biguint(
            (self.to_canonical_biguint() * rhs.to_canonical_biguint()).mod_floor(&Self::order()),
        )
    }
}
impl MulAssign for P256Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Product for P256Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, x| acc * x).unwrap_or(Self::ONE)
    }
}

impl Div for P256Scalar {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        p256_scalar_div(self, rhs)
    }
}
impl DivAssign for P256Scalar {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

// Factored out division function to silence Clippy.
fn p256_scalar_div(x: P256Scalar, y: P256Scalar) -> P256Scalar {
    x * y.inverse()
}
