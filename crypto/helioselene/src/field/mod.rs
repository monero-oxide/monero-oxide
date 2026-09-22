#![allow(clippy::needless_range_loop)]

use core::{
  iter::{Product, Sum},
  ops::*,
};

use subtle::*;
use zeroize::{DefaultIsZeroes, Zeroize as _};

use rand_core::RngCore;

use crypto_bigint::{Encoding as _, Word, Limb, U128, U256};

use group::ff::{Field, FieldBits, PrimeField, PrimeFieldBits, FromUniformBytes};

mod verified;

/// The field novel to Helios/Selene.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(transparent)]
pub struct HelioseleneField(pub(crate) U256);

/// The modulus of the field.
const MODULUS: U256 =
  U256::from_be_hex("7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df53");

impl From<u8> for HelioseleneField {
  fn from(a: u8) -> HelioseleneField {
    HelioseleneField(U256::from(a))
  }
}
impl From<u16> for HelioseleneField {
  fn from(a: u16) -> HelioseleneField {
    HelioseleneField(U256::from(a))
  }
}
impl From<u32> for HelioseleneField {
  fn from(a: u32) -> HelioseleneField {
    HelioseleneField(U256::from(a))
  }
}
impl From<u64> for HelioseleneField {
  fn from(a: u64) -> HelioseleneField {
    HelioseleneField(U256::from(a))
  }
}

impl DefaultIsZeroes for HelioseleneField {}

impl ConstantTimeEq for HelioseleneField {
  #[inline(always)]
  fn ct_eq(&self, b: &Self) -> Choice {
    self.0.ct_eq(&b.0)
  }
}

impl ConditionallySelectable for HelioseleneField {
  #[inline(always)]
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Self(<_>::conditional_select(&a.0, &b.0, choice))
  }
}

impl Add<&HelioseleneField> for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn add(self, b: &Self) -> Self::Output {
    self + *b
  }
}
impl AddAssign for HelioseleneField {
  #[inline(always)]
  fn add_assign(&mut self, b: Self) {
    *self = *self + b;
  }
}
impl AddAssign<&HelioseleneField> for HelioseleneField {
  #[inline(always)]
  fn add_assign(&mut self, b: &Self) {
    *self = *self + b;
  }
}
impl Sum for HelioseleneField {
  fn sum<I: Iterator<Item = HelioseleneField>>(iter: I) -> HelioseleneField {
    let mut res = HelioseleneField::ZERO;
    for item in iter {
      res += item;
    }
    res
  }
}
impl<'a> Sum<&'a HelioseleneField> for HelioseleneField {
  fn sum<I: Iterator<Item = &'a HelioseleneField>>(iter: I) -> HelioseleneField {
    iter.copied().sum()
  }
}

impl Neg for &HelioseleneField {
  type Output = HelioseleneField;
  #[inline(always)]
  fn neg(self) -> Self::Output {
    -*self
  }
}

impl Sub<&HelioseleneField> for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn sub(self, b: &Self) -> Self::Output {
    self - *b
  }
}
impl SubAssign for HelioseleneField {
  #[inline(always)]
  fn sub_assign(&mut self, b: Self) {
    *self = *self - b;
  }
}
impl SubAssign<&HelioseleneField> for HelioseleneField {
  #[inline(always)]
  fn sub_assign(&mut self, b: &Self) {
    *self = *self - b;
  }
}

impl Mul<&HelioseleneField> for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn mul(self, b: &Self) -> Self::Output {
    self * *b
  }
}
impl MulAssign for HelioseleneField {
  #[inline(always)]
  fn mul_assign(&mut self, b: Self) {
    *self = *self * b;
  }
}
impl MulAssign<&HelioseleneField> for HelioseleneField {
  #[inline(always)]
  fn mul_assign(&mut self, b: &Self) {
    *self = *self * b;
  }
}
impl Product<HelioseleneField> for HelioseleneField {
  fn product<I: Iterator<Item = HelioseleneField>>(iter: I) -> HelioseleneField {
    let mut res = HelioseleneField::ONE;
    for item in iter {
      res *= item;
    }
    res
  }
}
impl<'a> Product<&'a HelioseleneField> for HelioseleneField {
  fn product<I: Iterator<Item = &'a HelioseleneField>>(iter: I) -> HelioseleneField {
    iter.copied().product()
  }
}

impl HelioseleneField {
  /// A `const fn` to create a `HelioseleneField` element from a `U256`.
  ///
  /// This should only be called at time of compile as it defers to a less efficient
  /// implementation.
  pub(crate) const fn from_u256(value: &U256) -> Self {
    Self(value.const_rem(&MODULUS).0)
  }

  /// Perform an exponentation.
  #[allow(clippy::same_name_method)]
  #[must_use]
  pub fn pow(&self, exp: Self) -> Self {
    verified::pow(self, exp)
  }

  /// Perform a wide reduction.
  ///
  /// This is suitable to obtain a (statistically-close-to-)unbiased Helioselene field element when
  /// the input is uniformly distributed.
  pub fn wide_reduce(mut bytes: [u8; 64]) -> HelioseleneField {
    let result =
      verified::red512((U256::from_le_slice(&bytes[.. 32]), U256::from_le_slice(&bytes[32 ..])));
    bytes.zeroize();
    result
  }
}

impl Field for HelioseleneField {
  const ZERO: Self = Self(U256::ZERO);
  const ONE: Self = Self(U256::ONE);

  #[inline(always)]
  fn is_zero(&self) -> Choice {
    verified::is_zero(self)
  }

  fn random(mut rng: impl RngCore) -> Self {
    let mut a = [0; 32];
    rng.fill_bytes(&mut a);
    let mut b = [0; 32];
    rng.fill_bytes(&mut b);
    let result = verified::red512((U256::from_le_slice(&a), U256::from_le_slice(&b)));
    a.zeroize();
    b.zeroize();
    result
  }

  #[inline(always)]
  fn double(&self) -> Self {
    verified::double(self)
  }

  #[inline(always)]
  fn square(&self) -> Self {
    verified::square(self)
  }

  // Binary GCD Algorithm 1, https://eprint.iacr.org/2020/972
  #[inline(always)]
  fn invert(&self) -> CtOption<Self> {
    verified::invert(self)
  }

  fn sqrt(&self) -> CtOption<Self> {
    verified::sqrt(self)
  }

  fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
    ff::helpers::sqrt_ratio_generic(num, div)
  }
}

impl PrimeField for HelioseleneField {
  type Repr = [u8; 32];

  const MODULUS: &'static str =
    "0x7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df53";

  const NUM_BITS: u32 = 255;
  const CAPACITY: u32 = 254;

  const TWO_INV: Self =
    Self(U256::from_be_hex("3ffffffffffffffffffffffffffffffffb9aa40e8cb4f98bfcc285b46f88efaa"));

  const MULTIPLICATIVE_GENERATOR: Self = Self(U256::from_u8(2));
  const S: u32 = 1;

  const ROOT_OF_UNITY: Self =
    Self(U256::from_be_hex("7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df52"));
  const ROOT_OF_UNITY_INV: Self =
    Self(U256::from_be_hex("7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df52"));

  const DELTA: Self = Self(U256::from_u8(4));

  fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
    verified::from_repr(bytes)
  }

  fn to_repr(&self) -> Self::Repr {
    verified::to_repr(self)
  }

  fn is_odd(&self) -> Choice {
    verified::is_odd(self)
  }
}

impl PrimeFieldBits for HelioseleneField {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    MODULUS.to_le_bytes().into()
  }
}

impl FromUniformBytes<64> for HelioseleneField {
  fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
    Self::wide_reduce(*bytes)
  }
}

// The following tests assume a 64-bit host as it uses crypto-bigint's limbs directly
#[cfg(test)]
#[cfg(target_pointer_width = "64")]
mod tests_assuming_64_bits {
  use super::*;

  #[inline(always)]
  fn lo_hi_concat<T, S: crypto_bigint::Concat<Output = T>>(a: &S, b: &S) -> T {
    S::concat(b, a)
  }

  #[test]
  fn test_wide_reduction() {
    use crypto_bigint::Random as _;
    for _ in 0 .. 1000 {
      let to_reduce = crypto_bigint::U512::random(&mut rand_core::OsRng);
      let reduced = to_reduce.checked_rem(&lo_hi_concat(&MODULUS, &U256::ZERO)).unwrap();
      let reduced_apo = HelioseleneField::wide_reduce(to_reduce.to_le_bytes());
      assert_eq!(
        &reduced.as_limbs()[.. 4],
        reduced_apo.0.as_limbs(),
        "failed to reduce {:?}",
        to_reduce.to_words(),
      );
    }

    let to_reduce = crypto_bigint::U512::MAX;
    let reduced = to_reduce.checked_rem(&lo_hi_concat(&MODULUS, &U256::ZERO)).unwrap();
    let reduced_apo = HelioseleneField::wide_reduce(to_reduce.to_le_bytes());
    assert_eq!(
      &reduced.as_limbs()[.. 4],
      reduced_apo.0.as_limbs(),
      "failed to reduce {:?}",
      to_reduce.to_words(),
    );
  }
}

#[test]
fn test_helioselene_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, HelioseleneField>(&mut rand_core::OsRng);
}
