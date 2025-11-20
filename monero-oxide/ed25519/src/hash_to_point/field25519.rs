use crypto_bigint::{Limb, Word, U256};

const LAST_LIMB: usize = U256::LIMBS - 1;
const HIGH_BIT: Word = 1 << (Limb::BITS - 1);
const ALL_BUT_HIGH_BIT: Word = !HIGH_BIT;
const HIGH_TWO_BITS: Word = HIGH_BIT | (1 << (Limb::BITS - 2));

const MODULUS: U256 =
  U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

const INVERTER: crypto_bigint::modular::SafeGcdInverter<
  { U256::LIMBS },
  { (U256::BITS + 64).div_ceil(62) as usize },
> = crypto_bigint::modular::SafeGcdInverter::new(
  &MODULUS.to_odd().expect("2^255 - 19 is odd"),
  &U256::ONE,
);

// (p + 3) // 8
const SQRT_EXP: U256 = MODULUS.shr_vartime(3).wrapping_add(&U256::ONE);
// 2^{(p - 1) // 4}
pub(crate) const Z: Field25519 = Field25519(U256::from_u8(2)).pow(MODULUS.shr_vartime(2));

#[derive(Clone, Copy)]
pub(crate) struct Field25519(U256);
impl Field25519 {
  pub(crate) const ZERO: Self = Self(U256::ZERO);
  pub(crate) const ONE: Self = Self(U256::ONE);

  const fn reduce_once(value: U256) -> Self {
    let mut reduced = value;
    let limbs = reduced.as_limbs_mut();

    if (limbs[LAST_LIMB].0 & HIGH_TWO_BITS) == 0 {
      return Self(value);
    }

    let mut i = 0;
    let mut carry = 19;
    while i < U256::LIMBS {
      let carry_bool;
      (limbs[i].0, carry_bool) = limbs[i].0.overflowing_add(carry);
      if !carry_bool {
        break;
      }
      carry = carry_bool as Word;
      i = i.wrapping_add(1);
    }

    if (limbs[LAST_LIMB].0 & HIGH_BIT) != 0 {
      limbs[LAST_LIMB].0 &= ALL_BUT_HIGH_BIT;
      return Self(reduced);
    }
    Self(value)
  }

  pub(crate) const fn reduce(mut value: U256) -> Self {
    let limbs = value.as_limbs_mut();
    if (limbs[LAST_LIMB].0 & HIGH_BIT) != 0 {
      limbs[LAST_LIMB].0 &= ALL_BUT_HIGH_BIT;
      let mut i = 0;
      let mut carry = 19;
      while i < U256::LIMBS {
        let carry_bool;
        (limbs[i].0, carry_bool) = limbs[i].0.overflowing_add(carry);
        if !carry_bool {
          break;
        }
        carry = carry_bool as Word;
        i = i.wrapping_add(1);
      }
    }

    Self::reduce_once(value)
  }

  #[allow(clippy::cast_possible_truncation)]
  const fn wide_reduce_limb_256(lo: U256, carry: Limb) -> Self {
    let mut result = Self::reduce(lo).0;
    let limbs = result.as_limbs_mut();
    let mut i = 0;
    let mut carry = carry.0 * 38;
    while i < U256::LIMBS {
      let carry_bool;
      (limbs[i].0, carry_bool) = limbs[i].0.overflowing_add(carry);
      if !carry_bool {
        break;
      }
      carry = carry_bool as Word;
      i = i.wrapping_add(1);
    }
    Self(result)
  }

  #[allow(clippy::cast_possible_truncation)]
  const fn wide_reduce_256(mut lo: U256, hi: U256) -> Self {
    let lo_limbs = lo.as_limbs_mut();
    let hi = hi.as_limbs();

    let mut i = 0;
    let mut carry = Limb(0);
    while i < U256::LIMBS {
      (lo_limbs[i], carry) = lo_limbs[i].mac(hi[i], Limb(38), carry);
      i = i.wrapping_add(1);
    }

    Self::wide_reduce_limb_256(lo, carry)
  }

  const fn wide_reduce(lo: U256, hi: U256) -> Self {
    Self::reduce_once(Self::wide_reduce_256(lo, hi).0)
  }

  pub(crate) const fn add(&self, other: Self) -> Self {
    let unreduced = self.0.wrapping_add(&other.0);
    Self::reduce_once(unreduced)
  }

  pub(crate) const fn add_one(mut self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let mut i = 0;
    let mut carry_bool = true;
    while i < U256::LIMBS {
      (limbs[0].0, carry_bool) = limbs[0].0.overflowing_add(carry_bool as Word);
      i = i.wrapping_add(1);
    }
    Self::reduce_once(self.0)
  }

  pub(crate) const fn add_limb(mut self, limb: Limb) -> Self {
    let limbs = self.0.as_limbs_mut();
    let mut i = 0;
    let mut carry = limb.0;
    while i < U256::LIMBS {
      let carry_bool;
      (limbs[0].0, carry_bool) = limbs[0].0.overflowing_add(carry);
      carry = carry_bool as Word;
      i = i.wrapping_add(1);
    }
    Self::reduce_once(self.0)
  }

  pub(crate) const fn double(&self) -> Self {
    let unreduced = self.0.wrapping_shl(1);
    Self::reduce_once(unreduced)
  }

  pub(crate) const fn neg(mut self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let modulus = MODULUS.as_limbs();
    let mut borrow = Limb::ZERO;
    let mut i = 0;
    while i < U256::LIMBS {
      (limbs[i], borrow) = modulus[i].sbb(limbs[i], borrow);
      i = i.wrapping_add(1);
    }
    self
  }

  pub(crate) const fn sub(mut self, other: Self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let other = other.0.as_limbs();
    let mut borrow = Limb::ZERO;
    let mut i = 0;
    while i < U256::LIMBS {
      (limbs[i], borrow) = limbs[i].sbb(other[i], borrow);
      i = i.wrapping_add(1);
    }
    if borrow.0 != 0 {
      self.0 = self.0.wrapping_add(&MODULUS);
    }
    self
  }

  pub(crate) const fn sub_one(mut self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let mut borrow = true;
    let mut i = 0;
    while i < U256::LIMBS {
      (limbs[i].0, borrow) = limbs[i].0.overflowing_sub(borrow as Word);
      i = i.wrapping_add(1);
    }
    if borrow {
      self.0 = self.0.wrapping_add(&MODULUS);
    }
    self
  }

  pub(crate) const fn mul(&self, other: Self) -> Self {
    let (lo, hi) = self.0.split_mul(&other.0);
    Self::wide_reduce(lo, hi)
  }
  pub(crate) const fn square(&self) -> Self {
    let (lo, hi) = self.0.square_wide();
    Self::wide_reduce(lo, hi)
  }

  pub(crate) const fn mul_limb(&self, other: Limb) -> Self {
    let (lo, hi) = self.0.split_mul(&U256::from_word(other.0));
    Self::reduce_once(Self::wide_reduce_limb_256(lo, hi.to_limbs()[0]).0)
  }

  // Multiplication functions which reduce to 256 bits, not by the modulus.
  //
  // These allow correctly chaining multiplicative operations with less overhead.
  pub(crate) const fn chained_mul(&self, other: Self) -> Self {
    let (lo, hi) = self.0.split_mul(&other.0);
    Self::wide_reduce_256(lo, hi)
  }
  pub(crate) const fn chained_square(&self) -> Self {
    let (lo, hi) = self.0.square_wide();
    Self::wide_reduce_256(lo, hi)
  }

  pub(crate) const fn inv(&self) -> Self {
    Self(INVERTER.inv_vartime(&self.0).expect("requested inverse of number without inverse"))
  }

  const fn pow(&self, exp: U256) -> Self {
    let mut result = Self::ONE;
    let mut result_used = false;
    let mut i = 255;
    while i > 0 {
      if result_used {
        result = result.chained_square();
      }
      if exp.bit_vartime(i) {
        result_used = true;
        result = result.chained_mul(*self);
      }
      i = i.wrapping_sub(1);
    }
    result = result.chained_square();
    if exp.bit_vartime(i) {
      result = result.chained_mul(*self);
    }
    Self::reduce(result.0)
  }

  pub(crate) const fn sqrt(&self) -> Option<Self> {
    let y = self.pow(SQRT_EXP);
    if y.mul(y).eq(*self) {
      return Some(y);
    }
    let other = y.mul(Z);
    if other.mul(other).eq(*self) {
      return Some(other);
    }
    None
  }

  pub(crate) const fn eq(&self, other: Self) -> bool {
    let mut eq = true;
    let mut i = 0;
    let limbs = self.0.as_limbs();
    let other = other.0.as_limbs();
    while i < U256::LIMBS {
      eq &= limbs[i].0 == other[i].0;
      i = i.wrapping_add(1);
    }
    eq
  }

  pub(crate) const fn retrieve(&self) -> U256 {
    self.0
  }
}
