#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

extern crate alloc;
use alloc::{boxed::Box, vec, vec::Vec};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group,
};

mod poly;
pub use poly::Poly;

#[cfg(test)]
mod tests;

/// A curve usable with this library.
pub trait DivisorCurve: Group + ConstantTimeEq + ConditionallySelectable + Zeroize {
  /// An element of the field this curve is defined over.
  type FieldElement: Zeroize + PrimeField + ConditionallySelectable;

  /// The A in the curve equation `y^2 = x^3 + A x + B`.
  fn a() -> Self::FieldElement;
  /// The B in the curve equation `y^2 = x^3 + A x + B`.
  fn b() -> Self::FieldElement;

  /// Convert a point to its affine coordinates.
  ///
  /// Returns `None` if passed the point at infinity.
  ///
  /// This function may run in time variable to if the point is the identity.
  fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)>;
}

/// Calculate the slope and intercept between two points.
///
/// This function panics when `a @ infinity`, `b @ infinity`, `a == b`, or when `a == -b`.
pub(crate) fn slope_intercept<C: DivisorCurve>(a: C, b: C) -> (C::FieldElement, C::FieldElement) {
  let (ax, ay) = C::to_xy(a).unwrap();
  debug_assert_eq!(divisor_modulus::<C>().eval(ax, ay), C::FieldElement::ZERO);
  let (bx, by) = C::to_xy(b).unwrap();
  debug_assert_eq!(divisor_modulus::<C>().eval(bx, by), C::FieldElement::ZERO);
  let slope = (by - ay) *
    Option::<C::FieldElement>::from((bx - ax).invert())
      .expect("trying to get slope/intercept of points sharing an x coordinate");
  let intercept = by - (slope * bx);
  debug_assert!(bool::from((ay - (slope * ax) - intercept).is_zero()));
  debug_assert!(bool::from((by - (slope * bx) - intercept).is_zero()));
  (slope, intercept)
}

// The line interpolating two points.
fn line<C: DivisorCurve>(a: C, b: C) -> Poly<C::FieldElement> {
  #[expect(clippy::struct_field_names)]
  #[derive(Clone, Copy)]
  struct LineRes<F: ConditionallySelectable> {
    y_coefficient: F,
    x_coefficient: F,
    zero_coefficient: F,
  }
  impl<F: ConditionallySelectable> ConditionallySelectable for LineRes<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
      Self {
        y_coefficient: <_>::conditional_select(&a.y_coefficient, &b.y_coefficient, choice),
        x_coefficient: <_>::conditional_select(&a.x_coefficient, &b.x_coefficient, choice),
        zero_coefficient: <_>::conditional_select(&a.zero_coefficient, &b.zero_coefficient, choice),
      }
    }
  }

  let a_is_identity = a.is_identity();
  let b_is_identity = b.is_identity();

  // If they're both the point at infinity, we simply set the line to one
  let both_are_identity = a_is_identity & b_is_identity;
  let if_both_are_identity = LineRes {
    y_coefficient: C::FieldElement::ZERO,
    x_coefficient: C::FieldElement::ZERO,
    zero_coefficient: C::FieldElement::ONE,
  };

  // If either point is the point at infinity, or these are additive inverses, the line is
  // `1 * x - x`. The first `x` is a term in the polynomial, the `x` is the `x` coordinate of these
  // points (of which there is one, as the second point is either at infinity or has a matching `x`
  // coordinate).
  let one_is_identity = a_is_identity | b_is_identity;
  let additive_inverses = a.ct_eq(&-b);
  let one_is_identity_or_additive_inverses = one_is_identity | additive_inverses;
  let if_one_is_identity_or_additive_inverses = {
    // If both are identity, set `a` to the generator so we can safely evaluate the following
    // (which we won't select at the end of this function)
    let a = <_>::conditional_select(&a, &C::generator(), both_are_identity);
    // If `a` is identity, this selects `b`. If `a` isn't identity, this selects `a`
    let non_identity = <_>::conditional_select(&a, &b, a.is_identity());
    let (x, _) = C::to_xy(non_identity).unwrap();
    LineRes {
      y_coefficient: C::FieldElement::ZERO,
      x_coefficient: C::FieldElement::ONE,
      zero_coefficient: -x,
    }
  };

  // The following calculation assumes neither point is the point at infinity
  // If either are, we use a prior result
  // To ensure we can calculcate a result here, set any points at infinity to the generator
  let a = <_>::conditional_select(&a, &C::generator(), a_is_identity);
  let b = <_>::conditional_select(&b, &C::generator(), b_is_identity);
  // It also assumes a, b aren't additive inverses which is also covered by a prior result
  let b = <_>::conditional_select(&b, &a.double(), additive_inverses);

  // If the points are equal, we use the line interpolating the sum of these points with the point
  // at infinity
  let b = <_>::conditional_select(&b, &-a.double(), a.ct_eq(&b));

  let (slope, intercept) = slope_intercept::<C>(a, b);

  // Section 4 of the proofs explicitly state the line `L = y - lambda * x - mu`
  // y - (slope * x) - intercept
  let mut res = LineRes {
    y_coefficient: C::FieldElement::ONE,
    x_coefficient: -slope,
    zero_coefficient: -intercept,
  };

  res = <_>::conditional_select(
    &res,
    &if_one_is_identity_or_additive_inverses,
    one_is_identity_or_additive_inverses,
  );
  res = <_>::conditional_select(&res, &if_both_are_identity, both_are_identity);

  Poly {
    y_coefficients: vec![res.y_coefficient].into_boxed_slice(),
    yx_coefficients: vec![],
    x_coefficients: vec![res.x_coefficient].into_boxed_slice(),
    zero_coefficient: res.zero_coefficient,
  }
}

/// y^2 - x^3 - A x - B
///
/// Section 2 of Eagen's security proofs define this modulus.
fn divisor_modulus<C: DivisorCurve>() -> Poly<C::FieldElement> {
  Poly {
    // 0 y**1, 1 y*2
    y_coefficients: vec![C::FieldElement::ZERO, C::FieldElement::ONE].into_boxed_slice(),
    yx_coefficients: vec![],
    x_coefficients: vec![
      // - A x
      -C::a(),
      // 0 x^2
      C::FieldElement::ZERO,
      // - x^3
      -C::FieldElement::ONE,
    ]
    .into_boxed_slice(),
    // - B
    zero_coefficient: -C::b(),
  }
}

/// Create a divisor interpolating the following points.
///
/// Returns None if:
///   - No points were passed in
///   - The points don't sum to the point at infinity
///   - A passed in point was the point at infinity
///
/// If the arguments were valid, this function executes in an amount of time constant to the amount
/// of points.
#[allow(clippy::new_ret_no_self)]
pub fn new_divisor<C: DivisorCurve>(points: &[C]) -> Option<Poly<C::FieldElement>> {
  // No points were passed in, this is the point at infinity, or the single point isn't infinity
  // and accordingly doesn't sum to infinity. All three cause us to return None
  // Checks a bit other than the first bit is set, meaning this is >= 2
  let mut invalid_args = (points.len() & (!1)).ct_eq(&0);
  // The points don't sum to the point at infinity
  let sum = points.iter().copied().sum::<C>();
  invalid_args |= !sum.is_identity();
  // A point was the point at identity
  for point in points {
    invalid_args |= point.is_identity();
  }
  if bool::from(invalid_args) {
    None?;
  }

  let points_len = points.len();

  let mut modulus = divisor_modulus::<C>();
  // Create the initial set of divisors
  let mut divs = vec![];
  let mut iter = points.iter().copied();
  while let Some(a) = iter.next() {
    let b = iter.next();

    /*
      Draw the line between these points.

      These `unwrap`s are branching on the length of the iterator, without violating the desired
      constant-time properties.
    */
    divs.push((2, a + b.unwrap_or_else(C::identity), line::<C>(a, b.unwrap_or(-a))));
  }

  // Our Poly algorithm is leaky and will create an excessive amount of y x**j and x**j
  // coefficients which are zero, yet as our implementation is constant time, still come with
  // an immense performance cost. This code truncates the coefficients we know are zero.
  let trim = |divisor: &mut Poly<_>, points_len: usize| {
    // We should only be trimming divisors reduced by the modulus
    debug_assert!(divisor.yx_coefficients.len() <= 1);
    if divisor.yx_coefficients.len() == 1 {
      let truncate_to = points_len.div_ceil(2).saturating_sub(2);
      for coeff in divisor.yx_coefficients[0].iter().skip(truncate_to) {
        debug_assert_eq!(*coeff, <C::FieldElement as Field>::ZERO);
      }
      let mut yx_coefficients = Box::from(&divisor.yx_coefficients[0][.. truncate_to]);
      core::mem::swap(&mut divisor.yx_coefficients[0], &mut yx_coefficients);
      yx_coefficients.zeroize();
    }
    {
      let truncate_to = points_len / 2;
      for coeff in divisor.x_coefficients.iter().skip(truncate_to) {
        debug_assert_eq!(*coeff, <C::FieldElement as Field>::ZERO);
      }
      let mut x_coefficients = Box::from(&divisor.x_coefficients[.. truncate_to]);
      core::mem::swap(&mut divisor.x_coefficients, &mut x_coefficients);
      x_coefficients.zeroize();
    }
  };

  // Pair them off until only one remains
  while divs.len() > 1 {
    let mut next_divs = vec![];
    // If there's an odd amount of divisors, carry the odd one out to the next iteration
    if (divs.len() % 2) == 1 {
      next_divs.push(divs.pop().unwrap());
    }

    while let Some((a_points, a, a_div)) = divs.pop() {
      let (b_points, b, b_div) = divs.pop().unwrap();
      let points = a_points + b_points;

      // Merge the two divisors
      let numerator = a_div.mul_mod(&b_div, &mut modulus).mul_mod(&line::<C>(a, b), &mut modulus);
      let mut denominator = line::<C>(a, -a).mul_mod(&line::<C>(b, -b), &mut modulus);
      let (mut q, r) = numerator.div_rem(&mut denominator);
      debug_assert!(bool::from(r.is_zero()));
      trim(&mut q, 1 + points);
      next_divs.push((points, a + b, q));
    }

    divs = next_divs;
  }

  // Return the unified divisor
  let (_points, _point, mut divisor) = divs.remove(0);
  trim(&mut divisor, points_len);
  Some(divisor)
}

/// The decomposition of a scalar.
///
/// The decomposition ($d$) of a scalar ($s$) has the following two properties:
///
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i * 2^i = s$
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i = \mathsf{NUM_BITS}$
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScalarDecomposition<F: Zeroize + PrimeFieldBits> {
  scalar: F,
  decomposition: Vec<u64>,
}

impl<F: Zeroize + PrimeFieldBits> ScalarDecomposition<F> {
  /// Decompose a non-zero scalar.
  ///
  /// Returns `None` if the scalar is zero.
  ///
  /// This function is constant time if the scalar is non-zero.
  pub fn new(scalar: F) -> Option<Self> {
    if bool::from(scalar.is_zero()) {
      None?;
    }

    /*
      We need the sum of the coefficients to equal F::NUM_BITS. The scalar's bits will be less than
      F::NUM_BITS. Accordingly, we need to increment the sum of the coefficients without
      incrementing the scalar represented. We do this by finding the highest non-0 coefficient,
      decrementing it, and increasing the immediately less significant coefficient by 2. This
      increases the sum of the coefficients by 1 (-1+2=1).
    */

    let num_bits = u64::from(F::NUM_BITS);

    // Obtain the bits of the scalar
    let num_bits_usize = usize::try_from(num_bits).unwrap();
    let mut decomposition = vec![0; num_bits_usize];
    for (i, bit) in scalar.to_le_bits().into_iter().take(num_bits_usize).enumerate() {
      let bit = u64::from(u8::from(bit));
      decomposition[i] = bit;
    }

    // The following algorithm only works if the value of the scalar exceeds num_bits
    // If it isn't, we increase it by the modulus such that it does exceed num_bits
    {
      let mut less_than_num_bits = Choice::from(0);
      for i in 0 .. num_bits {
        less_than_num_bits |= scalar.ct_eq(&F::from(i));
      }
      let mut decomposition_of_modulus = vec![0; num_bits_usize];
      // Decompose negative one
      for (i, bit) in (-F::ONE).to_le_bits().into_iter().take(num_bits_usize).enumerate() {
        let bit = u64::from(u8::from(bit));
        decomposition_of_modulus[i] = bit;
      }
      // Increment it by one
      decomposition_of_modulus[0] += 1;

      // Add the decomposition onto the decomposition of the modulus
      for i in 0 .. num_bits_usize {
        let new_decomposition = <_>::conditional_select(
          &decomposition[i],
          &(decomposition[i] + decomposition_of_modulus[i]),
          less_than_num_bits,
        );
        decomposition[i] = new_decomposition;
      }
    }

    // Calculcate the sum of the coefficients
    let mut sum_of_coefficients: u64 = 0;
    for decomposition in &decomposition {
      sum_of_coefficients += *decomposition;
    }

    /*
      Now, because we added a log2(k)-bit number to a k-bit number, we may have our sum of
      coefficients be *too high*. We attempt to reduce the sum of the coefficients accordingly.

      This algorithm is guaranteed to complete as expected. Take the sequence `222`. `222` becomes
      `032` becomes `013`. Even if the next coefficient in the sequence is `2`, the third
      coefficient will be reduced once and the next coefficient (`2`, increased to `3`) will only
      be eligible for reduction once. This demonstrates, even for a worst case of log2(k) `2`s
      followed by `1`s (as possible if the modulus is a Mersenne prime), the log2(k) `2`s can be
      reduced as necessary so long as there is a single coefficient after (requiring the entire
      sequence be at least of length log2(k) + 1). For a 2-bit number, log2(k) + 1 == 2, so this
      holds for any odd prime field.

      To fully type out the demonstration for the Mersenne prime 3, with scalar to encode 1 (the
      highest value less than the number of bits):

      10 - Little-endian bits of 1
      21 - Little-endian bits of 1, plus the modulus
      02 - After one reduction, where the sum of the coefficients does in fact equal 2 (the target)
    */
    {
      let mut log2_num_bits = 0;
      while (1 << log2_num_bits) < num_bits {
        log2_num_bits += 1;
      }

      for _ in 0 .. log2_num_bits {
        // If the sum of coefficients is the amount of bits, we're done
        let mut done = sum_of_coefficients.ct_eq(&num_bits);

        for i in 0 .. (num_bits_usize - 1) {
          let should_act = (!done) & decomposition[i].ct_gt(&1);
          // Subtract 2 from this coefficient
          let amount_to_sub = <_>::conditional_select(&0, &2, should_act);
          decomposition[i] -= amount_to_sub;
          // Add 1 to the next coefficient
          let amount_to_add = <_>::conditional_select(&0, &1, should_act);
          decomposition[i + 1] += amount_to_add;

          // Also update the sum of coefficients
          sum_of_coefficients -= <_>::conditional_select(&0, &1, should_act);

          // If we updated the coefficients this loop iter, we're done for this loop iter
          done |= should_act;
        }
      }
    }

    for _ in 0 .. num_bits {
      // If the sum of coefficients is the amount of bits, we're done
      let mut done = sum_of_coefficients.ct_eq(&num_bits);

      // Find the highest coefficient currently non-zero
      for i in (1 .. decomposition.len()).rev() {
        // If this is non-zero, we should decrement this coefficient if we haven't already
        // decremented a coefficient this round
        let is_non_zero = !(0.ct_eq(&decomposition[i]));
        let should_act = (!done) & is_non_zero;

        // Update this coefficient and the prior coefficient
        let amount_to_sub = <_>::conditional_select(&0, &1, should_act);
        decomposition[i] -= amount_to_sub;

        let amount_to_add = <_>::conditional_select(&0, &2, should_act);
        // i must be at least 1, so i - 1 will be at least 0 (meaning it's safe to index with)
        decomposition[i - 1] += amount_to_add;

        // Also update the sum of coefficients
        sum_of_coefficients += <_>::conditional_select(&0, &1, should_act);

        // If we updated the coefficients this loop iter, we're done for this loop iter
        done |= should_act;
      }
    }
    debug_assert!(bool::from(decomposition.iter().sum::<u64>().ct_eq(&num_bits)));

    Some(ScalarDecomposition { scalar, decomposition })
  }

  /// The scalar.
  pub fn scalar(&self) -> &F {
    &self.scalar
  }

  /// The decomposition of the scalar.
  pub fn decomposition(&self) -> &[u64] {
    &self.decomposition
  }

  /// A divisor to prove a scalar multiplication.
  ///
  /// The divisor will interpolate $-(s \cdot G)$ with $d_i$ instances of $2^i \cdot G$.
  ///
  /// This function executes in constant time with regards to the scalar.
  ///
  /// This function MAY panic on integer overflow or if the generator is the point at infinity.
  pub fn scalar_mul_divisor<C: Zeroize + DivisorCurve<Scalar = F>>(
    &self,
    generator: C,
  ) -> Poly<C::FieldElement> {
    // 1 is used for the resulting point, NUM_BITS is used for the decomposition, and then we store
    // one additional index in a usize for the points we shouldn't write at all (hence the +2)
    let _ = usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 2)
      .expect("NUM_BITS + 2 didn't fit in usize");
    let mut divisor_points =
      vec![C::identity(); usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 1).unwrap()];

    // Write the inverse of the resulting point
    divisor_points[0] = -generator * self.scalar;
    let mut generator = generator;

    // Write the decomposition
    let mut write_above: u64 = 0;
    for coefficient in &self.decomposition {
      // Write the generator to every slot except the slots we have already written to.
      for i in 1 ..= <C::Scalar as PrimeField>::NUM_BITS {
        divisor_points[usize::try_from(i).unwrap()]
          .conditional_assign(&generator, u64::from(i).ct_gt(&write_above));
      }

      // Increase the next write start by the coefficient.
      write_above += coefficient;
      generator = generator.double();
    }

    // Create a divisor out of the points
    let res = new_divisor::<C>(&divisor_points).unwrap();
    divisor_points.zeroize();
    res
  }
}

#[cfg(any(test, feature = "ed25519"))]
mod ed25519 {
  use subtle::{Choice, ConditionallySelectable as _};
  use group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  };

  use dalek_ff_group::{FieldElement, EdwardsPoint};

  impl crate::DivisorCurve for EdwardsPoint {
    type FieldElement = FieldElement;

    // Wei25519 a/b
    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.3
    fn a() -> Self::FieldElement {
      use crypto_bigint::U256;
      Self::FieldElement::from_u256(&U256::from_be_hex(
        "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144",
      ))
    }
    fn b() -> Self::FieldElement {
      use crypto_bigint::U256;
      Self::FieldElement::from_u256(&U256::from_be_hex(
        "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864",
      ))
    }

    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.2
    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      if bool::from(point.is_identity()) {
        None?;
      }

      // Extract the y coordinate from the compressed point
      let mut edwards_y = point.to_bytes();
      let x_is_odd = edwards_y[31] >> 7;
      edwards_y[31] &= (1 << 7) - 1;
      let edwards_y = Self::FieldElement::from_repr(edwards_y)
        .expect("valid point compressed had an invalid coordinate");

      use crypto_bigint::{
        modular::runtime_mod::{DynResidueParams, DynResidue},
        U256,
      };
      const MODULUS: DynResidueParams<{ U256::LIMBS }> =
        DynResidueParams::new(&U256::ONE.shl_vartime(255).wrapping_sub(&U256::from_u64(19)));

      // Recover the x coordinate
      let edwards_y_sq = edwards_y * edwards_y;

      const D: FieldElement = FieldElement::from_u256(
        &DynResidue::new(&U256::from_u64(121_665), MODULUS)
          .neg()
          .mul(&DynResidue::new(&U256::from_u64(121_666), MODULUS).invert().0)
          .retrieve(),
      );

      let mut edwards_x = ((edwards_y_sq - Self::FieldElement::ONE) *
        ((D * edwards_y_sq) + Self::FieldElement::ONE)
          .invert()
          .expect("couldn't recover x coordinate from y coordinate of valid point"))
      .sqrt()
      .expect("couldn't recover x coordinate from y coordinate of valid point");

      // Negate the x coordinate if the sign doesn't match
      edwards_x = <_>::conditional_select(
        &edwards_x,
        &-edwards_x,
        edwards_x.is_odd() ^ Choice::from(x_is_odd),
      );

      const Y_TO_X_MAP_CONST: FieldElement = FieldElement::from_u256(
        &DynResidue::new(&U256::from_u64(486_662), MODULUS)
          .mul(&DynResidue::new(&U256::from_u64(3), MODULUS).invert().0)
          .retrieve(),
      );

      // Calculate the x and y coordinates for Wei25519
      let edwards_y_plus_one = Self::FieldElement::ONE + edwards_y;
      let one_minus_edwards_y = Self::FieldElement::ONE - edwards_y;
      let wei_x = (edwards_y_plus_one *
        one_minus_edwards_y
          .invert()
          .expect("couldn't map non-identity Ed25519 point's y coordinate to Wei25519 x")) +
        Y_TO_X_MAP_CONST;

      const C_SQUARE: DynResidue<{ U256::LIMBS }> =
        DynResidue::new(&U256::from_u64(486_662 + 2), MODULUS).neg();
      const C_I: DynResidue<{ U256::LIMBS }> =
        C_SQUARE.pow(&MODULUS.modulus().wrapping_add(&U256::from_u64(3)).shr_vartime(3));
      const SQRT_M1: DynResidue<{ U256::LIMBS }> = DynResidue::new(
        &U256::from_be_hex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0"),
        MODULUS,
      );
      const C: FieldElement = FieldElement::from_u256(&C_I.mul(&SQRT_M1).neg().retrieve());
      debug_assert_eq!(C.square(), FieldElement::from_u256(&C_SQUARE.retrieve()));

      let wei_y = C *
        edwards_y_plus_one *
        (one_minus_edwards_y * edwards_x)
          .invert()
          .expect("couldn't map non-identity Ed25519 point's x coordinate to Wei25519 y");
      Some((wei_x, wei_y))
    }
  }
}
