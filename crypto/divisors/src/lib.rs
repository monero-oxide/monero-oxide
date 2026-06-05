#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use core::{borrow::Borrow, ops::Add as _};
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{vec, vec::Vec};

use subtle::{Choice, CtOption, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use group::{
  ff::{Field, PrimeField, PrimeFieldBits, BatchInvert as _},
  Group,
};

mod barycentric;
pub use barycentric::Interpolator;

mod divisor;
use divisor::{SmallDivisor, Divisor};

mod ec;
pub use ec::{Projective, XyPoint};

mod poly;
pub use poly::Poly;

#[cfg(test)]
mod tests;

/// A curve usable with this library.
pub trait DivisorCurve: Group + ConstantTimeEq + ConditionallySelectable + Zeroize {
  /// An element of the field this curve is defined over.
  type FieldElement: Zeroize + PrimeField + ConditionallySelectable;
  /// A point for which it's sufficiently efficient to retrieve the affine coordinates.
  type XyPoint: XyPoint<Self::FieldElement> + From<Self>;

  /// The A in the curve equation `y^2 = x^3 + A x + B`.
  fn a() -> Self::FieldElement;
  /// The B in the curve equation `y^2 = x^3 + A x + B`.
  fn b() -> Self::FieldElement;

  /// The type representing an interpolator which has been borrowed.
  // TODO: Remove with Rust 1.75
  type BorrowedInterpolator: Borrow<Interpolator<Self::FieldElement>>;
  /// Precomputed interpolator required for interpolating a divisor representing a scalar
  /// multiplication.
  fn interpolator_for_scalar_mul() -> Self::BorrowedInterpolator;

  /// Convert a point to its affine coordinates.
  ///
  /// Returns `None` if passed the point at infinity.
  ///
  /// This function may run in time variable to if the point is the identity.
  fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)>;
}

type Xy<C> = (<C as DivisorCurve>::FieldElement, <C as DivisorCurve>::FieldElement);
type Denom<C> =
  (CtOption<<C as DivisorCurve>::FieldElement>, CtOption<<C as DivisorCurve>::FieldElement>);

struct LineArgs<C: DivisorCurve> {
  /// The `b` to use when calculating the line.
  ///
  /// This will be distinct if the points would otherwise share an `x` coordinate.
  b: C::XyPoint,
  /// If both points were the identity point.
  both_are_identity: Choice,
  /// If one point was the identity, or the points were additive inverses, and the single `x`
  /// coordinate between the two if so.
  one_is_identity_or_additive_inverses: (Choice, C::FieldElement),
}

/// Prepare points to calculate their lines.
fn line_args<C: DivisorCurve>(
  a: C::XyPoint,
  b: C::XyPoint,
  a_x: C::FieldElement,
  b_x: C::FieldElement,
  gen: &C::XyPoint,
) -> LineArgs<C> {
  let a_is_identity = a.is_identity();
  let b_is_identity = b.is_identity();

  let both_are_identity = a_is_identity & b_is_identity;

  let one_is_identity = a_is_identity | b_is_identity;
  let additive_inverses = a.ct_eq(&-b);
  let one_is_identity_or_additive_inverses = one_is_identity | additive_inverses;
  let one_is_identity_or_additive_inverses =
    (one_is_identity_or_additive_inverses, <_>::conditional_select(&a_x, &b_x, a.is_identity()));

  let a = <_>::conditional_select(&a, gen, a_is_identity);
  let b = <_>::conditional_select(&b, gen, b_is_identity);
  let b = <_>::conditional_select(&b, &a.double(), additive_inverses);
  let b = <_>::conditional_select(&b, &-a.double(), a.ct_eq(&b));

  LineArgs { b, both_are_identity, one_is_identity_or_additive_inverses }
}

/// Computes all (slope, intercept) pairs, batching inverses.
///
/// This will have undefined behavior if two points sharing an `x` coordinate is passed in.
fn slopes_and_intercepts<C: DivisorCurve>(
  a: Vec<Xy<C>>,
  b: &[C::XyPoint],
) -> Vec<(C::FieldElement, C::FieldElement)> {
  debug_assert_eq!(a.len(), b.len());
  let b: Vec<Xy<C>> = C::XyPoint::batch_to_xy(b);
  let mut diffs = a
    .iter()
    .zip(b.iter())
    .map(|(a, b)| {
      let (ax, bx) = (a.0, b.0);
      bx - ax
    })
    .collect::<Vec<_>>();

  (&mut diffs).batch_invert();

  a.into_iter()
    .zip(b)
    .zip(diffs)
    .map(|((a, b), inv_diff)| {
      let (ax, ay) = a;
      let (bx, by) = b;

      let slope = (by - ay) * inv_diff;
      let intercept = by - (slope * bx);
      debug_assert!(bool::from((ay - (slope * ax) - intercept).is_zero()));
      debug_assert!(bool::from((by - (slope * bx) - intercept).is_zero()));
      (slope, intercept)
    })
    .collect()
}

/// Complete calculation of a line from its arguments and the (potentitally stubbed)
/// slope/intercept.
fn finish_line<F: PrimeField>(
  slope: F,
  intercept: F,
  both_are_identity: Choice,
  one_is_identity_or_additive_inverses: (Choice, F),
) -> SmallDivisor<F> {
  // y - slope x - intercept
  let mut res = SmallDivisor::new(-slope, -intercept, F::ONE);
  // `x - x`, where the first `x` is the coefficient and the second `x` is a constant of the `x`
  // coordinate present within this pair of points
  let (one_is_identity_or_additive_inverses, constant_term) = one_is_identity_or_additive_inverses;
  res = <_>::conditional_select(
    &res,
    &SmallDivisor::new(F::ONE, -constant_term, F::ZERO),
    one_is_identity_or_additive_inverses,
  );
  // 1
  <_>::conditional_select(&res, &SmallDivisor::new(F::ZERO, F::ONE, F::ZERO), both_are_identity)
}

/// Computes all lines required to construct a divisor, batching expensive operations.
fn lines_and_denoms<C: DivisorCurve>(
  points: &[C::XyPoint],
) -> Vec<(SmallDivisor<C::FieldElement>, Denom<C>)> {
  // All the pairs of points from which lines will be created
  let pairs = {
    let mut pairs = Vec::<[C::XyPoint; 2]>::with_capacity(points.len());
    let mut divs = Vec::<C::XyPoint>::with_capacity(points.len().div_ceil(2));

    let mut iter = points.iter().copied();
    while let Some(a) = iter.next() {
      let b = iter.next();
      pairs.push([a, b.unwrap_or(C::XyPoint::IDENTITY)]);
      let div = match b {
        Some(b) => a + b,
        None => a,
      };
      divs.push(div);
    }

    while divs.len() > 1 {
      let mut next_divs = Vec::with_capacity((divs.len() / 2) + 1);
      // If there's an odd amount of divisors, carry the odd one out to the next iteration
      if (divs.len() % 2) == 1 {
        next_divs.push(divs.pop().unwrap());
      }

      while let Some(a) = divs.pop() {
        let b = divs.pop().unwrap();
        pairs.push([a, b]);
        next_divs.push(a + b);
      }
      divs = next_divs;
    }
    pairs
  };

  let gen = C::XyPoint::from(C::generator());
  let (a_xy, b_xy) = {
    let mut points = pairs
      .iter()
      .map(|[a, _]| {
        let is_identity = a.is_identity();
        <_>::conditional_select(a, &gen, is_identity)
      })
      .collect::<Vec<_>>();
    let a = points.len();
    points.extend(pairs.iter().map(|[_, b]| {
      let is_identity = b.is_identity();
      <_>::conditional_select(b, &gen, is_identity)
    }));
    let mut xy = C::XyPoint::batch_to_xy(&points);
    let b_xy = xy.split_off(a);
    let a_xy = xy;
    (a_xy, b_xy)
  };

  let (line_args_and_denom, b): (Vec<_>, Vec<_>) = pairs
    .into_iter()
    .zip(a_xy.iter().zip(b_xy))
    .map(|(pair, (a_xy, b_xy))| {
      let (a_x, _) = a_xy;
      let ax = CtOption::new(*a_x, !pair[0].is_identity());
      let (b_x, _) = b_xy;
      let bx = CtOption::new(b_x, !pair[1].is_identity());
      let denom = (ax, bx);
      let [a, b] = pair;
      let args = line_args::<C>(a, b, *a_x, b_x, &gen);
      let LineArgs { b, both_are_identity, one_is_identity_or_additive_inverses } = args;
      (((both_are_identity, one_is_identity_or_additive_inverses), denom), b)
    })
    .unzip();

  let slopes_and_intercepts = slopes_and_intercepts::<C>(a_xy, &b);

  line_args_and_denom
    .into_iter()
    .zip(slopes_and_intercepts)
    .map(
      |(((both_are_identity, one_is_identity_or_additive_inverses), denom), (slope, intercept))| {
        let line =
          finish_line(slope, intercept, both_are_identity, one_is_identity_or_additive_inverses);
        (line, denom)
      },
    )
    .collect()
}

/// Convert divisor from univariate to bivariate representation.
fn divisor_to_poly<C: DivisorCurve>(
  divisor: &Divisor<C::FieldElement>,
  interpolator: &Interpolator<C::FieldElement>,
) -> Option<Poly<C::FieldElement>> {
  let [a, b] = divisor.interpolate(interpolator)?;
  let zero_coefficient = a[0];
  let x_coefficients = a[1 ..].to_vec();
  let yx_coefficients = vec![b[1 ..].to_vec()];
  let y_coefficients = vec![b[0]];
  Some(Poly { y_coefficients, yx_coefficients, x_coefficients, zero_coefficient })
}

/// Create a divisor interpolating the following points.
///
/// Returns None if:
///   - No points were passed in
///   - The points don't sum to the point at infinity
///   - A passed in point was the point at infinity
///   - If too small of an interpolator was passed in
///
/// If the arguments were valid, this function executes in an amount of time constant to the amount
/// of points.
#[allow(clippy::new_ret_no_self)]
pub fn new_divisor<C: DivisorCurve>(
  points: &[C::XyPoint],
  interpolator: &Interpolator<C::FieldElement>,
) -> Option<Poly<C::FieldElement>> {
  // No points were passed in, this is the point at infinity, or the single point isn't infinity
  // and accordingly doesn't sum to infinity. All three cause us to return None
  // Checks a bit other than the first bit is set, meaning this is >= 2
  let mut invalid_args = (points.len() & (!1)).ct_eq(&0);
  // The points don't sum to the point at infinity
  let sum = points.iter().copied().reduce(C::XyPoint::add).unwrap_or(C::XyPoint::IDENTITY);
  invalid_args |= !sum.is_identity();
  // A point was the point at identity
  for point in points {
    invalid_args |= point.is_identity();
  }
  if bool::from(invalid_args) {
    None?;
  }

  let points_len = points.len();

  let modulus = Divisor::compute_modulus(C::a(), C::b(), interpolator.required_evaluations());
  // Create the initial set of divisors
  let mut divs = vec![];
  let mut all_lines = lines_and_denoms::<C>(points).into_iter();
  for _ in 0 .. ((points_len / 2) + (points_len % 2)) {
    let (line, _) = all_lines.next().unwrap();
    divs.push(Divisor::<C::FieldElement>::from_small(line, &modulus));
  }

  // Our Poly algorithm is leaky and will create an excessive amount of y x**j and x**j
  // coefficients which are zero, yet as our implementation is constant time, still come with
  // an immense performance cost. This code truncates the coefficients we know are zero.
  let trim = |divisor: &mut Poly<_>, points_len: usize| {
    // We should only be trimming divisors reduced by the modulus
    debug_assert!(divisor.yx_coefficients.len() <= 1);
    if divisor.yx_coefficients.len() == 1 {
      let truncate_to = points_len.div_ceil(2).saturating_sub(2);
      for p in truncate_to .. divisor.yx_coefficients[0].len() {
        debug_assert_eq!(divisor.yx_coefficients[0][p], <C::FieldElement as Field>::ZERO);
      }
      divisor.yx_coefficients[0].truncate(truncate_to);
    }
    {
      let truncate_to = points_len / 2;
      for p in truncate_to .. divisor.x_coefficients.len() {
        debug_assert_eq!(divisor.x_coefficients[p], <C::FieldElement as Field>::ZERO);
      }
      divisor.x_coefficients.truncate(truncate_to);
    }
  };

  // Pair them off until only one remains
  while divs.len() > 1 {
    let mut next_divs = vec![];
    // If there's an odd amount of divisors, carry the odd one out to the next iteration
    if (divs.len() % 2) == 1 {
      next_divs.push(divs.pop().unwrap());
    }

    while let Some(a_div) = divs.pop() {
      let b_div = divs.pop().unwrap();

      // Merge the two divisors
      let (line, denom) = all_lines.next().unwrap();
      let merged = Divisor::merge([a_div, b_div], line, denom, &modulus);
      next_divs.push(merged);
    }

    divs = next_divs;
  }

  // Return the unified divisor
  let divisor = divs.remove(0);
  let mut divisor = divisor_to_poly::<C>(&divisor, interpolator)?;
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
  /// This function MAY panic on integer overflow, if the generator is the point at infinity, or if
  /// `C::interpolator_for_scalar_mul` is insufficient.
  pub fn scalar_mul_divisor<C: Zeroize + DivisorCurve<Scalar = F>>(
    &self,
    generator: C,
  ) -> Poly<C::FieldElement> {
    // 1 is used for the resulting point, NUM_BITS is used for the decomposition, and then we store
    // one additional index in a usize for the points we shouldn't write at all (hence the +2)
    let _ = usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 2)
      .expect("NUM_BITS + 2 didn't fit in usize");
    let mut divisor_points =
      vec![C::XyPoint::IDENTITY; usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 1).unwrap()];

    // Write the inverse of the resulting point
    divisor_points[0] = C::XyPoint::from(-generator * self.scalar);
    let mut generator = C::XyPoint::from(generator);

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
    let res = new_divisor::<C>(&divisor_points, C::interpolator_for_scalar_mul().borrow()).unwrap();
    divisor_points.zeroize();
    res
  }
}

#[cfg(any(test, feature = "ed25519"))]
mod ed25519 {
  use std_shims::sync::LazyLock;

  use subtle::{Choice, ConditionallySelectable as _};
  use group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  };

  use dalek_ff_group::{FieldElement, EdwardsPoint};

  use crate::{Projective, Interpolator};

  impl crate::DivisorCurve for EdwardsPoint {
    type FieldElement = FieldElement;
    type XyPoint = Projective<Self>;

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

    type BorrowedInterpolator = &'static Interpolator<Self::FieldElement>;
    fn interpolator_for_scalar_mul() -> Self::BorrowedInterpolator {
      static PRECOMPUTE: LazyLock<Interpolator<FieldElement>> =
        LazyLock::new(|| Interpolator::new(128));
      &*PRECOMPUTE
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
