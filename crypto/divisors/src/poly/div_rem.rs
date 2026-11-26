#![allow(clippy::as_conversions)]

use super::*;

#[derive(Clone, Copy, PartialEq, Debug)]
struct CoefficientIndex {
  y_pow: u64,
  x_pow: u64,
}
impl ConditionallySelectable for CoefficientIndex {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Self {
      y_pow: <_>::conditional_select(&a.y_pow, &b.y_pow, choice),
      x_pow: <_>::conditional_select(&a.x_pow, &b.x_pow, choice),
    }
  }
}
impl ConstantTimeEq for CoefficientIndex {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.y_pow.ct_eq(&other.y_pow) & self.x_pow.ct_eq(&other.x_pow)
  }
}
impl CoefficientIndex {
  fn ct_gte(&self, other: &Self) -> Choice {
    (self.y_pow.ct_gt(&other.y_pow) | self.y_pow.ct_eq(&other.y_pow)) &
      (self.x_pow.ct_gt(&other.x_pow) | self.x_pow.ct_eq(&other.x_pow))
  }
}

fn pop_zero<F: Zeroize + PrimeField>(slice: &mut Box<[F]>) {
  if slice.is_empty() {
    return;
  }

  let mut popped = Box::from(&slice[.. (slice.len() - 1)]);
  core::mem::swap(slice, &mut popped);
  debug_assert_eq!(popped[slice.len()], F::ZERO);
  for popped in popped.iter_mut().take(slice.len()) {
    popped.zeroize();
  }
}

fn append_zeroes<F: Zeroize + PrimeField>(slice: &mut Box<[F]>, zeroes: usize) {
  let mut appended = Box::new_uninit_slice(slice.len() + zeroes);
  {
    let mut appended = appended.iter_mut();
    for (dst, src) in (&mut appended).take(slice.len()).zip(slice.iter()) {
      dst.write(*src);
    }
    for item in appended {
      item.write(F::ZERO);
    }
  }
  // SAFETY: We iterated over every item and wrote a value to each one
  let mut appended = unsafe { appended.assume_init() };
  core::mem::swap(slice, &mut appended);
  appended.zeroize();
}

impl<F: Zeroize + PrimeField> Poly<F> {
  /// Iterate over all coefficients within this polynomial, with their indexes.
  ///
  /// This will return the coefficients _in descending order_.
  ///
  /// This function runs in time solely variable to the structure of the polynomial.
  fn indexed_coefficients_mut(&mut self) -> impl Iterator<Item = (CoefficientIndex, &mut F)> {
    let Self { y_coefficients, yx_coefficients, x_coefficients, zero_coefficient } = self;

    let y_max = y_coefficients.len().max(yx_coefficients.len());
    let yx_coefficients = core::iter::repeat_with(|| const { None })
      .take(y_max - yx_coefficients.len())
      .chain(yx_coefficients.iter_mut().enumerate().rev().map(Some));
    let y_coefficients = core::iter::repeat_with(|| const { None })
      .take(y_max - y_coefficients.len())
      .chain(y_coefficients.iter_mut().enumerate().rev().map(Some));

    yx_coefficients
      .zip(y_coefficients)
      .flat_map(|(y_i_x_coefficients, y_i_x_0_coefficient)| {
        y_i_x_coefficients
          .into_iter()
          .flat_map(move |(y_pow_sub_one, coeffs)| {
            coeffs.iter_mut().enumerate().rev().map(move |(x_pow_sub_one, coeff)| {
              (
                CoefficientIndex {
                  y_pow: (y_pow_sub_one + 1) as u64,
                  x_pow: (x_pow_sub_one + 1) as u64,
                },
                coeff,
              )
            })
          })
          .chain(y_i_x_0_coefficient.into_iter().map(move |(y_pow_sub_one, coeff)| {
            (CoefficientIndex { y_pow: (y_pow_sub_one + 1) as u64, x_pow: 0 }, coeff)
          }))
      })
      .chain(x_coefficients.iter_mut().enumerate().rev().map(|(x_pow_sub_one, coeff)| {
        (CoefficientIndex { y_pow: 0, x_pow: (x_pow_sub_one + 1) as u64 }, coeff)
      }))
      .chain(core::iter::once((CoefficientIndex { y_pow: 0, x_pow: 0 }, zero_coefficient)))
  }

  fn leading_coefficient(&mut self) -> CoefficientIndex {
    let mut leading_coefficient = CoefficientIndex { y_pow: 0, x_pow: 0 };
    for (coeff_index, coeff) in self.indexed_coefficients_mut() {
      leading_coefficient = <_>::conditional_select(
        &leading_coefficient,
        &coeff_index,
        (!coeff.is_zero()) & coeff_index.ct_gte(&leading_coefficient),
      );
    }
    leading_coefficient
  }

  /// Get a coefficient of the polynomial in time solely variable to the structure of the
  /// polynomial.
  ///
  /// This function runs in time constant to _which_ coefficient is being got.
  fn ct_get(&mut self, index: CoefficientIndex) -> F {
    self.indexed_coefficients_mut().fold(F::ZERO, |accum, (coeff_index, coeff)| {
      <_>::conditional_select(&accum, coeff, index.ct_eq(&coeff_index))
    })
  }

  /// Set a coefficient of the polynomial in time solely variable to the structure of the
  /// polynomial.
  ///
  /// This function runs in time constant to _which_ coefficient is being set.
  fn ct_set(&mut self, index: CoefficientIndex, value: F) {
    for (coeff_index, coeff) in self.indexed_coefficients_mut() {
      *coeff = <_>::conditional_select(coeff, &value, index.ct_eq(&coeff_index));
    }
  }

  /// Pad polynomial `a` to have the same structure as polynomial `b`.
  ///
  /// This function runs in time solely variable to the structure of the polynomials.
  fn pad_to(a: &mut Poly<F>, b: &Poly<F>) {
    if let Some(gap) = b.x_coefficients.len().checked_sub(a.x_coefficients.len()) {
      if gap != 0 {
        append_zeroes(&mut a.x_coefficients, gap);
      }
    }
    while a.yx_coefficients.len() < b.yx_coefficients.len() {
      a.yx_coefficients.push(Box::default());
    }
    for (a, b) in a.yx_coefficients.iter_mut().zip(&b.yx_coefficients) {
      if let Some(gap) = b.len().checked_sub(a.len()) {
        if gap != 0 {
          append_zeroes(a, gap);
        }
      }
    }
    if let Some(gap) = b.y_coefficients.len().checked_sub(a.y_coefficients.len()) {
      if gap != 0 {
        append_zeroes(&mut a.y_coefficients, gap);
      }
    }
  }

  /// Select `b` if `choice` else `a`.
  ///
  /// The chosen polynomial will have the same _value_ but not necessarily the same _structure_.
  ///
  /// This function runs in time solely variable to the structure of the polynomials.
  fn conditional_select(mut a: Self, mut b: Self, choice: Choice) -> Poly<F> {
    // Pad these to be the same structure as each other
    Self::pad_to(&mut a, &b);
    Self::pad_to(&mut b, &a);

    // Because these have the same structure, the order of iteration is equivalent
    for ((a_index, a), (b_index, b)) in
      a.indexed_coefficients_mut().zip(b.indexed_coefficients_mut())
    {
      debug_assert!(bool::from(a_index.ct_eq(&b_index)));
      *a = <_>::conditional_select(a, b, choice);
    }

    a
  }

  /// Perform division, returning the result and remainder.
  ///
  /// This will NOT mutate the denominator, despite taking a mutable reference.
  ///
  /// This function runs in time solely variable to the structure of the polynomials, if the
  /// denominator is not the zero polynomial.
  ///
  /// This panics upon division by the zero polynomial.
  #[must_use]
  pub(crate) fn div_rem(self, denominator: &mut Self) -> (Self, Self) {
    /*
      The following long division algorithm only works if the denominator actually has a variable.
      If the denominator isn't variable to anything, short-circuit to scalar 'division'
      (multiplication by its multiplicative inverse).

      This is constant-time as this is solely derivative of the structure, not the value, of the
      denominator.
    */
    if denominator.indexed_coefficients_mut().count() == 1 {
      return (self * denominator.zero_coefficient.invert().unwrap(), Poly::zero());
    }

    // The structure of the quotient, which is the the numerator with all coefficients set to `0`
    let mut quotient_structure = self.clone();
    for coeff in quotient_structure.all_coefficients_mut() {
      *coeff = F::ZERO;
    }
    debug_assert!(bool::from(quotient_structure.is_zero()));

    // Calculate the amount of iterations we need to perform
    let iterations = self.y_coefficients.len() +
      self.yx_coefficients.iter().map(|coeffs| coeffs.len()).sum::<usize>() +
      self.x_coefficients.len();

    // Find the highest non-zero coefficient in the denominator
    // This is the coefficient which we actually perform division with
    let denominator_leading_coefficient = denominator.leading_coefficient();
    let denominator_leading_coefficient_inv =
      denominator.ct_get(denominator_leading_coefficient).invert().unwrap();

    let mut quotient = quotient_structure.clone();
    let mut remainder = self.clone();
    for _ in 0 .. iterations {
      // Find the numerator coefficient we're clearing
      let numerator_coefficient = remainder.leading_coefficient();
      /*
        We only write the effects of this iteration if the numerator's leading coefficient's index
        is actually greater than or equal to the denominator's leading coefficient's index.
      */
      let meaningful_iteration = numerator_coefficient.ct_gte(&denominator_leading_coefficient);

      // 1) Find the scalar `q` such that the leading coefficient of `q * denominator` is equal to
      //    the leading coefficient of `self`.
      let numerator_coefficient_value = remainder.ct_get(numerator_coefficient);
      let q = numerator_coefficient_value * denominator_leading_coefficient_inv;

      // 2) Calculate the full term of the quotient by scaling with the necessary powers of `y`/`x`
      let powers_of_yx = {
        let proper_powers_of_yx = CoefficientIndex {
          y_pow: numerator_coefficient.y_pow.wrapping_sub(denominator_leading_coefficient.y_pow),
          x_pow: numerator_coefficient.x_pow.wrapping_sub(denominator_leading_coefficient.x_pow),
        };
        /*
          If this isn't a 'meaningful' iteration, the 'proper' powers will have garbage in them due
          to underflowing, so we fallback to `0, 0`.
        */
        <_>::conditional_select(
          &CoefficientIndex { y_pow: 0, x_pow: 0 },
          &proper_powers_of_yx,
          meaningful_iteration,
        )
      };
      let mut quotient_term = quotient_structure.clone();
      quotient_term.ct_set(powers_of_yx, q);

      let quotient_if_meaningful = quotient.clone() + quotient_term.clone();
      quotient = Self::conditional_select(quotient, quotient_if_meaningful, meaningful_iteration);

      // 3) Remove what we've divided out from self
      let remainder_if_meaningful = remainder.clone() - (quotient_term * &*denominator);
      remainder =
        Self::conditional_select(remainder, remainder_if_meaningful, meaningful_iteration);
    }

    quotient = Self::conditional_select(
      quotient,
      // If the dividing coefficient was `y^0 x^0`, we return the poly scaled by its inverse
      self * denominator_leading_coefficient_inv,
      denominator_leading_coefficient.ct_eq(&CoefficientIndex { y_pow: 0, x_pow: 0 }),
    );
    remainder = Self::conditional_select(
      remainder,
      // If the dividing coefficient was `y^0 x^0`, there's no remainder
      Poly::zero(),
      denominator_leading_coefficient.ct_eq(&CoefficientIndex { y_pow: 0, x_pow: 0 }),
    );

    // Clear any junk terms out of the remainder which are less than the denominator
    let denominator_structurally_leading_coefficient =
      denominator.indexed_coefficients_mut().next().map(|(index, _coeff)| index).unwrap();
    while {
      let index =
        CoefficientIndex { y_pow: remainder.y_coefficients.len().try_into().unwrap(), x_pow: 0 };
      bool::from(index.ct_gte(&denominator_structurally_leading_coefficient))
    } {
      pop_zero(&mut remainder.y_coefficients);
    }
    for (y_pow_sub_one, y_i_x_coefficients) in remainder.yx_coefficients.iter_mut().enumerate() {
      while {
        let index = CoefficientIndex {
          y_pow: u64::try_from(y_pow_sub_one + 1).unwrap(),
          x_pow: u64::try_from(y_i_x_coefficients.len()).unwrap(),
        };
        (!y_i_x_coefficients.is_empty()) &&
          bool::from(index.ct_gte(&denominator_structurally_leading_coefficient))
      } {
        pop_zero(y_i_x_coefficients);
      }
    }
    while remainder
      .yx_coefficients
      .last()
      .is_some_and(|y_i_x_coefficients| y_i_x_coefficients.is_empty())
    {
      remainder.yx_coefficients.pop();
    }
    while {
      let index =
        CoefficientIndex { y_pow: 0, x_pow: remainder.x_coefficients.len().try_into().unwrap() };
      bool::from(index.ct_gte(&denominator_structurally_leading_coefficient))
    } {
      pop_zero(&mut remainder.x_coefficients);
    }

    (quotient, remainder)
  }
}

impl<F: Zeroize + PrimeField> Rem<&mut Self> for Poly<F> {
  type Output = Self;

  /// For further information, please refer to [`Poly::div_rem`].
  fn rem(self, modulus: &mut Self) -> Self {
    self.div_rem(modulus).1
  }
}
