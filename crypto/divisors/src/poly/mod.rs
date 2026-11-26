//! A bivariate polynomial represented over `x, y` coefficients.

use core::ops::{Add, Neg, Sub, Mul, Rem};
use alloc::boxed::Box;
use alloc::{vec, vec::Vec};

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater as _, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use group::ff::PrimeField;

mod add_sub;
mod mul;
mod div_rem;

/// A structure representing a Polynomial with `x^i`, `y^i`, and `y^i * x^j` terms.
///
/// The implementation of `Zeroize` is solely intended with regard to _values_, not the structure
/// of the polynomial (the amount of coefficients).
///
/// No arithmetic is presented as correct or complete _except_ as used for the purposes of
/// constructing elliptic curve divisors via the algorithm present in this library.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly<F: Zeroize + PrimeField> {
  /// `y_coefficients[i] * y^(i + 1)`
  pub y_coefficients: Box<[F]>,
  /// `yx_coefficients[i][j] * y^(i + 1) x^(j + 1)`
  pub yx_coefficients: Vec<Box<[F]>>,
  /// `x_coefficients[i] * x^(i + 1)`
  pub x_coefficients: Box<[F]>,
  /// `zero_coefficient`
  pub zero_coefficient: F,
}

impl<F: Zeroize + PrimeField> Poly<F> {
  pub(crate) fn all_coefficients_mut(&mut self) -> impl Iterator<Item = &mut F> {
    let Self { y_coefficients, yx_coefficients, x_coefficients, zero_coefficient } = self;
    y_coefficients
      .iter_mut()
      .chain(yx_coefficients.iter_mut().flatten())
      .chain(x_coefficients.iter_mut())
      .chain(core::iter::once(zero_coefficient))
  }

  /// The zero polynomial.
  pub(crate) fn zero() -> Self {
    Poly {
      y_coefficients: Box::default(),
      yx_coefficients: vec![],
      x_coefficients: Box::default(),
      zero_coefficient: F::ZERO,
    }
  }

  /// If this polynomial is equal (in value, not necessarily in structure) to the zero polynomial.
  ///
  /// This runs in time solely variable to the structure of the polynomial.
  pub(crate) fn is_zero(&self) -> Choice {
    let Self { y_coefficients, yx_coefficients, x_coefficients, zero_coefficient } = self;
    let all_coefficients = y_coefficients
      .iter()
      .chain(yx_coefficients.iter().flatten())
      .chain(x_coefficients.iter())
      .chain(core::iter::once(zero_coefficient));
    all_coefficients.fold(Choice::from(1u8), |accum, coeff| accum & coeff.is_zero())
  }

  /// Perform multiplication modulo `modulus`.
  ///
  /// This will NOT mutate the denominator, despite taking a mutable reference.
  ///
  /// This runs in time solely variable to the structure of the polynomials, if the
  /// modulus is not the zero polynomial.
  ///
  /// This panics when the modulus is the zero polynomial.
  #[must_use]
  pub(crate) fn mul_mod(self, other: &Self, modulus: &mut Self) -> Self {
    (self * other) % modulus
  }

  /// Evaluate this polynomial for the specified variables.
  ///
  /// This runs in time solely variable to the structure of the polynomial.
  #[must_use]
  pub(crate) fn eval(&self, x: F, y: F) -> F {
    let mut res = self.zero_coefficient;
    for (pow, coeff) in self.y_coefficients.iter().scan(F::ONE, |y_pow, coeff| {
      *y_pow *= y;
      Some((*y_pow, coeff))
    }) {
      res += pow * coeff;
    }
    for (y_pow, coeffs) in self.yx_coefficients.iter().scan(F::ONE, |y_pow, coeffs| {
      *y_pow *= y;
      Some((*y_pow, coeffs))
    }) {
      for (x_pow, coeff) in coeffs.iter().scan(F::ONE, |x_pow, coeff| {
        *x_pow *= x;
        Some((*x_pow, coeff))
      }) {
        res += y_pow * x_pow * coeff;
      }
    }
    for (x_pow, coeff) in self.x_coefficients.iter().scan(F::ONE, |x_pow, coeff| {
      *x_pow *= x;
      Some((*x_pow, coeff))
    }) {
      res += x_pow * coeff;
    }
    res
  }

  /// Differentiate a polynomial by `x` and by `y`.
  ///
  /// The input polynomial MUST have no terms for any power of `y` greater than `y^1`.
  ///
  /// This runs in time solely variable to the structure of the polynomial.
  #[must_use]
  pub fn differentiate(&self) -> (Poly<F>, Poly<F>) {
    // Differentation by `x` practically involves:
    // - Dropping everything without an `x` component
    // - Shifting everything down a power of `x`
    // - Multiplying the new coefficient by the power it was prior associated with
    let diff_x = {
      let mut diff_x = Poly {
        y_coefficients: Box::default(),
        yx_coefficients: vec![],
        x_coefficients: Box::default(),
        zero_coefficient: F::ZERO,
      };
      if !self.x_coefficients.is_empty() {
        diff_x.zero_coefficient = self.x_coefficients[0];
        diff_x.x_coefficients = Box::from(&self.x_coefficients[1 ..]);

        let mut prior_x_power = F::ONE.double();
        for x_coeff in &mut diff_x.x_coefficients {
          *x_coeff *= prior_x_power;
          prior_x_power += F::ONE;
        }
      }

      if !self.yx_coefficients.is_empty() {
        debug_assert!(self.yx_coefficients.len() < 2);
        let yx_coeffs = &self.yx_coefficients[0];
        if !yx_coeffs.is_empty() {
          diff_x.y_coefficients = vec![yx_coeffs[0]].into_boxed_slice();
          diff_x.yx_coefficients = vec![Box::from(&yx_coeffs[1 ..])];

          let mut prior_x_power = F::from(2);
          for yx_coeff in &mut diff_x.yx_coefficients[0] {
            *yx_coeff *= prior_x_power;
            prior_x_power += F::ONE;
          }
        }
      }

      diff_x
    };

    /*
      Differentation by `y` is trivial thanks to any power of `y` greater than `y^1`. It's the `y`
      coefficient as the zero coefficient, and the `y^1 x^j` coefficients as the `x` coefficients.
    */
    debug_assert!(self.y_coefficients.len() < 2);
    let diff_y = Poly {
      y_coefficients: Box::default(),
      yx_coefficients: vec![],
      x_coefficients: self.yx_coefficients.first().cloned().unwrap_or(Box::default()),
      zero_coefficient: self.y_coefficients.first().copied().unwrap_or(F::ZERO),
    };

    (diff_x, diff_y)
  }

  /// Normalize the `y^0 x^1` coefficient to `1`.
  ///
  /// This returns `None` if there is no `y^0 x^1` coefficient to normalize or if its `0`.
  ///
  /// This runs in time solely variable to the structure of the polynomial and if the `y^0 x^1`
  /// coefficient is `0`.
  #[must_use]
  pub fn normalize_x_coefficient(self) -> Option<Self> {
    let scalar = Option::<F>::from(self.x_coefficients.first()?.invert())?;
    Some(self * scalar)
  }
}
