use core::ops::{Index, IndexMut, Add, Sub, Mul};
use std_shims::{vec, vec::Vec};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

/// A scalar vector struct with the functionality necessary for Bulletproofs.
///
/// The math operations for this may panic upon any invalid operation, such as if vectors of
/// different lengths are added.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ScalarVector<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField + Zeroize> Zeroize for ScalarVector<F> {
  fn zeroize(&mut self) {
    self.0.zeroize()
  }
}

impl<F: PrimeField> Index<usize> for ScalarVector<F> {
  type Output = F;
  fn index(&self, index: usize) -> &F {
    &self.0[index]
  }
}
impl<F: PrimeField> IndexMut<usize> for ScalarVector<F> {
  fn index_mut(&mut self, index: usize) -> &mut F {
    &mut self.0[index]
  }
}

impl<F: PrimeField> Add<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn add(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s += scalar;
    }
    self
  }
}
impl<F: PrimeField> Sub<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn sub(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s -= scalar;
    }
    self
  }
}
impl<F: PrimeField> Mul<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn mul(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s *= scalar;
    }
    self
  }
}

impl<F: PrimeField> Add<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn add(mut self, other: &ScalarVector<F>) -> Self {
    debug_assert_eq!(self.len(), other.len(), "adding scalar vectors of different lengths");
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s += o;
    }
    self
  }
}
impl<F: PrimeField> Sub<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn sub(mut self, other: &ScalarVector<F>) -> Self {
    debug_assert_eq!(self.len(), other.len(), "subtracting scalar vectors of different lengths");
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s -= o;
    }
    self
  }
}
impl<F: PrimeField> Mul<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn mul(mut self, other: &ScalarVector<F>) -> Self {
    debug_assert_eq!(self.len(), other.len(), "multiplying scalar vectors of different lengths");
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s *= o;
    }
    self
  }
}

impl<F: PrimeField> ScalarVector<F> {
  /// Create a new scalar vector, initialized with `len` zero scalars.
  pub(crate) fn new(len: usize) -> Self {
    ScalarVector(vec![F::ZERO; len])
  }

  /// Create a new scalar vector of length `len` containing the powers of `x`.
  ///
  /// May panic if `len == 0`.
  pub(crate) fn powers(x: F, len: usize) -> Self {
    debug_assert!(len != 0);
    let mut res = Vec::with_capacity(len);
    res.push(F::ONE);
    res.push(x);
    for i in 2 .. len {
      res.push(res[i - 1] * x);
    }
    res.truncate(len); // Handle the edge case where `len == 1`
    ScalarVector(res)
  }

  /// If this scalar vector is empty.
  pub(crate) fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// The length of this scalar vector.
  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  /// The inner, or dot, product of two scalar vectors.
  ///
  /// If one vector is shorter, its non-present values are considered `0`.
  pub(crate) fn inner_product_without_length_checks<'a, V: Iterator<Item = &'a F>>(
    &self,
    mut vector: V,
  ) -> F {
    let mut res = F::ZERO;
    for (a, b) in self.0.iter().zip(&mut vector) {
      res += *a * b;
    }
    res
  }

  /// The inner, or dot, product of two scalar vectors.
  pub(crate) fn inner_product<'a, V: Iterator<Item = &'a F>>(&self, mut vector: V) -> F {
    let mut count = 0;
    let mut res = F::ZERO;
    for (a, b) in self.0.iter().zip(&mut vector) {
      res += *a * b;
      count += 1;
    }
    debug_assert_eq!(
      self.len(),
      count,
      "ScalarVector::inner_product where the rhs was shorter than the lhs"
    );
    debug_assert!(
      vector.next().is_none(),
      "ScalarVector::inner_product where lhs was shorter than the rhs"
    );
    res
  }

  /// Split this scalar vector into two parts.
  ///
  /// `at` represents the index split at, with all elements before `at` being in the first vector
  /// and all elements at and after `at` being in the second vector.
  ///
  /// May panic if `self.len() <= 1` or `at > self.len()`.
  pub(crate) fn split(mut self, at: usize) -> (Self, Self) {
    debug_assert!(self.len() > 1);
    let r = self.0.split_off(at);
    (self, ScalarVector(r))
  }
}

impl<F: PrimeField> From<Vec<F>> for ScalarVector<F> {
  fn from(vec: Vec<F>) -> Self {
    Self(vec)
  }
}
