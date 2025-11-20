use core::ops::{Index, IndexMut, Add, Sub, Mul};
use std_shims::vec::Vec;

use zeroize::Zeroize;

use ciphersuite::Ciphersuite;

use crate::ScalarVector;

/// A point vector struct with the functionality necessary for Bulletproofs.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct PointVector<C: Ciphersuite>(pub(crate) Vec<C::G>);

impl<C: Ciphersuite> Index<usize> for PointVector<C> {
  type Output = C::G;
  fn index(&self, index: usize) -> &C::G {
    &self.0[index]
  }
}

impl<C: Ciphersuite> IndexMut<usize> for PointVector<C> {
  fn index_mut(&mut self, index: usize) -> &mut C::G {
    &mut self.0[index]
  }
}

impl<C: Ciphersuite> Add<C::G> for PointVector<C> {
  type Output = Self;
  fn add(mut self, point: C::G) -> Self::Output {
    for val in &mut self.0 {
      *val += point;
    }
    self
  }
}

impl<C: Ciphersuite> Sub<C::G> for PointVector<C> {
  type Output = Self;
  fn sub(mut self, point: C::G) -> Self::Output {
    for val in &mut self.0 {
      *val -= point;
    }
    self
  }
}

impl<C: Ciphersuite> Mul<C::F> for PointVector<C> {
  type Output = Self;
  fn mul(mut self, scalar: C::F) -> Self::Output {
    for val in &mut self.0 {
      *val *= scalar;
    }
    self
  }
}

impl<C: Ciphersuite> PointVector<C> {
  /// Add two point vectors together.
  ///
  /// May panic if the vectors are of different lengths.
  #[allow(unused)]
  pub(crate) fn add_vec(mut self, vector: &Self) -> Self {
    debug_assert_eq!(self.len(), vector.len(), "adding point vectors of different lengths");
    for (i, val) in self.0.iter_mut().enumerate() {
      *val += vector.0[i];
    }
    self
  }

  /// Subtract a point vector from another.
  ///
  /// May panic if the vectors are of different lengths.
  #[allow(unused)]
  pub(crate) fn sub_vec(mut self, vector: &Self) -> Self {
    debug_assert_eq!(self.len(), vector.len(), "subtracting point vectors of different lengths");
    for (i, val) in self.0.iter_mut().enumerate() {
      *val -= vector.0[i];
    }
    self
  }

  /// Scales the points in this vector by the corresponding scalars within the scalar vector.
  ///
  /// May panic if the vectors are different lengths.
  pub(crate) fn mul_vec(mut self, vector: &ScalarVector<C::F>) -> Self {
    debug_assert_eq!(
      self.len(),
      vector.len(),
      "scaling a point vector by a scalar vector of a different length"
    );
    for (i, val) in self.0.iter_mut().enumerate() {
      *val *= vector.0[i];
    }
    self
  }

  /// Compute the multi-scalar multiplication of this point vector by the scalar vector.
  ///
  /// May panic if the vectors are different lengths.
  #[cfg(test)] // Only used by the tests at this time
  pub(crate) fn multiexp(&self, vector: &ScalarVector<C::F>) -> C::G {
    debug_assert_eq!(
      self.len(),
      vector.len(),
      "performing a multiexp for a point vector by a scalar vector of a different length"
    );
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp::multiexp(&res)
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  /// Split this point vector into two equally-sized parts.
  ///
  /// May panic if `self.len()` is not a power of two at least `2^1`.
  pub(crate) fn split(mut self) -> (Self, Self) {
    debug_assert!(self.len() > 1);
    let r = self.0.split_off(self.len() / 2);
    debug_assert_eq!(self.len(), r.len());
    (self, PointVector(r))
  }
}
