use core::ops::{Add, Sub, Mul};
use std_shims::{vec, vec::Vec, collections::BTreeMap};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

use crate::ScalarVector;

/// A reference to a variable usable within linear combinations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum Variable {
  /// A variable within the left vector of vectors multiplied against each other.
  aL(usize),
  /// A variable within the right vector of vectors multiplied against each other.
  aR(usize),
  /// A variable within the output vector of the left vector multiplied by the right vector.
  aO(usize),
  /// A variable within a Pedersen vector commitment, committed to with a generator from `g` (bold).
  CG {
    /// The commitment being indexed.
    commitment: usize,
    /// The index of the variable.
    index: usize,
  },
  /// A variable within a Pedersen commitment.
  V(usize),
}

/// A linear combination.
///
/// Specifically, `WL aL + WR aR + WO aO + WCG C_G + WV V + c`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[must_use]
pub struct LinComb<F: PrimeField> {
  /// The highest index within `aL`, `aR`, or `aO` which is used.
  pub(crate) highest_a_index: Option<usize>,
  /// The highest index for a Pedersen vector commitment.
  pub(crate) highest_c_index: Option<usize>,
  /// The highest index for a Pedersen commitment.
  pub(crate) highest_v_index: Option<usize>,

  // Sparse representation of WL/WR/WO
  pub(crate) WL: Vec<(usize, F)>,
  pub(crate) WR: Vec<(usize, F)>,
  pub(crate) WO: Vec<(usize, F)>,
  /// A sparse representation of the vector commitments and the weights for the variables within
  /// them.
  WCG: BTreeMap<usize, Vec<(usize, F)>>,
  /// A sparse representation of the weights for the variables within Pedersen commitments.
  pub(crate) WV: Vec<(usize, F)>,
  pub(crate) c: F,
}

impl<F: Zeroize + PrimeField> Zeroize for LinComb<F> {
  fn zeroize(&mut self) {
    self.highest_a_index.zeroize();
    self.highest_c_index.zeroize();
    self.highest_v_index.zeroize();
    self.WL.zeroize();
    self.WR.zeroize();
    self.WO.zeroize();
    for WCG in self.WCG.values_mut() {
      WCG.zeroize();
    }
    self.WV.zeroize();
    self.c.zeroize();
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Create an empty linear combination.
  pub fn empty() -> Self {
    Self {
      highest_a_index: None,
      highest_c_index: None,
      highest_v_index: None,
      WL: vec![],
      WR: vec![],
      WO: vec![],
      WCG: BTreeMap::new(),
      WV: vec![],
      c: F::ZERO,
    }
  }
}

impl<F: PrimeField> From<Variable> for LinComb<F> {
  fn from(constrainable: Variable) -> LinComb<F> {
    LinComb::empty().term(F::ONE, constrainable)
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Reconcile two linear combinations, making them interoperable and able to be merged.
  fn reconcile_for_merging(&mut self, other: &Self) {
    self.highest_a_index = self.highest_a_index.max(other.highest_a_index);
    self.highest_c_index = self.highest_c_index.max(other.highest_c_index);
    self.highest_v_index = self.highest_v_index.max(other.highest_v_index);
  }
}

impl<F: PrimeField> Add<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  /// This addition is actually a _concatenation_, where the result will use memory the sum of its
  /// inputs.  Conversion to a canonical representation only happens when building the final
  /// matrii.
  fn add(mut self, constraint: &Self) -> Self {
    self.reconcile_for_merging(constraint);

    self.WL.extend(&constraint.WL);
    self.WR.extend(&constraint.WR);
    self.WO.extend(&constraint.WO);
    for (i, sparse_vec) in &constraint.WCG {
      self
        .WCG
        .entry(*i)
        .and_modify(|existing| existing.extend(sparse_vec))
        .or_insert_with(|| sparse_vec.clone());
    }
    self.WV.extend(&constraint.WV);
    self.c += constraint.c;
    self
  }
}

impl<F: PrimeField> Sub<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  /// This subtraction is actually a _concatenation_ (with the right-hand side negated), where the
  /// result will use memory the sum of its inputs. Conversion to a canonical representation only
  /// happens when building the final matrii.
  fn sub(mut self, constraint: &Self) -> Self {
    self.reconcile_for_merging(constraint);

    self.WL.extend(constraint.WL.iter().map(|(i, weight)| (*i, -*weight)));
    self.WR.extend(constraint.WR.iter().map(|(i, weight)| (*i, -*weight)));
    self.WO.extend(constraint.WO.iter().map(|(i, weight)| (*i, -*weight)));
    for (i, sparse_vec) in &constraint.WCG {
      let mut sparse_vec = sparse_vec.iter().copied().map(|(j, value)| (j, -value));
      self
        .WCG
        .entry(*i)
        .and_modify(|existing| existing.extend(&mut sparse_vec))
        .or_insert_with(|| sparse_vec.collect());
    }
    self.WV.extend(constraint.WV.iter().map(|(i, weight)| (*i, -*weight)));
    self.c -= constraint.c;
    self
  }
}

impl<F: PrimeField> Mul<F> for LinComb<F> {
  type Output = Self;

  fn mul(mut self, scalar: F) -> Self {
    for (_, weight) in &mut self.WL {
      *weight *= scalar;
    }
    for (_, weight) in &mut self.WR {
      *weight *= scalar;
    }
    for (_, weight) in &mut self.WO {
      *weight *= scalar;
    }
    for WC in self.WCG.values_mut() {
      for (_, weight) in WC {
        *weight *= scalar;
      }
    }
    for (_, weight) in &mut self.WV {
      *weight *= scalar;
    }
    self.c *= scalar;
    self
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Add a new instance of a term to this linear combination.
  pub fn term(mut self, scalar: F, constrainable: Variable) -> Self {
    match constrainable {
      Variable::aL(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WL.push((i, scalar));
      }
      Variable::aR(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WR.push((i, scalar));
      }
      Variable::aO(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WO.push((i, scalar));
      }
      Variable::CG { commitment: i, index: j } => {
        self.highest_c_index = self.highest_c_index.max(Some(i));
        /*
          We use `highest_a_index` to track the highest index within the IPA, hence why it tracks
          indexes to `aL`, `aR`, and `aO`. The variables within a vector commitment are _also_
          dependent on the size of the IPA, hence why these _also_ update `highest_a_index`.
        */
        self.highest_a_index = self.highest_a_index.max(Some(j));
        self
          .WCG
          .entry(i)
          .and_modify(|values| values.push((j, scalar)))
          .or_insert_with(|| vec![(j, scalar)]);
      }
      Variable::V(i) => {
        self.highest_v_index = self.highest_v_index.max(Some(i));
        self.WV.push((i, scalar));
      }
    }
    self
  }

  /// Add to the constant `c`.
  pub fn constant(mut self, scalar: F) -> Self {
    self.c += scalar;
    self
  }

  /// View the current weights for `aL`.
  pub fn WL(&self) -> &[(usize, F)] {
    &self.WL
  }

  /// View the current weights for `aR`.
  pub fn WR(&self) -> &[(usize, F)] {
    &self.WR
  }

  /// View the current weights for `aO`.
  pub fn WO(&self) -> &[(usize, F)] {
    &self.WO
  }

  /// View the current weights for `CG`.
  pub fn WCG(&self) -> &BTreeMap<usize, Vec<(usize, F)>> {
    &self.WCG
  }

  /// View the current weights for `V`.
  pub fn WV(&self) -> &[(usize, F)] {
    &self.WV
  }

  /// View the current constant `c`.
  pub fn c(&self) -> F {
    self.c
  }
}

/// Accumulate a sparse vector into an accumulator with a multiplicative weight applied.
///
/// This is equivalent to `accumulator += values * weight`, if `values` was a normal vector.
///
/// Returns the highest index written to during accumulation.
pub(crate) fn accumulate_vector<F: PrimeField>(
  accumulator: &mut ScalarVector<F>,
  values: &[(usize, F)],
  weight: F,
) -> usize {
  let mut hi = 0;
  for (i, coeff) in values {
    accumulator[*i] += *coeff * weight;
    hi = hi.max(*i);
  }
  hi
}
