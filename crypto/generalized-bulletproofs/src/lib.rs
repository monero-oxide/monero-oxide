#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use core::fmt;
use std_shims::{vec, vec::Vec, collections::HashSet};

use zeroize::{Zeroize, ZeroizeOnDrop};

use multiexp::{multiexp, multiexp_vartime};
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

mod scalar_vector;
pub(crate) use scalar_vector::ScalarVector;
mod point_vector;
pub(crate) use point_vector::PointVector;

/// The transcript formats.
pub mod transcript;

pub(crate) mod inner_product;

pub(crate) mod lincomb;

/// The arithmetic circuit proof.
pub mod arithmetic_circuit_proof;

/// Functionlity useful when testing.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// An error from working with generators.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeneratorsError {
  /// The provided list of generators for `g` (bold) was empty.
  GBoldEmpty,
  /// The provided list of generators for `h` (bold) did not match `g` (bold) in length.
  DifferingGhBoldLengths,
  /// The amount of provided generators were not a power of two.
  NotPowerOfTwo,
  /// A generator was the identity point.
  IdentityPoint,
  /// A generator was used multiple times.
  DuplicatedGenerator,
}

/// A full set of generators.
#[derive(Clone)]
pub struct Generators<C: Ciphersuite> {
  g: C::G,
  h: C::G,

  g_bold: Vec<C::G>,
  h_bold: Vec<C::G>,
  h_sum: Vec<C::G>,
}

/// A batch verifier of proofs.
#[must_use]
#[derive(Clone)]
pub struct BatchVerifier<C: Ciphersuite> {
  /// The summed scalar for the `g` generator.
  pub g: C::F,
  /// The summed scalar for the `h` generator.
  pub h: C::F,

  /// The summed scalars for the `g` (bold) generators.
  pub g_bold: Vec<C::F>,
  /// The summed scalars for the `h` (bold) generators.
  pub h_bold: Vec<C::F>,
  /// The summed scalars for the sums of all `h` (bold) generators prior to the index.
  ///
  /// This is not populated with the full set of summed `h` (bold) generators. This is only
  /// populated with the powers of two. Accordingly, an index `i` specifies a scalar for the sum of
  /// all `h` (bold) generators with indexes `0 .. {2**i}`.
  pub h_sum: Vec<C::F>,

  /// Additional (non-fixed) points to include in the multiexp.
  ///
  /// This is used for proof-specific elements.
  pub additional: Vec<(C::F, C::G)>,
}

impl<C: Ciphersuite> fmt::Debug for Generators<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let g = self.g.to_bytes();
    let g: &[u8] = g.as_ref();

    let h = self.h.to_bytes();
    let h: &[u8] = h.as_ref();

    fmt.debug_struct("Generators").field("g", &g).field("h", &h).finish_non_exhaustive()
  }
}

/// The generators for a specific proof.
///
/// This potentially have been reduced in size from the original set of generators, as beneficial
/// to performance.
#[derive(Copy, Clone)]
pub struct ProofGenerators<'a, C: Ciphersuite> {
  g: &'a C::G,
  h: &'a C::G,

  g_bold: &'a [C::G],
  h_bold: &'a [C::G],
}

impl<C: Ciphersuite> fmt::Debug for ProofGenerators<'_, C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let g = self.g.to_bytes();
    let g: &[u8] = g.as_ref();

    let h = self.h.to_bytes();
    let h: &[u8] = h.as_ref();

    fmt.debug_struct("ProofGenerators").field("g", &g).field("h", &h).finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> Generators<C> {
  /// Construct an instance of Generators for usage with Bulletproofs.
  pub fn new(
    g: C::G,
    h: C::G,
    g_bold: Vec<C::G>,
    h_bold: Vec<C::G>,
  ) -> Result<Self, GeneratorsError> {
    if g_bold.is_empty() {
      Err(GeneratorsError::GBoldEmpty)?;
    }
    if g_bold.len() != h_bold.len() {
      Err(GeneratorsError::DifferingGhBoldLengths)?;
    }
    if !g_bold.len().is_power_of_two() {
      Err(GeneratorsError::NotPowerOfTwo)?;
    }

    let mut set = HashSet::new();
    let mut add_generator = |generator: &C::G| {
      if bool::from(generator.is_identity()) {
        return Err(GeneratorsError::IdentityPoint);
      }
      let bytes = generator.to_bytes();
      Ok(!set.insert(bytes.as_ref().to_vec()))
    };

    debug_assert!(!add_generator(&g)?, "g was prior present in empty set");
    if add_generator(&h)? {
      Err(GeneratorsError::DuplicatedGenerator)?;
    }
    for g in &g_bold {
      if add_generator(g)? {
        Err(GeneratorsError::DuplicatedGenerator)?;
      }
    }
    for h in &h_bold {
      if add_generator(h)? {
        Err(GeneratorsError::DuplicatedGenerator)?;
      }
    }

    let mut running_h_sum = C::G::identity();
    let mut h_sum = vec![];
    let mut next_pow_of_2 = 1;
    for (i, h) in h_bold.iter().enumerate() {
      running_h_sum += h;
      if (i + 1) == next_pow_of_2 {
        h_sum.push(running_h_sum);
        next_pow_of_2 *= 2;
      }
    }

    Ok(Generators { g, h, g_bold, h_bold, h_sum })
  }

  /// Create a `BatchVerifier` for proofs which use a consistent set of generators.
  pub fn batch_verifier() -> BatchVerifier<C> {
    BatchVerifier {
      g: C::F::ZERO,
      h: C::F::ZERO,

      g_bold: vec![],
      h_bold: vec![],
      h_sum: vec![],

      additional: Vec::with_capacity(128),
    }
  }

  /// Verify all proofs queued for batch verification in this `BatchVerifier`.
  ///
  /// This function executes in variable time.
  #[must_use]
  pub fn verify(&self, verifier: BatchVerifier<C>) -> bool {
    multiexp_vartime(
      &[(verifier.g, self.g), (verifier.h, self.h)]
        .into_iter()
        .chain(verifier.g_bold.into_iter().zip(self.g_bold.iter().copied()))
        .chain(verifier.h_bold.into_iter().zip(self.h_bold.iter().copied()))
        .chain(verifier.h_sum.into_iter().zip(self.h_sum.iter().copied()))
        .chain(verifier.additional)
        .collect::<Vec<_>>(),
    )
    .is_identity()
    .into()
  }

  /// The `g` generator.
  pub fn g(&self) -> C::G {
    self.g
  }

  /// The `h` generator.
  pub fn h(&self) -> C::G {
    self.h
  }

  /// A slice to view the `g` (bold) generators.
  pub fn g_bold_slice(&self) -> &[C::G] {
    &self.g_bold
  }

  /// A slice to view the `h` (bold) generators.
  pub fn h_bold_slice(&self) -> &[C::G] {
    &self.h_bold
  }

  /// Reduce a set of generators to the quantity necessary to support a certain amount of
  /// in-circuit multiplications/terms in a Pedersen vector commitment.
  ///
  /// Returns `None` if reducing to 0, or if the generators reduced are insufficient to provide
  /// this many generators.
  pub fn reduce(&self, generators: usize) -> Option<ProofGenerators<'_, C>> {
    if generators == 0 {
      None?;
    }

    // Round to the required power of two
    if generators > ((usize::MAX >> 1) + 1) {
      None?;
    }
    let generators = generators.next_power_of_two();
    if generators > self.g_bold.len() {
      None?;
    }

    Some(ProofGenerators {
      g: &self.g,
      h: &self.h,

      g_bold: &self.g_bold[.. generators],
      h_bold: &self.h_bold[.. generators],
    })
  }
}

impl<'a, C: Ciphersuite> ProofGenerators<'a, C> {
  pub(crate) fn len(&self) -> usize {
    self.g_bold.len()
  }

  pub(crate) fn g(&self) -> C::G {
    *self.g
  }

  pub(crate) fn h(&self) -> C::G {
    *self.h
  }

  pub(crate) fn g_bold(&self, i: usize) -> C::G {
    self.g_bold[i]
  }

  pub(crate) fn h_bold(&self, i: usize) -> C::G {
    self.h_bold[i]
  }

  pub(crate) fn g_bold_slice(&self) -> &[C::G] {
    self.g_bold
  }

  pub(crate) fn h_bold_slice(&self) -> &[C::G] {
    self.h_bold
  }
}

/// The opening of a Pedersen commitment.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PedersenCommitment<C: Ciphersuite> {
  /// The value committed to.
  pub value: C::F,
  /// The mask blinding the value committed to.
  pub mask: C::F,
}

impl<C: Ciphersuite> PedersenCommitment<C> {
  /// Commit to this value, yielding the Pedersen commitment.
  pub fn commit(&self, g: C::G, h: C::G) -> C::G {
    multiexp(&[(self.value, g), (self.mask, h)])
  }
}

/// The opening of a Pedersen vector commitment.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PedersenVectorCommitment<C: Ciphersuite> {
  /// The values committed to across the `g` (bold) generators.
  pub g_values: Vec<C::F>,
  /// The mask blinding the values committed to.
  pub mask: C::F,
}

impl<C: Ciphersuite> PedersenVectorCommitment<C> {
  /// Commit to the vectors of values.
  ///
  /// This function returns `None` if the amount of generators is less than the amount of values
  /// within the relevant vector.
  pub fn commit(&self, g_bold: &[C::G], h: C::G) -> Option<C::G> {
    if g_bold.len() < self.g_values.len() {
      None?;
    };

    let mut terms = vec![(self.mask, h)];
    for pair in self.g_values.iter().copied().zip(g_bold.iter().copied()) {
      terms.push(pair);
    }
    let res = multiexp(&terms);
    terms.zeroize();
    Some(res)
  }
}
