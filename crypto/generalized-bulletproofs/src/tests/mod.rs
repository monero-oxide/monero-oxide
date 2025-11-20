use rand_core::RngCore;

use ciphersuite::{group::Group, Ciphersuite};

use crate::{GeneratorsError, Generators};

#[cfg(test)]
mod inner_product;

/// Insecurely generate a set of generators for testing purposes.
///
/// This MUST NOT be considered a secure way to generate generators and MUST solely be considered
/// for testing purposes.
pub fn insecure_test_generators<R: RngCore, C: Ciphersuite>(
  rng: &mut R,
  n: usize,
) -> Result<Generators<C>, GeneratorsError> {
  let g = C::G::random(&mut *rng);
  let h = C::G::random(&mut *rng);
  let mut bold = || {
    let mut res = Vec::with_capacity(n.next_power_of_two());
    for _ in 0 .. n {
      res.push(C::G::random(&mut *rng));
    }
    res
  };
  Generators::new(g, h, bold(), bold())
}
