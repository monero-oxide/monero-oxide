use std_shims::prelude::*;

use curve25519_dalek::EdwardsPoint;

use monero_ed25519::CompressedPoint;

use crate::MAX_MN;

/// The maximum amount of commitments provable for within a single Bulletproof(+).
pub const MAX_COMMITMENTS: usize = 16;
/// The amount of bits a value within a commitment may use.
pub(crate) const COMMITMENT_BITS: usize = 64;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub(crate) struct Generators {
  /// The G (bold) vector of generators.
  pub(crate) G: Vec<EdwardsPoint>,
  /// The H (bold) vector of generators.
  pub(crate) H: Vec<EdwardsPoint>,
}

#[allow(clippy::cast_possible_truncation)]
const fn preimage(dst: &'static [u8], mut i: usize) -> [u8; 32] {
  let mut preimage =
    keccak_const::Keccak256::new().update(&CompressedPoint::H.to_bytes()).update(dst);

  // An inline `VarInt::write` which writes into our hasher
  while {
    let mut next = i & 0b0111_1111;
    i >>= 7;
    if i != 0 {
      next |= 1 << 7;
    }
    preimage = preimage.update(&[next as u8]);
    i != 0
  } {}

  preimage.finalize()
}

#[cfg(feature = "compile-time-generators")]
#[allow(clippy::large_stack_arrays)]
pub(crate) const fn generate(
  dst: &'static [u8],
) -> ([CompressedPoint; MAX_MN], [CompressedPoint; MAX_MN]) {
  let mut preimages = [[0u8; 32]; 2 * MAX_MN];
  let mut i = 0;
  while i < MAX_MN {
    preimages[i] = preimage(dst, 2 * i);
    preimages[MAX_MN + i] = preimage(dst, (2 * i) + 1);
    i += 1;
  }

  let joint = CompressedPoint::biased_hash_vartime::<{ 2 * MAX_MN }, { 2 * 2 * MAX_MN }>(preimages);

  let mut result = ([CompressedPoint::IDENTITY; MAX_MN], [CompressedPoint::IDENTITY; MAX_MN]);
  let mut i = 0;
  while i < MAX_MN {
    result.0[i] = joint[i];
    result.1[i] = joint[MAX_MN + i];
    i += 1;
  }
  result
}

#[cfg(not(feature = "compile-time-generators"))]
pub(crate) fn generate_alloc(dst: &'static [u8]) -> (Vec<CompressedPoint>, Vec<CompressedPoint>) {
  let mut result = (vec![CompressedPoint::G; MAX_MN], vec![CompressedPoint::G; MAX_MN]);
  let mut i = 0;
  while i < MAX_MN {
    result.0[i] = CompressedPoint::biased_hash_vartime::<1, 2>([preimage(dst, 2 * i)])[0];
    result.1[i] = CompressedPoint::biased_hash_vartime::<1, 2>([preimage(dst, (2 * i) + 1)])[0];
    i += 1;
  }
  result
}

pub(crate) fn decompress(
  generators: (
    impl IntoIterator<Item = CompressedPoint>,
    impl IntoIterator<Item = CompressedPoint>,
  ),
) -> Generators {
  Generators {
    G: generators
      .1
      .into_iter()
      .map(|point| point.decompress().expect("attempted to decompress an invalid generator").into())
      .collect::<Vec<_>>(),
    H: generators
      .0
      .into_iter()
      .map(|point| point.decompress().expect("attempted to decompress an invalid generator").into())
      .collect::<Vec<_>>(),
  }
}
