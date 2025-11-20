#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::prelude::*;

use curve25519_dalek::EdwardsPoint;

use monero_io::VarInt;
use monero_ed25519::Point;
use monero_primitives::keccak256;

/// The maximum amount of commitments provable for within a single Bulletproof(+).
#[doc(hidden)]
pub const MAX_BULLETPROOF_COMMITMENTS: usize = 16;
/// The amount of bits a value within a commitment may use.
#[doc(hidden)]
pub const COMMITMENT_BITS: usize = 64;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
#[doc(hidden)]
pub struct Generators {
  /// The G (bold) vector of generators.
  #[doc(hidden)]
  pub G: Vec<EdwardsPoint>,
  /// The H (bold) vector of generators.
  #[doc(hidden)]
  pub H: Vec<EdwardsPoint>,
}

/// Generate generators as needed for Bulletproofs(+), as Monero does.
///
/// Consumers should not call this function ad-hoc, yet call it within a build script or use a
/// once-initialized static.
#[doc(hidden)]
pub fn bulletproofs_generators(dst: &'static [u8]) -> Generators {
  // The maximum amount of bits used within a single range proof.
  const MAX_MN: usize = MAX_BULLETPROOF_COMMITMENTS * COMMITMENT_BITS;

  let mut preimage = monero_ed25519::CompressedPoint::H.to_bytes().to_vec();
  preimage.extend(dst);

  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    // We generate a pair of generators per iteration
    let i = 2 * i;

    let mut even = preimage.clone();
    VarInt::write(&i, &mut even).expect("write failed but <Vec as io::Write> doesn't fail");
    res.H.push(Point::biased_hash(keccak256(&even)).into());

    let mut odd = preimage.clone();
    VarInt::write(&(i + 1), &mut odd).expect("write failed but <Vec as io::Write> doesn't fail");
    res.G.push(Point::biased_hash(keccak256(&odd)).into());
  }
  res
}
