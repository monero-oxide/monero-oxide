use core::{
  cmp::{Ordering, PartialOrd},
  hash::{Hasher, Hash},
};
use std_shims::io::{self, Read, Write};

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use monero_io::read_bytes;

use crate::Point;

/// A compressed Ed25519 point.
///
/// [`curve25519_dalek::edwards::CompressedEdwardsY`], the [`curve25519_dalek`] version of this
/// struct, exposes a [`curve25519_dalek::edwards::CompressedEdwardsY::decompress`] function that
/// does not check the point is canonically encoded. This struct exposes a
/// [`CompressedPoint::decompress`] function that does check the point is canonically encoded. For
/// the exact details, please check its documentation.
///
/// The implementations of [`PartialOrd`], [`Ord`], and [`Hash`] are not guaranteed to execute in
/// constant time.
#[derive(Clone, Copy, Eq, Debug, Zeroize)]
pub struct CompressedPoint([u8; 32]);

impl ConstantTimeEq for CompressedPoint {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.0.ct_eq(&other.0)
  }
}
impl PartialEq for CompressedPoint {
  /// This defers to `ConstantTimeEq::ct_eq`.
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.ct_eq(other))
  }
}

impl PartialOrd for CompressedPoint {
  /// This executes in variable time.
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for CompressedPoint {
  /// This executes in variable time.
  fn cmp(&self, other: &Self) -> Ordering {
    self.0.cmp(&other.0)
  }
}

impl Hash for CompressedPoint {
  /// This executes in variable time.
  fn hash<H: Hasher>(&self, hasher: &mut H) {
    self.0.hash::<H>(hasher);
  }
}

impl CompressedPoint {
  /// The encoding of the identity point.
  #[rustfmt::skip]
  pub const IDENTITY: Self = Self([
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  /// The `G` generator for the Monero protocol.
  pub const G: Self = Self(curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes());
  /// The `H` generator for the Monero protocol.
  #[rustfmt::skip]
  pub const H: Self = Self([
    139, 101,  89, 112,  21,  55, 153, 175,  42, 234, 220, 159, 241, 173, 208, 234,
    108, 114,  81, 213,  65,  84, 207, 169,  44,  23,  58,  13, 211, 156,  31, 148,
  ]);

  /// Read a [`CompressedPoint`] without checking if this point can be decompressed.
  ///
  /// This may run in variable time.
  pub fn read<R: Read>(r: &mut R) -> io::Result<CompressedPoint> {
    Ok(CompressedPoint(read_bytes(r)?))
  }

  /// Write a compressed point.
  ///
  /// This may run in variable time.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.0)
  }

  /// Returns the raw bytes of the compressed point.
  ///
  /// This does not ensure these bytes represent a point of any validity, with no guarantees on
  /// their contents.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0
  }

  /// Decompress a canonically-encoded Ed25519 point.
  ///
  /// Ed25519 is of order `8 * l`. This function ensures each of those `8 * l` points have a
  /// singular encoding by checking points aren't encoded with an unreduced field element,
  /// and aren't negative when the negative is equivalent (0 == -0).
  ///
  /// Since this decodes an Ed25519 point, it does not check the point is in the prime-order
  /// subgroup. Torsioned points do have a canonical encoding, and only aren't canonical when
  /// considered in relation to the prime-order subgroup.
  pub fn decompress(&self) -> Option<Point> {
    // TODO: Instead of re-compressing, check the edge cases with optimized algorithms
    curve25519_dalek::edwards::CompressedEdwardsY(self.0)
      .decompress()
      // Ban points which are either unreduced or -0
      .filter(|point| point.compress().to_bytes() == self.0)
      .map(Point::from)
  }
}

impl From<[u8; 32]> for CompressedPoint {
  fn from(value: [u8; 32]) -> Self {
    Self(value)
  }
}

// This does not implement `From<CompressedPoint> for [u8; 32]` to ensure
// `CompressedPoint::to_bytes`, with its docstring, is the source of truth.
