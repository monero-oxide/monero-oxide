use std_shims::{
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::{EdwardsPoint, edwards::CompressedEdwardsY};

use crate::read_bytes;

/// A compressed Ed25519 point.
///
/// [`CompressedEdwardsY`], the [`curve25519_dalek`] version of this struct exposes a
/// [`CompressedEdwardsY::decompress`] function that does not check the point is canonically
/// encoded. This struct exposes a [`CompressedPoint::decompress`] function that does check
/// the point is canonically encoded, check that function for details.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct CompressedPoint(pub [u8; 32]);

impl CompressedPoint {
  /// Read a [`CompressedPoint`] without checking if this point can be decompressed.
  pub fn read<R: Read>(r: &mut R) -> io::Result<CompressedPoint> {
    Ok(CompressedPoint(read_bytes(r)?))
  }

  /// Write a compressed point.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.0)
  }

  /// Returns the raw bytes of the compressed point.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0
  }

  /// Returns a reference to the raw bytes of the compressed point.
  pub fn as_bytes(&self) -> &[u8; 32] {
    &self.0
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
  pub fn decompress(&self) -> Option<EdwardsPoint> {
    CompressedEdwardsY(self.0)
      .decompress()
      // Ban points which are either unreduced or -0
      .filter(|point| point.compress().to_bytes() == self.0)
  }
}

impl From<[u8; 32]> for CompressedPoint {
  fn from(value: [u8; 32]) -> Self {
    Self(value)
  }
}

impl From<CompressedEdwardsY> for CompressedPoint {
  fn from(compressed: CompressedEdwardsY) -> Self {
    Self(compressed.0)
  }
}
