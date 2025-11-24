use std_shims::{sync::LazyLock, io};

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use monero_io::read_u64;

use crate::{CompressedPoint, Point, Scalar};

// A static for `H` as it's frequently used yet this decompression is expensive.
static H: LazyLock<curve25519_dalek::EdwardsPoint> = LazyLock::new(|| {
  curve25519_dalek::edwards::CompressedEdwardsY(CompressedPoint::H.to_bytes())
    .decompress()
    .expect("couldn't decompress `CompressedPoint::H`")
});

/// The opening for a Pedersen commitment commiting to a `u64`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
  /// The mask for this commitment.
  pub mask: Scalar,
  /// The amount committed to by this commitment.
  pub amount: u64,
}

impl ConstantTimeEq for Commitment {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.mask.ct_eq(&other.mask) & self.amount.ct_eq(&other.amount)
  }
}

impl core::fmt::Debug for Commitment {
  /// This implementation reveals the `Commitment`'s amount.
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("Commitment").field("amount", &self.amount).finish_non_exhaustive()
  }
}

impl Commitment {
  /// A commitment to 0, defined with a mask of 1 (as to not be the identity).
  ///
  /// This follows the Monero protocol's definition for a commitment without randomness.
  /// https://github.com/monero-project/monero
  ///   /blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/src/ringct/rctOps.cpp#L333
  #[doc(hidden)] // TODO: Remove this for `without_randomness`, taking an amount? How is this used?
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::from(curve25519_dalek::Scalar::ONE), amount: 0 }
  }

  /// Create a new `Commitment`.
  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  /// Commit to the value within this opening.
  // TODO: Optimize around how `amount` is short.
  pub fn commit(&self) -> Point {
    Point::from(
      <curve25519_dalek::EdwardsPoint as curve25519_dalek::traits::MultiscalarMul>::multiscalar_mul(
        [self.mask.into(), self.amount.into()],
        [curve25519_dalek::constants::ED25519_BASEPOINT_POINT, *H],
      ),
    )
  }

  /// Write the `Commitment`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.mask.write(w)?;
    w.write_all(&self.amount.to_le_bytes())
  }

  /// Read a `Commitment`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Commitment> {
    Ok(Commitment::new(Scalar::read(r)?, read_u64(r)?))
  }
}
