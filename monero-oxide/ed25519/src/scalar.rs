use core::ops::DerefMut as _;

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, *};

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng};

use sha3::{Digest as _, Keccak256};

use monero_io::*;

/// A reduced scalar.
#[derive(Clone, Copy, Eq, Debug, Zeroize)]
pub struct Scalar([u8; 32]);

impl ConstantTimeEq for Scalar {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.0.ct_eq(&other.0)
  }
}
impl PartialEq for Scalar {
  /// This defers to `ConstantTimeEq::ct_eq`.
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.ct_eq(other))
  }
}

impl Scalar {
  /// The additive identity.
  pub const ZERO: Self = Self([0; 32]);
  /// The multiplicative identity.
  #[rustfmt::skip]
  pub const ONE: Self = Self([
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  /// The multiplicative inverse of `8 \mod l`.
  ///
  /// `l` is defined as the largest prime factor in the amount of points on the Ed25519 elliptic
  /// curve.
  ///
  /// This is useful as part of clearing terms belonging to a small-order subgroup from within a
  /// point.
  #[rustfmt::skip]
  pub const INV_EIGHT: Self = Self([
    121,  47, 220, 226,  41, 229,   6,  97, 208, 218,  28, 125, 179, 157, 211,   7,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   6,
    ]);

  /// Write a Scalar.
  ///
  /// This may run in variable time.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.0)
  }

  /// Read a canonically-encoded scalar.
  ///
  /// Some scalars within the Monero protocol are not enforced to be canonically encoded. For such
  /// scalars, they should be represented as `[u8; 32]` and later converted to scalars as relevant.
  ///
  /// This may run in variable time.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Scalar> {
    let bytes = read_bytes(r)?;
    Option::<curve25519_dalek::Scalar>::from(curve25519_dalek::Scalar::from_canonical_bytes(bytes))
      .ok_or_else(|| io::Error::other("unreduced scalar"))?;
    Ok(Self(bytes))
  }

  /// Create a `Scalar` from a `curve25519_dalek::Scalar`.
  ///
  /// This is not a public function as it is not part of our API commitment.
  #[doc(hidden)]
  pub fn from(scalar: curve25519_dalek::Scalar) -> Self {
    Self(scalar.to_bytes())
  }

  /// Create a `curve25519_dalek::Scalar` from a `Scalar`.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn into(self) -> curve25519_dalek::Scalar {
    curve25519_dalek::Scalar::from_canonical_bytes(self.0)
      .expect("`Scalar` instantiated with invalid contents")
  }

  /// Sample a uniform `Scalar` from an RNG.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
    let mut raw = Zeroizing::new([0; 64]);
    rng.fill_bytes(raw.deref_mut());
    Self(Zeroizing::new(curve25519_dalek::Scalar::from_bytes_mod_order_wide(&raw)).to_bytes())
  }

  /// Sample a scalar via hash function.
  ///
  /// The implementation of this is `keccak256(data) % l`, where `l` is the largest prime factor in
  /// the amount of points on the Ed25519 elliptic curve. Notably, this is not a wide reduction.
  ///
  /// This function panics if it finds a Keccak-256 preimage for an encoding of a multiple of `l`.
  pub fn hash(data: impl AsRef<[u8]>) -> Self {
    let scalar =
      curve25519_dalek::Scalar::from_bytes_mod_order(Keccak256::digest(data.as_ref()).into());

    /*
      Monero errors in this case to ensure its integrity, yet its of negligible probability to the
      degree Monero's integrity will be compromised by _other_ methods much much sooner.

      Accordingly, we don't propagate the error, and simply panic here. The end result is
      effectively the same: We will not claim proofs which generate zero challenges are valid. We
      just will panic, instead of flagging them as invalid.
    */
    assert!(
      scalar != curve25519_dalek::Scalar::ZERO,
      "keccak256(preimage) \\cong 0 \\mod l! Preimage: {:?}",
      data.as_ref()
    );

    Self::from(scalar)
  }
}

impl From<Scalar> for [u8; 32] {
  fn from(scalar: Scalar) -> [u8; 32] {
    scalar.0
  }
}
