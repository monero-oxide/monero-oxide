#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use monero_io::*;
use monero_ed25519::*;

/// Decoy data, as used for producing Monero's ring signatures.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Decoys {
  offsets: Vec<u64>,
  signer_index: u8,
  ring: Vec<[Point; 2]>,
}

impl core::fmt::Debug for Decoys {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("Decoys")
      .field("offsets", &self.offsets)
      .field("ring", &self.ring)
      .finish_non_exhaustive()
  }
}

/*
  The max ring size the monero-oxide libraries is programmed to support creating.

  This exceeds the current Monero protocol's ring size of `16`, with the next hard fork planned to
  remove rings entirely, making this without issue.
*/
const MAX_RING_SIZE: usize = u8::MAX as usize;

#[allow(clippy::len_without_is_empty)]
impl Decoys {
  /// This equality runs in constant-time if the decoys are the same length.
  ///
  /// This is not a public function as it is not part of our API commitment.
  #[doc(hidden)]
  pub fn ct_eq(&self, other: &Self) -> Choice {
    let ring = self.ring.len().ct_eq(&other.ring.len()) &
      self.ring.iter().zip(&other.ring).fold(Choice::from(1u8), |accum, (lhs, rhs)| {
        accum & lhs.as_slice().ct_eq(rhs.as_slice())
      });
    self.offsets.ct_eq(&other.offsets) & self.signer_index.ct_eq(&other.signer_index) & ring
  }

  /// Create a new instance of decoy data.
  ///
  /// `offsets` are the positions of each ring member within the Monero blockchain, offset from the
  /// prior member's position (with the initial ring member offset from 0).
  pub fn new(offsets: Vec<u64>, signer_index: u8, ring: Vec<[Point; 2]>) -> Option<Self> {
    if (offsets.len() > MAX_RING_SIZE) ||
      (offsets.len() != ring.len()) ||
      (usize::from(signer_index) >= ring.len())
    {
      None?;
    }
    // Check these offsets form representable positions
    if offsets.iter().copied().try_fold(0, u64::checked_add).is_none() {
      None?;
    }
    Some(Decoys { offsets, signer_index, ring })
  }

  /// The length of the ring.
  pub fn len(&self) -> usize {
    self.offsets.len()
  }

  /// The positions of the ring members within the Monero blockchain, as their offsets.
  ///
  /// The list is formatted as the position of the first ring member, then the offset from each
  /// ring member to its prior.
  pub fn offsets(&self) -> &[u64] {
    &self.offsets
  }

  /// The positions of the ring members within the Monero blockchain.
  pub fn positions(&self) -> Vec<u64> {
    let mut res = Vec::with_capacity(self.len());
    res.push(self.offsets[0]);
    for m in 1 .. self.len() {
      res.push(res[m - 1] + self.offsets[m]);
    }
    res
  }

  /// The index of the signer within the ring.
  pub fn signer_index(&self) -> u8 {
    self.signer_index
  }

  /// The ring.
  pub fn ring(&self) -> &[[Point; 2]] {
    &self.ring
  }

  /// The [key, commitment] pair of the signer.
  pub fn signer_ring_members(&self) -> [Point; 2] {
    self.ring[usize::from(self.signer_index)]
  }

  /// Write the Decoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write(&self, w: &mut impl io::Write) -> io::Result<()> {
    write_vec(VarInt::write, &self.offsets, w)?;
    w.write_all(&[self.signer_index])?;
    write_raw_vec(
      |pair, w| {
        pair[0].compress().write(w)?;
        pair[1].compress().write(w)
      },
      &self.ring,
      w,
    )
  }

  /// Serialize the Decoys to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res =
      Vec::with_capacity((1 + (2 * self.offsets.len())) + 1 + 1 + (self.ring.len() * 64));
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read a set of Decoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read(r: &mut impl io::Read) -> io::Result<Decoys> {
    let offsets = read_vec(VarInt::read, Some(MAX_RING_SIZE), r)?;
    let len = offsets.len();
    Decoys::new(
      offsets,
      read_byte(r)?,
      read_raw_vec(
        |r| {
          Ok([
            CompressedPoint::read(r)?
              .decompress()
              .ok_or(io::Error::other("Decoys had invalid key in ring"))?,
            CompressedPoint::read(r)?
              .decompress()
              .ok_or(io::Error::other("Decoys had invalid commitment in ring"))?,
          ])
        },
        len,
        r,
      )?,
    )
    .ok_or_else(|| io::Error::other("invalid Decoys"))
  }
}
