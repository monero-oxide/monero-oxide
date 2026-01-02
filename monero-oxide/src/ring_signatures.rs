use std_shims::{
  io::{self, *},
  vec::Vec,
};

use zeroize::Zeroize;

use crate::{io::*, ed25519::*};

#[cfg_attr(not(test), expect(clippy::cfg_not_test))]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct Signature {
  #[cfg(test)]
  pub(crate) c: Scalar,
  #[cfg(test)]
  pub(crate) s: Scalar,
  #[cfg(not(test))]
  c: Scalar,
  #[cfg(not(test))]
  s: Scalar,
}

impl Signature {
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.c.write(w)?;
    self.s.write(w)?;
    Ok(())
  }

  fn read<R: Read>(r: &mut R) -> io::Result<Signature> {
    Ok(Signature { c: Scalar::read(r)?, s: Scalar::read(r)? })
  }
}

/// A ring signature.
///
/// This was used by the original Cryptonote transaction protocol and was deprecated with RingCT.
#[cfg_attr(not(test), expect(clippy::cfg_not_test))]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct RingSignature {
  #[cfg(test)]
  pub(crate) sigs: Vec<Signature>,
  #[cfg(not(test))]
  sigs: Vec<Signature>,
}

impl RingSignature {
  /// Write the RingSignature.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for sig in &self.sigs {
      sig.write(w)?;
    }
    Ok(())
  }

  /// Read a RingSignature.
  pub fn read<R: Read>(members: usize, r: &mut R) -> io::Result<RingSignature> {
    Ok(RingSignature { sigs: read_raw_vec(Signature::read, members, r)? })
  }

  /// Verify the ring signature.
  ///
  /// WARNING: This follows the Fiat-Shamir transcript format used by the Monero protocol, which
  /// makes assumptions on what has already been transcripted and bound to within `msg_hash`. Do
  /// not use this if you don't know what you're doing.
  pub fn verify(
    &self,
    msg_hash: &[u8; 32],
    ring: &[CompressedPoint],
    key_image: &CompressedPoint,
  ) -> bool {
    if ring.len() != self.sigs.len() {
      return false;
    }

    let Some(key_image) = key_image.decompress() else {
      return false;
    };
    let Some(key_image) = key_image.key_image() else {
      return false;
    };

    let mut buf = Vec::with_capacity(32 + (2 * 32 * ring.len()));
    buf.extend_from_slice(msg_hash);

    let mut sum = curve25519_dalek::Scalar::ZERO;
    for (ring_member, sig) in ring.iter().zip(&self.sigs) {
      /*
        The traditional Schnorr signature is:
          r = sample()
          c = H(r G || m)
          s = r - c x
        Verified as:
          s G + c A == R

        Each ring member here performs a dual-Schnorr signature for:
          s G + c A
          s HtP(A) + c K
        Where the transcript is pushed both these values, r G, r HtP(A) for the real spend.
        This also serves as a DLEq proof between the key and the key image.

        Checking sum(c) == H(transcript) acts a disjunction, where any one of the `c`s can be
        modified to cause the intended sum, if and only if a corresponding `s` value is known.
      */

      let Some(decomp_ring_member) = ring_member.decompress() else {
        return false;
      };

      #[expect(non_snake_case)]
      let Li = curve25519_dalek::EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &sig.c.into(),
        &decomp_ring_member.into(),
        &sig.s.into(),
      );
      buf.extend_from_slice(Li.compress().as_bytes());
      #[expect(non_snake_case)]
      let Ri = (sig.s.into() * Point::biased_hash(ring_member.to_bytes()).into()) +
        (sig.c.into() * key_image);
      buf.extend_from_slice(Ri.compress().as_bytes());

      sum += sig.c.into();
    }
    Scalar::from(sum) == Scalar::hash(buf)
  }
}
