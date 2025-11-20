#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use core::fmt::Debug;
use std_shims::{
  sync::LazyLock,
  io::{self, Read, Write},
  vec::Vec,
};

use zeroize::Zeroize;

use curve25519_dalek::{traits::Identity, EdwardsPoint, edwards::CompressedEdwardsY};

use monero_io::*;
use monero_ed25519::{UnreducedScalar, Scalar, Point, CompressedPoint};

static H_POW_2_CELL: LazyLock<[EdwardsPoint; 64]> = LazyLock::new(|| {
  #[allow(non_snake_case)]
  let H = CompressedEdwardsY(monero_ed25519::CompressedPoint::H.to_bytes()).decompress().unwrap();
  let mut res = [H; 64];
  for i in 1 .. 64 {
    res[i] = res[i - 1] + res[i - 1];
  }
  res
});
/// Monero's `H` generator, multiplied by 2**i for i in 1 ..= 64.
///
/// This table is useful when working with amounts, which are u64s.
#[allow(non_snake_case)]
fn H_pow_2() -> &'static [EdwardsPoint; 64] {
  &H_POW_2_CELL
}

// 64 Borromean ring signatures, as needed for a 64-bit range proof.
//
// s0 and s1 are stored as `UnreducedScalar`s due to Monero not requiring they were reduced.
// `UnreducedScalar` preserves their original byte encoding and implements a custom reduction
// algorithm which was in use.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
struct BorromeanSignatures {
  s0: [UnreducedScalar; 64],
  s1: [UnreducedScalar; 64],
  ee: Scalar,
}

impl BorromeanSignatures {
  // Read a set of BorromeanSignatures.
  fn read<R: Read>(r: &mut R) -> io::Result<BorromeanSignatures> {
    Ok(BorromeanSignatures {
      s0: read_array(UnreducedScalar::read, r)?,
      s1: read_array(UnreducedScalar::read, r)?,
      ee: Scalar::read(r)?,
    })
  }

  // Write the set of BorromeanSignatures.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for s0 in &self.s0 {
      s0.write(w)?;
    }
    for s1 in &self.s1 {
      s1.write(w)?;
    }
    self.ee.write(w)
  }

  fn verify(&self, keys_a: &[EdwardsPoint], keys_b: &[EdwardsPoint]) -> bool {
    let mut transcript = [0; 2048];

    for i in 0 .. 64 {
      #[allow(non_snake_case)]
      let LL = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &self.ee.into(),
        &keys_a[i],
        &self.s0[i].ref10_slide_scalar_vartime().into(),
      );
      #[allow(non_snake_case)]
      let LV = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &Scalar::hash(LL.compress().to_bytes()).into(),
        &keys_b[i],
        &self.s1[i].ref10_slide_scalar_vartime().into(),
      );
      transcript[(i * 32) .. ((i + 1) * 32)].copy_from_slice(&LV.compress().to_bytes());
    }

    Scalar::hash(transcript) == self.ee
  }
}

/// A range proof premised on Borromean ring signatures.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct BorromeanRange {
  sigs: BorromeanSignatures,
  bit_commitments: [CompressedPoint; 64],
}

impl BorromeanRange {
  /// Read a BorromeanRange proof.
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorromeanRange> {
    Ok(BorromeanRange {
      sigs: BorromeanSignatures::read(r)?,
      bit_commitments: read_array(CompressedPoint::read, r)?,
    })
  }

  /// Write the BorromeanRange proof.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.sigs.write(w)?;
    write_raw_vec(CompressedPoint::write, &self.bit_commitments, w)
  }

  /// Verify the commitment contains a 64-bit value.
  #[must_use]
  pub fn verify(&self, commitment: &CompressedPoint) -> bool {
    let Some(bit_commitments) = self
      .bit_commitments
      .iter()
      .map(|compressed| compressed.decompress().map(Point::into))
      .collect::<Option<Vec<_>>>()
    else {
      return false;
    };

    if bit_commitments.iter().sum::<EdwardsPoint>().compress().0 != commitment.to_bytes() {
      return false;
    }

    #[allow(non_snake_case)]
    let H_pow_2 = H_pow_2();
    let mut commitments_sub_one = [EdwardsPoint::identity(); 64];
    for i in 0 .. 64 {
      commitments_sub_one[i] = bit_commitments[i] - H_pow_2[i];
    }

    self.sigs.verify(&bit_commitments, &commitments_sub_one)
  }
}
