#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use std_shims::{
  prelude::*,
  sync::LazyLock,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};
use zeroize::Zeroizing;

use curve25519_dalek::EdwardsPoint;

use monero_io::*;
use monero_ed25519::*;
pub use monero_bulletproofs_generators::MAX_BULLETPROOF_COMMITMENTS as MAX_COMMITMENTS;
use monero_bulletproofs_generators::COMMITMENT_BITS;

pub(crate) mod scalar_vector;
pub(crate) mod point_vector;

pub(crate) mod core;

pub(crate) mod batch_verifier;
use batch_verifier::{BulletproofsBatchVerifier, BulletproofsPlusBatchVerifier};
pub use batch_verifier::BatchVerifier;

pub(crate) mod original;
use crate::original::{
  IpProof, AggregateRangeStatement as OriginalStatement, AggregateRangeWitness as OriginalWitness,
  AggregateRangeProof as OriginalProof,
};

pub(crate) mod plus;
use crate::plus::{
  WipProof, AggregateRangeStatement as PlusStatement, AggregateRangeWitness as PlusWitness,
  AggregateRangeProof as PlusProof,
};

#[cfg(test)]
mod tests;

// The logarithm (over 2) of the amount of bits a value within a commitment may use.
const LOG_COMMITMENT_BITS: usize = COMMITMENT_BITS.ilog2() as usize;
// The maximum length of L/R `Vec`s.
const MAX_LR: usize = (MAX_COMMITMENTS.ilog2() as usize) + LOG_COMMITMENT_BITS;

// A static for `H` as it's frequently used yet this decompression is expensive.
static MONERO_H: LazyLock<EdwardsPoint> = LazyLock::new(|| {
  CompressedPoint::H.decompress().expect("couldn't decompress `CompressedPoint::H`").into()
});

/// An error from proving/verifying Bulletproofs(+).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BulletproofError {
  /// Proving/verifying a Bulletproof(+) range proof with no commitments.
  #[error("no commitments to prove the range for")]
  NoCommitments,
  /// Proving/verifying a Bulletproof(+) range proof with more commitments than supported.
  #[error("too many commitments to prove the range for")]
  TooManyCommitments,
}

/// A Bulletproof(+).
///
/// This encapsulates either a Bulletproof or a Bulletproof+.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproof {
  /// A Bulletproof.
  Original(OriginalProof),
  /// A Bulletproof+.
  Plus(PlusProof),
}

impl Bulletproof {
  fn bp_fields(plus: bool) -> usize {
    if plus {
      6
    } else {
      9
    }
  }

  /// Calculate the weight penalty for the Bulletproof(+).
  ///
  /// Bulletproofs(+) are logarithmically sized yet linearly timed. Evaluating by their size alone
  /// accordingly doesn't properly represent the burden of the proof. Monero 'claws back' some of
  /// the weight lost by using a proof smaller than it is fast to compensate for this.
  ///
  /// If the amount of outputs specified exceeds the maximum amount of outputs, the result for the
  /// maximum amount of outputs will be returned.
  // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
  //   src/cryptonote_basic/cryptonote_format_utils.cpp#L106-L124
  pub fn calculate_clawback(plus: bool, n_outputs: usize) -> (usize, usize) {
    #[allow(non_snake_case)]
    let mut LR_len = 0;
    let mut n_padded_outputs = 1;
    while n_padded_outputs < n_outputs.min(MAX_COMMITMENTS) {
      LR_len += 1;
      n_padded_outputs = 1 << LR_len;
    }
    LR_len += LOG_COMMITMENT_BITS;

    let mut clawback = 0;
    if n_padded_outputs > 2 {
      let fields = Bulletproof::bp_fields(plus);
      let base = ((fields + (2 * (LOG_COMMITMENT_BITS + 1))) * 32) / 2;
      let size = (fields + (2 * LR_len)) * 32;
      clawback = ((base * n_padded_outputs) - size) * 4 / 5;
    }

    (clawback, LR_len)
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof.
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: Vec<Commitment>,
  ) -> Result<Bulletproof, BulletproofError> {
    if outputs.is_empty() {
      Err(BulletproofError::NoCommitments)?;
    }
    if outputs.len() > MAX_COMMITMENTS {
      Err(BulletproofError::TooManyCommitments)?;
    }
    let commitments =
      outputs.iter().map(|commitment| commitment.commit().into()).collect::<Vec<_>>();
    Ok(Bulletproof::Original(
      OriginalStatement::new(&commitments)
        .expect("failed to create statement despite checking amount of commitments")
        .prove(
          rng,
          OriginalWitness::new(outputs)
            .expect("failed to create witness despite checking amount of commitments"),
        )
        .expect(
          "failed to prove Bulletproof::Original despite ensuring statement/witness consistency",
        ),
    ))
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof+.
  pub fn prove_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: Vec<Commitment>,
  ) -> Result<Bulletproof, BulletproofError> {
    if outputs.is_empty() {
      Err(BulletproofError::NoCommitments)?;
    }
    if outputs.len() > MAX_COMMITMENTS {
      Err(BulletproofError::TooManyCommitments)?;
    }
    let commitments =
      outputs.iter().map(|commitment| commitment.commit().into()).collect::<Vec<_>>();
    Ok(Bulletproof::Plus(
      PlusStatement::new(&commitments)
        .expect("failed to create statement despite checking amount of commitments")
        .prove(
          rng,
          &Zeroizing::new(
            PlusWitness::new(outputs)
              .expect("failed to create witness despite checking amount of commitments"),
          ),
        )
        .expect("failed to prove Bulletproof::Plus despite ensuring statement/witness consistency"),
    ))
  }

  /// Verify the given Bulletproof(+).
  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    commitments: &[CompressedPoint],
  ) -> bool {
    let Some(commitments) = commitments
      .iter()
      .map(|point| point.decompress().map(Point::into))
      .collect::<Option<Vec<_>>>()
    else {
      return false;
    };

    match self {
      Bulletproof::Original(bp) => {
        let mut verifier = BulletproofsBatchVerifier::default();
        let Some(statement) = OriginalStatement::new(&commitments) else {
          return false;
        };
        if !statement.verify(rng, &mut verifier, bp.clone()) {
          return false;
        }
        verifier.verify()
      }
      Bulletproof::Plus(bp) => {
        let mut verifier = BulletproofsPlusBatchVerifier::default();
        let Some(statement) = PlusStatement::new(&commitments) else {
          return false;
        };
        if !statement.verify(rng, &mut verifier, bp.clone()) {
          return false;
        }
        verifier.verify()
      }
    }
  }

  /// Accumulate the verification for the given Bulletproof(+) into the specified BatchVerifier.
  ///
  /// Returns false if the Bulletproof(+) isn't sane, leaving the BatchVerifier in an undefined
  /// state.
  ///
  /// Returns true if the Bulletproof(+) is sane, regardless of its validity.
  ///
  /// The BatchVerifier must have its verification function executed to actually verify this proof.
  #[must_use]
  pub fn batch_verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier,
    commitments: &[CompressedPoint],
  ) -> bool {
    let Some(commitments) = commitments
      .iter()
      .map(|point| point.decompress().map(Point::into))
      .collect::<Option<Vec<_>>>()
    else {
      return false;
    };

    match self {
      Bulletproof::Original(bp) => {
        let Some(statement) = OriginalStatement::new(&commitments) else {
          return false;
        };
        statement.verify(rng, &mut verifier.original, bp.clone())
      }
      Bulletproof::Plus(bp) => {
        let Some(statement) = PlusStatement::new(&commitments) else {
          return false;
        };
        statement.verify(rng, &mut verifier.plus, bp.clone())
      }
    }
  }

  // This uses `write_all(scalar.to_bytes())` as these are `curve25519_dalek::Scalar`, not
  // `monero_ed25519::Scalar`
  fn write_core<W: Write, F: Fn(&[CompressedPoint], &mut W) -> io::Result<()>>(
    &self,
    w: &mut W,
    specific_write_vec: F,
  ) -> io::Result<()> {
    match self {
      Bulletproof::Original(bp) => {
        bp.A.write(w)?;
        bp.S.write(w)?;
        bp.T1.write(w)?;
        bp.T2.write(w)?;
        w.write_all(&bp.tau_x.to_bytes())?;
        w.write_all(&bp.mu.to_bytes())?;
        specific_write_vec(&bp.ip.L, w)?;
        specific_write_vec(&bp.ip.R, w)?;
        w.write_all(&bp.ip.a.to_bytes())?;
        w.write_all(&bp.ip.b.to_bytes())?;
        w.write_all(&bp.t_hat.to_bytes())
      }

      Bulletproof::Plus(bp) => {
        bp.A.write(w)?;
        bp.wip.A.write(w)?;
        bp.wip.B.write(w)?;
        w.write_all(&bp.wip.r_answer.to_bytes())?;
        w.write_all(&bp.wip.s_answer.to_bytes())?;
        w.write_all(&bp.wip.delta_answer.to_bytes())?;
        specific_write_vec(&bp.wip.L, w)?;
        specific_write_vec(&bp.wip.R, w)
      }
    }
  }

  /// Write a Bulletproof(+) for the message signed by a transaction's signature.
  ///
  /// This has a distinct encoding from the standard encoding.
  pub fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_raw_vec(CompressedPoint::write, points, w))
  }

  /// Write a Bulletproof(+).
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_vec(CompressedPoint::write, points, w))
  }

  /// Serialize a Bulletproof(+) to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(512);
    self.write(&mut serialized).expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  /// Read a Bulletproof.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
    Ok(Bulletproof::Original(OriginalProof {
      A: CompressedPoint::read(r)?,
      S: CompressedPoint::read(r)?,
      T1: CompressedPoint::read(r)?,
      T2: CompressedPoint::read(r)?,
      tau_x: Scalar::read(r)?.into(),
      mu: Scalar::read(r)?.into(),
      ip: IpProof {
        L: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
        R: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
        a: Scalar::read(r)?.into(),
        b: Scalar::read(r)?.into(),
      },
      t_hat: Scalar::read(r)?.into(),
    }))
  }

  /// Read a Bulletproof+.
  pub fn read_plus<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
    Ok(Bulletproof::Plus(PlusProof {
      A: CompressedPoint::read(r)?,
      wip: WipProof {
        A: CompressedPoint::read(r)?,
        B: CompressedPoint::read(r)?,
        r_answer: Scalar::read(r)?.into(),
        s_answer: Scalar::read(r)?.into(),
        delta_answer: Scalar::read(r)?.into(),
        L: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
        R: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
      },
    }))
  }
}
