use core::{ops::RangeBounds, future::Future};
use alloc::{borrow::ToOwned as _, format, vec::Vec};

use monero_oxide::ed25519::Point;

use crate::{InterfaceError, TransactionsError, ProvidesBlockchainMeta};

/// How to evaluate if an output is unlocked.
pub enum EvaluateUnlocked {
  /// The normal method of evaluation.
  Normal,
  /// A deterministic method which only considers the view of the blockchain as of block
  /// #`block_number`. This is fingerprintable as outputs locked with a time-based timelock will
  /// always be considered locked and never be selected as decoys.
  FingerprintableDeterministic {
    /// The number of the block to premise the view upon.
    block_number: usize,
  },
}

/// Provides the necessary data to select decoys, without validating it.
///
/// This SHOULD be satisfied by a local store to prevent attack by malicious remote nodes.
pub trait ProvidesUnvalidatedDecoys: ProvidesBlockchainMeta {
  /// Get the distribution of RingCT outputs.
  ///
  /// `range` is in terms of block numbers. The result may be smaller than the requested range if
  /// the range starts before RingCT outputs were created on-chain.
  ///
  /// No validation of the distribution is performed.
  fn ringct_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>>;

  /// Get the specified RingCT outputs, but only return them if they're unlocked.
  ///
  /// No validation of the outputs is performed other than confirming the correct amount is
  /// returned.
  fn unlocked_ringct_outputs(
    &self,
    indexes: &[u64],
    evaluate_unlocked: EvaluateUnlocked,
  ) -> impl Send + Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>>;
}

/// Provides the necessary data to select decoys.
///
/// This SHOULD be satisfied by a local store to prevent attack by malicious remote nodes.
pub trait ProvidesDecoys: ProvidesBlockchainMeta {
  /// Get the distribution of RingCT outputs.
  ///
  /// `range` is in terms of block numbers. The result may be smaller than the requested range if
  /// the range starts before RingCT outputs were created on-chain.
  ///
  /// The distribution is checked to monotonically increase.
  fn ringct_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>>;

  /// Get the specified RingCT outputs, but only return them if they're unlocked.
  fn unlocked_ringct_outputs(
    &self,
    indexes: &[u64],
    evaluate_unlocked: EvaluateUnlocked,
  ) -> impl Send + Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>>;
}

impl<P: ProvidesUnvalidatedDecoys> ProvidesDecoys for P {
  fn ringct_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
    async move {
      let distribution =
        <P as ProvidesUnvalidatedDecoys>::ringct_output_distribution(self, range).await?;

      let mut monotonic = 0;
      for d in &distribution {
        if *d < monotonic {
          Err(InterfaceError::InvalidInterface(
            "received output distribution didn't increase monotonically".to_owned(),
          ))?;
        }
        monotonic = *d;
      }

      Ok(distribution)
    }
  }

  fn unlocked_ringct_outputs(
    &self,
    indexes: &[u64],
    evaluate_unlocked: EvaluateUnlocked,
  ) -> impl Send + Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>> {
    async move {
      let outputs =
        <P as ProvidesUnvalidatedDecoys>::unlocked_ringct_outputs(self, indexes, evaluate_unlocked)
          .await?;
      if outputs.len() != indexes.len() {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} outputs, expected {}",
          "ProvidesUnvalidatedDecoys::unlocked_ringct_outputs",
          outputs.len(),
          indexes.len(),
        )))?;
      }
      Ok(outputs)
    }
  }
}
