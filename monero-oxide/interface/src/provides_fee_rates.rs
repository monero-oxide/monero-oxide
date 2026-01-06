use core::future::Future;
use alloc::vec::Vec;
use std_shims::io;

use zeroize::Zeroize;

use monero_oxide::io::read_u64;

use crate::InterfaceError;

/// The priority for the fee.
///
/// Higher-priority transactions will be included in blocks earlier.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum FeePriority {
  /// The `Unimportant` priority, as defined by Monero.
  Unimportant,
  /// The `Normal` priority, as defined by Monero.
  Normal,
  /// The `Elevated` priority, as defined by Monero.
  Elevated,
  /// The `Priority` priority, as defined by Monero.
  Priority,
  /// A custom priority.
  Custom {
    /// The numeric representation of the priority, as used within the RPC.
    priority: u32,
  },
}

/// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
///   src/simplewallet/simplewallet.cpp#L161
impl FeePriority {
  /// The `u32` representation of this fee.
  pub fn to_u32(&self) -> u32 {
    match self {
      FeePriority::Unimportant => 1,
      FeePriority::Normal => 2,
      FeePriority::Elevated => 3,
      FeePriority::Priority => 4,
      FeePriority::Custom { priority, .. } => *priority,
    }
  }
}

/// A struct containing a fee rate.
///
/// The fee rate is defined as a per-weight cost, along with a mask for rounding purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct FeeRate {
  /// The fee per-weight of the transaction.
  per_weight: u64,
  /// The mask to round with.
  mask: u64,
}

impl FeeRate {
  /// Construct a new fee rate.
  ///
  /// Returns `None` if the fee rate is invalid.
  pub fn new(per_weight: u64, mask: u64) -> Option<FeeRate> {
    if (per_weight == 0) || (mask == 0) {
      None?;
    }
    Some(FeeRate { per_weight, mask })
  }

  /// Write the FeeRate.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn write(&self, w: &mut impl io::Write) -> io::Result<()> {
    w.write_all(&self.per_weight.to_le_bytes())?;
    w.write_all(&self.mask.to_le_bytes())
  }

  /// Serialize the FeeRate to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(16);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// The fee to pay per weight.
  pub fn per_weight(&self) -> u64 {
    self.per_weight
  }

  /// Read a FeeRate.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn read(r: &mut impl io::Read) -> io::Result<FeeRate> {
    let per_weight = read_u64(r)?;
    let mask = read_u64(r)?;
    FeeRate::new(per_weight, mask).ok_or_else(|| io::Error::other("fee rate was invalid"))
  }

  /// Calculate the fee to use from the weight.
  ///
  /// This function may panic upon overflow.
  pub fn calculate_fee_from_weight(&self, weight: usize) -> u64 {
    let fee =
      self.per_weight * u64::try_from(weight).expect("couldn't convert weight (usize) to u64");
    fee.div_ceil(self.mask) * self.mask
  }

  /// Calculate the weight from the fee.
  ///
  /// Returns `None` if the weight would not fit within a `usize`.
  pub fn calculate_weight_from_fee(&self, fee: u64) -> Option<usize> {
    usize::try_from(fee / self.per_weight).ok()
  }
}

/// An error from the interface.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FeeError {
  /// Error with the interface.
  #[error("interface error ({0})")]
  InterfaceError(InterfaceError),
  /// The fee was invalid.
  #[error("invalid fee")]
  InvalidFee,
  /// The fee priority was invalid.
  #[error("invalid fee priority")]
  InvalidFeePriority,
}

impl From<InterfaceError> for FeeError {
  fn from(err: InterfaceError) -> Self {
    Self::InterfaceError(err)
  }
}

/// An interface which provides unvalidated fee rates.
pub trait ProvidesUnvalidatedFeeRates: Sync {
  /// Get the recommended fee rate.
  ///
  /// This may be manipulated to unsafe levels and MUST be sanity checked.
  ///
  /// This MUST NOT be expected to be deterministic in any way.
  fn fee_rate(
    &self,
    priority: FeePriority,
  ) -> impl Send + Future<Output = Result<FeeRate, FeeError>>;
}

/// An interface which provides fee rates.
pub trait ProvidesFeeRates: Sync {
  /// Get the recommended fee rate.
  ///
  /// This MUST NOT be expected to be deterministic in any way.
  fn fee_rate(
    &self,
    priority: FeePriority,
    max_per_weight: u64,
  ) -> impl Send + Future<Output = Result<FeeRate, FeeError>>;
}

impl<P: ProvidesUnvalidatedFeeRates> ProvidesFeeRates for P {
  fn fee_rate(
    &self,
    priority: FeePriority,
    max_per_weight: u64,
  ) -> impl Send + Future<Output = Result<FeeRate, FeeError>> {
    async move {
      let fee_rate = <P as ProvidesUnvalidatedFeeRates>::fee_rate(self, priority).await?;
      if fee_rate.per_weight > max_per_weight {
        Err(FeeError::InvalidFee)?;
      }
      Ok(fee_rate)
    }
  }
}
