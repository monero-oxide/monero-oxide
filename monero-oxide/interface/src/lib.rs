#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;

extern crate alloc;
use alloc::string::String;

mod provides_blockchain_meta;
pub use provides_blockchain_meta::*;

mod provides_transactions;
pub use provides_transactions::*;

pub(crate) mod provides_blockchain;
pub use provides_blockchain::{ProvidesUnvalidatedBlockchain, ProvidesBlockchain};

mod provides_outputs;
pub use provides_outputs::*;

mod provides_scannable_blocks;
pub use provides_scannable_blocks::*;

mod provides_decoys;
pub use provides_decoys::*;

mod provides_fee_rates;
pub use provides_fee_rates::*;

/// An error from the interface.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum InterfaceError {
  /// An internal error.
  #[error("internal error ({0})")]
  InternalError(String),
  /// An error with the interface.
  #[error("interface error ({0})")]
  InterfaceError(String),
  /// The interface is invalid per the expected protocol and should be disconnected from.
  #[error("invalid node ({0})")]
  InvalidInterface(String),
}

/// A prelude of recommended imports to glob import.
pub mod prelude {
  pub use crate::{
    InterfaceError, ProvidesBlockchainMeta, TransactionsError, ProvidesTransactions,
    PublishTransactionError, PublishTransaction, ProvidesBlockchain, ProvidesOutputs,
    ScannableBlock, ExpandToScannableBlock, ProvidesScannableBlocks, EvaluateUnlocked,
    ProvidesDecoys, FeePriority, FeeRate, FeeError, ProvidesFeeRates,
  };
}
