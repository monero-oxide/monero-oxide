use core::future::Future;
use alloc::{format, vec, vec::Vec, string::String};

use monero_oxide::transaction::{Pruned, Transaction};

use crate::InterfaceError;

/// A pruned transaction with the hash of its pruned data, if `version != 1`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrunedTransactionWithPrunableHash {
  transaction: Transaction<Pruned>,
  prunable_hash: Option<[u8; 32]>,
}

impl PrunedTransactionWithPrunableHash {
  /// Create a new `PrunedTransactionWithPrunableHash`.
  ///
  /// This expects `(version != 1) == (prunable_hash = Some(_))` and returns `None` otherwise.
  pub fn new(
    transaction: Transaction<Pruned>,
    mut prunable_hash: Option<[u8; 32]>,
  ) -> Option<Self> {
    match &transaction {
      Transaction::V1 { .. } => {
        if prunable_hash.is_some() {
          None?;
        }
      }
      Transaction::V2 { proofs, .. } => {
        if prunable_hash.is_none() {
          None?;
        }
        if proofs.is_none() {
          prunable_hash = Some([0; 32]);
        }
      }
    }
    Some(Self { transaction, prunable_hash })
  }

  /// Verify the transaction has the expected hash, if possible.
  ///
  /// This only works for transaction where `version != 1`. Transactions where `version = 1` will
  /// be returned without any verification.
  ///
  /// If verification fails, the actual hash of the transaction is returned as the error.
  pub fn verify_as_possible(self, hash: [u8; 32]) -> Result<Transaction<Pruned>, [u8; 32]> {
    if let Some(prunable_hash) = self.prunable_hash {
      let actual_hash = self
        .transaction
        .hash_with_prunable_hash(prunable_hash)
        .expect("couldn't hash with prunable hash despite prior ensuring presence was as expected");
      if actual_hash != hash {
        Err(actual_hash)?;
      }
    }
    Ok(self.transaction)
  }
}

impl AsRef<Transaction<Pruned>> for PrunedTransactionWithPrunableHash {
  fn as_ref(&self) -> &Transaction<Pruned> {
    &self.transaction
  }
}

/// An error when fetching transactions.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TransactionsError {
  /// Error with the interface.
  #[error("interface error ({0})")]
  InterfaceError(InterfaceError),
  /// A transaction wasn't found.
  #[error("transaction wasn't found")]
  TransactionNotFound,
  /// A transaction expected to not be pruned was pruned.
  #[error("transaction was unexpectedly pruned")]
  PrunedTransaction,
}

impl From<InterfaceError> for TransactionsError {
  fn from(err: InterfaceError) -> Self {
    Self::InterfaceError(err)
  }
}

/// Provides unvalidated transactions from an untrusted interface.
///
/// This provides all its methods yet (`transactions` || `transaction`) &&
/// (`pruned_transactions` || `pruned_transaction`) MUST be overriden, ideally the batch
/// methods.
#[rustfmt::skip]
pub trait ProvidesUnvalidatedTransactions: Sync {
  /// Get transactions.
  ///
  /// This returns the correct amount of transactions, deserialized, without further validation.
  fn transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, TransactionsError>> {
    async move {
      let mut txs = Vec::with_capacity(hashes.len());
      for hash in hashes {
        txs.push(self.transaction(*hash).await?);
      }
      Ok(txs)
    }
  }

  /// Get pruned transactions.
  ///
  /// This returns the correct amount of transactions, deserialized, without further validation.
  fn pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<PrunedTransactionWithPrunableHash>, TransactionsError>>
  {
    async move {
      let mut txs = Vec::with_capacity(hashes.len());
      for hash in hashes {
        txs.push(self.pruned_transaction(*hash).await?);
      }
      Ok(txs)
    }
  }

  /// Get a transaction.
  fn transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, TransactionsError>> {
    async move {
      let mut txs = self.transactions(&[hash]).await?;
      if txs.len() != 1 {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} transactions, expected {}",
          "ProvidesUnvalidatedTransactions::transactions",
          txs.len(),
          1,
        )))?;
      }
      Ok(txs.pop().expect("verified we had a transaction"))
    }
  }

  /// Get a pruned transaction.
  fn pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<PrunedTransactionWithPrunableHash, TransactionsError>> {
    async move {
      let mut txs = self.pruned_transactions(&[hash]).await?;
      if txs.len() != 1 {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} transactions, expected {}",
          "ProvidesUnvalidatedTransactions::pruned_transactions",
          txs.len(),
          1,
        )))?;
      }
      Ok(txs.pop().expect("verified we had a pruned transaction"))
    }
  }
}

/// Provides transactions which have been sanity-checked.
pub trait ProvidesTransactions: Sync {
  /// Get transactions.
  ///
  /// This returns all of the requested deserialized transactions, ensuring they're the requested
  /// transactions.
  fn transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, TransactionsError>>;

  /// Get pruned transactions.
  ///
  /// This returns all of the requested deserialized transactions, ensuring they're the requested
  /// transactions. For transactions where `version == 1`, this may additionally request the
  /// non-pruned transactions.
  fn pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction<Pruned>>, TransactionsError>>;

  /// Get a transaction.
  ///
  /// This returns the requested transaction, ensuring it is the requested transaction.
  fn transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, TransactionsError>>;

  /// Get a pruned transaction.
  ///
  /// This returns the requested transaction, ensuring it is the requested transaction. For
  /// transactions where `version == 1`, this may additionally request the non-pruned transactions.
  fn pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction<Pruned>, TransactionsError>>;
}

pub(crate) async fn validate_pruned_transactions<P: ProvidesTransactions>(
  interface: &P,
  unvalidated: Vec<PrunedTransactionWithPrunableHash>,
  hashes: &[[u8; 32]],
) -> Result<Vec<Transaction<Pruned>>, TransactionsError> {
  if unvalidated.len() != hashes.len() {
    Err(InterfaceError::InternalError(format!(
      "`{}` returned {} transactions, expected {}",
      "ProvidesUnvalidatedTransactions::pruned_transactions",
      unvalidated.len(),
      hashes.len(),
    )))?;
  }

  let mut txs = Vec::with_capacity(unvalidated.len());
  let mut v1_indexes = vec![];
  let mut v1_hashes = vec![];
  for (tx, expected_hash) in unvalidated.into_iter().zip(hashes) {
    match tx.verify_as_possible(*expected_hash) {
      Ok(tx) => {
        if matches!(tx, Transaction::V1 { .. }) {
          v1_indexes.push(txs.len());
          v1_hashes.push(*expected_hash);
        }
        txs.push(tx);
      }
      Err(hash) => Err(InterfaceError::InvalidInterface(format!(
        "interface returned TX {} when {} was requested",
        hex::encode(hash),
        hex::encode(expected_hash)
      )))?,
    }
  }

  if !v1_indexes.is_empty() {
    let full_txs = <P as ProvidesTransactions>::transactions(interface, &v1_hashes).await?;
    for ((pruned_tx, hash), tx) in
      v1_indexes.into_iter().map(|i| &txs[i]).zip(v1_hashes).zip(full_txs)
    {
      if &Transaction::<Pruned>::from(tx) != pruned_tx {
        Err(InterfaceError::InvalidInterface(format!(
          "interface returned pruned V1 TX which didn't match TX {}",
          hex::encode(hash)
        )))?;
      }
    }
  }

  Ok(txs)
}

impl<P: ProvidesUnvalidatedTransactions> ProvidesTransactions for P {
  fn transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, TransactionsError>> {
    async move {
      let txs = <P as ProvidesUnvalidatedTransactions>::transactions(self, hashes).await?;
      if txs.len() != hashes.len() {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} transactions, expected {}",
          "ProvidesUnvalidatedTransactions::transactions",
          txs.len(),
          hashes.len(),
        )))?;
      }

      for (tx, expected_hash) in txs.iter().zip(hashes) {
        let hash = tx.hash();
        if &hash != expected_hash {
          Err(InterfaceError::InvalidInterface(format!(
            "interface returned TX {} when {} was requested",
            hex::encode(hash),
            hex::encode(expected_hash)
          )))?;
        }
      }
      Ok(txs)
    }
  }

  fn pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction<Pruned>>, TransactionsError>> {
    async move {
      let unvalidated =
        <P as ProvidesUnvalidatedTransactions>::pruned_transactions(self, hashes).await?;
      validate_pruned_transactions(self, unvalidated, hashes).await
    }
  }

  fn transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, TransactionsError>> {
    async move {
      let tx = <P as ProvidesUnvalidatedTransactions>::transaction(self, hash).await?;
      let actual_hash = tx.hash();
      if actual_hash != hash {
        Err(InterfaceError::InvalidInterface(format!(
          "interface returned TX {} when {} was requested",
          hex::encode(actual_hash),
          hex::encode(hash)
        )))?;
      }
      Ok(tx)
    }
  }

  fn pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction<Pruned>, TransactionsError>> {
    async move {
      let unvalidated =
        <P as ProvidesUnvalidatedTransactions>::pruned_transaction(self, hash).await?;
      Ok(validate_pruned_transactions(self, vec![unvalidated], &[hash]).await?.swap_remove(0))
    }
  }
}

/// An error from the interface.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum PublishTransactionError {
  /// Error with the interface.
  #[error("interface error ({0})")]
  InterfaceError(InterfaceError),
  /// The transaction was rejected.
  #[error("transaction was rejected ({0})")]
  TransactionRejected(String),
}

impl From<InterfaceError> for PublishTransactionError {
  fn from(err: InterfaceError) -> Self {
    Self::InterfaceError(err)
  }
}

/// An interface eligible to publish transactions over.
pub trait PublishTransaction: Sync {
  /// Publish a transaction.
  fn publish_transaction(
    &self,
    transaction: &Transaction,
  ) -> impl Send + Future<Output = Result<(), PublishTransactionError>>;
}
