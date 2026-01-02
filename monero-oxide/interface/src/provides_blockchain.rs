use core::{ops::RangeInclusive, future::Future};
use alloc::{borrow::ToOwned as _, format, vec::Vec};

use monero_oxide::block::Block;

use crate::{InterfaceError, ProvidesBlockchainMeta};

/// Provides the blockchain from an untrusted interface.
///
/// This provides some of its methods yet (`contiguous_blocks` || `block_by_number`) MUST be
/// overriden, and the batch  method SHOULD be overriden.
pub trait ProvidesUnvalidatedBlockchain: Sync + ProvidesBlockchainMeta {
  /// Get a contiguous range of blocks.
  ///
  /// No validation is applied to the received blocks other than that they deserialize and have the
  /// expected length.
  // This accepts a `RangeInclusive`, not a `impl RangeBounds`, to ensure the range is finite
  fn contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>> {
    async move {
      // If a caller requests an exorbitant amount of blocks, this may trigger an OOM kill
      // In order to maintain correctness, we have to attempt to service this request though
      let mut blocks =
        Vec::with_capacity(range.end().saturating_sub(*range.start()).saturating_add(1));
      for number in range {
        blocks.push(self.block_by_number(number).await?);
      }
      Ok(blocks)
    }
  }

  /* TODO
  /// Subscribe to blocks.
  fn subscribe(start: usize) ->
    impl Iterator<Item = Future<Output = Result<Block, InterfaceError>>> {}
  */

  /// Get a block by its hash.
  ///
  /// No validation is applied to the received block other than that it deserializes.
  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>>;

  /// Get a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  ///
  /// No validation is applied to the received blocks other than that it deserializes.
  fn block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      let mut blocks = self.contiguous_blocks(number ..= number).await?;
      if blocks.len() != 1 {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::contiguous_blocks",
          blocks.len(),
          1,
        )))?;
      }
      Ok(blocks.pop().expect("verified we had a block"))
    }
  }

  /// Get the hash of a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  fn block_hash(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<[u8; 32], InterfaceError>>;
}

/// Provides blocks which have been sanity-checked.
pub trait ProvidesBlockchain: ProvidesBlockchainMeta {
  /// Get a contiguous range of blocks.
  ///
  /// The blocks will be validated to build upon each other, as expected, and have the expected
  /// numbers.
  fn contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>>;

  /// Get a block by its hash.
  ///
  /// The block will be validated to be the requested block.
  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>>;

  /// Get a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  ///
  /// The block will be validated to be a block with the requested number.
  fn block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, InterfaceError>>;

  /// Get the hash of a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  fn block_hash(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<[u8; 32], InterfaceError>>;
}

#[expect(single_use_lifetimes)] // False positive, this can't be removed
pub(crate) fn sanity_check_contiguous_blocks<'block>(
  range: RangeInclusive<usize>,
  blocks: impl Iterator<Item = &'block Block>,
) -> Result<(), InterfaceError> {
  let mut parent = None;
  for (number, block) in range.zip(blocks) {
    if block.number() != number {
      Err(InterfaceError::InvalidInterface(format!(
        "requested block #{number}, received #{}",
        block.number()
      )))?;
    }

    let block_hash = block.hash();
    if let Some(parent) = parent.or((number == 0).then_some([0; 32])) {
      if parent != block.header.previous {
        Err(InterfaceError::InvalidInterface(
          "
            interface returned a block which doesn't build on the prior block \
            when requesting a contiguous series
          "
          .to_owned(),
        ))?;
      }
    }
    parent = Some(block_hash);
  }
  Ok(())
}

pub(crate) fn sanity_check_block_by_hash(
  hash: &[u8; 32],
  block: &Block,
) -> Result<(), InterfaceError> {
  let actual_hash = block.hash();
  if &actual_hash != hash {
    Err(InterfaceError::InvalidInterface(format!(
      "requested block {}, received {}",
      hex::encode(hash),
      hex::encode(actual_hash)
    )))?;
  }

  Ok(())
}

pub(crate) fn sanity_check_block_by_number(
  number: usize,
  block: &Block,
) -> Result<(), InterfaceError> {
  if block.number() != number {
    Err(InterfaceError::InvalidInterface(format!(
      "requested block #{number}, received #{}",
      block.number()
    )))?;
  }
  Ok(())
}

impl<P: ProvidesUnvalidatedBlockchain> ProvidesBlockchain for P {
  fn contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>> {
    async move {
      let blocks =
        <P as ProvidesUnvalidatedBlockchain>::contiguous_blocks(self, range.clone()).await?;
      let expected_blocks =
        range.end().saturating_sub(*range.start()).checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError(
            "amount of blocks requested wasn't representable in a `usize`".to_owned(),
          )
        })?;
      if blocks.len() != expected_blocks {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::contiguous_blocks",
          blocks.len(),
          expected_blocks,
        )))?;
      }
      sanity_check_contiguous_blocks(range, blocks.iter())?;
      Ok(blocks)
    }
  }

  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      let block = <P as ProvidesUnvalidatedBlockchain>::block(self, hash).await?;
      sanity_check_block_by_hash(&hash, &block)?;
      Ok(block)
    }
  }

  fn block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      let block = <P as ProvidesUnvalidatedBlockchain>::block_by_number(self, number).await?;
      sanity_check_block_by_number(number, &block)?;
      Ok(block)
    }
  }

  fn block_hash(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<[u8; 32], InterfaceError>> {
    <P as ProvidesUnvalidatedBlockchain>::block_hash(self, number)
  }
}
