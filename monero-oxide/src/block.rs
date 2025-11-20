use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use crate::{
  io::*,
  primitives::keccak256,
  merkle::merkle_root,
  transaction::{Input, Transaction},
};

pub(crate) const CORRECT_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("426d16cff04c71f8b16340b722dc4010a2dd3831c22041431f772547ba6e331a");
pub(crate) const EXISTING_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698");

/// A Monero block's header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
  /// The hard fork of the protocol this block follows.
  ///
  /// Per the C++ codebase, this is the `major_version`.
  pub hardfork_version: u8,
  /// A signal for a proposed hard fork.
  ///
  /// Per the C++ codebase, this is the `minor_version`.
  pub hardfork_signal: u8,
  /// Seconds since the epoch.
  pub timestamp: u64,
  /// The previous block's hash.
  pub previous: [u8; 32],
  /// The nonce used to mine the block.
  ///
  /// Miners should increment this while attempting to find a block with a hash satisfying the PoW
  /// rules.
  pub nonce: u32,
}

impl BlockHeader {
  /// Write the BlockHeader.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    VarInt::write(&self.hardfork_version, w)?;
    VarInt::write(&self.hardfork_signal, w)?;
    VarInt::write(&self.timestamp, w)?;
    w.write_all(&self.previous)?;
    w.write_all(&self.nonce.to_le_bytes())
  }

  /// Serialize the BlockHeader to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  /// Read a BlockHeader.
  pub fn read<R: Read>(r: &mut R) -> io::Result<BlockHeader> {
    Ok(BlockHeader {
      hardfork_version: VarInt::read(r)?,
      hardfork_signal: VarInt::read(r)?,
      timestamp: VarInt::read(r)?,
      previous: read_bytes(r)?,
      nonce: read_bytes(r).map(u32::from_le_bytes)?,
    })
  }
}

/// A Monero block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
  /// The block's header.
  pub header: BlockHeader,
  /// The miner's transaction.
  miner_transaction: Transaction,
  /// The transactions within this block.
  pub transactions: Vec<[u8; 32]>,
}

impl Block {
  /// The maximum amount of transactions a block may have, including the miner transaction.
  /*
    Definition of maximum amount of transaction:
    https://github.com/monero-project/monero
      /blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/src/cryptonote_config.h#L42

    Limitation of the amount of transactions within the `transactions` field:
    https://github.com/monero-project/monero
      /blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/src/cryptonote_basic/cryptonote_basic.h#L571

    This would mean the actual limit is `0x10000000 + 1`, including the miner transaction, except:
    https://github.com/monero-project/monero
      /blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/src/crypto/tree-hash.c#L55

    calculation of the Merkle tree representing all transactions will fail if this many
    transactions is consumed by the `transactions` field alone.
  */
  pub const MAX_TRANSACTIONS: usize = 0x10000000;

  /// Construct a new `Block`.
  ///
  /// This MAY apply miscellaneous consensus rules as useful for the sanity of working with this
  /// type. The result is not guaranteed to follow all Monero consensus rules or any specific set
  /// of consensus rules.
  pub fn new(
    header: BlockHeader,
    miner_transaction: Transaction,
    transactions: Vec<[u8; 32]>,
  ) -> Option<Block> {
    // Check this correctly defines the block's number
    // https://github.com/monero-project/monero/blob/a1dc85c5373a30f14aaf7dcfdd95f5a7375d3623
    //   /src/cryptonote_core/blockchain.cpp#L1365-L1382
    {
      let inputs = &miner_transaction.prefix().inputs;
      if inputs.len() != 1 {
        None?;
      }
      match inputs[0] {
        Input::Gen(_number) => {}
        _ => None?,
      }
    }

    Some(Block { header, miner_transaction, transactions })
  }

  /// The zero-indexed position of this block within the blockchain.
  pub fn number(&self) -> usize {
    match &self.miner_transaction {
      Transaction::V1 { prefix, .. } | Transaction::V2 { prefix, .. } => {
        match prefix.inputs.first() {
          Some(Input::Gen(number)) => *number,
          _ => panic!("invalid miner transaction accepted into block"),
        }
      }
    }
  }

  /// The block's miner's transaction.
  pub fn miner_transaction(&self) -> &Transaction {
    &self.miner_transaction
  }

  /// Write the Block.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.header.write(w)?;
    self.miner_transaction.write(w)?;
    VarInt::write(&self.transactions.len(), w)?;
    for tx in &self.transactions {
      w.write_all(tx)?;
    }
    Ok(())
  }

  /// Serialize the Block to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  /// Serialize the block as generally required for the proof of work hash.
  ///
  /// This is distinct from the serialization required for the block hash. To get the block hash,
  /// use the [`Block::hash`] function.
  ///
  /// Please note that for block #202,612, regardless of the network, the proof of work hash will
  /// be fixed to a specific value and this preimage will be irrelevant.
  pub fn serialize_pow_hash(&self) -> Vec<u8> {
    let mut blob = self.header.serialize();

    let mut transactions = Vec::with_capacity(self.transactions.len() + 1);
    transactions.push(self.miner_transaction.hash());
    transactions.extend_from_slice(&self.transactions);

    blob.extend_from_slice(
      &merkle_root(transactions)
        .expect("the tree will not be empty, the miner tx is always present"),
    );
    VarInt::write(&(1 + self.transactions.len()), &mut blob)
      .expect("write failed but <Vec as io::Write> doesn't fail");
    blob
  }

  /// Get the hash of this block.
  pub fn hash(&self) -> [u8; 32] {
    let mut hashable = self.serialize_pow_hash();
    // Monero pre-appends a VarInt of the block-to-hash's length before getting the block hash,
    // but doesn't do this when getting the proof of work hash :)
    let mut hashing_blob = Vec::with_capacity(<usize as VarInt>::UPPER_BOUND + hashable.len());
    VarInt::write(
      &u64::try_from(hashable.len()).expect("length of block hash's preimage exceeded u64::MAX"),
      &mut hashing_blob,
    )
    .expect("write failed but <Vec as io::Write> doesn't fail");
    hashing_blob.append(&mut hashable);

    let hash = keccak256(hashing_blob);
    // https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
    //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L1468-L1477
    if hash == CORRECT_BLOCK_HASH_202612 {
      return EXISTING_BLOCK_HASH_202612;
    };
    hash
  }

  /// Read a Block.
  ///
  /// This MAY error if miscellaneous Monero conseusus rules are broken, as useful when
  /// deserializing. The result is not guaranteed to follow all Monero consensus rules or any
  /// specific set of consensus rules.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Block> {
    let header = BlockHeader::read(r)?;

    let miner_transaction = Transaction::read(r)?;

    let transactions: usize = VarInt::read(r)?;
    if transactions >= Self::MAX_TRANSACTIONS {
      Err(io::Error::other("amount of transaction exceeds limit"))?;
    }
    let transactions = (0 .. transactions).map(|_| read_bytes(r)).collect::<Result<_, _>>()?;

    Block::new(header, miner_transaction, transactions)
      .ok_or_else(|| io::Error::other("block failed sanity checks"))
  }
}
