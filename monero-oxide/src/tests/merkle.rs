use std_shims::vec::Vec;

use rand_core::{RngCore, OsRng};

use crate::{primitives::keccak256, merkle::merkle_root};

fn old_merkle_root(mut leafs: Vec<[u8; 32]>) -> Option<[u8; 32]> {
  match leafs.len() {
    0 => None,
    1 => Some(leafs[0]),
    2 => Some(keccak256([leafs[0], leafs[1]].concat())),
    _ => {
      // Monero preprocess this so the length is a power of 2
      let mut high_pow_2 = 4; // 4 is the lowest value this can be
      while high_pow_2 < leafs.len() {
        high_pow_2 *= 2;
      }
      let low_pow_2 = high_pow_2 / 2;

      // Merge right-most hashes until we're at the low_pow_2
      {
        let overage = leafs.len() - low_pow_2;
        let mut rightmost = leafs.drain((low_pow_2 - overage) ..);
        // This is true since we took overage from beneath and above low_pow_2, taking twice as
        // many elements as overage
        debug_assert_eq!(rightmost.len() % 2, 0);

        let mut paired_hashes = Vec::with_capacity(overage);
        while let Some(left) = rightmost.next() {
          let right = rightmost.next().expect("rightmost is of even length");
          paired_hashes.push(keccak256([left, right].concat()));
        }
        drop(rightmost);

        leafs.extend(paired_hashes);
        assert_eq!(leafs.len(), low_pow_2);
      }

      // Do a traditional pairing off
      let mut new_hashes = Vec::with_capacity(leafs.len() / 2);
      while leafs.len() > 1 {
        let mut i = 0;
        while i < leafs.len() {
          new_hashes.push(keccak256([leafs[i], leafs[i + 1]].concat()));
          i += 2;
        }

        leafs = new_hashes;
        new_hashes = Vec::with_capacity(leafs.len() / 2);
      }
      Some(leafs[0])
    }
  }
}

#[test]
fn merkle() {
  assert!(old_merkle_root(vec![]).is_none());
  assert!(merkle_root(&mut []).is_none());

  for i in 1 .. 513 {
    let mut leaves = Vec::with_capacity(i);
    for _ in 0 .. i {
      let mut leaf = [0; 32];
      OsRng.fill_bytes(&mut leaf);
      leaves.push(leaf);
    }

    let old = old_merkle_root(leaves.clone()).unwrap();
    let new = merkle_root(leaves).unwrap();
    assert_eq!(old, new);
  }
}

/*
  Monero's Merkle tree code historically had a bug in it where it would produce an incorrect tree
  hash. Unfortunately, this condition arose on the Monero mainnet, with the decision being made to
  preserve the erroneously computed hash, defining it as the hash for block 202,612, as the path of
  least harm.

  This test computes the _correct_ hash for block 202,612 (in theory), verifying it against the
  constant we've declared. Then, it demonstrates the preimage for the _incorrect_ hash which was
  made the definitive hash via updating the consensus rules. This lets us discuss the impacts of
  this decision.

  Notably, there are not two known preimages for which the `Block::hash` function will output the
  same hash. This is because both preimages specify themselves as having _514_ transactions
  (including the miner transaction). Then, the erroneous hash truncates the last two transactions'
  hashes from inclusion in the preimage.

  Because it's impossible for any block to include 514 transactions yet only 512 hashes, except for
  the special case in front of us, it's impossible for the defined hash to be reached by a distinct
  block _without a collision in the Keccak-256 hash function itself_.

  It should be noted that the defined block hash _does not bind_ to the last two transactions in
  the block due to truncating their hashes. Thankfully, the block still claims to have so many
  transactions, preventing replacing the block with 514 transactions with a block with 512
  transactions. Unfortunately, those last two transactions may be assigned any value, which is why
  checking the blob has the technically correct hash is critical before returning the defined hash.

  To learn more, please refer to
  https://web.getmonero.org/resources/research-lab/pubs/MRL-0002.pdf.
*/
#[test]
fn block_202612() {
  use monero_io::VarInt;
  use crate::block::{BlockHeader, CORRECT_BLOCK_HASH_202612, EXISTING_BLOCK_HASH_202612};

  let header = BlockHeader {
    hardfork_version: 1,
    hardfork_signal: 0,
    previous: hex::decode("5da0a3d004c352a90cc86b00fab676695d76a4d1de16036c41ba4dd188c4d76f")
      .unwrap()
      .try_into()
      .unwrap(),
    timestamp: 1409804570,
    nonce: 1073744198,
  };

  // The list of transactions present in block 202,612
  let mut transactions = include!("./block_202612_transactions.txt")
    .into_iter()
    .map(|hash| <[u8; 32]>::try_from(hex::decode(hash).unwrap()).unwrap())
    .collect::<Vec<_>>();

  let mut blob = header.serialize();
  blob.extend_from_slice(&merkle_root(transactions.clone()).unwrap());
  VarInt::write(&transactions.len(), &mut blob).unwrap();
  let mut complete = vec![];
  VarInt::write(&blob.len(), &mut complete).unwrap();
  complete.extend_from_slice(&blob);
  assert_eq!(keccak256(complete), CORRECT_BLOCK_HASH_202612);

  let mut blob = header.serialize();
  blob.extend_from_slice(&merkle_root(&mut transactions[.. 512]).unwrap());
  VarInt::write(&transactions.len(), &mut blob).unwrap();
  let mut complete = vec![];
  VarInt::write(&blob.len(), &mut complete).unwrap();
  complete.extend_from_slice(&blob);
  assert_eq!(keccak256(complete), EXISTING_BLOCK_HASH_202612);
}
