use crate::primitives::keccak256;

/// Calculates the Merkle root for the given leaves.
///
/// Equivalent to `tree_hash` in monero-core:
/// https://github.com/monero-project/monero/blob/893916ad091a92e765ce3241b94e706ad012b62a
///   /src/crypto/tree-hash.c#L62
///
/// Monero's Merkle trees have two notable properties:
///  1) Merkle trees are unbalanced, causing each leaf to only be included once with a unique
///     index, without introducing padding.
///  2) The leaves of a Merkle tree are not distinguished from its branches. This would allow
///     proving a branch as a leaf, or claiming a leaf is a branch. In order to safely perform
///     proofs with a tree's root, the amount of leaves within the Merkle tree MUST be known.
///     Thankfully, Monero uses this to commit to the transactions within a block when calculating
///     its hash, and the amount of transactions is additionally committed to. Alternatively, one
///     could assume every valid transaction's serialization will be longer than 64 bytes.
///
/// This function accepts a mutable slice for the leaves, using it as scratch space for the
/// computation of the leaves. The value of this scratch space is undefined after the operation
/// completes.
///
/// This function returns [`None`] if the tree is empty and [`Some`] otherwise.
pub fn merkle_root(mut leaves: impl AsMut<[[u8; 32]]>) -> Option<[u8; 32]> {
  let mut leaves = leaves.as_mut();

  let mut pair_buf = [0; 64];
  let mut pair = |left: &[u8; 32], right: &[u8; 32]| {
    pair_buf[.. 32].copy_from_slice(left);
    pair_buf[32 ..].copy_from_slice(right);
    keccak256(pair_buf)
  };

  match leaves.len() {
    0 => None,
    1 => Some(leaves[0]),
    2 => Some(pair(&leaves[0], &leaves[1])),
    _ => {
      // First, we find the first power of two less than or equal to the amount of leaves
      let mut low_pow_2 = {
        let highest_bit_set = usize::BITS - leaves.len().leading_zeros();
        // This won't underflow as we know _a_ bit is set
        1 << (highest_bit_set - 1)
      };

      while leaves.len() != 1 {
        /*
          If the amount of leaves is a power of two, reduce to the next power of two (where "next"
          is defined as "next smaller").

          This condition will only be false for the first iteration, if the amount of leaves input
          isn't a power of two. Then, `low_pow_2` will already be the next power of two to reduce
          to.
        */
        if leaves.len() == low_pow_2 {
          low_pow_2 >>= 1;
        }

        // How many leaves we have to pair off in order to reduce to the next power of two
        let overage = leaves.len() - low_pow_2;
        // This choice of `start` means `leaves[start ..].len() == (2 * overage)`
        let start = low_pow_2 - overage;
        for i in 0 .. overage {
          // Take the next pair of leaves
          let left = leaves[start + (2 * i)];
          let right = leaves[start + (2 * i) + 1];
          // Write the branch to its new index
          leaves[start + i] = pair(&left, &right);
        }
        // Truncate now that we've performed the initial pairing off
        leaves = &mut leaves[.. low_pow_2];
      }

      Some(leaves[0])
    }
  }
}
