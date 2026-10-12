#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use sha3::Keccak256;

/// Re-export `sha3::Digest` so downstream crates can use `Keccak256::update(...)` without adding a
/// direct `sha3` dependency.
pub use sha3::Digest as KeccakDigest;

mod bounds;
pub use bounds::*;

/// The Keccak-256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  Keccak256::digest(data.as_ref()).into()
}

/// Create a Keccak-256 streaming hasher.
///
/// This is useful for allocation-free hashing when the input is naturally available in pieces
/// (for example, `"view_tag" || 8Ra || varint(o)` in wallet scanning).
#[inline]
pub fn keccak256_streaming() -> Keccak256 {
  Keccak256::new()
}

/// Finalize a Keccak-256 streaming hasher into a 32-byte digest.
///
/// This is a convenience wrapper around `finalize()` that returns a fixed-size array.
#[inline]
pub fn keccak256_finalize(hasher: Keccak256) -> [u8; 32] {
  hasher.finalize().into()
}
