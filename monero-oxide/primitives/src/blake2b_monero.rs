/*
  A specialization of Blake2b that is compatible with the CARROT hash functions.

  CARROT uses Blake2b with the personal string "Monero" and a zeroed salt. If
  there is a key, it is always 32 bytes. If there is no key, then no key
  block is included in the hash data. This contrasts with the [`blake2::Blake2bMac512`]
  implementation where key blocks are always included whenever a personal string
  is set, even if the key is zero-length.

  The [`blake2::Blake2bMac512`] impl is also restricted to 64-byte outputs, whereas
  the CARROT hash function include smaller output options.
*/

use core::fmt;
use blake2::{
  digest::{
    typenum::Unsigned as _,
    generic_array::GenericArray,
    block_buffer::{Block, LazyBuffer},
    core_api::{BlockSizeUser, UpdateCore as _, VariableOutputCore as _},
    OutputSizeUser, Update,
  },
  Blake2bVarCore,
};
use dalek_ff_group::Scalar;

/// Blake2b specialization for Monero.
///
/// - Salt: zero
/// - Personal string: "Monero"
/// - Key: 32 bytes OR null (no key block included when null)
/// - Output Length: 1-64 bytes (this value is embedded in the parameters block but otherwise does
///   not affect the algorithm)
#[doc(hidden)]
#[derive(Clone)]
pub struct Blake2bMonero<const OUTPUT_SIZE: usize> {
  core: Blake2bVarCore,
  buffer: LazyBuffer<<Blake2bVarCore as BlockSizeUser>::BlockSize>,
}

const PERSONAL: &[u8] = b"Monero";

impl<const OUTPUT_SIZE: usize> Blake2bMonero<OUTPUT_SIZE> {
  /// Create a new instance.
  ///
  /// Does *not* include a key block. See [`Self::new_with_key`],
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    const {
      assert!(1 <= OUTPUT_SIZE);
      assert!(OUTPUT_SIZE <= <Blake2bVarCore as OutputSizeUser>::OutputSize::USIZE);
    }

    Self {
      core: Blake2bVarCore::new_with_params(&[], PERSONAL, 0, OUTPUT_SIZE),
      buffer: LazyBuffer::default(),
    }
  }

  /// Create a new instance using the provided 32-byte key.
  pub fn new_with_key(key: &[u8; 32]) -> Self {
    const {
      assert!(32 <= <Blake2bVarCore as BlockSizeUser>::BlockSize::USIZE);
      assert!(1 <= OUTPUT_SIZE);
      assert!(OUTPUT_SIZE <= <Blake2bVarCore as OutputSizeUser>::OutputSize::USIZE);
    }

    let mut padded_key = Block::<<Blake2bVarCore as BlockSizeUser>::BlockSize>::default();
    padded_key[.. key.len()].copy_from_slice(key);
    Self {
      core: Blake2bVarCore::new_with_params(&[], PERSONAL, key.len(), OUTPUT_SIZE),
      buffer: LazyBuffer::new(&padded_key),
    }
  }

  /// Finalize the hash.
  pub fn finalize(self) -> [u8; OUTPUT_SIZE] {
    let Self { mut core, mut buffer } = self;

    let mut full_res = GenericArray::default();
    core.finalize_variable_core(&mut buffer, &mut full_res);

    let mut out = [0; OUTPUT_SIZE];
    out.copy_from_slice(&full_res[.. OUTPUT_SIZE]);
    out
  }
}

impl Blake2bMonero<64> {
  /// Finalize the hash as an Ed25519 scalar.
  #[doc(hidden)]
  pub fn finalize_as_scalar(self) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&self.finalize())
  }
}

impl<const OUTPUT_SIZE: usize> Update for Blake2bMonero<OUTPUT_SIZE> {
  fn update(&mut self, input: &[u8]) {
    let Self { core, buffer, .. } = self;
    buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
  }
}

impl<const OUTPUT_SIZE: usize> fmt::Debug for Blake2bMonero<OUTPUT_SIZE> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Blake2bMonero<{OUTPUT_SIZE}> {{ ... }}")
  }
}
