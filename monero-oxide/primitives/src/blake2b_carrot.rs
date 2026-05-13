/*
A specialization of blake2b that is compatible with Carrot hash functions.

Carrot uses blake2b with the personal string "Monero" and a zeroed salt. If
there is a key, it is always 32 bytes. If there is no key, then no key
block is included in the hash data. This contrasts with the `blake2::Blake2bMac512`
implmentation where key blocks are always included whenever a personal string
is set, even if the key is zero-length.

The `blake2::Blake2bMac512` impl is also restricted to 64-byte outputs, whereas
the carrot hash function include smaller-output options.

Adapted from the blake2::blake2_mac_impl macro.
*/

use core::fmt;
use blake2::Blake2bVarCore;
use digest::{
  InvalidBufferSize, InvalidLength, OutputSizeUser, Update,
  block_buffer::{Block, LazyBuffer},
  core_api::{BlockSizeUser, UpdateCore, VariableOutputCore},
  typenum::Unsigned,
};

/// Blake2b specialization for Monero.
///
/// Salt: zero
/// Personal string: "Monero"
/// Key: 32 bytes OR null (no key block included when null)
///
/// Hash output: custom 1 - 64 bytes (this value is embedded in the param block,
/// but otherwise does not affect the algorithm)
#[derive(Clone)]
pub struct Blake2bMonero {
  core: Blake2bVarCore,
  buffer: LazyBuffer<<Blake2bVarCore as BlockSizeUser>::BlockSize>,
  // Invariant: <= <Blake2bVarCore as OutputSizeUser>::OutputSize::USIZE
  output_size: usize,
}

impl Blake2bMonero {
  fn personal() -> &'static [u8] {
    b"Monero"
  }

  /// Create new instance using the provided output size (in bytes).
  ///
  /// Does *not* include a key block. See [`Self::new_with_key`],
  ///
  /// Returns an error if output size is greater than 64 bytes.
  #[inline]
  pub fn new(output_size: usize) -> Result<Self, InvalidLength> {
    let os = <Blake2bVarCore as OutputSizeUser>::OutputSize::USIZE;
    if output_size > os || output_size < 1 {
      return Err(InvalidLength);
    }
    Ok(Self {
      core: Blake2bVarCore::new_with_params(&[], Self::personal(), 0, output_size),
      buffer: LazyBuffer::default(),
      output_size,
    })
  }

  /// Create new instance using the provided 32-byte key and output size (in bytes).
  ///
  /// Returns an error if output size is greater than 64 bytes.
  #[inline]
  pub fn new_with_key(key: &[u8; 32], output_size: usize) -> Result<Self, InvalidLength> {
    let kl = key.len();
    let bs = <Blake2bVarCore as BlockSizeUser>::BlockSize::USIZE;
    let os = <Blake2bVarCore as OutputSizeUser>::OutputSize::USIZE;
    if kl > bs || output_size > os || output_size < 1 {
      return Err(InvalidLength);
    }
    let mut padded_key = Block::<<Blake2bVarCore as BlockSizeUser>::BlockSize>::default();
    padded_key[.. kl].copy_from_slice(key);
    Ok(Self {
      core: Blake2bVarCore::new_with_params(&[], Self::personal(), kl, output_size),
      buffer: LazyBuffer::new(&padded_key),
      output_size,
    })
  }

  /// Finalize the hash into the provided buffer.
  ///
  /// Returns an error if `out.len() > self.output_size`.
  #[inline]
  pub fn try_finalize_into(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
    let Self { core, buffer, output_size } = self;
    if out.len() > *output_size {
      return Err(InvalidBufferSize);
    }

    let mut full_res = Default::default();
    core.finalize_variable_core(buffer, &mut full_res);
    out.copy_from_slice(&full_res[.. *output_size]);

    Ok(())
  }
}

impl Update for Blake2bMonero {
  #[inline]
  fn update(&mut self, input: &[u8]) {
    let Self { core, buffer, .. } = self;
    buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
  }
}

impl fmt::Debug for Blake2bMonero {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}{} {{ ... }}", stringify!($name), self.output_size)
  }
}
