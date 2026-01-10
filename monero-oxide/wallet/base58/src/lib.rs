#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(test), no_std)]

use core::borrow::Borrow;
use std_shims::prelude::*;

use sha3::{Digest, Keccak256};

#[cfg(test)]
mod tests;

const ALPHABET_LEN: u64 = 58;
pub(crate) const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub(crate) const BLOCK_LEN: usize = 8;
const ENCODED_BLOCK_LEN: usize = 11;

const CHECKSUM_LEN: usize = 4;

// The maximum possible length of an encoding of this many bytes
//
// This is used for determining padding/how many bytes an encoding actually uses
pub(crate) fn encoded_len_for_bytes(bytes: usize) -> usize {
  let bits = u64::try_from(bytes).expect("length exceeded 2**64") * 8;
  let mut max = if bits == 64 { u64::MAX } else { (1 << bits) - 1 };

  let mut i = 0;
  while max != 0 {
    max /= ALPHABET_LEN;
    i += 1;
  }
  i
}

/// Encode an arbitrary-length stream of data.
pub fn encode(bytes: &[u8]) -> String {
  let mut res = String::with_capacity(bytes.len().div_ceil(BLOCK_LEN) * ENCODED_BLOCK_LEN);

  for chunk in bytes.chunks(BLOCK_LEN) {
    // Convert to a u64
    let mut fixed_len_chunk = [0; BLOCK_LEN];
    fixed_len_chunk[(BLOCK_LEN - chunk.len()) ..].copy_from_slice(chunk);
    let mut val = u64::from_be_bytes(fixed_len_chunk);

    // Convert to the Base58 encoding
    let mut chunk_str = [char::from(ALPHABET[0]); ENCODED_BLOCK_LEN];
    let mut i = 0;
    while val > 0 {
      chunk_str[i] = ALPHABET[usize::try_from(val % ALPHABET_LEN)
        .expect("ALPHABET_LEN exceeds usize despite being a usize")]
      .into();
      i += 1;
      val /= ALPHABET_LEN;
    }

    // Only take used bytes, and since we put the LSBs in the first byte, reverse the byte order
    for c in chunk_str.into_iter().take(encoded_len_for_bytes(chunk.len())).rev() {
      res.push(c);
    }
  }

  res
}

/// A non-allocating iterator to decode Base58-encoded data.
struct DecodeIterator<I: Iterator<Item = u8>> {
  data: I,
  /// The most recently decoded chunk from the input.
  queued: Option<([u8; 8], usize)>,
  /// If this iterator was fused.
  ///
  /// We track this ourselves due to returning `Some(None)` on error, and not wanting to continue
  /// iterating after an error. Unfortunately, even if we returned `Some(Err(_))`, Rust does offer
  /// `fuse()` yet not `try_fuse()`.
  fused: bool,
}
impl<I: Iterator<Item = u8>> Iterator for DecodeIterator<I> {
  type Item = Option<u8>;
  fn next(&mut self) -> Option<Self::Item> {
    if self.fused {
      None?;
    }

    // Grab the already-decoded chunk, decoding one if there was none
    let (bytes, mut i) = match self.queued.take() {
      Some(queued) => queued,
      None => {
        // Read the next chunk of the encoded data
        let mut chunk = [0; ENCODED_BLOCK_LEN];
        let mut chunk_len = 0;
        while chunk_len < ENCODED_BLOCK_LEN {
          let Some(byte) = self.data.next() else { break };
          chunk[chunk_len] = byte;
          chunk_len += 1;
        }
        // If the underlying iterator was empty, complete this iterator
        if chunk_len == 0 {
          self.fused = true;
          None?;
        }

        // Convert the Base58-encoded chunk back to a `u64`
        let mut sum = 0u64;
        for this_char in chunk.into_iter().take(chunk_len) {
          // Shift the existing value in the accumulator over
          sum = {
            let Some(sum) = sum.checked_mul(ALPHABET_LEN) else {
              self.fused = true;
              return Some(None);
            };
            sum
          };
          // Decode this digit from the alphabet
          let Some(pos) = ALPHABET.iter().position(|a| *a == this_char) else {
            self.fused = true;
            return Some(None);
          };
          // Accumulate this digit
          sum += u64::try_from(pos).expect("alphabet len exceeded 2**64");
        }

        // From the size of the encoding, determine the size of the bytes
        let mut used_bytes = None;
        for i in 1 ..= BLOCK_LEN {
          if encoded_len_for_bytes(i) == chunk_len {
            used_bytes = Some(i);
            break;
          }
        }
        let Some(used_bytes) = used_bytes else {
          self.fused = true;
          return Some(None);
        };

        // Only queue on the used bytes
        (sum.to_be_bytes(), BLOCK_LEN - used_bytes)
      }
    };

    let result = bytes[i];
    i += 1;
    // If we haven't exhausted this chunk, write it back to `queued`
    if i != BLOCK_LEN {
      self.queued = Some((bytes, i));
    }
    Some(Some(result))
  }
}

/// Decode an arbitrary-length stream of data.
///
/// `Some(None)` reflects the data was incorrectly encoded. The iterator must be exhausted to
/// ensure its validity.
#[inline(always)]
pub fn decode(data: impl IntoIterator<Item = impl Borrow<u8>>) -> impl Iterator<Item = Option<u8>> {
  DecodeIterator { data: data.into_iter().map(|item| *item.borrow()), queued: None, fused: false }
}

/// Encode an arbitrary-length stream of data, with a checksum.
pub fn encode_check(mut data: Vec<u8>) -> String {
  let checksum = Keccak256::digest(&data);
  data.extend(&checksum[.. CHECKSUM_LEN]);
  encode(&data)
}

/// A non-allocating iterator to decode Base58-encoded data, with a checksum.
struct DecodeCheckIterator<I: Iterator<Item = Option<u8>>> {
  underlying: I,
  /// This is `None` if the iterator has been exhausted.
  checksum: Option<Keccak256>,
  /// The index within the ring buffer.
  ring_buf_i: usize,
  /// A ring buffer containing the next set of bytes from the underlying iterator.
  ///
  /// This lets us detect if we've reached the end, and more specifically, the checksum.
  ring_buf: [u8; CHECKSUM_LEN],
}
impl<I: Iterator<Item = Option<u8>>> Iterator for DecodeCheckIterator<I> {
  type Item = Option<u8>;
  fn next(&mut self) -> Option<Self::Item> {
    let Some(checksum) = self.checksum.as_mut() else { None? };
    // This is correct since `CHECKSUM_LEN` is a power of two
    self.ring_buf_i &= CHECKSUM_LEN - 1;

    match self.underlying.next() {
      Some(Some(next)) => {
        let result = self.ring_buf[self.ring_buf_i];
        self.ring_buf[self.ring_buf_i] = next;
        self.ring_buf_i += 1;
        checksum.update([result]);
        Some(Some(result))
      }
      // Yield the error
      Some(None) => {
        self.checksum = None;
        Some(None)
      }
      // Verify the checksum
      None => {
        let checksum = self
          .checksum
          .take()
          .expect("function which only runs if `checksum = Some(_)` had `checksum = None`")
          .finalize();
        for (b, c) in (self.ring_buf_i .. (self.ring_buf_i + CHECKSUM_LEN)).zip(checksum) {
          if self.ring_buf[b & (CHECKSUM_LEN - 1)] != c {
            return Some(None);
          }
        }
        None
      }
    }
  }
}

/// Decode an arbitrary-length stream of data, with a checksum.
///
/// `Some(None)` reflects the data was incorrectly encoded. The iterator must be exhausted to
/// ensure its validity.
#[inline(always)]
pub fn decode_check(
  data: impl IntoIterator<Item = impl Borrow<u8>>,
) -> impl Iterator<Item = Option<u8>> {
  let mut data = decode(data);

  // Populate the ring buffer with its initial state
  let mut ring_buf = [0; CHECKSUM_LEN];
  let mut invalid = None;
  for b in &mut ring_buf {
    if let Some(Some(byte)) = data.next() {
      *b = byte;
    } else {
      // If this stream didn't even include the checksum, populate `invalid` with an iterator which
      // will yield an error
      invalid = Some(core::iter::once(None));
      break;
    }
  }
  // `checksum` is overloaded as `fused`, so don't create a checksum if this shouldn't ever run
  let checksum = invalid.is_none().then_some(Keccak256::new());
  invalid.into_iter().flatten().chain(DecodeCheckIterator {
    underlying: data,
    checksum,
    ring_buf_i: 0,
    ring_buf,
  })
}
