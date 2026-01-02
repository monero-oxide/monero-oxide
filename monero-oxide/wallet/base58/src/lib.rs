#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]

use std_shims::prelude::*;

use monero_primitives::keccak256;

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

    // Convert to the base58 encoding
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

/// Decode an arbitrary-length stream of data.
pub fn decode(data: &str) -> Option<Vec<u8>> {
  let mut res = Vec::with_capacity((data.len() / ENCODED_BLOCK_LEN) * BLOCK_LEN);

  for chunk in data.as_bytes().chunks(ENCODED_BLOCK_LEN) {
    // Convert the chunk back to a u64
    let mut sum = 0u64;
    for this_char in chunk {
      sum = sum.checked_mul(ALPHABET_LEN)?;
      sum = sum.checked_add(
        u64::try_from(ALPHABET.iter().position(|a| a == this_char)?)
          .expect("alphabet len exceeded 2**64"),
      )?;
    }

    // From the size of the encoding, determine the size of the bytes
    let mut used_bytes = None;
    for i in 1 ..= BLOCK_LEN {
      if encoded_len_for_bytes(i) == chunk.len() {
        used_bytes = Some(i);
        break;
      }
    }
    let used_bytes = used_bytes?;

    // Only push on the used bytes
    {
      let bytes = sum.to_be_bytes();
      let unused_bytes = BLOCK_LEN - used_bytes;
      // Check if any unused bytes were non-zero, as possible with a non-canonical encoding
      for b in &bytes[.. unused_bytes] {
        if *b != 0 {
          None?;
        }
      }
      res.extend(&bytes[unused_bytes ..]);
    }
  }

  Some(res)
}

/// Encode an arbitrary-length stream of data, with a checksum.
pub fn encode_check(mut data: Vec<u8>) -> String {
  let checksum = keccak256(&data);
  data.extend(&checksum[.. CHECKSUM_LEN]);
  encode(&data)
}

/// Decode an arbitrary-length stream of data, with a checksum.
pub fn decode_check(data: &str) -> Option<Vec<u8>> {
  let mut res = decode(data)?;
  if res.len() < CHECKSUM_LEN {
    None?;
  }
  let checksum_pos = res.len() - CHECKSUM_LEN;
  if keccak256(&res[.. checksum_pos])[.. CHECKSUM_LEN] != res[checksum_pos ..] {
    None?;
  }
  res.truncate(checksum_pos);
  Some(res)
}
