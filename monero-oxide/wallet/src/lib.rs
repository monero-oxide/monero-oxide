#![cfg_attr(docsrs, feature(doc_cfg))]
#![expect(unexpected_cfgs)]
#![cfg_attr(monero_oxide_rust_nightly, feature(variant_count))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref as _;
use std_shims::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use monero_oxide::{
  ed25519::*,
  primitives::{keccak256, keccak256_finalize, keccak256_streaming, KeccakDigest as _},
  ringct::EncryptedAmount,
  transaction::Input,
};

pub use monero_oxide::*;

pub use monero_interface as interface;

pub use monero_address as address;

mod view_pair;
pub use view_pair::{ViewPairError, ViewPair, GuaranteedViewPair};

/// Structures and functionality for working with transactions' extra fields.
pub mod extra;
pub(crate) use extra::{PaymentId, Extra};

pub(crate) mod output;
pub use output::WalletOutput;

mod scan;
pub use scan::{Timelocked, ScanError, Scanner, GuaranteedScanner};

mod decoys;
pub use decoys::OutputWithDecoys;

/// Structs and functionality for sending transactions.
pub mod send;

#[cfg(test)]
mod tests;

#[derive(Clone, PartialEq, Eq, Zeroize)]
struct SharedKeyDerivations {
  // Hs("view_tag" || 8Ra || o)
  view_tag: u8,
  // Hs(uniqueness || 8Ra || o) where uniqueness may be empty
  shared_key: Scalar,
}

impl SharedKeyDerivations {
  // https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
  fn uniqueness(inputs: &[Input]) -> [u8; 32] {
    // Avoid building a heap buffer; hash incrementally.
    //
    // uniqueness = keccak256("uniqueness" || VarInt(height)? || key_image_bytes? ...)
    let mut h = keccak256_streaming();
    h.update(b"uniqueness");

    // Stack buffer for VarInt encoding (enough for u64).
    let mut varint_buf = [0u8; 16];

    for input in inputs {
      match input {
        // If Gen, this should be the only input, making this loop somewhat pointless
        // This works and even if there were somehow multiple inputs, it'd be a false negative
        Input::Gen(height) => {
          // Encode `height` as VarInt into `varint_buf`
          let len = Self::encode_varint_u64(
            u64::try_from(*height).expect("block height fits into u64"),
            &mut varint_buf,
          );
          h.update(&varint_buf[.. len]);
        }
        Input::ToKey { key_image, .. } => {
          h.update(key_image.to_bytes());
        }
      }
    }

    keccak256_finalize(h)
  }

  fn output_derivations(
    uniqueness: Option<[u8; 32]>,
    ecdh: &Point,
    o: usize,
  ) -> Zeroizing<SharedKeyDerivations> {
    // 8Ra (32 bytes) - avoid heap allocation by keeping this on the stack
    let ra_bytes = Self::compute_ra_bytes(ecdh);

    // Encode VarInt(o) into a small stack buffer (avoid growing a Vec).
    let mut o_buf = [0u8; 16];
    let o_len =
      Self::encode_varint_u64(u64::try_from(o).expect("output index fits into u64"), &mut o_buf);

    // view_tag = keccak256("view_tag" || 8Ra || o_varint)[0] (allocation-free)
    let view_tag = Self::compute_view_tag_from_parts(&ra_bytes, &o_buf[.. o_len]);

    // shared_key = Scalar::hash( (uniqueness?) || 8Ra || o_varint )
    //
    // NOTE: Scalar::hash still takes a slice, so we still build a minimal buffer here.
    // Avoid concat patterns and keep it tight.
    let mut shared_key_input =
      Vec::with_capacity(uniqueness.as_ref().map(|_| 32).unwrap_or(0) + ra_bytes.len() + o_len);
    if let Some(u) = uniqueness {
      shared_key_input.extend_from_slice(u.as_slice());
    }
    shared_key_input.extend_from_slice(&ra_bytes);
    shared_key_input.extend_from_slice(&o_buf[.. o_len]);

    Zeroizing::new(SharedKeyDerivations { view_tag, shared_key: Scalar::hash(&shared_key_input) })
  }

  #[inline]
  fn compute_view_tag_from_parts(ra_bytes: &[u8], o_varint: &[u8]) -> u8 {
    // view_tag = keccak256("view_tag" || 8Ra || o_varint)[0] (allocation-free)
    let mut h_tag = keccak256_streaming();
    h_tag.update(b"view_tag");
    h_tag.update(ra_bytes);
    h_tag.update(o_varint);
    keccak256_finalize(h_tag)[0]
  }

  #[inline]
  fn compute_ra_bytes(ecdh: &Point) -> [u8; 32] {
    // 8Ra (32 bytes) - keep on stack to avoid heap allocation
    (*ecdh).into().mul_by_cofactor().compress().to_bytes()
  }

  #[inline]
  fn encode_varint_u64(mut n: u64, out: &mut [u8; 16]) -> usize {
    let mut len = 0usize;
    loop {
      let byte = u8::try_from(n & 0x7f).expect("7-bit varint limb fits into u8");
      n >>= 7;
      if n == 0 {
        out[len] = byte;
        len += 1;
        break;
      }
      out[len] = byte | 0x80;
      len += 1;
    }
    len
  }

  // Compute only the view tag (fast path for mismatch-heavy scanning).
  // This allows callers to check view tags before paying for shared_key hashing.
  #[inline]
  fn output_view_tag(ecdh: &Point, o: usize) -> u8 {
    let ra_bytes = Self::compute_ra_bytes(ecdh);

    let mut o_buf = [0u8; 16];
    let o_len =
      Self::encode_varint_u64(u64::try_from(o).expect("output index fits into u64"), &mut o_buf);

    Self::compute_view_tag_from_parts(&ra_bytes, &o_buf[.. o_len])
  }

  // Compute only the shared key (for outputs that passed the view tag check).
  #[inline]
  fn output_shared_key(uniqueness: Option<[u8; 32]>, ecdh: &Point, o: usize) -> Scalar {
    let ra_bytes = Self::compute_ra_bytes(ecdh);

    let mut o_buf = [0u8; 16];
    let o_len =
      Self::encode_varint_u64(u64::try_from(o).expect("output index fits into u64"), &mut o_buf);

    let mut shared_key_input =
      Vec::with_capacity(uniqueness.as_ref().map(|_| 32).unwrap_or(0) + ra_bytes.len() + o_len);
    if let Some(u) = uniqueness {
      shared_key_input.extend_from_slice(u.as_slice());
    }
    shared_key_input.extend_from_slice(&ra_bytes);
    shared_key_input.extend_from_slice(&o_buf[.. o_len]);

    Scalar::hash(&shared_key_input)
  }

  // H(8Ra || 0x8d)
  #[expect(clippy::needless_pass_by_value)]
  fn payment_id_xor(ecdh: Zeroizing<Point>) -> [u8; 8] {
    // 8Ra
    let output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new((*ecdh).into().mul_by_cofactor()).compress().to_bytes())
        .to_vec(),
    );

    // Avoid allocating a concatenated Vec by appending the marker byte into a small buffer.
    let mut buf = Vec::with_capacity(output_derivation.len() + 1);
    buf.extend_from_slice(output_derivation.as_slice());
    buf.push(0x8d);

    let mut payment_id_xor = [0; 8];
    payment_id_xor.copy_from_slice(&keccak256(buf)[.. 8]);
    payment_id_xor
  }

  fn commitment_mask(&self) -> Scalar {
    let mut mask = b"commitment_mask".to_vec();
    mask.extend(&<[u8; 32]>::from(self.shared_key));
    let res = Scalar::hash(&mask);
    mask.zeroize();
    res
  }

  fn compact_amount_encryption(&self, amount: u64) -> [u8; 8] {
    let mut amount_mask = Zeroizing::new(b"amount".to_vec());
    amount_mask.extend(<[u8; 32]>::from(self.shared_key));
    let mut amount_mask = keccak256(&amount_mask);

    let mut amount_mask_8 = [0; 8];
    amount_mask_8.copy_from_slice(&amount_mask[.. 8]);
    amount_mask.zeroize();

    (amount ^ u64::from_le_bytes(amount_mask_8)).to_le_bytes()
  }

  fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
    match enc_amount {
      EncryptedAmount::Original { mask, amount } => {
        let mask_shared_sec_scalar =
          Zeroizing::new(Scalar::hash(Zeroizing::new(<[u8; 32]>::from(self.shared_key))));
        let amount_shared_sec_scalar =
          Zeroizing::new(Scalar::hash(<[u8; 32]>::from(*mask_shared_sec_scalar)));

        let mask =
          curve25519_dalek::Scalar::from_bytes_mod_order(*mask) - (*mask_shared_sec_scalar).into();
        let amount_scalar = Zeroizing::new(
          curve25519_dalek::Scalar::from_bytes_mod_order(*amount) -
            (*amount_shared_sec_scalar).into(),
        );

        // d2b from rctTypes.cpp
        let amount = u64::from_le_bytes(
          Zeroizing::new(amount_scalar.to_bytes()).deref()[.. 8]
            .try_into()
            .expect("32-byte array couldn't have an 8-byte slice taken"),
        );

        Commitment::new(Scalar::from(mask), amount)
      }
      EncryptedAmount::Compact { amount } => Commitment::new(
        self.commitment_mask(),
        u64::from_le_bytes(self.compact_amount_encryption(u64::from_le_bytes(*amount))),
      ),
    }
  }
}
