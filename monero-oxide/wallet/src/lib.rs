#![cfg_attr(docsrs, feature(doc_cfg))]
#![expect(unexpected_cfgs)]
#![cfg_attr(monero_oxide_rust_nightly, feature(variant_count))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref as _;
use std_shims::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use monero_oxide::{
  io::VarInt, ed25519::*, primitives::keccak256, ringct::EncryptedAmount, transaction::Input,
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
    let mut u = b"uniqueness".to_vec();
    for input in inputs {
      match input {
        // If Gen, this should be the only input, making this loop somewhat pointless
        // This works and even if there were somehow multiple inputs, it'd be a false negative
        Input::Gen(height) => {
          VarInt::write(height, &mut u).expect("write failed but <Vec as io::Write> doesn't fail");
        }
        Input::ToKey { key_image, .. } => u.extend(key_image.to_bytes()),
      }
    }
    keccak256(u)
  }

  #[expect(clippy::needless_pass_by_value)]
  fn output_derivations(
    uniqueness: Option<[u8; 32]>,
    ecdh: Zeroizing<Point>,
    o: usize,
  ) -> Zeroizing<SharedKeyDerivations> {
    // 8Ra
    let mut output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new((*ecdh).into().mul_by_cofactor()).compress().to_bytes())
        .to_vec(),
    );

    // || o
    {
      let output_derivation: &mut Vec<u8> = output_derivation.as_mut();
      VarInt::write(&o, output_derivation)
        .expect("write failed but <Vec as io::Write> doesn't fail");
    }

    let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

    // uniqueness ||
    let output_derivation = if let Some(uniqueness) = uniqueness {
      Zeroizing::new([uniqueness.as_slice(), &output_derivation].concat())
    } else {
      output_derivation
    };

    Zeroizing::new(SharedKeyDerivations { view_tag, shared_key: Scalar::hash(&output_derivation) })
  }

  // H(8Ra || 0x8d)
  #[expect(clippy::needless_pass_by_value)]
  fn payment_id_xor(ecdh: Zeroizing<Point>) -> [u8; 8] {
    // 8Ra
    let output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new((*ecdh).into().mul_by_cofactor()).compress().to_bytes())
        .to_vec(),
    );

    let mut payment_id_xor = [0; 8];
    payment_id_xor
      .copy_from_slice(&keccak256([output_derivation.as_slice(), &[0x8d]].concat())[.. 8]);
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
