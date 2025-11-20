use core::ops::Deref;
use std_shims::{vec, vec::Vec};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(feature = "compile-time-generators")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(not(feature = "compile-time-generators"))]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

use crate::{
  ed25519::*,
  primitives::keccak256,
  ringct::EncryptedAmount,
  SharedKeyDerivations,
  send::{ChangeEnum, InternalPayment, SignableTransaction, key_image_sort},
};

fn seeded_rng(
  dst: &'static [u8],
  outgoing_view_key: &[u8; 32],
  input_keys_and_commitments: Vec<(Point, Point)>,
) -> ChaCha20Rng {
  // Apply the DST
  let mut transcript = Zeroizing::new(vec![
    u8::try_from(dst.len()).expect("internal RNG with constant DST had a too-long DST specified")
  ]);
  transcript.extend(dst);

  // Bind to the outgoing view key to prevent foreign entities from rebuilding the transcript
  transcript.extend(outgoing_view_key);

  let mut input_keys_and_commitments = input_keys_and_commitments
    .into_iter()
    .map(|(key, commitment)| (key.compress(), commitment.compress()))
    .collect::<Vec<_>>();

  // We sort the inputs here to ensure a consistent order
  // We use the key image sort as it's applicable and well-defined, not because these are key
  // images
  input_keys_and_commitments
    .sort_by(|(key_a, _commitment_a), (key_b, _commitment_b)| key_image_sort(key_a, key_b));

  // Ensure uniqueness across transactions by binding to a use-once object
  // The keys for the inputs is binding to their key images, making them use-once
  for (key, commitment) in input_keys_and_commitments {
    transcript.extend(key.to_bytes());
    transcript.extend(commitment.to_bytes());
  }

  let res = ChaCha20Rng::from_seed(keccak256(&transcript));
  transcript.zeroize();
  res
}

/// An iterator yielding an endless amount of ephemeral keys to use within a transaction.
///
/// This is used when sending and can be used after sending to re-derive the keys used, as
/// necessary for payment proofs.
pub struct TransactionKeys(ChaCha20Rng);
impl Drop for TransactionKeys {
  fn drop(&mut self) {
    // Advance the stream to attempt to clear any current state
    let mut seed = [0; 64];
    let _result = self.0.try_fill_bytes(&mut seed);
    // Reset the position of the stream
    self.0.set_stream(0);
    self.0.set_word_pos(0);
    // Overwrite the stream with a new one which has been zero-initialized
    self.0 = ChaCha20Rng::from_seed([0; 32]);
    core::hint::black_box(&mut self.0);
  }
}
impl ZeroizeOnDrop for TransactionKeys {}

impl TransactionKeys {
  /// Construct a new `TransactionKeys`.
  ///
  /// `input_keys` is the list of keys from the outputs spent within this transaction.
  pub fn new(
    outgoing_view_key: &Zeroizing<[u8; 32]>,
    input_keys_and_commitments: Vec<(Point, Point)>,
  ) -> Self {
    Self(seeded_rng(b"transaction_keys", outgoing_view_key, input_keys_and_commitments))
  }
}
impl Iterator for TransactionKeys {
  type Item = Zeroizing<Scalar>;
  fn next(&mut self) -> Option<Self::Item> {
    Some(Zeroizing::new(Scalar::random(&mut self.0)))
  }
}

impl SignableTransaction {
  fn input_keys_and_commitments(&self) -> Vec<(Point, Point)> {
    self.inputs.iter().map(|output| (output.key(), output.commitment().commit())).collect()
  }

  pub(crate) fn seeded_rng(&self, dst: &'static [u8]) -> ChaCha20Rng {
    seeded_rng(dst, &self.outgoing_view_key, self.input_keys_and_commitments())
  }

  fn has_payments_to_subaddresses(&self) -> bool {
    self.payments.iter().any(|payment| match payment {
      InternalPayment::Payment(addr, _) => addr.is_subaddress(),
      InternalPayment::Change(change) => match change {
        ChangeEnum::AddressOnly(addr) => addr.is_subaddress(),
        // These aren't considered payments to subaddresses as we don't need to send to them as
        // subaddresses
        // We can calculate the shared key using the view key, as if we were receiving, instead
        ChangeEnum::Standard { .. } | ChangeEnum::Guaranteed { .. } => false,
      },
    })
  }

  fn should_use_additional_keys(&self) -> bool {
    let has_payments_to_subaddresses = self.has_payments_to_subaddresses();
    if !has_payments_to_subaddresses {
      return false;
    }

    let has_change_view = self.payments.iter().any(|payment| match payment {
      InternalPayment::Payment(_, _) => false,
      InternalPayment::Change(change) => match change {
        ChangeEnum::AddressOnly(_) => false,
        ChangeEnum::Standard { .. } | ChangeEnum::Guaranteed { .. } => true,
      },
    });

    /*
      If sending to a subaddress, the shared key is not `rG` yet `rB`. Because of this, a
      per-subaddress shared key is necessary, causing the usage of additional keys.

      The one exception is if we're sending to a subaddress in a 2-output transaction. The second
      output, the change output, will attempt scanning the singular key `rB` with `v rB`. While we
      cannot calculate `r vB` with just `r` (as that'd require `vB` when we presumably only have
      `vG` when sending), since we do in fact have `v` (due to it being our own view key for our
      change output), we can still calculate the shared secret.
    */
    has_payments_to_subaddresses && !((self.payments.len() == 2) && has_change_view)
  }

  // Calculate the transaction keys used as randomness.
  fn transaction_keys(&self) -> (Zeroizing<Scalar>, Vec<Zeroizing<Scalar>>) {
    let mut tx_keys =
      TransactionKeys::new(&self.outgoing_view_key, self.input_keys_and_commitments());

    let tx_key = tx_keys.next().expect("TransactionKeys (never-ending) was exhausted");

    let mut additional_keys = vec![];
    if self.should_use_additional_keys() {
      for _ in 0 .. self.payments.len() {
        additional_keys.push(tx_keys.next().expect("TransactionKeys (never-ending) was exhausted"));
      }
    }
    (tx_key, additional_keys)
  }

  fn ecdhs(&self) -> Vec<Zeroizing<Point>> {
    let (tx_key, additional_keys) = self.transaction_keys();
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));
    let (tx_key_pub, additional_keys_pub) = self.transaction_keys_pub();
    debug_assert_eq!(additional_keys_pub.len(), additional_keys.len());

    let mut res = Vec::with_capacity(self.payments.len());
    for (i, payment) in self.payments.iter().enumerate() {
      let addr = payment.address();
      let key_to_use =
        if addr.is_subaddress() { additional_keys.get(i).unwrap_or(&tx_key) } else { &tx_key };
      let key_to_use = Zeroizing::new((**key_to_use).into());

      let ecdh = match payment {
        // If we don't have the view key, use the key dedicated for this address (r A)
        InternalPayment::Payment(_, _) |
        InternalPayment::Change(ChangeEnum::AddressOnly { .. }) => {
          Zeroizing::new(key_to_use.deref() * addr.view().into())
        }
        // If we do have the view key, use the commitment to the key (a R)
        InternalPayment::Change(ChangeEnum::Standard { view_pair, .. }) => {
          Zeroizing::new(Zeroizing::new((*view_pair.view).into()).deref() * tx_key_pub.into())
        }
        InternalPayment::Change(ChangeEnum::Guaranteed { view_pair, .. }) => {
          Zeroizing::new(Zeroizing::new((*view_pair.0.view).into()).deref() * tx_key_pub.into())
        }
      };

      res.push(Zeroizing::new(Point::from(*ecdh)));
    }
    res
  }

  // Calculate the shared keys and the necessary derivations.
  pub(crate) fn shared_key_derivations(
    &self,
    key_images: &[CompressedPoint],
  ) -> Vec<Zeroizing<SharedKeyDerivations>> {
    let ecdhs = self.ecdhs();

    let uniqueness = SharedKeyDerivations::uniqueness(&self.inputs(key_images));

    let mut res = Vec::with_capacity(self.payments.len());
    for (i, (payment, ecdh)) in self.payments.iter().zip(ecdhs).enumerate() {
      let addr = payment.address();
      res.push(SharedKeyDerivations::output_derivations(
        addr.is_guaranteed().then_some(uniqueness),
        ecdh,
        i,
      ));
    }
    res
  }

  // Calculate the payment ID XOR masks.
  pub(crate) fn payment_id_xors(&self) -> Vec<[u8; 8]> {
    let mut res = Vec::with_capacity(self.payments.len());
    for ecdh in self.ecdhs() {
      res.push(SharedKeyDerivations::payment_id_xor(ecdh));
    }
    res
  }

  // Calculate the transaction_keys' commitments.
  //
  // These depend on the payments. Commitments for payments to subaddresses use the spend key for
  // the generator.
  pub(crate) fn transaction_keys_pub(&self) -> (Point, Vec<CompressedPoint>) {
    let (tx_key, additional_keys) = self.transaction_keys();
    let tx_key = Zeroizing::new((*tx_key).into());
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));

    // The single transaction key uses the subaddress's spend key as its generator
    let has_payments_to_subaddresses = self.has_payments_to_subaddresses();
    let should_use_additional_keys = self.should_use_additional_keys();
    if has_payments_to_subaddresses && (!should_use_additional_keys) {
      debug_assert_eq!(additional_keys.len(), 0);

      let InternalPayment::Payment(addr, _) = self
        .payments
        .iter()
        .find(|payment| matches!(payment, InternalPayment::Payment(_, _)))
        .expect("payment to subaddress yet no payment")
      else {
        panic!("filtered payment wasn't a payment")
      };

      return (Point::from(tx_key.deref() * addr.spend().into()), vec![]);
    }

    if should_use_additional_keys {
      let mut additional_keys_pub = vec![];
      for (additional_key, payment) in additional_keys.into_iter().zip(&self.payments) {
        let additional_key = Zeroizing::new((*additional_key).into());
        let addr = payment.address();
        // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
        //   /src/device/device_default.cpp#L308-L312
        if addr.is_subaddress() {
          additional_keys_pub
            .push(Point::from(additional_key.deref() * addr.spend().into()).compress());
        } else {
          additional_keys_pub
            .push(Point::from(additional_key.deref() * ED25519_BASEPOINT_TABLE).compress());
        }
      }
      return (Point::from(tx_key.deref() * ED25519_BASEPOINT_TABLE), additional_keys_pub);
    }

    debug_assert!(!has_payments_to_subaddresses);
    debug_assert!(!should_use_additional_keys);
    (Point::from(tx_key.deref() * ED25519_BASEPOINT_TABLE), vec![])
  }

  pub(crate) fn commitments_and_encrypted_amounts(
    &self,
    key_images: &[CompressedPoint],
  ) -> Vec<(Commitment, EncryptedAmount)> {
    let shared_key_derivations = self.shared_key_derivations(key_images);

    let mut res = Vec::with_capacity(self.payments.len());
    for (payment, shared_key_derivations) in self.payments.iter().zip(shared_key_derivations) {
      let amount = match payment {
        InternalPayment::Payment(_, amount) => *amount,
        InternalPayment::Change(_) => {
          let inputs = self.inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
          let payments = self
            .payments
            .iter()
            .filter_map(|payment| match payment {
              InternalPayment::Payment(_, amount) => Some(amount),
              InternalPayment::Change(_) => None,
            })
            .sum::<u64>();
          let necessary_fee = self.weight_and_necessary_fee().1;
          // Safe since the constructor checked this TX has enough funds for itself
          inputs - (payments + necessary_fee)
        }
      };
      let commitment = Commitment::new(shared_key_derivations.commitment_mask(), amount);
      let encrypted_amount = EncryptedAmount::Compact {
        amount: shared_key_derivations.compact_amount_encryption(amount),
      };
      res.push((commitment, encrypted_amount));
    }
    res
  }

  pub(crate) fn sum_output_masks(&self, key_images: &[CompressedPoint]) -> Scalar {
    Scalar::from(
      self
        .commitments_and_encrypted_amounts(key_images)
        .into_iter()
        .map(|(commitment, _)| commitment.mask.into())
        .sum::<curve25519_dalek::Scalar>(),
    )
  }
}
