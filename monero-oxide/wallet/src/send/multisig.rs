use std_shims::{
  vec::Vec,
  io::{self, Read},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{traits::Identity, Scalar, EdwardsPoint};

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys,
  sign::{
    Writable, Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine,
    SignatureMachine, AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};

use monero_oxide::{
  ed25519::CompressedPoint,
  ringct::{
    clsag::{ClsagContext, ClsagMultisigMaskSender, ClsagAddendum, ClsagMultisig},
    RctPrunable, RctProofs,
  },
  transaction::Transaction,
};
use crate::send::{SendError, SignableTransaction, key_image_sort};

/// Initial FROST machine to produce a signed transaction.
pub struct TransactionMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  // The key image generator, and the (scalar, offset) linear combination from the spend key
  key_image_generators_and_lincombs: Vec<(EdwardsPoint, (Scalar, Scalar))>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmMachine<Ed25519, ClsagMultisig>)>,
}

/// Second FROST machine to produce a signed transaction.
///
/// Panics if a non-empty message is provided, or if `cache`, `from_cache` are called.
///
/// This MUST only be passed preprocesses obtained via calling `read_preprocess` with this very
/// machine. Other machines representing distinct executions of the protocol will almost certainly
/// be incompatible.
pub struct TransactionSignMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  key_image_generators_and_lincombs: Vec<(EdwardsPoint, (Scalar, Scalar))>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmSignMachine<Ed25519, ClsagMultisig>)>,

  our_preprocess: Vec<Preprocess<Ed25519, ClsagAddendum>>,
}

/// Final FROST machine to produce a signed transaction.
///
/// This MUST only be passed shares obtained via calling `read_share` with this very machine.
/// Shares from other machines, representing distinct executions of the signing protocol, will be
/// incompatible.
pub struct TransactionSignatureMachine {
  tx: Transaction,
  clsags: Vec<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  ///
  /// The created machine is expected to be called with an empty message, as it will generate its
  /// own, and may panic if a message is provided. The created machine DOES NOT support caching and
  /// may panic if `cache`, `from_cache` are called.
  pub fn multisig(self, keys: ThresholdKeys<Ed25519>) -> Result<TransactionMachine, SendError> {
    let mut clsags = vec![];

    let mut key_image_generators_and_lincombs = vec![];
    for input in &self.inputs {
      // Check this is the right set of keys
      let key_scalar = Scalar::ONE;
      let key_offset = input.key_offset();

      let offset = keys
        .clone()
        .scale(key_scalar)
        .expect("non-zero scalar (1) was zero")
        .offset(key_offset.into());
      if offset.group_key().0 != input.key().into() {
        Err(SendError::WrongPrivateKey)?;
      }

      let context = ClsagContext::new(input.decoys().clone(), input.commitment().clone())
        .map_err(SendError::ClsagError)?;
      let (clsag, clsag_mask_send) = ClsagMultisig::new(
        RecommendedTranscript::new(b"Monero Multisignature Transaction"),
        context,
      );
      key_image_generators_and_lincombs
        .push((clsag.key_image_generator(), (offset.current_scalar(), offset.current_offset())));
      clsags.push((clsag_mask_send, AlgorithmMachine::new(clsag, offset)));
    }

    Ok(TransactionMachine { signable: self, keys, key_image_generators_and_lincombs, clsags })
  }
}

/// The preprocess for a transaction.
// Opaque wrapper around the CLSAG preprocesses, forcing users to use `read_preprocess` to obtain
// this.
#[derive(Clone, PartialEq)]
pub struct TransactionPreprocess(Vec<Preprocess<Ed25519, ClsagAddendum>>);
impl Writable for TransactionPreprocess {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    for preprocess in &self.0 {
      preprocess.write(writer)?;
    }
    Ok(())
  }
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = TransactionPreprocess;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (TransactionSignMachine, Self::Preprocess) {
    // Iterate over each CLSAG calling preprocess
    let mut preprocesses = Vec::with_capacity(self.clsags.len());
    let clsags = self
      .clsags
      .drain(..)
      .map(|(clsag_mask_send, clsag)| {
        let (clsag, preprocess) = clsag.preprocess(rng);
        preprocesses.push(preprocess);
        (clsag_mask_send, clsag)
      })
      .collect();
    let our_preprocess = preprocesses.clone();

    (
      TransactionSignMachine {
        signable: self.signable,

        keys: self.keys,

        key_image_generators_and_lincombs: self.key_image_generators_and_lincombs,
        clsags,

        our_preprocess,
      },
      TransactionPreprocess(preprocesses),
    )
  }
}

/// The signature share for a transaction.
// Opaque wrapper around the CLSAG signature shares, forcing users to use `read_share` to
// obtain this.
#[derive(Clone, PartialEq)]
pub struct TransactionSignatureShare(Vec<SignatureShare<Ed25519>>);
impl Writable for TransactionSignatureShare {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    for share in &self.0 {
      share.write(writer)?;
    }
    Ok(())
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Ed25519>;
  type Preprocess = TransactionPreprocess;
  type SignatureShare = TransactionSignatureShare;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Ed25519>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    Ok(TransactionPreprocess(
      self.clsags.iter().map(|clsag| clsag.1.read_preprocess(reader)).collect::<Result<_, _>>()?,
    ))
  }

  fn sign(
    self,
    mut commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      panic!("message was passed to the TransactionMachine when it generates its own");
    }

    for preprocess in commitments.values() {
      if preprocess.0.len() != self.clsags.len() {
        Err(FrostError::InternalError(
          "preprocesses from another instance of the signing protocol were passed in",
        ))?;
      }
    }

    // We do not need to be included here, yet this set of signers has yet to be validated
    // We explicitly remove ourselves to ensure we aren't included twice, if we were redundantly
    // included
    commitments.remove(&self.keys.params().i());

    // Find out who's included
    let mut included = commitments.keys().copied().collect::<Vec<_>>();
    // This push won't duplicate due to the above removal
    included.push(self.keys.params().i());
    // unstable sort may reorder elements of equal order
    // Given our lack of duplicates, we should have no elements of equal order
    included.sort_unstable();

    // Start calculating the key images, as needed on the TX level
    let mut key_images = vec![EdwardsPoint::identity(); self.clsags.len()];

    // Convert the serialized nonces commitments to a parallelized Vec
    let view = self.keys.view(included.clone()).map_err(|_| {
      FrostError::InvalidSigningSet("couldn't form an interpolated view of the key")
    })?;
    let mut commitments = (0 .. self.clsags.len())
      .map(|c| {
        included
          .iter()
          .map(|l| {
            let preprocess = if *l == self.keys.params().i() {
              self.our_preprocess[c].clone()
            } else {
              commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?.0[c].clone()
            };

            // While here, calculate the key image as needed to call sign
            // The CLSAG algorithm will independently calculate the key image/verify these shares
            key_images[c] += preprocess.addendum.key_image_share().0 *
              view.interpolation_factor(*l).ok_or(FrostError::InternalError(
                "view successfully formed with participant without an interpolation factor",
              ))?;

            Ok((*l, preprocess))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    let key_images: Vec<_> = key_images
      .into_iter()
      .zip(&self.key_image_generators_and_lincombs)
      .map(|(mut key_image, (generator, (scalar, offset)))| {
        key_image *= scalar;
        key_image += generator * offset;
        CompressedPoint::from(key_image.compress().to_bytes())
      })
      .collect();

    // The above inserted our own preprocess into these maps (which is unnecessary)
    // Remove it now
    for map in &mut commitments {
      map.remove(&self.keys.params().i());
    }

    // The actual TX will have sorted its inputs by key image
    // We apply the same sort now to our CLSAG machines
    let mut clsags = Vec::with_capacity(self.clsags.len());
    for ((key_image, clsag), commitments) in key_images.iter().zip(self.clsags).zip(commitments) {
      clsags.push((key_image, clsag, commitments));
    }
    clsags.sort_by(|x, y| key_image_sort(x.0, y.0));
    let clsags =
      clsags.into_iter().map(|(_, clsag, commitments)| (clsag, commitments)).collect::<Vec<_>>();

    // Specify the TX's key images
    let tx = self.signable.with_key_images(key_images);

    // We now need to decide the masks for each CLSAG
    let clsag_len = clsags.len();
    let output_masks = tx.intent.sum_output_masks(&tx.key_images);
    let mut rng = tx.intent.seeded_rng(b"multisig_pseudo_out_masks");
    let mut sum_pseudo_outs = Scalar::ZERO;
    let mut to_sign = Vec::with_capacity(clsag_len);
    for (i, ((clsag_mask_send, clsag), commitments)) in clsags.into_iter().enumerate() {
      let mut mask = monero_oxide::ed25519::Scalar::random(&mut rng).into();
      if i == (clsag_len - 1) {
        mask = output_masks.into() - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }
      clsag_mask_send.send(mask);
      to_sign.push((clsag, commitments));
    }

    let tx = tx.transaction_without_signatures();
    let msg = tx.signature_hash().expect("signing a transaction which isn't signed?");

    // Iterate over each CLSAG calling sign
    let mut shares = Vec::with_capacity(to_sign.len());
    let clsags = to_sign
      .drain(..)
      .map(|(clsag, commitments)| {
        let (clsag, share) = clsag.sign(commitments, &msg)?;
        shares.push(share);
        Ok(clsag)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx, clsags }, TransactionSignatureShare(shares)))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = TransactionSignatureShare;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    Ok(TransactionSignatureShare(
      self.clsags.iter().map(|clsag| clsag.read_share(reader)).collect::<Result<_, _>>()?,
    ))
  }

  fn complete(
    mut self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    for share in shares.values() {
      if share.0.len() != self.clsags.len() {
        Err(FrostError::InternalError(
          "signature shares from another instance of the signing protocol were passed in",
        ))?;
      }
    }

    let mut tx = self.tx;
    match tx {
      Transaction::V2 {
        proofs:
          Some(RctProofs {
            prunable: RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. },
            ..
          }),
        ..
      } => {
        for (c, clsag) in self.clsags.drain(..).enumerate() {
          let (clsag, pseudo_out) = clsag.complete(
            shares.iter().map(|(l, shares)| (*l, shares.0[c].clone())).collect::<HashMap<_, _>>(),
          )?;
          clsags.push(clsag);
          pseudo_outs.push(CompressedPoint::from(pseudo_out.compress().to_bytes()));
        }
      }
      _ => unreachable!("attempted to sign a multisig TX which wasn't CLSAG"),
    }
    Ok(tx)
  }
}
