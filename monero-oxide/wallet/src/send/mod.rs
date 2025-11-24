use core::{ops::Deref, fmt};
use std_shims::{
  io, vec,
  vec::Vec,
  string::{String, ToString},
  collections::HashSet,
};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

#[cfg(feature = "compile-time-generators")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(not(feature = "compile-time-generators"))]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  io::*,
  ed25519::*,
  ringct::{
    clsag::{ClsagError, ClsagContext, Clsag},
    bulletproofs::MAX_COMMITMENTS as MAX_BULLETPROOF_COMMITMENTS,
    RctType, RctPrunable, RctProofs,
  },
  transaction::{TransactionPrefix, Transaction},
  address::{Network, SubaddressIndex, MoneroAddress},
  extra::{MAX_ARBITRARY_DATA_SIZE, MAX_EXTRA_SIZE_BY_RELAY_RULE},
  interface::FeeRate,
  ViewPair, GuaranteedViewPair, OutputWithDecoys,
};

mod tx_keys;
pub use tx_keys::TransactionKeys;
mod tx;
mod eventuality;
pub use eventuality::Eventuality;

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{TransactionMachine, TransactionSignMachine, TransactionSignatureMachine};

pub(crate) fn key_image_sort(x: &CompressedPoint, y: &CompressedPoint) -> core::cmp::Ordering {
  x.cmp(y).reverse()
}

#[derive(Clone, Zeroize)]
enum ChangeEnum {
  AddressOnly(MoneroAddress),
  Standard { view_pair: ViewPair, subaddress: Option<SubaddressIndex> },
  Guaranteed { view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex> },
}

impl PartialEq for ChangeEnum {
  fn eq(&self, other: &Self) -> bool {
    match (self, other) {
      (ChangeEnum::AddressOnly(lhs), ChangeEnum::AddressOnly(rhs)) => lhs == rhs,
      (
        ChangeEnum::Standard { view_pair: lhs_vp, subaddress: lhs_s },
        ChangeEnum::Standard { view_pair: rhs_vp, subaddress: rhs_s },
      ) => {
        bool::from(lhs_vp.spend.ct_eq(&rhs_vp.spend) & lhs_vp.view.ct_eq(&rhs_vp.view)) &
          (lhs_s == rhs_s)
      }
      (
        ChangeEnum::Guaranteed { view_pair: lhs_vp, subaddress: lhs_s },
        ChangeEnum::Guaranteed { view_pair: rhs_vp, subaddress: rhs_s },
      ) => {
        bool::from(lhs_vp.0.spend.ct_eq(&rhs_vp.0.spend) & lhs_vp.0.view.ct_eq(&rhs_vp.0.view)) &
          (lhs_s == rhs_s)
      }
      _ => false,
    }
  }
}
impl Eq for ChangeEnum {}

impl ChangeEnum {
  fn address(&self) -> MoneroAddress {
    match self {
      ChangeEnum::AddressOnly(addr) => *addr,
      // Network::Mainnet as the network won't effect the derivations
      ChangeEnum::Standard { view_pair, subaddress } => match subaddress {
        Some(subaddress) => view_pair.subaddress(Network::Mainnet, *subaddress),
        None => view_pair.legacy_address(Network::Mainnet),
      },
      ChangeEnum::Guaranteed { view_pair, subaddress } => {
        view_pair.address(Network::Mainnet, *subaddress, None)
      }
    }
  }
}

impl fmt::Debug for ChangeEnum {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let kind = match self {
      ChangeEnum::AddressOnly(addr) => {
        return f.debug_struct("ChangeEnum::AddressOnly").field("0", &addr).finish();
      }
      ChangeEnum::Standard { .. } => "ChangeEnum::Standard",
      ChangeEnum::Guaranteed { .. } => "ChangeEnum::Guaranteed",
    };
    f.debug_struct(kind).field("0", &self.address()).finish_non_exhaustive()
  }
}

/// Specification for a change output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Change(Option<ChangeEnum>);

impl Change {
  /// Create a change output specification.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn new(view_pair: ViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Standard { view_pair, subaddress }))
  }

  /// Create a change output specification for a guaranteed view pair.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn guaranteed(view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Guaranteed { view_pair, subaddress }))
  }

  /// Create a fingerprintable change output specification.
  ///
  /// You MUST assume this will harm your privacy. Only use this if you know what you're doing.
  ///
  /// If the change address is Some, this will be unable to optimize the transaction as the
  /// Monero wallet protocol expects it can (due to presumably having the view key for the change
  /// output). If a transaction should be optimized, and isn't, it will be fingerprintable.
  ///
  /// If the change address is None, there are two fingerprints:
  ///
  /// 1) The change in the TX is shunted to the fee (making it fingerprintable).
  ///
  /// 2) In two-output transactions, where the payment address doesn't have a payment ID, wallet2
  ///    includes an encrypted dummy payment ID for the non-change output in order to not allow
  ///    differentiating if transactions send to addresses with payment IDs or not. monero-wallet
  ///    includes a dummy payment ID which at least one recipient will identify as not the expected
  ///    dummy payment ID, revealing to the recipient(s) the sender is using non-wallet2 software.
  ///
  pub fn fingerprintable(address: Option<MoneroAddress>) -> Change {
    Change(address.map(ChangeEnum::AddressOnly))
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
enum InternalPayment {
  Payment(MoneroAddress, u64),
  Change(ChangeEnum),
}

impl InternalPayment {
  fn address(&self) -> MoneroAddress {
    match self {
      InternalPayment::Payment(addr, _) => *addr,
      InternalPayment::Change(change) => change.address(),
    }
  }
}

/// An error while sending Monero.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SendError {
  /// The RingCT type to produce proofs for this transaction with weren't supported.
  #[error("this library doesn't yet support that RctType")]
  UnsupportedRctType,
  /// The transaction had no inputs specified.
  #[error("no inputs")]
  NoInputs,
  /// The provided inputs were invalid.
  #[error("invalid inputs")]
  InvalidInputs,
  /// The decoy quantity was invalid for the specified RingCT type.
  #[error("invalid number of decoys")]
  InvalidDecoyQuantity,
  /// The transaction had no outputs specified.
  #[error("no outputs")]
  NoOutputs,
  /// The transaction had too many outputs specified.
  #[error("too many outputs")]
  TooManyOutputs,
  /// The transaction did not have a change output, and did not have two outputs.
  ///
  /// Monero requires all transactions have at least two outputs, assuming one payment and one
  /// change (or at least one dummy and one change). Accordingly, specifying no change and only
  /// one payment prevents creating a valid transaction
  #[error("only one output and no change address")]
  NoChange,
  /// Multiple addresses had payment IDs specified.
  ///
  /// Only one payment ID is allowed per transaction.
  #[error("multiple addresses with payment IDs")]
  MultiplePaymentIds,
  /// Too much arbitrary data was specified.
  #[error("too much data")]
  TooMuchArbitraryData,
  /// The created transaction was too large.
  #[error("too large of a transaction")]
  TooLargeTransaction,
  /// The transactions' amounts could not be represented within a `u64`.
  #[error("transaction amounts exceed u64::MAX (in {in_amount}, out {out_amount})")]
  AmountsUnrepresentable {
    /// The amount in (via inputs).
    in_amount: u128,
    /// The amount which would be out (between outputs and the fee).
    out_amount: u128,
  },
  /// This transaction could not pay for itself.
  #[error(
    "not enough funds (inputs {inputs}, outputs {outputs}, necessary_fee {necessary_fee:?})"
  )]
  NotEnoughFunds {
    /// The amount of funds the inputs contributed.
    inputs: u64,
    /// The amount of funds the outputs required.
    outputs: u64,
    /// The fee necessary to be paid on top.
    ///
    /// If this is None, it is because the fee was not calculated as the outputs alone caused this
    /// error.
    necessary_fee: Option<u64>,
  },
  /// This transaction is being signed with the wrong private key.
  #[error("wrong spend private key")]
  WrongPrivateKey,
  /// This transaction was read from a bytestream which was malicious.
  #[error("this SignableTransaction was created by deserializing a malicious serialization")]
  MaliciousSerialization,
  /// There was an error when working with the CLSAGs.
  #[error("clsag error ({0})")]
  ClsagError(ClsagError),
  /// There was an error when working with FROST.
  #[cfg(feature = "multisig")]
  #[error("frost error {0}")]
  FrostError(FrostError),
}

/// A signable transaction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignableTransaction {
  rct_type: RctType,
  outgoing_view_key: Zeroizing<[u8; 32]>,
  inputs: Vec<OutputWithDecoys>,
  payments: Vec<InternalPayment>,
  data: Vec<Vec<u8>>,
  fee_rate: FeeRate,
}

impl PartialEq for SignableTransaction {
  fn eq(&self, other: &Self) -> bool {
    (self.rct_type == other.rct_type) &&
      bool::from(self.outgoing_view_key.deref().ct_eq(other.outgoing_view_key.deref())) &&
      (self.inputs == other.inputs) &&
      (self.payments == other.payments) &&
      (self.data == other.data) &&
      (self.fee_rate == other.fee_rate)
  }
}
impl Eq for SignableTransaction {}

impl fmt::Debug for SignableTransaction {
  /// This `Debug` implementation may run in variable time and reveal everything except the
  /// `outgoing_view_key`.
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("SignableTransaction")
      .field("rct_type", &self.rct_type)
      .field("inputs", &self.inputs)
      .field("payments", &self.payments)
      .field("data", &self.data)
      .field("fee_rate", &self.fee_rate)
      .finish_non_exhaustive()
  }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SignableTransactionWithKeyImages {
  intent: SignableTransaction,
  key_images: Vec<CompressedPoint>,
}

impl SignableTransaction {
  fn validate(&self) -> Result<(), SendError> {
    match self.rct_type {
      RctType::ClsagBulletproof | RctType::ClsagBulletproofPlus => {}
      _ => Err(SendError::UnsupportedRctType)?,
    }

    if self.inputs.is_empty() {
      Err(SendError::NoInputs)?;
    }
    if self.inputs.iter().map(|input| input.key().compress()).collect::<HashSet<_>>().len() !=
      self.inputs.len()
    {
      Err(SendError::InvalidInputs)?;
    }
    for input in &self.inputs {
      if input.decoys().len() !=
        match self.rct_type {
          RctType::ClsagBulletproof => 11,
          RctType::ClsagBulletproofPlus => 16,
          _ => panic!("unsupported RctType"),
        }
      {
        Err(SendError::InvalidDecoyQuantity)?;
      }
    }

    // Check we have at least one non-change output
    if !self.payments.iter().any(|payment| matches!(payment, InternalPayment::Payment(_, _))) {
      Err(SendError::NoOutputs)?;
    }
    // If we don't have at least two outputs, as required by Monero, error
    if self.payments.len() < 2 {
      Err(SendError::NoChange)?;
    }
    // Check we don't have multiple Change outputs due to decoding a malicious serialization
    {
      let mut change_count = 0;
      for payment in &self.payments {
        change_count += usize::from(u8::from(matches!(payment, InternalPayment::Change(_))));
      }
      if change_count > 1 {
        Err(SendError::MaliciousSerialization)?;
      }
    }

    // Make sure there's at most one payment ID
    {
      let mut payment_ids = 0;
      for payment in &self.payments {
        payment_ids += usize::from(u8::from(payment.address().payment_id().is_some()));
      }
      if payment_ids > 1 {
        Err(SendError::MultiplePaymentIds)?;
      }
    }

    if self.payments.len() > MAX_BULLETPROOF_COMMITMENTS {
      Err(SendError::TooManyOutputs)?;
    }

    // Check the length of each arbitrary data
    for part in &self.data {
      if part.len() > MAX_ARBITRARY_DATA_SIZE {
        Err(SendError::TooMuchArbitraryData)?;
      }
    }

    // Check the length of TX extra
    if self.extra().len() > MAX_EXTRA_SIZE_BY_RELAY_RULE {
      Err(SendError::TooMuchArbitraryData)?;
    }

    // Make sure we have enough funds
    let weight;
    {
      let in_amount: u128 =
        self.inputs.iter().map(|input| u128::from(input.commitment().amount)).sum();
      let payments_amount: u128 = self
        .payments
        .iter()
        .filter_map(|payment| match payment {
          InternalPayment::Payment(_, amount) => Some(u128::from(*amount)),
          InternalPayment::Change(_) => None,
        })
        .sum();
      let necessary_fee;
      (weight, necessary_fee) = self.weight_and_necessary_fee();
      let out_amount = payments_amount + u128::from(necessary_fee);
      let in_out_amount = u64::try_from(in_amount)
        .and_then(|in_amount| u64::try_from(out_amount).map(|out_amount| (in_amount, out_amount)));
      let Ok((in_amount, out_amount)) = in_out_amount else {
        Err(SendError::AmountsUnrepresentable { in_amount, out_amount })?
      };
      if in_amount < out_amount {
        Err(SendError::NotEnoughFunds {
          inputs: in_amount,
          outputs: u64::try_from(payments_amount)
            .expect("total out fit within u64 but not part of total out"),
          necessary_fee: Some(necessary_fee),
        })?;
      }
    }

    // The limit is half the no-penalty block size
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/wallet/wallet2.cpp#L11076-L11085
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/cryptonote_config.h#L61
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/cryptonote_config.h#L64
    const MAX_TX_SIZE: usize = (300_000 / 2) - 600;
    if weight >= MAX_TX_SIZE {
      Err(SendError::TooLargeTransaction)?;
    }

    Ok(())
  }

  /// Create a new SignableTransaction.
  ///
  /// `outgoing_view_key` is used to seed the RNGs for this transaction. Anyone with knowledge of
  /// the outgoing view key will be able to identify a transaction produced with this methodology,
  /// and the data within it. Accordingly, it must be treated as a private key.
  ///
  /// If one `outgoing_view_key` is reused across two transactions which share keys in their
  /// inputs, such transactions being mutually incompatible with each other on that premise, some
  /// ephemeral secrets MAY be reused causing adverse effects. Do NOT reuse an `outgoing_view_key`
  /// across incompatible transactions accordingly.
  ///
  /// `data` represents arbitrary data which will be embedded into the transaction's `extra` field.
  /// Please see `Extra::arbitrary_data` for the full impacts of this.
  ///
  /// This will attempt to sign a transaction as constructed, even if the arguments are
  /// inconsistent or invalid for some view of the Monero network. It is the caller's
  /// responsibility to ensure their sanity.
  ///
  /// This function runs in time variable to the validity of the arguments and the public data.
  pub fn new(
    rct_type: RctType,
    outgoing_view_key: Zeroizing<[u8; 32]>,
    inputs: Vec<OutputWithDecoys>,
    payments: Vec<(MoneroAddress, u64)>,
    change: Change,
    data: Vec<Vec<u8>>,
    fee_rate: FeeRate,
  ) -> Result<SignableTransaction, SendError> {
    // Re-format the payments and change into a consolidated payments list
    let mut payments = payments
      .into_iter()
      .map(|(addr, amount)| InternalPayment::Payment(addr, amount))
      .collect::<Vec<_>>();

    if let Some(change) = change.0 {
      payments.push(InternalPayment::Change(change));
    }

    let mut res =
      SignableTransaction { rct_type, outgoing_view_key, inputs, payments, data, fee_rate };
    res.validate()?;

    // Shuffle the payments
    {
      let mut rng = res.seeded_rng(b"shuffle_payments");
      res.payments.shuffle(&mut rng);
    }

    Ok(res)
  }

  /// The fee rate this transaction uses.
  pub fn fee_rate(&self) -> FeeRate {
    self.fee_rate
  }

  /// The fee this transaction requires.
  ///
  /// This is distinct from the fee this transaction will use. If no change output is specified,
  /// all unspent coins will be shunted to the fee.
  pub fn necessary_fee(&self) -> u64 {
    self.weight_and_necessary_fee().1
  }

  /// Write a SignableTransaction.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(addr, amount) => {
          w.write_all(&[0])?;
          write_vec(write_byte, addr.to_string().as_bytes(), w)?;
          w.write_all(&amount.to_le_bytes())
        }
        InternalPayment::Change(change) => match change {
          ChangeEnum::AddressOnly(addr) => {
            w.write_all(&[1])?;
            write_vec(write_byte, addr.to_string().as_bytes(), w)
          }
          ChangeEnum::Standard { view_pair, subaddress } => {
            w.write_all(&[2])?;
            view_pair.spend().compress().write(w)?;
            view_pair.view.write(w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
          ChangeEnum::Guaranteed { view_pair, subaddress } => {
            w.write_all(&[3])?;
            view_pair.spend().compress().write(w)?;
            view_pair.0.view.write(w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
        },
      }
    }

    write_byte(&u8::from(self.rct_type), w)?;
    w.write_all(self.outgoing_view_key.as_slice())?;
    write_vec(OutputWithDecoys::write, &self.inputs, w)?;
    write_vec(write_payment, &self.payments, w)?;
    write_vec(|data, w| write_vec(write_byte, data, w), &self.data, w)?;
    self.fee_rate.write(w)
  }

  /// Serialize the SignableTransaction to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    self.write(&mut buf).expect("write failed but <Vec as io::Write> doesn't fail");
    buf
  }

  /// Read a `SignableTransaction`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<SignableTransaction> {
    fn read_address<R: io::Read>(r: &mut R) -> io::Result<MoneroAddress> {
      String::from_utf8(read_vec(read_byte, Some(MoneroAddress::SIZE_UPPER_BOUND.0), r)?)
        .ok()
        .and_then(|str| MoneroAddress::from_str_with_unchecked_network(&str).ok())
        .ok_or_else(|| io::Error::other("invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment(read_address(r)?, read_u64(r)?),
        1 => InternalPayment::Change(ChangeEnum::AddressOnly(read_address(r)?)),
        2 => InternalPayment::Change(ChangeEnum::Standard {
          view_pair: ViewPair::new(
            CompressedPoint::read(r)?
              .decompress()
              .ok_or_else(|| io::Error::other("`Change` payment had invalid public spend key"))?,
            Zeroizing::new(Scalar::read(r)?),
          )
          .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        3 => InternalPayment::Change(ChangeEnum::Guaranteed {
          view_pair: GuaranteedViewPair::new(
            CompressedPoint::read(r)?.decompress().ok_or_else(|| {
              io::Error::other("guaranteed `Change` payment had invalid public spend key")
            })?,
            Zeroizing::new(Scalar::read(r)?),
          )
          .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        _ => Err(io::Error::other("invalid payment"))?,
      })
    }

    let res = SignableTransaction {
      rct_type: RctType::try_from(read_byte(r)?)
        .map_err(|()| io::Error::other("unsupported/invalid RctType"))?,
      outgoing_view_key: Zeroizing::new(read_bytes(r)?),
      inputs: read_vec(OutputWithDecoys::read, Some(TransactionPrefix::INPUTS_UPPER_BOUND.0), r)?,
      payments: read_vec(read_payment, Some(MAX_BULLETPROOF_COMMITMENTS), r)?,
      /*
        This doesn't assert the _total_ length is `< MAX_EXTRA_SIZE_BY_RELAY_RULE`, yet the
        following call to `validate` will.
      */
      data: read_vec(
        |r| read_vec(read_byte, Some(MAX_ARBITRARY_DATA_SIZE), r),
        Some(MAX_EXTRA_SIZE_BY_RELAY_RULE),
        r,
      )?,
      fee_rate: FeeRate::read(r)?,
    };
    match res.validate() {
      Ok(()) => {}
      Err(e) => Err(io::Error::other(e))?,
    }
    Ok(res)
  }

  fn with_key_images(
    mut self,
    mut key_images: Vec<CompressedPoint>,
  ) -> SignableTransactionWithKeyImages {
    debug_assert_eq!(self.inputs.len(), key_images.len());

    // Sort the inputs by their key images
    let mut sorted_inputs = self.inputs.drain(..).zip(key_images.drain(..)).collect::<Vec<_>>();
    sorted_inputs
      .sort_by(|(_, key_image_a), (_, key_image_b)| key_image_sort(key_image_a, key_image_b));

    for (input, key_image) in sorted_inputs {
      self.inputs.push(input);
      key_images.push(key_image);
    }

    SignableTransactionWithKeyImages { intent: self, key_images }
  }

  /// Fetch what the transaction will be, without its signatures (and associated fields).
  ///
  /// This returns `None` if an improper amount of key images is provided.
  pub fn unsigned_transaction(self, key_images: Vec<CompressedPoint>) -> Option<Transaction> {
    if self.inputs.len() != key_images.len() {
      None?
    };
    Some(self.with_key_images(key_images).transaction_without_signatures())
  }

  /// Sign this transaction.
  ///
  /// This function runs in time variable to the validity of the arguments and the public data.
  pub fn sign(
    self,
    rng: &mut (impl RngCore + CryptoRng),
    sender_spend_key: &Zeroizing<Scalar>,
  ) -> Result<Transaction, SendError> {
    let sender_spend_key = Zeroizing::new((**sender_spend_key).into());

    // Calculate the key images
    let mut key_images = vec![];
    for input in &self.inputs {
      let input_key = Zeroizing::new(sender_spend_key.deref() + input.key_offset().into());
      if bool::from(!(input_key.deref() * ED25519_BASEPOINT_TABLE).ct_eq(&input.key().into())) {
        Err(SendError::WrongPrivateKey)?;
      }
      let key_image = Point::from(
        input_key.deref() * Point::biased_hash(input.key().compress().to_bytes()).into(),
      );
      key_images.push(key_image.compress());
    }

    // Convert to a SignableTransactionWithKeyImages
    let tx = self.with_key_images(key_images);

    // Prepare the CLSAG signatures
    let mut clsag_signs = Vec::with_capacity(tx.intent.inputs.len());
    for input in &tx.intent.inputs {
      // Re-derive the input key as this will be in a different order
      let input_key =
        Zeroizing::new(Scalar::from(sender_spend_key.deref() + input.key_offset().into()));
      clsag_signs.push((
        input_key,
        ClsagContext::new(input.decoys().clone(), input.commitment().clone())
          .map_err(SendError::ClsagError)?,
      ));
    }

    // Get the output commitments' mask sum
    let mask_sum = tx.intent.sum_output_masks(&tx.key_images);

    // Get the actual TX, just needing the CLSAGs
    let mut tx = tx.transaction_without_signatures();

    // Sign the CLSAGs
    let clsags_and_pseudo_outs = Clsag::sign(
      rng,
      clsag_signs,
      mask_sum,
      tx.signature_hash().expect("signing a transaction which isn't signed?"),
    )
    .map_err(SendError::ClsagError)?;

    // Fill in the CLSAGs/pseudo-outs
    let inputs_len = tx.prefix().inputs.len();
    let Transaction::V2 {
      proofs:
        Some(RctProofs {
          prunable: RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. },
          ..
        }),
      ..
    } = tx
    else {
      panic!("not signing clsag?")
    };
    *clsags = Vec::with_capacity(inputs_len);
    *pseudo_outs = Vec::with_capacity(inputs_len);
    for (clsag, pseudo_out) in clsags_and_pseudo_outs {
      clsags.push(clsag);
      pseudo_outs.push(pseudo_out.compress());
    }

    // Return the signed TX
    Ok(tx)
  }
}
