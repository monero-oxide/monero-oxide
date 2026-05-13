#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use std_shims::{sync::LazyLock, vec, vec::Vec, io};

use rand_core::{RngCore, CryptoRng};
use zeroize::Zeroize;

use generic_array::typenum::U;

use blake2::digest::Update;

use dalek_ff_group::{EdwardsPoint, Ed25519};
use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding as _},
  Ciphersuite,
};
use helioselene::{Selene, Helios};

use generalized_bulletproofs_ec_gadgets::*;
pub use fcmps;
use fcmps::*;

use monero_primitives::Blake2bMonero;
use monero_ed25519::CompressedPoint;
use monero_fcmp_plus_plus_generators::{
  FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, HELIOS_HASH_INIT, SELENE_HASH_INIT,
};

/// The Spend-Authorization and Linkability proof.
pub mod sal;
use sal::*;

#[cfg(test)]
mod tests;

/// The discrete-log gadget parameters for Ed25519.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519Params;
impl DiscreteLogParameter for Ed25519Params {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Ed25519 as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The discrete-log gadget parameters for Selene.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeleneParams;
impl DiscreteLogParameter for SeleneParams {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Selene as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The discrete-log gadget parameters for Helios.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeliosParams;
impl DiscreteLogParameter for HeliosParams {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Helios as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The curves to use with the FCMP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Curves;
impl FcmpCurves for Curves {
  type OC = Ed25519;
  type OcParameters = Ed25519Params;
  type C1 = Selene;
  type C1Parameters = SeleneParams;
  type C2 = Helios;
  type C2Parameters = HeliosParams;
}

include!(concat!(env!("OUT_DIR"), "/generators.rs"));

pub(crate) static T: LazyLock<EdwardsPoint> =
  LazyLock::new(|| EdwardsPoint(CompressedPoint::T.decompress().unwrap().into()));

/// The parameters for an FCMP.
// TODO: Don't expose this directly
pub static FCMP_PARAMS: LazyLock<FcmpParams<Curves>> = LazyLock::new(|| {
  FcmpParams::<Curves>::new(
    SELENE_FCMP_GENERATORS.generators.clone(),
    HELIOS_FCMP_GENERATORS.generators.clone(),
    // Hash init generators
    *SELENE_HASH_INIT,
    *HELIOS_HASH_INIT,
    // G, T, U, V
    <Ed25519 as Ciphersuite>::generator(),
    *T,
    EdwardsPoint((*FCMP_PLUS_PLUS_U).into()),
    EdwardsPoint((*FCMP_PLUS_PLUS_V).into()),
  )
});

/// An input tuple.
///
/// The FCMP crate has this same object yet with a distinct internal layout. This definition should
/// be preferred.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Input {
  O_tilde: [u8; 32],
  I_tilde: [u8; 32],
  R: [u8; 32],
  C_tilde: [u8; 32],
}

impl Input {
  // Write an Input without the pseudo-out.
  fn write_partial(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.O_tilde)?;
    writer.write_all(&self.I_tilde)?;
    writer.write_all(&self.R)
  }

  fn read_partial(C_tilde: [u8; 32], reader: &mut impl io::Read) -> io::Result<Input> {
    Ok(Self {
      O_tilde: monero_io::read_bytes(reader)?,
      I_tilde: monero_io::read_bytes(reader)?,
      R: monero_io::read_bytes(reader)?,
      C_tilde,
    })
  }

  fn transcript(&self, transcript: &mut Blake2bMonero, L: <Ed25519 as Ciphersuite>::G) {
    transcript.update(&self.O_tilde);
    transcript.update(&self.I_tilde);
    transcript.update(&self.C_tilde);
    transcript.update(&self.R);
    transcript.update(&L.to_bytes());
  }

  /// O~ from the input commitment.
  pub fn O_tilde(&self) -> [u8; 32] {
    self.O_tilde
  }

  /// I~ from the input commitment.
  pub fn I_tilde(&self) -> [u8; 32] {
    self.I_tilde
  }

  /// R from the input commitment.
  pub fn R(&self) -> [u8; 32] {
    self.R
  }

  /// C~ from the input commitment (the pseudo-out).
  pub fn C_tilde(&self) -> [u8; 32] {
    self.C_tilde
  }
}

/// A FCMP++ output tuple.
pub type Output = fcmps::Output<<Ed25519 as Ciphersuite>::G>;

/// An error encountered when working with FCMP++.
#[derive(Debug)]
pub enum FcmpPlusPlusError {
  /// An invalid quantity of key images was provided.
  InvalidKeyImageQuantity,
  /// A propagated FCMP error.
  FcmpError(FcmpError),
}
impl From<FcmpError> for FcmpPlusPlusError {
  fn from(err: FcmpError) -> FcmpPlusPlusError {
    FcmpPlusPlusError::FcmpError(err)
  }
}

/// A FCMP++ proof for a set of inputs.
#[derive(Clone, Debug, Zeroize)]
pub struct FcmpPlusPlus {
  inputs: Vec<(Input, SpendAuthAndLinkability)>,
  fcmp: Fcmp<Curves>,
}

impl FcmpPlusPlus {
  /// Create a new FCMP++ proof from its components.
  pub fn new(inputs: Vec<(Input, SpendAuthAndLinkability)>, fcmp: Fcmp<Curves>) -> FcmpPlusPlus {
    FcmpPlusPlus { inputs, fcmp }
  }

  /// The size of a FCMP++ proof.
  pub fn proof_size(inputs: usize, layers: usize) -> usize {
    // Each input tuple, without C~, each SAL, and the FCMP
    (inputs * ((3 * 32) + (12 * 32))) + Fcmp::<Curves>::proof_size(inputs, layers)
  }

  /// Write a FCMP++ proof.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    for (input, spend_auth_and_linkability) in &self.inputs {
      input.write_partial(writer)?;
      spend_auth_and_linkability.write(writer)?;
    }
    self.fcmp.write(writer)
  }

  /// Read an FCMP++.
  ///
  /// The pseudo-outs are passed in as Monero already defines a field for them. It's less annoying
  /// to receive them here than to move them into here and expose them to Monero. It also informs
  /// us of how many inputs we're reading a proof for.
  ///
  /// The amount of layers for the FCMP are also passed in here as the FCMP's length is variable to
  /// that.
  pub fn read(
    pseudo_outs: &[[u8; 32]],
    layers: usize,
    reader: &mut impl io::Read,
  ) -> io::Result<Self> {
    let mut inputs = vec![];
    for pseudo_out in pseudo_outs {
      inputs
        .push((Input::read_partial(*pseudo_out, reader)?, SpendAuthAndLinkability::read(reader)?));
    }
    let fcmp = Fcmp::read(reader, pseudo_outs.len(), layers)?;
    Ok(Self { inputs, fcmp })
  }

  /// Verify an FCMP++.
  ///
  /// See [`Fcmp::verify`] for further context.
  ///
  /// `signable_tx_hash` must be binding to the transaction prefix, the RingCT base, and the
  /// pseudo-outs.
  ///
  /// This only queues the proofs for batch verification. The BatchVerifiers MUST also be verified.
  ///
  /// If this function returns an error, the BatchVerifiers MUST be considered corrupted and
  /// discarded.
  #[allow(clippy::too_many_arguments)]
  pub fn verify(
    &self,
    rng: &mut (impl RngCore + CryptoRng),
    verifier_ed: &mut multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
    verifier_1: &mut generalized_bulletproofs::BatchVerifier<Selene>,
    verifier_2: &mut generalized_bulletproofs::BatchVerifier<Helios>,
    tree: TreeRoot<<Curves as FcmpCurves>::C1, <Curves as FcmpCurves>::C2>,
    layers: usize,
    signable_tx_hash: [u8; 32],
    key_images: Vec<<Ed25519 as Ciphersuite>::G>,
  ) -> Result<(), FcmpPlusPlusError> {
    if self.inputs.len() != key_images.len() {
      Err(FcmpPlusPlusError::InvalidKeyImageQuantity)?;
    }

    let mut fcmp_inputs = Vec::with_capacity(self.inputs.len());
    for ((input, spend_auth_and_linkability), key_image) in self.inputs.iter().zip(key_images) {
      spend_auth_and_linkability
        .verify(rng, verifier_ed, signable_tx_hash, input, key_image)
        .map_err(|e| FcmpPlusPlusError::FcmpError(FcmpError::IoError(e)))?;

      let O_tilde = Ed25519::read_G(&mut input.O_tilde.as_slice())
        .map_err(|e| FcmpPlusPlusError::FcmpError(FcmpError::IoError(e)))?;
      let I_tilde = Ed25519::read_G(&mut input.I_tilde.as_slice())
        .map_err(|e| FcmpPlusPlusError::FcmpError(FcmpError::IoError(e)))?;
      let R = Ed25519::read_G(&mut input.R.as_slice())
        .map_err(|e| FcmpPlusPlusError::FcmpError(FcmpError::IoError(e)))?;
      let C_tilde = Ed25519::read_G(&mut input.C_tilde.as_slice())
        .map_err(|e| FcmpPlusPlusError::FcmpError(FcmpError::IoError(e)))?;
      fcmp_inputs.push(fcmps::Input::new(O_tilde, I_tilde, R, C_tilde)?);
    }

    Ok(self.fcmp.verify(rng, verifier_1, verifier_2, &*FCMP_PARAMS, tree, layers, &fcmp_inputs)?)
  }
}
