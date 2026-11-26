#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use core::{marker::PhantomData, borrow::Borrow};
extern crate alloc;
use std_shims::{prelude::*, io};

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize, Zeroizing};

use blake2::{
  digest::{consts::U32, Digest as _},
  Blake2b,
};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField, FromUniformBytes},
    Group, GroupEncoding,
  },
  Ciphersuite,
};

use ec_divisors::DivisorCurve;
use generalized_bulletproofs::{
  BatchVerifier, PedersenVectorCommitment,
  transcript::{Transcript as ProverTranscript, VerifierTranscript},
  arithmetic_circuit_proof::{AcStatementError, AcProveError, AcVerifyError},
};

mod gadgets;
pub(crate) use gadgets::*;
mod circuit;
pub(crate) use circuit::*;
pub use circuit::FcmpCurves;

mod prover;
pub use prover::*;

mod tape;
use tape::*;

mod params;
pub use params::*;

/// Functions for tree building and maintenance.
pub mod tree;

#[cfg(test)]
mod tests;

/// The length of branches proved for on the first layer.
///
/// The leaves' layer is six times as wide.
pub const LAYER_ONE_LEN: usize = 38;
/// The length of branches proved for on the second layer.
pub const LAYER_TWO_LEN: usize = 18;
#[cfg(test)]
const TARGET_LAYERS: usize = 8;

const C1_LEAVES_ROWS_PER_INPUT: usize = 97;
const C1_BRANCH_ROWS_PER_INPUT: usize = 52;
const C2_ROWS_PER_INPUT_PER_LAYER: usize = 32;

const C1_TARGET_ROWS: usize = 256;
const C2_TARGET_ROWS: usize = 128;

/// A struct representing an output tuple.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Output<G: Group> {
  O: G,
  I: G,
  C: G,
}

impl<G: Group> Output<G> {
  /// Construct a new Output tuple.
  pub fn new(O: G, I: G, C: G) -> Result<Self, FcmpError> {
    if bool::from(O.is_identity()) || bool::from(I.is_identity()) || bool::from(C.is_identity()) {
      Err(FcmpError::IdentityPoint)?;
    }
    Ok(Output { O, I, C })
  }

  /// The O element of the output tuple.
  pub fn O(&self) -> G {
    self.O
  }
  /// The I element of the output tuple.
  pub fn I(&self) -> G {
    self.I
  }
  /// The C element of the output tuple.
  pub fn C(&self) -> G {
    self.C
  }
}

/// A struct representing an input tuple.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Input<F: PrimeField> {
  O_tilde: (F, F),
  I_tilde: (F, F),
  R: (F, F),
  C_tilde: (F, F),
}

impl<F: PrimeField> Input<F> {
  /// Construct a new input tuple.
  pub fn new<G: DivisorCurve<FieldElement = F>>(
    O_tilde: G,
    I_tilde: G,
    R: G,
    C_tilde: G,
  ) -> Result<Self, FcmpError> {
    Ok(Input {
      O_tilde: G::to_xy(O_tilde).ok_or(FcmpError::IdentityPoint)?,
      I_tilde: G::to_xy(I_tilde).ok_or(FcmpError::IdentityPoint)?,
      R: G::to_xy(R).ok_or(FcmpError::IdentityPoint)?,
      C_tilde: G::to_xy(C_tilde).ok_or(FcmpError::IdentityPoint)?,
    })
  }
}

/// A tree root, represented as a point from either curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeRoot<C1: Ciphersuite, C2: Ciphersuite> {
  /// A root on the first curve.
  C1(C1::G),
  /// A root on the second curve.
  C2(C2::G),
}

#[derive(Clone)]
pub(crate) struct TranscriptedInput<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  pub(crate) O: (Variable, Variable),
  pub(crate) I: (Variable, Variable),
  pub(crate) C: (Variable, Variable),
  pub(crate) o_blind_claim: PointWithDlog<C::OcParameters>,
  pub(crate) i_blind_u_claim: PointWithDlog<C::OcParameters>,
  pub(crate) i_blind_v_claim: PointWithDlog<C::OcParameters>,
  pub(crate) i_blind_blind_claim: PointWithDlog<C::OcParameters>,
  pub(crate) c_blind_claim: PointWithDlog<C::OcParameters>,
}

/// An error encountered while working with FCMPs.
#[derive(Debug)]
pub enum FcmpError {
  /// A point was identity when it isn't allowed to be.
  IdentityPoint,
  /// An incorrect quantity of blinds was provided.
  IncorrectBlindQuantity,
  /// Not enough generators to work with this FCMP.
  NotEnoughGenerators,
  /// The proof was empty (no inputs proven for or no elements in tree).
  EmptyProof,
  /// A propagated IO error.
  IoError(io::Error),
  /// A propagated arithmetic circuit statement error.
  AcStatementError(AcStatementError),
  /// A propagated arithmetic circuit prover error.
  AcProveError(AcProveError),
  /// A propagated arithmetic circuit verifier error.
  AcVerifyError(AcVerifyError),
}
impl From<io::Error> for FcmpError {
  fn from(err: io::Error) -> Self {
    FcmpError::IoError(err)
  }
}
impl From<AcStatementError> for FcmpError {
  fn from(err: AcStatementError) -> Self {
    FcmpError::AcStatementError(err)
  }
}
impl From<AcProveError> for FcmpError {
  fn from(err: AcProveError) -> Self {
    FcmpError::AcProveError(err)
  }
}
impl From<AcVerifyError> for FcmpError {
  fn from(err: AcVerifyError) -> Self {
    FcmpError::AcVerifyError(err)
  }
}

/// The full-chain membership proof.
#[derive(Clone, Debug)]
pub struct Fcmp<C> {
  _curves: PhantomData<C>,
  proof: Vec<u8>,
  root_blind_pok: [u8; 64],
}
impl<C> Zeroize for Fcmp<C> {
  fn zeroize(&mut self) {
    let Self { _curves: PhantomData, proof, root_blind_pok } = self;
    proof.zeroize();
    root_blind_pok.zeroize();
  }
}

impl<C> Fcmp<C> {
  /// Returns how many rows would be used in each of the two IPAs.
  ///
  /// This may panic if too many inputs/layers are specified, causing an overflow. This may return
  /// an incorrect value if either `inputs` or `layers` is zero.
  pub const fn ipa_rows(inputs: usize, layers: usize) -> (usize, usize) {
    // usize::max isn't `const`
    const fn const_max(a: usize, b: usize) -> usize {
      if a < b {
        b
      } else {
        a
      }
    }

    let non_leaves_c1_branches = layers.saturating_sub(1) / 2;
    let c1_rows =
      inputs * (C1_LEAVES_ROWS_PER_INPUT + (non_leaves_c1_branches * C1_BRANCH_ROWS_PER_INPUT));

    let c2_branches = layers / 2;
    let c2_rows = inputs * const_max(c2_branches * C2_ROWS_PER_INPUT_PER_LAYER, 1);

    let c1_rows = c1_rows.next_power_of_two();
    let c2_rows = c2_rows.next_power_of_two();
    (const_max(c1_rows, C1_TARGET_ROWS), const_max(c2_rows, C2_TARGET_ROWS))
  }
}

impl<C: FcmpCurves> Fcmp<C>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::F: FromUniformBytes<64>,
  <C::C2 as Ciphersuite>::F: FromUniformBytes<64>,
{
  /// The proof size for a FCMP proving for so many inputs in a tree with so many layers.
  ///
  /// This assumes points and scalars are each encoded as 32 bytes for all relevant curves.
  pub fn proof_size(inputs: usize, layers: usize) -> usize {
    let mut proof_elements = 16; // AI, AO, AS, tau_x, u, t_caret, a, b for each BP

    let (c1_padded_pow_2, c2_padded_pow_2) = Self::ipa_rows(inputs, layers);

    {
      let base = c1_padded_pow_2;
      let mut res = 1;
      while res < base {
        res <<= 1;
        proof_elements += 2;
      }
    }
    {
      let base = c2_padded_pow_2;
      let mut res = 1;
      while res < base {
        res <<= 1;
        proof_elements += 2;
      }
    }

    let c1_root = layers % 2;
    let c2_root = 1 - c1_root;
    let c1_branches = (inputs * (layers / 2)) + c1_root;
    let c2_branches = (inputs * ((layers / 2) - c2_root)) + c2_root;

    const WORDS_PER_DLOG: usize = 2;
    const WORDS_PER_DIVISOR: usize = 2;
    const WORDS_PER_CLAIMED_POINT: usize = WORDS_PER_DLOG + WORDS_PER_DIVISOR;

    let c1_words = (inputs * (WORDS_PER_DIVISOR + (4 * WORDS_PER_CLAIMED_POINT))) +
      ((inputs * ((layers - 1) / 2)) * WORDS_PER_CLAIMED_POINT);
    let c2_words = (inputs * (layers / 2)) * WORDS_PER_CLAIMED_POINT;

    {
      let c1_commitments = c1_branches + (c1_words * COMMITMENT_WORD_LEN).div_ceil(c1_padded_pow_2);
      let ni = 2 + (2 * c1_commitments);
      let l_r_poly_len = 1 + ni + 1;
      let t_poly_len = (2 * l_r_poly_len) - 1;
      let t_commitments = t_poly_len - (ni / 2) - 1;
      proof_elements += c1_commitments + t_commitments;
    }

    {
      let c2_commitments = c2_branches + (c2_words * COMMITMENT_WORD_LEN).div_ceil(c2_padded_pow_2);
      let ni = 2 + (2 * c2_commitments);
      let l_r_poly_len = 1 + ni + 1;
      let t_poly_len = (2 * l_r_poly_len) - 1;
      let t_commitments = t_poly_len - (ni / 2) - 1;
      proof_elements += c2_commitments + t_commitments;
    }

    // This assumes 32 bytes per proof element, then 64 bytes for the PoK
    (32 * proof_elements) + 64
  }

  fn transcript(
    tree: TreeRoot<C::C1, C::C2>,
    inputs: &[impl Borrow<Input<<C::C1 as Ciphersuite>::F>>],
    root_blind_R: &[u8],
  ) -> [u8; 32] {
    let mut res = Blake2b::<U32>::new();

    // Transcript the tree root
    match tree {
      TreeRoot::C1(p) => {
        res.update([0]);
        res.update(p.to_bytes());
      }
      TreeRoot::C2(p) => {
        res.update([1]);
        res.update(p.to_bytes());
      }
    }

    // Transcript the input tuples
    res.update(u32::try_from(inputs.len()).unwrap().to_le_bytes());
    for input in inputs {
      let input = input.borrow();
      res.update(input.O_tilde.0.to_repr());
      res.update(input.O_tilde.1.to_repr());
      res.update(input.I_tilde.0.to_repr());
      res.update(input.I_tilde.1.to_repr());
      res.update(input.R.0.to_repr());
      res.update(input.R.1.to_repr());
      res.update(input.C_tilde.0.to_repr());
      res.update(input.C_tilde.1.to_repr());
    }

    // Transcript the nonce for the difference of the root and our output VC of the root
    res.update(root_blind_R);

    res.finalize().into()
  }

  // Prove for a single input's membership
  #[allow(clippy::too_many_arguments, clippy::type_complexity)]
  fn input(
    params: &FcmpParams<C>,
    layers: usize,
    transcript: &mut impl Transcript,
    c1_circuit: &mut Circuit<C::C1>,
    c1_dlog_challenge: &mut Option<(
      DiscreteLogChallenge<<C::C1 as Ciphersuite>::F, C::C2Parameters>,
      ChallengedGenerator<<C::C1 as Ciphersuite>::F, C::C2Parameters>,
    )>,
    c2_circuit: &mut Circuit<C::C2>,
    c2_dlog_challenge: &mut Option<(
      DiscreteLogChallenge<<C::C2 as Ciphersuite>::F, C::C1Parameters>,
      ChallengedGenerator<<C::C2 as Ciphersuite>::F, C::C1Parameters>,
    )>,
    root: Vec<Variable>,
    c1_branches: &mut impl Iterator<Item = Vec<Variable>>,
    c2_branches: &mut impl Iterator<Item = Vec<Variable>>,
    c1_commitments: &mut impl Iterator<
      Item = (
        (<C::C1 as Ciphersuite>::G, Option<<C::C1 as Ciphersuite>::F>),
        PointWithDlog<C::C1Parameters>,
      ),
    >,
    c2_commitments: &mut impl Iterator<
      Item = (
        (<C::C2 as Ciphersuite>::G, Option<<C::C2 as Ciphersuite>::F>),
        PointWithDlog<C::C2Parameters>,
      ),
    >,
    input: &Input<<C::C1 as Ciphersuite>::F>,
    opening: TranscriptedInput<C>,
  ) -> Result<(), FcmpError> {
    // Open the input tuple to the output and prove its membership on the first branch
    c1_circuit.first_layer(
      transcript,
      &CurveSpec {
        a: <<C::OC as Ciphersuite>::G as DivisorCurve>::a(),
        b: <<C::OC as Ciphersuite>::G as DivisorCurve>::b(),
      },
      &params.T_table,
      &params.U_table,
      &params.V_table,
      &params.G_table,
      //
      input.O_tilde,
      opening.o_blind_claim,
      opening.O,
      //
      input.I_tilde,
      opening.i_blind_u_claim,
      opening.I,
      //
      input.R,
      opening.i_blind_v_claim,
      opening.i_blind_blind_claim,
      //
      input.C_tilde,
      opening.c_blind_claim,
      opening.C,
      //
      // If the leaves are the only layer, the root branch is the leaves
      // Else, the first C1 branch is the leaves
      (if layers == 1 { root.clone() } else { c1_branches.next().unwrap() })
        .chunks(6)
        .map(|chunk| {
          assert_eq!(chunk.len(), 6);
          chunk.to_vec()
        })
        .collect(),
    );

    let amount_of_c1_branches = (layers / 2) + (layers % 2);
    let amount_of_non_leaf_c1_branches = amount_of_c1_branches - 1;
    let amount_of_c2_branches = layers / 2;

    // Populate the challenges if they weren't prior
    if (c1_dlog_challenge.is_none()) && (amount_of_non_leaf_c1_branches != 0) {
      *c1_dlog_challenge = Some(c1_circuit.additional_layer_discrete_log_challenge(
        transcript,
        &CurveSpec {
          a: <<C::C2 as Ciphersuite>::G as DivisorCurve>::a(),
          b: <<C::C2 as Ciphersuite>::G as DivisorCurve>::b(),
        },
        &params.H_2_table,
      ));
    }

    if (c2_dlog_challenge.is_none()) && (amount_of_c2_branches != 0) {
      *c2_dlog_challenge = Some(c2_circuit.additional_layer_discrete_log_challenge(
        transcript,
        &CurveSpec {
          a: <<C::C1 as Ciphersuite>::G as DivisorCurve>::a(),
          b: <<C::C1 as Ciphersuite>::G as DivisorCurve>::b(),
        },
        &params.H_1_table,
      ));
    }

    let root_is_c1 = (layers % 2) == 1;

    // Take the branches for this input
    // We've already taken the leaf branch, so we only have to take the non-leaf branch
    // We don't take the root branch from the iterator as we were passed it separately
    let these_c1_branches = c1_branches
      .take(amount_of_non_leaf_c1_branches.saturating_sub(usize::from(u8::from(root_is_c1))));
    let these_c2_branches =
      c2_branches.take(amount_of_c2_branches - usize::from(u8::from(!root_is_c1)));
    // Now extend the proper iterator with the root
    let (c1_chain, c2_chain) = if root_is_c1 { (Some(root), None) } else { (None, Some(root)) };
    let these_c1_branches = these_c1_branches.map(Some).chain(core::iter::once(c1_chain)).flatten();
    let these_c2_branches = these_c2_branches.map(Some).chain(core::iter::once(c2_chain)).flatten();

    // Each branch represents a layer, which also opens the prior layer's commitment
    for (branch, ((mut prior_commitment, prior_blind), prior_blind_opening)) in
      these_c1_branches.zip(c2_commitments)
    {
      prior_commitment += params.curve_2_hash_init;
      let (hash_x, hash_y, _) = c1_circuit.mul(
        None,
        None,
        prior_blind.map(|blind| {
          // Only reachable if the blind happens to be the discrete log of the commitment
          // (negligible probability)
          <C::C2 as Ciphersuite>::G::to_xy(
            prior_commitment - (params.curve_2_generators.h() * blind),
          )
          .unwrap()
        }),
      );

      c1_circuit.additional_layer(
        &CurveSpec {
          a: <<C::C2 as Ciphersuite>::G as DivisorCurve>::a(),
          b: <<C::C2 as Ciphersuite>::G as DivisorCurve>::b(),
        },
        c1_dlog_challenge.as_ref().unwrap(),
        <C::C2 as Ciphersuite>::G::to_xy(prior_commitment).ok_or(FcmpError::IdentityPoint)?,
        prior_blind_opening,
        (hash_x, hash_y),
        branch,
      );
    }

    for (branch, ((mut prior_commitment, prior_blind), prior_blind_opening)) in
      these_c2_branches.zip(c1_commitments)
    {
      prior_commitment += params.curve_1_hash_init;
      let (hash_x, hash_y, _) = c2_circuit.mul(
        None,
        None,
        prior_blind.map(|blind| {
          <C::C1 as Ciphersuite>::G::to_xy(
            prior_commitment - (params.curve_1_generators.h() * blind),
          )
          .unwrap()
        }),
      );
      c2_circuit.additional_layer(
        &CurveSpec {
          a: <<C::C1 as Ciphersuite>::G as DivisorCurve>::a(),
          b: <<C::C1 as Ciphersuite>::G as DivisorCurve>::b(),
        },
        c2_dlog_challenge.as_ref().unwrap(),
        <C::C1 as Ciphersuite>::G::to_xy(prior_commitment).ok_or(FcmpError::IdentityPoint)?,
        prior_blind_opening,
        (hash_x, hash_y),
        branch,
      );
    }

    Ok(())
  }

  /// Prove a FCMP.
  ///
  /// This function MAY panic upon an invalid witness, despite returning a result.
  ///
  /// This functions runs in variable-time for paths which aren't full (paths which run along the
  /// latest edge of the tree).
  // We want to consume the single-use `BranchesWithBlinds`, hence `needless_pass_by_value`
  #[allow(clippy::needless_pass_by_value)]
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &FcmpParams<C>,
    branches: BranchesWithBlinds<C>,
  ) -> Result<Self, FcmpError>
  where
    <C::C1 as Ciphersuite>::G: GroupEncoding<Repr = [u8; 32]>,
    <C::C2 as Ciphersuite>::G: GroupEncoding<Repr = [u8; 32]>,
  {
    let tree: TreeRoot<C::C1, C::C2> = match &branches.root {
      RootBranch::Leaves(leaves) => {
        let mut items = Vec::with_capacity(leaves.len());
        for (scalar, point) in leaves
          .iter()
          .flat_map(|output| {
            let O = <C::OC as Ciphersuite>::G::to_xy(output.O).unwrap();
            let I = <C::OC as Ciphersuite>::G::to_xy(output.I).unwrap();
            let C = <C::OC as Ciphersuite>::G::to_xy(output.C).unwrap();
            [O.0, O.1, I.0, I.1, C.0, C.1]
          })
          .zip(params.curve_1_generators.g_bold_slice())
        {
          items.push((scalar, *point));
        }
        TreeRoot::C1(params.curve_1_hash_init + multiexp::multiexp(&items))
      }
      RootBranch::C1(branches) => {
        let mut items = Vec::with_capacity(branches.len());
        for (scalar, point) in branches.iter().zip(params.curve_1_generators.g_bold_slice()) {
          items.push((*scalar, *point));
        }
        TreeRoot::C1(params.curve_1_hash_init + multiexp::multiexp(&items))
      }
      RootBranch::C2(branches) => {
        let mut items = Vec::with_capacity(branches.len());
        for (scalar, point) in branches.iter().zip(params.curve_2_generators.g_bold_slice()) {
          items.push((*scalar, *point));
        }
        TreeRoot::C2(params.curve_2_hash_init + multiexp::multiexp(&items))
      }
    };

    let inputs = branches.per_input.len();
    let layers = usize::from(u8::from(branches.per_input[0].branches.leaves.is_some())) +
      branches.per_input[0].branches.curve_1_layers.len() +
      branches.per_input[0].branches.curve_2_layers.len() +
      1;

    let (c1_padded_pow_2, c2_padded_pow_2) = Self::ipa_rows(inputs, layers);
    let mut c1_tape = VectorCommitmentTape::<<C::C1 as Ciphersuite>::F> {
      commitment_len: c1_padded_pow_2,
      current_j_offset: 0,
      commitments: Vec::with_capacity(inputs * layers),
      branch_lengths: Vec::with_capacity(inputs * layers / 2),
    };
    let mut c2_tape = VectorCommitmentTape::<<C::C2 as Ciphersuite>::F> {
      commitment_len: c2_padded_pow_2,
      current_j_offset: 0,
      commitments: Vec::with_capacity(inputs * layers),
      branch_lengths: Vec::with_capacity(inputs * layers / 2),
    };

    // This transcripts each input's branches, then the root
    let transcripted_branches = branches.transcript_branches(&mut c1_tape, &mut c2_tape);
    let transcripted_inputs = branches.transcript_inputs(&mut c1_tape);
    let transcripted_blinds = branches.transcript_blinds(&mut c1_tape, &mut c2_tape);

    // The blinds we have are for each input's branches
    // We explicitly transcript each input's branches before transcripting anything else, so we
    // simply exhaust all blinds on the first commitments
    let mut pvc_blinds_1 = Vec::with_capacity(c1_tape.commitments.len());
    for blind in &branches.branches_1_blinds {
      pvc_blinds_1.push(-*blind.0.scalar.scalar());
    }
    let mut pvc_blinds_2 = Vec::with_capacity(c2_tape.commitments.len());
    for blind in &branches.branches_2_blinds {
      pvc_blinds_2.push(-*blind.0.scalar.scalar());
    }

    // Now that we've mapped the blinds to the relevant commitments, create random blinds for the
    // rest of the commitments
    while pvc_blinds_1.len() < c1_tape.commitments.len() {
      pvc_blinds_1.push(<C::C1 as Ciphersuite>::F::random(&mut *rng));
    }
    while pvc_blinds_2.len() < c2_tape.commitments.len() {
      pvc_blinds_2.push(<C::C2 as Ciphersuite>::F::random(&mut *rng));
    }

    // Actually commit
    let commitments_1 = c1_tape.commit(&params.curve_1_generators, &pvc_blinds_1);
    let commitments_2 = c2_tape.commit(&params.curve_2_generators, &pvc_blinds_2);

    // Decide the nonce which will be used for proving knowledge of the tree root blind
    let mut root_blind_r_C1 = None;
    let mut root_blind_r_C2 = None;
    let mut root_blind_C1 = None;
    let mut root_blind_C2 = None;
    let root_blind_R: [u8; 32];
    if matches!(tree, TreeRoot::C1(_)) {
      root_blind_C1 = Some(pvc_blinds_1[branches.branches_1_blinds.len()]);
      let root_blind_r = Zeroizing::new(<C::C1 as Ciphersuite>::F::random(&mut *rng));
      root_blind_R = (params.curve_1_generators.h() * *root_blind_r).to_bytes();
      root_blind_r_C1 = Some(root_blind_r);
    } else {
      root_blind_C2 = Some(pvc_blinds_2[branches.branches_2_blinds.len()]);
      let root_blind_r = Zeroizing::new(<C::C2 as Ciphersuite>::F::random(&mut *rng));
      root_blind_R = (params.curve_2_generators.h() * *root_blind_r).to_bytes();
      root_blind_r_C2 = Some(root_blind_r);
    }

    let mut transcript = ProverTranscript::new(Self::transcript(
      tree,
      &branches.per_input.iter().map(|input| &input.input).collect::<Vec<_>>(),
      &root_blind_R,
    ));
    let commitments_1 = transcript.write_commitments(commitments_1, vec![]);
    let commitments_2 = transcript.write_commitments(commitments_2, vec![]);

    let mut root_blind_pok = [0; 64];
    if matches!(tree, TreeRoot::C1(_)) {
      let s =
        *root_blind_r_C1.unwrap() + (transcript.challenge::<C::C1>() * root_blind_C1.unwrap());
      root_blind_pok[.. 32].copy_from_slice(&root_blind_R);
      root_blind_pok[32 ..].copy_from_slice(s.to_repr().as_ref());
    } else {
      let s =
        *root_blind_r_C2.unwrap() + (transcript.challenge::<C::C2>() * root_blind_C2.unwrap());
      root_blind_pok[.. 32].copy_from_slice(&root_blind_R);
      root_blind_pok[32 ..].copy_from_slice(s.to_repr().as_ref());
    }

    // Create the circuits
    let mut c1_circuit = Circuit::<C::C1>::prove(
      c1_tape
        .commitments
        .into_iter()
        .zip(pvc_blinds_1.iter())
        .map(|(g_values, mask)| PedersenVectorCommitment { g_values, mask: *mask })
        .collect(),
    );
    let mut c2_circuit = Circuit::<C::C2>::prove(
      c2_tape
        .commitments
        .into_iter()
        .zip(pvc_blinds_2.iter())
        .map(|(g_values, mask)| PedersenVectorCommitment { g_values, mask: *mask })
        .collect(),
    );

    let mut c1_dlog_challenge = None;
    let mut c2_dlog_challenge = None;

    let TranscriptedBlinds { c1: transcripted_blinds_c1, c2: transcripted_blinds_c2 } =
      transcripted_blinds;
    let mut transcripted_blinds_c1 = transcripted_blinds_c1.into_iter();
    let mut transcripted_blinds_c2 = transcripted_blinds_c2.into_iter();

    // Perform the layers
    let mut c1_commitments = commitments_1
      .C()
      .iter()
      .copied()
      .zip(pvc_blinds_1.into_iter().map(Some))
      .zip(&mut transcripted_blinds_c2);
    let mut c2_commitments = commitments_2
      .C()
      .iter()
      .copied()
      .zip(pvc_blinds_2.into_iter().map(Some))
      .zip(&mut transcripted_blinds_c1);

    let TranscriptedBranches { root, per_input: transcripted_branches_per_input } =
      transcripted_branches;
    for (transcripted_branch, (input, transcripted_input)) in transcripted_branches_per_input
      .into_iter()
      .zip(branches.per_input.iter().zip(transcripted_inputs))
    {
      Self::input(
        params,
        transcripted_branch.c1.len() + transcripted_branch.c2.len() + 1,
        &mut transcript,
        &mut c1_circuit,
        &mut c1_dlog_challenge,
        &mut c2_circuit,
        &mut c2_dlog_challenge,
        root.clone(),
        &mut transcripted_branch.c1.into_iter(),
        &mut transcripted_branch.c2.into_iter(),
        &mut c1_commitments,
        &mut c2_commitments,
        &input.input,
        transcripted_input,
      )?;
    }
    debug_assert!(transcripted_blinds_c1.next().is_none());
    debug_assert!(transcripted_blinds_c2.next().is_none());

    debug_assert!(c1_circuit.muls() <= c1_padded_pow_2);
    debug_assert!(c2_circuit.muls() <= c2_padded_pow_2);

    let (c1_statement, c1_witness) = c1_circuit.statement(
      params.curve_1_generators.reduce(c1_padded_pow_2).ok_or(FcmpError::NotEnoughGenerators)?,
      commitments_1,
    )?;
    c1_statement.prove(rng, &mut transcript, c1_witness.unwrap())?;

    // This circuit may be empty, meaning we don't have to prove a Bulletproof for it
    // It should only be empty in negligible environments and at worst is an inefficiency so it's
    // on-purposely left as-is
    let (c2_statement, c2_witness) = c2_circuit.statement(
      params.curve_2_generators.reduce(c2_padded_pow_2).ok_or(FcmpError::NotEnoughGenerators)?,
      commitments_2,
    )?;
    c2_statement.prove(rng, &mut transcript, c2_witness.unwrap())?;

    let res = Fcmp { _curves: PhantomData, proof: transcript.complete(), root_blind_pok };
    debug_assert_eq!(res.proof.len() + 64, Self::proof_size(inputs, layers));
    Ok(res)
  }

  /// Verify an FCMP.
  ///
  /// This MAY panic if called with invalid arguments, such as a tree root which doesn't correspond
  /// to the layer count.
  ///
  /// The caller must pass the correct amount of layers for this tree root. If the prover specified
  /// the amount of layers, the specified amount of layers must be checked to be equal to the
  /// actual amount of layers.
  ///
  /// This only queues the FCMP for batch verification. The BatchVerifiers MUST also be verified.
  ///
  /// If this function returns an error, the batch verifiers are corrupted and MUST be discarded.
  #[allow(clippy::too_many_arguments)]
  pub fn verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier_1: &mut BatchVerifier<C::C1>,
    verifier_2: &mut BatchVerifier<C::C2>,
    params: &FcmpParams<C>,
    tree: TreeRoot<C::C1, C::C2>,
    layers: usize,
    inputs: &[Input<<C::C1 as Ciphersuite>::F>],
  ) -> Result<(), FcmpError> {
    if (layers == 0) || inputs.is_empty() {
      Err(FcmpError::EmptyProof)?;
    }

    let (c1_padded_pow_2, c2_padded_pow_2) = Self::ipa_rows(inputs.len(), layers);

    let mut c1_tape = VectorCommitmentTape::<<C::C1 as Ciphersuite>::F> {
      commitment_len: c1_padded_pow_2,
      current_j_offset: 0,
      commitments: Vec::with_capacity(inputs.len() * layers),
      branch_lengths: Vec::with_capacity(inputs.len() * layers / 2),
    };
    let mut c1_branches = Vec::with_capacity((layers / 2) + (layers % 2));
    let mut c2_tape = VectorCommitmentTape::<<C::C2 as Ciphersuite>::F> {
      commitment_len: c2_padded_pow_2,
      current_j_offset: 0,
      commitments: Vec::with_capacity(inputs.len() * layers),
      branch_lengths: Vec::with_capacity(inputs.len() * layers / 2),
    };
    let mut c2_branches = Vec::with_capacity(layers / 2);

    // Append the leaves and the non-root branches to the tape
    for _ in inputs {
      for i in 0 .. (layers - 1) {
        if (i % 2) == 0 {
          c1_branches.push(
            c1_tape.append_branch(if i == 0 { 6 * LAYER_ONE_LEN } else { LAYER_ONE_LEN }, None),
          );
        } else {
          c2_branches.push(c2_tape.append_branch(LAYER_TWO_LEN, None));
        }
      }
    }

    // Append the root branch to the tape
    let root = if (layers % 2) == 1 {
      c1_tape.append_branch(if layers == 1 { 6 * LAYER_ONE_LEN } else { LAYER_ONE_LEN }, None)
    } else {
      c2_tape.append_branch(LAYER_TWO_LEN, None)
    };

    // Transcript the inputs
    let append_claimed_point_1 = |c1_tape: &mut VectorCommitmentTape<<C::C1 as Ciphersuite>::F>| {
      c1_tape.append_claimed_point::<C::OcParameters>(None, None, None, None)
    };

    let mut input_openings = Vec::with_capacity(inputs.len());
    for _ in inputs {
      // Since this is presumed over Ed25519, which has a 253-bit discrete logarithm, we have two
      // items avilable in padding. We use this padding for all the other points we must commit to
      // For o_blind, we use the padding for O
      let (o_blind_claim, O) = append_claimed_point_1(&mut c1_tape);
      // For i_blind_u, we use the padding for I
      let (i_blind_u_claim, I) = append_claimed_point_1(&mut c1_tape);

      // Commit to the divisor for `i_blind V`, which doesn't commit to the point `i_blind V`
      // (and that still has to be done)
      let (i_blind_v_divisor, _extra) = c1_tape.append_divisor(None, None);

      // For i_blind_blind, we use the padding for (i_blind V)
      let (i_blind_blind_claim, i_blind_V) = append_claimed_point_1(&mut c1_tape);

      let i_blind_v_claim = PointWithDlog {
        // This has the same discrete log, i_blind, as i_blind_u
        dlog: i_blind_u_claim.dlog.clone(),
        divisor: i_blind_v_divisor,
        point: (i_blind_V[0], i_blind_V[1]),
      };

      // For c_blind, we use the padding for C
      let (c_blind_claim, C) = append_claimed_point_1(&mut c1_tape);

      input_openings.push(TranscriptedInput {
        O: (O[0], O[1]),
        I: (I[0], I[1]),
        C: (C[0], C[1]),
        o_blind_claim,
        i_blind_u_claim,
        i_blind_v_claim,
        i_blind_blind_claim,
        c_blind_claim,
      });
    }

    // We now have committed to O, I, C, and all interpolated points

    // The first circuit's tape opens the blinds from the second curve
    let mut commitment_blind_claims_1 = vec![];
    for _ in 0 .. (if c1_branches.is_empty() {
      // There's only the leaves handled by C1, which don't have branch unblindings
      0
    } else {
      // We unblind a C2 branch for every branch except the ones representing the leaves
      // We also unblind a C2 branch in the root branch, if the root branch is C1
      (c1_branches.len() - inputs.len()) +
        (inputs.len() * usize::from(u8::from(matches!(tree, TreeRoot::C1(_)))))
    }) {
      commitment_blind_claims_1
        .push(c1_tape.append_claimed_point::<C::C2Parameters>(None, None, None, None).0);
    }
    let commitment_blind_claims_1 = commitment_blind_claims_1.into_iter();

    // The second circuit's tape opens the blinds from the first curve
    let mut commitment_blind_claims_2 = vec![];
    for _ in 0 .. (c2_branches.len() +
      (inputs.len() * usize::from(u8::from(matches!(tree, TreeRoot::C2(_))))))
    {
      commitment_blind_claims_2
        .push(c2_tape.append_claimed_point::<C::C1Parameters>(None, None, None, None).0);
    }
    let commitment_blind_claims_2 = commitment_blind_claims_2.into_iter();

    let mut transcript = VerifierTranscript::new(
      Self::transcript(tree, inputs, &self.root_blind_pok[.. 32]),
      &self.proof,
    );
    let proof_1_vcs = transcript.read_commitments::<C::C1>(c1_tape.commitments.len(), 0)?;
    let proof_2_vcs = transcript.read_commitments::<C::C2>(c2_tape.commitments.len(), 0)?;

    // Verify the root blind PoK
    {
      let claimed_root = if (layers % 2) == 1 {
        #[allow(clippy::wildcard_enum_match_arm)]
        TreeRoot::<C::C1, C::C2>::C1(match root[0] {
          Variable::CG { commitment: i, index: _ } => params.curve_1_hash_init + proof_1_vcs.C()[i],
          _ => panic!("branch wasn't present in a vector commitment"),
        })
      } else {
        #[allow(clippy::wildcard_enum_match_arm)]
        TreeRoot::<C::C1, C::C2>::C2(match root[0] {
          Variable::CG { commitment: i, index: _ } => params.curve_2_hash_init + proof_2_vcs.C()[i],
          _ => panic!("branch wasn't present in a vector commitment"),
        })
      };
      match (claimed_root, tree) {
        (TreeRoot::C1(claimed), TreeRoot::C1(actual)) => {
          let R = <C::C1 as Ciphersuite>::read_G(&mut &self.root_blind_pok[.. 32])?;
          let s = <C::C1 as Ciphersuite>::read_F(&mut &self.root_blind_pok[32 ..])?;

          let c = transcript.challenge::<C::C1>();

          // R + cX == sH, where X is the difference in the roots
          // (which should only be the randomness, and H is the generator for the randomness)
          let batch_verifier_weight = <C::C1 as Ciphersuite>::F::random(&mut *rng);
          verifier_1.additional.push((batch_verifier_weight, R));
          verifier_1.additional.push((batch_verifier_weight * c, claimed - actual));
          verifier_1.h -= s * batch_verifier_weight;
        }
        (TreeRoot::C2(claimed), TreeRoot::C2(actual)) => {
          let R = <C::C2 as Ciphersuite>::read_G(&mut &self.root_blind_pok[.. 32])?;
          let s = <C::C2 as Ciphersuite>::read_F(&mut &self.root_blind_pok[32 ..])?;

          let c = transcript.challenge::<C::C2>();

          // R + cX == sH, where X is the difference in the roots
          // (which should only be the randomness, and H is the generator for the randomness)
          let batch_verifier_weight = <C::C2 as Ciphersuite>::F::random(&mut *rng);
          verifier_2.additional.push((batch_verifier_weight, R));
          verifier_2.additional.push((batch_verifier_weight * c, claimed - actual));
          verifier_2.h -= s * batch_verifier_weight;
        }
        _ => panic!("claimed root is on a distinct layer than tree root"),
      }
    };

    // Create the circuits
    let mut c1_circuit = Circuit::<C::C1>::verify();
    let mut c2_circuit = Circuit::<C::C2>::verify();

    let mut c1_dlog_challenge = None;
    let mut c2_dlog_challenge = None;

    let mut c1_branches = c1_branches.into_iter();
    let mut c2_branches = c2_branches.into_iter();
    let mut c1_commitments =
      proof_1_vcs.C().iter().copied().zip(core::iter::repeat(None)).zip(commitment_blind_claims_2);
    let mut c2_commitments =
      proof_2_vcs.C().iter().copied().zip(core::iter::repeat(None)).zip(commitment_blind_claims_1);

    // Perform the layers
    for (input, opening) in inputs.iter().zip(input_openings) {
      Self::input(
        params,
        layers,
        &mut transcript,
        &mut c1_circuit,
        &mut c1_dlog_challenge,
        &mut c2_circuit,
        &mut c2_dlog_challenge,
        root.clone(),
        &mut c1_branches,
        &mut c2_branches,
        &mut c1_commitments,
        &mut c2_commitments,
        input,
        opening,
      )?;
    }

    // Escape to the raw weights to form a GBP with
    debug_assert!(c1_circuit.muls() <= c1_padded_pow_2);
    debug_assert!(c2_circuit.muls() <= c2_padded_pow_2);

    let (c1_statement, _witness) = c1_circuit.statement(
      params.curve_1_generators.reduce(c1_padded_pow_2).ok_or(FcmpError::NotEnoughGenerators)?,
      proof_1_vcs,
    )?;
    c1_statement.verify(rng, verifier_1, &mut transcript)?;

    let (c2_statement, _witness) = c2_circuit.statement(
      params.curve_2_generators.reduce(c2_padded_pow_2).ok_or(FcmpError::NotEnoughGenerators)?,
      proof_2_vcs,
    )?;
    c2_statement.verify(rng, verifier_2, &mut transcript)?;

    Ok(())
  }

  /// Read an FCMP.
  pub fn read(reader: &mut impl io::Read, inputs: usize, layers: usize) -> io::Result<Self> {
    let mut proof = vec![0; Self::proof_size(inputs, layers) - 64];
    reader.read_exact(&mut proof)?;
    let mut root_blind_pok = [0; 64];
    reader.read_exact(&mut root_blind_pok)?;
    Ok(Self { _curves: PhantomData, proof, root_blind_pok })
  }

  /// Write a FCMP.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.proof)?;
    writer.write_all(&self.root_blind_pok)
  }
}
