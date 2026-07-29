#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{vec, vec::Vec};

use subtle::ConditionallySelectable;
use zeroize::Zeroize;

use generic_array::{typenum::Unsigned as _, GenericArray};

use multiexp::multiexp;
use ciphersuite::{group::ff::PrimeFieldBits, Ciphersuite};

use ec_divisors::Poly;
use generalized_bulletproofs::Generators;

use crate::{
  Variable,
  gadgets::{DiscreteLogParameters, Divisor, PointWithDlog},
};

pub(crate) const COMMITMENT_WORD_LEN: usize = 128;

/// The variables used for elements in Vector Commitments.
pub(crate) struct VectorCommitmentTape<F: Zeroize + PrimeFieldBits> {
  pub(crate) commitment_len: usize,
  pub(crate) current_j_offset: usize,
  pub(crate) commitments: Vec<Vec<F>>,
  pub(crate) branch_lengths: Vec<usize>,
}

impl<F: Zeroize + PrimeFieldBits> VectorCommitmentTape<F> {
  /// Append a series of variables to the vector commitment tape.
  pub(crate) fn append(&mut self, variables: Option<Vec<F>>) -> Vec<Variable> {
    // Any chunk of variables should be the word-length long
    if let Some(variables) = &variables {
      assert_eq!(variables.len(), COMMITMENT_WORD_LEN);
    }

    #[allow(clippy::unwrap_or_default)]
    let variables = variables.unwrap_or(vec![]);

    if self.current_j_offset == 0 {
      self.commitments.push(variables);
    } else {
      let commitment = self.commitments.last_mut().unwrap();
      commitment.extend(variables);
    }
    let i = self.commitments.len() - 1;
    let j_range = self.current_j_offset .. (self.current_j_offset + COMMITMENT_WORD_LEN);
    let res = j_range.map(|j| Variable::CG { commitment: i, index: j }).collect();

    self.current_j_offset += COMMITMENT_WORD_LEN;
    if self.current_j_offset == self.commitment_len {
      self.current_j_offset = 0;
    }
    res
  }

  // This must be called before all other appends
  pub(crate) fn append_branch(
    &mut self,
    branch_len: usize,
    branch: Option<Vec<F>>,
  ) -> Vec<Variable> {
    // Make sure we're at the start of a commitment as this needs its own dedicated commitment
    assert_eq!(self.current_j_offset, 0);
    // Make sure we haven't pushed any non-branches yet
    assert_eq!(self.branch_lengths.len(), self.commitments.len());
    self.branch_lengths.push(branch_len);
    assert!(branch_len != 0);
    assert!(branch_len <= self.commitment_len);
    let words_in_branch = branch_len.div_ceil(COMMITMENT_WORD_LEN);

    // An empty vector commitment of the word length
    let empty = branch.as_ref().map(|_| vec![F::ZERO; COMMITMENT_WORD_LEN]);

    let branch = branch.map(|mut branch| {
      assert_eq!(branch_len, branch.len());

      // Pad the branch
      while (branch.len() % COMMITMENT_WORD_LEN) != 0 {
        branch.push(F::ZERO);
      }
      branch
    });

    // Append each chunk of the branch
    let mut branch_variables = Vec::with_capacity(branch_len);
    for b in 0 .. words_in_branch {
      branch_variables.extend(&self.append(branch.as_ref().map(|branch| {
        branch[(b * COMMITMENT_WORD_LEN) .. ((b + 1) * COMMITMENT_WORD_LEN)].to_vec()
      })));
    }
    // Truncate any padding we created a variable for
    branch_variables.truncate(branch_len);

    // Append padding to this vector commitment so nothing else is added to this
    for _ in words_in_branch .. (self.commitment_len / COMMITMENT_WORD_LEN) {
      self.append(empty.clone());
    }

    branch_variables
  }

  /// Append a discrete logarithm of up to 255 coefficients, allowing usage of the extra slot for
  /// an arbitrary variable.
  ///
  /// If the discrete logarithm is less than 255 bits, additional extra elements may be provided
  /// (`padding`), yet these are only accessible on certain curves. This function panics if more
  /// elements are provided in `padding` than free spaces remaining.
  pub(crate) fn append_dlog<Parameters: DiscreteLogParameters>(
    &mut self,
    dlog: Option<&[u64]>,
    padding: Option<Vec<F>>,
    extra: Option<F>,
  ) -> (GenericArray<Variable, Parameters::ScalarBits>, Vec<Variable>, Variable) {
    assert!(Parameters::ScalarBits::USIZE <= 255);
    let dlog_bits = Parameters::ScalarBits::USIZE;

    let witness = dlog.map(|dlog| {
      let mut witness = Vec::with_capacity(256);
      assert_eq!(dlog.len(), dlog_bits);
      for coeff in dlog {
        witness.push(F::from(*coeff));
      }

      let padding = padding.unwrap();
      assert!(padding.len() <= (255 - dlog_bits));
      for i in 0 .. (255 - dlog_bits) {
        witness.push(*padding.get(i).unwrap_or(&F::ZERO));
      }
      assert_eq!(witness.len(), 255);

      // Since we have an extra slot, push an extra item
      witness.push(extra.unwrap());
      witness
    });

    let (witness_a, witness_b) = witness
      .map(|mut witness| {
        debug_assert_eq!(witness.len(), 2 * COMMITMENT_WORD_LEN);
        let witness_b = witness.split_off(COMMITMENT_WORD_LEN);
        (Some(witness), Some(witness_b))
      })
      .unwrap_or((None, None));
    let mut variables = self.append(witness_a);
    variables.append(&mut self.append(witness_b));

    let extra = variables.pop().unwrap();
    let padding = variables.drain(dlog_bits .. 255).collect::<Vec<_>>();
    let dlog = GenericArray::from_slice(&variables).clone();
    (dlog, padding, extra)
  }

  pub(crate) fn append_divisor<Parameters: DiscreteLogParameters>(
    &mut self,
    divisor: Option<Poly<F>>,
    extra: Option<F>,
  ) -> (Divisor<Parameters>, Variable) {
    let witness = divisor.map(|divisor| {
      // Divisor y
      // This takes 1 slot
      let mut divisor_witness = Vec::with_capacity(256);
      divisor_witness.push(*divisor.y_coefficients.first().unwrap_or(&F::ZERO));

      // Divisor yx
      let empty_vec = vec![];
      let yx = divisor.yx_coefficients.first().unwrap_or(&empty_vec);
      assert!(yx.len() <= Parameters::YxCoefficients::USIZE);
      for i in 0 .. Parameters::YxCoefficients::USIZE {
        divisor_witness.push(*yx.get(i).unwrap_or(&F::ZERO));
      }

      // Divisor x
      assert!(divisor.x_coefficients.len() <= Parameters::XCoefficients::USIZE);
      assert_eq!(divisor.x_coefficients[0], F::ONE);
      // Transcript from 1 given we expect a normalization of the first coefficient
      // We allocate 127 slots for this
      for i in 1 .. Parameters::XCoefficients::USIZE {
        divisor_witness.push(*divisor.x_coefficients.get(i).unwrap_or(&F::ZERO));
      }

      // Divisor 0
      // This takes 1 slot
      divisor_witness.push(divisor.zero_coefficient);

      assert!(divisor_witness.len() <= 255);
      while divisor_witness.len() < 255 {
        divisor_witness.push(F::ZERO);
      }

      // Since we have an extra slot, push an extra item
      let mut witness = divisor_witness;
      witness.push(extra.unwrap());
      witness
    });

    let (witness_a, witness_b) = witness
      .map(|mut witness| {
        debug_assert_eq!(witness.len(), 2 * COMMITMENT_WORD_LEN);
        let witness_b = witness.split_off(COMMITMENT_WORD_LEN);
        (Some(witness), Some(witness_b))
      })
      .unwrap_or((None, None));
    let mut variables = self.append(witness_a);
    variables.append(&mut self.append(witness_b));

    let extra = variables.pop().unwrap();

    let mut cursor_start = 1;
    let mut cursor_end = cursor_start + Parameters::YxCoefficients::USIZE;
    let yx = GenericArray::from_slice(&variables[cursor_start .. cursor_end]).clone();
    cursor_start = cursor_end;
    cursor_end += Parameters::XCoefficientsMinusOne::USIZE;
    let x_from_power_of_2 =
      GenericArray::from_slice(&variables[cursor_start .. cursor_end]).clone();
    let divisor = Divisor { y: variables[0], yx, x_from_power_of_2, zero: variables[cursor_end] };

    (divisor, extra)
  }

  pub(crate) fn append_claimed_point<Parameters: DiscreteLogParameters>(
    &mut self,
    dlog: Option<&[u64]>,
    divisor: Option<Poly<F>>,
    point: Option<(F, F)>,
    padding: Option<Vec<F>>,
  ) -> (PointWithDlog<Parameters>, Vec<Variable>) {
    // Append the x coordinate with the discrete logarithm
    let (dlog, padding, x) =
      self.append_dlog::<Parameters>(dlog, padding, point.map(|point| point.0));
    // Append the y coordinate with the divisor
    let (divisor, y) = self.append_divisor(divisor, point.map(|point| point.1));

    (PointWithDlog { divisor, dlog, point: (x, y) }, padding)
  }

  pub(crate) fn commit<C: Ciphersuite<F = F, G: ConditionallySelectable>>(
    &self,
    generators: &Generators<C>,
    blinds: &[C::F],
  ) -> Vec<C::G> {
    assert_eq!(self.commitments.len(), blinds.len());

    let mut res = Vec::with_capacity(self.commitments.len());
    for (i, (values, blind)) in self.commitments.iter().zip(blinds).enumerate() {
      let g_generators = generators.g_bold_slice()[.. values.len()].iter().copied();
      let commitment = g_generators.enumerate().map(|(i, g)| (values[i], g));
      let mut commitment = if let Some(branch_length) = self.branch_lengths.get(i) {
        commitment.take(*branch_length).collect::<Vec<_>>()
      } else {
        commitment.collect::<Vec<_>>()
      };
      commitment.push((*blind, generators.h()));
      res.push(multiexp(&commitment));
    }
    res
  }
}
