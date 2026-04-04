use std_shims::{vec, vec::Vec};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use multiexp::{multiexp, multiexp_vartime};
use ciphersuite::{
  group::ff::{Field, FromUniformBytes},
  Ciphersuite,
};

use crate::{
  ScalarVector, PointVector, ProofGenerators, PedersenCommitment, PedersenVectorCommitment,
  BatchVerifier,
  transcript::*,
  lincomb::accumulate_vector,
  inner_product::{IpProveError, IpVerifyError, IpStatement, IpWitness, P},
};
pub use crate::lincomb::{Variable, LinComb};

/// An Arithmetic Circuit Statement.
///
/// Bulletproofs' constraints are of the form
///  `aL * aR = aO, WL * aL + WR * aR + WO * aO = WV * V + c`.
///
/// Generalized Bulletproofs modifies this to
/// `aL * aR = aO, WL * aL + WR * aR + WO * aO + WCG * C_G = WV * V + c`.
///
/// We implement the latter, yet represented (for simplicity) as
/// `aL * aR = aO, WL * aL + WR * aR + WO * aO + WCG * C_G + WV * V + c = 0`.
#[derive(Clone, Debug)]
pub struct ArithmeticCircuitStatement<'a, C: Ciphersuite> {
  generators: ProofGenerators<'a, C>,

  constraints: Vec<LinComb<C::F>>,
  C: PointVector<C>,
  V: PointVector<C>,
}

impl<'a, C: Ciphersuite> Zeroize for ArithmeticCircuitStatement<'a, C> {
  fn zeroize(&mut self) {
    self.constraints.zeroize();
    self.C.zeroize();
    self.V.zeroize();
  }
}

/// The witness for an arithmetic circuit statement.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ArithmeticCircuitWitness<C: Ciphersuite> {
  aL: ScalarVector<C::F>,
  aR: ScalarVector<C::F>,
  aO: ScalarVector<C::F>,

  c: Vec<PedersenVectorCommitment<C>>,
  v: Vec<PedersenCommitment<C>>,
}

impl<C: Ciphersuite> ArithmeticCircuitWitness<C> {
  /// Constructs a new witness instance.
  ///
  /// Returns `None` if `aL.len() != aR.len()`.
  pub fn new(
    mut aL: Vec<C::F>,
    mut aR: Vec<C::F>,
    c: Vec<PedersenVectorCommitment<C>>,
    v: Vec<PedersenCommitment<C>>,
  ) -> Option<Self> {
    if aL.len() != aR.len() {
      None?;
    }
    // If no IPA rows were used, pad to have a length of one
    // This proof may be pointless, but it'll prove
    if aL.is_empty() {
      aL.push(C::F::ZERO);
      aR.push(C::F::ZERO);
    }

    let aL = ScalarVector::from(aL);
    let aR = ScalarVector::from(aR);

    let aO = aL.clone() * &aR;
    Some(ArithmeticCircuitWitness { aL, aR, aO, c, v })
  }
}

/// An error incurred when constructing an arithmetic circuit statement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcStatementError {
  /// A constraint referred to a non-existent term.
  ConstrainedNonExistentTerm,
  /// A constraint referred to a non-existent vector commitment.
  ConstrainedNonExistentVectorCommitment,
  /// A constraint referred to a non-existent commitment.
  ConstrainedNonExistentCommitment,
}

impl<'a, C: Ciphersuite> ArithmeticCircuitStatement<'a, C>
where
  C::F: FromUniformBytes<64>,
{
  /// Create a new `ArithmeticCircuitStatement` for the specified relationship.
  ///
  /// The `LinComb`s passed as `constraints` will be bound to evaluate to `0`.
  ///
  /// The generators/constraints are not transcripted. They're expected to be deterministic from
  /// the context and higher-level statement. If your constraints are variable, you MUST transcript
  /// them before calling `ArithmeticCircuitStatement::prove`/`ArithmeticCircuitStatement::verify`.
  ///
  /// The commitments are expected to have been transcripted extenally to this statement's
  /// invocation. That's practically ensured by taking a `Commitments` struct here, which is only
  /// obtainable via a transcript. The commitments MUST be transcripted though.
  pub fn new(
    generators: ProofGenerators<'a, C>,
    constraints: Vec<LinComb<C::F>>,
    commitments: Commitments<C>,
  ) -> Result<Self, AcStatementError> {
    let Commitments { C, V } = commitments;

    for constraint in &constraints {
      if Some(generators.len()) <= constraint.highest_a_index {
        Err(AcStatementError::ConstrainedNonExistentTerm)?;
      }
      if Some(C.len()) <= constraint.highest_c_index {
        Err(AcStatementError::ConstrainedNonExistentVectorCommitment)?;
      }
      if Some(V.len()) <= constraint.highest_v_index {
        Err(AcStatementError::ConstrainedNonExistentCommitment)?;
      }
    }

    Ok(Self { generators, constraints, C, V })
  }

  /// The amount of rows within the resulting inner-product argument.
  ///
  /// This MUST be greater than or equal to the length of `aL`, `aR`, and the length of the terms
  /// within each Pedersen vector commitment.
  fn n(&self) -> usize {
    self.generators.len()
  }

  /// The amount of constraints.
  fn q(&self) -> usize {
    self.constraints.len()
  }

  /// The amount of Pedersen vector commitments.
  fn c(&self) -> usize {
    self.C.len()
  }

  /// The amount of Pedersen commitments.
  fn m(&self) -> usize {
    self.V.len()
  }
}

struct YzChallenges<C: Ciphersuite> {
  y_inv: ScalarVector<C::F>,
  z: ScalarVector<C::F>,
}

impl<'a, C: Ciphersuite> ArithmeticCircuitStatement<'a, C>
where
  C::F: FromUniformBytes<64>,
{
  fn yz_challenges(&self, y: C::F, z_1: C::F) -> YzChallenges<C> {
    let y_inv = y.invert().expect("y challenge was zero");
    let y_inv = ScalarVector::powers(y_inv, self.n());

    // Powers of z *starting with z**1*
    // We could reuse powers and remove the first element, yet this is cheaper than the shift that
    // would require
    let q = self.q();
    let mut z = ScalarVector(Vec::with_capacity(q));
    z.0.push(z_1);
    for _ in 1 .. q {
      z.0.push(*z.0.last().expect("always non-empty Vec didn't have a last element") * z_1);
    }
    z.0.truncate(q);

    YzChallenges { y_inv, z }
  }
}

/// An error incurred when proving an arithmetic circuit statement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcProveError {
  /// An incorrect amount of generators was provided.
  IncorrectAmountOfGenerators,
  /// The witness was inconsistent to the statement.
  ///
  /// Sanity checks on the witness are always performed. This library may also check whether or not
  /// the witness actually opens the statement (such as if `debug_assertions = on`), and if so, may
  /// return this error if the witness is perceived as inconsistent with the statement.
  InconsistentWitness,
}

impl<'a, C: Ciphersuite> ArithmeticCircuitStatement<'a, C>
where
  C::F: FromUniformBytes<64>,
{
  /// Prove for this statement/witness.
  pub fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    transcript: &mut Transcript,
    mut witness: ArithmeticCircuitWitness<C>,
  ) -> Result<(), AcProveError> {
    let n = self.n();
    let c = self.c();
    let m = self.m();

    // Check the witness length
    if witness.aL.len() > n {
      Err(AcProveError::IncorrectAmountOfGenerators)?;
    }
    for c in &mut witness.c {
      if c.g_values.len() > n {
        Err(AcProveError::IncorrectAmountOfGenerators)?;
      }
    }

    // Check the witness's consistency with the statement
    if (c != witness.c.len()) || (m != witness.v.len()) {
      Err(AcProveError::InconsistentWitness)?;
    }

    #[cfg(debug_assertions)]
    {
      for (commitment, opening) in self.V.0.iter().zip(witness.v.iter()) {
        if *commitment != opening.commit(self.generators.g(), self.generators.h()) {
          Err(AcProveError::InconsistentWitness)?;
        }
      }
      for (commitment, opening) in self.C.0.iter().zip(witness.c.iter()) {
        if Some(*commitment) != opening.commit(self.generators.g_bold_slice(), self.generators.h())
        {
          Err(AcProveError::InconsistentWitness)?;
        }
      }
      for constraint in &self.constraints {
        let eval = constraint
          .WL
          .iter()
          .map(
            |(i, weight)| {
              if let Some(value) = witness.aL.0.get(*i) {
                *weight * *value
              } else {
                C::F::ZERO
              }
            },
          )
          .chain(constraint.WR.iter().map(|(i, weight)| {
            if let Some(value) = witness.aR.0.get(*i) {
              *weight * *value
            } else {
              C::F::ZERO
            }
          }))
          .chain(constraint.WO.iter().map(|(i, weight)| {
            if let Some(value) = witness.aO.0.get(*i) {
              *weight * *value
            } else {
              C::F::ZERO
            }
          }))
          .chain(
            witness
              .c
              .iter()
              .enumerate()
              .map(|(i, c)| {
                (constraint.WCG().get(&i).into_iter().flat_map(|value| value.iter()), c)
              })
              .flat_map(|(weights, c)| {
                weights.map(|(j, weight)| {
                  if let Some(value) = c.g_values.get(*j) {
                    *weight * value
                  } else {
                    C::F::ZERO
                  }
                })
              }),
          )
          .chain(constraint.WV.iter().map(|(i, weight)| *weight * witness.v[*i].value))
          .chain(core::iter::once(constraint.c))
          .sum::<C::F>();

        if eval != C::F::ZERO {
          Err(AcProveError::InconsistentWitness)?;
        }
      }
    }

    let alpha = C::F::random(&mut *rng);
    let beta = C::F::random(&mut *rng);
    let rho = C::F::random(&mut *rng);

    let AI = {
      let alg = witness.aL.0.iter().enumerate().map(|(i, aL)| (*aL, self.generators.g_bold(i)));
      let arh = witness.aR.0.iter().enumerate().map(|(i, aR)| (*aR, self.generators.h_bold(i)));
      let ah = core::iter::once((alpha, self.generators.h()));
      let mut AI_terms = alg.chain(arh).chain(ah).collect::<Vec<_>>();
      let AI = multiexp(&AI_terms);
      AI_terms.zeroize();
      AI
    };
    let AO = {
      let aog = witness.aO.0.iter().enumerate().map(|(i, aO)| (*aO, self.generators.g_bold(i)));
      let bh = core::iter::once((beta, self.generators.h()));
      let mut AO_terms = aog.chain(bh).collect::<Vec<_>>();
      let AO = multiexp(&AO_terms);
      AO_terms.zeroize();
      AO
    };

    let mut sL = ScalarVector(Vec::with_capacity(n));
    let mut sR = ScalarVector(Vec::with_capacity(n));
    for _ in 0 .. n {
      sL.0.push(C::F::random(&mut *rng));
      sR.0.push(C::F::random(&mut *rng));
    }
    let S = {
      let slg = sL.0.iter().enumerate().map(|(i, sL)| (*sL, self.generators.g_bold(i)));
      let srh = sR.0.iter().enumerate().map(|(i, sR)| (*sR, self.generators.h_bold(i)));
      let rh = core::iter::once((rho, self.generators.h()));
      let mut S_terms = slg.chain(srh).chain(rh).collect::<Vec<_>>();
      let S = multiexp(&S_terms);
      S_terms.zeroize();
      S
    };

    transcript.push_point(&AI);
    transcript.push_point(&AO);
    transcript.push_point(&S);
    let y = transcript.challenge::<C>();
    let z = transcript.challenge::<C>();
    let YzChallenges { y_inv, z } = self.yz_challenges(y, z);
    let y = ScalarVector::powers(y, n);

    // t is a n'-term polynomial
    // While Bulletproofs discuss it as a 6-term polynomial, Generalized Bulletproofs re-defines it
    // as `2(n' + 1)`-term, where `n'` is `2 (c + 1)`.
    // When `c = 0`, `n' = 2`, and t is `6` (which lines up with Bulletproofs having a 6-term
    // polynomial).

    // ni = n'
    let ni = 2 + (2 * (c / 2));
    // These indexes are from the Generalized Bulletproofs paper
    #[rustfmt::skip]
    let ilr = ni / 2; // 1 if c = 0
    #[rustfmt::skip]
    let io = ni; // 2 if c = 0
    #[rustfmt::skip]
    let is = ni + 1; // 3 if c = 0
    #[rustfmt::skip]
    let jlr = ni / 2; // 1 if c = 0
    #[rustfmt::skip]
    let jo = 0; // 0 if c = 0
    #[rustfmt::skip]
    let js = ni + 1; // 3 if c = 0

    // If c = 0, these indexes perfectly align with the stated powers of X from the Bulletproofs
    // paper for the following coefficients

    // Declare the l and r polynomials, assigning the traditional coefficients to their positions
    let mut l = vec![];
    let mut r = vec![];
    #[allow(clippy::range_plus_one)]
    for _ in 0 .. (is + 1) {
      l.push(ScalarVector::new(0));
      r.push(ScalarVector::new(0));
    }

    let (l_weights, r_weights, o_weights) = {
      // Initially, we allocate vectors of full length so we can write into them as needed, without
      // panicking.
      let mut l_weights = ScalarVector::new(n);
      let mut r_weights = ScalarVector::new(n);
      let mut o_weights = ScalarVector::new(n);

      /*
        Track the index of the highest element within this vector actually used.

        This allows us to truncate it after, saving operations over values we know will be zero.
      */
      let mut l_hi = 0;
      let mut r_hi = 0;
      let mut o_hi = 0;
      for (constraint, z) in self.constraints.iter().zip(&z.0) {
        l_hi = l_hi.max(accumulate_vector(&mut l_weights, &constraint.WL, *z));
        r_hi = r_hi.max(accumulate_vector(&mut r_weights, &constraint.WR, *z));
        o_hi = o_hi.max(accumulate_vector(&mut o_weights, &constraint.WO, *z));
      }

      // Perform the truncation, and as `*_hi` represents the index, add `1` to obtain the length
      // we're truncating to (preserving all values we did actually write to)
      l_weights.0.truncate(l_hi + 1);
      r_weights.0.truncate(r_hi + 1);
      o_weights.0.truncate(o_hi + 1);

      (l_weights, r_weights, o_weights)
    };

    l[ilr] = r_weights;
    for (dest, weight) in l[ilr].0.iter_mut().zip(&y_inv.0) {
      *dest *= weight;
    }
    for (dest, src) in l[ilr].0.iter_mut().zip(&witness.aL.0) {
      *dest += src;
    }
    // If the prior while loop terminated because `l[ilr]` was short, push the rest of `aL`
    {
      let l_ilr_len = l[ilr].len();
      if l_ilr_len < witness.aL.len() {
        l[ilr].0.extend(&witness.aL.0[l_ilr_len ..]);
      }
    }

    l[io] = witness.aO.clone();

    l[is] = sL;

    r[jlr] = l_weights;
    r[jlr].0.reserve(witness.aR.len());
    let mut aR_y = witness.aR.0.iter().zip(&y.0).map(|(aR, y)| *aR * y);
    for (dest, aR_y) in r[jlr].0.iter_mut().zip(&mut aR_y) {
      *dest += aR_y;
    }
    // If the prior while loop terminated because `r[jlr]` was short, push the rest of `aR_y`
    for aR_y in aR_y {
      r[jlr].0.push(aR_y);
    }

    r[jo] = ScalarVector::new(n);
    for (dest, (o, y)) in r[jo].0.iter_mut().zip(o_weights.0.iter().zip(&y.0)) {
      *dest = *o - *y;
    }
    // As the prior loop may terminate if `o_weights` was short, push the rest of `[jo]`
    for i in o_weights.len() .. n {
      r[jo][i] = -y[i];
    }

    r[js] = sR * &y;

    /*
      We now fill in the vector commitments.

      We use unused coefficients of `l` increasing from `0` (skipping `ilr`), and unused
      coefficients of `r` decreasing from `ni` (skipping `jlr`).
    */

    for (mut i, c) in witness.c.iter().enumerate() {
      let cg_weights = {
        let mut cg = ScalarVector::new(n);
        let mut cg_hi = 0;
        for (constraint, z) in self.constraints.iter().zip(&z.0) {
          if let Some(WCG) = constraint.WCG().get(&i) {
            cg_hi = cg_hi.max(accumulate_vector(&mut cg, WCG, *z));
          }
        }
        cg.0.truncate(cg_hi + 1);
        cg
      };

      // Modify `i` from the index of the vector commitment to its index within `l`
      if i >= ilr {
        i += 1;
      }
      // Because `i` has skipped `ilr`, `j` will inherently skip `jlr`
      let j = ni - i;

      l[i] = ScalarVector::from(c.g_values.clone());
      r[j] = cg_weights;
    }

    // Multiply `l` and `r` to obtain `t`
    let mut t = ScalarVector::new(1 + (2 * (l.len() - 1)));
    for (i, l) in l.iter().enumerate() {
      for (j, r) in r.iter().enumerate() {
        t[i + j] += l.inner_product_without_length_checks(r.0.iter());
      }
    }

    /*
      Per Bulletproofs, calculate masks `tau` for each element of `t` where `(i > 0) && (i != 2)`.
      Per Generalized Bulletproofs, calculate masks `tau` for each `t` where `i != n'`.
      With Bulletproofs, `t[0]` is zero, hence its omission, yet Generalized Bulletproofs uses it.
      Then, `n'` is equal to `2` when no vector commitments are present.
    */
    let mut tau_before_ni = vec![];
    for _ in 0 .. ni {
      tau_before_ni.push(C::F::random(&mut *rng));
    }
    let mut tau_after_ni = vec![];
    for _ in 0 .. t.0[(ni + 1) ..].len() {
      tau_after_ni.push(C::F::random(&mut *rng));
    }
    // Calculate commitments to the coefficients of `t`, blinded by `tau`
    for (t, tau) in t.0[0 .. ni].iter().zip(tau_before_ni.iter()) {
      transcript.push_point(&multiexp(&[(*t, self.generators.g()), (*tau, self.generators.h())]));
    }
    for (t, tau) in t.0[(ni + 1) ..].iter().zip(tau_after_ni.iter()) {
      transcript.push_point(&multiexp(&[(*t, self.generators.g()), (*tau, self.generators.h())]));
    }

    let x: ScalarVector<C::F> = ScalarVector::powers(transcript.challenge::<C>(), t.len());

    let poly_eval = |poly: &[ScalarVector<C::F>], x: &ScalarVector<C::F>| -> ScalarVector<_> {
      let mut res = ScalarVector::<C::F>::new(n);
      for (i, coeff) in poly.iter().enumerate() {
        for (res, coeff) in res.0.iter_mut().zip(coeff.0.iter()) {
          *res += *coeff * x[i];
        }
      }
      res
    };
    let l = poly_eval(&l, &x);
    let r = poly_eval(&r, &x);

    let t_caret = l.inner_product(r.0.iter());

    let mut V_weights = ScalarVector::new(self.V.len());
    for (constraint, z) in self.constraints.iter().zip(&z.0) {
      // We use `-z`, not `z`, as we write our constraint as `... + WV V = 0` not `= WV V + ..`
      // This means we need to subtract `WV V` from both sides, which we accomplish here
      accumulate_vector(&mut V_weights, &constraint.WV, -*z);
    }

    let tau_x = {
      let mut tau_x_poly = Vec::with_capacity(t.len());
      tau_x_poly.extend(tau_before_ni);
      tau_x_poly.push(V_weights.inner_product(witness.v.iter().map(|v| &v.mask)));
      tau_x_poly.extend(tau_after_ni);

      let mut tau_x = C::F::ZERO;
      for (i, coeff) in tau_x_poly.into_iter().enumerate() {
        tau_x += coeff * x[i];
      }
      tau_x
    };

    // Calculate `u` for the powers of `x` variable to `ilr`/`io`/`is`
    let u = {
      // Calculate the first part of `u`
      let mut u = (alpha * x[ilr]) + (beta * x[io]) + (rho * x[is]);

      // Incorporate the commitment masks multiplied by the associated power of `x`
      for (mut i, commitment) in witness.c.iter().enumerate() {
        // If this index is `ni / 2`, skip it
        if i >= (ni / 2) {
          i += 1;
        }
        u += x[i] * commitment.mask;
      }
      u
    };

    // Use the Inner-Product argument to prove for the following:
    // `P = t_caret * g + l * g_bold + r * (y_inv * h_bold)`

    let mut P_terms = Vec::with_capacity(1 + (2 * self.generators.len()));
    debug_assert_eq!(l.len(), r.len());
    for (i, (l, r)) in l.0.iter().zip(r.0.iter()).enumerate() {
      P_terms.push((*l, self.generators.g_bold(i)));
      P_terms.push((y_inv[i] * r, self.generators.h_bold(i)));
    }

    // Protocol 1, inlined, since our IpStatement is for Protocol 2
    transcript.push_scalar(tau_x);
    transcript.push_scalar(u);
    transcript.push_scalar(t_caret);
    let ip_x = transcript.challenge::<C>();
    P_terms.push((ip_x * t_caret, self.generators.g()));
    IpStatement::new(
      self.generators,
      y_inv,
      ip_x,
      // Safe since IpStatement isn't a ZK proof
      P::Prover(multiexp_vartime(&P_terms)),
    )
    .expect("created an invalid IpStatement")
    .prove(transcript, IpWitness::new(l, r).expect("created an invalid IpWitness"))
    .map_err(|e| match e {
      IpProveError::IncorrectAmountOfGenerators => AcProveError::IncorrectAmountOfGenerators,
      IpProveError::InconsistentWitness => AcProveError::InconsistentWitness,
    })
  }
}

/// An error incurred when verifying an arithmetic circuit statement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcVerifyError {
  /// An incorrect amount of generators was provided.
  IncorrectAmountOfGenerators,
  /// The proof wasn't complete and the necessary values could not be read from the transcript.
  IncompleteProof,
}

impl<'a, C: Ciphersuite> ArithmeticCircuitStatement<'a, C>
where
  C::F: FromUniformBytes<64>,
{
  /// Verify a proof for this statement.
  ///
  /// This solely queues the statement for batch verification. The resulting BatchVerifier MUST
  /// still be verified.
  ///
  /// If this proof returns an error, the BatchVerifier MUST be assumed corrupted and discarded.
  pub fn verify<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BatchVerifier<C>,
    transcript: &mut VerifierTranscript,
  ) -> Result<(), AcVerifyError> {
    if verifier.g_bold.len() < self.generators.len() {
      verifier.g_bold.resize(self.generators.len(), C::F::ZERO);
      verifier.h_bold.resize(self.generators.len(), C::F::ZERO);
      verifier.h_sum.resize(self.generators.len(), C::F::ZERO);
    }

    let n = self.n();
    let c = self.c();

    let ni = 2 + (2 * (c / 2));

    let ilr = ni / 2;
    let io = ni;
    let is = ni + 1;
    let jlr = ni / 2;
    let jo = 0;

    let l_r_poly_len = 1 + ni + 1;
    let t_poly_len = (2 * l_r_poly_len) - 1;

    let AI = transcript.read_point::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;
    let AO = transcript.read_point::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;
    let S = transcript.read_point::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;
    let y = transcript.challenge::<C>();
    let z = transcript.challenge::<C>();
    let YzChallenges { y_inv, z } = self.yz_challenges(y, z);

    let mut l_weights = ScalarVector::new(n);
    let mut r_weights = ScalarVector::new(n);
    let mut o_weights = ScalarVector::new(n);
    for (constraint, z) in self.constraints.iter().zip(&z.0) {
      accumulate_vector(&mut l_weights, &constraint.WL, *z);
      accumulate_vector(&mut r_weights, &constraint.WR, *z);
      accumulate_vector(&mut o_weights, &constraint.WO, *z);
    }
    let r_weights = r_weights * &y_inv;

    let delta = r_weights.inner_product(l_weights.0.iter());

    let mut T_before_ni = Vec::with_capacity(ni);
    let mut T_after_ni = Vec::with_capacity(t_poly_len - ni - 1);
    for _ in 0 .. ni {
      T_before_ni.push(transcript.read_point::<C>().map_err(|_| AcVerifyError::IncompleteProof)?);
    }
    for _ in 0 .. (t_poly_len - ni - 1) {
      T_after_ni.push(transcript.read_point::<C>().map_err(|_| AcVerifyError::IncompleteProof)?);
    }
    let x: ScalarVector<C::F> = ScalarVector::powers(transcript.challenge::<C>(), t_poly_len);

    let tau_x = transcript.read_scalar::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;
    let u = transcript.read_scalar::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;
    let t_caret = transcript.read_scalar::<C>().map_err(|_| AcVerifyError::IncompleteProof)?;

    // Lines 88-90, modified per Generalized Bulletproofs as needed w.r.t. `t`
    {
      let verifier_weight = C::F::random(&mut *rng);
      // lhs of the equation, weighted to enable batch verification
      verifier.g += t_caret * verifier_weight;
      verifier.h += tau_x * verifier_weight;

      let mut V_weights = ScalarVector::new(self.V.len());
      for (constraint, z) in self.constraints.iter().zip(&z.0) {
        // We use `-z`, not `z`, as we write our constraint as `... + WV V = 0` not `= WV V + ..`
        // This means we need to subtract `WV V` from both sides, which we accomplish here
        accumulate_vector(&mut V_weights, &constraint.WV, -*z);
      }
      V_weights = V_weights * x[ni];

      // rhs of the equation, negated to cause a sum to zero
      // `delta - z...`, instead of `delta + z...`, is done for the same reason as in the above WV
      // matrix transform
      verifier.g -= verifier_weight *
        x[ni] *
        (delta - z.inner_product(self.constraints.iter().map(|constraint| &constraint.c)));
      for pair in V_weights.0.into_iter().zip(self.V.0) {
        verifier.additional.push((-verifier_weight * pair.0, pair.1));
      }
      for (i, T) in T_before_ni.into_iter().enumerate() {
        verifier.additional.push((-verifier_weight * x[i], T));
      }
      for (i, T) in T_after_ni.into_iter().enumerate() {
        verifier.additional.push((-verifier_weight * x[ni + 1 + i], T));
      }
    }

    let verifier_weight = C::F::random(&mut *rng);
    // Multiply `x` by `verifier_weight` as this effects `verifier_weight` onto most scalars and
    // saves a notable amount of operations
    let x = x * verifier_weight;

    // This following block effectively calculates P, within the multiexp
    {
      verifier.additional.push((x[ilr], AI));
      verifier.additional.push((x[io], AO));
      // `h_bold' * y` is equivalent to `h_bold` as `h_bold'` _is_ `h_bold * y^{-1}`
      let mut log2_n = 0;
      while (1 << log2_n) != n {
        log2_n += 1;
      }
      verifier.h_sum[log2_n] -= verifier_weight;
      verifier.additional.push((x[is], S));

      // Lines 85-87 calculate `WL`, `WR`, `WO`
      // We preserve them in terms of `g_bold` and `h_bold` for a more efficient multiexp
      let mut h_bold_scalars = l_weights * x[jlr];
      for (i, wr) in (r_weights * x[jlr]).0.into_iter().enumerate() {
        verifier.g_bold[i] += wr;
      }
      h_bold_scalars = h_bold_scalars + &(o_weights * x[jo]);

      for i in 0 .. self.C.len() {
        let mut cg = ScalarVector::new(n);
        for (constraint, z) in self.constraints.iter().zip(&z.0) {
          if let Some(WCG) = constraint.WCG().get(&i) {
            accumulate_vector(&mut cg, WCG, *z);
          }
        }

        // Push the terms for `C`, which increment from `0`, and the terms for `WC`, which
        // decrement from `n'`
        {
          let mut i = i;
          let C = self.C.0[i];
          let WCG = cg;

          if i >= (ni / 2) {
            i += 1;
          }
          let j = ni - i;
          verifier.additional.push((x[i], C));
          h_bold_scalars = h_bold_scalars + &(WCG * x[j]);
        }
      }

      // All terms for `h_bold` here have actually been for `h_bold'`, `h_bold * y^{-1}`
      h_bold_scalars = h_bold_scalars * &y_inv;
      for (i, scalar) in h_bold_scalars.0.into_iter().enumerate() {
        verifier.h_bold[i] += scalar;
      }

      // Remove `u * h` from `P`
      verifier.h -= verifier_weight * u;
    }

    // Prove for lines 88, 92 with an Inner-Product statement
    // This inlines Protocol 1, as our IpStatement implements Protocol 2
    let ip_x = transcript.challenge::<C>();
    // `P` is amended with this additional term
    verifier.g += verifier_weight * ip_x * t_caret;
    IpStatement::new(self.generators, y_inv, ip_x, P::Verifier { verifier_weight })
      .expect("created an invalid IpStatement")
      .verify(verifier, transcript)
      .map_err(|e| match e {
        IpVerifyError::IncompleteProof => AcVerifyError::IncompleteProof,
      })
  }
}
