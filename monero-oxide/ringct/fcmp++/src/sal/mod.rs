use std_shims::io;

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use blake2::digest::Update;

use dalek_ff_group::{Scalar, EdwardsPoint, Ed25519};
use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  },
  Ciphersuite,
};

use monero_primitives::Blake2bMonero;

use monero_fcmp_plus_plus_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V};

use crate::{T, Input, Output};

/// A multisignature algorithm for a secret-shared `x`, not supporting outgoing view keys and as
/// historically generated.
#[cfg(all(feature = "std", feature = "multisig"))]
pub mod legacy_multisig;
/// A multisignature algorithm for a secret-shared `y`, supporting outgoing view keys.
#[cfg(all(feature = "std", feature = "multisig"))]
pub mod multisig;

/// A re-randomized output.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RerandomizedOutput {
  O_tilde: <Ed25519 as Ciphersuite>::G,
  I_tilde: <Ed25519 as Ciphersuite>::G,
  R: <Ed25519 as Ciphersuite>::G,
  C_tilde: <Ed25519 as Ciphersuite>::G,

  r_o: <Ed25519 as Ciphersuite>::F,
  r_i: <Ed25519 as Ciphersuite>::F,
  r_r_i: <Ed25519 as Ciphersuite>::F,
  r_c: <Ed25519 as Ciphersuite>::F,
}

impl core::fmt::Debug for RerandomizedOutput {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("RerandomizedOutput").field("input", &self.input()).finish_non_exhaustive()
  }
}

impl RerandomizedOutput {
  /// Re-randomize an output.
  pub fn new(rng: &mut (impl RngCore + CryptoRng), output: Output) -> RerandomizedOutput {
    let r_o = <Ed25519 as Ciphersuite>::F::random(&mut *rng);
    let r_i = <Ed25519 as Ciphersuite>::F::random(&mut *rng);
    let r_r_i = <Ed25519 as Ciphersuite>::F::random(&mut *rng);
    let r_c = <Ed25519 as Ciphersuite>::F::random(&mut *rng);

    let O_tilde = output.O() + (*T * r_o);
    let I_tilde = output.I() + (EdwardsPoint((*FCMP_PLUS_PLUS_U).into()) * r_i);
    let R = (EdwardsPoint((*FCMP_PLUS_PLUS_V).into()) * r_i) + (*T * r_r_i);
    let C_tilde = output.C() + (<Ed25519 as Ciphersuite>::generator() * r_c);

    RerandomizedOutput { O_tilde, I_tilde, R, C_tilde, r_o, r_i, r_r_i, r_c }
  }

  /// Write a re-randomized output.
  ///
  /// This allows saving a re-randomization to prove for the output's membership later.
  ///
  /// This does contain secrets which allow linking an output to the input its spent with.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.O_tilde.to_bytes())?;
    writer.write_all(&self.I_tilde.to_bytes())?;
    writer.write_all(&self.R.to_bytes())?;
    writer.write_all(&self.C_tilde.to_bytes())?;

    writer.write_all(&self.r_o.to_repr())?;
    writer.write_all(&self.r_i.to_repr())?;
    writer.write_all(&self.r_r_i.to_repr())?;
    writer.write_all(&self.r_c.to_repr())
  }

  /// Read a re-randomized output.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    Ok(Self {
      O_tilde: Ed25519::read_G(reader)?,
      I_tilde: Ed25519::read_G(reader)?,
      R: Ed25519::read_G(reader)?,
      C_tilde: Ed25519::read_G(reader)?,

      r_o: Ed25519::read_F(reader)?,
      r_i: Ed25519::read_F(reader)?,
      r_r_i: Ed25519::read_F(reader)?,
      r_c: Ed25519::read_F(reader)?,
    })
  }

  // The FCMP code expects these as used in the proof, which adds these blinds to the blinded
  // values to recover the original values (requiring their negation)
  /// The scalar to use with `OBlind::new`.
  ///
  /// This is the additive inverse of the re-randomization applied to the `y T` term.
  pub fn o_blind(&self) -> <Ed25519 as Ciphersuite>::F {
    -self.r_o
  }
  /// The scalar to use with `IBlind::new`.
  pub fn i_blind(&self) -> <Ed25519 as Ciphersuite>::F {
    -self.r_i
  }
  /// The scalar to use with `IBlindBlind::new`.
  // I's blind's blind is kept in its actual form
  pub fn i_blind_blind(&self) -> <Ed25519 as Ciphersuite>::F {
    self.r_r_i
  }
  /// The scalar to use with `CBlind::new`.
  pub fn c_blind(&self) -> <Ed25519 as Ciphersuite>::F {
    -self.r_c
  }

  /// The input tuple produced by this output and set of rerandomizations.
  pub fn input(&self) -> Input {
    Input {
      O_tilde: self.O_tilde.to_bytes(),
      I_tilde: self.I_tilde.to_bytes(),
      R: self.R.to_bytes(),
      C_tilde: self.C_tilde.to_bytes(),
    }
  }
}

/// The opening for the O~, I~, R of an Input tuple.
///
/// This does not open C~ as it's unnecessary for the purposes of this proof.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OpenedInputTuple {
  O_tilde: <Ed25519 as Ciphersuite>::G,
  I_tilde: <Ed25519 as Ciphersuite>::G,
  R: <Ed25519 as Ciphersuite>::G,
  C_tilde: <Ed25519 as Ciphersuite>::G,

  // O~ = xG + yT
  x: <Ed25519 as Ciphersuite>::F,
  y: <Ed25519 as Ciphersuite>::F,
  // R = r_i V + r_r_i T
  r_i: <Ed25519 as Ciphersuite>::F,
  r_r_i: <Ed25519 as Ciphersuite>::F,
}

impl OpenedInputTuple {
  /// Open a re-randomized output as necessary for spending it.
  ///
  /// x and y are for the x and y variables in `O = xG + yT`.
  pub fn open(
    rerandomized_output: &RerandomizedOutput,
    x: &<Ed25519 as Ciphersuite>::F,
    y: &<Ed25519 as Ciphersuite>::F,
  ) -> Option<OpenedInputTuple> {
    // Verify the opening is consistent.
    let mut y_tilde = rerandomized_output.r_o + y;
    if ((<Ed25519 as Ciphersuite>::generator() * x) + (*T * y_tilde)) != rerandomized_output.O_tilde
    {
      y_tilde.zeroize();
      None?;
    }
    Some(OpenedInputTuple {
      O_tilde: rerandomized_output.O_tilde,
      I_tilde: rerandomized_output.I_tilde,
      R: rerandomized_output.R,
      C_tilde: rerandomized_output.C_tilde,

      x: *x,
      y: y_tilde,
      r_i: rerandomized_output.r_i,
      r_r_i: rerandomized_output.r_r_i,
    })
  }

  /// The input tuple produced by this output and set of rerandomizations.
  pub fn input(&self) -> Input {
    Input {
      O_tilde: self.O_tilde.to_bytes(),
      I_tilde: self.I_tilde.to_bytes(),
      R: self.R.to_bytes(),
      C_tilde: self.C_tilde.to_bytes(),
    }
  }
}

/// The Spend-Authorization and Linkability proof for an input under FCMP++.
// BP+ and GSP Conjuction from Cypher Stack's Review of the FCMP++ Composition
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SpendAuthAndLinkability {
  P: [u8; 32],
  A: [u8; 32],
  B: [u8; 32],
  R_O: [u8; 32],
  R_P: [u8; 32],
  R_L: [u8; 32],
  s_alpha: <Ed25519 as Ciphersuite>::F,
  s_beta: <Ed25519 as Ciphersuite>::F,
  s_delta: <Ed25519 as Ciphersuite>::F,
  s_y: <Ed25519 as Ciphersuite>::F,
  s_z: <Ed25519 as Ciphersuite>::F,
  s_r_p: <Ed25519 as Ciphersuite>::F,
}

impl SpendAuthAndLinkability {
  #[allow(clippy::too_many_arguments)]
  fn challenge(
    signable_tx_hash: [u8; 32],
    input: &Input,
    L: EdwardsPoint,
    P: [u8; 32],
    A: [u8; 32],
    B: [u8; 32],
    R_O: [u8; 32],
    R_P: [u8; 32],
    R_L: [u8; 32],
  ) -> Scalar {
    let mut transcript = Blake2bMonero::new(64).expect("personal length is valid");

    transcript.update(&signable_tx_hash);
    input.transcript(&mut transcript, L);

    transcript.update(&P);
    transcript.update(&A);
    transcript.update(&B);
    transcript.update(&R_O);
    transcript.update(&R_P);
    transcript.update(&R_L);

    let mut output = [0u8; 64];
    transcript.try_finalize_into(&mut output).expect("output length valid");
    Scalar::from_bytes_mod_order_wide(&output)
  }

  /// Prove a Spend-Authorization and Linkability proof.
  ///
  /// This returns the key image with the proof.
  pub fn prove(
    rng: &mut (impl RngCore + CryptoRng),
    signable_tx_hash: [u8; 32],
    opening: &OpenedInputTuple,
  ) -> (<Ed25519 as Ciphersuite>::G, SpendAuthAndLinkability) {
    let G = <Ed25519 as Ciphersuite>::G::generator();
    let T_ = *T;
    let U = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let V = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let L = (opening.I_tilde * opening.x) - (U * (opening.r_i * opening.x));

    let alpha = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let beta = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let delta = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let mu = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let r_y = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let r_z = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let r_p = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));
    let r_r_p = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut *rng));

    let x_r_i = Zeroizing::new(opening.x * opening.r_i);

    let P = (G * opening.x) + (V * opening.r_i) + (U * *x_r_i) + (T_ * *r_p);

    let alpha_G = G * *alpha;

    let A =
      alpha_G + (V * *beta) + (U * ((*alpha * opening.r_i) + (*beta * opening.x))) + (T_ * *delta);
    let B = (U * (*alpha * *beta)) + (T_ * *mu);

    let R_O = alpha_G + (T_ * *r_y);
    let R_P = (U * *r_z) + (T_ * *r_r_p);
    let R_L = (opening.I_tilde * *alpha) - (U * *r_z);

    let e = Self::challenge(
      signable_tx_hash,
      &opening.input(),
      L,
      P.to_bytes(),
      A.to_bytes(),
      B.to_bytes(),
      R_O.to_bytes(),
      R_P.to_bytes(),
      R_L.to_bytes(),
    );

    let s_alpha = *alpha + (e * opening.x);
    let s_beta = *beta + (e * opening.r_i);
    let s_delta = *mu + (e * *delta) + (*r_p * e.square());
    let s_y = *r_y + (e * opening.y);
    // z is x_r_i
    let s_z = *r_z + (e * *x_r_i);
    // r_p is overloaded into r_p' and r_p'' by the paper, hence this distinguishing
    let r_p_double_quote = Zeroizing::new(*r_p - opening.y - opening.r_r_i);
    let s_r_p = *r_r_p + (e * *r_p_double_quote);

    (
      L,
      SpendAuthAndLinkability {
        P: P.to_bytes(),
        A: A.to_bytes(),
        B: B.to_bytes(),
        R_O: R_O.to_bytes(),
        R_P: R_P.to_bytes(),
        R_L: R_L.to_bytes(),
        s_alpha,
        s_beta,
        s_delta,
        s_y,
        s_z,
        s_r_p,
      },
    )
  }

  /// Verify a Spend-Authorization and Linkability proof.
  ///
  /// This only queues the proof for batch verification. The BatchVerifier MUST also be verified.
  ///
  /// If this function returns an error, the BatchVerifier MUST be considered corrupted and
  /// discarded.
  #[allow(clippy::result_unit_err)]
  pub fn verify(
    &self,
    rng: &mut (impl RngCore + CryptoRng),
    verifier: &mut multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
    signable_tx_hash: [u8; 32],
    input: &Input,
    L: <Ed25519 as Ciphersuite>::G,
  ) -> Result<(), std_shims::io::Error> {
    let G = <Ed25519 as Ciphersuite>::G::generator();
    let T_ = *T;
    let U = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let V = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let O_tilde = Ed25519::read_G(&mut input.O_tilde.as_slice())?;
    let I_tilde = Ed25519::read_G(&mut input.I_tilde.as_slice())?;
    let R = Ed25519::read_G(&mut input.R.as_slice())?;

    let Self { P, A, B, R_O, R_P, R_L, s_alpha, s_beta, s_delta, s_y, s_z, s_r_p } = self;

    let e = Self::challenge(signable_tx_hash, input, L, *P, *A, *B, *R_O, *R_P, *R_L);

    let P = Ed25519::read_G(&mut P.as_slice())?;
    let A = Ed25519::read_G(&mut A.as_slice())?;
    let B = Ed25519::read_G(&mut B.as_slice())?;
    let R_O = Ed25519::read_G(&mut R_O.as_slice())?;
    let R_P = Ed25519::read_G(&mut R_P.as_slice())?;
    let R_L = Ed25519::read_G(&mut R_L.as_slice())?;

    // BP+ Verification Statement
    verifier.queue(
      rng,
      (),
      [
        (e * e, P),
        (e, A),
        (Scalar::ONE, B),
        // RHS
        (-(s_alpha * e), G),
        (-(s_beta * e), V),
        (-(s_alpha * s_beta), U),
        (-s_delta, T_),
      ],
    );

    // O_tilde GSP Verification Statement
    verifier.queue(
      rng,
      (),
      [
        (Scalar::ONE, R_O),
        (e, O_tilde),
        // RHS
        (-s_alpha, G),
        (-s_y, T_),
      ],
    );

    // P' GSP Verification Statement
    verifier.queue(
      rng,
      (),
      [
        (Scalar::ONE, R_P),
        (e, (P - O_tilde - R)),
        // RHS
        (-s_z, U),
        (-s_r_p, T_),
      ],
    );

    // L GSP Verification Statement
    verifier.queue(
      rng,
      (),
      [
        (Scalar::ONE, R_L),
        (e, L),
        // RHS
        (-s_alpha, I_tilde),
        // This term was supposed to be subtracted, so our negation cancels out
        (*s_z, U),
      ],
    );

    Ok(())
  }

  /// Write a Spend-Authorization and Linkability proof.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.P)?;
    writer.write_all(&self.A)?;
    writer.write_all(&self.B)?;
    writer.write_all(&self.R_O)?;
    writer.write_all(&self.R_P)?;
    writer.write_all(&self.R_L)?;
    writer.write_all(&self.s_alpha.to_repr())?;
    writer.write_all(&self.s_beta.to_repr())?;
    writer.write_all(&self.s_delta.to_repr())?;
    writer.write_all(&self.s_y.to_repr())?;
    writer.write_all(&self.s_z.to_repr())?;
    writer.write_all(&self.s_r_p.to_repr())
  }

  /// Read a Spend-Authorization and Linkability proof.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    Ok(Self {
      P: monero_io::read_bytes(reader)?,
      A: monero_io::read_bytes(reader)?,
      B: monero_io::read_bytes(reader)?,
      R_O: monero_io::read_bytes(reader)?,
      R_P: monero_io::read_bytes(reader)?,
      R_L: monero_io::read_bytes(reader)?,
      s_alpha: Ed25519::read_F(reader)?,
      s_beta: Ed25519::read_F(reader)?,
      s_delta: Ed25519::read_F(reader)?,
      s_y: Ed25519::read_F(reader)?,
      s_z: Ed25519::read_F(reader)?,
      s_r_p: Ed25519::read_F(reader)?,
    })
  }
}
