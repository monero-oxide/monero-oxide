use core::{ops::Deref as _, fmt::Debug};
use std_shims::{io, collections::HashMap};

use rand_core::{RngCore, CryptoRng, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};

use dalek_ff_group::{Scalar, EdwardsPoint, Ed25519};
use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  },
  Ciphersuite,
};

use modular_frost::{
  FrostError, Participant, ThresholdKeys, ThresholdView,
  algorithm::{WriteAddendum, Algorithm},
};

use monero_fcmp_plus_plus_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V};

use crate::{T, sal::*};

#[derive(Clone, PartialEq, Eq, Zeroize)]
struct PartialSpendAuthAndLinkability {
  P: <Ed25519 as Ciphersuite>::G,
  A: <Ed25519 as Ciphersuite>::G,
  B: <Ed25519 as Ciphersuite>::G,
  R_O: <Ed25519 as Ciphersuite>::G,
  R_P: <Ed25519 as Ciphersuite>::G,
  R_L: <Ed25519 as Ciphersuite>::G,
  s_beta: <Ed25519 as Ciphersuite>::F,
  s_delta: <Ed25519 as Ciphersuite>::F,
  s_y: <Ed25519 as Ciphersuite>::F,
  s_r_p: <Ed25519 as Ciphersuite>::F,
  r_z: Zeroizing<<Ed25519 as Ciphersuite>::F>,
}

impl core::fmt::Debug for PartialSpendAuthAndLinkability {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("PartialSpendAuthAndLinkability").finish_non_exhaustive()
  }
}

/// Addendum produced during the signing process.
#[derive(Clone, PartialEq, Eq, Zeroize, Debug)]
pub struct SalLegacyAddendum {
  key_image_share: EdwardsPoint,
  x_U_share: EdwardsPoint,
}

impl SalLegacyAddendum {
  /// The key image share within this addendum.
  pub fn key_image_share(&self) -> EdwardsPoint {
    self.key_image_share
  }
}

impl WriteAddendum for SalLegacyAddendum {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.key_image_share.compress().to_bytes())?;
    writer.write_all(&self.x_U_share.compress().to_bytes())
  }
}

/// An algorithm to produce a SpendAuthAndLinkability with modular-frost.
///
/// This panics if the message signed for isn't empty. The entire message is expected to be
/// specified at initialization.
///
/// This may panic if functions are not called in the expected order.
#[derive(Clone)]
pub struct SalLegacyAlgorithm<
  R: Send + Sync + Clone + RngCore + CryptoRng,
  T: Sync + Clone + Debug + Transcript,
> {
  rng: R,
  transcript: T,
  signable_tx_hash: [u8; 32],
  rerandomized_output: RerandomizedOutput,
  y: Scalar,
  I: EdwardsPoint,
  key_image_shares: HashMap<[u8; 32], EdwardsPoint>,
  x_U_shares: HashMap<[u8; 32], EdwardsPoint>,
  L: EdwardsPoint,
  x_U: EdwardsPoint,
  partial: Option<PartialSpendAuthAndLinkability>,
  e: Option<Scalar>,
}

impl<R: Send + Sync + Clone + RngCore + CryptoRng, T: Sync + Clone + Debug + Transcript>
  core::fmt::Debug for SalLegacyAlgorithm<R, T>
{
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("SalLegacyAlgorithm").finish_non_exhaustive()
  }
}

impl<R: Send + Sync + Clone + RngCore + CryptoRng, T: Sync + Clone + Debug + Transcript>
  Algorithm<Ed25519> for SalLegacyAlgorithm<R, T>
{
  type Transcript = T;
  type Addendum = SalLegacyAddendum;
  type Signature = (EdwardsPoint, SpendAuthAndLinkability);

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn nonces(&self) -> Vec<Vec<EdwardsPoint>> {
    // One nonce, represented across G, U, I_tilde
    vec![vec![
      EdwardsPoint::generator(),
      EdwardsPoint((*FCMP_PLUS_PLUS_U).into()),
      self.rerandomized_output.I_tilde,
    ]]
  }

  fn preprocess_addendum<R2: RngCore + CryptoRng>(
    &mut self,
    _rng: &mut R2,
    keys: &ThresholdKeys<Ed25519>,
  ) -> SalLegacyAddendum {
    SalLegacyAddendum {
      key_image_share: self.I * keys.original_secret_share().deref(),
      // This could be done once, not per signing protocol, but it'd require a dedicated
      // interactive migration protocol for all existing multisigs
      x_U_share: EdwardsPoint((*FCMP_PLUS_PLUS_U).into()) * keys.original_secret_share().deref(),
    }
  }
  fn read_addendum<R2: io::Read>(&self, reader: &mut R2) -> io::Result<Self::Addendum> {
    let key_image_share = Ed25519::read_G(reader)?;
    let x_U_share = Ed25519::read_G(reader)?;

    Ok(SalLegacyAddendum { key_image_share, x_U_share })
  }

  fn process_addendum(
    &mut self,
    view: &ThresholdView<Ed25519>,
    l: Participant,
    addendum: Self::Addendum,
  ) -> Result<(), FrostError> {
    // Transcript this participant's contribution
    self.transcript.append_message(b"participant", l.to_bytes());
    self
      .transcript
      .append_message(b"key_image_share", addendum.key_image_share.compress().to_bytes());
    self.transcript.append_message(b"x_U_share", addendum.x_U_share.compress().to_bytes());

    // Accumulate the interpolated shares
    let interpolation_factor = view.scalar() *
      view
        .interpolation_factor(l)
        .ok_or(FrostError::InternalError("processing addendum from unincluded participant"))?;
    let mut interpolated_key_image_share = addendum.key_image_share * interpolation_factor;
    let mut interpolated_x_U_share = addendum.x_U_share * interpolation_factor;

    // TODO: This introspects how `dkg` applies the offset to secret shares. Upstream to `dkg`?
    if *view
      .included()
      .first()
      .ok_or(FrostError::InternalError("processing addendum but no signers incluced"))? ==
      l
    {
      interpolated_key_image_share += self.I * view.offset();
      interpolated_x_U_share += EdwardsPoint((*FCMP_PLUS_PLUS_U).into()) * view.offset();
    }

    self.L += interpolated_key_image_share;
    self.x_U += interpolated_x_U_share;

    self
      .key_image_shares
      .insert(view.verification_share(l).to_bytes(), interpolated_key_image_share);

    self.x_U_shares.insert(view.verification_share(l).to_bytes(), interpolated_x_U_share);

    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &ThresholdView<Ed25519>,
    nonce_sums: &[Vec<EdwardsPoint>],
    nonces: Vec<Zeroizing<Scalar>>,
    msg: &[u8],
  ) -> Scalar {
    assert!(msg.is_empty(), "SalLegacyAlgorithm message wasn't empty");

    let T_ = *T;
    let U = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let V = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let y = self.y + self.rerandomized_output.r_o;

    // We deterministically derive all the nonces which aren't for the `x` parameter as that's the
    // only variable considered private by this protocol
    let mut deterministic_nonces =
      ChaCha20Rng::from_seed(self.transcript.rng_seed(b"deterministic_nonces"));

    let beta = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let delta = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let mu = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let r_y = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let r_z = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let r_p = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));
    let r_r_p = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut deterministic_nonces));

    /*
      We have to sign:

        - `s_alpha = alpha + (e * x)`
        - `s_z = r_z + (e * (x * r_i))

      We use the nonce we generated as `alpha`, with `x` as our secret represented by our
      ThresholdKeys. We then observe the following:

        - `s_alpha * r_i = (alpha * r_i) + (e * x * r_i)`

      We can set `r_z` to `alpha * r_i`, then `s_z` to `s_alpha * r_i`, Since `s_alpha` is ZK to
      `x`, any permutations off of it (which don't re-introduce `x`) must also be ZK to `x`. While
      `r_z = alpha * r_i` would be nonce reuse (albeit with a different secret), we don't actually
      reuse `alpha`. We solely specify our commitment to `r_z` to be the scaled commitment to
      `r_i`, which is satisfactory for our purposes here. Reusing commitments isn't an issue as the
      commitments are to uniformly sampled scalars in a group where the discrete-log problem is
      assumed hard.

      It would be publicly observable that `r_z = alpha * r_i`, so we further tweak the supposed
      commitment to `r_z` (the scaled commitment to `alpha`) by a deterministically derived offset
      we label `r_z` here. This resolves as:

        - `R_alpha = alpha U`
        - `R_z = (r_i * R_alpha) + (r_z * U)`
        - `s_alpha = alpha + (e * x)`
        - `s_z = (s_alpha * r_i) + r_z`

      Please note `R_alpha`/`R_z` do not actually exist and are terms in various vector
      commitments.
    */

    let alpha_G = nonce_sums[0][0];
    let R_alpha = nonce_sums[0][1];
    let R_z = (R_alpha * self.rerandomized_output.r_i) + (U * *r_z);

    let P = params.group_key() +
      (V * self.rerandomized_output.r_i) +
      (self.x_U * self.rerandomized_output.r_i) +
      (T_ * *r_p);

    let A = alpha_G +
      (V * *beta) +
      (nonce_sums[0][1] * self.rerandomized_output.r_i) +
      (self.x_U * *beta) +
      (T_ * *delta);
    let B = (nonce_sums[0][1] * *beta) + (T_ * *mu);

    let R_O = alpha_G + (T_ * *r_y);
    let R_P = R_z + (T_ * *r_r_p);
    let R_L = nonce_sums[0][2] - (U * *r_z);

    let e = SpendAuthAndLinkability::challenge(
      self.signable_tx_hash,
      &self.rerandomized_output.input(),
      self.L,
      P.to_bytes(),
      A.to_bytes(),
      B.to_bytes(),
      R_O.to_bytes(),
      R_P.to_bytes(),
      R_L.to_bytes(),
    );

    let s_beta = *beta + (e * self.rerandomized_output.r_i);
    let s_delta = *mu + (e * *delta) + (*r_p * e.square());
    let s_y = *r_y + (e * y);
    // r_p is overloaded into r_p' and r_p'' by the paper, hence this distinguishing
    let r_p_double_quote = Zeroizing::new(*r_p - y - self.rerandomized_output.r_r_i);
    let s_r_p = *r_r_p + (e * *r_p_double_quote);

    self.partial = Some(PartialSpendAuthAndLinkability {
      P,
      A,
      B,
      R_O,
      R_P,
      R_L,
      s_beta,
      s_delta,
      s_y,
      s_r_p,
      r_z,
    });
    self.e = Some(e);

    // Yield the share of s_alpha
    (e * params.secret_share().deref()) + nonces[0].deref()
  }

  fn verify(
    &self,
    _group_key: EdwardsPoint,
    _nonces: &[Vec<EdwardsPoint>],
    sum: Scalar,
  ) -> Option<Self::Signature> {
    type Psaal = PartialSpendAuthAndLinkability;
    let Psaal { P, A, B, R_O, R_P, R_L, s_beta, s_delta, s_y, s_r_p, r_z } =
      { self.partial.clone().unwrap() };
    let s_alpha = sum;
    let s_z = *r_z + (self.rerandomized_output.r_i * s_alpha);
    let sig = SpendAuthAndLinkability {
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
    };

    let mut verifier = multiexp::BatchVerifier::new(4);
    // Use the internal RNG for this
    let () = sig
      .verify(
        &mut self.rng.clone(),
        &mut verifier,
        self.signable_tx_hash,
        &self.rerandomized_output.input(),
        self.L,
      )
      .ok()?;
    if verifier.verify_vartime() {
      return Some((self.L, sig));
    }
    None
  }

  fn verify_share(
    &self,
    verification_share: EdwardsPoint,
    nonces: &[Vec<EdwardsPoint>],
    share: Scalar,
  ) -> Result<Vec<(Scalar, EdwardsPoint)>, ()> {
    /*
      We need to verify three statements.

        - alpha G + e VerificationShare == s_alpha G
        - alpha U + e lagrange x U == s_alpha U
        - alpha I~ + e lagrange x (I + r_i U) == s_alpha I~
    */

    let key_image_share = self.key_image_shares[&verification_share.to_bytes()];
    let x_U_share = self.x_U_shares[&verification_share.to_bytes()];

    let e = self.e.unwrap();

    // Hash every variable relevant here, using the hash output as the random weight
    let mut weight_transcript =
      RecommendedTranscript::new(b"monero-fcmp-plus-plus v0.1 SalLegacyAlgorithm::verify_share");
    weight_transcript.append_message(b"G", EdwardsPoint::generator().to_bytes());
    weight_transcript.append_message(b"U", EdwardsPoint((*FCMP_PLUS_PLUS_U).into()).to_bytes());
    weight_transcript.append_message(b"I", self.I.to_bytes());
    weight_transcript.append_message(b"I~", self.rerandomized_output.I_tilde.to_bytes());
    weight_transcript.append_message(b"xG", verification_share.to_bytes());
    weight_transcript.append_message(b"xU", x_U_share.to_bytes());
    weight_transcript.append_message(b"xH", key_image_share.to_bytes());
    weight_transcript.append_message(b"rG", nonces[0][0].to_bytes());
    weight_transcript.append_message(b"rU", nonces[0][1].to_bytes());
    weight_transcript.append_message(b"rI", nonces[0][2].to_bytes());
    weight_transcript.append_message(b"e", e.to_repr());
    weight_transcript.append_message(b"s", share.to_repr());
    let weight_u = Scalar::from_bytes_mod_order_wide(&weight_transcript.challenge(b"U").into());
    let weight_i = Scalar::from_bytes_mod_order_wide(&weight_transcript.challenge(b"I").into());

    Ok(vec![
      // G
      (Scalar::ONE, nonces[0][0]),
      (e, verification_share),
      (-share, EdwardsPoint::generator()),
      // U
      (weight_u, nonces[0][1]),
      (weight_u * e, x_U_share),
      (weight_u * -share, EdwardsPoint((*FCMP_PLUS_PLUS_U).into())),
      // `I~`
      (weight_i, nonces[0][2]),
      (weight_i * e, key_image_share),
      // The key image share is `x I`, yet we're checking the verification equation with `I~`
      // `I~` means there's an additional `r_i U` term scaled by `x`
      // We rewrite this from `x r_i U` to `r_i x U` since the prior statement checked `x U`
      (weight_i * e * self.rerandomized_output.r_i, x_U_share),
      (weight_i * -share, self.rerandomized_output.I_tilde),
    ])
  }
}

impl<R: Send + Sync + Clone + RngCore + CryptoRng, T: Sync + Clone + Debug + Transcript>
  SalLegacyAlgorithm<R, T>
{
  /// Sign a SpendAuthAndLinkability proof using modular-frost.
  ///
  /// y is the yet-to-be-rerandomized y committed to within the output key.
  pub fn new(
    rng: R,
    mut transcript: T,
    signable_tx_hash: [u8; 32],
    rerandomized_output: RerandomizedOutput,
    y: <Ed25519 as Ciphersuite>::F,
  ) -> Self {
    transcript.domain_separate(b"SpendAuthAndLinkability Legacy Multisig");

    transcript.append_message(b"signable_tx_hash", signable_tx_hash);

    transcript.append_message(b"O_tilde", rerandomized_output.O_tilde.to_bytes());
    transcript.append_message(b"I_tilde", rerandomized_output.I_tilde.to_bytes());
    transcript.append_message(b"C_tilde", rerandomized_output.C_tilde.to_bytes());
    transcript.append_message(b"R", rerandomized_output.R.to_bytes());

    transcript.append_message(b"r_o", rerandomized_output.r_o.to_repr());
    transcript.append_message(b"r_i", rerandomized_output.r_i.to_repr());
    transcript.append_message(b"r_r_i", rerandomized_output.r_r_i.to_repr());
    transcript.append_message(b"r_c", rerandomized_output.r_c.to_repr());

    transcript.append_message(b"y", y.to_repr());

    let I = rerandomized_output.I_tilde -
      (EdwardsPoint((*FCMP_PLUS_PLUS_U).into()) * rerandomized_output.r_i);

    Self {
      rng,
      transcript,
      signable_tx_hash,
      rerandomized_output,
      y,
      I,
      L: EdwardsPoint::identity(),
      key_image_shares: HashMap::new(),
      x_U: EdwardsPoint::identity(),
      x_U_shares: HashMap::new(),
      partial: None,
      e: None,
    }
  }
}
