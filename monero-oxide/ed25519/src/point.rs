use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};
use zeroize::Zeroize;

use sha3::{Digest, Keccak256};

use crate::CompressedPoint;

/// A decompressed point on the Ed25519 elliptic curve.
#[derive(Clone, Copy, Eq, Debug, Zeroize)]
pub struct Point(curve25519_dalek::EdwardsPoint);

impl ConstantTimeEq for Point {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.0.ct_eq(&other.0)
  }
}

impl PartialEq for Point {
  /// This defers to `ConstantTimeEq::ct_eq`.
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.ct_eq(other))
  }
}

impl Point {
  /// Sample a biased point via a hash function.
  ///
  /// This is comparable to Monero's `hash_to_ec` function.
  ///
  /// This achieves parity with https://github.com/monero-project/monero
  ///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto.cpp#L611, inlining the
  /// `ge_fromfe_frombytes_vartime` function (https://github.com/monero-project/monero
  ///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto-ops.c#L2309). This
  /// implementation runs in constant time.
  ///
  /// According to the original authors
  /// (https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf), this
  /// would implement https://arxiv.org/abs/0706.1448. Shen Noether also describes the algorithm
  /// (https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf), yet without reviewing
  /// its security and in a very straight-forward fashion.
  ///
  /// In reality, this implements Elligator 2 as detailed in
  /// "Elligator: Elliptic-curve points indistinguishable from uniform random strings"
  /// (https://eprint.iacr.org/2013/325). Specifically, Section 5.5 details the application of
  /// Elligator 2 to Curve25519, after which the result is mapped to Ed25519.
  ///
  /// As this only applies Elligator 2 once, it's limited to a subset of points where a certain
  /// derivative of their `u` coordinates (in Montgomery form) are quadratic residues. It's biased
  /// accordingly. The yielded points SHOULD still have uniform relations to each other however.
  pub fn biased_hash(bytes: [u8; 32]) -> Self {
    use crypto_bigint::{Encoding, modular::constant_mod::*, U256, impl_modulus, const_residue};

    const MODULUS_STR: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    impl_modulus!(Two25519, U256, MODULUS_STR);

    type Two25519Residue = Residue<Two25519, { U256::LIMBS }>;

    /*
      Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

      A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
      `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
    */
    const A_U256: U256 = U256::from_u64(486662);
    const A: Two25519Residue = const_residue!(A_U256, Two25519);
    const NEGATIVE_A: Two25519Residue = A.neg();

    // Sample a uniform field element
    /*
      This isn't a wide reduction, implying it'd be biased, yet the bias should only be negligible
      due to the shape of the prime number. All elements within the prime field field have a
      `2 / 2^{256}` chance of being selected, except for the first 19 which have a `3 / 2^256`
      chance of being selected. In order for this 'third chance' (the bias) to be relevant, the
      hash function would have to output a number greater than or equal to:

        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda

      which is of negligible probability.
    */
    let r = Two25519Residue::new(&U256::from_le_bytes(Keccak256::digest(bytes).into()));

    // Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
    let r_square = r.square();
    let ur_square = r_square + r_square;

    /*
      We know this is non-zero as:

      ```sage
      p = 2**255 - 19
      Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
      ```
    */
    let one_plus_ur_square = Two25519Residue::ONE + ur_square;
    let (one_plus_ur_square_inv, _value_was_zero) = one_plus_ur_square.invert();
    let upsilon = NEGATIVE_A * one_plus_ur_square_inv;
    /*
      Quoting section 5.5,
      "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

      Whereas in the specification present in Section 5.2, the expansion of the `u` coordinate when
      `\epsilon = -1` is `-\upsilon - A`. Per Section 5.2, in the "Second case",
      `= -\upsilon - A = \upsilon u r^2`. These two values are equivalent, yet the negation and
      subtract outperform a multiplication.
    */
    let other_candidate = -upsilon - A;

    // RFC-8032 provides `sqrt8k5`
    fn is_quadratic_residue_8_mod_5(value: &Two25519Residue) -> Choice {
      // (p + 3) // 8
      const SQRT_EXP: U256 = Two25519::MODULUS.shr_vartime(3).wrapping_add(&U256::ONE);
      // 2^{(p - 1) // 4}
      const Z: Two25519Residue =
        Two25519Residue::ONE.add(&Two25519Residue::ONE).pow(&Two25519::MODULUS.shr_vartime(2));
      let y = value.pow(&SQRT_EXP);
      let other_candidate = y * Z;
      // If `value` is a quadratic residue, one of these will be its square root
      y.square().ct_eq(value) | other_candidate.square().ct_eq(value)
    }

    /*
      Check if `\upsilon` is a valid `u` coordinate by checking for a solution for the square root
      of `\upsilon^3 + A \upsilon^2 + \upsilon`.
    */
    let epsilon = is_quadratic_residue_8_mod_5(&(((upsilon + A) * upsilon.square()) + upsilon));
    let u = Two25519Residue::conditional_select(&other_candidate, &upsilon, epsilon);

    // Map from Curve25519 to Ed25519
    /*
      Elligator 2's specification in section 5.2 says to choose the negative square root as the
      `v` coordinate if `\upsilon` was chosen (as signaled by `\epsilon = 1`). The following
      chooses the odd `y` coordinate if `\upsilon` was chosen, which is functionally equivalent.
    */
    let res = curve25519_dalek::MontgomeryPoint(u.retrieve().to_le_bytes())
      .to_edwards(epsilon.unwrap_u8())
      .expect("neither Elligator 2 candidate was a square");

    // Ensure this point lies within the prime-order subgroup
    Self::from(res.mul_by_cofactor())
  }

  /// Compress a point to a `CompressedPoint`.
  pub fn compress(self) -> CompressedPoint {
    CompressedPoint::from(self.0.compress().to_bytes())
  }

  /// Create a `Point` from a `curve25519_dalek::EdwardsPoint`.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn from(point: curve25519_dalek::EdwardsPoint) -> Self {
    Self(point)
  }

  /// Create a `curve25519_dalek::EdwardsPoint` from a `Point`.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn into(self) -> curve25519_dalek::EdwardsPoint {
    self.0
  }

  /// Interpret a point as a key image.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn key_image(self) -> Option<curve25519_dalek::EdwardsPoint> {
    use curve25519_dalek::traits::IsIdentity;
    if self.0.is_identity() || (!self.0.is_torsion_free()) {
      None?;
    }
    Some(self.0)
  }
}
