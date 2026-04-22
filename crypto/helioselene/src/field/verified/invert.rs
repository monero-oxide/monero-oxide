use super::*;

/// Perform a sub with underflow, bounding the underflow to be zero or one.
///
/// Unlike `sbb`, this returns `0` or `1`, not `0` or `Limb::MAX`.
///
/// This was not one of the functions considered formally verified but is solely used by the
/// following `invert` function, which was. It also was formally verified:
/// https://github.com/VeridiseAuditing/helioselene-dafny-proofs
///   /blob/9da40f40d62776d380f4423124ae7ca6b956f12b/src/crypto_bigint_0_5_5/Limb.dfy#L342-L355
#[inline(always)]
fn sub_with_bounded_overflow(a: Limb, b: Limb, c: Limb) -> (Limb, Limb) {
  let (limb, borrow1) = a.0.overflowing_sub(b.0);
  let (limb, borrow2) = limb.overflowing_sub(c.0);
  (Limb(limb), Limb(Word::from(borrow1 | borrow2)))
}

/// Binary GCD Algorithm 1, https://eprint.iacr.org/2020/972.
///
/// The exact implementation is the stated algorithm but has been heavily optimized with _how_ it's
/// encoded into Rust.
#[inline(always)]
pub(crate) fn invert(value: &HelioseleneField) -> CtOption<HelioseleneField> {
  let mut a = value.0;
  let mut b = MODULUS;
  let mut u = U256::ONE;
  let mut v = U256::ZERO;

  #[inline(always)]
  fn step(a: &mut U256, b: &mut U256, u: &mut U256, v: &mut U256) {
    #[cfg(debug_assertions)]
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let a_b_bits = (a.bits() as u32) + (b.bits() as u32);

    let a_is_odd = a.as_limbs()[0].0 & 1;
    let a_is_odd = Limb(a_is_odd).wrapping_neg();

    // Calculate `a - b`, which also yields if `a < b` by if it underflows
    let mut borrow = Limb::ZERO;
    let mut a_sub_b = U256::ZERO;
    for l in 0 .. U256::LIMBS {
      (a_sub_b.as_limbs_mut()[l], borrow) =
        sub_with_bounded_overflow(a.as_limbs()[l], b.as_limbs()[l], borrow);
    }
    let a_lt_b = borrow.wrapping_neg();

    let both = a_is_odd & a_lt_b;

    // https://github.com/VeridiseAuditing/helioselene-dafny-proofs
    //  /blob/9da40f40d62776d380f4423124ae7ca6b956f12b/src/helioselene/field/Base.dfy#L238-L264
    #[inline(always)]
    fn select(a: &U256, b: &U256, choice: Limb) -> U256 {
      let mut res = U256::ZERO;
      for l in 0 .. U256::LIMBS {
        res.as_limbs_mut()[l] = select_word(a.as_limbs()[l], b.as_limbs()[l], choice);
      }
      res
    }

    // Set `b` to `a` (part of the swap defined on line 8 of the algorithm's description)
    *b = select(b, a, both);

    // Negate `a_sub_b` to obtain `a_diff_b` if `a_lt_b`
    let a_diff_b = {
      // Negation is applying the logical NOT to every word while adding 1
      let mut carry = Limb::ONE & a_lt_b;
      let mut a_diff_b = U256::ZERO;
      for l in 0 .. U256::LIMBS {
        // (a ^ x) is a logical NOT if `x` is set and a NOP if `x` is 0
        let limb;
        let carry_bool;
        (limb, carry_bool) = (a_sub_b.as_limbs()[l] ^ a_lt_b).0.overflowing_add(carry.0);
        (a_diff_b.as_limbs_mut()[l], carry) = (Limb(limb), Limb(Word::from(carry_bool)));
      }
      a_diff_b
    };
    // Leave `a` untouched if `a` is even, else set `a` to the difference of `a` and `b`
    *a = select(a, &a_diff_b, a_is_odd);

    /*
      The following code immediately takes the difference of `u - v`, before negating to
      obtain `v - u` if necessary. The advantage to this methodology, compared to swapping
      `u, v` and then peforming the subtraction, is how during the negation any required
      additions of the modulus can be performed.
    */

    let u_start = *u;

    // Calculate `v` or `v - u` depending on if `a & 1`
    let mut borrow = Limb::ZERO;
    let mut u_sub_v = U256::ZERO;
    for l in 0 .. U256::LIMBS {
      (u_sub_v.as_limbs_mut()[l], borrow) =
        sub_with_bounded_overflow(u.as_limbs()[l], v.as_limbs()[l] & a_is_odd, borrow);
    }
    let u_sub_v_neg = borrow.wrapping_neg();

    // Negate in the case `(a & 1) & (a < b)`
    let should_negate = a_is_odd & a_lt_b;
    /*
      Whether the resulting number will be negative, with the exceptional case of if the
      resulting number is 0, in which case this iteration will terminate with `u = MODULUS`.
      `u, v` being not in the range `0 .. MODULUS` yet `0 ..= MODULUS` does not affect this
      algorithm at all, until the very end when we do expect the value to be in-range. The
      worst case, we calculate `0 - MODULUS -> -MODULUS`, will cause addition of the `MODULUS`
      (due to the underflow) and a result of `0`.

      One final reduction, outside of this loop, is cheaper than checking if the number is
      -0 on every loop iteration.
    */
    let v_u_sub_u_v_neg = u_sub_v_neg ^ should_negate;

    // Negation is the logical NOT *and* the addition of the constant `1`, so this is the
    // parity regardless of if we're about to perform a negation
    let result_is_odd = (u_sub_v.as_limbs()[0] & Limb::ONE).wrapping_neg();

    /*
      This is a XOR as to allow `add_one_modulus` and `add_two_modulus` to be simultaneously
      set and achieve the desired result. If it is modified to the modulus directly, then we'd
      require `add_one_modulus` and `add_two_modulus` be exclusive which may enable the
      compiler to be intelligent enough to insert a branch.

      This pattern does allow the compiler to, if it realizes `add_two_modulus` is only set
      when `add_one_modulus` is, create the XOR'd constant and compress to a branch, yet that
      should be much tricker for an optimization pass.
    */
    const MODULUS_XOR_TWO_MODULUS: U256 =
      U256::from_be_hex("80000000000000000000000000000000195fd8272bba15380a8f1db9613261f5");
    /*
      Add two instances of the modulus if:
      - We must add one instance due to the current number being negative
      - Adding one instance will cause the result to be odd
    */
    let add_two_modulus = v_u_sub_u_v_neg & (!result_is_odd);
    // Add one instance if negative/currently odd but not both
    let add_one_modulus = v_u_sub_u_v_neg | result_is_odd;

    // This is the starting carry for the negation algorithm
    let mut carry = Limb::ONE & should_negate;
    for l in 0 .. U128::LIMBS {
      // The modulus to add in, to correct for underflow/enable halving
      let modulus_instances = (MODULUS.as_limbs()[l] & add_one_modulus) ^
        (MODULUS_XOR_TWO_MODULUS.as_limbs()[l] & add_two_modulus);

      /*
        Instead of adding the 255-bit modulus, it may be more efficient to subtract out the
        distance from 2**255, which is only 127 bits. This would be quite marginal however on
        64-bit platforms, where four additions would be replaced with two subtractions and one
        binary OR.
      */
      // The carry is bounded to be `<= 1` and the low 128-bits of the modulus aren't full
      let (limb, carry_bool) = (u_sub_v.as_limbs()[l] ^ should_negate)
        .0
        .overflowing_add(modulus_instances.wrapping_add(carry).0);
      (u.as_limbs_mut()[l], carry) = (Limb(limb), Limb(Word::from(carry_bool)));
    }
    // Unroll the later iterations due to the structure of the XOR
    for l in U128::LIMBS .. U256::LIMBS {
      let modulus_instances = MODULUS.as_limbs()[l] & add_one_modulus;

      (u.as_limbs_mut()[l], carry) =
        add_with_bounded_overflow(u_sub_v.as_limbs()[l] ^ should_negate, modulus_instances, carry);
    }
    u.as_limbs_mut()[U256::LIMBS - 1] =
      u.as_limbs()[U256::LIMBS - 1] | (add_two_modulus << (Limb::BITS - 1));

    // Set `v` to the `u` from the start if `(a & 1) & (a < b)`
    *v = select(v, &u_start, both);

    // Divide by 2
    *a = a.shr_vartime(1);
    *u = u.shr_vartime(1);

    #[cfg(debug_assertions)]
    {
      debug_assert!(bool::from({
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
        let new_a_b_bits = (a.bits() as u32) + (b.bits() as u32);
        (new_a_b_bits.ct_lt(&a_b_bits)) | a.ct_eq(&U256::ZERO)
      }));
    }
  }

  // Note the limbs still in use so we don't apply operations over unused limbs
  for _ in 2 ..= U256::LIMBS {
    for _ in 0 .. (2 * Limb::BITS) {
      step(&mut a, &mut b, &mut u, &mut v);
    }
  }
  for _ in 0 .. ((2 * Limb::BITS) - 2) {
    step(&mut a, &mut b, &mut u, &mut v);
  }

  CtOption::new(HelioseleneField(red1(v)), !value.is_zero())
}

#[test]
fn invert_3_66() {
  let three_66 =
    HelioseleneField::from_repr(U256::from(3u8).shl_vartime(66).to_le_bytes()).unwrap();
  assert_eq!(three_66.invert().unwrap() * three_66, HelioseleneField::ONE);
}
