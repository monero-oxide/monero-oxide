use crypto_bigint::{Limb, U256};

mod field25519;
use field25519::{Field25519, Z};

use crate::CompressedPoint;

/*
  Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

  A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
  `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
*/
const A_LIMB: Limb = Limb(486662);
const A: Field25519 = Field25519::reduce(U256::from_u64(486662));

const SQRT_NEG_A_2: Field25519 = A.add(Field25519::reduce(U256::from_u8(2))).neg().sqrt().unwrap();

const fn batch_invert<const N: usize>(to_invert: &mut [Field25519; N]) {
  let mut scratch = [Field25519::ZERO; N];

  scratch[0] = to_invert[0];
  let mut i = 1;
  while i < N {
    scratch[i] = scratch[i - 1];
    if !to_invert[i].eq(Field25519::ONE) {
      scratch[i] = scratch[i].chained_mul(to_invert[i]);
    }
    i = i.wrapping_add(1);
  }
  let mut accum = scratch[N.wrapping_sub(1)].inv();

  let mut i = N.wrapping_sub(1);
  while i > 0 {
    let res_i = accum.mul(scratch[i - 1]);
    if !to_invert[i].eq(Field25519::ONE) {
      accum = accum.chained_mul(to_invert[i]);
    }
    to_invert[i] = res_i;
    i = i.wrapping_sub(1);
  }
  to_invert[0] = Field25519::reduce(accum.retrieve());
}

const fn batch_sqrt<const N: usize>(to_sqrt: &mut [Field25519; N], scratch: &mut [Field25519; N]) {
  let originals = *to_sqrt;

  // We want $x^{\floor (p + 3) / 8 \rfloor}$ where $\floor (p + 3) / 8 \rfloor = 2^{253} - 2$
  let mut i = 0;
  while i < to_sqrt.len() {
    if to_sqrt[i].eq(Field25519::ZERO) {
      scratch[i] = Field25519::ONE;
    } else {
      let mut square = to_sqrt[i].square();
      scratch[i] = square;
      let mut j = 2;
      while j < 253 {
        square = square.chained_square();
        j += 1;
      }
      to_sqrt[i] = square;
    }
    i += 1;
  }

  batch_invert(scratch);

  let mut i = 0;
  while i < to_sqrt.len() {
    let y = to_sqrt[i].chained_mul(scratch[i]);
    if y.square().eq(originals[i]) {
      to_sqrt[i] = Field25519::reduce(y.retrieve());
    } else {
      let other = y.chained_mul(Z);
      if other.square().eq(originals[i]) {
        to_sqrt[i] = Field25519::reduce(other.retrieve());
      } else {
        to_sqrt[i] = Field25519::ZERO;
      }
    }
    i += 1;
  }
}

const fn curve_equation(u: Field25519) -> Field25519 {
  u.add_limb(A_LIMB).mul(u.chained_square()).add(u)
}

pub(crate) const fn const_map_batch<const N: usize, const TWO_N: usize>(
  preimages: [[u8; 32]; N],
) -> [CompressedPoint; N] {
  let mut one_plus_ur_square_inv = [Field25519::ZERO; N];
  {
    let mut i = 0;
    while i < N {
      let r = Field25519::reduce(U256::from_le_slice(
        &keccak_const::Keccak256::new().update(&preimages[i]).finalize(),
      ));
      let ur_square = r.square().double();
      one_plus_ur_square_inv[i] = ur_square.add_one();

      i = i.wrapping_add(1);
    }

    batch_invert(&mut one_plus_ur_square_inv);
  }

  let mut upsilon = [Field25519::ZERO; N];
  let mut sqrt_buf = [Field25519::ZERO; N];
  let mut i = 0;
  while i < N {
    upsilon[i] = one_plus_ur_square_inv[i].mul_limb(A_LIMB).neg();
    sqrt_buf[i] = curve_equation(upsilon[i]);

    i = i.wrapping_add(1);
  }

  let mut sqrt_scratch = [Field25519::ZERO; N];
  batch_sqrt(&mut sqrt_buf, &mut sqrt_scratch);

  let mut u_epsilon = [(Field25519::ZERO, 0u8); N];
  let mut x_and_y_denom = [Field25519::ZERO; TWO_N];
  let mut i = 0;
  while i < N {
    if sqrt_buf[i].eq(Field25519::ZERO) {
      upsilon[i] = upsilon[i].add_limb(A_LIMB).neg();
      sqrt_buf[i] = curve_equation(upsilon[i]);
    } else {
      u_epsilon[i] = (upsilon[i], 1);
      x_and_y_denom[i] = sqrt_buf[i];
      x_and_y_denom[i + N] = upsilon[i].add_one();
      upsilon[i] = Field25519::ZERO;
      sqrt_buf[i] = Field25519::ZERO;
    }

    i = i.wrapping_add(1);
  }

  batch_sqrt(&mut sqrt_buf, &mut sqrt_scratch);

  let mut i = 0;
  while i < N {
    if !sqrt_buf[i].eq(Field25519::ZERO) {
      u_epsilon[i] = (upsilon[i], 0);
      x_and_y_denom[i] = sqrt_buf[i];
      x_and_y_denom[i + N] = upsilon[i].add_one();
    }

    i = i.wrapping_add(1);
  }

  // Map to Ed25519
  batch_invert(&mut x_and_y_denom);
  let mut xy = [(Field25519::ZERO, Field25519::ZERO); N];
  // Re-use the scratch space from the no-longer-used `one_plus_ur_square`
  let z = &mut one_plus_ur_square_inv;
  let mut i = 0;
  while i < N {
    let (u_i, epsilon_i) = u_epsilon[i];
    let mut x_i = {
      let x_candidate = SQRT_NEG_A_2.mul(u_i.chained_mul(x_and_y_denom[i]));
      // If the parity of our candidate is distinct from epsilon, negate it
      if ((x_candidate.retrieve().as_limbs()[0].0 % 2) as u8) != epsilon_i {
        x_candidate.neg()
      } else {
        x_candidate
      }
    };
    let mut y_i = u_i.sub_one().mul(x_and_y_denom[i + N]);
    let mut z_i = Field25519::ONE;

    // Clear the cofactor
    // dbl-2008-hwcd, optimized for `a = -1`
    {
      let mut i = 0usize;
      while i < 3 {
        let a = x_i.square();
        let b = y_i.square();
        let c = (if i == 0 { z_i } else { z_i.square() }).double();
        let d = a.neg();
        let e = x_i.add(y_i).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        x_i = e.mul(f);
        y_i = g.mul(h);
        z_i = f.chained_mul(g);

        i = i.wrapping_add(1);
      }
    }

    xy[i] = (x_i, y_i);
    z[i] = z_i;

    i = i.wrapping_add(1);
  }

  // Normalize, encode these points
  batch_invert(z);
  let mut res = [CompressedPoint::IDENTITY; N];
  let mut i = 0;
  while i < N {
    let z_i = z[i];
    let (x, y) = xy[i];
    let x = x.mul(z_i);
    let y = y.mul(z_i);
    // Encode the result
    let y = y.retrieve();
    let mut this = y.to_le_bytes();
    this[31] |= ((x.retrieve().as_limbs()[0].0 % 2) as u8) << 7;
    res[i] = CompressedPoint(this);

    i = i.wrapping_add(1);
  }
  res
}
