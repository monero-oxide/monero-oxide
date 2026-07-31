use core::{
  ops::{DerefMut as _, Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
  iter::Sum,
};

use rand_core::RngCore;

use zeroize::Zeroize;
#[rustfmt::skip]
use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable as _};

use group::{
  ff::{Field as _, PrimeField, PrimeFieldBits as _},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

use dalek_ff_group::FieldElement as Field25519;
use crate::{u8_from_bool, field::HelioseleneField};

macro_rules! curve {
  (
    $Scalar: ident,
    $Field: ident,
    $Point: ident,
    $B: expr,
    $G_Y: expr,
  ) => {
    const G_X: $Field = $Field::from_u256(&U256::from_u8(1));
    const G_Y: $Field = $G_Y;

    const B: $Field = $B;

    // Evaluate the curve equation to obtain what would be the `y^2` for this `x`, if it was the
    // `x` coordinate for a valid, on-curve point
    fn curve_equation(x: $Field) -> $Field {
      (x.square() * x) - x.double() - x + B
    }

    fn recover_y(x: $Field) -> CtOption<$Field> {
      // x**3 + -3x + B
      curve_equation(x).sqrt()
    }

    /// Point.
    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    pub struct $Point {
      x: $Field, // / Z
      y: $Field, // / Z
      z: $Field,
    }

    impl Zeroize for $Point {
      fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        let identity = Self::identity();
        self.x = identity.x;
        self.y = identity.y;
        self.z = identity.z;
      }
    }

    const G: $Point = $Point { x: G_X, y: G_Y, z: $Field::ONE };

    impl ConstantTimeEq for $Point {
      fn ct_eq(&self, other: &Self) -> Choice {
        let x1 = self.x * other.z;
        let x2 = other.x * self.z;

        let y1 = self.y * other.z;
        let y2 = other.y * self.z;

        (self.x.is_zero() & other.x.is_zero()) | (x1.ct_eq(&x2) & y1.ct_eq(&y2))
      }
    }

    impl PartialEq for $Point {
      fn eq(&self, other: &$Point) -> bool {
        self.ct_eq(other).into()
      }
    }

    impl Eq for $Point {}

    impl ConditionallySelectable for $Point {
      fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        $Point {
          x: $Field::conditional_select(&a.x, &b.x, choice),
          y: $Field::conditional_select(&a.y, &b.y, choice),
          z: $Field::conditional_select(&a.z, &b.z, choice),
        }
      }
    }

    impl Add for $Point {
      type Output = $Point;
      #[allow(non_snake_case)]
      fn add(self, other: Self) -> Self {
        // add-2015-rcb-3
        let X1 = self.x;
        let Y1 = self.y;
        let Z1 = self.z;
        let X2 = other.x;
        let Y2 = other.y;
        let Z2 = other.z;

        let t0 = X1 * X2;
        let t1 = Y1 * Y2;
        let t2 = Z1 * Z2;
        let t3 = X1 + Y1;
        let t4 = X2 + Y2;
        let t3 = t3 * t4;
        let t4 = t0 + t1;
        let t3 = t3 - t4;
        let t4 = Y1 + Z1;
        let X3 = Y2 + Z2;
        let t4 = t4 * X3;
        let X3 = t1 + t2;
        let t4 = t4 - X3;
        let X3 = X1 + Z1;
        let Y3 = X2 + Z2;
        let X3 = X3 * Y3;
        let Y3 = t0 + t2;
        let Y3 = X3 - Y3;
        let Z3 = B * t2;
        let X3 = Y3 - Z3;
        let Z3 = X3.double();
        let X3 = X3 + Z3;
        let Z3 = t1 - X3;
        let X3 = t1 + X3;
        let Y3 = B * Y3;
        let t1 = t2.double();
        let t2 = t1 + t2;
        let Y3 = Y3 - t2;
        let Y3 = Y3 - t0;
        let t1 = Y3.double();
        let Y3 = t1 + Y3;
        let t1 = t0.double();
        let t0 = t1 + t0;
        let t0 = t0 - t2;
        let t1 = t4 * Y3;
        let t2 = t0 * Y3;
        let Y3 = X3 * Z3;
        let Y3 = Y3 + t2;
        let X3 = t3 * X3;
        let X3 = X3 - t1;
        let Z3 = t4 * Z3;
        let t1 = t3 * t0;
        let Z3 = Z3 + t1;

        $Point { x: X3, y: Y3, z: Z3 }
      }
    }

    impl AddAssign for $Point {
      fn add_assign(&mut self, other: $Point) {
        *self = *self + other;
      }
    }

    impl Add<&$Point> for $Point {
      type Output = $Point;
      fn add(self, other: &$Point) -> $Point {
        self + *other
      }
    }

    impl AddAssign<&$Point> for $Point {
      fn add_assign(&mut self, other: &$Point) {
        *self += *other;
      }
    }

    impl Neg for $Point {
      type Output = $Point;
      fn neg(self) -> Self {
        $Point { x: self.x, y: -self.y, z: self.z }
      }
    }

    impl Sub for $Point {
      type Output = $Point;
      #[allow(clippy::suspicious_arithmetic_impl)]
      fn sub(self, other: Self) -> Self {
        self + other.neg()
      }
    }

    impl SubAssign for $Point {
      fn sub_assign(&mut self, other: $Point) {
        *self = *self - other;
      }
    }

    impl Sub<&$Point> for $Point {
      type Output = $Point;
      fn sub(self, other: &$Point) -> $Point {
        self - *other
      }
    }

    impl SubAssign<&$Point> for $Point {
      fn sub_assign(&mut self, other: &$Point) {
        *self -= *other;
      }
    }

    impl Group for $Point {
      type Scalar = $Scalar;
      fn random(mut rng: impl RngCore) -> Self {
        loop {
          let mut bytes = $Field::random(&mut rng).to_repr();
          let mut_ref: &mut [u8] = bytes.as_mut();
          mut_ref[31] |= u8::try_from(rng.next_u32() % 2).unwrap() << 7;
          let opt = Self::from_bytes(&bytes);
          if opt.is_some().into() {
            return opt.unwrap();
          }
        }
      }
      fn identity() -> Self {
        $Point { x: $Field::ZERO, y: $Field::ONE, z: $Field::ZERO }
      }
      fn generator() -> Self {
        G
      }
      fn is_identity(&self) -> Choice {
        self.x.ct_eq(&$Field::ZERO)
      }
      #[allow(non_snake_case)]
      fn double(&self) -> Self {
        // dbl-2007-bl-2
        let X1 = self.x;
        let Y1 = self.y;
        let Z1 = self.z;

        let w = (X1 - Z1) * (X1 + Z1);
        let w = w.double() + w;
        let s = (Y1 * Z1).double();
        let ss = s.square();
        let sss = s * ss;
        let R = Y1 * s;
        let RR = R.square();
        let B_ = (X1 * R).double();
        let h = w.square() - B_.double();
        let X3 = h * s;
        let Y3 = w * (B_ - h) - RR.double();
        let Z3 = sss;

        // If self is identity, res will pass is_identity yet have a distinct internal
        // representation and not be well-formed when used for addition
        let res = Self { x: X3, y: Y3, z: Z3 };
        // Select identity explicitly if this was identity
        Self::conditional_select(&res, &Self::identity(), self.is_identity())
      }
    }

    impl Sum<$Point> for $Point {
      fn sum<I: Iterator<Item = $Point>>(iter: I) -> $Point {
        let mut res = Self::identity();
        for i in iter {
          res += i;
        }
        res
      }
    }

    impl<'a> Sum<&'a $Point> for $Point {
      fn sum<I: Iterator<Item = &'a $Point>>(iter: I) -> $Point {
        $Point::sum(iter.cloned())
      }
    }

    impl Mul<$Scalar> for $Point {
      type Output = $Point;
      fn mul(self, mut other: $Scalar) -> $Point {
        // Precompute the optimal amount that's a multiple of 2
        let mut table = [$Point::identity(); 16];
        table[1] = self;
        table[2] = self.double();
        table[3] = table[2] + self;
        table[4] = table[2].double();
        table[5] = table[4] + self;
        table[6] = table[3].double();
        table[7] = table[6] + self;
        table[8] = table[4].double();
        table[9] = table[8] + self;
        table[10] = table[5].double();
        table[11] = table[10] + self;
        table[12] = table[6].double();
        table[13] = table[12] + self;
        table[14] = table[7].double();
        table[15] = table[14] + self;

        let mut res = Self::identity();
        let mut bits = 0;
        for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
          bits <<= 1;
          let mut bit = u8_from_bool(bit.deref_mut());
          bits |= bit;
          bit.zeroize();

          if ((i + 1) % 4) == 0 {
            if i != 3 {
              for _ in 0 .. 4 {
                res = res.double();
              }
            }

            let mut term = table[0];
            for (j, candidate) in table[1 ..].iter().enumerate() {
              let j = j + 1;
              term = Self::conditional_select(&term, &candidate, usize::from(bits).ct_eq(&j));
            }
            res += term;
            bits = 0;
          }
        }
        other.zeroize();
        res
      }
    }

    impl MulAssign<$Scalar> for $Point {
      fn mul_assign(&mut self, other: $Scalar) {
        *self = *self * other;
      }
    }

    impl Mul<&$Scalar> for $Point {
      type Output = $Point;
      fn mul(self, other: &$Scalar) -> $Point {
        self * *other
      }
    }

    impl MulAssign<&$Scalar> for $Point {
      fn mul_assign(&mut self, other: &$Scalar) {
        *self *= *other;
      }
    }

    impl GroupEncoding for $Point {
      type Repr = <$Field as PrimeField>::Repr;

      fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        // Extract and clear the sign bit
        let sign = Choice::from(bytes[31] >> 7);
        let mut bytes = *bytes;
        let mut_ref: &mut [u8] = bytes.as_mut();
        mut_ref[31] &= !(1 << 7);

        // Parse x, recover y
        $Field::from_repr(bytes).and_then(|x| {
          let is_identity = x.is_zero();

          let y = recover_y(x).map(|mut y| {
            y.conditional_negate(y.is_odd().ct_eq(&!sign));
            y
          });

          // Create the point if we have a solution for `y`
          let point = y.map(|y| $Point { x, y, z: $Field::ONE });

          // Set this to the identity, if it is the encoding of the identity
          let point = <_>::conditional_select(
            &point,
            &CtOption::new($Point::identity(), 1.into()),
            is_identity,
          );

          // Only return the point if it isn't `-identity` nor `-0`
          let positive_is_negative = is_identity | y.map(|y| y.is_zero()).unwrap_or(0.into());
          CtOption::conditional_select(
            &CtOption::new($Point::identity(), 0.into()),
            &point,
            !(sign & positive_is_negative),
          )
        })
      }

      fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        $Point::from_bytes(bytes)
      }

      fn to_bytes(&self) -> Self::Repr {
        // If this the identity, set `z = 0`, causing `x = 0, y = 0`
        let z = self.z.invert().unwrap_or($Field::ZERO);
        let x = self.x * z;
        let y = self.y * z;

        let mut bytes = x.to_repr();
        let mut_ref: &mut [u8] = bytes.as_mut();

        let y_sign = y.is_odd().unwrap_u8();
        mut_ref[31] |= y_sign << 7;
        bytes
      }
    }

    impl PrimeGroup for $Point {}

    impl $Point {
      /// Instantiate a point from its `x, y` coordinates in the affine model.
      ///
      /// Returns `None` if the provided coordinates don't satisfy the curve equation.
      // Unfortunately, there's no API in `group` to model affine coordinates, even though there is
      // a trait to model affine points...
      pub fn from_xy(x: $Field, y: $Field) -> CtOption<Self> {
        CtOption::new(Self { x, y, z: $Field::ONE }, y.square().ct_eq(&curve_equation(x)))
      }
    }

    #[cfg(feature = "alloc")]
    impl ec_divisors::DivisorCurve for $Point {
      type FieldElement = $Field;
      type XyPoint = ec_divisors::Projective<Self>;

      type BorrowedInterpolator = &'static ec_divisors::Interpolator<Self::FieldElement>;
      fn interpolator_for_scalar_mul() -> Self::BorrowedInterpolator {
        static PRECOMPUTE: std_shims::sync::LazyLock<ec_divisors::Interpolator<$Field>> =
          std_shims::sync::LazyLock::new(|| {
            ec_divisors::Interpolator::new(usize::try_from(130).unwrap())
          });
        &*PRECOMPUTE
      }

      fn a() -> Self::FieldElement {
        -$Field::from(3u64)
      }
      fn b() -> Self::FieldElement {
        B
      }

      fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
        let z: Self::FieldElement = Option::from(point.z.invert())?;
        Some((point.x * z, point.y * z))
      }
    }
  };
}

mod helios {
  use crypto_bigint::U256;

  use super::*;
  curve!(
    HelioseleneField,
    Field25519,
    HeliosPoint,
    Field25519::from_u256(&U256::from_be_hex(
      "26bdec0884fe05f20cb42071569fab6432be360d07da8c5b460b82b980fd8c60"
    )),
    Field25519::from_u256(&U256::from_be_hex(
      "611dffc62fe02c759e5ac10f40e009b8e3b147387068aaf810dbdf2d817c67ba"
    )),
  );

  #[test]
  fn test_helios() {
    ff_group_tests::group::test_prime_group_bits::<_, HeliosPoint>(&mut rand_core::OsRng);
  }

  #[test]
  fn generator_helios() {
    use helios::{G_X, G_Y, G};
    assert_eq!(G.x, G_X);
    assert_eq!(G.y, G_Y);
    assert_eq!(recover_y(G.x).unwrap(), G.y);
    assert!(bool::from(!G.y.is_odd()));
  }

  #[test]
  fn zero_x_is_invalid() {
    assert!(Option::<Field25519>::from(recover_y(Field25519::ZERO)).is_none());
  }
}
pub use helios::HeliosPoint;

mod selene {
  use crypto_bigint::U256;

  use super::*;

  curve!(
    Field25519,
    HelioseleneField,
    SelenePoint,
    HelioseleneField(U256::from_be_hex(
      "38c40d10c226ef3bc597c2e1e25bc748e3401c3d031d14ca2265f309ba81efe4"
    )),
    HelioseleneField(U256::from_be_hex(
      "39098c0a54bd9d2781c7d734720d5ca639ee79deeefcd74517fced93ad6635c0"
    )),
  );

  #[test]
  fn test_selene() {
    ff_group_tests::group::test_prime_group_bits::<_, SelenePoint>(&mut rand_core::OsRng);
  }

  #[test]
  fn generator_selene() {
    use selene::{G_X, G_Y, G};
    assert_eq!(G.x, G_X);
    assert_eq!(G.y, G_Y);
    assert_eq!(recover_y(G.x).unwrap(), G.y);
    assert!(bool::from(!G.y.is_odd()));
  }

  #[test]
  fn zero_x_is_invalid() {
    assert!(Option::<HelioseleneField>::from(recover_y(HelioseleneField::ZERO)).is_none());
  }
}
pub use selene::SelenePoint;

// Checks random won't infinitely loop
#[test]
fn random() {
  HeliosPoint::random(&mut rand_core::OsRng);
  SelenePoint::random(&mut rand_core::OsRng);
}
