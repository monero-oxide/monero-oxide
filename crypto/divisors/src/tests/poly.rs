use zeroize::Zeroize;
use rand_core::OsRng;

use group::ff::PrimeField;

use crate::Poly;

impl<F: From<u64> + Zeroize + PrimeField> PartialEq for Poly<F> {
  /// Equality of the polynomials' _values_, not their structure.
  ///
  /// This function does not execute in constant time.
  fn eq(&self, b: &Poly<F>) -> bool {
    {
      let mutual_y_coefficients = self.y_coefficients.len().min(b.y_coefficients.len());
      if self.y_coefficients[.. mutual_y_coefficients] != b.y_coefficients[.. mutual_y_coefficients]
      {
        return false;
      }
      for coeff in self.y_coefficients.iter().skip(mutual_y_coefficients) {
        if *coeff != F::ZERO {
          return false;
        }
      }
      for coeff in b.y_coefficients.iter().skip(mutual_y_coefficients) {
        if *coeff != F::ZERO {
          return false;
        }
      }
    }

    {
      for (i, yx_coeffs) in self.yx_coefficients.iter().enumerate() {
        for (j, coeff) in yx_coeffs.iter().enumerate() {
          if coeff != b.yx_coefficients.get(i).and_then(|coeffs| coeffs.get(j)).unwrap_or(&F::ZERO)
          {
            return false;
          }
        }
      }
      // Run from the other perspective in case other is longer than self
      for (i, yx_coeffs) in b.yx_coefficients.iter().enumerate() {
        for (j, coeff) in yx_coeffs.iter().enumerate() {
          if coeff !=
            self.yx_coefficients.get(i).and_then(|coeffs| coeffs.get(j)).unwrap_or(&F::ZERO)
          {
            return false;
          }
        }
      }
    }

    {
      let mutual_x_coefficients = self.x_coefficients.len().min(b.x_coefficients.len());
      if self.x_coefficients[.. mutual_x_coefficients] != b.x_coefficients[.. mutual_x_coefficients]
      {
        return false;
      }
      for coeff in self.x_coefficients.iter().skip(mutual_x_coefficients) {
        if *coeff != F::ZERO {
          return false;
        }
      }
      for coeff in b.x_coefficients.iter().skip(mutual_x_coefficients) {
        if *coeff != F::ZERO {
          return false;
        }
      }
    }

    self.zero_coefficient == b.zero_coefficient
  }
}

type F = dalek_ff_group::Scalar;

#[test]
fn test_poly() {
  let zero = F::ZERO;
  let one = F::ONE;

  {
    let mut poly = Poly::zero();
    poly.y_coefficients = vec![zero, one].into_boxed_slice();

    let mut modulus = Poly::zero();
    modulus.y_coefficients = vec![one].into_boxed_slice();
    assert_eq!(
      poly.clone().div_rem(&mut modulus).0,
      Poly {
        y_coefficients: vec![one].into_boxed_slice(),
        yx_coefficients: vec![],
        x_coefficients: Box::default(),
        zero_coefficient: zero
      }
    );
    assert_eq!(
      poly % &mut modulus,
      Poly {
        y_coefficients: Box::default(),
        yx_coefficients: vec![],
        x_coefficients: Box::default(),
        zero_coefficient: zero
      }
    );
  }

  {
    let mut poly = Poly::zero();
    poly.y_coefficients = vec![zero, one].into_boxed_slice();

    let mut squared = Poly::zero();
    squared.y_coefficients = vec![zero, zero, zero, one].into_boxed_slice();
    assert_eq!(poly.clone() * &poly, squared);
  }

  {
    let mut a = Poly::zero();
    a.zero_coefficient = F::from(2u64);

    let mut b = Poly::zero();
    b.zero_coefficient = F::from(3u64);

    let mut res = Poly::zero();
    res.zero_coefficient = F::from(6u64);
    assert_eq!(a.clone() * &b, res);

    b.y_coefficients = vec![F::from(4u64)].into_boxed_slice();
    res.y_coefficients = vec![F::from(8u64)].into_boxed_slice();
    assert_eq!(a.clone() * &b, res);
    assert_eq!(b.clone() * &a, res);

    a.x_coefficients = vec![F::from(5u64)].into_boxed_slice();
    res.x_coefficients = vec![F::from(15u64)].into_boxed_slice();
    res.yx_coefficients = vec![vec![F::from(20u64)].into_boxed_slice()];
    assert_eq!(a.clone() * &b, res);
    assert_eq!(b * &a, res);

    // res is now 20xy + 8*y + 15*x + 6
    // res ** 2 =
    //   400*x^2*y^2 + 320*x*y^2 + 64*y^2 + 600*x^2*y + 480*x*y + 96*y + 225*x^2 + 180*x + 36

    let mut squared = Poly::zero();
    squared.y_coefficients = vec![F::from(96u64), F::from(64u64)].into_boxed_slice();
    squared.yx_coefficients = vec![
      vec![F::from(480u64), F::from(600u64)].into_boxed_slice(),
      vec![F::from(320u64), F::from(400u64)].into_boxed_slice(),
    ];
    squared.x_coefficients = vec![F::from(180u64), F::from(225u64)].into_boxed_slice();
    squared.zero_coefficient = F::from(36u64);
    assert_eq!(res.clone() * &res, squared);

    let (res_by_div, zero) = squared.div_rem(&mut res);
    assert_eq!(res_by_div, res);
    assert!(bool::from(zero.is_zero()));
  }
}

#[test]
fn test_differentation() {
  let random = || F::random(&mut OsRng);

  let input = Poly {
    y_coefficients: vec![random()].into_boxed_slice(),
    yx_coefficients: vec![vec![random()].into_boxed_slice()],
    x_coefficients: vec![random(), random(), random()].into_boxed_slice(),
    zero_coefficient: random(),
  };
  let (diff_x, diff_y) = input.differentiate();
  assert_eq!(
    diff_x,
    Poly {
      y_coefficients: vec![input.yx_coefficients[0][0]].into_boxed_slice(),
      yx_coefficients: vec![],
      x_coefficients: vec![
        F::from(2u64) * input.x_coefficients[1],
        F::from(3u64) * input.x_coefficients[2]
      ]
      .into_boxed_slice(),
      zero_coefficient: input.x_coefficients[0],
    }
  );
  assert_eq!(
    diff_y,
    Poly {
      y_coefficients: Box::default(),
      yx_coefficients: vec![],
      x_coefficients: vec![input.yx_coefficients[0][0]].into_boxed_slice(),
      zero_coefficient: input.y_coefficients[0],
    }
  );

  let input = Poly {
    y_coefficients: vec![random()].into_boxed_slice(),
    yx_coefficients: vec![vec![random(), random()].into_boxed_slice()],
    x_coefficients: vec![random(), random(), random(), random()].into_boxed_slice(),
    zero_coefficient: random(),
  };
  let (diff_x, diff_y) = input.differentiate();
  assert_eq!(
    diff_x,
    Poly {
      y_coefficients: vec![input.yx_coefficients[0][0]].into_boxed_slice(),
      yx_coefficients: vec![vec![F::from(2u64) * input.yx_coefficients[0][1]].into_boxed_slice()],
      x_coefficients: vec![
        F::from(2u64) * input.x_coefficients[1],
        F::from(3u64) * input.x_coefficients[2],
        F::from(4u64) * input.x_coefficients[3],
      ]
      .into_boxed_slice(),
      zero_coefficient: input.x_coefficients[0],
    }
  );
  assert_eq!(
    diff_y,
    Poly {
      y_coefficients: Box::default(),
      yx_coefficients: vec![],
      x_coefficients: vec![input.yx_coefficients[0][0], input.yx_coefficients[0][1]]
        .into_boxed_slice(),
      zero_coefficient: input.y_coefficients[0],
    }
  );
}
