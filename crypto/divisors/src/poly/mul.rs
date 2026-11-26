use super::*;

impl<F: Zeroize + PrimeField> Mul<F> for Poly<F> {
  type Output = Self;

  /// This runs in time solely variable to the structure of the polynomial.
  fn mul(mut self, scalar: F) -> Self {
    for coefficient in self.all_coefficients_mut() {
      *coefficient *= scalar;
    }
    self
  }
}

fn prepend_zeroes<F: Zeroize + PrimeField>(slice: &mut Box<[F]>, zeroes: usize) {
  let mut prepended = Box::new_uninit_slice(zeroes + slice.len());
  {
    let mut prepended = prepended.iter_mut();
    for item in (&mut prepended).take(zeroes) {
      item.write(F::ZERO);
    }
    for (dst, src) in prepended.zip(slice.iter()) {
      dst.write(*src);
    }
  }
  // SAFETY: We iterated over every item and wrote a value to each one
  let mut prepended = unsafe { prepended.assume_init() };
  core::mem::swap(slice, &mut prepended);
  prepended.zeroize();
}

impl<F: Zeroize + PrimeField> Poly<F> {
  /// This runs in time solely variable to the structure of the polynomial and the power of `x`.
  #[must_use]
  fn shift_by_x(mut self, power_of_x: usize) -> Self {
    if power_of_x == 0 {
      return self;
    }

    prepend_zeroes(&mut self.x_coefficients, power_of_x);
    for yx_coefficients in &mut self.yx_coefficients {
      prepend_zeroes(yx_coefficients, power_of_x);
    }
    self.x_coefficients[power_of_x - 1] = self.zero_coefficient;
    self.zero_coefficient = F::ZERO;

    while self.yx_coefficients.len() < self.y_coefficients.len() {
      self.yx_coefficients.push(vec![F::ZERO; power_of_x].into_boxed_slice());
    }
    for (i, y_coeff) in self.y_coefficients.iter().enumerate() {
      self.yx_coefficients[i][power_of_x - 1] = *y_coeff;
    }
    self.y_coefficients.zeroize();
    self.y_coefficients = Box::default();

    self
  }

  /// This runs in time solely variable to the structure of the polynomial and the power of `y`.
  #[must_use]
  fn shift_by_y(mut self, power_of_y: usize) -> Self {
    if power_of_y == 0 {
      return self;
    }

    prepend_zeroes(&mut self.y_coefficients, power_of_y);
    self.yx_coefficients = core::iter::repeat_n(Box::<[F]>::default(), power_of_y - 1)
      .chain(core::iter::once(core::mem::take(&mut self.x_coefficients)))
      .chain(core::mem::take(&mut self.yx_coefficients))
      .collect::<Vec<_>>();

    self.y_coefficients[power_of_y - 1] = self.zero_coefficient;
    self.zero_coefficient = F::ZERO;

    self
  }
}

impl<F: Zeroize + PrimeField> Mul<&Poly<F>> for Poly<F> {
  type Output = Self;

  /// This runs in time solely variable to the structure of the polynomials.
  fn mul(self, other: &Self) -> Self {
    let mut res = self.clone() * other.zero_coefficient;

    for (i, y_coeff) in other.y_coefficients.iter().enumerate() {
      let scaled = self.clone() * *y_coeff;
      res = res + scaled.shift_by_y(i + 1);
    }

    for (y_i, yx_coeffs) in other.yx_coefficients.iter().enumerate() {
      for (x_i, yx_coeff) in yx_coeffs.iter().enumerate() {
        let scaled = self.clone() * *yx_coeff;
        res = res + scaled.shift_by_y(y_i + 1).shift_by_x(x_i + 1);
      }
    }

    for (i, x_coeff) in other.x_coefficients.iter().enumerate() {
      let scaled = self.clone() * *x_coeff;
      res = res + scaled.shift_by_x(i + 1);
    }

    res
  }
}
