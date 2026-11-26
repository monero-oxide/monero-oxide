use super::*;

impl<F: Zeroize + PrimeField> Add<Self> for Poly<F> {
  type Output = Self;

  /// This runs in time solely variable to the structure of the polynomials.
  fn add(mut self, mut other: Self) -> Self {
    // Ensure `self` has all of the longest buffers
    if self.y_coefficients.len() < other.y_coefficients.len() {
      core::mem::swap(&mut self.y_coefficients, &mut other.y_coefficients);
    }
    if self.yx_coefficients.len() < other.yx_coefficients.len() {
      core::mem::swap(&mut self.yx_coefficients, &mut other.yx_coefficients);
    }
    for i in 0 .. other.yx_coefficients.len() {
      if self.yx_coefficients[i].len() < other.yx_coefficients[i].len() {
        core::mem::swap(&mut self.yx_coefficients[i], &mut other.yx_coefficients[i]);
      }
    }
    if self.x_coefficients.len() < other.x_coefficients.len() {
      core::mem::swap(&mut self.x_coefficients, &mut other.x_coefficients);
    }

    // Perform the addition
    for (i, coeff) in other.y_coefficients.iter().enumerate() {
      self.y_coefficients[i] += coeff;
    }
    for (i, coeffs) in other.yx_coefficients.iter().enumerate() {
      for (j, coeff) in coeffs.iter().enumerate() {
        self.yx_coefficients[i][j] += coeff;
      }
    }
    for (i, coeff) in other.x_coefficients.iter().enumerate() {
      self.x_coefficients[i] += coeff;
    }
    self.zero_coefficient += other.zero_coefficient;

    self
  }
}

impl<F: Zeroize + PrimeField> Neg for Poly<F> {
  type Output = Self;

  /// This runs in time solely variable to the structure of the polynomial.
  fn neg(mut self) -> Self {
    for coefficient in self.all_coefficients_mut() {
      *coefficient = -*coefficient;
    }
    self
  }
}

impl<F: Zeroize + PrimeField> Sub for Poly<F> {
  type Output = Self;

  /// This runs in time solely  variable to the structure of the polynomials.
  fn sub(self, other: Self) -> Self {
    self + -other
  }
}
