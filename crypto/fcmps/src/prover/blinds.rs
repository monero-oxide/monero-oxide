use core::ops::Deref as _;

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::group::ff::PrimeFieldBits;

use ec_divisors::{Poly, DivisorCurve, ScalarDecomposition};

use crate::{Output, Input, FcmpError};

#[derive(Clone, Zeroize)]
pub(crate) struct ScalarMulAndDivisor<G: DivisorCurve> {
  /// The point resulting from this scalar multiplication.
  pub(crate) point: Zeroizing<G>,
  /// The `x` coordinate of the result of this scalar multiplication.
  pub(crate) x: G::FieldElement,
  /// The `y` coordinate of the result of this scalar multiplication.
  pub(crate) y: G::FieldElement,
  /// The divisor interpolating the inverse of this result with instances of `2**i G`, where `G` is
  /// some generator.
  pub(crate) divisor: Poly<G::FieldElement>,
}

impl<G: DivisorCurve> ScalarMulAndDivisor<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  fn new(A: G, scalar: &ScalarDecomposition<G::Scalar>) -> Self {
    let point = Zeroizing::new(A * scalar.scalar());
    let (x, y) = G::to_xy(*point).expect("zero scalar was decomposed");
    let divisor = scalar.scalar_mul_divisor(A).normalize_x_coefficient();
    ScalarMulAndDivisor { point, x, y, divisor }
  }
}

/// A blind, prepared for usage within the circuit.
#[derive(Zeroize)]
pub(crate) struct PreparedBlind<G: DivisorCurve>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  pub(crate) scalar: ScalarDecomposition<G::Scalar>,
  pub(crate) scalar_mul_and_divisor: ScalarMulAndDivisor<G>,
}

impl<G: DivisorCurve> PreparedBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  fn new(A: G, scalar: ScalarDecomposition<G::Scalar>) -> Self {
    let scalar_mul_and_divisor = ScalarMulAndDivisor::new(A, &scalar);
    PreparedBlind { scalar, scalar_mul_and_divisor }
  }
}

/// A blind for `O` (the output's key).
#[derive(Zeroize)]
pub struct OBlind<G: DivisorCurve>(pub(crate) PreparedBlind<G>)
where
  G::Scalar: Zeroize + PrimeFieldBits;
impl<G: DivisorCurve> OBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blind for `O`.
  ///
  /// `scalar` MUST be consumed just once, for a single blind, across any/all contexts.
  ///
  /// This will calculate a divisor and is computationally non-trivial.
  pub fn new(T: G, scalar: ScalarDecomposition<G::Scalar>) -> Self
  where
    G::Scalar: Zeroize + PrimeFieldBits,
  {
    Self(PreparedBlind::new(T, scalar))
  }
}

/// A blind for `I` (the output's key image generator).
#[derive(Zeroize)]
pub struct IBlind<G: DivisorCurve>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  pub(crate) scalar: ScalarDecomposition<G::Scalar>,
  pub(crate) u: ScalarMulAndDivisor<G>,
  pub(crate) v: ScalarMulAndDivisor<G>,
}
impl<G: DivisorCurve> IBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blind for `I`.
  ///
  /// `scalar` MUST be consumed just once, for a single blind, across any/all contexts.
  ///
  /// This will calculate two divisors (distinct from the other blinds which only calculate one
  /// each) and is computationally non-trivial.
  pub fn new(U: G, V: G, scalar: ScalarDecomposition<G::Scalar>) -> Self {
    let u = ScalarMulAndDivisor::new(U, &scalar);
    let v = ScalarMulAndDivisor::new(V, &scalar);
    IBlind { scalar, u, v }
  }
}

/// A blind for `I`'s blind.
#[derive(Zeroize)]
pub struct IBlindBlind<G: DivisorCurve>(pub(crate) PreparedBlind<G>)
where
  G::Scalar: Zeroize + PrimeFieldBits;
impl<G: DivisorCurve> IBlindBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blind for `I`'s blind.
  ///
  /// `scalar` MUST be consumed just once, for a single blind, across any/all contexts.
  ///
  /// This will calculate a divisor and is computationally non-trivial.
  pub fn new(T: G, scalar: ScalarDecomposition<G::Scalar>) -> Self {
    Self(PreparedBlind::new(T, scalar))
  }
}

/// A blind for `C` (the output's commitment).
#[derive(Zeroize)]
pub struct CBlind<G: DivisorCurve>(pub(crate) PreparedBlind<G>)
where
  G::Scalar: Zeroize + PrimeFieldBits;
impl<G: DivisorCurve> CBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blind for `C`.
  ///
  /// `scalar` MUST be consumed just once, for a single blind, across any/all contexts.
  ///
  /// This will calculate a divisor and is computationally non-trivial.
  pub fn new(G: G, scalar: ScalarDecomposition<G::Scalar>) -> Self {
    Self(PreparedBlind::new(G, scalar))
  }
}

/// All of the blinds used for an output, prepared for usage within the circuit.
#[allow(clippy::struct_field_names)]
#[derive(Zeroize)]
pub struct OutputBlinds<G: DivisorCurve>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  pub(crate) o_blind: OBlind<G>,
  pub(crate) i_blind: IBlind<G>,
  pub(crate) i_blind_blind: IBlindBlind<G>,
  pub(crate) c_blind: CBlind<G>,
}

impl<G: DivisorCurve> OutputBlinds<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blinded output.
  ///
  /// These blinds MUST be consumed just once across any/all contexts.
  pub fn new(
    o_blind: OBlind<G>,
    i_blind: IBlind<G>,
    i_blind_blind: IBlindBlind<G>,
    c_blind: CBlind<G>,
  ) -> Self {
    Self { o_blind, i_blind, i_blind_blind, c_blind }
  }

  /// Blind an output.
  pub(crate) fn blind(
    &self,
    output: &Output<G>,
  ) -> Result<Input<<G as DivisorCurve>::FieldElement>, FcmpError> {
    // We add the proven results of the blinds to the input tuple to recalculate the output
    // tuple
    // In order for `input_tuple_value + blind_value = output_tuple_value`,
    // `input_tuple_value = output_tuple_value - blind_value`
    let O_tilde = output.O - self.o_blind.0.scalar_mul_and_divisor.point.deref();
    let I_tilde = output.I - self.i_blind.u.point.deref();
    let C_tilde = output.C - self.c_blind.0.scalar_mul_and_divisor.point.deref();
    // I's blind's blind is not inverted, yet I's blind was prior inverted and remains
    // inverted
    let R = *self.i_blind_blind.0.scalar_mul_and_divisor.point - self.i_blind.v.point.deref();
    Input::new(O_tilde, I_tilde, R, C_tilde)
  }
}

/// A blind for a branch.
#[derive(Zeroize)]
pub struct BranchBlind<G: DivisorCurve>(pub(crate) PreparedBlind<G>)
where
  G::Scalar: Zeroize + PrimeFieldBits;
impl<G: DivisorCurve> BranchBlind<G>
where
  G::Scalar: Zeroize + PrimeFieldBits,
{
  /// Construct a new blind for a branch.
  ///
  /// `scalar` MUST be consumed just once, for a single blind, across any/all contexts.
  ///
  /// This will calculate a divisor and is computationally non-trivial.
  pub fn new(H: G, scalar: ScalarDecomposition<G::Scalar>) -> Self {
    Self(PreparedBlind::new(H, scalar))
  }
}
