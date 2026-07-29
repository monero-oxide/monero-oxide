use std_shims::{vec, vec::Vec};

use ciphersuite::Ciphersuite;

use ec_divisors::DivisorCurve;

use crate::*;

mod blinds;
pub use blinds::*;

/// The path information for a specific leaf in the tree.
///
/// The caller MUST pad the non-leaf branches to the expected layer lengths.
#[derive(Clone)]
pub struct Path<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  /// The output being proven for.
  pub output: Output<<C::OC as Ciphersuite>::G>,
  /// The leaves along this path.
  pub leaves: Vec<Output<<C::OC as Ciphersuite>::G>>,
  /// The branches on this path proven for with the second curve.
  pub curve_2_layers: Vec<Vec<<C::C2 as Ciphersuite>::F>>,
  /// The branches on this path proven for with the first curve.
  pub curve_1_layers: Vec<Vec<<C::C1 as Ciphersuite>::F>>,
}

/// The branches, except for the root branch.
///
/// We do a multi-input proof where all inputs share a root. Accordingly, we don't need to
/// represent the root for each input. We just need to represent the root for all inputs.
#[derive(Clone)]
pub(crate) struct BranchesWithoutRootBranch<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  // This is None if the leaves directly feed into the root
  pub(crate) leaves: Option<Vec<Output<<C::OC as Ciphersuite>::G>>>,
  pub(crate) curve_2_layers: Vec<Vec<<C::C2 as Ciphersuite>::F>>,
  pub(crate) curve_1_layers: Vec<Vec<<C::C1 as Ciphersuite>::F>>,
}

/// The root branch.
#[derive(Clone)]
pub(crate) enum RootBranch<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  Leaves(Vec<Output<<C::OC as Ciphersuite>::G>>),
  C1(Vec<<C::C1 as Ciphersuite>::F>),
  C2(Vec<<C::C2 as Ciphersuite>::F>),
}

/// The branches for a multi-input FCMP proof.
#[derive(Clone)]
pub struct Branches<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  #[allow(clippy::type_complexity)]
  per_input: Vec<(Output<<C::OC as Ciphersuite>::G>, BranchesWithoutRootBranch<C>)>,
  root: RootBranch<C>,
}

/// The proof data for a specific input.
#[derive(Clone)]
pub(crate) struct InputProofData<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  /// The output.
  output: Output<<C::OC as Ciphersuite>::G>,
  /// The output blinds.
  output_blinds: OutputBlinds<<C::OC as Ciphersuite>::G>,
  /// The input.
  pub(crate) input: Input<<<C::OC as Ciphersuite>::G as DivisorCurve>::FieldElement>,
  /// The non-root branches for this output in the tree.
  pub(crate) branches: BranchesWithoutRootBranch<C>,
}

/// The blinded branches for a multi-input FCMP proof.
pub struct BranchesWithBlinds<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  pub(crate) per_input: Vec<InputProofData<C>>,
  pub(crate) root: RootBranch<C>,
  pub(crate) branches_1_blinds: Vec<BranchBlind<<C::C1 as Ciphersuite>::G>>,
  pub(crate) branches_2_blinds: Vec<BranchBlind<<C::C2 as Ciphersuite>::G>>,
}

impl<C: FcmpCurves> Branches<C>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  /// Create a new set of Branches from a set of paths.
  ///
  /// Returns None if the paths don't belong to the same tree.
  pub fn new(paths: Vec<Path<C>>) -> Option<Self> {
    let mut paths = paths.into_iter();

    let mut first = paths.next()?;
    let expected_1_layers = first.curve_1_layers.len();
    let expected_2_layers = first.curve_2_layers.len();
    // The leaves produce a branch which is a point on C1
    // Those produce a branch which is a point on C2
    // Those produce a branch which is a point on C1
    // ..
    // Accordingly, after the leaves, we have a branch proved for over C2, meaning the amount of C1
    // branches should always be equal to or one less than the amount of C2 branches
    if expected_2_layers.checked_sub(expected_1_layers)?.saturating_sub(1) != 0 {
      None?;
    }
    // The root is a point on the curve most recently proved with
    // If we only have leaves (so these are empty), C1
    // Else, since curve_2_layers is populated before curve_1_layers, curve_1_layers was last
    let root_is_leaves = first.curve_1_layers.is_empty() && first.curve_2_layers.is_empty();
    let root_is_c1 = expected_2_layers == expected_1_layers;
    let root = if root_is_leaves {
      let mut leaves = vec![];
      core::mem::swap(&mut leaves, &mut first.leaves);
      RootBranch::Leaves(leaves)
    } else if root_is_c1 {
      RootBranch::C1(first.curve_1_layers.pop().unwrap())
    } else {
      RootBranch::C2(first.curve_2_layers.pop().unwrap())
    };

    let mut per_input = vec![(
      first.output,
      BranchesWithoutRootBranch {
        leaves: (!root_is_leaves).then_some(first.leaves),
        curve_1_layers: first.curve_1_layers,
        curve_2_layers: first.curve_2_layers,
      },
    )];

    for mut path in paths {
      // Check the path length is consistent
      if (path.curve_1_layers.len() != expected_1_layers) ||
        (path.curve_2_layers.len() != expected_2_layers)
      {
        None?;
      }

      // Check the root is consistent
      match &root {
        RootBranch::Leaves(leaves) => {
          if leaves != &path.leaves {
            None?;
          }
        }
        RootBranch::C1(branch) => {
          if branch != &path.curve_1_layers.pop().unwrap() {
            None?;
          }
        }
        RootBranch::C2(branch) => {
          if branch != &path.curve_2_layers.pop().unwrap() {
            None?;
          }
        }
      }

      per_input.push((
        path.output,
        BranchesWithoutRootBranch {
          leaves: (!root_is_leaves).then_some(path.leaves),
          curve_1_layers: path.curve_1_layers,
          curve_2_layers: path.curve_2_layers,
        },
      ));
    }

    Some(Branches { per_input, root })
  }

  /// The amount of branch blinds needed on the first curve.
  pub fn necessary_c1_blinds(&self) -> usize {
    self.per_input.len() *
      (usize::from(u8::from(self.per_input[0].1.leaves.is_some())) +
        self.per_input[0].1.curve_1_layers.len())
  }

  /// The amount of branch blinds needed on the second curve.
  pub fn necessary_c2_blinds(&self) -> usize {
    self.per_input.len() * self.per_input[0].1.curve_2_layers.len()
  }

  /// Blind these branches with the specified blinds.
  pub fn blind(
    self,
    output_blinds: Vec<OutputBlinds<<C::OC as Ciphersuite>::G>>,
    branches_1_blinds: Vec<BranchBlind<<C::C1 as Ciphersuite>::G>>,
    branches_2_blinds: Vec<BranchBlind<<C::C2 as Ciphersuite>::G>>,
  ) -> Result<BranchesWithBlinds<C>, FcmpError> {
    if (output_blinds.len() != self.per_input.len()) ||
      (branches_1_blinds.len() != self.necessary_c1_blinds()) ||
      (branches_2_blinds.len() != self.necessary_c2_blinds())
    {
      Err(FcmpError::IncorrectBlindQuantity)?;
    }

    Ok(BranchesWithBlinds {
      per_input: self
        .per_input
        .into_iter()
        .zip(output_blinds)
        .map(|((output, branches), output_blinds)| {
          let input = output_blinds.blind(&output)?;
          Ok(InputProofData { output, output_blinds, input, branches })
        })
        .collect::<Result<_, FcmpError>>()?,
      root: self.root,
      branches_1_blinds,
      branches_2_blinds,
    })
  }
}

pub(crate) struct TranscriptedBranchesPerInput {
  pub(crate) c1: Vec<Vec<Variable>>,
  pub(crate) c2: Vec<Vec<Variable>>,
}

pub(crate) struct TranscriptedBranches {
  pub(crate) per_input: Vec<TranscriptedBranchesPerInput>,
  pub(crate) root: Vec<Variable>,
}

pub(crate) struct TranscriptedBlinds<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  pub(crate) c1: Vec<PointWithDlog<C::C2Parameters>>,
  pub(crate) c2: Vec<PointWithDlog<C::C1Parameters>>,
}

impl<C: FcmpCurves> BranchesWithBlinds<C>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  // This function executes in variable-time as it pads the path. Paths which aren't full (paths
  // along the latest edge of the tree) will need padding and have that difference in performance.
  pub(crate) fn transcript_branches(
    &self,
    c1_tape: &mut VectorCommitmentTape<<C::C1 as Ciphersuite>::F>,
    c2_tape: &mut VectorCommitmentTape<<C::C2 as Ciphersuite>::F>,
  ) -> TranscriptedBranches {
    let flatten_leaves = |leaves: &[Output<<C::OC as Ciphersuite>::G>]| {
      // Flatten the leaves for the branch
      let mut flattened_leaves = vec![];
      for leaf in leaves {
        // leaf is of type Output which checks its members to not be the identity
        let O = <C::OC as Ciphersuite>::G::to_xy(leaf.O).unwrap();
        let I = <C::OC as Ciphersuite>::G::to_xy(leaf.I).unwrap();
        let C = <C::OC as Ciphersuite>::G::to_xy(leaf.C).unwrap();
        flattened_leaves.extend(&[O.0, O.1, I.0, I.1, C.0, C.1]);
      }
      while flattened_leaves.len() < (6 * LAYER_ONE_LEN) {
        flattened_leaves.push(<C::C1 as Ciphersuite>::F::ZERO);
      }
      flattened_leaves
    };

    let mut per_input = vec![];
    for input in &self.per_input {
      let mut c1 = vec![];
      let mut c2 = vec![];
      if let Some(leaves) = &input.branches.leaves {
        let flattened_leaves = flatten_leaves(leaves);
        c1.push(c1_tape.append_branch(6 * LAYER_ONE_LEN, Some(flattened_leaves)));
      }
      for branch in &input.branches.curve_1_layers {
        let mut branch = branch.clone();
        while branch.len() < LAYER_ONE_LEN {
          branch.push(<C::C1 as Ciphersuite>::F::ZERO);
        }
        c1.push(c1_tape.append_branch(LAYER_ONE_LEN, Some(branch.clone())));
      }
      for branch in &input.branches.curve_2_layers {
        let mut branch = branch.clone();
        while branch.len() < LAYER_TWO_LEN {
          branch.push(<C::C2 as Ciphersuite>::F::ZERO);
        }
        c2.push(c2_tape.append_branch(LAYER_TWO_LEN, Some(branch.clone())));
      }
      per_input.push(TranscriptedBranchesPerInput { c1, c2 });
    }

    let root = match &self.root {
      RootBranch::Leaves(leaves) => {
        let flattened_leaves = flatten_leaves(leaves);
        c1_tape.append_branch(flattened_leaves.len(), Some(flattened_leaves))
      }
      RootBranch::C1(branch) => c1_tape.append_branch(branch.len(), Some(branch.clone())),
      RootBranch::C2(branch) => c2_tape.append_branch(branch.len(), Some(branch.clone())),
    };

    TranscriptedBranches { per_input, root }
  }

  pub(crate) fn transcript_inputs(
    &self,
    c1_tape: &mut VectorCommitmentTape<<C::C1 as Ciphersuite>::F>,
  ) -> Vec<TranscriptedInput<C>> {
    let mut res = vec![];
    for input in &self.per_input {
      // Accumulate the opening for the leaves
      let append_claimed_point =
        |c1_tape: &mut VectorCommitmentTape<<C::C1 as Ciphersuite>::F>,
         dlog: &[u64],
         scalar_mul_and_divisor: ScalarMulAndDivisor<<C::OC as Ciphersuite>::G>,
         padding| {
          c1_tape.append_claimed_point::<C::OcParameters>(
            Some(dlog),
            Some(scalar_mul_and_divisor.divisor.clone()),
            Some((scalar_mul_and_divisor.x, scalar_mul_and_divisor.y)),
            Some(padding),
          )
        };

      // Since this is presumed over Ed25519, which has a 253-bit discrete logarithm, we have two
      // items avilable in padding. We use this padding for all the other points we must commit to
      // For o_blind, we use the padding for O
      let (o_blind_claim, O) = {
        let (x, y) = <C::OC as Ciphersuite>::G::to_xy(input.output.O).unwrap();

        append_claimed_point(
          c1_tape,
          input.output_blinds.o_blind.0.scalar.decomposition(),
          input.output_blinds.o_blind.0.scalar_mul_and_divisor.clone(),
          vec![x, y],
        )
      };
      let O = (O[0], O[1]);

      // For i_blind_u, we use the padding for I
      let (i_blind_u_claim, I) = {
        let (x, y) = <C::OC as Ciphersuite>::G::to_xy(input.output.I).unwrap();
        append_claimed_point(
          c1_tape,
          input.output_blinds.i_blind.scalar.decomposition(),
          input.output_blinds.i_blind.u.clone(),
          vec![x, y],
        )
      };
      let I = (I[0], I[1]);

      // Commit to the divisor for `i_blind V`, which doesn't commit to the point `i_blind V`
      // (and that still has to be done)
      let (i_blind_v_divisor, _extra) = c1_tape.append_divisor(
        Some(input.output_blinds.i_blind.v.divisor.clone()),
        // Since we're the prover, we need to use this slot, yet we don't actually put anything here
        Some(<C::C1 as Ciphersuite>::F::ZERO),
      );

      // For i_blind_blind, we use the padding for (i_blind V)
      let (i_blind_blind_claim, i_blind_V) = {
        let (x, y) = (input.output_blinds.i_blind.v.x, input.output_blinds.i_blind.v.y);
        append_claimed_point(
          c1_tape,
          input.output_blinds.i_blind_blind.0.scalar.decomposition(),
          input.output_blinds.i_blind_blind.0.scalar_mul_and_divisor.clone(),
          vec![x, y],
        )
      };

      let i_blind_v_claim = PointWithDlog {
        // This has the same discrete log, i_blind, as i_blind_u
        dlog: i_blind_u_claim.dlog.clone(),
        divisor: i_blind_v_divisor,
        point: (i_blind_V[0], i_blind_V[1]),
      };

      // For c_blind, we use the padding for C
      let (c_blind_claim, C) = {
        let (x, y) = <C::OC as Ciphersuite>::G::to_xy(input.output.C).unwrap();
        append_claimed_point(
          c1_tape,
          input.output_blinds.c_blind.0.scalar.decomposition(),
          input.output_blinds.c_blind.0.scalar_mul_and_divisor.clone(),
          vec![x, y],
        )
      };
      let C = (C[0], C[1]);

      // We now have committed to O, I, C, and all interpolated points

      res.push(TranscriptedInput {
        O,
        I,
        C,
        o_blind_claim,
        i_blind_u_claim,
        i_blind_v_claim,
        i_blind_blind_claim,
        c_blind_claim,
      });
    }
    res
  }

  pub(crate) fn transcript_blinds(
    &self,
    c1_tape: &mut VectorCommitmentTape<<C::C1 as Ciphersuite>::F>,
    c2_tape: &mut VectorCommitmentTape<<C::C2 as Ciphersuite>::F>,
  ) -> TranscriptedBlinds<C> {
    // The first circuit's tape opens the blinds from the second curve
    let mut c1 = vec![];
    for blind in &self.branches_2_blinds {
      c1.push(
        c1_tape
          .append_claimed_point::<C::C2Parameters>(
            Some(blind.0.scalar.decomposition()),
            Some(blind.0.scalar_mul_and_divisor.divisor.clone()),
            Some((blind.0.scalar_mul_and_divisor.x, blind.0.scalar_mul_and_divisor.y)),
            Some(vec![]),
          )
          .0,
      );
    }

    // The second circuit's tape opens the blinds from the first curve
    let mut c2 = vec![];
    for blind in &self.branches_1_blinds {
      c2.push(
        c2_tape
          .append_claimed_point::<C::C1Parameters>(
            Some(blind.0.scalar.decomposition()),
            Some(blind.0.scalar_mul_and_divisor.divisor.clone()),
            Some((blind.0.scalar_mul_and_divisor.x, blind.0.scalar_mul_and_divisor.y)),
            Some(vec![]),
          )
          .0,
      );
    }

    TranscriptedBlinds { c1, c2 }
  }
}
