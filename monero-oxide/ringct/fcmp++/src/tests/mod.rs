mod sal;

use rand_core::OsRng;

use multiexp::multiexp_vartime;
use dalek_ff_group::{Scalar, EdwardsPoint, Ed25519};
use ciphersuite::{group::Group as _, Ciphersuite};
use helioselene::{Selene, Helios};
use ec_divisors::{DivisorCurve as _, ScalarDecomposition};

use monero_fcmp_plus_plus_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V};

use crate::{
  T, SELENE_FCMP_GENERATORS, HELIOS_FCMP_GENERATORS, SELENE_HASH_INIT, FCMP_PARAMS, Output,
  fcmps::{TreeRoot, Path, Branches, OBlind, IBlind, IBlindBlind, CBlind, OutputBlinds, Fcmp},
  sal::*,
  FcmpPlusPlus,
};

#[test]
fn test() {
  let x = Scalar::random(&mut OsRng);
  let y = Scalar::random(&mut OsRng);

  let O = (EdwardsPoint::generator() * x) + (*T * y);
  let I = EdwardsPoint::random(&mut OsRng);
  let C = EdwardsPoint::random(&mut OsRng);

  let L = I * x;

  let output = Output::new(O, I, C).unwrap();

  let rerandomized_output = RerandomizedOutput::new(&mut OsRng, output);

  let (input, spend_auth_and_linkability) = {
    let input = rerandomized_output.input();
    let opening = OpenedInputTuple::open(&rerandomized_output, &x, &y).unwrap();
    let (L_, spend_auth_and_linkability) =
      SpendAuthAndLinkability::prove(&mut OsRng, [0; 32], &opening);
    assert_eq!(L_, L);
    (input, spend_auth_and_linkability)
  };

  let (tree, fcmp) = {
    let leaves = vec![output];

    let tree = TreeRoot::<Selene, Helios>::C1(
      *SELENE_HASH_INIT +
        multiexp_vartime(
          &([
            <Ed25519 as Ciphersuite>::G::to_xy(output.O()).unwrap().0,
            <Ed25519 as Ciphersuite>::G::to_xy(output.O()).unwrap().1,
            <Ed25519 as Ciphersuite>::G::to_xy(output.I()).unwrap().0,
            <Ed25519 as Ciphersuite>::G::to_xy(output.I()).unwrap().1,
            <Ed25519 as Ciphersuite>::G::to_xy(output.C()).unwrap().0,
            <Ed25519 as Ciphersuite>::G::to_xy(output.C()).unwrap().1,
          ]
          .into_iter()
          .zip(SELENE_FCMP_GENERATORS.generators.g_bold_slice().iter().copied())
          .collect::<Vec<_>>()),
        ),
    );

    let path = Path { output, leaves, curve_2_layers: vec![], curve_1_layers: vec![] };

    let branches = Branches::new(vec![path]).unwrap();

    let output_blinds = OutputBlinds::new(
      OBlind::new(*T, ScalarDecomposition::new(rerandomized_output.o_blind()).unwrap()).unwrap(),
      IBlind::new(
        EdwardsPoint((*FCMP_PLUS_PLUS_U).into()),
        EdwardsPoint((*FCMP_PLUS_PLUS_V).into()),
        ScalarDecomposition::new(rerandomized_output.i_blind()).unwrap(),
      )
      .unwrap(),
      IBlindBlind::new(*T, ScalarDecomposition::new(rerandomized_output.i_blind_blind()).unwrap())
        .unwrap(),
      CBlind::new(
        EdwardsPoint::generator(),
        ScalarDecomposition::new(rerandomized_output.c_blind()).unwrap(),
      )
      .unwrap(),
    );

    let blinded_branches = branches.blind(vec![output_blinds], vec![], vec![]).unwrap();
    (tree, Fcmp::prove(&mut OsRng, &*FCMP_PARAMS, blinded_branches).unwrap())
  };

  let fcmp_plus_plus = FcmpPlusPlus::new(vec![(input, spend_auth_and_linkability)], fcmp);

  let mut ed_verifier = multiexp::BatchVerifier::new(1);
  let mut c1_verifier = generalized_bulletproofs::Generators::batch_verifier();
  let mut c2_verifier = generalized_bulletproofs::Generators::batch_verifier();

  fcmp_plus_plus
    .verify(
      &mut OsRng,
      &mut ed_verifier,
      &mut c1_verifier,
      &mut c2_verifier,
      tree,
      1, // Layers
      [0; 32],
      vec![L],
    )
    .unwrap();

  let mut buf = vec![];
  fcmp_plus_plus.write(&mut buf).unwrap();
  assert_eq!(FcmpPlusPlus::proof_size(1, 1), buf.len());
  let fcmp_plus_plus = FcmpPlusPlus::read(&[input.C_tilde], 1, &mut buf.as_slice()).unwrap();

  fcmp_plus_plus
    .verify(
      &mut OsRng,
      &mut ed_verifier,
      &mut c1_verifier,
      &mut c2_verifier,
      tree,
      1, // Layers
      [0; 32],
      vec![L],
    )
    .unwrap();

  assert!(ed_verifier.verify_vartime());
  assert!(SELENE_FCMP_GENERATORS.generators.verify(c1_verifier));
  assert!(HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier));
}
