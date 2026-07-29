use rand_core::OsRng;

use generic_array::typenum::U;

use multiexp::multiexp_vartime;
use ciphersuite::Ciphersuite;
use dalek_ff_group::Ed25519;
use helioselene::{Selene, Helios};
use ec_divisors::ScalarDecomposition;

use crate::{*, tree::hash_grow};

struct Ed25519Params;
impl DiscreteLogParameter for Ed25519Params {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Ed25519 as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

struct SeleneParams;
impl DiscreteLogParameter for SeleneParams {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Selene as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

struct HeliosParams;
impl DiscreteLogParameter for HeliosParams {
  #[allow(clippy::as_conversions)]
  type ScalarBits = U<{ <<Helios as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

#[derive(Clone)]
struct MoneroCurves;
impl FcmpCurves for MoneroCurves {
  type OC = Ed25519;
  type OcParameters = Ed25519Params;
  type C1 = Selene;
  type C1Parameters = SeleneParams;
  type C2 = Helios;
  type C2Parameters = HeliosParams;
}

#[allow(clippy::type_complexity)]
fn random_params(
  input_limit: usize,
) -> (
  <Ed25519 as Ciphersuite>::G,
  <Ed25519 as Ciphersuite>::G,
  <Ed25519 as Ciphersuite>::G,
  <Ed25519 as Ciphersuite>::G,
  FcmpParams<MoneroCurves>,
) {
  let G = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  let T = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  let U = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  let V = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);

  let params = FcmpParams::<MoneroCurves>::new(
    generalized_bulletproofs::tests::insecure_test_generators::<_, Selene>(
      &mut OsRng,
      2 * (input_limit * 256),
    )
    .unwrap(),
    generalized_bulletproofs::tests::insecure_test_generators::<_, Helios>(
      &mut OsRng,
      2 * (input_limit * 128),
    )
    .unwrap(),
    // Hash init generators
    <Selene as Ciphersuite>::G::random(&mut OsRng),
    <Helios as Ciphersuite>::G::random(&mut OsRng),
    // G, T, U, V
    G,
    T,
    U,
    V,
  );

  (G, T, U, V, params)
}

fn random_output() -> Output<<Ed25519 as Ciphersuite>::G> {
  let O = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  let I = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  let C = <Ed25519 as Ciphersuite>::G::random(&mut OsRng);
  Output::new(O, I, C).unwrap()
}

fn random_path(
  params: &FcmpParams<MoneroCurves>,
  layers: usize,
) -> (Path<MoneroCurves>, TreeRoot<Selene, Helios>) {
  assert!(layers >= 1);

  let mut leaves = vec![];
  while leaves.len() < LAYER_ONE_LEN {
    leaves.push(random_output());
  }

  let output =
    leaves[usize::try_from(OsRng.next_u64() % u64::try_from(leaves.len()).unwrap()).unwrap()];

  let mut selene_hash = Some({
    let mut multiexp = vec![];
    for (scalar, point) in leaves
      .iter()
      .flat_map(|output| {
        let O = <Ed25519 as Ciphersuite>::G::to_xy(output.O).unwrap();
        let I = <Ed25519 as Ciphersuite>::G::to_xy(output.I).unwrap();
        let C = <Ed25519 as Ciphersuite>::G::to_xy(output.C).unwrap();
        [O.0, O.1, I.0, I.1, C.0, C.1]
      })
      .zip(params.curve_1_generators.g_bold_slice())
    {
      multiexp.push((scalar, *point));
    }
    params.curve_1_hash_init + multiexp_vartime(&multiexp)
  });
  let mut helios_hash = None;

  let mut curve_2_layers = vec![];
  let mut curve_1_layers = vec![];
  loop {
    if layers == 1 {
      break;
    }

    let mut curve_2_layer = vec![];
    while curve_2_layer.len() < LAYER_TWO_LEN {
      curve_2_layer.push(<Selene as Ciphersuite>::G::random(&mut OsRng));
    }
    let layer_len = curve_2_layer.len();
    curve_2_layer[usize::try_from(OsRng.next_u64()).unwrap() % layer_len] =
      selene_hash.take().unwrap();
    let curve_2_layer = curve_2_layer
      .into_iter()
      .map(|point| <Selene as Ciphersuite>::G::to_xy(point).unwrap().0)
      .collect::<Vec<_>>();

    helios_hash = Some({
      let mut multiexp = vec![];
      for (scalar, point) in curve_2_layer.iter().zip(params.curve_2_generators.g_bold_slice()) {
        multiexp.push((*scalar, *point));
      }
      params.curve_2_hash_init + multiexp_vartime(&multiexp)
    });

    curve_2_layers.push(curve_2_layer);

    if (1 + curve_1_layers.len() + curve_2_layers.len()) == layers {
      break;
    }

    let mut curve_1_layer = vec![];
    while curve_1_layer.len() < LAYER_ONE_LEN {
      curve_1_layer.push(<Helios as Ciphersuite>::G::random(&mut OsRng));
    }
    let layer_len = curve_1_layer.len();
    curve_1_layer[usize::try_from(OsRng.next_u64()).unwrap() % layer_len] =
      helios_hash.take().unwrap();
    let curve_1_layer = curve_1_layer
      .into_iter()
      .map(|point| <Helios as Ciphersuite>::G::to_xy(point).unwrap().0)
      .collect::<Vec<_>>();

    selene_hash = Some({
      let mut multiexp = vec![];
      for (scalar, point) in curve_1_layer.iter().zip(params.curve_1_generators.g_bold_slice()) {
        multiexp.push((*scalar, *point));
      }
      params.curve_1_hash_init + multiexp_vartime(&multiexp)
    });

    curve_1_layers.push(curve_1_layer);

    if (1 + curve_1_layers.len() + curve_2_layers.len()) == layers {
      break;
    }
  }

  let root = if let Some(selene_hash) = selene_hash {
    TreeRoot::<Selene, Helios>::C1(selene_hash)
  } else {
    TreeRoot::<Selene, Helios>::C2(helios_hash.unwrap())
  };

  (Path { output, leaves, curve_2_layers, curve_1_layers }, root)
}

fn random_paths(
  params: &FcmpParams<MoneroCurves>,
  layers: usize,
  paths: usize,
) -> (Vec<Path<MoneroCurves>>, TreeRoot<Selene, Helios>) {
  assert!(paths >= 1);
  assert!(paths <= LAYER_ONE_LEN.min(LAYER_TWO_LEN));

  let mut res = vec![];
  for _ in 0 .. paths {
    let (path, _root) = random_path(params, layers);
    res.push(path);
  }

  // Pop each path's top layer
  // Then push a new top layer which is unified for all paths
  // 1st layer has a C1 root (so the top layer is the leaves)
  // 2nd layer has a C2 root (so the top layer is C1)
  // 3rd layer has a C1 root (so the top layer is C2)
  let root = if layers == 1 {
    let mut outputs = vec![];
    for path in &res {
      outputs.push(path.output);
    }
    while outputs.len() < LAYER_ONE_LEN {
      outputs.push(random_output());
    }
    let mut shuffled_outputs = vec![];
    while !outputs.is_empty() {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(outputs.len()).unwrap()).unwrap();
      shuffled_outputs.push(outputs.swap_remove(i));
    }

    for path in &mut res {
      path.leaves = shuffled_outputs.clone();
    }

    let mut new_leaves_layer = vec![];
    for output in shuffled_outputs {
      let O = <Ed25519 as Ciphersuite>::G::to_xy(output.O).unwrap();
      let I = <Ed25519 as Ciphersuite>::G::to_xy(output.I).unwrap();
      let C = <Ed25519 as Ciphersuite>::G::to_xy(output.C).unwrap();
      new_leaves_layer.extend(&[O.0, O.1, I.0, I.1, C.0, C.1]);
    }

    TreeRoot::C1(
      hash_grow(
        &params.curve_1_generators,
        params.curve_1_hash_init,
        0,
        <Selene as Ciphersuite>::F::ZERO,
        &new_leaves_layer,
      )
      .unwrap(),
    )
  } else if (layers % 2) == 0 {
    let mut branch = vec![];
    for path in &res {
      branch.push(
        <Selene as Ciphersuite>::G::to_xy(if let Some(branch) = path.curve_1_layers.last() {
          hash_grow(
            &params.curve_1_generators,
            params.curve_1_hash_init,
            0,
            <Selene as Ciphersuite>::F::ZERO,
            branch,
          )
          .unwrap()
        } else {
          let mut leaves_layer = vec![];
          for output in &path.leaves {
            let O = <Ed25519 as Ciphersuite>::G::to_xy(output.O).unwrap();
            let I = <Ed25519 as Ciphersuite>::G::to_xy(output.I).unwrap();
            let C = <Ed25519 as Ciphersuite>::G::to_xy(output.C).unwrap();
            leaves_layer.extend(&[O.0, O.1, I.0, I.1, C.0, C.1]);
          }

          hash_grow(
            &params.curve_1_generators,
            params.curve_1_hash_init,
            0,
            <Selene as Ciphersuite>::F::ZERO,
            &leaves_layer,
          )
          .unwrap()
        })
        .unwrap()
        .0,
      );
    }
    while branch.len() < LAYER_TWO_LEN {
      branch.push(<Helios as Ciphersuite>::F::random(&mut OsRng));
    }
    let mut shuffled_branch = vec![];
    while !branch.is_empty() {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(branch.len()).unwrap()).unwrap();
      shuffled_branch.push(branch.swap_remove(i));
    }

    for path in &mut res {
      *path.curve_2_layers.last_mut().unwrap() = shuffled_branch.clone();
    }

    TreeRoot::C2(
      hash_grow(
        &params.curve_2_generators,
        params.curve_2_hash_init,
        0,
        <Helios as Ciphersuite>::F::ZERO,
        &shuffled_branch,
      )
      .unwrap(),
    )
  } else {
    let mut branch = vec![];
    for path in &res {
      branch.push(
        <Helios as Ciphersuite>::G::to_xy({
          let branch = path.curve_2_layers.last().unwrap();
          hash_grow(
            &params.curve_2_generators,
            params.curve_2_hash_init,
            0,
            <Helios as Ciphersuite>::F::ZERO,
            branch,
          )
          .unwrap()
        })
        .unwrap()
        .0,
      );
    }
    while branch.len() < LAYER_ONE_LEN {
      branch.push(<Selene as Ciphersuite>::F::random(&mut OsRng));
    }
    let mut shuffled_branch = vec![];
    while !branch.is_empty() {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(branch.len()).unwrap()).unwrap();
      shuffled_branch.push(branch.swap_remove(i));
    }

    for path in &mut res {
      *path.curve_1_layers.last_mut().unwrap() = shuffled_branch.clone();
    }

    TreeRoot::C1(
      hash_grow(
        &params.curve_1_generators,
        params.curve_1_hash_init,
        0,
        <Selene as Ciphersuite>::F::ZERO,
        &shuffled_branch,
      )
      .unwrap(),
    )
  };

  // Verify each of these paths are valid
  for path in &res {
    assert!(path.leaves.iter().any(|output| output == &path.output));

    let mut leaves_layer = vec![];
    for output in &path.leaves {
      let O = <Ed25519 as Ciphersuite>::G::to_xy(output.O).unwrap();
      let I = <Ed25519 as Ciphersuite>::G::to_xy(output.I).unwrap();
      let C = <Ed25519 as Ciphersuite>::G::to_xy(output.C).unwrap();
      leaves_layer.extend(&[O.0, O.1, I.0, I.1, C.0, C.1]);
    }

    let mut c1_hash = Some(
      <Selene as Ciphersuite>::G::to_xy(
        hash_grow(
          &params.curve_1_generators,
          params.curve_1_hash_init,
          0,
          <Selene as Ciphersuite>::F::ZERO,
          &leaves_layer,
        )
        .unwrap(),
      )
      .unwrap()
      .0,
    );
    let mut c2_hash = None;

    let mut c1s = path.curve_1_layers.iter();
    let mut c2s = path.curve_2_layers.iter();
    loop {
      if let Some(layer) = c2s.next() {
        assert!(layer.iter().any(|leaf| leaf == &c1_hash.unwrap()));
        c1_hash = None;
        c2_hash = Some(
          <Helios as Ciphersuite>::G::to_xy(
            hash_grow(
              &params.curve_2_generators,
              params.curve_2_hash_init,
              0,
              <Helios as Ciphersuite>::F::ZERO,
              layer,
            )
            .unwrap(),
          )
          .unwrap()
          .0,
        );
      } else {
        assert!(c1s.next().is_none());
      }

      if let Some(layer) = c1s.next() {
        assert!(layer.iter().any(|leaf| leaf == &c2_hash.unwrap()));
        c2_hash = None;
        c1_hash = Some(
          <Selene as Ciphersuite>::G::to_xy(
            hash_grow(
              &params.curve_1_generators,
              params.curve_1_hash_init,
              0,
              <Selene as Ciphersuite>::F::ZERO,
              layer,
            )
            .unwrap(),
          )
          .unwrap()
          .0,
        );
      } else {
        assert!(c2s.next().is_none());
        break;
      }
    }
    match root {
      TreeRoot::C1(root) => {
        assert_eq!(<Selene as Ciphersuite>::G::to_xy(root).unwrap().0, c1_hash.unwrap());
      }
      TreeRoot::C2(root) => {
        assert_eq!(<Helios as Ciphersuite>::G::to_xy(root).unwrap().0, c2_hash.unwrap());
      }
    }
  }

  (res, root)
}

fn random_output_blinds(
  G: <Ed25519 as Ciphersuite>::G,
  T: <Ed25519 as Ciphersuite>::G,
  U: <Ed25519 as Ciphersuite>::G,
  V: <Ed25519 as Ciphersuite>::G,
) -> OutputBlinds<<Ed25519 as Ciphersuite>::G> {
  let output_blinds_start = std::time::Instant::now();
  let res = OutputBlinds::new(
    OBlind::new(
      T,
      ScalarDecomposition::new(<Ed25519 as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ),
    IBlind::new(
      U,
      V,
      ScalarDecomposition::new(<Ed25519 as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ),
    IBlindBlind::new(
      T,
      ScalarDecomposition::new(<Ed25519 as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ),
    CBlind::new(
      G,
      ScalarDecomposition::new(<Ed25519 as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ),
  );
  println!("Output blinds took {}ms to calculate", output_blinds_start.elapsed().as_millis());
  res
}

fn blind_branches(
  params: &FcmpParams<MoneroCurves>,
  branches: Branches<MoneroCurves>,
  output_blinds: Vec<OutputBlinds<<Ed25519 as Ciphersuite>::G>>,
) -> BranchesWithBlinds<MoneroCurves> {
  let branch_blinds_start = std::time::Instant::now();
  let mut branches_1_blinds = vec![];
  for _ in 0 .. branches.necessary_c1_blinds() {
    branches_1_blinds.push(BranchBlind::<<Selene as Ciphersuite>::G>::new(
      params.curve_1_generators.h(),
      ScalarDecomposition::new(<Selene as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ));
  }

  let mut branches_2_blinds = vec![];
  for _ in 0 .. branches.necessary_c2_blinds() {
    branches_2_blinds.push(BranchBlind::<<Helios as Ciphersuite>::G>::new(
      params.curve_2_generators.h(),
      ScalarDecomposition::new(<Helios as Ciphersuite>::F::random(&mut OsRng)).unwrap(),
    ));
  }
  println!(
    "{} C1 branch blinds and {} C2 branch blinds took {}ms to calculate",
    branches.necessary_c1_blinds(),
    branches.necessary_c2_blinds(),
    branch_blinds_start.elapsed().as_millis()
  );

  branches.blind(output_blinds, branches_1_blinds, branches_2_blinds).unwrap()
}

#[inline(never)]
fn verify_fn(
  iters: usize,
  batch: usize,
  proof: &Fcmp<MoneroCurves>,
  params: &FcmpParams<MoneroCurves>,
  root: TreeRoot<Selene, Helios>,
  layers: usize,
  inputs: &[Input<<Selene as Ciphersuite>::F>],
) {
  let mut times = vec![];
  for _ in 0 .. iters {
    let instant = std::time::Instant::now();

    let mut verifier_1 = generalized_bulletproofs::Generators::batch_verifier();
    let mut verifier_2 = generalized_bulletproofs::Generators::batch_verifier();

    for _ in 0 .. batch {
      proof
        .verify(&mut OsRng, &mut verifier_1, &mut verifier_2, params, root, layers, inputs)
        .unwrap();
    }

    assert!(params.curve_1_generators.verify(verifier_1));
    assert!(params.curve_2_generators.verify(verifier_2));

    times.push(instant.elapsed().as_millis());
  }
  times.sort_unstable();
  println!("Median time to verify {batch} proof(s) was {}ms (n={iters})", times[times.len() / 2]);
}

#[test]
fn test_single_input() {
  let (G, T, U, V, params) = random_params(1);

  let output_blinds = random_output_blinds(G, T, U, V);

  for layers in 1 ..= (TARGET_LAYERS + 1) {
    println!("Testing a proof with 1 input and {layers} layers");

    let (path, root) = random_path(&params, layers);
    let output = path.output;

    let branches = Branches::new(vec![path]).unwrap();

    let input = output_blinds.blind(&output).unwrap();

    let proof = Fcmp::prove(
      &mut OsRng,
      &params,
      blind_branches(&params, branches, vec![output_blinds.clone()]),
    )
    .unwrap();

    verify_fn(1, 1, &proof, &params, root, layers, &[input]);
  }
}

#[test]
fn test_multiple_inputs() {
  let (G, T, U, V, params) = random_params(8);

  let mut all_proofs = vec![];

  for paths in 2 ..= 4 {
    // This is less than target layers yet still tests a C1 root and a C2 root
    for layers in 1 ..= 4 {
      println!("Testing a proof with {paths} inputs and {layers} layers");

      let (paths, root) = random_paths(&params, layers, paths);

      let mut output_blinds = vec![];
      for _ in 0 .. paths.len() {
        output_blinds.push(random_output_blinds(G, T, U, V));
      }

      let mut inputs = vec![];
      for (path, output_blinds) in paths.iter().zip(&output_blinds) {
        inputs.push(output_blinds.blind(&path.output).unwrap());
      }

      let branches = Branches::new(paths).unwrap();

      let proof =
        Fcmp::prove(&mut OsRng, &params, blind_branches(&params, branches, output_blinds)).unwrap();
      all_proofs.push((root, layers, inputs.clone(), proof.clone()));

      verify_fn(1, 1, &proof, &params, root, layers, &inputs);
    }
  }

  // Test batch verification of all of these proofs
  let mut verifier_1 = generalized_bulletproofs::Generators::batch_verifier();
  let mut verifier_2 = generalized_bulletproofs::Generators::batch_verifier();

  for (root, layers, inputs, proof) in all_proofs {
    proof
      .verify(&mut OsRng, &mut verifier_1, &mut verifier_2, &params, root, layers, &inputs)
      .unwrap();
  }
  assert!(params.curve_1_generators.verify(verifier_1));
  assert!(params.curve_2_generators.verify(verifier_2));
}

#[test]
fn test_malleated_proofs() {
  let (G, T, U, V, params) = random_params(2);

  for paths in [1, 2] {
    for layers in [1, 2] {
      let (paths, root) = random_paths(&params, layers, paths);

      let mut output_blinds = vec![];
      for _ in 0 .. paths.len() {
        output_blinds.push(random_output_blinds(G, T, U, V));
      }

      let mut inputs = vec![];
      for (path, output_blinds) in paths.iter().zip(&output_blinds) {
        inputs.push(output_blinds.blind(&path.output).unwrap());
      }

      let branches = Branches::new(paths.clone()).unwrap();

      let mut buf = vec![];
      {
        let proof =
          Fcmp::prove(&mut OsRng, &params, blind_branches(&params, branches, output_blinds))
            .unwrap();
        proof.write(&mut buf).unwrap();
      }

      for i in 0 .. buf.len() {
        let mut buf = buf.clone();
        let existing_byte = buf[i];
        while buf[i] == existing_byte {
          buf[i] = u8::try_from(OsRng.next_u64() & u64::from(u8::MAX)).unwrap();
        }
        if let Ok(proof) = Fcmp::read(&mut buf.as_slice(), paths.len(), layers) {
          let mut verifier_1 = generalized_bulletproofs::Generators::batch_verifier();
          let mut verifier_2 = generalized_bulletproofs::Generators::batch_verifier();

          if proof
            .verify(&mut OsRng, &mut verifier_1, &mut verifier_2, &params, root, layers, &inputs)
            .is_ok()
          {
            let valid = params.curve_1_generators.verify(verifier_1) &&
              params.curve_2_generators.verify(verifier_2);
            assert!(!valid, "malleated proof yet still verified");
          }
        }
      }
    }
  }
}

#[test]
fn prove_benchmark() {
  const RUNS: usize = 10;

  let (G, T, U, V, params) = random_params(8);

  for paths in 1 ..= 4 {
    let (paths, _root) = random_paths(&params, TARGET_LAYERS, paths);

    let mut set_size = 1u64;
    for i in 0 .. TARGET_LAYERS {
      if i % 2 == 0 {
        set_size *= u64::try_from(LAYER_ONE_LEN).unwrap();
      } else {
        set_size *= u64::try_from(LAYER_TWO_LEN).unwrap();
      }
    }

    let branches = Branches::new(paths.clone()).unwrap();

    let prove_start = std::time::Instant::now();
    for _ in 0 .. 10 {
      let mut output_blinds = vec![];
      for _ in 0 .. paths.len() {
        output_blinds.push(random_output_blinds(G, T, U, V));
      }

      let proof =
        Fcmp::prove(&mut OsRng, &params, blind_branches(&params, branches.clone(), output_blinds))
          .unwrap();

      core::hint::black_box(proof);
    }
    #[allow(clippy::print_literal)]
    {
      println!(
        "{} for {RUNS} {}-input FCMPs with a set size of {} took an average of {}ms each",
        "Sequentially proving",
        paths.len(),
        set_size,
        prove_start.elapsed().as_millis() / u128::try_from(RUNS).unwrap()
      );
    }
  }
}

#[test]
fn verify_benchmark() {
  let (G, T, U, V, params) = random_params(1);

  let (path, root) = random_path(&params, TARGET_LAYERS);
  let output = path.output;

  let branches = Branches::new(vec![path]).unwrap();

  let output_blinds = random_output_blinds(G, T, U, V);
  let input = output_blinds.blind(&output).unwrap();

  let proof =
    Fcmp::prove(&mut OsRng, &params, blind_branches(&params, branches, vec![output_blinds]))
      .unwrap();

  verify_fn(100, 1, &proof, &params, root, TARGET_LAYERS, &[input]);
  verify_fn(100, 10, &proof, &params, root, TARGET_LAYERS, &[input]);
  verify_fn(100, 100, &proof, &params, root, TARGET_LAYERS, &[input]);
}

#[test]
fn proof_sizes() {
  for inputs in 0 ..= 256 {
    println!(
      "Proof size for {inputs} inputs: {}",
      Fcmp::<MoneroCurves>::proof_size(inputs, TARGET_LAYERS)
    );
  }
}
