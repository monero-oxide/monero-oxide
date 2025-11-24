use std_shims::collections::HashMap;

use rand_core::{RngCore, OsRng};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use dalek_ff_group::Scalar as DScalar;

use transcript::{Transcript, RecommendedTranscript};

use frost::{
  dkg::{Participant, ThresholdKeys},
  FrostError,
  curve::Ed25519,
  sign::*,
  tests::{clone_without, key_gen, algorithm_machines_without_clone, sign_without_clone},
};

use monero_ed25519::{Scalar, CompressedPoint, Commitment};
use crate::{Decoys, ClsagContext, ClsagMultisig};

#[allow(clippy::type_complexity)]
fn setup(
  scalar: DScalar,
  offset: DScalar,
) -> (
  [u8; 32],
  Box<impl Fn() -> ClsagMultisig>,
  HashMap<Participant, ThresholdKeys<Ed25519>>,
  HashMap<Participant, AlgorithmMachine<Ed25519, ClsagMultisig>>,
) {
  let amount = OsRng.next_u64();
  #[allow(clippy::cast_possible_truncation)]
  let ring_len = (OsRng.next_u64() as u8).saturating_add(1);
  let ring_index = u8::try_from(OsRng.next_u64() % u64::from(ring_len)).unwrap();

  let mut keys = key_gen::<_, Ed25519>(&mut OsRng);
  for keys in keys.values_mut() {
    *keys = keys.clone().scale(scalar).unwrap().offset(offset);
  }

  let randomness = Scalar::random(&mut OsRng).into();
  let mut ring = vec![];
  for i in 0 .. ring_len {
    let dest;
    let mask;
    let amount = if i != ring_index {
      dest = &Scalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE;
      mask = Scalar::random(&mut OsRng).into();
      OsRng.next_u64()
    } else {
      dest = keys[&Participant::new(1).unwrap()].group_key().0;
      mask = randomness;
      amount
    };
    ring.push([
      CompressedPoint::from(dest.compress().to_bytes()).decompress().unwrap(),
      Commitment::new(Scalar::from(mask), amount).commit(),
    ]);
  }

  let mask = Scalar::random(&mut OsRng).into();
  let params = move || {
    let (algorithm, mask_send) = ClsagMultisig::new(
      RecommendedTranscript::new(b"monero-oxide CLSAG Test"),
      ClsagContext::new(
        Decoys::new((1 ..= u64::from(ring_len)).collect(), ring_index, ring.clone()).unwrap(),
        Commitment::new(Scalar::from(randomness), amount),
      )
      .unwrap(),
    );
    mask_send.send(mask);
    algorithm
  };

  let mut msg = [1; 32];
  OsRng.fill_bytes(&mut msg);

  (
    msg,
    Box::new(params.clone()),
    keys.clone(),
    algorithm_machines_without_clone(
      &mut OsRng,
      &keys,
      keys
        .values()
        .map(|keys| (keys.params().i(), AlgorithmMachine::new(params(), keys.clone())))
        .collect(),
    ),
  )
}

#[test]
fn clsag_multisig() {
  for (scalar, offset) in [
    (DScalar::ONE, DScalar::ZERO),
    (DScalar::ONE, DScalar::random(&mut OsRng)),
    (DScalar::random(&mut OsRng), DScalar::ZERO),
    (DScalar::random(&mut OsRng), DScalar::random(&mut OsRng)),
  ] {
    let (msg, params, keys, machines) = setup(scalar, offset);

    // Use the provided `sign_without_clone` test helper to ensure this works
    sign_without_clone(
      &mut OsRng,
      keys.clone(),
      keys.values().map(|keys| (keys.params().i(), params())).collect(),
      machines,
      &msg,
    );
  }
}

#[test]
fn clsag_ia() {
  for (scalar, offset) in [
    (DScalar::ONE, DScalar::ZERO),
    (DScalar::ONE, DScalar::random(&mut OsRng)),
    (DScalar::random(&mut OsRng), DScalar::ZERO),
    (DScalar::random(&mut OsRng), DScalar::random(&mut OsRng)),
  ] {
    let (msg, _params, keys, machines) = setup(scalar, offset);

    let mut sign_machines = HashMap::new();
    let mut preprocesses = HashMap::new();
    for (i, machine) in machines {
      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      sign_machines.insert(i, machine);
      preprocesses.insert(i, preprocess);
    }
    let mut signature_machines = HashMap::new();
    let mut shares = HashMap::new();
    for (i, machine) in sign_machines {
      let (machine, share) = machine.sign(clone_without(&preprocesses, &i), &msg).unwrap();
      signature_machines.insert(i, machine);
      shares.insert(i, share);
    }

    // Select a random signer to mutate the share of
    let corrupt = loop {
      if let Some(i) = Participant::new(
        u16::try_from(OsRng.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap(),
      ) {
        if shares.contains_key(&i) {
          break i;
        }
      }
    };
    shares.insert(
      corrupt,
      signature_machines
        .values()
        .next()
        .unwrap()
        .read_share(&mut <[u8; 32]>::from(Scalar::random(&mut OsRng)).as_slice())
        .unwrap(),
    );
    for (i, machine) in signature_machines {
      if i != corrupt {
        assert_eq!(
          machine.complete(clone_without(&shares, &i)).unwrap_err(),
          FrostError::InvalidShare(corrupt)
        );
      }
    }
  }
}
