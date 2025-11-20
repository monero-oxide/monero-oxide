use core::ops::Deref;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

#[cfg(feature = "multisig")]
use transcript::{Transcript, RecommendedTranscript};
#[cfg(feature = "multisig")]
use frost::curve::Ed25519;

use monero_ed25519::{Scalar, CompressedPoint, Point, Commitment};
use crate::{Decoys, ClsagContext, Clsag};
#[cfg(feature = "multisig")]
use crate::ClsagMultisig;

#[cfg(feature = "multisig")]
use frost::{
  Participant,
  sign::AlgorithmMachine,
  tests::{key_gen, algorithm_machines_without_clone, sign_without_clone},
};

const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[cfg(feature = "multisig")]
const RING_INDEX: u8 = 3;

#[test]
fn clsag() {
  for real in 0 .. RING_LEN {
    let msg_hash = [1; 32];

    let mut secrets = (Zeroizing::new(Scalar::ZERO.into()), Scalar::ZERO.into());
    let mut ring = vec![];
    for i in 0 .. RING_LEN {
      let dest = Zeroizing::new(Scalar::random(&mut OsRng).into());
      let mask = Scalar::random(&mut OsRng).into();
      let amount;
      if i == real {
        secrets = (dest.clone(), mask);
        amount = AMOUNT;
      } else {
        amount = OsRng.next_u64();
      }
      ring.push([
        CompressedPoint::from((dest.deref() * ED25519_BASEPOINT_TABLE).compress().to_bytes())
          .decompress()
          .unwrap(),
        Commitment::new(Scalar::from(mask), amount).commit(),
      ]);
    }

    let (clsag, pseudo_out) = Clsag::sign(
      &mut OsRng,
      vec![(
        Zeroizing::new(Scalar::from(*secrets.0.clone())),
        ClsagContext::new(
          Decoys::new((1 ..= RING_LEN).collect(), u8::try_from(real).unwrap(), ring.clone())
            .unwrap(),
          Commitment::new(Scalar::from(secrets.1), AMOUNT),
        )
        .unwrap(),
      )],
      Scalar::random(&mut OsRng),
      msg_hash,
    )
    .unwrap()
    .swap_remove(0);

    let pseudo_out = CompressedPoint::from(pseudo_out.compress().to_bytes());

    let image = CompressedPoint::from(
      (Point::biased_hash((ED25519_BASEPOINT_TABLE * secrets.0.deref()).compress().0).into() *
        secrets.0.deref())
      .compress()
      .to_bytes(),
    );

    let ring = ring.iter().map(|r| [r[0].compress(), r[1].compress()]).collect::<Vec<_>>();

    clsag.verify(ring.clone(), &image, &pseudo_out, &msg_hash).unwrap();

    // Test verification fails if we malleate a ring member
    {
      use curve25519_dalek::traits::IsIdentity;

      let mut ring = ring.clone();
      let torsion = curve25519_dalek::edwards::CompressedEdwardsY([0; 32]).decompress().unwrap();
      assert!(!torsion.is_identity());
      assert!(!torsion.is_torsion_free());
      ring[0][0] = CompressedPoint::from(
        (ring[0][0].decompress().unwrap().into() + torsion).compress().to_bytes(),
      );
      assert!(clsag.verify(ring, &image, &pseudo_out, &msg_hash).is_err());
    }

    // make sure verification fails if we throw a random `c1` at it.
    {
      let mut clsag = clsag.clone();
      clsag.c1 = Scalar::random(&mut OsRng);
      assert!(clsag.verify(ring, &image, &pseudo_out, &msg_hash).is_err());
    }
  }
}

#[cfg(feature = "multisig")]
#[test]
fn clsag_multisig() {
  let keys = key_gen::<_, Ed25519>(&mut OsRng);

  let randomness = Scalar::random(&mut OsRng).into();
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest;
    let mask;
    let amount;
    if i != u64::from(RING_INDEX) {
      dest = &Scalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE;
      mask = Scalar::random(&mut OsRng).into();
      amount = OsRng.next_u64();
    } else {
      dest = keys[&Participant::new(1).unwrap()].group_key().0;
      mask = randomness;
      amount = AMOUNT;
    }
    ring.push([
      CompressedPoint::from(dest.compress().to_bytes()).decompress().unwrap(),
      Commitment::new(Scalar::from(mask), amount).commit(),
    ]);
  }

  let mask = Scalar::random(&mut OsRng).into();
  let params = || {
    let (algorithm, mask_send) = ClsagMultisig::new(
      RecommendedTranscript::new(b"monero-oxide CLSAG Test"),
      ClsagContext::new(
        Decoys::new((1 ..= RING_LEN).collect(), RING_INDEX, ring.clone()).unwrap(),
        Commitment::new(Scalar::from(randomness), AMOUNT),
      )
      .unwrap(),
    );
    mask_send.send(mask);
    algorithm
  };

  sign_without_clone(
    &mut OsRng,
    keys.clone(),
    keys.values().map(|keys| (keys.params().i(), params())).collect(),
    algorithm_machines_without_clone(
      &mut OsRng,
      &keys,
      keys
        .values()
        .map(|keys| (keys.params().i(), AlgorithmMachine::new(params(), keys.clone())))
        .collect(),
    ),
    &[1; 32],
  );
}
