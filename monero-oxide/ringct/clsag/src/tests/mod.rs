use core::ops::Deref;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use monero_ed25519::{Scalar, CompressedPoint, Point, Commitment};
use crate::{Decoys, ClsagContext, Clsag};

#[cfg(feature = "multisig")]
mod multisig;

#[test]
fn clsag() {
  for ring_len in 1 ..= 16 {
    for real in 0 .. ring_len {
      let mut msg_hash = [1; 32];
      OsRng.fill_bytes(&mut msg_hash);
      let amount = OsRng.next_u64();

      let mut secrets = (Zeroizing::new(Scalar::ZERO.into()), Scalar::ZERO.into());
      let mut ring = vec![];
      for i in 0 .. ring_len {
        let dest = Zeroizing::new(Scalar::random(&mut OsRng).into());
        let mask = Scalar::random(&mut OsRng).into();
        let amount = if i == real {
          secrets = (dest.clone(), mask);
          amount
        } else {
          OsRng.next_u64()
        };
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
            Decoys::new((1 ..= u64::from(ring_len)).collect(), real, ring.clone()).unwrap(),
            Commitment::new(Scalar::from(secrets.1), amount),
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
}
