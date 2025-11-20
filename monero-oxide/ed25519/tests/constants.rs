use sha3::{Digest, Keccak256};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};
use monero_ed25519::{Scalar, CompressedPoint};

#[test]
fn constants() {
  assert_eq!(
    <[u8; 32]>::from(Scalar::INV_EIGHT),
    curve25519_dalek::Scalar::from(8u8).invert().to_bytes()
  );

  assert_eq!(
    CompressedPoint::G,
    CompressedPoint::from(ED25519_BASEPOINT_POINT.compress().to_bytes())
  );
  assert_eq!(
    CompressedPoint::H,
    CompressedPoint::from(
      CompressedEdwardsY(Keccak256::digest(ED25519_BASEPOINT_POINT.compress().to_bytes()).into())
        .decompress()
        .expect("known on-curve point wasn't on-curve")
        .mul_by_cofactor()
        .compress()
        .to_bytes()
    )
  );
}
