use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar as DalekScalar};
use zeroize::Zeroizing;
use crate::{ed25519::Point, io::VarInt, primitives::keccak256, SharedKeyDerivations};

#[test]
fn optimized_derivations_match_original_formula_at_varint_boundaries() {
  for scalar in [1u64, 7, 65535] {
    let ecdh = Point::from(DalekScalar::from(scalar) * ED25519_BASEPOINT_POINT);
    for index in [0usize, 1, 127, 128, 16383, 16384, usize::MAX] {
      let mut original =
        Zeroizing::new(ecdh.into().mul_by_cofactor().compress().to_bytes().to_vec());
      VarInt::write(&index, &mut *original).unwrap();
      let expected_tag = keccak256([b"view_tag".as_slice(), original.as_slice()].concat())[0];
      for uniqueness in [None, Some([42u8; 32])] {
        let mut shared = Zeroizing::new(Vec::new());
        if let Some(u) = uniqueness {
          shared.extend_from_slice(&u);
        }
        shared.extend_from_slice(&original);
        let expected_key = crate::ed25519::Scalar::hash(&shared);
        let derived = SharedKeyDerivations::output_derivations(uniqueness, &ecdh, index);
        assert_eq!(derived.view_tag, expected_tag);
        assert_eq!(derived.shared_key, expected_key);
        assert_eq!(SharedKeyDerivations::output_view_tag(&ecdh, index), expected_tag);
        assert_eq!(SharedKeyDerivations::output_shared_key(uniqueness, &ecdh, index), expected_key);
      }
      let ra = ecdh.into().mul_by_cofactor().compress().to_bytes();
      let expected_id = keccak256([ra.as_slice(), &[0x8d]].concat());
      assert_eq!(SharedKeyDerivations::payment_id_xor(Zeroizing::new(ecdh)), expected_id[..8]);
    }
  }
}
