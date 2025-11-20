use monero_ed25519::UnreducedScalar;

mod hex;

#[test]
fn recover_scalars() {
  let test_recover = |stored: &str, recovered: &str| {
    let stored = UnreducedScalar::read(&mut hex::decode(stored).as_slice()).unwrap();
    let recovered = curve25519_dalek::Scalar::from_canonical_bytes(hex::decode(recovered)).unwrap();
    assert_eq!(<[u8; 32]>::from(stored.ref10_slide_scalar_vartime()), recovered.to_bytes());
  };

  // https://www.moneroinflation.com/static/data_py/report_scalars_df.pdf, Table 4
  test_recover(
    "cb2be144948166d0a9edb831ea586da0c376efa217871505ad77f6ff80f203f8",
    "b8ffd6a1aee47828808ab0d4c8524cb5c376efa217871505ad77f6ff80f20308",
  );
  test_recover(
    "343d3df8a1051c15a400649c423dc4ed58bef49c50caef6ca4a618b80dee22f4",
    "21113355bc682e6d7a9d5b3f2137a30259bef49c50caef6ca4a618b80dee2204",
  );
  test_recover(
    "c14f75d612800ca2c1dcfa387a42c9cc086c005bc94b18d204dd61342418eba7",
    "4f473804b1d27ab2c789c80ab21d034a096c005bc94b18d204dd61342418eb07",
  );
  test_recover(
    "000102030405060708090a0b0c0d0e0f826c4f6e2329a31bc5bc320af0b2bcbb",
    "a124cfd387f461bf3719e03965ee6877826c4f6e2329a31bc5bc320af0b2bc0b",
  );
}
