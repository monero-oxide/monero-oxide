use blake2::digest::Update;

use crate::Blake2bMonero;

struct HashTestVector {
  data: &'static [u8; 1],
  result_size: usize,
  to_scalar: bool,
  // Hexadecimal 64 digits
  key: Option<&'static str>,
  // Hexadecimal 128 digits
  expected: &'static str,
}
#[rustfmt::skip]
static HASH_TEST_VECTORS: &[HashTestVector] = &[
    HashTestVector{ data: &[88], result_size: 3, to_scalar: false, key: None, expected: "2ab9f400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 3, to_scalar: false, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "9d69f300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 8, to_scalar: false, key: None, expected: "780929e05b0c3b180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 8, to_scalar: false, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "bf3af50e6dc334a60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 16, to_scalar: false, key: None, expected: "bdfc7146cd226d5d4067a72fdfa8896e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 16, to_scalar: false, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "0f2dbcdbca827f2bd2f4860ab34a2c63000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 32, to_scalar: false, key: None, expected: "84b1cf12fe7ef008abdc2031610511d7a22f58abf9f8222910696a8ac9cb98330000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 32, to_scalar: false, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "ac7a1c22b038cc2ed63feb43dd70efd8b191cd5a7708bc5da81449a4931f28bf0000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 64, to_scalar: false, key: None, expected: "38261c9406d58392edd45f2a0b0a54956db4043322973d210b5b0711604b202102b5fdd226dfb8479c0cce599a47bbb372ac19a54f6bfaf5343548f39fa733e4" },
    HashTestVector{ data: &[88], result_size: 64, to_scalar: false, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "b4daf6765b70332990eb02c19105b50ef9ce642411013dd3b43c4d63b4674a60671e51bb01fc0a62800eccb101db7279b7b332ee5a9ba93b70472bf458365136" },
    HashTestVector{ data: &[88], result_size: 32, to_scalar: true, key: None, expected: "0064daffad6ef73bfbf8889ae01e91afd4b7313fd0f770cdda21a0c8099bb5010000000000000000000000000000000000000000000000000000000000000000" },
    HashTestVector{ data: &[88], result_size: 32, to_scalar: true, key: Some("1212121212121212121212121212121212121212121212121212121212121212"), expected: "a529e55012787574f9cd08af72660bcb11bc9ea276e9c66c5d39edc66917aa030000000000000000000000000000000000000000000000000000000000000000" }
];

#[test]
fn hash_test_vectors() {
  let test_fn = |data: &[u8; 1],
                 result_size: usize,
                 to_scalar: bool,
                 key: Option<[u8; 32]>,
                 expected: [u8; 64]| {
    // result_size refers to the number of bytes in the result, not necessarily the size of
    // the hash output.
    let output_size = if to_scalar { 64 } else { result_size };
    let mut transcript = match key {
      Some(k) => Blake2bMonero::new_with_key(&k, output_size),
      None => Blake2bMonero::new(output_size),
    }
    .expect("output size should be valid");

    transcript.update(data);

    let mut actual = [0u8; 64];

    if to_scalar {
      let scalar = transcript.finalize_as_scalar().expect("valid output size");
      for i in 0 .. 32 {
        actual[i] = scalar[i];
      }
    } else {
      transcript
        .try_finalize_into(&mut actual[0 .. result_size])
        .expect("output data length should be valid");
    }

    for i in 0 .. result_size {
      assert_eq!(expected[i], actual[i]);
    }
  };

  for v in HASH_TEST_VECTORS {
    let key = if let Some(k) = v.key {
      let mut key = [0u8; 32];
      hex::decode_to_slice(k, &mut key).expect("decode valid");
      Some(key)
    } else {
      None
    };
    let mut expected = [0u8; 64];
    hex::decode_to_slice(v.expected, &mut expected).expect("decode valid");
    (test_fn)(v.data, v.result_size, v.to_scalar, key, expected);
  }
}
