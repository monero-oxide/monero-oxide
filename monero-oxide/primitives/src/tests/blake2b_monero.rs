use blake2::digest::Update as _;

use crate::Blake2bMonero;

fn test<const OUTPUT_SIZE: usize>(data: &[u8], key: Option<[u8; 32]>, expected: &[u8]) {
  let mut transcript = match key {
    Some(k) => Blake2bMonero::<OUTPUT_SIZE>::new_with_key(&k),
    None => Blake2bMonero::<OUTPUT_SIZE>::new(),
  };
  transcript.update(data);
  assert_eq!(expected, &transcript.finalize()[.. expected.len()]);
}

fn test_scalar(data: &[u8], key: Option<[u8; 32]>, expected: [u8; 32]) {
  let mut transcript = match key {
    Some(k) => Blake2bMonero::<64>::new_with_key(&k),
    None => Blake2bMonero::<64>::new(),
  };
  transcript.update(data);
  assert_eq!(expected, transcript.finalize_as_scalar().to_bytes());
}

const DATA: &[u8] = &[88];
const KEY: &str = "1212121212121212121212121212121212121212121212121212121212121212";

#[rustfmt::skip]
#[test]
fn hash_test_vectors() {
  let mut key = [0; 32];
  hex::decode_to_slice(KEY, &mut key).expect("valid key");

  test::<3>(DATA, None, &hex::decode(b"2ab9f4").unwrap());
  test::<3>(DATA, Some(key), &hex::decode(b"9d69f3").unwrap());

  test::<8>(DATA, None, &hex::decode(b"780929e05b0c3b18").unwrap());
  test::<8>(DATA, Some(key), &hex::decode(b"bf3af50e6dc334a6").unwrap());

  test::<16>(DATA, None, &hex::decode(b"bdfc7146cd226d5d4067a72fdfa8896e").unwrap());
  test::<16>(DATA, Some(key), &hex::decode(b"0f2dbcdbca827f2bd2f4860ab34a2c63").unwrap());

  test::<32>(
    DATA,
    None,
    &hex::decode(b"84b1cf12fe7ef008abdc2031610511d7a22f58abf9f8222910696a8ac9cb9833").unwrap(),
  );
  test::<32>(
    DATA,
    Some(key),
    &hex::decode(b"ac7a1c22b038cc2ed63feb43dd70efd8b191cd5a7708bc5da81449a4931f28bf").unwrap(),
  );

  test::<64>(DATA, None, &hex::decode(b"38261c9406d58392edd45f2a0b0a54956db4043322973d210b5b0711604b202102b5fdd226dfb8479c0cce599a47bbb372ac19a54f6bfaf5343548f39fa733e4").unwrap());
  test::<64>(DATA, Some(key), &hex::decode(b"b4daf6765b70332990eb02c19105b50ef9ce642411013dd3b43c4d63b4674a60671e51bb01fc0a62800eccb101db7279b7b332ee5a9ba93b70472bf458365136").unwrap());

  test_scalar(
    DATA,
    None,
    hex::decode(b"0064daffad6ef73bfbf8889ae01e91afd4b7313fd0f770cdda21a0c8099bb501")
      .unwrap()
      .try_into()
      .unwrap(),
  );
  test_scalar(
    DATA,
    Some(key),
    hex::decode(b"a529e55012787574f9cd08af72660bcb11bc9ea276e9c66c5d39edc66917aa03")
      .unwrap()
      .try_into()
      .unwrap(),
  );
}
