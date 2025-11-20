#[allow(dead_code)]
pub(crate) fn decode(hex: &str) -> [u8; 32] {
  let mut point = [0; 32];
  assert_eq!(hex.len(), 64);
  for (i, c) in hex.chars().enumerate() {
    point[i / 2] |= (match c {
      '0' ..= '9' => (c as u8) - b'0',
      'A' ..= 'F' => (c as u8) - b'A' + 10,
      'a' ..= 'f' => (c as u8) - b'a' + 10,
      _ => panic!("test vectors contained invalid hex"),
    }) << (4 * ((i + 1) % 2));
  }
  point
}
