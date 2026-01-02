#![allow(missing_docs)]

use monero_ed25519::CompressedPoint;

mod hex;

#[test]
fn decompress() {
  let reader = include_str!("./tests.txt");

  for line in reader.lines() {
    let mut words = line.split_whitespace();

    let command = words.next().unwrap();
    match command {
      "check_key" => {
        let key = hex::decode(words.next().unwrap());
        let expected = match words.next().unwrap() {
          "true" => true,
          "false" => false,
          _ => unreachable!("invalid result"),
        };

        let actual = CompressedPoint::from(key).decompress();
        assert_eq!(actual.is_some(), expected);
      }
      "hash_to_ec" => {}
      _ => unreachable!("unknown command"),
    }
  }
}
