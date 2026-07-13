#![allow(missing_docs)]

use monero_ed25519::{CompressedPoint, Point};

mod hex;

#[test]
fn known_answer() {
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
      "biased_hash_to_ec" => {
        let preimage = hex::decode(words.next().unwrap());
        let actual = Point::biased_hash(preimage);
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
      }
      "derive_key_image_generator" => {
        let word = words.next().unwrap();
        let point = hex::decode(word);
        let biased: bool = words.next().unwrap().parse().unwrap();
        let actual = if biased { Point::biased_hash(point) } else { Point::hash(point) };
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
      }
      _ => unreachable!("unknown command"),
    }
  }
}
