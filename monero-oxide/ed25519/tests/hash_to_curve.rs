#![allow(missing_docs)]

use monero_ed25519::Point;

mod hex;

#[test]
fn hash_to_curve() {
  let reader = include_str!("./tests.txt");

  for line in reader.lines() {
    let mut words = line.split_whitespace();

    let command = words.next().unwrap();
    match command {
      "check_key" => {}
      "biased_hash_to_ec" => {
        let preimage = hex::decode(words.next().unwrap());
        let actual = Point::biased_hash(preimage);
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
      }
      "derive_key_image_generator" => {
        let point = hex::decode(words.next().unwrap());
        let biased: bool = words.next().unwrap().parse().unwrap(); 
        let actual = if biased {
          Point::biased_hash(point)
        } else {
          Point::hash(point)
        };
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
      }
      _ => unreachable!("unknown command"),
    }
  }
}
