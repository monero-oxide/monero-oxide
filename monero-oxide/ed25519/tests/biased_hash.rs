use monero_ed25519::{Point, CompressedPoint};

mod hex;

#[test]
fn biased_hash() {
  let mut batch = vec![];
  let mut preimages = vec![];

  let reader = include_str!("./tests.txt");
  for line in reader.lines() {
    let mut words = line.split_whitespace();

    let command = words.next().unwrap();
    match command {
      "check_key" => {}
      "hash_to_ec" => {
        let preimage = hex::decode(words.next().unwrap());
        let actual = Point::biased_hash(preimage);
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
        batch.push(actual.compress());
        preimages.push(preimage);
      }
      _ => unreachable!("unknown command"),
    }
  }

  for (actual, constant) in batch
    .into_iter()
    .zip(CompressedPoint::biased_hash_vartime::<256, 512>(preimages.try_into().unwrap()))
  {
    assert_eq!(actual, constant);
  }
}
