use crate::*;

#[test]
fn test_encoded_len_for_bytes() {
  // For an encoding of length `l`, we prune to the amount of bytes which encodes with length `l`
  // This assumes length `l` -> amount of bytes has a singular answer, which is tested here
  let mut set = std::collections::HashSet::new();
  for i in 0 .. BLOCK_LEN {
    set.insert(encoded_len_for_bytes(i));
  }
  assert_eq!(set.len(), BLOCK_LEN);
}

fn encode_decode(bytes: &[u8]) {
  assert_eq!(decode(encode(bytes).as_bytes()).collect::<Option<Vec<u8>>>().unwrap(), bytes);
  assert_eq!(
    decode_check(encode_check(bytes.to_vec()).as_bytes()).collect::<Option<Vec<u8>>>().unwrap(),
    bytes
  );
}

#[test]
fn base58() {
  assert_eq!(encode(&[]), String::new());
  assert!(decode("".as_bytes()).collect::<Option<Vec<u8>>>().unwrap().is_empty());

  let full_block = &[1, 2, 3, 4, 5, 6, 7, 8];
  encode_decode(full_block);

  let partial_block = &[1, 2, 3];
  encode_decode(partial_block);

  let max_encoded_block = &[u8::MAX; 8];
  encode_decode(max_encoded_block);

  let max_decoded_block = "zzzzzzzzzzz";
  assert_eq!(decode(max_decoded_block.as_bytes()).next(), Some(None));

  let full_and_partial_block = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
  encode_decode(full_and_partial_block);
}

#[test]
fn fuzz_base58() {
  use rand_core::{RngCore, OsRng};

  for _ in 0 .. 1000 {
    for len in 1 .. 200 {
      {
        let mut bytes = vec![0; len];
        OsRng.fill_bytes(&mut bytes);
        encode_decode(&bytes);
      }

      {
        let mut str = vec![0; len];
        for c in &mut str {
          *c = ALPHABET
            [usize::try_from(OsRng.next_u64() % u64::try_from(ALPHABET.len()).unwrap()).unwrap()];
        }
        let str = String::from_utf8(str).unwrap();
        // We don't care what the results are, solely that it doesn't panic
        let _ = core::hint::black_box(decode(str.as_bytes()).collect::<Option<Vec<u8>>>());
        let _ = core::hint::black_box(decode_check(str.as_bytes()).collect::<Option<Vec<u8>>>());
      }
    }
  }
}
