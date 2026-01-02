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
  assert_eq!(decode(&encode(bytes)).unwrap(), bytes);
  assert_eq!(decode_check(&encode_check(bytes.to_vec())).unwrap(), bytes);
}

#[test]
fn base58() {
  assert_eq!(encode(&[]), String::new());
  assert!(decode("").unwrap().is_empty());

  let full_block = &[1, 2, 3, 4, 5, 6, 7, 8];
  encode_decode(full_block);

  let partial_block = &[1, 2, 3];
  encode_decode(partial_block);

  let max_encoded_block = &[u8::MAX; 8];
  encode_decode(max_encoded_block);

  let max_decoded_block = "zzzzzzzzzzz";
  assert!(decode(max_decoded_block).is_none());

  // Shifts into position without issue but fails to add the last character
  assert!(decode("jpXCZedGfVz").is_none());

  let full_and_partial_block = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
  encode_decode(full_and_partial_block);
}

#[test]
fn fuzz_base58() {
  use rand_core::{RngCore as _, OsRng};

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
        let _ = core::hint::black_box(decode(&str));
        let _ = core::hint::black_box(decode_check(&str));
      }
    }
  }
}

#[test]
fn non_canonical() {
  // `decode_check("8Tge7kr") == decode_check("dLricHU")` without a check for if we're truncating
  /*
    let canon = crate::decode_check("8Tge7kr").unwrap();
    let non_canon = crate::decode_check("dLricHU").unwrap();
    assert_eq!(canon, non_canon);
  */
  assert!(crate::decode_check("dLricHU").is_none());
}
