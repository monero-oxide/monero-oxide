use core::num::NonZero;

use crate::{
  io::VarInt,
  ed25519::CompressedPoint,
  extra::{ARBITRARY_DATA_MARKER, MAX_EXTRA_SIZE_BY_RELAY_RULE, ExtraField, Extra},
};

// https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
//   /src/cryptonote_basic/tx_extra.h#L43
const MAX_TX_EXTRA_PADDING_COUNT: u8 = 255;

// Tests derived from
// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
//   tests/unit_tests/test_tx_utils.cpp
// which is licensed as follows:
#[rustfmt::skip]
/*
Copyright (c) 2014-2022, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Parts of the project are originally copyright (c) 2012-2013 The Cryptonote
developers

Parts of the project are originally copyright (c) 2014 The Boolberry
developers, distributed under the MIT licence:

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
const _RUSTFMT_SKIP: () = ();

const PUB_KEY_BYTES: [u8; 33] = [
  1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63,
  198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
];

fn pub_key() -> CompressedPoint {
  CompressedPoint::from(<[u8; 32]>::try_from(&PUB_KEY_BYTES[1 .. PUB_KEY_BYTES.len()]).unwrap())
}

const MERKLE_ROOT: [u8; 32] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

fn test_write_buf(extra: &Extra, buf: &[u8]) {
  let mut w: Vec<u8> = vec![];
  Extra::write(extra, &mut w).unwrap();
  assert_eq!(buf, w);
}

#[test]
fn empty_extra() {
  let buf: Vec<u8> = vec![];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_size_1() {
  let buf: Vec<u8> = vec![0];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(NonZero::new(1).unwrap())]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_size_2() {
  let buf: Vec<u8> = vec![0, 0];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(NonZero::new(2).unwrap())]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_max_size() {
  let buf: Vec<u8> = vec![0; usize::from(MAX_TX_EXTRA_PADDING_COUNT)];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(NonZero::new(MAX_TX_EXTRA_PADDING_COUNT).unwrap())]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_exceed_max_size() {
  let buf: Vec<u8> = vec![0; usize::from(MAX_TX_EXTRA_PADDING_COUNT) + 1];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn invalid_padding_only() {
  let buf: Vec<u8> = vec![0, 42];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_only() {
  let buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key())]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_nonce_only() {
  let buf: Vec<u8> = vec![2, 1, 42];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Nonce(vec![42])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_nonce_only_wrong_size() {
  let mut buf: Vec<u8> = vec![0; 20];
  buf[0] = 2;
  buf[1] = 255;
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_and_padding() {
  let mut buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  buf.extend([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(
    extra.0,
    vec![ExtraField::PublicKey(pub_key()), ExtraField::Padding(NonZero::new(76).unwrap())]
  );
  test_write_buf(&extra, &buf);
}

#[test]
fn pub_key_and_invalid_padding() {
  let mut buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  buf.extend([0, 1]);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key())]);
}

#[test]
fn extra_mysterious_minergate_only() {
  let buf: Vec<u8> = vec![222, 1, 42];
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MysteriousMinergate(vec![42])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_mysterious_minergate_only_large() {
  let mut buf: Vec<u8> = vec![222];
  VarInt::write(&512u64, &mut buf).unwrap();
  buf.extend_from_slice(&vec![0; 512]);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MysteriousMinergate(vec![0; 512])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_mysterious_minergate_only_wrong_size() {
  let mut buf: Vec<u8> = vec![0; 20];
  buf[0] = 222;
  buf[1] = 255;
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn extra_mysterious_minergate_and_pub_key() {
  let buf = [PUB_KEY_BYTES.as_slice(), &[222, 1, 42]].concat();
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(
    extra.0,
    vec![ExtraField::PublicKey(pub_key()), ExtraField::MysteriousMinergate(vec![42])]
  );
  test_write_buf(&extra, &buf);
}

// Why the merge-mining blob must be _exactly_ consumed is documented on the `3 =>` arm of
// `ExtraField::read` in `extra.rs`. Each expectation below was established by running its exact
// byte string through a verbatim copy of `cryptonote::parse_tx_extra`:
// https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
//   /src/cryptonote_basic/cryptonote_format_utils.cpp#L534-L553

// Case A: A well-formed depth-0 tag. `monerod` accepts this, yielding one field.
#[test]
fn merge_mining_only() {
  // 03 21 00 <32-byte merkle root>
  let buf: Vec<u8> = [[3, 0x21, 0x00].as_slice(), MERKLE_ROOT.as_slice()].concat();
  assert_eq!(buf.len(), 35);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MergeMining(0, MERKLE_ROOT)]);
  test_write_buf(&extra, &buf);
}

// Case B: A trailing byte _inside_ the blob. `monerod` rejects this, yielding no fields.
#[test]
fn merge_mining_only_trailing_byte_within_blob() {
  // 03 22 00 <32-byte merkle root> AA
  let buf: Vec<u8> =
    [[3, 0x22, 0x00].as_slice(), MERKLE_ROOT.as_slice(), [0xAA].as_slice()].concat();
  assert_eq!(buf.len(), 36);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

// Case C: A blob length too small for the fields. `monerod` rejects this, yielding no fields.
#[test]
fn merge_mining_only_length_too_small() {
  // 03 10 00 <32-byte merkle root>
  let buf: Vec<u8> = [[3, 0x10, 0x00].as_slice(), MERKLE_ROOT.as_slice()].concat();
  assert_eq!(buf.len(), 35);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

/*
  Case D: A public key followed by an invalid merge-mining tag.

  `monerod` keeps the one field which preceded the failure. Notably, the merge-mining tag must not
  read past its own blob, else it'd consume bytes belonging to whatever follows it.
*/
#[test]
fn pub_key_and_invalid_merge_mining() {
  let buf: Vec<u8> = [
    PUB_KEY_BYTES.as_slice(),
    [3, 0x22, 0x00].as_slice(),
    MERKLE_ROOT.as_slice(),
    [0xAA].as_slice(),
  ]
  .concat();
  assert_eq!(buf.len(), 69);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key())]);
}

// Case E: An invalid merge-mining tag followed by a public key. `monerod` yields no fields, as the
// failure occurs before the public key is ever read.
#[test]
fn invalid_merge_mining_and_pub_key() {
  let buf: Vec<u8> = [
    [3, 0x22, 0x00].as_slice(),
    MERKLE_ROOT.as_slice(),
    [0xAA].as_slice(),
    PUB_KEY_BYTES.as_slice(),
  ]
  .concat();
  assert_eq!(buf.len(), 69);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

// Case F: A non-canonical VarInt for the depth. `monerod` rejects this, yielding no fields.
#[test]
fn merge_mining_only_non_canonical_depth() {
  // 03 22 80 00 <32-byte merkle root>
  let buf: Vec<u8> = [[3, 0x22, 0x80, 0x00].as_slice(), MERKLE_ROOT.as_slice()].concat();
  assert_eq!(buf.len(), 36);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

// Case G: A depth requiring a multi-byte VarInt. `monerod` accepts this, yielding one field.
#[test]
fn merge_mining_only_multi_byte_depth() {
  // 03 22 80 01 <32-byte merkle root>
  let buf: Vec<u8> = [[3, 0x22, 0x80, 0x01].as_slice(), MERKLE_ROOT.as_slice()].concat();
  assert_eq!(buf.len(), 36);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MergeMining(128, MERKLE_ROOT)]);
  test_write_buf(&extra, &buf);
}

/*
  Case H: A blob length which overshoots into the field which follows it.

  The blob declares 0x23 == 35 bytes, yet only 33 bytes of its own content exist (the depth's
  `VarInt` and the merkle root), so the declared length reaches two bytes into the public key which
  follows. `monerod` rejects this, yielding no fields.

  This is the case which pins that the tag is read from within its own blob, as the divergence is
  unobservable in every case above. An implementation reading the depth and merkle root directly
  off the outer stream would find them well-formed and yield a `MergeMining` field, then resume
  parsing from somewhere inside the public key.
*/
#[test]
fn merge_mining_length_overshoots_into_next_field() {
  // 03 23 00 <32-byte merkle root> 01 <32-byte public key>
  let buf: Vec<u8> =
    [[3, 0x23, 0x00].as_slice(), MERKLE_ROOT.as_slice(), PUB_KEY_BYTES.as_slice()].concat();
  assert_eq!(buf.len(), 68);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

// Case I: A blob length which exceeds every remaining byte in the extra. The blob declares
// 0x40 == 64 bytes with only 33 following. `monerod` rejects this, yielding no fields.
#[test]
fn merge_mining_length_exceeds_remaining_extra() {
  // 03 40 00 <32-byte merkle root>
  let buf: Vec<u8> = [[3, 0x40, 0x00].as_slice(), MERKLE_ROOT.as_slice()].concat();
  assert_eq!(buf.len(), 35);
  let extra = Extra::read(&mut buf.as_slice()).unwrap();
  assert!(extra.0.is_empty());
}

// The depths used by
// https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
//   /tests/unit_tests/cryptonote_format_utils.cpp
#[test]
fn merge_mining_round_trip() {
  for depth in [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 63, 64, 127, 128, 16383, 16384] {
    let extra = Extra(vec![ExtraField::MergeMining(depth, MERKLE_ROOT)]);
    let buf = extra.serialize();
    assert_eq!(Extra::read(&mut buf.as_slice()).unwrap(), extra, "depth {depth} didn't round-trip");
    test_write_buf(&extra, &buf);
  }
}

#[test]
fn fetching_data_does_not_panic() {
  assert!(Extra::read(&mut [0x02, 0x00].as_slice()).unwrap().arbitrary_data().is_empty());
  assert_eq!(
    Extra::read(&mut [0x02, 0x01, 0x7F].as_slice()).unwrap().arbitrary_data(),
    vec![Vec::<u8>::new()]
  );
}

#[test]
fn fetching_long_data_does_not_panic() {
  let mut extra = Extra::new(CompressedPoint::IDENTITY, vec![]);

  let mut arb_data = vec![0; 200];
  arb_data[0] = ARBITRARY_DATA_MARKER;

  // Push sets of arbitrary data
  for _ in 0 .. 5 {
    extra.push_nonce(arb_data.clone());
  }
  // Confirm we're within policy
  assert!(extra.serialize().len() < MAX_EXTRA_SIZE_BY_RELAY_RULE);

  // Push one more
  extra.push_nonce(arb_data.clone());
  // Confirm we're no longer in policy
  assert!(extra.serialize().len() > MAX_EXTRA_SIZE_BY_RELAY_RULE);

  // The extra should encode and decode
  assert_eq!(Extra::read(&mut extra.serialize().as_slice()).unwrap(), extra);
  // Yet we should only read arbitrary data from the set within policy
  assert_eq!(extra.arbitrary_data().len(), 5);
}
