use core::{ops::BitXor, num::NonZero};
use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, BufRead, Write},
};

use zeroize::Zeroize;

use monero_oxide::{
  io::*,
  ed25519::{CompressedPoint, Point},
};

const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

const PAYMENT_ID_MARKER: u8 = 0;
const ENCRYPTED_PAYMENT_ID_MARKER: u8 = 1;
// Used as it's the highest value not interpretable as a continued VarInt
pub(crate) const ARBITRARY_DATA_MARKER: u8 = 127;

/// The max amount of data which will fit within a blob of arbitrary data.
// 1 byte is used for the marker
pub const MAX_ARBITRARY_DATA_SIZE: usize = MAX_TX_EXTRA_NONCE_SIZE - 1;

/// The maximum length for a transaction's extra under current relay rules.
// https://github.com/monero-project/monero
//  /blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/src/cryptonote_config.h#L217
pub const MAX_EXTRA_SIZE_BY_RELAY_RULE: usize = 1060;

/// A Payment ID.
///
/// This is a legacy method of identifying why Monero was sent to the receiver.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum PaymentId {
  /// A deprecated form of payment ID which is no longer supported.
  Unencrypted([u8; 32]),
  /// An encrypted payment ID.
  Encrypted([u8; 8]),
}

impl BitXor<[u8; 8]> for PaymentId {
  type Output = PaymentId;

  fn bitxor(self, bytes: [u8; 8]) -> PaymentId {
    match self {
      // Don't perform the xor since this isn't intended to be encrypted with xor
      PaymentId::Unencrypted(_) => self,
      PaymentId::Encrypted(id) => {
        PaymentId::Encrypted((u64::from_le_bytes(id) ^ u64::from_le_bytes(bytes)).to_le_bytes())
      }
    }
  }
}

impl PaymentId {
  /// Write the PaymentId.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      PaymentId::Unencrypted(id) => {
        w.write_all(&[PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
      PaymentId::Encrypted(id) => {
        w.write_all(&[ENCRYPTED_PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
    }
    Ok(())
  }

  /// Serialize the PaymentId to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1 + 8);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read a PaymentId.
  pub fn read<R: Read>(r: &mut R) -> io::Result<PaymentId> {
    Ok(match read_byte(r)? {
      0 => PaymentId::Unencrypted(read_bytes(r)?),
      1 => PaymentId::Encrypted(read_bytes(r)?),
      _ => Err(io::Error::other("unknown payment ID type"))?,
    })
  }
}

/// A field within the TX extra.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum ExtraField {
  /// Padding.
  ///
  /// This is a block of zeroes within the TX extra.
  Padding(NonZero<u8>),
  /// The transaction key.
  ///
  /// This is a commitment to the randomness used for deriving outputs.
  PublicKey(CompressedPoint),
  /// The nonce field.
  ///
  /// This is used for data, such as payment IDs.
  ///
  /// When read, this is bounded by a maximum size. As we directly expose the field here (without a
  /// constructor asserting its validity), this means it's possible to create an
  /// `ExtraField::Nonce` which can be written but not read. Please be careful accordingly.
  Nonce(Vec<u8>),
  /// The field for merge-mining.
  ///
  /// This is used within miner transactions who are merge-mining Monero to specify the foreign
  /// block they mined.
  MergeMining(u64, [u8; 32]),
  /// The additional transaction keys.
  ///
  /// These are the per-output commitments to the randomness used for deriving outputs.
  PublicKeys(Vec<CompressedPoint>),
  /// The 'mysterious' Minergate tag.
  ///
  /// This was used by a closed source entity without documentation. Support for parsing it was
  /// added to reduce extra which couldn't be decoded.
  MysteriousMinergate(Vec<u8>),
}

impl ExtraField {
  /// Write the ExtraField.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      ExtraField::Padding(size) => {
        w.write_all(&[0])?;
        for _ in 1 .. u8::from(*size) {
          write_byte(&0u8, w)?;
        }
      }
      ExtraField::PublicKey(key) => {
        w.write_all(&[1])?;
        key.write(w)?;
      }
      ExtraField::Nonce(data) => {
        w.write_all(&[2])?;
        /*
          This uses `write_vec`, where the `Vec` will be length-prefixed with a VarInt, which
          differs from Monero's `add_extra_nonce_to_tx_extra`:

          https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
            /src/cryptonote_basic/cryptonote_format_utils.cpp#L726

          This is because the definition in `tx_extra.h` is followed which does consider this a
          `VarInt`-length-prefixed container:

          https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
            /src/cryptonote_basic/tx_extra.h#L112-L115

          The former is considered faulty. See https://github.com/monero-project/monero/pull/10220.
        */
        write_vec(write_byte, data, w)?;
      }
      ExtraField::MergeMining(depth, merkle_root) => {
        w.write_all(&[3])?;
        VarInt::write(&(depth.varint_len() + merkle_root.len()), w)?;
        VarInt::write(depth, w)?;
        w.write_all(merkle_root)?;
      }
      ExtraField::PublicKeys(keys) => {
        w.write_all(&[4])?;
        write_vec(CompressedPoint::write, keys, w)?;
      }
      ExtraField::MysteriousMinergate(data) => {
        w.write_all(&[0xDE])?;
        write_vec(write_byte, data, w)?;
      }
    }
    Ok(())
  }

  /// Serialize the ExtraField to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1 + 8);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read an ExtraField.
  ///
  /// This may be lossy in that `ExtraField::read(&mut buf.as_slice()).serialize() == buf` is not
  /// guaranteed to hold true.
  pub fn read<R: BufRead>(r: &mut R) -> io::Result<ExtraField> {
    Ok(match read_byte(r)? {
      0 => ExtraField::Padding({
        // Read until either non-zero, max padding count, or end of buffer
        let mut size = 1u8;
        loop {
          let buf = r.fill_buf()?;
          let mut n_consume = 0;
          for v in buf {
            if *v != 0u8 {
              Err(io::Error::other("non-zero value after padding"))?;
            }
            n_consume += 1;
            // https://github.com/monero-project/monero
            //   /blob/02357fe53fbcab3f5102183f0837feed68cf5355/src/cryptonote_basic/tx_extra.h#L43
            if size == u8::MAX {
              Err(io::Error::other("padding exceeded max count"))?;
            }
            size += 1;
          }
          if n_consume == 0 {
            break;
          }
          r.consume(n_consume);
        }
        NonZero::new(size).expect("size started at 1 but incremented to 0?")
      }),
      1 => ExtraField::PublicKey(CompressedPoint::read(r)?),
      2 => ExtraField::Nonce(read_vec(read_byte, Some(MAX_TX_EXTRA_NONCE_SIZE), r)?),
      3 => {
        let field_len = <usize as VarInt>::read(r)?;
        let depth = <u64 as VarInt>::read(r)?;
        let merkle_root = read_bytes(r)?;

        match field_len.checked_sub(depth.varint_len() + merkle_root.len()) {
          Some(remaining) => {
            for _ in 0 .. remaining {
              read_byte(r)?;
            }
          }
          None => Err(io::Error::other("`MergeMining` tag had a length smaller than its fields"))?,
        }
        ExtraField::MergeMining(depth, merkle_root)
      }
      4 => ExtraField::PublicKeys(read_vec(CompressedPoint::read, None, r)?),
      0xDE => ExtraField::MysteriousMinergate(read_vec(read_byte, None, r)?),
      _ => Err(io::Error::other("unknown extra field"))?,
    })
  }
}

/// The result of decoding a transaction's extra field.
///
/// Note that the Monero protocol defines a transaction's `extra` field as a byte vector. This is a
/// parsed view of such a byte vector, yet the Monero protocol does not require the `extra` field
/// be parseable. The parsing is also lossy in that
/// `Extra::read(&mut buf.as_slice()).serialize() == buf` is not guaranteed to hold true.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Extra(pub(crate) Vec<ExtraField>);
impl Extra {
  /// The keys within this extra.
  ///
  /// This returns all keys specified with `PublicKey` and the first set of keys specified with
  /// `PublicKeys`. If any are improperly encoded, identity will be yielded in place, intending to
  /// cause an ECDH of the identity point, as Monero uses upon improperly-encoded points.
  // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c45
  //   /src/wallet/wallet2.cpp#L2290-L2300 (use all transaction keys)
  // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
  //   /src/wallet/wallet2.cpp#L2337-L2340 (use only the first set of additional keys)
  // https://github.com/monero-project/monero/blob/6bb36309d69e7157b459e957a9a2d64c67e5892e
  //   /src/wallet/wallet2.cpp#L2368-L2373 (public key was improperly encoded)
  // https://github.com/monero-project/monero/blob/6bb36309d69e7157b459e957a9a2d64c67e5892e
  //   /src/wallet/wallet2.cpp#L2383-L2387 (additional key was improperly encoded)
  pub fn keys(&self) -> Option<(Vec<Point>, Option<Vec<Point>>)> {
    let identity = {
      use curve25519_dalek::{traits::Identity as _, EdwardsPoint};
      Point::from(EdwardsPoint::identity())
    };

    let mut keys = vec![];
    let mut additional = None;
    for field in &self.0 {
      match field.clone() {
        ExtraField::PublicKey(key) => keys.push(key.decompress().unwrap_or(identity)),
        ExtraField::PublicKeys(keys) => {
          additional = additional
            .or(Some(keys.into_iter().map(|key| key.decompress().unwrap_or(identity)).collect()));
        }
        ExtraField::Padding(_) |
        ExtraField::Nonce(_) |
        ExtraField::MergeMining(_, _) |
        ExtraField::MysteriousMinergate(_) => (),
      }
    }
    // Don't return any keys if this was non-standard and didn't include the primary key
    // https://github.com/monero-project/monero/blob/6bb36309d69e7157b459e957a9a2d64c67e5892e
    //   /src/wallet/wallet2.cpp#L2338-L2346
    if keys.is_empty() {
      None
    } else {
      Some((keys, additional))
    }
  }

  /// The payment ID embedded within this extra.
  // Monero finds the first nonce field and reads the payment ID from it:
  // https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
  //   src/wallet/wallet2.cpp#L2709-L2752
  pub fn payment_id(&self) -> Option<PaymentId> {
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        let mut reader = data.as_slice();
        let res = PaymentId::read(&mut reader).ok();
        // https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
        //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L801
        //
        //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L811
        if !reader.is_empty() {
          None?;
        }
        return res;
      }
    }
    None
  }

  /// The arbitrary data within this extra.
  ///
  /// This looks for all instances of `ExtraField::Nonce` with a marker byte of 0b0111_1111. This
  /// is the largest possible value not interpretable as a VarInt, ensuring it's able to be
  /// interpreted as a VarInt without issue, and that it's the most unlikely value to be used by
  /// the Monero wallet protocol itself (which itself has assigned marker bytes incrementally). As
  /// Monero itself does not support including arbitrary data with its wallet however, this was
  /// first introduced by `monero-wallet` (under the monero-oxide project) and may be bespoke to
  /// the ecosystem of monero-oxide and dependents of it.
  ///
  /// The data is stored without any padding or encryption applied. Applications MUST consider this
  /// themselves. As Monero does not reserve any space for arbitrary data, the inclusion of _any_
  /// arbitrary data will _always_ be a fingerprint even before considering what the data is.
  /// Applications SHOULD include arbitrary data indistinguishable from random, of a popular length
  /// (such as padded to the next power of two or the maximum length per chunk) IF arbitrary data
  /// is included at all.
  ///
  /// For applications where indistinguishability from 'regular' Monero transactions is required,
  /// steganography should be considered. Steganography is somewhat-frowned upon however due to it
  /// bloating the Monero blockchain however and efficient methods are likely specific to
  /// individual hard forks. They may also have their own privacy implications, which is why no
  /// methods of stegnography are supported outright by `monero-wallet`.
  pub fn arbitrary_data(&self) -> Vec<Vec<u8>> {
    // Only parse arbitrary data from the amount of extra data accepted under the relay rule
    let serialized = self.serialize();
    let bounded_extra =
      Self::read(&mut &serialized[.. serialized.len().min(MAX_EXTRA_SIZE_BY_RELAY_RULE)])
        .expect("`Extra::read` only fails if the IO fails and `&[u8]` won't");

    let mut res = vec![];
    for field in &bounded_extra.0 {
      if let ExtraField::Nonce(data) = field {
        if data.first() == Some(&ARBITRARY_DATA_MARKER) {
          res.push(data[1 ..].to_vec());
        }
      }
    }
    res
  }

  pub(crate) fn new(key: CompressedPoint, additional: Vec<CompressedPoint>) -> Extra {
    let mut res = Extra(Vec::with_capacity(3));
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L627-L633
    // We only support pushing nonces which come after these in the sort order
    res.0.push(ExtraField::PublicKey(key));
    if !additional.is_empty() {
      res.0.push(ExtraField::PublicKeys(additional));
    }
    res
  }

  // TODO: This allows pushing a nonce of size greater than allowed. That's likely fine as it's
  // internal, yet should be better?
  pub(crate) fn push_nonce(&mut self, nonce: Vec<u8>) {
    self.0.push(ExtraField::Nonce(nonce));
  }

  /// Write the Extra.
  ///
  /// This will write the value in a sorted fashion.
  ///
  /// This is not of deterministic length nor length-prefixed. It should only be written to a
  /// buffer which will be delimited.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    #[cfg(debug_assertions)]
    let mut written = 0;
    // https://github.com/monero-project/monero/blob/02357fe53fbcab3f5102183f0837feed68cf5355
    //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L618-L624
    const SORT_ORDER: [fn(&ExtraField) -> bool; 6] = [
      |field: &ExtraField| matches!(field, ExtraField::PublicKey(_)),
      |field: &ExtraField| matches!(field, ExtraField::PublicKeys(_)),
      |field: &ExtraField| matches!(field, ExtraField::Nonce(_)),
      |field: &ExtraField| matches!(field, ExtraField::MergeMining(_, _)),
      |field: &ExtraField| matches!(field, ExtraField::MysteriousMinergate(_)),
      |field: &ExtraField| matches!(field, ExtraField::Padding(_)),
    ];
    // Ensure the length of the `SORT_ORDER` array corresponds to the amount of variants
    #[cfg(monero_oxide_rust_nightly)]
    const _SORT_LEN: [(); 0 - core::mem::variant_count::<ExtraField>().abs_diff(SORT_ORDER.len())] =
      [(); _];
    for selection in SORT_ORDER {
      for field in &self.0 {
        if selection(field) {
          field.write(w)?;
          #[cfg(debug_assertions)]
          {
            written += 1;
          }
        }
      }
    }
    debug_assert_eq!(written, self.0.len());
    Ok(())
  }

  /// Serialize the Extra to a `Vec<u8>`.
  ///
  /// This will write the value in a sorted fashion.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).expect("write failed but <Vec as io::Write> doesn't fail");
    buf
  }

  /// Read an `Extra`.
  ///
  /// This is not of deterministic length nor length-prefixed. It should only be read from a buffer
  /// already delimited.
  pub fn read<R: BufRead>(r: &mut R) -> io::Result<Extra> {
    let mut res = Extra(vec![]);
    // Extra reads until EOF
    // We take a BufRead so we can detect when the buffer is empty
    // `fill_buf` returns the current buffer, filled if empty, only empty if the reader is
    // exhausted
    while !r.fill_buf()?.is_empty() {
      let Ok(field) = ExtraField::read(r) else { break };
      res.0.push(field);
    }
    Ok(res)
  }
}
