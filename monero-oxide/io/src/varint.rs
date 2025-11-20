//! Monero's VarInt type, frequently used to encode integers expected to be of low norm.
//!
//! This corresponds to
//! https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
//!   /src/common/varint.h.

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, Read, Write};

use crate::{read_byte, write_byte};

const VARINT_CONTINUATION_FLAG: u8 = 0b1000_0000;
const VARINT_VALUE_MASK: u8 = !VARINT_CONTINUATION_FLAG;

mod sealed {
  /// A seal to prevent implementing `VarInt` on foreign types.
  pub trait Sealed {
    /// Lossless, guaranteed conversion into a `u64`.
    ///
    /// This is due to internally implementing encoding for `u64` alone and `usize` not implementing
    /// `From<u64>`.
    // This is placed here so it's not within our public API commitment.
    fn into_u64(self) -> u64;
  }
}

/// Compute the upper bound for the encoded length of a integer type as a VarInt.
///
/// This is a private function only called at compile-time, hence why it panics on unexpected
/// input.
#[allow(clippy::cast_possible_truncation)]
const fn upper_bound(bits: u32) -> usize {
  // This assert ensures the following cast is correct even on 8-bit platforms
  assert!(bits <= 256, "defining a number exceeding u256 as a VarInt");
  // Manually implement `div_ceil` as it was introduced with 1.73 and `std-shims` cannot provide
  // a `const fn` shim due to using a trait to provide this as a method
  ((bits + (7 - 1)) / 7) as usize
}

/// A trait for a number readable/writable as a VarInt.
///
/// This is sealed to prevent unintended implementations. It MUST only be implemented for primitive
/// types (or sufficiently approximate types like `NonZero<_>`).
pub trait VarInt: TryFrom<u64> + Copy + sealed::Sealed {
  /// The lower bound on the amount of bytes this will take up when encoded.
  const LOWER_BOUND: usize;

  /// The upper bound on the amount of bytes this will take up when encoded.
  const UPPER_BOUND: usize;

  /// The amount of bytes this number will take when serialized as a VarInt.
  fn varint_len(self) -> usize {
    let varint_u64 = self.into_u64();
    usize::try_from(u64::BITS - varint_u64.leading_zeros()).expect("64 > usize::MAX?").div_ceil(7)
  }

  /// Read a canonically-encoded VarInt.
  fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    let mut bits = 0;
    let mut res = 0;
    while {
      let b = read_byte(r)?;
      // Reject trailing zero bytes
      // https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
      //   /src/common/varint.h#L107
      if (bits != 0) && (b == 0) {
        Err(io::Error::other("non-canonical varint"))?;
      }

      // We use `size_of` here as we control what `VarInt` is implemented for, and it's only for
      // types whose size correspond to their range
      #[allow(non_snake_case)]
      let U_BITS = core::mem::size_of::<Self>() * 8;
      if ((bits + 7) >= U_BITS) && (b >= (1 << (U_BITS - bits))) {
        Err(io::Error::other("varint overflow"))?;
      }

      res += u64::from(b & VARINT_VALUE_MASK) << bits;
      bits += 7;
      (b & VARINT_CONTINUATION_FLAG) == VARINT_CONTINUATION_FLAG
    } {}
    res.try_into().map_err(|_| io::Error::other("VarInt does not fit into integer type"))
  }

  /// Encode a number as a VarInt.
  ///
  /// This doesn't accept `self` to force writing it as `VarInt::write`, making it clear it's being
  /// written with the VarInt encoding.
  fn write<W: Write>(varint: &Self, w: &mut W) -> io::Result<()> {
    let mut varint: u64 = varint.into_u64();

    // A do-while loop as we always encode at least one byte
    while {
      // Take the next seven bits
      let mut b = u8::try_from(varint & u64::from(VARINT_VALUE_MASK))
        .expect("& 0b0111_1111 left more than 8 bits set");
      varint >>= 7;

      // If there's more, set the continuation flag
      if varint != 0 {
        b |= VARINT_CONTINUATION_FLAG;
      }

      // Write this byte
      write_byte(&b, w)?;

      // Continue until the number is fully encoded
      varint != 0
    } {}

    Ok(())
  }
}

impl sealed::Sealed for u8 {
  fn into_u64(self) -> u64 {
    self.into()
  }
}
impl VarInt for u8 {
  const LOWER_BOUND: usize = 1;
  const UPPER_BOUND: usize = upper_bound(Self::BITS);
}

impl sealed::Sealed for u32 {
  fn into_u64(self) -> u64 {
    self.into()
  }
}
impl VarInt for u32 {
  const LOWER_BOUND: usize = 1;
  const UPPER_BOUND: usize = upper_bound(Self::BITS);
}

impl sealed::Sealed for u64 {
  fn into_u64(self) -> u64 {
    self
  }
}
impl VarInt for u64 {
  const LOWER_BOUND: usize = 1;
  const UPPER_BOUND: usize = upper_bound(Self::BITS);
}

impl sealed::Sealed for usize {
  fn into_u64(self) -> u64 {
    // Ensure the falling conversion is infallible
    const _NO_128_BIT_PLATFORMS: [(); (u64::BITS - usize::BITS) as usize] =
      [(); (u64::BITS - usize::BITS) as usize];

    self.try_into().expect("compiling on platform with <64-bit usize yet value didn't fit in u64")
  }
}
impl VarInt for usize {
  const LOWER_BOUND: usize = 1;
  const UPPER_BOUND: usize = upper_bound(Self::BITS);
}
