//! A non-allocating alternative to `Vec`, used to track the state of an EPEE decoder.
//!
//! This is only possible due to bounding the depth of objects we decode, which we are able to do
//! with complete correctness due to EPEE defining a maximum depth of just `100`. This limit is
//! also sufficiently small as to make this not only feasible yet performant, with the stack taking
//! less than a kibibyte (even on 64-bit platforms).
//!
//! This code is internal to `monero-epee` yet is still written not to panic in any case.

/*
  Introducing `NonZero` bumped us from a MSRV of Rust 1.60 to Rust 1.79. We have no incentive to
  support Rust 1.60 here, yet it would be trivial to expand the supported versions of Rust.
*/
use core::num::NonZero;

use crate::{EpeeError, Type, TypeOrEntry};

// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/
//   contrib/epee/include/storages/portable_storage_from_bin.h#L42
const EPEE_LIB_MAX_OBJECT_DEPTH: usize = 100;
/*
  Explicitly set a larger depth in case we have slight differences in counting the current depth.

  The goal of this library is to decode at _least_ the set of objects EPEE itself will handle.
  While we may be slightly more tolerant, this is accepted over incompatibility given the lack of a
  strict specification for EPEE.

  Additionally, decoding a larget set of objects will not be considered an incompatibility so long
  as encodings (unsupported at the time of writing this comment) will always be handled by EPEE,
  ensuring _mutual_ compatibility.
*/
const MAX_OBJECT_DEPTH: usize = EPEE_LIB_MAX_OBJECT_DEPTH + 2;

/// An array of `TypeOrEntry`, using `u4` for each value.
struct PackedTypes([u8; MAX_OBJECT_DEPTH.div_ceil(2)]);
impl PackedTypes {
  fn get(&self, i: usize) -> TypeOrEntry {
    let mut entry = self.0[i / 2];
    entry >>= (i & 1) * 4;
    entry &= 0b1111;
    match entry {
      0 => TypeOrEntry::Entry,
      1 => TypeOrEntry::Type(Type::Int64),
      2 => TypeOrEntry::Type(Type::Int32),
      3 => TypeOrEntry::Type(Type::Int16),
      4 => TypeOrEntry::Type(Type::Int8),
      5 => TypeOrEntry::Type(Type::Uint64),
      6 => TypeOrEntry::Type(Type::Uint32),
      7 => TypeOrEntry::Type(Type::Uint16),
      8 => TypeOrEntry::Type(Type::Uint8),
      9 => TypeOrEntry::Type(Type::Double),
      10 => TypeOrEntry::Type(Type::String),
      11 => TypeOrEntry::Type(Type::Bool),
      12 => TypeOrEntry::Type(Type::Object),
      13 ..= 15 => panic!("`PackedTypes` was written to with a non-existent `TypeOrEntry`"),
      _ => unreachable!("masked by 0b1111"),
    }
  }

  fn set(&mut self, i: usize, kind: TypeOrEntry) {
    let four_bits = match kind {
      TypeOrEntry::Entry => 0,
      #[expect(clippy::as_conversions)]
      TypeOrEntry::Type(kind) => kind as u8,
    };
    let shift = (i & 1) * 4;
    // Clear the existing value in this slot
    self.0[i / 2] &= 0b1111_0000 >> shift;
    // Set the new value
    self.0[i / 2] |= four_bits << shift;
  }
}

/// A non-allocating `Vec`.
///
/// This has a maximum depth premised on the bound for an EPEE's object depth.
pub(crate) struct Stack {
  /*
    We represent items to decode as `(TypeOrEntry, usize)` so that if told to decode a vector with
    one billion entries, we don't have to allocate
    `vec![TypeOrEntry::Entry(Type::*), 1_000_000_000]` to keep track of the state. Instead, the
    size of the state is solely a function of depth, not width.

    The following two arrays are separate as Rust would pad `(TypeOrEntry, usize)` to 16 bytes,
    when it only requires 9 bytes to represent. Additionally, as there's less than 2**4 possible
    states for a `TypeOrEntry`, we represent it with a `u4` (via `PackedTypes`).
  */
  /// The type of the item being read.
  types: PackedTypes,
  /// The amount remaining for the item being read.
  amounts: [NonZero<usize>; MAX_OBJECT_DEPTH],

  /// The current depth of the stack.
  ///
  /// This is analogous to the length of a `Vec`, yet we use the term `depth` to distinguish how it
  /// tracks the depth of an object, not the amount of items present (which would be a function of
  /// depth and width, as noted above).
  depth: u8,
}

/*
  Because every time we decode an object, we allocate this fixed-size item on the stack (avoiding
  requiring dynamic allocation on the heap), ensure it's tiny and not an issue to allocate.
*/
#[cfg(test)]
const _ASSERT_KIBIBYTE_STACK: [(); 1024 - core::mem::size_of::<Stack>()] =
  [(); 1024 - core::mem::size_of::<Stack>()];

impl Stack {
  /// Create a new stack to use with decoding the root object.
  #[inline(always)]
  pub(crate) fn root_object() -> Self {
    /*
      Zero-initialize the arrays.

      Because we require `amounts` to be non-zero, we use `NonZero::MIN`. Alternatively, we'd need
      to use `unsafe` for the uninitialized memory.
    */
    let mut types = PackedTypes([0; MAX_OBJECT_DEPTH.div_ceil(2)]);
    let mut amounts = [NonZero::<usize>::MIN; MAX_OBJECT_DEPTH];

    types.set(0, TypeOrEntry::Type(Type::Object));
    amounts[0] = NonZero::<usize>::MIN; // 1

    Self { types, amounts, depth: 1 }
  }

  /// The current stack depth.
  #[inline(always)]
  pub(crate) fn depth(&self) -> usize {
    usize::from(self.depth)
  }

  /// Peek the current item on the stack.
  #[inline(always)]
  pub(crate) fn peek(&self) -> Option<(TypeOrEntry, NonZero<usize>)> {
    let i = self.depth().checked_sub(1)?;
    Some((self.types.get(i), self.amounts[i]))
  }

  /// Pop the next item from the stack.
  pub(crate) fn pop(&mut self) -> Option<TypeOrEntry> {
    let i = self.depth().checked_sub(1)?;

    let kind = self.types.get(i);

    // This will not panic as `amount` is unsigned and non-zero.
    let amount = self.amounts[i].get() - 1;
    if let Some(amount) = NonZero::new(amount) {
      self.amounts[i] = amount;
    } else {
      // This will not panic as we know depth can have `1` subtracted.
      self.depth -= 1;
    }

    Some(kind)
  }

  /// Push an item onto the stack.
  pub(crate) fn push(&mut self, kind: TypeOrEntry, amount: usize) -> Result<(), EpeeError> {
    // Assert the maximum depth for an object
    if self.depth() == MAX_OBJECT_DEPTH {
      Err(EpeeError::DepthLimitExceeded)?;
    }

    let Some(amount) = NonZero::new(amount) else {
      // If we have nothing to decode, immediately return
      return Ok(());
    };

    // These will not panic due to our depth check at the start of the function
    self.types.set(self.depth(), kind);
    self.amounts[self.depth()] = amount;
    self.depth += 1;

    Ok(())
  }
}
