use core::marker::PhantomData;

use crate::{EpeeError, Stack, io::*};

/// The EPEE-defined type of the field being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Type {
  /// An `i64`.
  Int64 = 1,
  /// An `i32`.
  Int32 = 2,
  /// An `i16`.
  Int16 = 3,
  /// An `i8`.
  Int8 = 4,
  /// A `u64`.
  Uint64 = 5,
  /// A `u32`.
  Uint32 = 6,
  /// A `u16`.
  Uint16 = 7,
  /// A `u8`.
  Uint8 = 8,
  /// A `f64`.
  Double = 9,
  /// A length-prefixed collection of bytes.
  String = 10,
  /// A `bool`.
  Bool = 11,
  /// An object.
  Object = 12,
  /*
    Unused and unsupported. See
    https://github.com/monero-project/monero/pull/10138 for more info.
  */
  // Array = 13,
}

/// A bitflag for if the field is actually an array.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Array {
  /// A unit type.
  Unit = 0,
  /// An array.
  Array = 1 << 7,
}

/*
  An internal marker used to distinguish if we're reading an EPEE-defined field OR if we're reading
  an entry within an section (object). This lets us collapse the definition of a section to an
  array of entries, simplifying decoding.
*/
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeOrEntry {
  // An epee-defined type
  Type(Type),
  // An entry (name, type, value)
  Entry,
}

impl Type {
  /// Read a type specification, including its length.
  pub fn read<'encoding>(reader: &mut impl BytesLike<'encoding>) -> Result<(Self, u64), EpeeError> {
    let kind = reader.read_byte()?;

    // Check if the array bit is set
    #[expect(clippy::as_conversions)]
    let array = kind & (Array::Array as u8);
    // Clear the array bit
    #[expect(clippy::as_conversions)]
    let kind = kind & (!(Array::Array as u8));

    let kind = match kind {
      1 => Type::Int64,
      2 => Type::Int32,
      3 => Type::Int16,
      4 => Type::Int8,
      5 => Type::Uint64,
      6 => Type::Uint32,
      7 => Type::Uint16,
      8 => Type::Uint8,
      9 => Type::Double,
      10 => Type::String,
      11 => Type::Bool,
      12 => Type::Object,
      _ => Err(EpeeError::UnrecognizedType)?,
    };

    // Flatten non-array values to an array of length one
    /*
      TODO: Will `epee` proper return an error if an array of length one is specified for a unit
      type? This wouldn't break our definition of compatibility yet should be revisited.
    */
    let len = if array != 0 { read_varint(reader)? } else { 1 };

    Ok((kind, len))
  }
}

/// Read a entry's key.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//   /contrib/epee/include/storages/portable_storage_from_bin.h#143-L152
fn read_key<'encoding, B: BytesLike<'encoding>>(
  reader: &mut B,
) -> Result<String<'encoding, B>, EpeeError> {
  let len = usize::from(reader.read_byte()?);
  if len == 0 {
    Err(EpeeError::EmptyKey)?;
  }
  let (len, bytes) = reader.read_bytes(len)?;
  Ok(String { len, bytes, _encoding: PhantomData })
}

/// The result from a single step of the decoder.
pub(crate) enum SingleStepResult<'encoding, B: BytesLike<'encoding>> {
  Object { fields: usize },
  Entry { key: String<'encoding, B>, kind: Type, len: usize },
  Unit,
}

impl Stack {
  /// Execute a single step of the decoding algorithm.
  ///
  /// Returns `Some((key, kind, len))` if an entry was read, or `None` otherwise. This also returns
  /// `None` if the stack is empty.
  pub(crate) fn single_step<'encoding, B: BytesLike<'encoding>>(
    &mut self,
    encoding: &mut B,
  ) -> Result<Option<SingleStepResult<'encoding, B>>, EpeeError> {
    let Some(kind) = self.pop() else {
      return Ok(None);
    };
    match kind {
      TypeOrEntry::Type(Type::Int64) => {
        encoding.advance::<{ core::mem::size_of::<i64>() }>()?;
      }
      TypeOrEntry::Type(Type::Int32) => {
        encoding.advance::<{ core::mem::size_of::<i32>() }>()?;
      }
      TypeOrEntry::Type(Type::Int16) => {
        encoding.advance::<{ core::mem::size_of::<i16>() }>()?;
      }
      TypeOrEntry::Type(Type::Int8) => {
        encoding.advance::<{ core::mem::size_of::<i8>() }>()?;
      }
      TypeOrEntry::Type(Type::Uint64) => {
        encoding.advance::<{ core::mem::size_of::<u64>() }>()?;
      }
      TypeOrEntry::Type(Type::Uint32) => {
        encoding.advance::<{ core::mem::size_of::<u32>() }>()?;
      }
      TypeOrEntry::Type(Type::Uint16) => {
        encoding.advance::<{ core::mem::size_of::<u16>() }>()?;
      }
      TypeOrEntry::Type(Type::Uint8) => {
        encoding.advance::<{ core::mem::size_of::<u8>() }>()?;
      }
      TypeOrEntry::Type(Type::Double) => {
        encoding.advance::<{ core::mem::size_of::<f64>() }>()?;
      }
      TypeOrEntry::Type(Type::String) => {
        read_str(encoding)?;
      }
      TypeOrEntry::Type(Type::Bool) => {
        encoding.advance::<{ core::mem::size_of::<bool>() }>()?;
      }
      TypeOrEntry::Type(Type::Object) => {
        let fields = read_varint(encoding)?;
        // Since the amount of fields exceeds our virtual address space, claim the encoding is
        // short
        let fields = usize::try_from(fields).map_err(|_| EpeeError::Short(usize::MAX))?;
        self.push(TypeOrEntry::Entry, fields)?;
        return Ok(Some(SingleStepResult::Object { fields }));
      }
      TypeOrEntry::Entry => {
        let key = read_key(encoding)?;
        let (kind, len) = Type::read(encoding)?;
        let len = usize::try_from(len).map_err(|_| EpeeError::Short(usize::MAX))?;
        self.push(TypeOrEntry::Type(kind), len)?;
        return Ok(Some(SingleStepResult::Entry { key, kind, len }));
      }
    }
    Ok(Some(SingleStepResult::Unit))
  }

  /// Step through the entirety of the next item.
  ///
  /// Returns `None` if the stack is empty.
  pub(crate) fn step<'encoding, B: BytesLike<'encoding>>(
    &mut self,
    encoding: &mut B,
  ) -> Result<Option<()>, EpeeError> {
    let Some((_kind, len)) = self.peek() else { return Ok(None) };

    let current_stack_depth = self.depth();
    // Read until the next item within this array
    let stop_at_stack_depth = if len.get() > 1 {
      current_stack_depth
    } else {
      // Read until we've popped this item entirely
      // We could peek at an item on the stack, therefore it has an item
      current_stack_depth - 1
    };

    while {
      self.single_step(encoding)?;
      self.depth() != stop_at_stack_depth
    } {}

    Ok(Some(()))
  }
}
