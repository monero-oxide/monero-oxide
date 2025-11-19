#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::marker::PhantomData;

mod io;
mod stack;
mod parser;

pub(crate) use io::*;
pub use io::{BytesLike, String};
pub(crate) use stack::*;
pub use parser::*;

/// An error incurred when decoding.
#[derive(Clone, Copy, Debug)]
pub enum EpeeError {
  /// An unexpected state was reached while decoding.
  InternalError,
  /// The blob did not have the expected header.
  InvalidHeader,
  /// The blob did not have the expected version.
  ///
  /// For `EpeeError::InvalidVersion(version)`, `version` is the version read from the blob.
  InvalidVersion(Option<u8>),
  /// The blob was short, as discovered when trying to read `{0}` bytes.
  Short(usize),
  /// Unrecognized type specified.
  UnrecognizedType,
  /// An object defined a key of `""`.
  EmptyKey,
  /// The depth limit was exceeded.
  DepthLimitExceeded,
  /// An operation expected one type yet the actual type was distinct.
  TypeError,
  /// An `Epee` object was reused.
  EpeeReuse,
}

/// The EPEE header.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L37-L38
pub const HEADER: [u8; 8] = *b"\x01\x11\x01\x01\x01\x01\x02\x01";
/// The supported version of the EPEE protocol.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L39
pub const VERSION: u8 = 1;

/// A decoder for an EPEE-encoded object.
pub struct Epee<'encoding, B: BytesLike<'encoding>> {
  current_encoding_state: B,
  stack: Stack,
  error: Option<EpeeError>,
  _encoding_lifetime: PhantomData<&'encoding ()>,
}
/// An item with an EPEE-encoded object.
pub struct EpeeEntry<'encoding, 'parent, B: BytesLike<'encoding>> {
  root: Option<&'parent mut Epee<'encoding, B>>,
  kind: Type,
  len: usize,
}

// When this entry is dropped, advance the decoder past it
impl<'encoding, 'parent, B: BytesLike<'encoding>> Drop for EpeeEntry<'encoding, 'parent, B> {
  #[inline(always)]
  fn drop(&mut self) {
    if let Some(root) = self.root.take() {
      while root.error.is_none() && (self.len != 0) {
        root.error = root.stack.step(&mut root.current_encoding_state).err();
        self.len -= 1;
      }
    }
  }
}

impl<'encoding, B: BytesLike<'encoding>> Epee<'encoding, B> {
  /// Create a new view of an encoding.
  pub fn new(mut encoding: B) -> Result<Self, EpeeError> {
    // Check the header
    {
      let mut present_header = [0; HEADER.len()];
      encoding.read_into_slice(&mut present_header)?;
      if present_header != HEADER {
        Err(EpeeError::InvalidHeader)?;
      }
    }

    // Check the version
    {
      let version = encoding.read_byte().ok();
      if version != Some(VERSION) {
        Err(EpeeError::InvalidVersion(version))?;
      }
    }

    Ok(Epee {
      current_encoding_state: encoding,
      stack: Stack::root_object(),
      error: None,
      _encoding_lifetime: PhantomData,
    })
  }

  /// Obtain an `EpeeEntry` representing the encoded object.
  ///
  /// This takes a mutable reference as `Epee` is the owned object representing the decoder's
  /// state. However, this is not eligible to be called again after consumption. Multiple calls to
  /// this function will cause an error to be returned.
  pub fn entry(&mut self) -> Result<EpeeEntry<'encoding, '_, B>, EpeeError> {
    if (self.stack.depth() != 1) || self.error.is_some() {
      Err(EpeeError::EpeeReuse)?;
    }
    Ok(EpeeEntry { root: Some(self), kind: Type::Object, len: 1 })
  }
}

/// An iterator over fields.
pub struct FieldIterator<'encoding, 'parent, B: BytesLike<'encoding>> {
  root: &'parent mut Epee<'encoding, B>,
  len: usize,
}

// When this object is dropped, advance the decoder past the unread items
impl<'encoding, 'parent, B: BytesLike<'encoding>> Drop for FieldIterator<'encoding, 'parent, B> {
  #[inline(always)]
  fn drop(&mut self) {
    while self.root.error.is_none() && (self.len != 0) {
      self.root.error = self.root.stack.step(&mut self.root.current_encoding_state).err();
      self.len -= 1;
    }
  }
}

impl<'encoding, 'parent, B: BytesLike<'encoding>> FieldIterator<'encoding, 'parent, B> {
  /// The next entry (key, value) within the object.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  ///
  /// [polonius-the-crab](https://docs.rs/polonius-the-crab) details a frequent limitation of
  /// Rust's borrow checker which users of this function may incur. It also details potential
  /// solutions (primarily using inlined code instead of functions, callbacks) before presenting
  /// itself as a complete solution. Please refer to it if you have difficulties calling this
  /// method for context.
  #[allow(clippy::type_complexity, clippy::should_implement_trait)]
  pub fn next(
    &mut self,
  ) -> Option<Result<(String<'encoding, B>, EpeeEntry<'encoding, '_, B>), EpeeError>> {
    if let Some(error) = self.root.error {
      return Some(Err(error));
    }

    self.len = self.len.checked_sub(1)?;
    let (key, kind, len) = match self.root.stack.single_step(&mut self.root.current_encoding_state)
    {
      Ok(Some(SingleStepResult::Entry { key, kind, len })) => (key, kind, len),
      // A `FieldIterator` was constructed incorrectly or some other internal error
      Ok(_) => return Some(Err(EpeeError::InternalError)),
      Err(e) => return Some(Err(e)),
    };

    Some(Ok((key, EpeeEntry { root: Some(self.root), kind, len })))
  }
}

/// An iterator over an array.
pub struct ArrayIterator<'encoding, 'parent, B: BytesLike<'encoding>> {
  root: &'parent mut Epee<'encoding, B>,
  kind: Type,
  len: usize,
}

// When this array is dropped, advance the decoder past the unread items
impl<'encoding, 'parent, B: BytesLike<'encoding>> Drop for ArrayIterator<'encoding, 'parent, B> {
  #[inline(always)]
  fn drop(&mut self) {
    while self.root.error.is_none() && (self.len != 0) {
      self.root.error = self.root.stack.step(&mut self.root.current_encoding_state).err();
      self.len -= 1;
    }
  }
}

impl<'encoding, 'parent, B: BytesLike<'encoding>> ArrayIterator<'encoding, 'parent, B> {
  /// The next item within the array.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  ///
  /// [polonius-the-crab](https://docs.rs/polonius-the-crab) details a frequent limitation of
  /// Rust's borrow checker which users of this function may incur. It also details potential
  /// solutions (primarily using inlined code instead of functions, callbacks) before presenting
  /// itself as a complete solution. Please refer to it if you have difficulties calling this
  /// method for context.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Option<Result<EpeeEntry<'encoding, '_, B>, EpeeError>> {
    if let Some(err) = self.root.error {
      return Some(Err(err));
    }

    self.len = self.len.checked_sub(1)?;
    Some(Ok(EpeeEntry { root: Some(self.root), kind: self.kind, len: 1 }))
  }
}

impl<'encoding, 'parent, B: BytesLike<'encoding>> EpeeEntry<'encoding, 'parent, B> {
  /// The type of object this entry represents.
  #[inline(always)]
  pub fn kind(&self) -> Type {
    self.kind
  }

  /// The amount of items present within this entry.
  #[allow(clippy::len_without_is_empty)]
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.len
  }

  /// Iterate over the fields within this object.
  pub fn fields(mut self) -> Result<FieldIterator<'encoding, 'parent, B>, EpeeError> {
    let root = self.root.take().ok_or(EpeeError::InternalError)?;

    if let Some(err) = root.error {
      Err(err)?;
    }

    if (self.kind != Type::Object) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    // Read past the `Type::Object` this was constructed with into `[Type::Entry; n]`
    let len = match root.stack.single_step(&mut root.current_encoding_state)? {
      Some(SingleStepResult::Object { fields }) => fields,
      _ => Err(EpeeError::InternalError)?,
    };
    Ok(FieldIterator { root, len })
  }

  /// Get an iterator of all items within this container.
  ///
  /// If you want to index a specific item, you may use `.iterate()?.nth(i)?`. An `index` method
  /// isn't provided as each index operation is of O(n) complexity and single indexes SHOULD NOT be
  /// used. Only exposing `iterate` attempts to make this clear to the user.
  pub fn iterate(mut self) -> Result<ArrayIterator<'encoding, 'parent, B>, EpeeError> {
    let root = self.root.take().ok_or(EpeeError::InternalError)?;

    if let Some(err) = root.error {
      Err(err)?;
    }

    Ok(ArrayIterator { root, kind: self.kind, len: self.len })
  }

  #[allow(clippy::wrong_self_convention)]
  #[inline(always)]
  fn to_primitive(mut self, kind: Type, slice: &mut [u8]) -> Result<&mut [u8], EpeeError> {
    if (self.kind != kind) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let root = self.root.take().ok_or(EpeeError::InternalError)?;
    if let Some(error) = root.error {
      Err(error)?;
    }
    root.stack.pop();
    root.current_encoding_state.read_into_slice(slice)?;
    Ok(slice)
  }

  /// Get the current item as an `i64`.
  #[inline(always)]
  pub fn to_i64(self) -> Result<i64, EpeeError> {
    let mut buf = [0; core::mem::size_of::<i64>()];
    Ok(i64::from_le_bytes(self.to_primitive(Type::Int64, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as an `i32`.
  #[inline(always)]
  pub fn to_i32(self) -> Result<i32, EpeeError> {
    let mut buf = [0; core::mem::size_of::<i32>()];
    Ok(i32::from_le_bytes(self.to_primitive(Type::Int32, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as an `i16`.
  #[inline(always)]
  pub fn to_i16(self) -> Result<i16, EpeeError> {
    let mut buf = [0; core::mem::size_of::<i16>()];
    Ok(i16::from_le_bytes(self.to_primitive(Type::Int16, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as an `i8`.
  #[inline(always)]
  pub fn to_i8(self) -> Result<i8, EpeeError> {
    let mut buf = [0; core::mem::size_of::<i8>()];
    Ok(i8::from_le_bytes(self.to_primitive(Type::Int8, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as a `u64`.
  #[inline(always)]
  pub fn to_u64(self) -> Result<u64, EpeeError> {
    let mut buf = [0; core::mem::size_of::<u64>()];
    Ok(u64::from_le_bytes(self.to_primitive(Type::Uint64, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as a `u32`.
  #[inline(always)]
  pub fn to_u32(self) -> Result<u32, EpeeError> {
    let mut buf = [0; core::mem::size_of::<u32>()];
    Ok(u32::from_le_bytes(self.to_primitive(Type::Uint32, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as a `u16`.
  #[inline(always)]
  pub fn to_u16(self) -> Result<u16, EpeeError> {
    let mut buf = [0; core::mem::size_of::<u16>()];
    Ok(u16::from_le_bytes(self.to_primitive(Type::Uint16, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as a `u8`.
  #[inline(always)]
  pub fn to_u8(self) -> Result<u8, EpeeError> {
    let mut buf = [0; core::mem::size_of::<u8>()];
    Ok(self.to_primitive(Type::Uint8, &mut buf)?[0])
  }

  /// Get the current item as an `f64`.
  #[inline(always)]
  pub fn to_f64(self) -> Result<f64, EpeeError> {
    let mut buf = [0; core::mem::size_of::<f64>()];
    Ok(f64::from_le_bytes(self.to_primitive(Type::Double, &mut buf)?.try_into().unwrap()))
  }

  /// Get the current item as a 'string' (represented as a `B`).
  #[inline(always)]
  pub fn to_str(mut self) -> Result<String<'encoding, B>, EpeeError> {
    if (self.kind != Type::String) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let root = self.root.take().ok_or(EpeeError::InternalError)?;
    if let Some(error) = root.error {
      Err(error)?;
    }
    root.stack.pop();
    read_str(&mut root.current_encoding_state)
  }

  /// Get the current item as a 'string' (represented as a `B`) of a specific length.
  ///
  /// This will error if the result is not actually the expected length.
  #[inline(always)]
  pub fn to_fixed_len_str(self, len: usize) -> Result<String<'encoding, B>, EpeeError> {
    let str = self.to_str()?;
    if str.len() != len {
      Err(EpeeError::TypeError)?;
    }
    Ok(str)
  }

  /// Get the current item as a `bool`.
  #[inline(always)]
  pub fn to_bool(self) -> Result<bool, EpeeError> {
    let mut buf = [0; core::mem::size_of::<bool>()];
    Ok(self.to_primitive(Type::Bool, &mut buf)?[0] != 0)
  }
}
