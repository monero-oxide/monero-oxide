//! IO primitives around bytes.

use core::marker::PhantomData;

use crate::EpeeError;

/// An item which is like a `&[u8]`.
pub trait BytesLike<'encoding>: Sized {
  /// The type representing the length of a _read_ `BytesLike`, if a `BytesLike` does not
  /// inherently know its length.
  ///
  /// This should be `usize` or `()`.
  type ExternallyTrackedLength: Sized + Copy;

  /// The length of these bytes.
  fn len(&self, len: Self::ExternallyTrackedLength) -> usize;

  /// Read a fixed amount of bytes from the container.
  ///
  /// This MUST return `Ok((len, slice))` where `slice` is the expected length or `Err(_)`.
  fn read_bytes(
    &mut self,
    bytes: usize,
  ) -> Result<(Self::ExternallyTrackedLength, Self), EpeeError>;

  /// Read a fixed amount of bytes from the container into a slice.
  /*
    We _could_ provide this method around `read_bytes` but it'd be a very inefficient
    default implementation. It's best to require callers provide the implementation.
  */
  fn read_into_slice(&mut self, slice: &mut [u8]) -> Result<(), EpeeError>;

  /// Read a byte from the container.
  #[inline(always)]
  fn read_byte(&mut self) -> Result<u8, EpeeError> {
    let mut buf = [0; 1];
    self.read_into_slice(&mut buf)?;
    Ok(buf[0])
  }

  /// Advance the container by a certain amount of bytes.
  #[inline(always)]
  fn advance<const N: usize>(&mut self) -> Result<(), EpeeError> {
    self.read_bytes(N).map(|_| ())
  }
}

impl<'encoding> BytesLike<'encoding> for &'encoding [u8] {
  type ExternallyTrackedLength = ();

  #[inline(always)]
  fn len(&self, (): ()) -> usize {
    <[u8]>::len(self)
  }

  #[inline(always)]
  fn read_bytes(
    &mut self,
    bytes: usize,
  ) -> Result<(Self::ExternallyTrackedLength, Self), EpeeError> {
    if self.len() < bytes {
      Err(EpeeError::Short(bytes))?;
    }
    let res = &self[.. bytes];
    *self = &self[bytes ..];
    Ok(((), res))
  }

  #[inline(always)]
  fn read_into_slice(&mut self, slice: &mut [u8]) -> Result<(), EpeeError> {
    /*
      Ideally, we could return a immutable slice here as to avoid allocating the destination (even
      if on the stack) and copying into it. That's only possible as this is itself a slice however,
      so we can return a subslice. Allowing distinct containers does effectively require this
      pattern. Thankfully, we only call this method for a max of just eight bytes.
    */
    slice.copy_from_slice(self.read_bytes(slice.len())?.1);
    Ok(())
  }
}

/// Read a VarInt per EPEE's definition.
///
/// This does not require the VarInt is canonically encoded. It _may_ be malleated to have a larger
/// than necessary encoding.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//   /contrib/epee/include/storages/portable_storage_from_bin.h#L237-L255
pub(crate) fn read_varint<'encoding>(
  reader: &mut impl BytesLike<'encoding>,
) -> Result<u64, EpeeError> {
  let vi_start = reader.read_byte()?;

  // https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
  //  /contrib/epee/include/storages/portable_storage_base.h#L41
  let len = match vi_start & 0b11 {
    0 => 1,
    1 => 2,
    2 => 4,
    3 => 8,
    _ => unreachable!(),
  };

  let mut vi = u64::from(vi_start);
  for i in 1 .. len {
    vi |= u64::from(reader.read_byte()?) << (i * 8);
  }
  vi >>= 2;

  Ok(vi)
}

/// A collection of bytes with an associated length.
///
/// This avoids defining `BytesLike::len` which lets us relax the requirement `BytesLike` knows its
/// length before it has reached its end.
pub struct String<'encoding, B: BytesLike<'encoding>> {
  pub(crate) len: B::ExternallyTrackedLength,
  pub(crate) bytes: B,
  pub(crate) _encoding: PhantomData<&'encoding ()>,
}

impl<'encoding, B: BytesLike<'encoding>> String<'encoding, B> {
  /// If this string is empty.
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.bytes.len(self.len) == 0
  }

  /// The length of this string.
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.bytes.len(self.len)
  }

  /// Consume this into its underlying bytes.
  #[inline(always)]
  pub fn consume(self) -> B {
    self.bytes
  }
}

/// Read a string per EPEE's definition.
#[inline(always)]
pub(crate) fn read_str<'encoding, B: BytesLike<'encoding>>(
  reader: &mut B,
) -> Result<String<'encoding, B>, EpeeError> {
  /*
    Since this VarInt exceeds `usize::MAX`, it references more bytes than our system can represent
    within a single slice. Accordingly, our slice _must_ be short. As we potentially can't
    represent how short, we simply use `usize::MAX` here.
  */
  let len = usize::try_from(read_varint(reader)?).map_err(|_| EpeeError::Short(usize::MAX))?;
  let (len, bytes) = reader.read_bytes(len)?;
  Ok(String { len, bytes, _encoding: PhantomData })
}
