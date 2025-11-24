# Monero EPEE

`epee` is a bespoke library with various utilities, primarily seen today due to
its continued usage within the Monero project. Originating without
documentation, it contained a self-describing typed binary format referred to
as 'portable storage'. We refer to it as `epee`, after the library introducing
it, within this library and throughout our ecosystem. Thankfully, the
[Monero project now hosts a description](
  https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570/docs/PORTABLE_STORAGE.md
) which is sufficient to understand and implement it.

Our library has the following exceptions:
- We don't support the `Array` type (type 13) as it's unused in practice and
  lacking documentation. See
  [this PR](https://github.com/monero-project/monero/pull/10138) to Monero
  removing it entirely.
- We may accept a _wider_ class of inputs than the `epee` library itself. Our
  definition of compatibility is explicitly if we can decode anything encoded
  by the `epee` library _it itself will decode_ and all encodings we produce
  may be decoded by the `epee` library. We do not expect completeness, so some
  successfully decoded objects may not be able to be encoded, and vice versa.

At this time, we do not support:
- Encoding objects
- Decoding objects into typed data structures

Instead, we support indexing `epee`-encoded values and decoding individual
fields in a manner comparable to `serde_json::Value` (albeit without
allocating, recursing, or using a proc macro). This is sufficient for basic
needs, much simpler, and should be trivial to verify won't panic/face various
resource exhaustion attacks compared to more complex implementations.

Because of this, we are also able to support no-`std` and no-`alloc`, without
any dependencies other than `core`, while only consuming approximately one
kibibyte of memory on the stack.

For a more functional library, please check out
[`cuprate-epee-encoding`](
  https://github.com/cuprate/cuprate/tree/9c2c942d2fcf26ed8916dc3f9be6db43d8d2ae78/net/epee-encoding
).
