# Monero Interface

`monero-interface` provides two sets of traits for interfacing with the Monero
network.

1) `Unvalidated*`: Traits representing data from an arbitrary source, with
   minimal validation if any.
2) `Validated*`: Traits representing data from a (potentially trusted) source
   which certain guarantees on the structure, sanity of the returned results.

Neither set of traits promise the returned data is completely accurate and up
to date. Using an untrusted interface, even if the results are validated as
sane, may _always_ inject invalid data unless the caller locally behaves as a
full node, applying all consensus rules, and is able to detect if they are not
on the best chain. Please carefully consider the exact promises made and how
that relates to your security model.

Additionally, interfaces presumably learn the pattern of your requests (due to
responding to your requests), which may reveal information to the interface.
Callers SHOULD NOT make any requests specific to their wallet which will not
eventually end up as on-chain information, and callers SHOULD even be careful
with _when_ they make requests, as discussed in
[Remote Side-Channel Attacks on Anonymous Transactions](
  https://eprint.iacr.org/2020/220
).

This library is usable under no-`std`, with `alloc`, when the `std` feature (on
by default) is disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
