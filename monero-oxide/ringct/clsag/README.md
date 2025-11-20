# Monero CLSAG

The CLSAG linkable ring signature, as defined by the Monero protocol.
Additionally included is an implementation of
[FROSTLASS](
  https://github.com/monero-oxide/monero-oxide/tree/main/audits/FROSTLASS
), a FROST-inspired threshold multisignature algorithm with identifiable
aborts.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives (expansions of) generators
  at compile-time so they don't need to be derived at runtime. This is
  recommended if program size doesn't need to be kept minimal.
- `multisig`: Provides a FROST-inspired threshold multisignature algorithm for
  use. This functionality is not covered by SemVer, except along minor
  versions.
