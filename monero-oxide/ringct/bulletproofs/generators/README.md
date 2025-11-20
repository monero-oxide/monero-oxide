# Monero Bulletproofs(+) Generators

Generators used by Monero to instantiate Bulletproofs(+). This is an internal
crate not covered by semver or any guarantees, with no public API.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
