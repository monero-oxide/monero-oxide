# Monero Ed25519

Ed25519 functionality, as within the Monero protocol.

This library primarily serves to allow our API to not bind to any specific
elliptic curve implementation, allowing us to upgrade/replace it without
breaking SemVer.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
