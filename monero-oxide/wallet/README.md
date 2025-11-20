# [monero-wallet](https://docs.rs/monero-wallet)

Wallet functionality for the Monero protocol, built around
[monero-oxide](https://docs.rs/monero-oxide). This library prides itself on
resolving common pitfalls developers may face.

`monero-wallet` also offers a FROST-inspired multisignature protocol orders of
magnitude more performant than Monero's own, formalized as
[FROSTLASS](../../audits/FROSTLASS/FROSTLASS.pdf).

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Features

- Scanning Monero transactions
- Sending Monero transactions
- Sending Monero transactions with a FROST-inspired threshold multisignature
  protocol, orders of magnitude more performant than Monero's own

### Caveats

This library DOES attempt to do the following:

- Create on-chain transactions identical to how wallet2 would (unless told not
  to)
- Not be detectable as `monero-wallet` when scanning outputs
- Not reveal spent outputs to the connected RPC node

This library DOES NOT attempt to do the following:

- Have identical RPC behavior when scanning outputs/creating transactions
- Be a wallet, maintaining state, performing output selection, and running in
  the background

This means that `monero-wallet` shouldn't be fingerprintable on-chain. It also
shouldn't be fingerprintable if a targeted attack occurs to detect if the
receiving wallet is `monero-wallet` or `wallet2`. It also should be generally
safe for usage with remote nodes, but may be detected as `monero-wallet` by a
remote node. The implications of this are left to the user to consider.

It also won't act as a wallet, just as a wallet-functionality library.
`wallet2` has several *non-transaction-level* policies, such as always
attempting to use two inputs to create transactions. These are considered out
of scope to `monero-wallet`.

Finally, this library only supports producing transactions with CLSAG
signatures. That means this library cannot spend non-RingCT outputs.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives the generators at
  compile-time so they don't need to be derived at runtime. This is recommended
  if program size doesn't need to be kept minimal.
- `multisig`: Adds support for creation of transactions using a threshold
  multisignature wallet represented by [`dkg`](https://docs.rs/dkg). This
  functionality is not covered by SemVer, except along minor versions.
