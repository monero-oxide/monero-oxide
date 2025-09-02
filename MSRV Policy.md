# MSRV Policy

monero-oxide officially tracks the latest stable Rust version there's merit to
track. Where possible, `std-shims` (primarily used to provide alternatives to
members of `std` on `no-std` environments) may provide polyfills so
monero-oxide may use modern features without actually bumping its MSRV.

Any polyfills provided by `std-shims` are not recommended for usage. They will
presumably be much more inefficient and will receive a fraction of the testing.
Only the targeted Rust version is officially supported.
