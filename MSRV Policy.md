# MSRV Policy

monero-oxide tracks the latest stable Rust version. monero-oxide _may_ adopt
a soft-MSRV where [`msrv-shims`](https::/crates.io/crates/msrv-shims) is used
for all `std` objects introduced after a certain version. This would enable
downstream consumers to patch `msrv-shims` with the necessary set of polyfills
to achieve a certain MSRV.
