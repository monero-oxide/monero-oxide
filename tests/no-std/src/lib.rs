#![expect(missing_docs)]
#![no_std]

pub use monero_epee;

#[cfg(feature = "alloc")]
pub mod alloc {
  pub use monero_wallet;
  pub use monero_daemon_rpc;
}
