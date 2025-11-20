#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

mod scalar;
pub use scalar::Scalar;
mod unreduced_scalar;
pub use unreduced_scalar::UnreducedScalar;

mod point;
pub use point::Point;
mod compressed_point;
pub use compressed_point::CompressedPoint;

mod commitment;
pub use commitment::Commitment;
