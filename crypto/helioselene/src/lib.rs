#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

use core::hint::black_box;

use zeroize::Zeroize as _;

pub use group;

pub(crate) fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  let res = black_box(u8::from(bit));
  bit.zeroize();
  debug_assert_eq!((res | 1), 1);

  bit_ref.zeroize();
  res
}

pub use dalek_ff_group::FieldElement as Field25519;

mod field;
pub use field::HelioseleneField;

mod point;
pub use point::{HeliosPoint, SelenePoint};

mod ciphersuite;
pub use crate::ciphersuite::*;
