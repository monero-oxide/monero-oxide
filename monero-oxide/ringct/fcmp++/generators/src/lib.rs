#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{sync::LazyLock, vec::Vec, string::String, alloc::format};

use group::{prime::PrimeGroup, GroupEncoding};
use helioselene::{HeliosPoint, SelenePoint, Helios, Selene};

use monero_primitives::keccak256;
use monero_ed25519::{CompressedPoint, Point};

/// FCMP++s's key-image generator blinding generator `U`.
pub static FCMP_PLUS_PLUS_U: LazyLock<Point> = LazyLock::new(|| {
  CompressedPoint::from([
    138, 148, 142, 40, 84, 7, 58, 160, 188, 184, 47, 134, 60, 128, 134, 91, 92, 201, 190, 23, 151,
    35, 252, 28, 191, 28, 37, 184, 133, 89, 126, 84,
  ])
  .decompress()
  .expect("Failed to de-compress Monero FCMP++ Generator U")
});

/// FCMP++s's randomness commitment generator `V`.
pub static FCMP_PLUS_PLUS_V: LazyLock<Point> = LazyLock::new(|| {
  CompressedPoint::from([
    26, 66, 53, 9, 247, 103, 94, 145, 32, 17, 209, 75, 86, 16, 168, 87, 221, 213, 136, 115, 52, 19,
    181, 21, 224, 3, 188, 64, 85, 133, 91, 241,
  ])
  .decompress()
  .expect("Failed to de-compress Monero FCMP++ Generator V")
});

/// The maximum amount of input tuples provable for within a single FCMP.
// https://github.com/seraphis-migration/monero
//  /blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L217
pub const MAX_FCMP_INPUTS: usize = 128;
/// The maximum amount of layers supported within a FCMP.
///
/// The FCMP itself theoretically supports an unbounded amount of layers, with exponential growth
/// in set size as additional layers are added. The size of the proof (for each input) still grows
/// linearly with the amount of layers, requiring a sufficiently-large constant reference string.
/// This constant is used to generate the constant reference string, and it's that which bounds the
/// amount of layers supported.
///
/// Theoretically, the generators could be dynamically built/extended at runtime to remove this
/// limit, yet this offers such a large set size it will never be reached.
// https://github.com/seraphis-migration/monero
//  /blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L222
pub const MAX_FCMP_LAYERS: usize = 12;

// Sample a uniform non-identity on-curve point via rejection sampling.
//
// This is intended for generating constants and is fine to require many iterations accordingly.
fn rejection_sampling_hash_to_curve<G: PrimeGroup + GroupEncoding<Repr = [u8; 32]>>(
  buf: &[u8],
) -> G {
  let mut buf = keccak256(buf);
  loop {
    // Check this is a valid point
    if let Some(point) = Option::<G>::from(G::from_bytes(&buf)) {
      // Check the point is canonically encoded, which `from_bytes` doesn't guarantee, and not the
      // identity point
      if (point.to_bytes() == buf) && (!bool::from(point.is_identity())) {
        return point;
      }
    }
    buf = keccak256(buf);
  }
}

/// The hash-initialization generator for Helios hashes.
pub static HELIOS_HASH_INIT: LazyLock<HeliosPoint> = LazyLock::new(|| {
  rejection_sampling_hash_to_curve::<HeliosPoint>(b"Monero Helios Hash Initializer")
});

/// The hash-initialization generator for Selene hashes.
pub static SELENE_HASH_INIT: LazyLock<SelenePoint> = LazyLock::new(|| {
  rejection_sampling_hash_to_curve::<SelenePoint>(b"Monero Selene Hash Initializer")
});

const FCMP_GENERATORS: (usize, usize) =
  full_chain_membership_proofs::Fcmp::<()>::ipa_rows(MAX_FCMP_INPUTS, MAX_FCMP_LAYERS);
const FCMP_SELENE_GENERATORS: usize = FCMP_GENERATORS.0;
const FCMP_HELIOS_GENERATORS: usize = FCMP_GENERATORS.1;

/// Container struct for FCMP generators.
pub struct FcmpGenerators<C: ciphersuite::Ciphersuite> {
  /// The underlying generators.
  pub generators: generalized_bulletproofs::Generators<C>,
}
impl<C: ciphersuite::Ciphersuite> FcmpGenerators<C>
where
  C::G: GroupEncoding<Repr = [u8; 32]>,
{
  fn id() -> String {
    String::from_utf8(C::ID.to_vec()).expect("Helios/Selene din't have a UTF-8 ID")
  }

  fn g_h(id: &str) -> (C::G, C::G) {
    (
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G").as_bytes()),
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H").as_bytes()),
    )
  }

  fn new_generator_pair(id: &str, i: usize) -> (C::G, C::G) {
    (
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G {i}").as_bytes()),
      rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H {i}").as_bytes()),
    )
  }

  fn new_internal_singlethreaded(generators: usize) -> Self {
    let id = Self::id();
    let (g, h) = Self::g_h(&id);
    let mut g_bold = Vec::with_capacity(generators);
    let mut h_bold = Vec::with_capacity(generators);
    for i in 0 .. generators {
      let (g_bold_i, h_bold_i) = Self::new_generator_pair(&id, i);
      g_bold.push(g_bold_i);
      h_bold.push(h_bold_i);
    }
    Self {
      generators: generalized_bulletproofs::Generators::new(g, h, g_bold, h_bold)
        .expect("uniformly sampled points couldn't instantiate generators"),
    }
  }

  #[cfg(feature = "std")]
  fn new_internal_multithreaded(generators: usize) -> Option<Self> {
    let id = Self::id();
    let (g, h) = Self::g_h(&id);

    use std::thread;
    use group::Group as _;

    let threads = {
      let threads = thread::available_parallelism().ok()?;
      // Don't use more threads than generators
      let threads = usize::from(threads).min(generators);
      // Only use an amount of threads which are a power of two
      let next_power_of_two = threads.next_power_of_two();
      // If `threads` was already a power of two, return it as-is
      if threads == next_power_of_two {
        threads
      } else {
        // Return the largest power of two less than threads
        next_power_of_two / 2
      }
    };

    // This will be a perfect division as `threads` is a smaller or equal power of two than
    // `generators`
    let generators_per_thread = generators / threads;
    debug_assert_eq!(
      generators.next_power_of_two(),
      generators,
      "generators wasn't a power of two"
    );
    assert_eq!(
      generators_per_thread * threads,
      generators,
      "generating the wrong amount of generators"
    );

    let mut g_bold = vec![C::G::identity(); generators];
    let mut h_bold = vec![C::G::identity(); generators];
    thread::scope(|scope| {
      let mut g_bold_slice: &mut [_] = g_bold.as_mut();
      let mut h_bold_slice: &mut [_] = h_bold.as_mut();
      for i in 0 .. threads {
        let id = &id;
        let i = i * generators_per_thread;
        let local_g_bold_slice;
        (local_g_bold_slice, g_bold_slice) = g_bold_slice.split_at_mut(generators_per_thread);
        let local_h_bold_slice;
        (local_h_bold_slice, h_bold_slice) = h_bold_slice.split_at_mut(generators_per_thread);
        scope.spawn(move || {
          for j in 0 .. generators_per_thread {
            (local_g_bold_slice[j], local_h_bold_slice[j]) = Self::new_generator_pair(id, i + j);
          }
        });
      }
    });

    Some(Self {
      generators: generalized_bulletproofs::Generators::new(g, h, g_bold, h_bold)
        .expect("uniformly sampled points couldn't instantiate generators"),
    })
  }

  fn new_internal(generators: usize) -> Self {
    #[cfg(feature = "std")]
    let res = Self::new_internal_multithreaded(generators)
      .unwrap_or_else(|| Self::new_internal_singlethreaded(generators));
    #[cfg(not(feature = "std"))]
    let res = Self::new_internal_singlethreaded(generators);
    res
  }
}

impl FcmpGenerators<Helios> {
  /// Generate generators as needed for FCMPs.
  ///
  /// Consumers should not call this function ad-hoc, yet call it within a build script or use a
  /// once-initialized static.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self::new_internal(FCMP_HELIOS_GENERATORS)
  }
}

impl FcmpGenerators<Selene> {
  /// Generate generators as needed for FCMPs.
  ///
  /// Consumers should not call this function ad-hoc, yet call it within a build script or use a
  /// once-initialized static.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self::new_internal(FCMP_SELENE_GENERATORS)
  }
}

#[test]
fn single_and_multithreaded_generators() {
  use helioselene::Helios;
  use crate::{FCMP_HELIOS_GENERATORS, FcmpGenerators};

  let single = FcmpGenerators::<Helios>::new_internal_singlethreaded(FCMP_HELIOS_GENERATORS);
  let multi = FcmpGenerators::<Helios>::new_internal_multithreaded(FCMP_HELIOS_GENERATORS).unwrap();
  assert_eq!(single.generators.g(), multi.generators.g());
  assert_eq!(single.generators.h(), multi.generators.h());
  assert_eq!(single.generators.g_bold_slice(), multi.generators.g_bold_slice());
  assert_eq!(single.generators.h_bold_slice(), multi.generators.h_bold_slice());
}

#[test]
#[allow(non_snake_case)]
fn reproduce_U() {
  let reproduced_U = Point::hash(keccak256(b"Monero FCMP++ Generator U"));
  assert_eq!(*FCMP_PLUS_PLUS_U, reproduced_U);
}

#[test]
#[allow(non_snake_case)]
fn reproduce_V() {
  let reproduced_V = Point::hash(keccak256(b"Monero FCMP++ Generator V"));
  assert_eq!(*FCMP_PLUS_PLUS_V, reproduced_V);
}
