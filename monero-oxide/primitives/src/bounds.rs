/*
  These structs exist just to consolidate documentation. We define these bounds in several places
  and copying these docstrings would be very annoying.
*/

/// A `const`-context variant of the `max` function.
///
/// This is hidden as it's not to be considered part of our API commitment and is not guaranteed to
/// be available/usable. It's implemented as a macro to work with any type, as we can't express an
/// `Ord` bound within a `const` context.
#[doc(hidden)]
#[macro_export]
macro_rules! const_max {
  ($a: expr, $b: expr) => {
    if $a > $b {
      $a
    } else {
      $b
    }
  };
}

/// A `const`-context variant of the `min` function.
///
/// This is hidden as it's not to be considered part of our API commitment and is not guaranteed to
/// be available/usable. It's implemented as a macro to work with any type, as we can't express an
/// `Ord` bound within a `const` context.
#[doc(hidden)]
#[macro_export]
macro_rules! const_min {
  ($a: expr, $b: expr) => {
    if $a < $b {
      $a
    } else {
      $b
    }
  };
}

/// An upper bound for a value.
///
/// This is not guaranteed to be the minimal upper bound, solely a correct bound. This is not
/// guaranteed to be a bound stable throughout the lifetime of the entire Monero protocol, solely
/// as of the targeted version of the Monero protocol. It is intended to be used for size hints.
/// Changes to this value, whether decreasing it to be closer to the actual bound or increasing it
/// in response to a new version of the protocol, will not be considered breaking changes under
/// SemVer.
pub struct UpperBound<U>(pub U);

/// A lower bound for a value.
///
/// This is not guaranteed to be the maximal lower bound, solely a correct bound (meaning `0` would
/// always be acceptable). This is not guaranteed to be a bound stable throughout the lifetime of
/// the entire Monero protocol, solely as of the targeted version of the Monero protocol. It is
/// intended to be used for size hints. Changes to this value, whether increasing it to be closer
/// to the actual bound or decreasing it in response to a new version of the protocol, will not be
/// considered breaking changes under SemVer.
pub struct LowerBound<U>(pub U);
