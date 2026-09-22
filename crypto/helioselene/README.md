# Helioselene

An Implementation of Helios and Selene, a curve cycle towering Ed25519.
Please refer to https://gist.github.com/tevador/4524c2092178df08996487d4e272b096
for documentation of these curves, and our
[`audits/` folder](
  https://github.com/monero-oxide/monero-oxide/tree/fcmp++/audits
).

### Lifetime of Secrets

If a secret (such as a private key) is represented as a scalar, it SHOULD be
handled with care in order to not leave copies littered around the program's
memory. The
`helioselene::{Field25519, HelioseleneField, HeliosPoint, SelenePoint}` types
support [`zeroize::Zeroize`], allowing callers to explicitly zero them out in
memory.

This library, internally, solely uses the stack for all variables _except_ when
performing IO operations. This means the lifetimes for all variables SHOULD be
limited to however long they're in use for, with the unfortunate
acknowledgement the compiler MAY not immediately clean up stack frames. This is
considered out of scope to `helioselene`, where the caller MAY make an effort
to handle this via [`zeroize::zeroize_stack`]. The handling of any variables
which cross an IO boundary are considered entirely out of scope to
`helioselene`.

`helioselene` MAY selectively zero out some intermediate variables at its
discretion, yet makes no guarantees to do so, and will not consider the lack of
inherent zeroization as a security issue.

### Bespoke Field Implementation

The Helios, Selene curves use the `2**255-19` finite field used by Ed25519,
along with a finite field over the prime
`0x7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df53`. The
mutual field, over `2**255-19`, has its implementation provided by
`dalek-ff-group`. The bespoke field has its implementation within this crate.

The implementation is technically premised on `crypto-bigint` yet implements
most arithmetic itself for performance reasons, such as the modular reduction
premised on how the modulus is a Crandall prime. Some functions within the
implementation of this field, as of commit
`27b1c7f2918444560c7383e7a5fbddb481dbf2d2`,
[were formally verified by Veridise](
  https://github.com/VeridiseAuditing/helioselene-dafny-proofs
). While their scope did include the formal verification of the library as a
whole, only the implementation of some functions was completed within the time
constraints. The exact functions used to implement the field which were marked
as formally verified have been isolated in the `src/field/verified` folder.
Note the caveat that a translation into Dafny was formally verified, not the
literal Rust as written.

The original formal verification noted a flaw in the implementation, which was
fixed with commit `00bafcf08e9f0bbe334e68b6d89ddbaccc292c6c`.
