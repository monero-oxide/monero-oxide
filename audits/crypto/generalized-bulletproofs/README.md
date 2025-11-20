# Generalized Bulletproofs

Generalized Bulletproofs is an extension of
[Bulletproofs](https://eprint.iacr.org/2017/1066)'s R1CS arithmetic circuit
proof. While the original proving system allowed opening Pedersen Commitments,
Generalized Bulletproofs supports committing within and opening Pedersen Vector
Commitments. The scheme was proposed for the
[Curve Trees](https://eprint.iacr.org/2022/756) paper (albeit omitted from the
paper itself), and initially detailed [here](
  https://github.com/simonkamp/curve-trees/blob/01c800559b5634109fbec2faa9c51ebf8650eb7f/bulletproofs/generalized-bulletproofs.md
).

Cypher Stack was contracted to provide security proofs, assigning Aaron
Feickert, who noticed an inaccuracy in the Generalized Bulletproofs proposal.
The proposed proof would supposedly prove knowledge of the vector commitments'
openings over the `G` vector of generators used by the Bulletproof. In reality,
the prover was able to prove knowledge of an opening over the `G` _and_ `H`
vectors of generators used by the Bulletproof.

While this adjustment was fine, it should be noted a tweak to the prover was
necessary for completeness. Either:
- The `T` polynomial required roughly double the degree
- The prover must only use the `G` vector of generators, despite proving
  knowledge of an opening over the `G` _and_ `H` vectors of generators

This repository initially preferred the first solution, resulting in
[these proofs](<./Security Proofs.pdf>). The proofs were then
[reviewed by Brandon Goodell](
  https://repo.getmonero.org/-/project/54/uploads/b2d5c8198f55d72b588f1ef138126850/GBP_Security_Review.pdf
).

Later, it was realized the latter choice was the more efficient option (despite
the gap between the statements the prover can successfully prove and the
statement proved to the verifier), and the implementation moved to the second
option. Aaron Goodell was contracted via Cypher Stack to perform the audit of
the implementation, yielding [this audit](./Audit.pdf), yet also
[updated security proofs](<./Updated Security Proofs.pdf>).

For provenance, please see the following links.
- https://github.com/cypherstack/generalized-bulletproofs/releases
- https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/449#note_27508
- https://github.com/cypherstack/generalized-bulletproofs-code/releases
