# Discrete Logarithm Proofs Premised on Elliptic Curve Divisors

In 2022, Liam Eagen published the idea of using
[elliptic curve divisors to efficiently prove discrete logarithms within zero-knowledge proofs](
  https://eprint.iacr.org/2022/596
).

The [FCMP++ paper](https://github.com/kayabaNerve/fcmp-plus-plus-paper)
detailed an R1CS gadget on this premise, later excerpted to (and unmaintained
as) a [standalone paper](
  https://github.com/kayabaNerve/fcmp-plus-plus-paper/tree/divisor-paper
).

The Monero project solicited Veridise to write security proofs, producing the
following list of papers.
- https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=229&list=1&highlight=1
- https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=241&list=1&highlight=1
- https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=259&list=1&highlight=1

Cypher Stack was contracted to review the first document, assigning Aaron
Feickert, producing [the following review](
  https://github.com/cypherstack/divisor-report/releases/tag/final
). This led to the solicitation of Veridise's second document.

Cypher Stack was continued to be contracted for review, assigning different
people moving forward due to Aaron Feickert moving to a new position with
another company.

Veridise's second document was reviewed [here](
  https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=258&list=1&highlight=1
). Cypher Stack was not convinced at the time, but found the results possible
and agreed to move forward.

Cypher Stack's third review is available [here](
  https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=268&list=1&highlight=1
), with Cypher Stack unable to independently affirm Veridise's security proofs
at the time.

Around this time, the [eVRF paper](https://eprint.iacr.org/2024/397) was
updated to include a section on implementing an eVRF premised on divisors. The
eVRF paper cited Veridise's first document, and the 'standalone paper', while
independently presenting the background.

Cypher Stack proceeded to develop their own paper on using divisors to
efficiently prove discrete logarithms,
[SLVer Bullet](https://eprint.iacr.org/2025/1345).

Later, [Cypher Stack believed SLVer Bullet's equations (of independent
derivation and methodology) equivalent to Veridise's](
  https://github.com/monero-project/meta/issues/1244
), effectively serving as an independent proof of security for Veridise's
protocol. As Veridise's protocol was implemented, and both parties agreed we
could move forward with it, it is the version implemented within
`generalized-bulletproofs-ec-gadgets`. For the audit of the implementation of
the circuit by Veridise, please see [here](../generalized-bulletproofs).

Additionally, [zkSecurity published a review](
  https://blog.zksecurity.xyz/posts/divisor-notes/divisor-techniques.pdf
). It notes that the check the divisor is non-zero, here via fixing the
coefficient for `x` to be `1`, is incomplete as some divisors may have the
relevant coefficient be `0`. While unlikely, sampling masks _MUST_ be followed
by checking they have a divisor associated. In following discussions with
Matthias Hall-Andersen, it was also noted how our representations of discrete
logarithms are malleable and how even if the divisor yielded by our prover
isn't usable, there may still be a usable divisor for a malleated, congruent
discrete logarithm. We do not adopt their idea of using an inner-product due to
how late in the process it was suggested and due to how the divisors we're
incomplete for should be negligible, only possibly preventing certain
rerandomizations from use (never certain outputs).

In order to produce the witness, the `ec-divisors` library is used by
_the prover only_. A straightforward implementation was originally done by
kayabaNerve, though it was quite slow, leading the Monero project to
[sponsor a competition](
  https://github.com/j-berman/fcmp-plus-plus-optimization-competition
) for an efficient implementation. The winner premised their work on
[Barycentric Lagrange Interpolation](
  https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
). This library has not undergone any audits at this time.
