# monero-oxide Governance

The monero-oxide project is governed by two administrators, `kayabaNerve`
(`@kayabaNerve:monero.social`) and `boog900` (`@boog900:monero.social`). Upon
their disagreement, `j-berman` serves as tie-breaker regarding decisions. The
tie-breaker may also serve in-place of where an administrator is needed, yet
should only do so if the administrators are in extended disagreement or one
administrator has become unavailable for a non-trivial amount of time.

The Code of Conduct, Contributing guide, Security policy, and Governance rules
(collectively the "governance documents") are to be followed at all times.

All changes to the project, including its governance, are to be done via pull
requests.

## Place of Discussion

monero-oxide discussions are to be held in `#cuprate:monero.social` pending
the creation of a channel for monero-oxide itself.

## Governance Changes

Changes to the governance documents are to be agreed upon by both
administrators. Changes to the Code of Conduct and Governance rules must only
be merged after an open comment period by the community.

## Feature Additions

New features are to be agreed upon by both administrators. The PR implementing
them is to be reviewed in the same fashion.

## Bug Fixes and Documentation

Bug fixes and documentation only require a single administrator to perform the
PR review.

## Releases

Cut releases must be agreed upon by both administrators and follow
[Rust's definition of SemVer](https://doc.rust-lang.org/cargo/reference/semver.html).
Any major version release must have one-year support target. The only allowed
exceptions to this rule are:
- If a Monero hard-fork (or other such significant change) mandates it
- If a critical issue is found which can only be properly resolved with a new
  major version
