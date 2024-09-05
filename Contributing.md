# Contributing

All contributions to monero-oxide are done with pull requests. This project
has a series of established regulations regarding contributed code, as follows:

1) All code contributed must be your own work as an individual, or legally
   licensed and appropriately attributed. Contributions generated via large
   data-sets without full licensing and attribution of the underlying data
   points is not allowed.

2) The CI must pass, including `+nightly fmt`, `+nightly clippy`, and the full
   test suite.

3) Panics must be minimized and explicitly documented when allowed to occur.

4) The priorities of the code are safety first and foremost, propriety second,
   clarity third, and having parity with Monero regarding organization/naming
   fourth. The lack of parity with Monero may impact clarity yet is not itself
   inherently an issue.
