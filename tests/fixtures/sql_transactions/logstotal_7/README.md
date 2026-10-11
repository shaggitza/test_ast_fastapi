# LogsTotal pull request 7 source fixture

This fixture contains complete upstream `app/` and `tests/` files from the
baseline and merged target snapshots, plus the exact changed-file patch stored
as base64 so upstream blank lines and trailing spaces remain byte-exact while
the repository whitespace check stays useful. It is
source-only: tests are not imported or run, and no upstream package is installed
or executed. `LICENSE.txt` preserves the MIT license and copyright notice.

`expected-static-labels-before-prediction.json` records handwritten physical
call spans and conditional source-level labels from the full helper source and
available route/database context. It was frozen before the analyzer probe; its
SHA-256 is recorded in `provenance.json`. A one-character Git blob ID typo in
one flush span was corrected before the probe produced output. Labels are
source observations, not independently adjudicated truth.

The changed helpers move `db.add(...)` inside `db.begin_nested()` and then call
`db.flush()`. Their `db` parameters are unannotated, there is no selected outer
commit call, and the locked analysis interpreter lacks SQLAlchemy. Therefore
this fixture does not assert typed SQL evidence, successful runtime behavior,
commit reachability, or durability. The route's `AsyncSession` annotation does
not establish a type for the helper parameter. The source is not a complete
project snapshot.
