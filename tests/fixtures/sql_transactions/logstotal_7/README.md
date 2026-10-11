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
one flush span was corrected before the probe produced output. Its original
"independent adjudication pending" wording records the status at freeze time;
the file remains byte-for-byte unchanged to preserve that chronology.

The later independent R7 review checked all 18 physical spans against the
complete frozen files and independently confirmed the lexical movement of
`db.add(...)` into each helper's `db.begin_nested()` body, followed by
`db.flush()`. The separate `independent-source-adjudication-r7.json` pins the
review report, candidate commit, source snapshots, provenance, and frozen-label
hash. This adjudication covers source spans and lexical placement only. It does
not establish typed SQLAlchemy applicability, mapper output, endpoint
reachability, context exit, successful SQL execution, commit reachability, or
durability.

The changed helpers move `db.add(...)` inside `db.begin_nested()` and then call
`db.flush()`. Their `db` parameters are unannotated, there is no selected outer
commit call, and the locked analysis interpreter lacks SQLAlchemy. Therefore
this fixture does not assert typed SQL evidence, successful runtime behavior,
commit reachability, or durability. The route's `AsyncSession` annotation does
not establish a type for the helper parameter. The source is not a complete
project snapshot. The recorded one-byte overage of the strict 2 MiB metadata
attempt and the full/reduced mapper probe outcomes remain disclosed in the
provenance and adjudication records; neither is converted to a positive or
negative analyzer result.
