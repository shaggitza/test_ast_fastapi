# GH103 frozen source metadata attempt v1 (historical)

This is a separate evidence layer for the exact 50 repositories and survey
commits frozen in v1 and v2. It never edits their manifests, checksum profiles,
PR lock, selection policy, partitions, truth, reviews, or ledger. Each repository
record binds its `survey_commit` to GitHub's commit response and tree SHA. Raw
metadata bytes are base64-encoded in JSON (non-executable storage); each file
also records its repository path, Git blob object SHA-1, SHA-256, and byte size.

The collector fetches only `https://api.github.com` commit, recursive tree, and
blob endpoints. Redirects fail closed. Credentials, when `GITHUB_TOKEN` is set,
are sent only to the fixed API origin. Bounds are 500 requests, 32 MiB returned
bytes, 600 response/file fetches, 12 selected files per repository, 512 KiB per
source file, 2 MiB per repository, 900 seconds wall time, 15 seconds per
request, and two retries. Publication uses a hard-link no-clobber operation.
Statuses retain unavailable, truncated, malformed, and retrieved-but-unparsed
states. Absence from a complete recursive tree is not interpreted as proof that
a declaration never existed outside the selected metadata paths.

`pyproject.toml` declarative project fields are parsed with the standard TOML
parser. `setup.py` is parsed with Python AST and literal values only; it is
never imported or evaluated. `setup.cfg`, `tox.ini`, and workflow matrices are
retained as raw evidence and are not normalized by v1. Therefore no runtime
compatibility, installability, security, dependency resolution, or feasibility
is verified. A declared `requires-python`, package classifier, or test matrix is
only a declaration. Review of license and dependency evidence also remains a
human/legal and environment-specific decision. PR types remain unclassified;
no semantics, labels, impact, or truth were inferred.

This directory preserves the original v1 attempt and its exact failed retrieval
record. Its v1 status strings and hashes are historical observations, not
authenticated source evidence; use the strict v2 collector and validator in
`benchmarks/real_world/source_metadata_v2.py` for current evidence.

## Observed bounded run

Command: `python3 benchmarks/real_world/source_metadata_v1.py --collect
--output /tmp/gh103-source-metadata-attempt.json`. Collector source SHA-256 at
collection time: `7b489e63a7b91b171b8b743fef6e54889ac1c26fdd27eac37eebeb6e83a30ea8`.
The environment had no `GITHUB_TOKEN`. All 50 exact-commit requests returned
HTTP 403; 50 requests, 0 response bytes, and 17.527 seconds were observed. No
source bytes or license/dependency declarations were obtained. The committed
result preserves these explicit unavailable states and validates as 50/50
population coverage; it is not source evidence. Result SHA-256:
`b360bf14a6166cf338bf558c6ee96f7c2f065f016e04c7a2e58cc14a1f258762`.

The collector and validator are covered by synthetic offline fixtures. If
access fails, the command records per-repository unavailable status; no sources
are fabricated or carried forward from another revision.
