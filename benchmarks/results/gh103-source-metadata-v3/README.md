# GH103 frozen source metadata evidence v3

V3 uses the exact 50 repositories and `survey_commit` SHAs frozen by the
independently profiled v1/v2 manifests. It preserves the historical v1 and v2
results. No frozen manifest, lock, checksum profile, selection policy,
partition, truth, review, or ledger is changed.

Only fixed-origin HTTPS GitHub REST commit, recursive tree, and blob endpoints
are requested. `GITHUB_TOKEN` is preferred; otherwise `gh auth token --hostname
github.com` supplies an existing profile token directly into process memory.
Tokens are never written to output, logs, subprocess arguments other than the
CLI retrieval itself, or non-GitHub hosts. Requests never follow redirects.

Commit and complete tree response bytes are stored with URL, size, and SHA-256.
The validator checks the commit response against the frozen survey SHA, checks
the commit-to-tree link, recomputes the root and every nested Git tree SHA from
the recursive tree listing, checks each source path and blob SHA against that
tree, verifies Git blob SHA-1 and source SHA-256, and recomputes every parsed
metadata record from the retained source bytes. Request attempts, statuses,
returned byte counts, retry counts, endpoint containment, and aggregate limits
are validated. GitHub over TLS is an external trusted authority for commit
identity; this record does not claim an independent cryptographic signature.

V3 bounds collection to 1,200 requests and objects, 128 MiB response bytes,
900 seconds wall time, 15 seconds per request, two retries, 24 files and 6 MiB
per repository, 512 KiB per source file, and 192 MiB result size. Recursive
trees explicitly marked truncated, response caps, redirects, exhausted budgets,
metadata file caps, and per-file failures remain unavailable, truncated, or
incomplete; none is converted into “not declared.” File selection prioritizes
package metadata, root licenses, and requirements files, then likely CI/test/
Python workflows. Complete means the entire relevant set found in a complete
tree was retrieved under that per-repository cap.

`pyproject.toml` and `Pipfile` are parsed as TOML when a parser exists;
Python 3.10 without `tomli` yields `parser_unavailable`, not malformed. `setup.py`
uses AST literal extraction only, `setup.cfg`/`tox.ini` use `ConfigParser`,
requirements files are read as lines, and workflow matrices are statically
recognized as data. Dynamic or unsupported matrix shapes stay distinct from
no matrix declaration. A declaration is not verified Python compatibility,
dependency resolution, installation feasibility, or runtime behavior. License
texts and package license fields are source evidence, not legal conclusions.
PR semantics, labels, impacts, and truth remain unclassified.

## Reproduce and validate

```bash
python3 benchmarks/real_world/source_metadata_v3.py --collect
python3 benchmarks/real_world/source_metadata_v3.py --validate benchmarks/results/gh103-source-metadata-v3/source-metadata-v3.json
uv run --with pytest python -m pytest tests/benchmarks/test_source_metadata_v3.py -q
```

Collection is a dedicated bounded operation, not a test. Publication is
deterministic and no-clobber. The result below records the exact command, code
hash, observed counters, statuses, and result hash for the actual live run.
