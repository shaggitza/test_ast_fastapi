# Materializing locked raw diffs

`benchmarks/real_world/materialize_locked_diffs_v2.py` retrieves only the 50
diff URLs already bound to `fastapi/full-stack-fastapi-template` in
`pr-lock-2500-v2.json`. It captures the lock, manifest, and checksum profile
once, checks their SHA-256 values against pins computed from the committed base
tree, then applies the v2 semantic validators to those captured bytes before
making requests. It does not execute or parse downloaded content.

Run it with the repository's pinned interpreter:

```sh
/tmp/pr341-ci-host-locked-20261010/bin/python \
  benchmarks/real_world/materialize_locked_diffs_v2.py \
  --output /tmp/locked-raw-diffs-149-new-run
```

Each verified blob is stored once under `blobs/<sha256>`. `receipts.json`
contains one status for each locked row and records URL, expected and observed
hash/size, final URL, and blob path. Failures include a structured
`failure_class`; HTTP failures also include numeric `http_status` without
recording response headers. Existing output files are never replaced. Output
directories are opened component by component without following symlinks, and
creation and publication remain relative to those verified directory handles.
The collector enforces 2 MB per diff, 443,496 aggregate bytes, 180 seconds,
HTTPS-only exact-PR redirects, and the protocol's credential-free host rules.
Failed requests and lock mismatches remain explicit row statuses; the lock is
never rewritten to accept changed remote bytes.

An earlier local acquisition, before the snapshot/containment hardening in this
collector, retained 49 matching diff blobs (441,794 bytes) and one missing
request for locked PR 2168. Those existing blobs and receipt bindings were
independently reconciled against the frozen lock; the incomplete cache remains
unchanged. The hardened collector was validated with offline controls, not
rerun against the remote URLs. Do not reuse an existing output directory or
substitute a different PR or diff for an unavailable locked row. This cache is
raw source collection only; it contains no reviews, adjudications, or truth labels.
