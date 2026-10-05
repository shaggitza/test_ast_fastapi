# GH103 frozen source metadata evidence v2

This separately versioned record supplements, and does not replace, the
historical unauthenticated v1 attempt. Its collector used the authenticated
`gh` profile after finding no `GITHUB_TOKEN`; the token was kept in process
memory and sent only to `https://api.github.com`, with redirects rejected.

The result preserves commit and full recursive tree API response bytes, hashes,
request URLs, and selected source bytes. The validator recomputes the Git tree
and blob object IDs, validates every selected path against that tree, and
recomputes parsed declarations from raw bytes. Its trust basis is explicit:
the GitHub API over HTTPS is the external authority for the commit response;
the snapshots are not independently signed. Source text was parsed as data and
never imported, installed, built, or executed.

## Observed bounded run

Command: `python3 benchmarks/real_world/source_metadata_v2.py --collect`.
Collector SHA-256: `ffeb985acb8502aa0e89ac58cc0600d40ccfeaf91438820a513875947e880925`.
Authentication source: `gh_auth_profile` (credential value not recorded).
Observed: 212 requests, 33,554,432 response bytes, 210 successful response
objects, 0 retries, 128.091 seconds. Seventeen repositories have complete
selected metadata retrieval; 25 are explicitly truncated by the 12-file cap;
seven are unavailable/truncated because the 32 MiB response bound or a
redirect stopped collection. The raw result SHA-256 is
`561842705d48ca4d88a447abaf8f768545385e28895c067de2fb08c9f966d114`.

The v2 run is retained as a historical result. V3 increases bounded capacity
and prioritizes package/license evidence before workflow files.

The validator was subsequently hardened to require each repeated URL attempt
to follow an actual retryable prior status (`truncated`, network unavailable,
or HTTP 429/500/502/503/504). A prior success or terminal HTTP status cannot
be followed by another attempt. The original collector digest above remains
pinned for this unchanged historical artifact; its bytes and observation were
not rewritten.
