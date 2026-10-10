# GH103 frozen source metadata evidence v4

V4 is the final bounded supplement to the retained v1, v2, and v3 records.
It uses the same exact 50 frozen survey commits and exact-source protocol, with
the same external GitHub/TLS trust basis and recomputable commit/tree/path/blob
relationships. It does not change frozen population, PR identities, partitions,
truth, reviews, or ledger.

The collector selects at most 32 source files per repository and 8 MiB of
decoded source per repository. It prioritizes root package declarations, root
license text, root requirements, and test/CI/Python workflows, then nested
package metadata and other workflows. A repository exceeding this file cap is
explicitly `truncated`; the result records the selected paths and validates
that they match this priority rule. Other bounds remain 1,200 requests and
objects, 128 MiB returned response bytes, 900 seconds wall time, 15 seconds per
request, two retries, 512 KiB per source file, and 192 MiB result size.

Only fixed-origin HTTPS GitHub REST requests are made. Credentials come from
`GITHUB_TOKEN` or the existing `gh` profile, stay in process memory, and are
never emitted. Redirects fail closed. Source is parsed as data only. Missing
parser support, dynamic declarations, incomplete retrieval, truncation, and
contradictory identity are distinct states. Nothing here proves installation,
dependency resolution, runtime compatibility, security, or legal conclusions;
PR semantics, impact, and truth remain unclassified.

```bash
python3 benchmarks/real_world/source_metadata_v4.py --collect
python3 benchmarks/real_world/source_metadata_v4.py --validate benchmarks/results/gh103-source-metadata-v4/source-metadata-v4.json
uv run --with pytest python -m pytest tests/benchmarks/test_source_metadata_v4.py -q
```

## Observed collection

Command: `python3 benchmarks/real_world/source_metadata_v4.py --collect`.
The collector revision is SHA-256
`2aff46623a3edd5aa551b480b39a1f6ef8171d54a23de9bb577d2366cbc0efdf`.
The canonical result SHA-256 is
`da47a21b25e5e1d48cefce5f81efdbc83d8031829f4818a3c17e257866ec5231`.
The authenticated `gh` profile supplied credentials; the collection made 945
requests, received 52,259,101 response bytes across 944 unique objects, used
zero retries, and took 593.413 seconds. Validation reports exact 50-project
coverage: 39 `complete`, 10 `truncated` by the 32-file cap, and one
`unavailable` (`dbt-labs/dbt-core`, redirect rejected). The truncated projects
and full candidate counts are recorded in the JSON; selected evidence remains
available for each of those projects. The v1 0/50 HTTP 403 record is retained
unchanged as a historical failed attempt.

Request-log validation checks retry chronology per URL: each retry must follow
a `truncated`, network-unavailable, or HTTP 429/500/502/503/504 result. Success
and terminal HTTP statuses cannot be followed by another attempt. The original
collector digest remains pinned for this unchanged historical artifact; its
bytes and observation were not rewritten.

Revalidation command:
`python3 benchmarks/real_world/source_metadata_v4.py --validate benchmarks/results/gh103-source-metadata-v4/source-metadata-v4.json`.
The synthetic validator suite is run with the pytest command above; it does not
execute upstream source.

This result supplies frozen-commit source evidence, not the missing GH103
feasibility determination. Ten repositories have incomplete candidate-file
retrieval and one has no source retrieval because redirects are rejected.
Even for complete projects, declared Python constraints, classifiers, workflow
matrices, license texts, and dependency declarations do not verify dependency
resolution, package installation, or runtime support. GH103 therefore remains
unmet. All 2,500 frozen PR identities remain unclassified for type and
semantics pending independent blind reviews and adjudication; this collection
does not create or alter any review, truth, ledger, attestation, or canary
record.
