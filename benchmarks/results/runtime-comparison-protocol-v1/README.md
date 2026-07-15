# Secure versus runtime comparison protocol v1

Issue: [#100](https://github.com/shaggitza/test_ast_fastapi/issues/100)

This freezes the artifact contract before corpus execution. Each secure/runtime
record declares mode, target/baseline snapshot, success/failure, identical entry
and backend configuration, timing/RSS, provenance, and either complete list and
impact artifacts or one structured abstention.

Recognized failure phases are `dependency`, `import`, `app_resolution`,
`extraction`, `timeout`, and `unavailable`. Failed runs cannot publish partial
quality metrics. A pair contributes route/impact quality only when both runs
succeed with byte-equivalent configuration.

`benchmarks/real_world/compare_runtime.py` reports:

- inventory intersection, secure-only, runtime-only, and Jaccard;
- exact candidate-impact agreement;
- separately normalized path-parameter agreement;
- secure/runtime timing and RSS fields;
- content hashes for both source records.

The comparator never mutates truth, predictions, or primary secure artifacts.
Runtime-only results are disagreement candidates requiring source adjudication,
not automatic positives. Runtime absence proves little.

Example:

```bash
python benchmarks/real_world/compare_runtime.py \
  --secure secure-target.json \
  --runtime runtime-target.json \
  --output comparison-target.json
```

Operational corpus results remain blocked on #101's trusted gVisor/Kata canary
and snapshot-specific dependency images. Target and baseline are compared as
separate pairs; mixing snapshots or entry/backend configuration fails closed.
