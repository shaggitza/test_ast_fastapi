# GH108 R9 project-adapter evaluation

R9 runs the repository adapter on the hash-verified selected source snapshots. It records six audited PRs, eight provisional client route atoms and one conditional deployment atom. Those atoms are historical reviewed evidence, not canonical benchmark truth.

The runner pins scanner commit `d4eec140bed84d3ff8cea8374f7f9e589b0e6def` and the complete imported package closure in `nonpython_v1/pinned_scanner/source_manifest-r9.json`. The project adapter's SHA-256 is `2c2b3731b5818c30946b682c7dccfa879b6d68a8541eb5f66c5461d1b98a9ed5`. The isolated worker reports the hashes of the package files it actually imports; the parent reconciles them with the pinned manifest and staged bytes.

Each case stages only authenticated selected source bytes in a private temporary directory. Exact client and deployment path patterns, the 10,000 file budget and the 2,000,000 byte per-file budget appear in its report. Selected Python sources are parsed as inert text for subprocess observations. Application and client source modules are not imported by the worker.

Run from the repository:

```sh
python -m benchmarks.real_world.evaluate_nonpython_r9 --write /tmp/nonpython-r9.json
```

The R9 result separates raw client observations, client uncertainties, hash-bound audited-callsite matches, query evidence, deployment observations and subprocess selection. A selected Python file with zero subprocess observations is reported as such. Selection is complete only when the adapter reports completeness and its scanned file count matches the selected denominator.

This corpus supplies no established endpoint objects or attested server origins. The runner requires empty join output and does not infer origins from audit citations or route coincidences. It does not compute canonical precision or recall. GH108 acceptance remains open for broader coverage and independently attested joins.

The measured result is `benchmarks/real_world/nonpython_v1/results/evaluation-r9.json`, SHA-256 `1c418a5c7908214b870a9fdc986d33e90da85589fe00ecc99c4bb7f445393c8c` (84,495 bytes). It was produced from runner revision `b4ea67c9d1f14bbabe6ea16a00bb0ffbadad522c` using Python 3.11.16 and this command, with exit status 0:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B benchmarks/real_world/evaluate_nonpython_r9.py \
  --fixture-dir benchmarks/real_world/nonpython_v1 --write /tmp/nonpython-r9.json
```

All six case scans were complete and their scanned counts matched the selected paths: 2, 5, 3, 5, 4 and 6 files. The result verifies 25 source files and reconciles all 18 imported scanner modules with the pinned manifest. It records 35 raw client observations, 41 client uncertainties and 36 deployment observations. The eight client atoms have separate audited-callsite statuses: one observed, six unobserved and one unresolved location. These statuses are provisional source comparisons, not true-positive/false-negative labels or precision/recall scores.

No endpoint objects or trusted origins were supplied, so established-surface joins remain zero. Langflow's selected Python source was scanned but yielded zero subprocess observations; the deployment observations remain conditional source evidence, with no runtime execution claim. The result records the protocol-evidence file digest; that digest is not independently pinned or externally attested. This run does not satisfy GH108's broader coverage or attested-origin acceptance.

The original R8 runner, manifest and result remain available under their existing paths.
