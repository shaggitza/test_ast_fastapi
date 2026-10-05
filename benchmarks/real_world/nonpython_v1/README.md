# Non-Python source evaluation, v1

This evaluation covers **six audited PRs** and **nine route atoms**: eight client HTTP atoms across the five TypeScript/Svelte PRs, plus one conditional Docker/environment/subprocess deployment atom for Langflow. GH108 says “nine audited non-Python cases” without defining whether a case means a PR, client request, or deployment-to-route contract. The nine audited atoms could be its intended unit; this repository evidence does not establish that interpretation or full acceptance. No additional PR identities are inferred. The atoms are reviewed historical evidence, provisional and separate from canonical truth.

## Reproduction

Run from a checkout whose local Git object database contains the pinned trusted scanner revisions:

```sh
uv run --frozen python benchmarks/real_world/evaluate_nonpython.py
uv run --frozen python benchmarks/real_world/evaluate_nonpython.py \
  --scanner-commit 1d9242d0d1d411b529c3227918aa2d05e98e8943 \
  --write benchmarks/real_world/nonpython_v1/results/historical-pr310-1d9242d0.json
```

The default current result pins PR #310 at `84efc3d877c2d93a25bdd2c625120e6a6d918139`. The historical result pins the earlier scanner at `1d9242d0d1d411b529c3227918aa2d05e98e8943`; it is retained separately and does not substitute for the current evaluation. Both outputs record exact scanner module hashes, verified source/diff/audit/license hashes, raw observations, normalized method/path identities, query evidence, joins, and every audited atom independently.

The harness verifies all fixture hashes before scanning. Vendored upstream Python files retain their original paths and hashes in `source_manifest.json`, but are stored as `.py.txt` data. The harness reads all upstream snapshots as strings. It executes only trusted internal scanner code archived from the exact pinned Git commit. It never imports or executes fetched source, invokes Docker, runs third-party subprocesses, or uses production canaries.

## Evaluation behavior

The finite client scanner records literal HTTP/WebSocket observations and joins only when an explicit surface matches the observed method, route path, trusted origin, and surface ID. Dynamic base URLs, helper calls, or unknown request chains abstain. Query strings remain attached to observations as evidence and do not change normalized route identity. A raw literal route observation alone is not treated as a verified server join.

The Langflow atom is reported as `conditional_deployment_impact`, not observed runtime behavior. It preserves the Docker environment/cache, stdio subprocess, and route evidence plus deployment assumptions. The result does not claim that the runtime effect occurs across image variants, mounts, UIDs, or configured MCP servers.

The dedicated harness tests exercise source and manifest hash tampering, schema and atom-count tampering, data-only vendoring, and false joins for wrong origin, method, and untrusted surfaces:

```sh
uv run --frozen --extra dev pytest -q tests/benchmarks/test_evaluate_nonpython.py
```

`protocol_evidence.json` records the GH108 body, its empty comment thread, pinned protocol document, and frozen ranked audit index. The six PR identities and nine atom identities are explicit in `evaluation_cases.json`; neither file asserts that they exhaust an ambiguously worded issue requirement.
