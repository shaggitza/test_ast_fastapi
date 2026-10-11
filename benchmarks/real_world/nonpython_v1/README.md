# Non-Python source evaluation, v1

This evaluation covers **six audited PRs** and **nine route atoms**: eight client HTTP atoms across the five TypeScript/Svelte PRs, plus one conditional Docker/environment deployment atom for Langflow, whose subprocess evidence remains unverified. GH108 says “nine audited non-Python cases” without defining whether a case means a PR, client request, or deployment-to-route contract. The nine audited atoms could be its intended unit; this repository evidence does not establish that interpretation or full acceptance. No additional PR identities are inferred. The atoms are reviewed historical evidence, provisional and separate from canonical truth.

## Reproduction

The R8 replay writes a separate versioned artifact and keeps the existing
`results/evaluation.json` historical output unchanged:

```sh
uv run --frozen python benchmarks/real_world/evaluate_nonpython_r8.py \
  --write benchmarks/real_world/nonpython_v1/results/evaluation-r8.json
```

The replay verifies every fixture hash, archives only the pinned trusted
scanner closure, and treats upstream source snapshots as inert text. The R8
artifact records source observations and audited callsites. Its historical
atoms remain provisional and separate from canonical truth. Bounded R8/R9
source observations are recorded; the subprocess criterion remains unverified,
and this does not establish full GH108 acceptance. This replay calls the
client/deployment extractors directly; project-adapter dispatch remains
unverified by this artifact.

## Evaluation behavior

The finite client scanner records literal HTTP/WebSocket observations and joins only when an explicit surface matches the observed method, route path, trusted origin, and surface ID. Dynamic base URLs, helper calls, or unknown request chains abstain. Query strings remain attached to observations as evidence and do not change normalized route identity. A raw literal route observation alone is not treated as a verified server join.

The Langflow atom is reported as `conditional_deployment_impact`, not observed runtime behavior. It preserves the Docker/environment observations, route evidence, deployment assumptions and historical audit citations. No raw subprocess observations or subprocess source references were emitted, so the subprocess contract remains unverified; historical stdio.client citations are not scanner records. The result does not claim that the runtime effect occurs across image variants, mounts, UIDs, or configured MCP servers.

The dedicated harness tests exercise source and manifest hash tampering, schema and atom-count tampering, data-only vendoring, and false joins for wrong origin, method, and untrusted surfaces:

```sh
uv run --frozen --extra dev pytest -q tests/benchmarks/test_evaluate_nonpython.py
```

`protocol_evidence.json` records the GH108 body, its empty comment thread, pinned protocol document, and frozen ranked audit index. The six PR identities and nine atom identities are explicit in `evaluation_cases.json`; neither file asserts that they exhaust an ambiguously worded issue requirement.
