# Non-Python source evaluation, v1

This fixture evaluates the **six** source-audited PR identities currently present in the ranked audit corpus. It preserves the historical route atoms provisionally; it does not write or amend canonical truth. Three additional GH108 case identities and immutable inputs remain unresolved.

## Reproduction

From a checkout whose local Git object database contains trusted scanner commit `1d9242d0d1d411b529c3227918aa2d05e98e8943`:

```sh
uv run --frozen python benchmarks/real_world/evaluate_nonpython.py
```

The harness verifies the SHA-256 of every pinned raw source file, PR commit patch, and audit before scanning. It reads third-party source as text only. It materializes the trusted PR #310 scanner from its exact commit into a temporary directory and runs the scanner over the saved TypeScript/Svelte files. No third-party code, Docker image, subprocess, or production canary is executed.

## Current result

`protocol_evidence.json` records the GH108 request, empty issue-comment result, frozen protocol document hash, and the six-case audit-index hash.

`results/evaluation.json` stores raw observations, normalized method/path identities, query evidence, explicitly origin-gated surface joins, and the audited historical atoms separately. On the finite PR #310 scanner, the five client PR cases yielded one unrelated literal `GET https://ipapi.co/json` observation and no joins to the reviewed case surfaces. The eight client atoms therefore remain unjoined. The dynamic base URLs, helper calls, and Svelte request chains are abstentions under this scanner contract. This is a measured baseline, not a claim that the source does not use those endpoints.

Langflow #13992 is represented as `conditional_deployment_impact`, not an observed runtime effect. The route, MCP stdio subprocess contract, Docker environment/cache change, and their provenance are recorded with deployment assumptions.

Queries are retained as evidence (`agent_slug`, `client=obsidian`, and serialized search parameters) and excluded from normalized route identity. Surface IDs are per audited server registration; origins are deliberately unset because these sources do not establish an exact client origin. Thus the scanner's exact-origin join correctly abstains and does not fan a URL out globally.

## Scope status

| GH108 criterion | Status in this evaluation |
|---|---|
| Finite normalized client extraction | Exercised using the pinned TypeScript/Svelte scanner; helper/dynamic cases abstain |
| Explicit established surface join | Exercised; no case origin attestation, so zero joins |
| Query evidence separate from route identity | Preserved for all reviewed atoms and scanner observations |
| WebSocket client support | Scanner supports literal `new WebSocket`; none of the six audited cases exercises it |
| Docker/env/subprocess contract | Langflow source contract retained conditionally; no runtime observation |
| No global URL fanout | Exact origin/method/path join only; no inferred origins |
| Nine audited case identities | **Incomplete:** six identities available; three unresolved slots, no identities invented |

The fixture has eight reviewed client route atoms and one conditional Docker/runtime route atom. Those nine atoms are not nine PR case identities.
