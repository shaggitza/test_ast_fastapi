## Review
- **Correct:** `benchmarks/real_world/adjudicated.jsonl` preserves the complete cross-surface truth: 180 labels over 58 adjudicated PRs. This is valuable corpus evidence and should not be narrowed or rewritten for one adapter.
- **Correct:** FastAPI WebSockets are genuinely adapter-supported: `src/fastapi_endpoint_detector/models/endpoint.py:14-24`, the secure extractor, and `benchmarks/real_world/run_current.py:319-324` all model/emit `WEBSOCKET ...`.
- **Blocker:** `benchmarks/real_world/benchmark_scope.py:12-17` classifies every `kind=http` label as FastAPI-addressable. Five labels cannot be emitted by the adapter’s `HTTP METHOD /path` contract:
  - Open WebUI #26924 global `HTTP * ...`
  - Langflow #13992 descriptive “HTTP flow execution...”
  - Three Khoj methodless/mounted admin wildcards  
  Consequently, the current partition has 86 labels/89 normalized atoms instead of the principled adapter-addressable 81 labels/84 atoms.
- **Blocker:** The concurrent change to `semantic_normalization.py:137-146` removes kind compatibility to make a new test pass using the unsupported prediction kind `"websocket"`. README’s schema permits `event`, not `websocket` (`benchmarks/real_world/README.md:44-49`), and `run_current.py:319-321` emits WebSockets as `kind=event`. This unnecessarily widens normalized matching: an HTTP truth claim can now match an equivalent prediction declared as `other`, `event`, or `websocket`.
- **Note:** `benchmarks/real_world/scopes/README.md:6-7` therefore overstates that all partitioned HTTP surfaces are representable by the current adapter.
- **Note:** Main benchmark documentation does not explain which score is the adapter-primary score; `README.md:103-105` still describes only one undifferentiated evaluation.
## Principled scope
Use output-contract addressability, not broad behavioral relevance:
**FastAPI adapter v1**
- A finite, syntactically valid `HTTP METHOD /path` claim accepted by `parse_claims`.
- A finite `WebSocket /path` claim, regardless of WebSocket token casing, represented as benchmark kind `event`.
- Composite HTTP labels expand to method atoms.
- Explicit aliases and qualifiers remain normalization concerns, not scope criteria.
**Preserved broader truth**
- UI, CLI, cron, SDK, task, Socket.IO/browser/domain events.
- Mounted non-FastAPI applications and methodless HTTP wildcards.
- Global HTTP wildcard effects until expanded against a frozen route universe.
- Descriptive “HTTP execution” labels without an adapter-emittable route identity.
If all HTTP-impact labels are desired as a separate view, call it `network-surface`, not `fastapi-adapter`.
## Truth quantification
| Repository | Adapter HTTP | Adapter WS (`kind=event`) | Adapter total | Broader truth |
|---|---:|---:|---:|---:|
| `khoj-ai/khoj` | 24 | 8 | 32 | 23 |
| `langflow-ai/langflow` | 16 | 0 | 16 | 46 |
| `open-webui/open-webui` | 33 | 0 | 33 | 30 |
| **Total** | **73** | **8** | **81** | **99** |
Broader truth by kind:
- HTTP but not adapter-addressable: 5
- Non-WebSocket event: 5
- CLI: 8
- cron: 3
- other/UI: 73
- SDK: 4
- task: 1
The adapter truth becomes 84 normalized atoms because the one four-method composite adds three atoms. It occurs on 26 truth-positive PRs: Khoj 14, Langflow 7, Open WebUI 5. The remaining 32 adjudicated PRs are adapter-negative controls.
## Corrected adapter score
These figures use only parseable FastAPI HTTP/WebSocket claims; all broader labels remain in the full truth.
| Backend | Repository | Raw TP/FP/FN | Normalized TP/FP/FN |
|---|---|---:|---:|
| mypy | Khoj | 0/0/32 | 0/0/32 |
| mypy | Langflow | 0/0/16 | 0/0/16 |
| mypy | Open WebUI | 10/107/23 | 14/100/22 |
| **mypy total** | | **10/107/71** | **14/100/70** |
| SCIP | Khoj | 0/0/32 | 0/0/32 |
| SCIP | Langflow | 0/0/16 | 0/0/16 |
| SCIP | Open WebUI | 15/468/18 | 19/462/17 |
| **SCIP total** | | **15/468/66** | **19/462/65** |
- mypy normalized: precision **12.28%**, recall **16.67%**, F1 **14.14%**
- SCIP normalized: precision **3.95%**, recall **22.62%**, F1 **6.73%**
The current broad `kind=http` implementation instead reports 89 atoms and normalized recall of 15.73%/21.35%, adding five impossible-to-emit FNs.
Both hardened backends emitted predictions only for Open WebUI. Per-repository reporting is therefore essential; aggregate recall obscures zero recall on the other two repositories.
## Recommended folder schema
Avoid committing duplicated filtered adjudication files as independent truth:
```text
benchmarks/real_world/
  corpus/
    corpus.json
    repos.json
  truth/
    adjudicated.jsonl
    review-a.jsonl
    review-b.jsonl
  semantics/
    normalization-v1.json
    aliases-v1.json
  scopes/
    fastapi-adapter-v1/
      manifest.json
      membership.jsonl
    all-surfaces/
      manifest.json
benchmarks/results/hardened/<backend>/
  manifest.json
  predictions.jsonl
  evaluations/
    all-surfaces.json
    fastapi-adapter-v1.json
  audit/
    disagreements/
```
`membership.jsonl` should reference stable `(repository, pr, raw_id)` identities with inclusion reason and scope version. `manifest.json` should include the source adjudication SHA-256 and classifier version. Generated full copies of every adjudicated record risk stale divergence.
## Evaluator changes
1. Preserve default `all-surfaces` metrics for historical comparability.
2. Make `fastapi-adapter-v1` the explicitly named product score.
3. Select truth through a versioned membership sidecar; do not infer solely from `kind`.
4. Add prediction provenance such as `"adapter": "fastapi-v1"`. Otherwise malformed predictions may disappear during scope filtering instead of counting as FPs.
5. Report:
   - source and scope hashes/versions;
   - selected/excluded raw labels and atoms;
   - truth-positive PRs and negative controls;
   - `by_repository`, then `by_repository_and_kind`;
   - full-corpus micro;
   - macro over scope-positive PRs;
   - negative-control PRs producing any FP.
6. Keep operational unresolved/coverage statistics separate from scoped endpoint metrics; current filtering leaves unresolved items unchanged.
7. Retain raw exact and normalized metrics together.
8. Restore kind-compatible normalized matching and use `kind=event` for WebSocket tests.
## SCIP #26911 source audit
`/tmp/audit-inputs/scip-26911.json` reports 18 truth labels, 5 predictions, 4 raw-exact TPs, 1 FP, and 14 FNs. That packet is consistent with the source:
- The changed `_create_shared_collection` is reached from `upsert` through `_ensure_collection` in `retrieval/vector/dbs/milvus_multitenancy.py:118-187`.
- The three predicted knowledge routes are supported by:
  - `knowledge.py:269-299`
  - `knowledge.py:409-426`
  - `knowledge.py:1086-1130`
- The predicted memory reset is supported by `memories.py:388-415`.
- Router prefixes are confirmed in `main.py:741,755,760`.
- The unmatched prediction `POST /api/v1/retrieval/embedding/update` is a genuine FP: `retrieval.py:515-593` updates embedding configuration and function state but does not call the vector client or shared-collection creation.
- Several FNs are directly evidenced in source, including memory add/update calls to `ASYNC_VECTOR_DB_CLIENT.upsert`, external knowledge routes calling `embed_knowledge_base_metadata`, and retrieval writes through `VECTOR_DB_CLIENT.insert`.
## Review gate
**Not passed.** Correct the five-label scope widening and restore kind-compatible normalization before accepting the current scope implementation.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "not_satisfied",
      "evidence": "The in-progress benchmark_scope.py widens FastAPI scope to five non-emittable HTTP labels, and semantic_normalization.py removes kind compatibility beyond the requested scope change."
    },
    {
      "id": "criterion-2",
      "status": "satisfied",
      "evidence": "Report includes kind/repository counts, corrected hardened metrics, source citations, folder/evaluator design, five concrete scope disagreements, and SCIP #26911 source validation."
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "Python scope audit over adjudicated.jsonl using semantic_normalization.parse_claims",
      "result": "passed",
      "summary": "Found 81 adapter-addressable labels, 84 atoms, 99 broader labels, and five disagreements with the current scope predicate."
    },
    {
      "command": "Python per-repository hardened score prototype",
      "result": "passed",
      "summary": "Calculated corrected FastAPI-adapter raw and normalized metrics for mypy and SCIP."
    },
    {
      "command": ".venv/bin/pytest -q tests/benchmarks/test_evaluate.py tests/benchmarks/test_semantic_normalization.py tests/benchmarks/test_benchmark_scope.py",
      "result": "passed",
      "summary": "15 tests passed after concurrent worktree changes; coverage still encodes the overly broad HTTP scope."
    },
    {
      "command": ".venv/bin/ruff check benchmark scope/evaluator/normalization files and benchmark tests",
      "result": "passed",
      "summary": "All checked files passed lint."
    },
    {
      "command": "git show and source searches under /tmp/audit-source/26911",
      "result": "passed",
      "summary": "Verified four SCIP TPs, one FP, and representative FNs against immutable source."
    },
    {
      "command": "git diff --cached --name-only",
      "result": "passed",
      "summary": "No staged files."
    }
  ],
  "validationOutput": [
    "Full truth: 180 raw labels; FastAPI adapter: 81 raw labels and 84 normalized atoms; broader truth: 99 labels.",
    "Current scope predicate selects 86 labels and 89 atoms, five too many.",
    "mypy corrected normalized adapter score: TP=14 FP=100 FN=70 F1=0.141414.",
    "SCIP corrected normalized adapter score: TP=19 FP=462 FN=65 F1=0.067257.",
    "SCIP #26911 audit: 4 supported TP, 1 confirmed FP, 14 FN."
  ],
  "residualRisks": [
    "Scope inferred from raw ID syntax still needs a versioned sidecar for exceptional or mounted surfaces.",
    "Both hardened candidates have zero emitted predictions for Khoj and Langflow, so aggregate scores remain repository-skewed.",
    "Concurrent unstaged worktree changes were present and changed during review.",
    "Generated scope copies can drift unless tied to an adjudication hash."
  ],
  "noStagedFiles": true,
  "diffSummary": "Read-only audit; no files changed by this reviewer. Concurrent unstaged changes exist in benchmark scope/evaluator files and uv.lock.",
  "reviewFindings": [
    "blocker: benchmarks/real_world/benchmark_scope.py:12-17 - every kind=http label is treated as adapter-addressable, adding five claims the adapter cannot emit.",
    "blocker: benchmarks/real_world/semantic_normalization.py:137-146 - kind compatibility was removed, allowing cross-kind normalized matches.",
    "medium: benchmarks/real_world/scopes/README.md:6-7 - documentation incorrectly says all 78 HTTP labels are representable by the adapter.",
    "medium: benchmarks/real_world/README.md:103-105 - primary adapter scope and full-surface score are not distinguished."
  ],
  "manualNotes": "The worktree was actively modified by another process during review. No reviewer edits were made."
}
```
