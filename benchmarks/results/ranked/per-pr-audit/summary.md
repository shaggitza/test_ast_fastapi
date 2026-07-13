# Cross-PR ranked FastAPI audit

## Scope and method

- This audit covers the requested **26 truth-positive PRs** only. Canonical complete truth was read first, then `benchmark_scope.filter_record(record, "fastapi")` was applied before every score.
- Those 26 records contain the entire **177 normalized atoms** in the ranked `fastapi-adapter-v1` truth. Broader UI, CLI, event, deployment, or generic truth is described in individual reports but never mixed into scored TP/FN.
- Predictions came from `benchmarks/results/ranked/{mypy,scip}/predictions.jsonl`; selected HIGH/MEDIUM atoms were matched before LOW using the repository alias table and deterministic one-to-one matcher.
- Every merge SHA and first parent was resolved in the three bare clones under `/tmp/current-corpus-cache`; changed paths/hunks and canonical path references were checked against those snapshots.
- Analyzer interpretation used `run_current.py:487-494` (non-Python gate), `mypy_analyzer.py:939-976` (typed call-edge tracing), `change_mapper.py:533-570` (mypy reachability/effect projection), and `change_mapper.py:745-777` (SCIP reverse-reference evidence and its reachability-only limitation).

## Aggregate exact normalized accounting

| Backend | TP | FP | FN | LOW TP | LOW FP |
|---|---:|---:|---:|---:|---:|
| mypy | 95 | 10 | 82 | 0 | 9 |
| scip | 110 | 371 | 67 | 0 | 0 |

- Mypy: 95 + 82 = 177 truth atoms; its nine LOW atoms are excluded from primary TP/FP/FN.
- SCIP: 110 + 67 = 177 truth atoms; its 371 FP are selected reverse-reference candidates, overwhelmingly from #26642.

## Per-PR index and exact counts

| Repository | PR | Truth atoms | mypy TP/FP/FN; LOW | SCIP TP/FP/FN; LOW | Report |
|---|---:|---:|---|---|---|
| khoj-ai/khoj | 1207 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1207](khoj/1207.md) |
| khoj-ai/khoj | 1212 | 5 | 0/0/5; 0/0 | 0/0/5; 0/0 | [1212](khoj/1212.md) |
| khoj-ai/khoj | 1216 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [1216](khoj/1216.md) |
| khoj-ai/khoj | 1221 | 3 | 0/0/3; 0/0 | 0/0/3; 0/0 | [1221](khoj/1221.md) |
| khoj-ai/khoj | 1229 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1229](khoj/1229.md) |
| khoj-ai/khoj | 1235 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1235](khoj/1235.md) |
| khoj-ai/khoj | 1238 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [1238](khoj/1238.md) |
| khoj-ai/khoj | 1265 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [1265](khoj/1265.md) |
| khoj-ai/khoj | 1269 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1269](khoj/1269.md) |
| khoj-ai/khoj | 1271 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1271](khoj/1271.md) |
| khoj-ai/khoj | 1292 | 3 | 0/0/3; 0/0 | 0/0/3; 0/0 | [1292](khoj/1292.md) |
| khoj-ai/khoj | 1296 | 4 | 0/0/4; 0/0 | 0/0/4; 0/0 | [1296](khoj/1296.md) |
| khoj-ai/khoj | 1312 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1312](khoj/1312.md) |
| khoj-ai/khoj | 1348 | 2 | 0/0/2; 0/0 | 0/0/2; 0/0 | [1348](khoj/1348.md) |
| langflow-ai/langflow | 13949 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [13949](langflow/13949.md) |
| langflow-ai/langflow | 13950 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [13950](langflow/13950.md) |
| langflow-ai/langflow | 13952 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [13952](langflow/13952.md) |
| langflow-ai/langflow | 13960 | 3 | 0/0/3; 0/0 | 0/0/3; 0/0 | [13960](langflow/13960.md) |
| langflow-ai/langflow | 13968 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [13968](langflow/13968.md) |
| langflow-ai/langflow | 13976 | 8 | 0/0/8; 0/0 | 0/0/8; 0/0 | [13976](langflow/13976.md) |
| langflow-ai/langflow | 13992 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [13992](langflow/13992.md) |
| open-webui/open-webui | 26384 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [26384](open-webui/26384.md) |
| open-webui/open-webui | 26405 | 1 | 0/0/1; 0/0 | 0/0/1; 0/0 | [26405](open-webui/26405.md) |
| open-webui/open-webui | 26642 | 106 | 92/10/14; 0/0 | 106/369/0; 0/0 | [26642](open-webui/26642.md) |
| open-webui/open-webui | 26906 | 3 | 3/0/0; 0/9 | 0/1/3; 0/0 | [26906](open-webui/26906.md) |
| open-webui/open-webui | 26911 | 18 | 0/0/18; 0/0 | 4/1/14; 0/0 | [26911](open-webui/26911.md) |

## Cross-PR failure taxonomy

### 1. Discovery failures

- **Non-Python gate:** Khoj #1216, #1221, #1235; Open WebUI #26384 and #26405; and Langflow #13992 are unresolved before analysis because `run_current.is_python_change` requires a `.py` file. Their truth is nevertheless FastAPI-addressable because changed clients or deployment configuration alter requests to concrete API routes.
- **Alternate app roots:** Khoj #1265 changes `src/telemetry/telemetry.py`, outside the configured `src/khoj` root.
- **Router/plugin discovery:** Khoj #1207 and Langflow #13950/#13976 expose direct or mounted WebSocket/A2A/MCP handlers that produce zero candidates. Langflow #13968 is a dynamic package-entry-point/component-palette edge.

### 2. Propagation failures

- **Shared chat orchestration:** Khoj #1229, #1269, #1271, #1312, #1348 and parts of #1207/#1212 require traversal through command branches, async generators, online-search tools, model tables, or WebSocket wrappers.
- **Adapter/class layers:** Khoj #1238, #1292, #1296 require tracing provider, converter, or adapter methods back through route helpers.
- **A2A/service layers:** Langflow #13949, #13952 and #13960 require response-builder, JSON-RPC dispatcher, or cascade-delete edges.
- **Vector facade depth:** Open WebUI #26911 is the clearest propagation miss: mypy finds 0/18; SCIP finds only 4/18 and adds one unrelated embedding-config route.

### 3. Matching behavior

- No cohort-wide failure is caused by spelling alone. Selected-first atomic matching correctly expands composite methods and normalizes templates.
- Open WebUI #26642 demonstrates this: 103 scored labels expand to **106 atoms**; four methods on `/openai/{path:path}` are independently credited. Mypy scores 92/10/14 and SCIP 106/369/0.
- Canonical complete truth and FastAPI scored truth differ for several PRs; each report states both counts to prevent out-of-scope labels from becoming apparent FN.

### 4. Observability and confidence

- Open WebUI #26906 separates behavior from reachability correctly. Mypy selects three behavioral routes (3 TP, 0 FP, 0 FN) and retains nine task/compaction routes as LOW. All nine are behavioral LOW FP but independently reachability-supported; they do not change primary precision.
- SCIP currently lacks that effect-aware projection: on #26906 it misses all three behavioral routes and selects `GET /api/v1/functions/`; on #26642 it promotes broad reverse reachability to MEDIUM, yielding 369 FP.
- `change_mapper.py:759-777` itself describes SCIP evidence as reachability-only and says runtime observation is not established. The general fix is to keep reverse reachability as a candidate pool and promote only with direct change or corroborating data-flow/effect evidence.

## Deep-case conclusions

### Open WebUI #26642 — 106 scored atoms

- Truth groups account exactly: direct 15 atoms, data 15, admin 20, extensions 15, other 41.
- Mypy TP/FN by group: 13/2, 11/4, 15/5, 15/0, 38/3; plus 10 FP.
- SCIP covers all 106 truth atoms but selects 369 extra routes. Its full-inventory shape is an observability/ranking failure, not a recall success suitable for deployment.
- General regression: a shared configuration/provider change must recover the bounded source-audited handlers while leaving unrelated reverse-reachable route inventory LOW.

### Open WebUI #26906 — nine reachability-only LOW

- Behavioral truth is three atoms; mypy gets all three.
- Nine additional call-reachable task/compaction routes execute the defensive-copy path but have no established caller-visible payload observation. Supplemental truth supports reachability only.
- Required invariant: those nine remain outside primary TP/FP/FN and are reported as reachability-supported LOW, not promoted behavioral effects.

### Open WebUI #26911 — 18 truth atoms

- Four memory routes, six retrieval processing routes, two file routes, and six knowledge routes reach first-write Milvus shared-collection creation.
- Mypy misses all 18. SCIP finds memory reset and three knowledge routes, misses 14, and adds retrieval embedding update as FP.
- Repair the vector facade/async alias/file wrapper propagation, then assert exactly the 18 audited route atoms under the Milvus-first-write condition.

## Prioritized general repairs

1. Add a versioned cross-language/deployment evidence adapter rather than classifying every non-Python PR as no prediction.
2. Support multiple application roots and improve secure router discovery for WebSocket, A2A and MCP v2 mounts.
3. Extend typed propagation across async generators, dispatch tables, class adapters, plugin entry points and client facades.
4. Keep SCIP reverse reachability as LOW unless direct overlap or a typed/data-flow observation establishes behavior.
5. Add the per-PR regression fixtures proposed in the linked reports; evaluate both endpoint identity and confidence tier.

## Global unknowns

- Dynamic plugins, runtime-selected vector backends, configured function pipes, event consumers and deployment environments remain conditional.
- Source evidence establishes reachability/behavioral paths but does not execute every runtime configuration.
- Canonical audits include bounded unknowns per PR; those are retained verbatim in the individual reports.
- The one automatically unresolved snapshot-path parse in Khoj #1207 came from prose/query punctuation; the underlying configure/router evidence was inspected in the merge snapshot.

## Review result

- **Complete:** 26/26 requested reports exist, all 177 scored truth atoms are accounted for, and aggregate counts reproduce the ranked evaluation artifacts.
- **No benchmark-scoring blocker found:** primary/LOW separation and selected-first matching are reflected consistently in these audits. Analyzer repair opportunities are categorized above.
