# Code Context
## Files Retrieved
1. `/tmp/audit-inputs/mypy-26642.json` — 15 selected unmatched predictions.
2. `/tmp/audit-inputs/scip-26642.json` — 118 selected unmatched predictions, including all 15 mypy IDs.
3. `/tmp/audit-source/26642/backend/open_webui/models/config.py` (lines 87-213) — changed serialization and persistent/non-persistent `Config.upsert` behavior.
4. `/tmp/audit-source/26642/backend/open_webui/utils/automations.py` (lines 267-270) — changed automation model-feature handling.
5. `/tmp/audit-source/26642/backend/open_webui/routers/automations.py` (lines 281-293) — `/automations/{id}/run` reaches automation execution.
6. `/tmp/audit-source/26642/backend/open_webui/utils/images/comfyui.py` (lines 202-245) — changed ComfyUI workflow logging.
7. `/tmp/audit-source/26642/backend/open_webui/routers/images.py` (lines 270-315, 732-763, 1098-1146) — image config writes and ComfyUI generation/edit callers.
8. `/tmp/audit-source/26642/backend/open_webui/routers/tasks.py` (lines 180-205, 250-275; analogous callers through line 685) — task completion routes delegate to changed chat/provider processing.
9. `/tmp/audit-source/26642/backend/open_webui/routers/evaluations.py` (lines 268-295) — evaluation config read/write routes.
10. `/tmp/audit-source/26642/backend/open_webui/routers/pipelines.py` (lines 198-201) — pipeline listing invokes provider model discovery.
11. `/tmp/audit-source/26642/backend/open_webui/routers/models.py` — only the already-matched model-update handler changed directly among selected router modules.
## Audit Accounting
After deduplication:
| Classification | Unique IDs |
|---|---:|
| `ground_truth_gap` | 15 |
| `true_false_positive` | 103 |
| `normalization_gap` | 0 |
| `unknown` | 0 |
| **Total** | **118** |
Backend overlap:
- mypy selected: 15
- SCIP selected: 118
- Shared: 15
- SCIP-only: 103
## Ground-truth gaps
All 15 mypy IDs are credible affected entrypoints omitted by adjudication:
- `HTTP GET /api/v1/pipelines/list`
- `HTTP POST /api/v1/automations/{id}/run`
- `HTTP POST /api/v1/evaluations/config`
- `HTTP POST /api/v1/images/config/update`
- `HTTP POST /api/v1/images/edit`
- `HTTP POST /api/v1/images/generations`
- `HTTP POST /api/v1/tasks/auto/completions`
- `HTTP POST /api/v1/tasks/config/update`
- `HTTP POST /api/v1/tasks/emoji/completions`
- `HTTP POST /api/v1/tasks/follow_up/completions`
- `HTTP POST /api/v1/tasks/image_prompt/completions`
- `HTTP POST /api/v1/tasks/moa/completions`
- `HTTP POST /api/v1/tasks/queries/completions`
- `HTTP POST /api/v1/tasks/tags/completions`
- `HTTP POST /api/v1/tasks/title/completions`
Evidence:
- Automation run invokes the execution path affected by `_resolve_model_features`; see `routers/automations.py:281-291` and `utils/automations.py:267-270`.
- Image edit/generation directly invoke the changed ComfyUI functions at `routers/images.py:732-763` and `1098-1146`.
- Image, evaluation, and task config updates reach changed `Config.upsert`, whose persistence and JSON encoding semantics changed in `models/config.py:193-213`.
- Task completion handlers delegate to `generate_chat_completion`, e.g. `routers/tasks.py:191-198` and `261-268`, reaching changed provider/chat middleware.
- Pipeline listing performs provider model discovery at `routers/pipelines.py:198-201`, reaching changed upstream error publication.
Severity: **medium** — the adjudicated truth understates valid HTTP impact, penalizing precise transitive predictions.
## True false positives
The 103 SCIP-only IDs are route-inventory expansion without an evidenced path to the PR changes:
| Area | Count | IDs accounted for |
|---|---:|---|
| functions | 16 | Every selected functions route: delete; six GET detail/valve variants plus root/list; create, toggle/global, update, valve updates, load URL, sync |
| models | 15 | All selected model routes except the already-matched `POST /model/update` |
| prompts | 15 | All selected prompt CRUD, history, tags, toggle, access, metadata, and version routes |
| tools | 15 | All selected tool CRUD, export/list, valves, access, and load routes |
| evaluations | 14 | All selected feedback/leaderboard routes and `GET /config`; excludes the valid `POST /config` |
| skills | 9 | All selected skill CRUD, export/list, access, and toggle routes |
| automations | 7 | Delete/list/get/runs/create/toggle/update; excludes valid run |
| pipelines | 7 | Root, delete, add/upload, and valve routes; excludes valid list |
| images | 3 | `GET /config`, `GET /config/url/verify`, `GET /models` |
| tasks | 2 | `GET /config`, `POST /active/chats` |
| **Total** | **103** | Fully accounted |
The source diff changes no functions, prompts, tools, skills, pipelines, automations, evaluations, tasks, or images router file. The only selected router file changed directly is `routers/models.py`, specifically the already-ground-truth model-update endpoint. SCIP therefore appears to have promoted file/module or broad graph adjacency into application-wide route impact.
Severity: **high** — these 103 IDs are systematic over-approximation, not normalization differences.
## Architecture
The mypy result preserves useful transitive paths through changed helpers and shared configuration/provider logic. SCIP additionally floods predictions with sibling routes from related modules. Because every emitted ID already has a concrete canonical method and mounted path, none of the 118 disagreements is attributable to normalization.
## Start Here
Open `/tmp/audit-source/26642/backend/open_webui/models/config.py` at lines 193-213. It explains several legitimate transitive predictions and provides the clearest boundary between the 15 ground-truth omissions and SCIP’s unrelated sibling-route expansion.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Deduplicated and classified all 118 selected unmatched IDs: 15 ground_truth_gap, 103 true_false_positive, 0 normalization_gap, and 0 unknown, with target-source file and line evidence."
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "uv run python audit-input inventory and deduplication scripts",
      "result": "passed",
      "summary": "Found 15 mypy IDs, 118 SCIP IDs, 15 shared IDs, and 118 unique selected IDs."
    },
    {
      "command": "git diff HEAD^ HEAD -- selected backend source",
      "result": "passed",
      "summary": "Confirmed only models.py changed directly among selected router modules; identified changed shared Config, automation, image, provider, and middleware paths."
    },
    {
      "command": "Targeted grep and numbered source inspection",
      "result": "passed",
      "summary": "Verified automation, image, task, evaluation-config, and pipeline-list reachability."
    }
  ],
  "validationOutput": [
    "Classification sum: 15 + 103 + 0 + 0 = 118 unique IDs.",
    "SCIP-only category sum: 16 + 15 + 15 + 15 + 14 + 9 + 7 + 7 + 3 + 2 = 103.",
    "All 15 mypy IDs are present in SCIP and classified consistently as ground_truth_gap."
  ],
  "residualRisks": [
    "Task/provider behavior is configuration-dependent: the changed provider failure path is exercised only when the selected provider fails.",
    "ComfyUI image effects apply only when ComfyUI is the configured generation or edit engine.",
    "Pipeline provider discovery depends on configured upstream providers."
  ],
  "noStagedFiles": true,
  "diffSummary": "Read-only audit; no files changed.",
  "reviewFindings": [
    "high: /tmp/audit-inputs/scip-26642.json - 103 selected unmatched IDs are broad sibling-route false positives without changed-symbol reachability.",
    "medium: /tmp/audit-inputs/mypy-26642.json - all 15 selected unmatched IDs have defensible transitive impact and expose ground-truth omissions.",
    "medium: /tmp/audit-source/26642/backend/open_webui/models/config.py:193-213 - changed shared Config.upsert semantics affect multiple omitted configuration-update endpoints."
  ],
  "manualNotes": "No normalization or unresolved cases were found. Audit was read-only."
}
```
