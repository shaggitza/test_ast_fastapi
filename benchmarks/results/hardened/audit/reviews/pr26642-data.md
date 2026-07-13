## Review
Scope: unmatched predictions whose IDs are under `/api/v1/{chats,knowledge,files,retrieval,memories}`. Backend notation: **M** = mypy, **S** = SCIP.
### Summary
| Classification | Deduplicated IDs | Mypy memberships | SCIP memberships |
|---|---:|---:|---:|
| `ground_truth_gap` | 15 | 11 | 15 |
| `true_false_positive` | 106 | 3 | 106 |
| `normalization_gap` | 0 | 0 | 0 |
| `unknown` | 0 | 0 | 0 |
| **Total** | **121** | **14** | **121** |
### Ground-truth gaps
1. **[S] `HTTP GET /api/v1/chats/search`**
   - Structured output persistence and emitted content changed at `backend/open_webui/utils/middleware.py:3469-3546`.
   - Search explicitly examines persisted `message.content` at `backend/open_webui/routers/chats.py:73-100,731-748`.
   - This can change whether structured-output text is searchable and what snippet is returned.
2. **[S] `HTTP GET /api/v1/chats/{id}`**
   - SearchModal still loads the chat through `getChatById` but now derives title-generation text from `message.output` at `src/lib/components/layout/SearchModal.svelte:195-216`.
   - The route supplying that changed behavior is `backend/open_webui/routers/chats.py:1168-1198`.
3. **[M+S] `HTTP POST /api/v1/chats/config`**
   - The handler directly calls changed `Config.upsert` at `backend/open_webui/routers/chats.py:712-723`.
   - `Config.upsert` now JSON-encodes values and updates in-memory defaults instead of writing disabled-persistence keys to the database at `backend/open_webui/models/config.py:193-216`.
4. **[M+S] `HTTP POST /api/v1/files/`**
   - Directory upload now invokes `uploadFile` with `knowledge_id`, checksum and directory metadata at `src/lib/components/workspace/Knowledge/KnowledgeBase.svelte:604-650`.
   - `uploadFile` maps to POST `/files/` at `src/lib/apis/files/index.ts:4-31`; the backend consumes the changed metadata at `backend/open_webui/routers/files.py:241-305`.
5. **[M+S] `HTTP DELETE /api/v1/knowledge/external/connections/{id}`**
   - The handler rewrites external connections through changed `Config.upsert` at `backend/open_webui/routers/knowledge.py:693-719`, via `_set_external_connections` at lines 569-570.
6. **[M+S] `HTTP PATCH /api/v1/knowledge/external/connections/{id}`**
   - Direct changed persistence path at `backend/open_webui/routers/knowledge.py:667-690`.
7. **[M+S] `HTTP PATCH /api/v1/knowledge/external/source/{id}`**
   - Updates and rollback paths write the connection collection through `_set_external_connections` at `backend/open_webui/routers/knowledge.py:949-1023`.
8. **[M+S] `HTTP POST /api/v1/knowledge/external/connections`**
   - Creation persists through changed `Config.upsert` at `backend/open_webui/routers/knowledge.py:634-652`.
9. **[M+S] `HTTP POST /api/v1/knowledge/external/connections/{id}/test`**
   - Testing updates health and persists the collection at `backend/open_webui/routers/knowledge.py:722-744`.
10. **[M+S] `HTTP POST /api/v1/knowledge/external/source/create`**
    - Creation and rollback both persist external connections at `backend/open_webui/routers/knowledge.py:884-945`.
11. **[S] `HTTP POST /api/v1/knowledge/{id}/dirs/create`**
    - The rewritten directory upload now creates server-side directories at `src/lib/components/workspace/Knowledge/KnowledgeBase.svelte:574-594`.
    - The API mapping is `src/lib/apis/knowledge/index.ts:982-1017`, reaching `backend/open_webui/routers/knowledge.py:2187-2218`.
12. **[S] `HTTP POST /api/v1/knowledge/{id}/sync/diff`**
    - Directory selection and drag/drop now perform manifest diffing before upload at `src/lib/components/workspace/Knowledge/KnowledgeBase.svelte:604-628,662-680`.
    - The API mapping is `src/lib/apis/knowledge/index.ts:821-855`.
13. **[M+S] `HTTP POST /api/v1/retrieval/config/update`**
    - The handler records updates and calls `config.save()` at `backend/open_webui/routers/retrieval.py:929-1313`.
    - `RetrievalConfig.save` directly invokes changed `Config.upsert` at lines 406-422.
14. **[M+S] `HTTP POST /api/v1/retrieval/embedding/update`**
    - Direct persistence through `config.save()` at `backend/open_webui/routers/retrieval.py:515-580`.
15. **[M+S] `HTTP POST /api/v1/retrieval/process/web/search`**
    - `get_filtered_results` changed URL filtering from `netloc` to `hostname` at `backend/open_webui/retrieval/web/main.py:11-35`.
    - The route dispatches configured search providers at `backend/open_webui/routers/retrieval.py:2515-2576`; those providers call the changed filter, for example `backend/open_webui/retrieval/web/brave.py:47` and `serpapi.py:38`.
These are genuine behaviors omitted by the supplied truth rather than analyzer false positives.
### True false positives
The five backend router files were unchanged in the parent diff. The IDs below lack a direct changed implementation, changed caller contract, or changed persistence write comparable to the 15 cases above.
#### Chats — 44
Evidence: ordinary chat CRUD remains in `backend/open_webui/routers/chats.py:131-1944`. In particular, compact calls unchanged `utils/context_compaction.py` at `chats.py:1116-1160`.
- [S] `HTTP DELETE /api/v1/chats/`
- [S] `HTTP DELETE /api/v1/chats/share/all`
- [S] `HTTP DELETE /api/v1/chats/{id}`
- [S] `HTTP DELETE /api/v1/chats/{id}/messages/{message_id}`
- [S] `HTTP DELETE /api/v1/chats/{id}/share`
- [S] `HTTP DELETE /api/v1/chats/{id}/tags`
- [S] `HTTP GET /api/v1/chats/`
- [S] `HTTP GET /api/v1/chats/all`
- [S] `HTTP GET /api/v1/chats/all/archived`
- [S] `HTTP GET /api/v1/chats/all/db`
- [S] `HTTP GET /api/v1/chats/all/tags`
- [S] `HTTP GET /api/v1/chats/archived`
- [S] `HTTP GET /api/v1/chats/archived/count`
- [S] `HTTP GET /api/v1/chats/config`
- [S] `HTTP GET /api/v1/chats/folder/{folder_id}`
- [S] `HTTP GET /api/v1/chats/folder/{folder_id}/list`
- [S] `HTTP GET /api/v1/chats/list`
- [S] `HTTP GET /api/v1/chats/list/user/{user_id}`
- [S] `HTTP GET /api/v1/chats/pinned`
- [S] `HTTP GET /api/v1/chats/share/{share_id}`
- [S] `HTTP GET /api/v1/chats/shared`
- [S] `HTTP GET /api/v1/chats/shared/{id}/access`
- [S] `HTTP GET /api/v1/chats/stats/export`
- [S] `HTTP GET /api/v1/chats/stats/export/{chat_id}`
- [S] `HTTP GET /api/v1/chats/stats/usage`
- [S] `HTTP GET /api/v1/chats/{id}/pinned`
- [S] `HTTP GET /api/v1/chats/{id}/tags`
- [S] `HTTP POST /api/v1/chats/archive/all`
- [S] `HTTP POST /api/v1/chats/import`
- [S] `HTTP POST /api/v1/chats/new`
- [S] `HTTP POST /api/v1/chats/shared/{id}/access/update`
- [S] `HTTP POST /api/v1/chats/tags`
- [S] `HTTP POST /api/v1/chats/unarchive/all`
- [S] `HTTP POST /api/v1/chats/{id}`
- [S] `HTTP POST /api/v1/chats/{id}/archive`
- [S] `HTTP POST /api/v1/chats/{id}/clone`
- [S] `HTTP POST /api/v1/chats/{id}/clone/shared`
- [M+S] `HTTP POST /api/v1/chats/{id}/compact`
- [S] `HTTP POST /api/v1/chats/{id}/folder`
- [S] `HTTP POST /api/v1/chats/{id}/messages/{message_id}`
- [S] `HTTP POST /api/v1/chats/{id}/messages/{message_id}/event`
- [S] `HTTP POST /api/v1/chats/{id}/pin`
- [S] `HTTP POST /api/v1/chats/{id}/share`
- [S] `HTTP POST /api/v1/chats/{id}/tags`
#### Files — 12
Evidence: only the POST upload contract receives changed client metadata. List, read, rename, content-update and deletion handlers remain independent at `backend/open_webui/routers/files.py:446-971`.
- [S] `HTTP DELETE /api/v1/files/all`
- [S] `HTTP DELETE /api/v1/files/{id}`
- [S] `HTTP GET /api/v1/files/`
- [S] `HTTP GET /api/v1/files/count`
- [S] `HTTP GET /api/v1/files/search`
- [S] `HTTP GET /api/v1/files/{id}`
- [S] `HTTP GET /api/v1/files/{id}/content`
- [S] `HTTP GET /api/v1/files/{id}/content/html`
- [S] `HTTP GET /api/v1/files/{id}/data/content`
- [S] `HTTP GET /api/v1/files/{id}/process/status`
- [S] `HTTP POST /api/v1/files/{id}/data/content/update`
- [S] `HTTP POST /api/v1/files/{id}/rename`
#### Knowledge — 27
Evidence: these handlers do not write through the changed external-connection configuration path and are not newly called by the directory-upload rewrite. Route implementations are at `backend/open_webui/routers/knowledge.py:129-2299`.
- [M+S] `HTTP DELETE /api/v1/knowledge/{id}/delete`
- [S] `HTTP DELETE /api/v1/knowledge/{id}/dirs/{dir_id}/delete`
- [S] `HTTP GET /api/v1/knowledge/`
- [S] `HTTP GET /api/v1/knowledge/external/connections`
- [S] `HTTP GET /api/v1/knowledge/external/connections/{id}`
- [S] `HTTP GET /api/v1/knowledge/search`
- [S] `HTTP GET /api/v1/knowledge/search/files`
- [S] `HTTP GET /api/v1/knowledge/{id}`
- [S] `HTTP GET /api/v1/knowledge/{id}/export`
- [S] `HTTP GET /api/v1/knowledge/{id}/files`
- [S] `HTTP GET /api/v1/knowledge/{id}/files/pending`
- [S] `HTTP POST /api/v1/knowledge/create`
- [S] `HTTP POST /api/v1/knowledge/external/connections/{id}/retrieve-test`
- [S] `HTTP POST /api/v1/knowledge/external/knowledge/create`
- [S] `HTTP POST /api/v1/knowledge/external/source/test`
- [S] `HTTP POST /api/v1/knowledge/metadata/reindex`
- [S] `HTTP POST /api/v1/knowledge/reindex`
- [S] `HTTP POST /api/v1/knowledge/{id}/access/update`
- [S] `HTTP POST /api/v1/knowledge/{id}/dirs/{dir_id}/update`
- [S] `HTTP POST /api/v1/knowledge/{id}/file/add`
- [S] `HTTP POST /api/v1/knowledge/{id}/file/move`
- [S] `HTTP POST /api/v1/knowledge/{id}/file/remove`
- [S] `HTTP POST /api/v1/knowledge/{id}/file/update`
- [S] `HTTP POST /api/v1/knowledge/{id}/files/batch/add`
- [S] `HTTP POST /api/v1/knowledge/{id}/reset`
- [S] `HTTP POST /api/v1/knowledge/{id}/sync/cleanup`
- [S] `HTTP POST /api/v1/knowledge/{id}/update`
#### Retrieval — 12
Evidence: configuration reads use unchanged `Config.get_many` (`backend/open_webui/routers/retrieval.py:425-431`). Only the two update routes call changed `Config.upsert`, and only web **search** reaches the changed result filter. Other processing/query/reset handlers are at `retrieval.py:1809-2962`.
- [M+S] `HTTP GET /api/v1/retrieval/config`
- [S] `HTTP GET /api/v1/retrieval/embedding`
- [S] `HTTP POST /api/v1/retrieval/delete`
- [S] `HTTP POST /api/v1/retrieval/process/file`
- [S] `HTTP POST /api/v1/retrieval/process/files/batch`
- [S] `HTTP POST /api/v1/retrieval/process/text`
- [S] `HTTP POST /api/v1/retrieval/process/web`
- [S] `HTTP POST /api/v1/retrieval/process/youtube`
- [S] `HTTP POST /api/v1/retrieval/query/collection`
- [S] `HTTP POST /api/v1/retrieval/query/doc`
- [S] `HTTP POST /api/v1/retrieval/reset/db`
- [S] `HTTP POST /api/v1/retrieval/reset/uploads`
#### Memories — 11
Evidence: the changed memory files alter chat-time memory enablement and tool instructions, not the memory CRUD API. `backend/open_webui/utils/memory.py:284-543` and `tools/builtin.py:726-775` feed chat processing; the predicted handlers are separate CRUD/vector operations at `backend/open_webui/routers/memories.py:56-536`.
- [S] `HTTP DELETE /api/v1/memories/delete/user`
- [S] `HTTP DELETE /api/v1/memories/{memory_id}`
- [S] `HTTP GET /api/v1/memories/`
- [S] `HTTP POST /api/v1/memories/add`
- [S] `HTTP POST /api/v1/memories/path`
- [S] `HTTP POST /api/v1/memories/paths`
- [S] `HTTP POST /api/v1/memories/query`
- [S] `HTTP POST /api/v1/memories/reset`
- [S] `HTTP POST /api/v1/memories/search`
- [S] `HTTP POST /api/v1/memories/update`
- [S] `HTTP POST /api/v1/memories/{memory_id}/update`
### Normalization and unknowns
- **Normalization gaps: none.** No selected unmatched ID is merely a method-set, path-prefix, query-string, or alias spelling of a supplied truth label.
- **Unknown: none.** The parent diff and local callers were sufficient to classify all 121 selected IDs.
### Findings
- **High — ground truth is incomplete by 15 selected HTTP behaviors.** Eleven are independently identified by both backends. The omissions include direct changed `Config.upsert` callers, the changed web-search filter, and new frontend directory-upload API calls.
- **High — SCIP still emits 106 genuine false positives in this slice.** Its class/structural reachability expands the `Config` and shared model changes to virtually every route in the five domains.
- **Medium — mypy is substantially more discriminating here.** Of 14 selected memberships, 11 are supported ground-truth gaps and only three are true false positives: chat compact, knowledge delete, and retrieval config GET.
- **Note — the selected backend router modules themselves are unchanged.** Valid gaps arise through changed callees or changed frontend callers; route existence alone was not treated as behavioral evidence.
### Residual risks
- Chat search impact depends on structured-output persistence state; the code path establishes changed persisted fields and content-based search, but no database/browser integration test was executed.
- Config-related gaps are most visible when persistence is disabled or values need `jsonable_encoder`; default deployments may not exercise every branch.
- The audit intentionally excludes all other PR #26642 unmatched IDs.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "All 121 deduplicated selected IDs are classified with backend membership; findings cite changed and consuming files including models/config.py:193-216, routers/chats.py:73-100 and 707-723, routers/knowledge.py:569-1023, routers/retrieval.py:406-422 and 2515-2576, and KnowledgeBase.svelte:574-650."
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "python3 audit accounting over /tmp/audit-inputs/{mypy,scip}-26642.json",
      "result": "passed",
      "summary": "Verified 121 deduplicated IDs: 15 ground_truth_gap, 106 true_false_positive, 0 normalization_gap, 0 unknown; mypy 14 memberships and SCIP 121."
    },
    {
      "command": "git -C /tmp/audit-source/26642 diff HEAD^ HEAD --stat and targeted parent diffs",
      "result": "passed",
      "summary": "Inspected the 107-file parent diff and the changed Config, middleware, web retrieval, chat, SearchModal, and KnowledgeBase implementations."
    },
    {
      "command": "git -C /tmp/audit-source/26642 diff --quiet HEAD^ HEAD -- backend/open_webui/routers/{chats,knowledge,files,retrieval,memories}.py",
      "result": "passed",
      "summary": "Confirmed all five selected backend router files were unchanged in the parent diff."
    },
    {
      "command": "git -C /home/shaggi/test_ast_fastapi diff --cached --quiet",
      "result": "passed",
      "summary": "No staged files."
    }
  ],
  "validationOutput": [
    "Deduplicated selected IDs: 121.",
    "ground_truth_gap=15, true_false_positive=106, normalization_gap=0, unknown=0.",
    "mypy: 11 ground-truth gaps and 3 true false positives.",
    "SCIP: 15 ground-truth gaps and 106 true false positives."
  ],
  "residualRisks": [
    "Chat search impact was established statically but not exercised against a database.",
    "Config impacts depend on persistence mode and runtime value types.",
    "Non-selected PR #26642 IDs were outside this audit."
  ],
  "noStagedFiles": true,
  "diffSummary": "Read-only audit; no files changed.",
  "reviewFindings": [
    "high: backend/open_webui/models/config.py:193-216 - supplied truth omits direct changed Config.upsert callers in chat, knowledge, and retrieval routes.",
    "high: backend/open_webui/routers/{chats,knowledge,files,retrieval,memories}.py - SCIP structurally fans out to 106 routes without behavioral impact.",
    "medium: src/lib/components/workspace/Knowledge/KnowledgeBase.svelte:574-650 - new directory synchronization behavior adds three omitted HTTP impacts."
  ],
  "manualNotes": "The main repository already contained unrelated unstaged audit/benchmark work; this review made no edits and the index remained clean."
}
```
