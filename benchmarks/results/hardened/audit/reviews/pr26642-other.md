# PR #26642 unmatched-ID audit
Audited the deduplicated union of mypy and SCIP unmatched predictions after excluding the assigned domains. **68 IDs were selected and fully accounted for: 41 behaviorally affected, 27 false positives.** No files were edited.
Backend notation: **M** = mypy, **S** = SCIP.
## Findings
### 1. High — 41 unmatched IDs have behavioral impact
#### Event-management endpoints: 5 confirmed
`backend/open_webui/main.py:2059-2148` exposes the new event catalog/webhook configuration and publishes `CONFIG_WEBHOOK_UPDATED` after mutations.
- `[S]` `HTTP GET /api/events`
- `[S]` `HTTP GET /api/events/webhooks`
- `[M,S]` `HTTP POST /api/events/webhooks`
- `[M,S]` `HTTP PUT /api/events/webhooks/{webhook_id}`
- `[M,S]` `HTTP DELETE /api/events/webhooks/{webhook_id}`
These should be added to behavioral truth rather than treated as analyzer false positives.
#### Ollama endpoints: 32 confirmed
`backend/open_webui/routers/ollama.py:85-143` changes `send_request` so upstream failures publish `model.provider_request.failed`. The following handlers reach it:
- `[M,S]` `HTTP GET /ollama/api/tags/{url_idx}`
- `[M,S]` `HTTP GET /ollama/api/version/{url_idx}`
- `[M,S]` `HTTP GET /ollama/v1/models/{url_idx}`
- `[M,S]` `HTTP DELETE /ollama/api/delete`
- `[M,S]` `HTTP DELETE /ollama/api/delete/{url_idx}`
- `[M,S]` `HTTP DELETE /ollama/api/push`
- `[M,S]` `HTTP DELETE /ollama/api/push/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/chat`
- `[M,S]` `HTTP POST /ollama/api/chat/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/copy`
- `[M,S]` `HTTP POST /ollama/api/copy/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/create`
- `[M,S]` `HTTP POST /ollama/api/create/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/embed`
- `[M,S]` `HTTP POST /ollama/api/embed/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/embeddings`
- `[M,S]` `HTTP POST /ollama/api/embeddings/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/generate`
- `[M,S]` `HTTP POST /ollama/api/generate/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/pull`
- `[M,S]` `HTTP POST /ollama/api/pull/{url_idx}`
- `[M,S]` `HTTP POST /ollama/api/show`
- `[M,S]` `HTTP POST /ollama/api/unload`
- `[M,S]` `HTTP POST /ollama/v1/chat/completions`
- `[M,S]` `HTTP POST /ollama/v1/chat/completions/{url_idx}`
- `[M,S]` `HTTP POST /ollama/v1/completions`
- `[M,S]` `HTTP POST /ollama/v1/completions/{url_idx}`
- `[M,S]` `HTTP POST /ollama/v1/messages`
- `[M,S]` `HTTP POST /ollama/v1/messages/{url_idx}`
- `[M,S]` `HTTP POST /ollama/v1/responses`
- `[M,S]` `HTTP POST /ollama/v1/responses/{url_idx}`
Additionally:
- `[M,S]` `HTTP POST /ollama/config/update` is directly affected because it publishes `MODEL_PROVIDER_CONFIG_UPDATED` at `backend/open_webui/routers/ollama.py:287-321`.
`copy` and `delete` also publish success events directly around `ollama.py:681-762`.
#### OpenAI provider configuration: 1 confirmed
- `[M,S]` `HTTP POST /openai/config/update`
It directly publishes `MODEL_PROVIDER_CONFIG_UPDATED` at `backend/open_webui/routers/openai.py:312-353`.
#### Audio speech: 1 confirmed
- `[S]` `HTTP POST /api/v1/audio/speech`
Both cached and newly generated speech publish `AUDIO_SPEECH_REQUESTED` at `backend/open_webui/routers/audio.py:536-595`.
#### Anthropic-compatible messages aliases: 2 confirmed
- `[M,S]` `HTTP POST /api/message`
- `[M,S]` `HTTP POST /api/v1/messages`
Both decorators reach `generate_messages`, which delegates to the changed `chat_completion` pipeline at `backend/open_webui/main.py:1607-1646`.
### 2. Medium — 27 predictions are false positives
No behavioral path from the PR’s changed provider-failure, memory, STT-format, model-update, permission, or event-publication logic was found.
#### Ollama: 10 false positives
- `[S]` `HTTP GET /ollama/api/ps`
- `[M,S]` `HTTP GET /ollama/api/tags`
- `[M,S]` `HTTP GET /ollama/api/version`
- `[S]` `HTTP GET /ollama/config`
- `[M,S]` `HTTP GET /ollama/v1/models`
- `[S]` `HTTP POST /ollama/models/download`
- `[S]` `HTTP POST /ollama/models/download/{url_idx}`
- `[S]` `HTTP POST /ollama/models/upload`
- `[S]` `HTTP POST /ollama/models/upload/{url_idx}`
- `[S]` `HTTP POST /ollama/verify`
Evidence: aggregate tags, versions, loaded models, and model lists use `send_get_request` or direct `aiohttp` calls rather than changed `send_request`; upload/download/verify likewise use route-local sessions. See `backend/open_webui/routers/ollama.py:334-510,1405-1620`.
#### OpenAI: 5 false positives
- `[S]` `HTTP GET /openai/config`
- `[M,S]` `HTTP GET /openai/models`
- `[M,S]` `HTTP GET /openai/models/{url_idx}`
- `[S]` `HTTP POST /openai/audio/speech`
- `[S]` `HTTP POST /openai/verify`
These use configuration reads or direct `aiohttp` request paths and do not invoke the changed provider-failure publisher. See `backend/open_webui/routers/openai.py:303-310,360-430,585-800`.
#### Audio metadata endpoints: 2 false positives
- `[S]` `HTTP GET /api/v1/audio/models`
- `[S]` `HTTP GET /api/v1/audio/voices`
They only invoke `get_available_models`/`get_available_voices`; neither reaches the changed transcription request-format path or new speech publication. See `backend/open_webui/routers/audio.py:1280-1450`.
#### Generic/static endpoints: 5 false positives
- `[S]` `HTTP GET /api/usage`
- `[S]` `HTTP GET /api/version/updates`
- `[S]` `HTTP GET /cache/{path:path}`
- `[S]` `HTTP GET /manifest.json`
- `[S]` `HTTP GET /opensearch.xml`
Their route-local behavior at `backend/open_webui/main.py:2150-2218,2460-2600` is independent of the changed chat/provider/event paths.
#### Utility endpoints: 5 false positives
- `[S]` `HTTP GET /api/v1/utils/db/download`
- `[S]` `HTTP GET /api/v1/utils/gravatar`
- `[S]` `HTTP POST /api/v1/utils/code/execute`
- `[S]` `HTTP POST /api/v1/utils/code/format`
- `[S]` `HTTP POST /api/v1/utils/pdf`
`backend/open_webui/routers/utils.py:20-112` shows self-contained gravatar, formatting, execution, PDF, and database-export implementations with no changed dependency path.
### 3. Medium — Ollama failure events frequently lack application/request context
Twenty-one affected Ollama route IDs call `send_request` without forwarding their available `request`. On failure, `publish_model_provider_request_failed(request, ...)` therefore receives `None` at `backend/open_webui/routers/ollama.py:109-143`.
`backend/open_webui/events.py:950-979,1081-1172` tolerates this for event construction and webhook scheduling, but:
- `instance_id` becomes `None`;
- event-function dispatch receives a synthetic context whose `app` is `None`;
- request-aware custom event functions cannot receive the originating request.
The chat/completions/messages/responses handlers correctly pass `request=request`; other callers should do the same if full event semantics are intended.
## Deduplication/accounting
| Classification | Unique IDs |
|---|---:|
| Confirmed affected | 41 |
| False positives | 27 |
| **Total selected union** | **68** |
Overlapping mypy/SCIP IDs were counted once. Named excluded domains and already matched predictions were not re-audited.
## Residual risks
- Source inspection used the supplied PR snapshot; no base revision or executable git-diff facility was available to distinguish pre-existing code mechanically.
- Optional/runtime-only event sinks and configured custom event functions were not executed.
- `send_request(None, ...)` still schedules webhook delivery, so those Ollama endpoints were conservatively classified as affected despite degraded context.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audited and deduplicated 68 remaining unmatched IDs, classified 41 as behaviorally affected and 27 as false positives, and returned severity-tagged findings with concrete source paths and line ranges."
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "Read /tmp/audit-inputs/{mypy,scip}-26642.json",
      "result": "passed",
      "summary": "Collected unmatched predictions and backend overlap."
    },
    {
      "command": "Inspect /tmp/audit-source/26642 backend routes and event helpers",
      "result": "passed",
      "summary": "Traced selected IDs through main.py, ollama.py, openai.py, audio.py, utils.py, and events.py."
    }
  ],
  "validationOutput": [
    "Deduplicated accounting: 41 confirmed affected + 27 false positives = 68 selected IDs.",
    "All selected IDs are explicitly listed under one classification.",
    "No repository files were modified."
  ],
  "residualRisks": [
    "No base revision/diff command was available, so classification relies on behavioral reachability in the supplied PR snapshot and the known changed behaviors.",
    "Runtime-configured webhook and custom event-function behavior was not executed."
  ],
  "noStagedFiles": true,
  "diffSummary": "No edits; review-only audit.",
  "reviewFindings": [
    "high: backend/open_webui/main.py:2059-2148 - five unmatched event-management endpoints are genuinely affected and missing from behavioral truth",
    "high: backend/open_webui/routers/ollama.py:85-143 - 31 route IDs reach changed provider-failure publication; config/update adds one further direct event impact",
    "medium: backend/open_webui/routers/ollama.py:109-143 - 21 affected route IDs invoke failure publication without request/application context",
    "medium: 27 unmatched predictions are false positives from broad shared-file/router reachability"
  ],
  "manualNotes": "No edits or staging operations were performed. Counts are deduplicated across mypy and SCIP."
}
```
