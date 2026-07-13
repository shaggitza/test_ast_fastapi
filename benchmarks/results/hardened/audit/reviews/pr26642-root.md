# PR #26642 residual root-route audit

Ten normalized disagreements escaped the delegated prefix buckets because they
use root `/api/*` paths rather than `/api/v1/*`. All are **true false
positives**; no additional ground-truth amendment is warranted.

- `POST /api/chat/actions/{action_id}` delegates to unchanged
  `utils.actions.chat_action` (`backend/open_webui/main.py:1751-1760`).
- `POST /api/chat/completed` delegates to unchanged
  `utils.chat.chat_completed` (`main.py:1731-1743`).
- `GET /api/tasks`, `GET /api/tasks/chat/{chat_id:path}`, `POST
  /api/tasks/chat/{chat_id:path}/stop`, and `POST /api/tasks/stop/{task_id}`
  only inspect or stop task-manager state (`main.py:1768-1811`).
- `GET /api/config` reads a fixed list of unrelated public configuration keys;
  the newly introduced memory/STT keys are not returned (`main.py:1820-1915`).
- `GET /api/models`, `GET /api/models/base`, and `POST /api/models/unload`
  do not invoke the changed provider-failure, Config write, or model-update
  paths. Their structural proximity to changed model/provider code is not a
  behavioral edge.

Classification total: 10 true false positives, 0 ground-truth gaps, 0
normalization gaps, 0 unknowns.
