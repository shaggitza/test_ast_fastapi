## Review
**Selection rule:** deduplicated `unmatched_predictions` for route families `/api/v1/{configs,users,auths,groups,channels,calendars,folders,notes,terminals}` plus root `/oauth/*`. Embedded OAuth routes remain under their owning family. `[B]` means predicted by both backends; `[S]` means SCIP only.
- **143 unique IDs audited:** 16 appeared in both inputs and 127 only in SCIP.
- **20 behaviorally supported:** 15 `[B]`, 5 `[S]`.
- **123 unsupported false positives:** 1 `[B]`, 122 `[S]`.
- Thus **15 of mypy’s 16 selected unmatched IDs have real changed-code reachability**. SCIP found all 20 supported IDs but added 123 unsupported IDs.
### High: 20 unmatched IDs have changed-code-to-route evidence
#### Changed `Config.upsert` callers — 14 IDs
`Config.upsert` now JSON-encodes every value and routes non-persistent keys into in-memory defaults rather than the database (`backend/open_webui/models/config.py:193-216`).
- `[B] HTTP POST /api/v1/configs/import` → `Config.upsert` at `backend/open_webui/routers/configs.py:92-102`.
- `[B] HTTP POST /api/v1/configs/connections` → line 141.
- `[B] HTTP POST /api/v1/configs/tool_servers` → lines 230-284, call at 253.
- `[B] HTTP POST /api/v1/configs/terminal_servers` → lines 318-335, call at 325.
- `[B] HTTP POST /api/v1/configs/code_execution` → lines 693-712, call at 697.
- `[B] HTTP POST /api/v1/configs/models` → lines 738-754, call at 740.
- `[B] HTTP POST /api/v1/configs/suggestions` → lines 766-783, call at 773.
- `[B] HTTP POST /api/v1/configs/banners` → lines 795-812, call at 802.
- `[B] HTTP POST /api/v1/auths/admin/config/ldap/server` → `Config.upsert` at `backend/open_webui/routers/auths.py:1198-1216`.
- `[B] HTTP POST /api/v1/auths/admin/config/ldap` → lines 1228-1231.
- `[B] HTTP POST /api/v1/auths/admin/config/oauth` → lines 1370-1373. This is especially concrete because OAuth persistence defaults off at `backend/open_webui/config.py:3129-3135`.
- `[B] HTTP POST /api/v1/auths/signup` → `signup_handler` invokes changed `Config.upsert` for the first user at `backend/open_webui/routers/auths.py:763-818`.
- `[B] HTTP POST /api/v1/auths/signin` → trusted-header/no-auth first-user branches invoke `signup_handler` at `backend/open_webui/routers/auths.py:683-691,725-732`.
- `[B] HTTP POST /api/v1/users/default/permissions` → changed `Config.upsert` at `backend/open_webui/routers/users.py:275-286`.
These impacts are input/runtime-conditional, but they are genuine executable paths through changed code.
#### New default keys exposed by generic config reads — 2 IDs
PR26642 adds `memories.system_context.enable` and `audio.stt.openai.api_request_format` to `DEFAULT_CONFIG` (`backend/open_webui/config.py:2766-2769,2967-2973`). Startup seeds defaults through changed `Config.seed_defaults` (`backend/open_webui/main.py:314-318`; `backend/open_webui/config.py:40-43`; `backend/open_webui/models/config.py:237-258`).
- `[S] HTTP GET /api/v1/configs/export` returns `Config.get_all()` at `backend/open_webui/routers/configs.py:110-112`, exposing newly seeded keys.
- `[S] HTTP GET /api/v1/configs/namespace/{namespace}` returns `Config.get_namespace(namespace)` at `backend/open_webui/routers/configs.py:115-117`; behavior changes for applicable `memories` or `audio` namespaces.
#### Changed chat path from channel messages — 1 ID
- `[B] HTTP POST /api/v1/channels/{id}/messages/post` conditionally schedules `model_response_handler` (`backend/open_webui/routers/channels.py:1193-1229`), which invokes `CHAT_COMPLETION_HANDLER` for model mentions (`backend/open_webui/routers/channels.py:947-1106`). That reaches PR26642’s changed `chat_completion` and middleware response/memory processing.
#### JWS registry change reaches OAuth callbacks — 3 IDs
PR26642 registers the provider-specific `client_id` JWS header globally (`backend/open_webui/utils/oauth.py:192-197`).
- `[S] HTTP GET /oauth/clients/{client_id}/callback` → main route at `backend/open_webui/main.py:2376-2388` → `authorize_access_token` at `backend/open_webui/utils/oauth.py:1143-1159`.
- `[S] HTTP GET /oauth/{provider}/callback`
- `[S] HTTP GET /oauth/{provider}/login/callback`
The latter two decorate the same handler (`backend/open_webui/main.py:2396-2413`) and reach Authlib ID-token parsing at `backend/open_webui/utils/oauth.py:1691-1719`.
### High: 123 unsupported false positives
The following IDs have no concrete route execution path to changed PR26642 code.
#### Configs — 13 `[S]`
- `HTTP GET /api/v1/configs/banners`
- `HTTP GET /api/v1/configs/code_execution`
- `HTTP GET /api/v1/configs/connections`
- `HTTP GET /api/v1/configs/models`
- `HTTP GET /api/v1/configs/models/defaults`
- `HTTP GET /api/v1/configs/terminal_servers`
- `HTTP GET /api/v1/configs/tool_servers`
- `HTTP POST /api/v1/configs/oauth/clients/register`
- `HTTP POST /api/v1/configs/terminal_servers/lifecycle`
- `HTTP POST /api/v1/configs/terminal_servers/policy`
- `HTTP POST /api/v1/configs/terminal_servers/refresh`
- `HTTP POST /api/v1/configs/terminal_servers/verify`
- `HTTP POST /api/v1/configs/tool_servers/verify`
The GET routes read unchanged, specific keys (`backend/open_webui/routers/configs.py:130-132,225-227,313-315,688-690,726-735,815-820`). The POST verification/lifecycle routes do not call changed `Config.upsert` (`backend/open_webui/routers/configs.py:340-536`).
#### Users — 21 `[S]`
- `HTTP DELETE /api/v1/users/{user_id}`
- `HTTP GET /api/v1/users/`
- `HTTP GET /api/v1/users/all`
- `HTTP GET /api/v1/users/default/permissions`
- `HTTP GET /api/v1/users/default/permissions/defaults`
- `HTTP GET /api/v1/users/groups`
- `HTTP GET /api/v1/users/permissions`
- `HTTP GET /api/v1/users/search`
- `HTTP GET /api/v1/users/user/info`
- `HTTP GET /api/v1/users/user/settings`
- `HTTP GET /api/v1/users/user/status`
- `HTTP GET /api/v1/users/{user_id}`
- `HTTP GET /api/v1/users/{user_id}/active`
- `HTTP GET /api/v1/users/{user_id}/groups`
- `HTTP GET /api/v1/users/{user_id}/info`
- `HTTP GET /api/v1/users/{user_id}/oauth/sessions`
- `HTTP GET /api/v1/users/{user_id}/preview`
- `HTTP GET /api/v1/users/{user_id}/profile/image`
- `HTTP POST /api/v1/users/user/info/update`
- `HTTP POST /api/v1/users/user/status/update`
- `HTTP POST /api/v1/users/{user_id}/update`
The only users-router change is inside the already-labeled settings-update handler (`backend/open_webui/routers/users.py:321-335`). These handlers occupy `backend/open_webui/routers/users.py:61-308,372-795` and do not reach it or changed configuration writers.
#### Auths — 15 `[S]`
- `HTTP DELETE /api/v1/auths/api_key`
- `HTTP DELETE /api/v1/auths/oauth/sessions/{provider:path}`
- `HTTP GET /api/v1/auths/`
- `HTTP GET /api/v1/auths/admin/config/ldap`
- `HTTP GET /api/v1/auths/admin/config/ldap/server`
- `HTTP GET /api/v1/auths/admin/config/oauth`
- `HTTP GET /api/v1/auths/admin/details`
- `HTTP GET /api/v1/auths/api_key`
- `HTTP POST /api/v1/auths/add`
- `HTTP POST /api/v1/auths/api_key`
- `HTTP POST /api/v1/auths/ldap`
- `HTTP POST /api/v1/auths/signout`
- `HTTP POST /api/v1/auths/update/password`
- `HTTP POST /api/v1/auths/update/profile`
- `HTTP POST /api/v1/auths/update/timezone`
The auths diff only adds the already-labeled admin-memory field (`backend/open_webui/routers/auths.py:105-108,1143-1147`). These routes neither use that field nor call changed `Config.upsert`; for example the GET LDAP/OAuth routes only read unchanged keys (`backend/open_webui/routers/auths.py:1193-1195,1219-1221,1365-1367`).
#### Groups — all 11 `[S]`
- `HTTP DELETE /api/v1/groups/id/{id}/delete`
- `HTTP GET /api/v1/groups/`
- `HTTP GET /api/v1/groups/id/{id}`
- `HTTP GET /api/v1/groups/id/{id}/export`
- `HTTP GET /api/v1/groups/id/{id}/info`
- `HTTP GET /api/v1/groups/id/{id}/preview`
- `HTTP POST /api/v1/groups/create`
- `HTTP POST /api/v1/groups/id/{id}/update`
- `HTTP POST /api/v1/groups/id/{id}/users`
- `HTTP POST /api/v1/groups/id/{id}/users/add`
- `HTTP POST /api/v1/groups/id/{id}/users/remove`
`backend/open_webui/routers/groups.py` is unchanged; these handlers are at lines 36-339 and have no changed configuration, chat, or OAuth callback path.
#### Channels — 27 `[S]`
- `HTTP DELETE /api/v1/channels/{id}/delete`
- `HTTP DELETE /api/v1/channels/{id}/messages/{message_id}/delete`
- `HTTP DELETE /api/v1/channels/{id}/webhooks/{webhook_id}/delete`
- `HTTP GET /api/v1/channels/`
- `HTTP GET /api/v1/channels/list`
- `HTTP GET /api/v1/channels/users/{user_id}`
- `HTTP GET /api/v1/channels/webhooks/{webhook_id}/profile/image`
- `HTTP GET /api/v1/channels/{id}`
- `HTTP GET /api/v1/channels/{id}/members`
- `HTTP GET /api/v1/channels/{id}/messages`
- `HTTP GET /api/v1/channels/{id}/messages/pinned`
- `HTTP GET /api/v1/channels/{id}/messages/{message_id}`
- `HTTP GET /api/v1/channels/{id}/messages/{message_id}/data`
- `HTTP GET /api/v1/channels/{id}/messages/{message_id}/thread`
- `HTTP GET /api/v1/channels/{id}/webhooks`
- `HTTP POST /api/v1/channels/create`
- `HTTP POST /api/v1/channels/webhooks/{webhook_id}/{token}`
- `HTTP POST /api/v1/channels/{id}/members/active`
- `HTTP POST /api/v1/channels/{id}/messages/{message_id}/pin`
- `HTTP POST /api/v1/channels/{id}/messages/{message_id}/reactions/add`
- `HTTP POST /api/v1/channels/{id}/messages/{message_id}/reactions/remove`
- `HTTP POST /api/v1/channels/{id}/messages/{message_id}/update`
- `HTTP POST /api/v1/channels/{id}/update`
- `HTTP POST /api/v1/channels/{id}/update/members/add`
- `HTTP POST /api/v1/channels/{id}/update/members/remove`
- `HTTP POST /api/v1/channels/{id}/webhooks/create`
- `HTTP POST /api/v1/channels/{id}/webhooks/{webhook_id}/update`
The router is unchanged. Unlike `/messages/post`, none invokes `model_response_handler`. The webhook posting route only stores/emits the message and invokes unchanged `publish_event` (`backend/open_webui/routers/channels.py:1957-2035`).
#### Calendars — all 13 `[S]`
- `HTTP DELETE /api/v1/calendars/events/{event_id}/delete`
- `HTTP DELETE /api/v1/calendars/{calendar_id}/delete`
- `HTTP GET /api/v1/calendars/`
- `HTTP GET /api/v1/calendars/events`
- `HTTP GET /api/v1/calendars/events/search`
- `HTTP GET /api/v1/calendars/events/{event_id}`
- `HTTP GET /api/v1/calendars/{calendar_id}`
- `HTTP POST /api/v1/calendars/create`
- `HTTP POST /api/v1/calendars/events/create`
- `HTTP POST /api/v1/calendars/events/{event_id}/rsvp`
- `HTTP POST /api/v1/calendars/events/{event_id}/update`
- `HTTP POST /api/v1/calendars/{calendar_id}/default`
- `HTTP POST /api/v1/calendars/{calendar_id}/update`
`backend/open_webui/routers/calendar.py` is unchanged; handlers at lines 87-467 only reach calendar storage/permission and unchanged event publishing.
#### Folders — all 10 `[S]`
- `HTTP DELETE /api/v1/folders/{id}`
- `HTTP GET /api/v1/folders/`
- `HTTP GET /api/v1/folders/shared`
- `HTTP GET /api/v1/folders/{id}`
- `HTTP GET /api/v1/folders/{id}/shared/chats`
- `HTTP POST /api/v1/folders/`
- `HTTP POST /api/v1/folders/{id}/access/update`
- `HTTP POST /api/v1/folders/{id}/update`
- `HTTP POST /api/v1/folders/{id}/update/expanded`
- `HTTP POST /api/v1/folders/{id}/update/parent`
`backend/open_webui/routers/folders.py` is unchanged; the listed routes are at lines 70-526 with no changed-code path.
#### Notes — all 9 `[S]`
- `HTTP DELETE /api/v1/notes/{id}/delete`
- `HTTP GET /api/v1/notes/`
- `HTTP GET /api/v1/notes/pinned`
- `HTTP GET /api/v1/notes/search`
- `HTTP GET /api/v1/notes/{id}`
- `HTTP POST /api/v1/notes/create`
- `HTTP POST /api/v1/notes/{id}/access/update`
- `HTTP POST /api/v1/notes/{id}/pin`
- `HTTP POST /api/v1/notes/{id}/update`
`backend/open_webui/routers/notes.py` is unchanged; handlers at lines 63-494 do not reach changed code.
#### Terminals — 1 `[S]`
- `HTTP GET /api/v1/terminals/`
The route only reads unchanged terminal-server configuration (`backend/open_webui/routers/terminals.py:65-82`).
#### Root OAuth — 3 false IDs
- `[B] HTTP GET /oauth/clients/{client_id}/authorize`
- `[S] HTTP GET /oauth/{provider}/login`
- `[S] HTTP POST /oauth/backchannel-logout`
The first two only create authorization redirects (`backend/open_webui/main.py:2333-2373,2391-2393`; `backend/open_webui/utils/oauth.py:1126-1141,1671-1689`) and do not parse a JWS. Back-channel logout explicitly uses PyJWT rather than the changed joserfc registry (`backend/open_webui/utils/oauth.py:2041-2049,2121-2136`).
### Root cause note
Many unsupported CRUD routes invoke the unchanged generic `publish_event` ending at `backend/open_webui/events.py:1087-1115`. PR26642 adds a new sibling publisher starting at line 1118. Treating the containing event structure or adjacent lines as changed fans out to unrelated routes; there is no behavioral path from those existing event types to the new provider-failure helper.
### Residual risks
- `Config.upsert` effects depend on input values and persistence settings. They are real dependency paths, but not every request produces observably different output.
- Generic config export/namespace impact assumes normal startup seeding; namespace impact is limited to relevant namespace arguments.
- OAuth callback classification relies on Authlib/joserfc using `JWSRegistry.default_header_registry` during `authorize_access_token`; source establishes that parsing point, but no provider integration test was run.
- “Configs” was interpreted as the `routers/configs.py` family, not every unrelated route containing the singular word `config`.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audited and accounted for 143 deduplicated IDs with classifications and source evidence from models/config.py, routers/configs.py, routers/auths.py, routers/users.py, routers/channels.py, main.py, and utils/oauth.py."
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "Parse mypy-26642.json and scip-26642.json, filter selected route families, and deduplicate IDs",
      "result": "passed",
      "summary": "Found 143 unique IDs: 16 in both backends and 127 SCIP-only."
    },
    {
      "command": "Compare PR26642 HEAD^..HEAD for selected backend modules",
      "result": "passed",
      "summary": "Selected-area changes are confined to models/config.py, routers/auths.py, routers/users.py, and utils/oauth.py; other audited routers are unchanged."
    },
    {
      "command": "Trace selected route handlers to Config.upsert, Config seed/read paths, CHAT_COMPLETION_HANDLER, and authorize_access_token",
      "result": "passed",
      "summary": "Classified 20 supported IDs and 123 unsupported IDs; all 143 were accounted for exactly once."
    },
    {
      "command": "git -C /tmp/audit-source/26642 status --short",
      "result": "passed",
      "summary": "Audit source remained clean."
    }
  ],
  "validationOutput": [
    "Deduplicated total=143; supported=20; unsupported=123.",
    "Mypy selected slice: 15 supported of 16, with only GET /oauth/clients/{client_id}/authorize unsupported.",
    "SCIP selected slice: 20 supported and 123 unsupported.",
    "Backend overlap: 15 supported and 1 unsupported appeared in both; 5 supported and 122 unsupported were SCIP-only."
  ],
  "residualRisks": [
    "Config writer effects are conditional on request values and persistence configuration.",
    "OAuth registry behavior was source-traced but not integration-tested against an Apereo CAS token.",
    "Selection treats configs as the /api/v1/configs router family."
  ],
  "noStagedFiles": true,
  "diffSummary": "Read-only audit; no files changed.",
  "reviewFindings": [
    "high: backend/open_webui/models/config.py:193-216 - changed Config.upsert supports 14 unmatched route impacts through direct or conditional callers.",
    "high: backend/open_webui/routers/channels.py:947-1229 - channel message posting conditionally reaches the changed chat pipeline and is a missing truth label.",
    "high: backend/open_webui/utils/oauth.py:192-197,1143-1159,1691-1719 - three OAuth callback IDs reach changed JWS handling.",
    "high: backend/open_webui/routers/groups.py, calendar.py, folders.py, notes.py, terminals.py - 44 selected SCIP predictions have no changed-code path.",
    "high: selected audit totals - SCIP contributes 122 SCIP-only unsupported IDs, demonstrating structural fanout."
  ],
  "manualNotes": "Every selected ID is listed under either supported or unsupported. IDs appearing in both backends were deduplicated before classification."
}
```
