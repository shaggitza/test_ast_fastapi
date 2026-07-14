# Conditional factory discovery findings

## Inventory change

Compared with route-census v1:

| Repository | Unique routes before | Unique routes after | Lost | Gained |
|---|---:|---:|---:|---:|
| Khoj | 0 | 0 | 0 | 0 |
| Langflow | 0 | 5 | 0 | 5 |
| Open WebUI | 488 | 488 | 0 | 0 |

Langflow now has 5 conditional routes in every target snapshot (95 target occurrences across 19 PRs):

- `HTTP GET /api/v1/voice/elevenlabs/voice_ids`
- `WEBSOCKET /api/v1/voice/ws/flow_as_tool/{flow_id}`
- `WEBSOCKET /api/v1/voice/ws/flow_as_tool/{flow_id}/{session_id}`
- `WEBSOCKET /api/v1/voice/ws/flow_tts/{flow_id}`
- `WEBSOCKET /api/v1/voice/ws/flow_tts/{flow_id}/{session_id}`

No Open WebUI or Khoj inventory was lost. Census health remained 39 completed, 19 partial, and 2 unresolved records.

## Verification impact

The recovered Langflow routes do not correspond to the 16 Langflow truth atoms in `fastapi-verification-v1`, so FN stages do not move yet.

| Backend | Observation | Propagation | Discovery | Unavailable |
|---|---:|---:|---:|---:|
| mypy | 0 | 20 | 48 | 0 |
| calibrated SCIP | 4 | 19 | 48 | 0 |

The required invariant still holds for both backends:

```text
FN = observation_missing + propagation_missing
   + discovery_missing + inventory_unavailable
```

Primary prediction scores are unchanged because the census is diagnostic-only and existing prediction artifacts were reused.

## Interpretation

The explicit factory and conditional-provenance mechanism produces a real, conservative Langflow inventory gain without repository-specific route or helper rules and without Open WebUI regression. It does not yet solve the benchmark discovery deficit: the missing Langflow truth routes are registered through additional unresolved router/export patterns, while Khoj still requires bootstrap registration summaries through `main.run() -> configure_routes(app)`.

The next discovery work should therefore target project-local registration helpers and imported router export patterns, not confidence promotion. Conditional routes remain LOW-only until independently established.
