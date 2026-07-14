# Explicit bootstrap registration findings

## Inventory movement

| Repository | Unique routes before | Unique routes after | Gained | Lost |
|---|---:|---:|---:|---:|
| Khoj | 0 | 86 | 86 | 0 |
| Langflow | 250 | 250 | 0 | 0 |
| Open WebUI | 488 | 488 | 0 | 0 |

Khoj target inventories contain 79–86 routes depending on snapshot. No bootstrap or helper name is inferred: the manifest explicitly records `main:app` and `main:run` for Khoj.

PR #1207 supplies a deletion/addition oracle:

- target contains `HTTP POST /api/chat` and `WEBSOCKET /api/chat/ws`;
- baseline contains `HTTP POST /api/chat` but not the WebSocket route;
- both sides remain conditional because unresolved bootstrap effects prevent an exhaustive claim.

No route was lost in Langflow or Open WebUI.

## Strength-aware FN stages

| Backend | Observation | Propagation | Discovery | Unavailable |
|---|---:|---:|---:|---:|
| mypy | 0 | 20 | 0 | 48 |
| calibrated SCIP | 4 | 19 | 0 | 48 |

By repository:

- Khoj: 32 discovery FN move to inventory-unavailable after source-backed conditional recovery.
- Langflow: 16 remain inventory-unavailable after transitive re-export recovery.
- Open WebUI remains classifiable: mypy has 20 propagation FN; SCIP has 4 observation and 19 propagation FN.

The movement is deliberately not called propagation: bootstrap and factory inventories still contain explicit limitations. Primary scores remain unchanged because census evidence is diagnostic-only.

## Safety correction during validation

Initial composition limitations downgraded every known route under an object. This erased useful Open WebUI propagation diagnostics. The final implementation separates:

- occurrence limitations, which can mean a known route was mutated or replaced; and
- inventory-only limitations, where unresolved additive registration prevents exhaustiveness but independently proven routes remain established.

After this correction, Open WebUI staging returns exactly to its prior 20 mypy and 19 SCIP propagation counts while Khoj gains 86 routes.

## Decision

The explicit bootstrap slice passes the inventory gate: finite generic recovery, correct target/baseline separation, no cross-repository inventory loss, and no confidence promotion. The remaining 48 unavailable FN now identify the next requirement precisely: establish narrower helper/factory effects or retain abstention, rather than performing broader route discovery.
