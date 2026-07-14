# Transitive router re-export findings

## Inventory movement

| Repository | Unique routes before | Unique routes after | Gained | Lost |
|---|---:|---:|---:|---:|
| Khoj | 0 | 0 | 0 | 0 |
| Langflow | 5 | 250 | 245 | 0 |
| Open WebUI | 488 | 488 | 0 | 0 |

The resolver follows only exact, source-order-effective project-local imports with cycle and hop bounds. It fails closed on star/dynamic exports, deletion, rebinding, ambiguity, package/submodule conflicts, and kind mismatch. No production rule contains repository, route, helper, or symbol-name knowledge.

Langflow PR #13950 is the deletion/control oracle:

- target: 250 routes and `HTTP GET /api/v1/a2a/agents` present;
- baseline: 249 routes and `/api/v1/a2a/agents` absent.

No route was lost from Khoj or Open WebUI.

## Strength-aware FN stages

| Backend | Observation | Propagation | Discovery | Unavailable |
|---|---:|---:|---:|---:|
| mypy | 0 | 20 | 32 | 16 |
| calibrated SCIP | 4 | 19 | 32 | 16 |

Repository interpretation:

- Khoj: all 32 FN remain discovery-missing.
- Langflow: all 16 FN move out of discovery, but remain inventory-unavailable because the selected factory contains unresolved app-mutating/plugin work. The newly recovered registrations are therefore conditional, not propagation proof.
- Open WebUI: unchanged at 20 propagation FN for mypy and 4 observation plus 19 propagation FN for SCIP.

This is the intended consequence of schema v2: route-ID recovery does not falsely promote conditional inventory to complete inventory. Primary scores remain unchanged because the census is diagnostic-only and prediction artifacts were reused.

## Census health

The manifest reports 20 completed, 38 partial, and 2 unresolved records. The apparent reduction in completed records is a measurement correction: 19 Langflow records previously containing conditional routes are now explicitly partial rather than completed.

## Decision

The re-export slice passes the inventory gate (245 generic Langflow routes gained, zero cross-repository loss) and the measurement gate (16 Langflow atoms no longer claimed as discovery absence). It intentionally does not pass a propagation claim: establishing those occurrences requires resolving or explicitly attesting the remaining registration/bootstrap effects.

The next production slice should harden composition semantics (`include_router` copy versus `mount` live reference and destructive mutation) before adding explicit bootstrap registration summaries for Khoj.
