from __future__ import annotations

from typing import TYPE_CHECKING

import yaml

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config

if TYPE_CHECKING:
    from pathlib import Path


def test_shared_helper_resource_identity_stays_endpoint_correlated(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "def write_state(bucket: str, key: str) -> None: pass\n"
        "def read_state(bucket: str, key: str) -> str: return key\n"
        "def write_helper(bucket: str, key: str) -> None:\n"
        "    write_state(bucket, key)\n"
        "def read_helper(bucket: str, key: str) -> str:\n"
        "    return read_state(bucket, key)\n\n"
        "@app.post('/write-a')\n"
        "def write_a() -> None:\n"
        "    write_helper('alpha', 'same')\n\n"
        "@app.post('/write-b')\n"
        "def write_b() -> None:\n"
        "    write_helper('beta', 'same')\n\n"
        "@app.get('/read-a')\n"
        "def read_a() -> str:\n"
        "    return read_helper('alpha', 'same')\n\n"
        "@app.get('/read-b')\n"
        "def read_b() -> str:\n"
        "    return read_helper('alpha', 'different')\n\n"
        "@app.post('/write-dynamic')\n"
        "def write_dynamic(bucket: str) -> None:\n"
        "    write_helper(bucket, 'same')\n\n"
        "@app.post('/write-reassigned')\n"
        "def write_reassigned(bucket: str) -> None:\n"
        "    value = 'alpha'\n"
        "    value = bucket\n"
        "    write_helper(value, 'same')\n\n"
        "@app.post('/write-starred')\n"
        "def write_starred(values: tuple[str, str]) -> None:\n"
        "    write_helper(*values)\n\n"
        "@app.post('/write-capped')\n"
        "def write_capped(\n"
        "    a: bool, b: bool, c: bool, d: bool, e: bool, f: bool, g: bool, h: bool\n"
        ") -> None:\n"
        "    bucket = (\n"
        "        'a' if a else 'b' if b else 'c' if c else 'd' if d else\n"
        "        'e' if e else 'f' if f else 'g' if g else 'h' if h else 'i'\n"
        "    )\n"
        "    write_helper(bucket, 'same')\n",
        encoding="utf-8",
    )
    contracts = tmp_path / "effects.yaml"
    selector = {
        "kind": "composite",
        "components": [
            {"kind": "argument", "index": 0},
            {"kind": "argument", "index": 1},
        ],
    }
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 4,
                "preset": {
                    "id": "shared-helper-contexts",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "write-state",
                        "symbol": "main.write_state",
                        "invocation": "function",
                        "operation": "write",
                        "channel": "custom",
                        "resource": selector,
                    },
                    {
                        "id": "read-state",
                        "symbol": "main.read_state",
                        "invocation": "function",
                        "operation": "read",
                        "channel": "custom",
                        "resource": selector,
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    coupling = tmp_path / "coupling.yaml"
    coupling.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "mode": "report_only",
                "groups": [
                    {
                        "id": "shared-helper-state",
                        "resource_space": "shared-helper-state-test",
                        "producer_contract_ids": ["write-state"],
                        "consumer_contract_ids": ["read-state"],
                    }
                ],
                "limits": {"max_endpoint_links_per_resource": 16, "max_edges": 32},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n"
        "@@ -5,1 +5,1 @@\n-def write_state(bucket: str, key: str) -> None: pass\n"
        "+def write_state(bucket: str, key: str) -> None: return None\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(effect_contracts=contracts, resource_coupling=coupling)
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    audit = report.effect_contract_audit
    graph = report.resource_coupling_graph
    assert audit is not None and graph is not None
    write_occurrences = [item for item in audit.occurrences if item.contract_id == "write-state"]
    assert len(write_occurrences) == 1
    write_occurrence = write_occurrences[0]
    assert len(write_occurrence.endpoints) == 6
    assert len(write_occurrence.invocation_contexts) == 6
    endpoint_by_id = {endpoint.id: endpoint for endpoint in write_occurrence.endpoints}
    contexts = {
        endpoint_by_id[context.endpoint_id].path: context
        for context in write_occurrence.invocation_contexts
    }
    for path in ("/write-dynamic", "/write-reassigned", "/write-starred", "/write-capped"):
        assert contexts[path].resource_identity is not None
        assert contexts[path].resource_identity.status.value == "unavailable"

    endpoint_by_id = {
        endpoint.id: endpoint
        for occurrence in audit.occurrences
        for endpoint in occurrence.endpoints
    }
    pairs = [
        (
            endpoint_by_id[edge.producer_endpoint_id].path,
            endpoint_by_id[edge.consumer_endpoint_id].path,
        )
        for edge in graph.edges
    ]
    assert pairs == [("/write-a", "/read-a")]
